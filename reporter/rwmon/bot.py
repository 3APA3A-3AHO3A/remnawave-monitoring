"""Бот мониторинга: алерты с кнопками, тишина, /status, /mutes, /settings.

Grafana отдаёт алерты сюда (webhook на reporter), бот рассылает их во все чаты
панелей. Кнопки и команды бот получает через getUpdates — поэтому бот нужен свой:
если того же бота слушает кто-то ещё (IP Limiter, другой сервис), они отнимают
друг у друга нажатия.

Тишина и настройки хранятся у reporter (data_dir/bot.json), а не в Grafana: так
не нужен пароль Grafana, и смена пароля ничего не ломает. Заглушенный сбой просто
не попадает в чат; Grafana продолжает его видеть.
"""
import json
import secrets
import threading
import time
import urllib.request
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from . import alertfmt as F
from .clients import USER_AGENT, ApiError, Prometheus, _open
from .util import esc, log, read_json, write_json

FOREVER = 0
MUTE_PRESETS = (60, 360, 1440)
REPEAT_PRESETS = (30, 60, 180, 360)
QUIET_PRESETS = {'': 'нет', '23-08': '23–08', '00-09': '00–09', '22-07': '22–07'}
KEEP_MESSAGES = 3 * 86400          # сколько помнить отправленные алерты (для кнопок)
COMMANDS = [('status', 'Что сейчас с серверами'), ('mutes', 'Что заглушено'),
            ('settings', 'Настройки уведомлений')]


def _mute_label(minutes):
    return {60: '1 ч', 360: '6 ч', 1440: '24 ч'}.get(minutes, f'{minutes} мин')


def _repeat_label(minutes):
    return f'{minutes} мин' if minutes < 60 else f'{minutes // 60} ч'


class Api:
    """Bot API: rich-сообщение, а если его не приняли — обычный HTML с клавиатурой."""

    def __init__(self, token):
        self.base = f'https://api.telegram.org/bot{token}/'

    def call(self, method, params, timeout=30):
        req = urllib.request.Request(self.base + method, data=json.dumps(params).encode(),
                                     headers={'Content-Type': 'application/json', 'User-Agent': USER_AGENT})
        try:
            res = json.loads(_open(req, timeout))
        except ApiError as e:
            raise ApiError(str(e).replace(self.base, 'telegram/')) from None
        if not res.get('ok'):
            raise ApiError(f'Telegram {method}: {res.get("description")}')
        return res['result']

    def send(self, chat, topic, body, rows, silent=False):
        """Отправить; вернуть (message_id, режим). Режим нужен, чтобы потом так же править."""
        base = {'chat_id': chat}
        if topic:
            base['message_thread_id'] = int(topic)
        if silent:
            base['disable_notification'] = True
        try:
            r = self.call('sendRichMessage', {**base, 'rich_message': {
                'html': F.rich(body, rows), 'skip_entity_detection': True}})
            return r['message_id'], 'rich'
        except ApiError as e:
            if 'HTTP 4' not in str(e) and 'Telegram' not in str(e):
                raise
            log('bot', f'rich-сообщение не принято, отправляю обычным: {e}')
        p = {**base, 'text': F.plain(body), 'parse_mode': 'HTML', 'disable_web_page_preview': True}
        if rows:
            p['reply_markup'] = F.keyboard(rows)
        return self.call('sendMessage', p)['message_id'], 'plain'

    def edit(self, chat, msg_id, mode, body, rows):
        try:
            if mode == 'rich':
                self.call('editMessageText', {'chat_id': chat, 'message_id': msg_id, 'rich_message': {
                    'html': F.rich(body, rows), 'skip_entity_detection': True},
                    'reply_markup': {'inline_keyboard': []}})
            else:
                self.call('editMessageText', {'chat_id': chat, 'message_id': msg_id, 'text': F.plain(body),
                                              'parse_mode': 'HTML', 'disable_web_page_preview': True,
                                              'reply_markup': F.keyboard(rows)})
        except ApiError as e:
            if 'not modified' not in str(e):
                raise


class Bot:
    def __init__(self, cfg, prom=None):
        self.cfg = cfg
        self.api = Api(cfg.bot.token)
        self.prom = prom or Prometheus(cfg.prometheus_url)
        self.path = f'{cfg.data_dir}/bot.json'
        self.lock = threading.RLock()
        self.state = read_json(self.path, {})
        for k, v in (('settings', {}), ('mutes', []), ('msgs', {}), ('firing', {}), ('last', {})):
            self.state.setdefault(k, v)
        self.username = ''
        self.rule_uid = self._rule_uids()

    def _rule_uids(self):
        """Название правила (alertname) → uid, чтобы узнать группу для /settings."""
        try:
            from .render import rules
            return {r['title']: r['uid'] for g in rules(self.cfg)['groups'] for r in g['rules']}
        except Exception as e:
            log('bot', f'список правил не собрался: {e}')
            return {}

    # ── состояние ──
    def save(self):
        with self.lock:
            now = time.time()
            self.state['mutes'] = [m for m in self.state['mutes'] if not m['until'] or m['until'] > now]
            self.state['msgs'] = {k: v for k, v in self.state['msgs'].items() if now - v['at'] < KEEP_MESSAGES}
            write_json(self.path, self.state)

    @property
    def settings(self):
        s = self.state['settings']
        s.setdefault('off', [])
        s.setdefault('repeat', self.cfg.repeat_minutes)
        s.setdefault('quiet', '')
        s.setdefault('daily', True)
        return s

    def chats(self):
        seen, out = set(), []
        for t in self.cfg.chats():
            if (t.chat_id, t.topic_id) not in seen:
                seen.add((t.chat_id, t.topic_id))
                out.append((t.chat_id, t.topic_id))
        return out

    def quiet_now(self):
        q = self.settings['quiet']
        if not q:
            return False
        a, b = (int(x) for x in q.split('-'))
        h = datetime.now(ZoneInfo(self.cfg.bot.timezone)).hour
        return a <= h < b if a < b else (h >= a or h < b)

    # ── тишина ──
    def muted(self, alert):
        lb = alert.get('labels', {})
        now = time.time()
        for m in self.state['mutes']:
            if m['rule'] == lb.get('alertname') and (not m['until'] or m['until'] > now) \
                    and all(lb.get(k) == v for k, v in m['labels'].items()):
                return m
        return None

    def category_off(self, alert):
        uid = self.rule_uid.get(alert.get('labels', {}).get('alertname', ''), '')
        return F.category(uid) in self.settings['off']

    # ── алерты от Grafana ──
    def on_alert(self, payload):
        with self.lock:
            alerts = payload.get('alerts') or []
            for a in alerts:          # что сейчас горит — для /status
                fp = a.get('fingerprint') or json.dumps(a.get('labels'), sort_keys=True)
                if a.get('status') == 'firing':
                    self.state['firing'][fp] = {'labels': a.get('labels', {}), 'startsAt': a.get('startsAt'),
                                                'reason': (a.get('annotations') or {}).get('reason', '')}
                else:
                    self.state['firing'].pop(fp, None)
            alerts = [a for a in alerts if not self.muted(a) and not self.category_off(a)]
            firing = [a for a in alerts if a.get('status') == 'firing']
            resolved = [a for a in alerts if a.get('status') != 'firing']
            if not alerts:
                self.save()
                return
            key = payload.get('groupKey', '')
            fps = sorted(a.get('fingerprint', '') for a in firing)
            last = self.state['last'].get(key)
            if not resolved and last and last['fps'] == fps \
                    and time.time() - last['t'] < self.settings['repeat'] * 60 - 30:
                self.save()           # повтор того же самого — раньше, чем просили, не шлём
                return
            self.state['last'][key] = {'t': time.time(), 'fps': fps}
            gid = secrets.token_hex(4)
            msg = {'at': time.time(), 'firing': firing, 'resolved': resolved, 'copies': [],
                   'url': self._grafana_url(firing or resolved)}
            self.state['msgs'][gid] = msg
            body, rows = self.render_alert(gid)
            silent = self.quiet_now()
            for chat, topic in self.chats():
                try:
                    mid, mode = self.api.send(chat, topic, body, rows, silent)
                    msg['copies'].append([chat, mid, mode])
                except Exception as e:
                    log('bot', f'не отправилось в чат {chat}: {e}')
            self.save()

    def _grafana_url(self, alerts):
        url = (alerts[0].get('generatorURL') or '') if alerts else ''
        return url if url.startswith('https://') and '://localhost' not in url else ''

    def render_alert(self, gid):
        msg = self.state['msgs'][gid]
        body = F.alert_body(msg['firing'], msg['resolved'], self.cfg.multi)
        if not msg['firing']:
            return body, []
        mute = msg.get('mute')
        if mute and (not mute['until'] or mute['until'] > time.time()):
            body += F.muted_footer(mute['until'], mute['by'])
            rows = [[F.cb('🔔 Вернуть уведомления', f'u:{gid}', 'success'), F.cb('Подробнее', f'd:{gid}')]]
        else:
            rows = [[F.cb(f'🔕 {_mute_label(m)}', f'm:{gid}:{m}') for m in MUTE_PRESETS],
                    [F.cb('Отключить навсегда', f'm:{gid}:0', 'danger'), F.cb('Подробнее', f'd:{gid}')]]
        if msg.get('url'):
            rows.append([F.url_btn('Открыть в Grafana', msg['url'])])
        return body, rows

    def _refresh_copies(self, gid):
        body, rows = self.render_alert(gid)
        for chat, mid, mode in self.state['msgs'][gid]['copies']:
            try:
                self.api.edit(chat, mid, mode, body, rows)
            except Exception as e:
                log('bot', f'не удалось обновить сообщение в чате {chat}: {e}')

    def mute(self, gid, minutes, by):
        msg = self.state['msgs'].get(gid)
        if not msg or not msg['firing']:
            return 'Это сообщение уже не найти — заглушите из /status'
        until = FOREVER if minutes == FOREVER else time.time() + minutes * 60
        for a in msg['firing']:
            lb = a.get('labels', {})
            self.state['mutes'].append({'id': secrets.token_hex(3), 'gid': gid, 'rule': lb.get('alertname', ''),
                                        'labels': F.ident(lb), 'text': F.target(lb, self.cfg.multi),
                                        'until': until, 'by': by, 'at': time.time()})
        msg['mute'] = {'until': until, 'by': by}
        self._refresh_copies(gid)
        self.save()
        return 'Заглушено навсегда' if until == FOREVER else f'Заглушено на {_mute_label(minutes)}'

    def unmute(self, gid=None, mute_id=None):
        """Вернуть уведомления: по сообщению, по одной записи или все (mute_id='all')."""
        drop = [m for m in self.state['mutes']
                if mute_id == 'all' or m['id'] == mute_id or (gid and m.get('gid') == gid)]
        self.state['mutes'] = [m for m in self.state['mutes'] if m not in drop]
        for g in {m.get('gid') for m in drop} | ({gid} if gid else set()):
            if g in self.state['msgs'] and not any(m.get('gid') == g for m in self.state['mutes']):
                self.state['msgs'][g].pop('mute', None)
                self._refresh_copies(g)
        self.save()
        return len(drop)

    # ── подробнее ──
    def details(self, gid):
        msg = self.state['msgs'].get(gid)
        if not msg:
            return F.details_body([])
        now = datetime.now(timezone.utc)
        items = []
        for a in msg['firing'][:5]:
            lb, ann = a.get('labels', {}), a.get('annotations') or {}
            start = F.parse_time(a.get('startsAt'))
            rows = [('Правило', esc(lb.get('alertname', ''))),
                    ('Началось', F.tg_time(start, 'wDT') if start else ''),
                    ('Длится', F.duration((now - start).total_seconds()) if start else ''),
                    ('Причина', esc(ann.get('reason', ''))),
                    ('Панель', esc(lb.get('panel_title', ''))),
                    ('Адрес', esc(lb.get('address') or lb.get('ip') or lb.get('target') or ''))]
            rows += self._history(lb)
            if ann.get('description'):
                rows.append(('Что делать', esc(ann['description'])))
            items.append((F.target(lb, self.cfg.multi), rows))
        if len(msg['firing']) > 5:
            items.append((f'и ещё {len(msg["firing"]) - 5}', []))
        return F.details_body(items)

    def _history(self, lb):
        """Сколько за сутки не проходила проверка хоста — если это проверка хоста."""
        if not lb.get('name'):
            return []
        checks = [lb['check']] if lb.get('check') else ['xray']
        out = []
        for c in checks:
            try:
                r = self.prom.query(f'sum_over_time((xray_proxy_status{{name="{lb["name"]}",check="{c}"}}'
                                    f' == bool 0)[24h:1m])')
            except Exception:
                continue
            if r:
                out.append(('Не проходила за 24 ч', F.duration(r[0][1] * 60)))
        return out

    # ── /status ──
    def status_body(self):
        from .daily import check_names
        rows = []

        def q(expr):
            try:
                return {tuple(sorted(m.items())): v for m, v in self.prom.query(expr)}
            except Exception:
                return {}

        def by(expr, label):
            return {dict(k).get(label, ''): v for k, v in q(expr).items()}

        up = by('sum by (panel) (rwmon_node_connected)', 'panel')
        total = by('count by (panel) (rwmon_node_connected)', 'panel')
        for p in self.cfg.panels:
            if p.id in total:
                rows.append((f'{p.title} · ноды', up.get(p.id, 0), total[p.id]))
        names = check_names(self.cfg)
        ok = by('count by (check) (xray_proxy_status == 1)', 'check')
        allc = by('count by (check) (xray_proxy_status)', 'check')
        for c, title in names.items():
            if c in allc:
                rows.append((f'Хосты · {title}', ok.get(c, 0), allc[c]))
        su, st = by('count(rwmon_site_up == 1)', ''), by('count(rwmon_site_up)', '')
        if st:
            rows.append(('Сайты', su.get('', 0), st['']))
        blocked = by('count(rwmon_rkn_blocked == 1)', '')
        checked = by('count(rwmon_rkn_blocked)', '')
        if checked:
            rows.append(('Без блокировок РКН', checked[''] - blocked.get('', 0), checked['']))
        firing = list(self.state['firing'].values())
        muted = sum(1 for a in firing if self.muted(a))
        lines = ''.join(f'<tr><td>{"🟢" if int(a) == int(b) else "🔴"} {esc(t)}</td>'
                        f'<td align="right">{int(a)} / {int(b)}</td></tr>' for t, a, b in rows)
        body = '<h4>Состояние сейчас</h4>'
        body += f'<table bordered compact>{lines}</table>' if lines else '<p>Prometheus не ответил.</p>'
        body += f'<p>Горит алертов: <b>{len(firing)}</b>' + (f', из них заглушено {muted}' if muted else '') + '</p>'
        body += f'<footer>Обновлено {F.tg_time(time.time(), "wDT")}</footer>'
        return body, [[F.cb('🔄 Обновить', 'st:r'), F.cb('Что горит', 'st:f')]]

    def firing_body(self):
        items = []
        for a in sorted(self.state['firing'].values(), key=lambda a: a.get('startsAt') or ''):
            lb = a['labels']
            mark = '🔕 ' if self.muted(a) else ''
            start = F.parse_time(a.get('startsAt'))
            items.append(f'<li>{mark}<b>{esc(F.target(lb, self.cfg.multi))}</b> — {esc(lb.get("alertname", ""))}'
                         + (f', с {F.tg_time(start, "wDT")}' if start else '')
                         + (f' · {esc(a["reason"])}' if a.get('reason') else '') + '</li>')
        body = '<h4>Что горит</h4>' + (f'<ul>{"".join(items[:40])}</ul>' if items else '<p>Ничего, всё работает.</p>')
        return body, [[F.cb('← Назад', 'st:r')]]

    # ── /mutes ──
    def mutes_body(self):
        now = time.time()
        ms = [m for m in self.state['mutes'] if not m['until'] or m['until'] > now]
        if not ms:
            return '<h4>Заглушено: ничего</h4>', [[F.cb('🔄 Обновить', 'mu:r')]]
        rows = ''.join(f'<tr><td>{esc(m["text"])}</td><td>{esc(m["rule"])}</td><td>'
                       + ('навсегда' if not m['until'] else 'до ' + F.tg_time(m['until'], 'wDT'))
                       + f'</td><td>{esc(m["by"])}</td></tr>' for m in ms)
        buttons = [[F.cb(f'🔔 {m["text"][:28]}', f'um:{m["id"]}')] for m in ms[:12]]
        buttons.append([F.cb('Вернуть всё', 'um:all', 'success'), F.cb('🔄 Обновить', 'mu:r')])
        return (f'<h4>Заглушено: {len(ms)}</h4><table bordered compact><tr><th>Что</th><th>Сбой</th>'
                f'<th>Срок</th><th>Кто</th></tr>{rows}</table>'), buttons

    # ── /settings ──
    def settings_body(self):
        s = self.settings
        lines = ''.join(f'<tr><td>{esc(t)}</td><td>{"вкл" if k not in s["off"] else "<b>выкл</b>"}</td></tr>'
                        for k, t, _ in F.CATEGORIES)
        lines += f'<tr><td>Ежедневная сводка</td><td>{"вкл" if s["daily"] else "<b>выкл</b>"}</td></tr>'
        lines += f'<tr><td>Повтор, пока не починили</td><td>раз в {_repeat_label(s["repeat"])}</td></tr>'
        quiet = QUIET_PRESETS.get(s['quiet'], s['quiet'])
        lines += f'<tr><td>Тихие часы (без звука)</td><td>{quiet}{"" if not s["quiet"] else " · " + esc(self.cfg.bot.timezone)}</td></tr>'
        body = f'<h4>Уведомления</h4><table bordered compact>{lines}</table>'
        cats = [F.cb(('✓ ' if k not in s['off'] else '✗ ') + t, f'cf:c:{k}', 'success' if k not in s['off'] else '')
                for k, t, _ in F.CATEGORIES]
        rows = [cats[i:i + 2] for i in range(0, len(cats), 2)]
        rows.append([F.cb(('✓ ' if s['daily'] else '✗ ') + 'Ежедневная сводка', 'cf:d',
                          'success' if s['daily'] else '')])
        rows.append([F.cb(_repeat_label(m), f'cf:r:{m}', 'primary' if s['repeat'] == m else '')
                     for m in REPEAT_PRESETS])
        rows.append([F.cb('Тихо: ' + t if k else 'Без тихих часов', f'cf:q:{k}', 'primary' if s['quiet'] == k else '')
                     for k, t in QUIET_PRESETS.items()])
        return body, rows

    # ── нажатия и команды ──
    def is_admin(self, user):
        return (user or {}).get('id') in self.cfg.bot.admins

    def who(self, user):
        return (user or {}).get('first_name') or (user or {}).get('username') or str((user or {}).get('id'))

    def on_callback(self, q):
        data, user = q.get('data', ''), q.get('from')
        m = q.get('message') or {}
        chat, mid = (m.get('chat') or {}).get('id'), m.get('message_id')
        mode = 'rich' if m.get('rich_message') else 'plain'
        if not self.is_admin(user):
            return 'Кнопки — только для админов мониторинга'
        with self.lock:
            kind, _, rest = data.partition(':')
            if kind == 'm':
                gid, _, minutes = rest.partition(':')
                return self.mute(gid, int(minutes or 0), self.who(user))
            if kind == 'u':
                self.unmute(gid=rest)
                return 'Уведомления возвращены'
            if kind == 'd':
                self.api.edit(chat, mid, mode, self.details(rest), [[F.cb('← Назад', f'b:{rest}')]])
                return ''
            if kind == 'b':
                if rest in self.state['msgs']:
                    self.api.edit(chat, mid, mode, *self.render_alert(rest))
                return ''
            if kind == 'st':
                self.api.edit(chat, mid, mode, *(self.firing_body() if rest == 'f' else self.status_body()))
                return ''
            if kind in ('um', 'mu'):
                n = self.unmute(mute_id=rest) if kind == 'um' else 0
                self.api.edit(chat, mid, mode, *self.mutes_body())
                return f'Возвращено: {n}' if kind == 'um' else ''
            if kind == 'cf':
                what, _, val = rest.partition(':')
                s = self.settings
                if what == 'c':
                    s['off'] = [k for k in s['off'] if k != val] if val in s['off'] else s['off'] + [val]
                elif what == 'd':
                    s['daily'] = not s['daily']
                elif what == 'r':
                    s['repeat'] = int(val)
                elif what == 'q':
                    s['quiet'] = val if val in QUIET_PRESETS else ''
                self.save()
                self.api.edit(chat, mid, mode, *self.settings_body())
                return 'Сохранено'
        return ''

    def on_message(self, m):
        text = (m.get('text') or '').strip()
        if not text.startswith('/'):
            return
        cmd = text.split()[0][1:]
        cmd, _, at = cmd.partition('@')
        if at and self.username and at.lower() != self.username.lower():
            return                    # команда другому боту в том же чате
        if not self.is_admin(m.get('from')):
            return
        screens = {'status': self.status_body, 'mutes': self.mutes_body, 'settings': self.settings_body,
                   'start': self.status_body}
        if cmd not in screens:
            return
        chat = m['chat']['id']
        topic = m.get('message_thread_id') if m.get('is_topic_message') else None
        with self.lock:
            body, rows = screens[cmd]()
        self.api.send(chat, topic, body, rows)

    def poll_forever(self):
        try:
            me = self.api.call('getMe', {})
            self.username = me.get('username', '')
            self.api.call('setMyCommands', {'commands': [{'command': c, 'description': d} for c, d in COMMANDS]})
            log('bot', f'бот @{self.username} слушает кнопки и команды')
        except Exception as e:
            log('bot', f'бот не запустился: {e}')
        offset = None
        while True:
            try:
                params = {'timeout': 50, 'allowed_updates': ['message', 'callback_query']}
                if offset:
                    params['offset'] = offset
                updates = self.api.call('getUpdates', params, timeout=70)
            except ApiError as e:
                if 'Conflict' in str(e) or '409' in str(e):
                    log('bot', 'этого бота слушает кто-то ещё (другой сервис или копия reporter) — '
                               'кнопки не будут работать; нужен отдельный бот')
                    time.sleep(60)
                else:
                    log('bot', f'getUpdates: {e}')
                    time.sleep(5)
                continue
            for u in updates:
                offset = u['update_id'] + 1
                try:
                    if 'callback_query' in u:
                        q = u['callback_query']
                        answer = self.on_callback(q)
                        self.api.call('answerCallbackQuery', {'callback_query_id': q['id'], 'text': answer or ''})
                    elif 'message' in u:
                        self.on_message(u['message'])
                except Exception as e:
                    log('bot', f'ошибка при обработке нажатия: {e}')

    def start(self):
        threading.Thread(target=self.poll_forever, daemon=True).start()


def daily_enabled(cfg):
    """Выключена ли сводка через /settings (если бота нет — включена всегда)."""
    if not cfg.bot:
        return True
    s = read_json(f'{cfg.data_dir}/bot.json', {}).get('settings', {})
    return s.get('daily', True)


RKN_RULE = 'Блокировка РФ: адрес в списках'


def rkn_muted(cfg):
    """Для сводки: заглушён ли в боте алерт о блокировке этого адреса (target из [rkn])."""
    if not cfg.bot:
        return lambda item: False
    now = time.time()
    targets = {m['labels'].get('target') for m in read_json(f'{cfg.data_dir}/bot.json', {}).get('mutes', [])
               if m.get('rule') == RKN_RULE and (not m.get('until') or m['until'] > now)}
    return lambda item: item.get('target') in targets
