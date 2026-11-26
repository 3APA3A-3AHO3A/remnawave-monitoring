"""Ежедневная сводка: одна на все панели, уходит во все чаты панелей.

Порядок: GeoCheck (изменения наверху) → сбои за сутки → по каждой панели
пользователи и ноды.
"""
from datetime import timedelta

from . import geocheck, rkn, scan
from .clients import ApiError, Telegram
from .util import esc, gb, log, minutes, now, promql_regex

def check_names(cfg):
    """Подписи проверок сервера мониторинга: на ноду, через вход и проверки маршрутов."""
    return {'xray': 'На ноду', 'entry': 'Через вход', **{c.id: c.title for c in cfg.route_checks}}


# Итог по хосту (rwmon_host_state) → как написать в сводке
STATE_TEXT = {
    1: 'не открывался из РФ (вход и нода работали)',
    2: 'не работал вход (прокладка, CDN)',
    3: 'нода не отвечала',
    4: 'не открывался из РФ (сломан вход или заблокирован)',
}


def flag(cc):
    cc = (cc or '').upper()
    if len(cc) != 2 or not cc.isalpha():
        return ''
    return chr(0x1F1E6 + ord(cc[0]) - 65) + chr(0x1F1E6 + ord(cc[1]) - 65) + ' '


def _by(prom, expr, *labels):
    return {tuple(m.get(lab, '') for lab in labels): v for m, v in prom.query(expr)}


def collect(prom, cfg):
    """Все цифры за последние сутки. Ключи — (panel, node_uuid) и т.п."""
    tags = promql_regex(cfg.outbound_tags)
    pn = ('panel', 'node_uuid')
    d = {
        'info': {(m['panel'], m['node_uuid']): m for m, _ in
                 prom.query('topk by (panel, node_uuid) (1, rwmon_node_info)')},
        'now': _by(prom, 'rwmon_node_online_users', *pn),
        'peak': _by(prom, 'max_over_time(rwmon_node_online_users[24h])', *pn),
        'traffic': _by(prom, 'sum by (panel, node_uuid) (increase(rwmon_node_inbound_upload_bytes[24h])'
                             ' + increase(rwmon_node_inbound_download_bytes[24h]))', *pn),
        # трафик клиентов по направлениям и сеть сервера ноды (всё, что принял и отдал сервер)
        'down': _by(prom, 'sum by (panel, node_uuid) (increase(rwmon_node_inbound_download_bytes[24h]))', *pn),
        'up': _by(prom, 'sum by (panel, node_uuid) (increase(rwmon_node_inbound_upload_bytes[24h]))', *pn),
        'net_rx': _by(prom, 'sum by (panel, node_uuid) (increase(rwmon_node_network_rx_bytes[24h]))', *pn),
        'net_tx': _by(prom, 'sum by (panel, node_uuid) (increase(rwmon_node_network_tx_bytes[24h]))', *pn),
        'offline': _by(prom, 'sum by (panel, node_uuid) '
                             '(sum_over_time((rwmon_node_connected == bool 0)[24h:1m]))', *pn),
        'outbound': {},
        'status': _by(prom, 'rwmon_users', 'panel', 'status'),
        'online': _by(prom, 'rwmon_users_online', 'panel', 'period'),
        'total': _by(prom, 'rwmon_users_total', 'panel'),
        'panel_down': _by(prom, 'sum by (panel) (sum_over_time((rwmon_panel_up == bool 0)[24h:1m]))', 'panel'),
        'checks': [],
        'sites_down': _by(prom, 'sum by (site) (sum_over_time((rwmon_site_up == bool 0)[24h:1m]))', 'site'),
        'sites_ru_down': _by(prom, 'sum by (site) (sum_over_time((max by (site) '
                                   '(probe_success{kind="http"}) == bool 0)[24h:1m]))', 'site'),
        'site_cert': _by(prom, '(rwmon_site_cert_expiry_timestamp_seconds - time()) / 86400', 'site'),
        'site_up': _by(prom, 'rwmon_site_up', 'site'),
        'states': [],
        # сколько минут за сутки проба из РФ не присылала результаты
        'probe_silent': _by(prom, 'sum by (probe) (sum_over_time((rwmon_ru_probe_up == bool 0)[24h:1m]))',
                            'probe'),
    }
    for code in STATE_TEXT:                      # сколько минут за сутки хост был в этом итоге
        for m, v in prom.query(f'rwmon_host * on (name) group_left () sum by (name) '
                               f'(sum_over_time((rwmon_host_state == bool {code})[24h:1m]))'):
            if v > 0:
                d['states'].append((m.get('panel', ''), m.get('host', '?'), m.get('name', ''), code, v))
    for m, v in prom.query(
            f'sum by (panel, node_uuid, tag) (increase(rwmon_node_outbound_upload_bytes{{tag=~{tags}}}[24h])'
            f' + increase(rwmon_node_outbound_download_bytes{{tag=~{tags}}}[24h]))'):
        d['outbound'].setdefault((m.get('panel'), m.get('node_uuid')), {})[m.get('tag')] = v
    for check in [c.id for c in cfg.route_checks]:   # сколько минут за сутки не проходила проверка маршрута
        hosts = f'rwmon_host{{{check}="1"}}'
        for m, v in prom.query(
                f'{hosts} * on (name) group_left () '
                f'sum by (name) (sum_over_time((xray_proxy_status{{check="{check}"}} == bool 0)[24h:1m]))'):
            if v > 0:
                d['checks'].append((m.get('panel', ''), m.get('host', '?'), m.get('name', ''), check, v))
    return d


def panel_extras(rw):
    """Из API: новые/истёкшие за сутки. Нет права — тихо пропускаем."""
    out = {'digest': None}
    end = now().replace(microsecond=0)
    try:
        out['digest'] = rw.digest((end - timedelta(days=1)).isoformat(), end.isoformat())
    except ApiError:
        pass
    return out


def merged_name(hosts, cfg):
    """Один сервер в двух панелях (через маппер) — одной строкой:
    «Канада · FixErrorVPN + OVRO» или «Швеция 2 · OVRO / Швеция 3 · FixErrorVPN»."""
    titles = {p.id: p.title for p in cfg.panels}
    hosts = sorted(set(hosts), key=lambda x: (x[1], x[0]))
    if not cfg.multi:
        return hosts[0][1]
    names = {h for _, h in hosts}
    if len(names) == 1:
        return f'{hosts[0][1]} · ' + ' + '.join(titles.get(p, p) for p, _ in hosts)
    return ' / '.join(f'{h} · {titles.get(p, p)}' for p, h in hosts)


def problem_lines(d, cfg):
    """Строки «Сбои за сутки» и сколько коротких сбоев свернуть в одну строку."""
    lim = cfg.short_minutes
    out, short = [], 0

    def add(label, text, mins):
        nonlocal short
        if mins <= lim:
            short += 1
        else:
            out.append((label, f'• {esc(label)} — {text}, {minutes(mins)}'))

    for p in cfg.panels:
        mins = d['panel_down'].get((p.id,), 0)
        if mins > cfg.panel_down_minutes:
            out.append(('', f'• {esc(p.title)} — API панели был недоступен, {minutes(mins)}'))
    for (pid, uid), mins in d['offline'].items():
        info = d['info'].get((pid, uid))
        if mins >= 1 and info:
            add(_node_name(info, cfg), 'отключалась от панели', mins)
    checks = {}                     # один сервер в двух панелях проверяется один раз
    for pid, host, name, check, mins in d['checks']:
        c = checks.setdefault((name or f'{pid}:{host}', check), {'hosts': [], 'mins': mins})
        c['hosts'].append((pid, host))
    for (_, check), c in checks.items():
        add(f'{merged_name(c["hosts"], cfg)} · {check_names(cfg).get(check, check)}', 'не проходила проверка',
            c['mins'])
    states = {}                     # итог по хосту: один сервер в двух панелях — одной строкой
    for pid, host, name, code, mins in d.get('states') or []:
        st = states.setdefault((name or f'{pid}:{host}', code), {'hosts': [], 'mins': mins})
        st['hosts'].append((pid, host))
    for (_, code), st in states.items():
        add(merged_name(st['hosts'], cfg), STATE_TEXT.get(code, 'не работал'), st['mins'])
    for (site,), mins in (d.get('sites_down') or {}).items():
        if mins >= 1:
            add(f'🌐 {site}', 'не открывался', mins)
    for (site,), mins in (d.get('sites_ru_down') or {}).items():
        if mins >= 1:
            add(f'🌐 {site}', 'не открывался из РФ', mins)
    lines = [text for _, text in sorted(out, key=lambda x: x[0])]
    for (probe,), mins in sorted((d.get('probe_silent') or {}).items()):
        if mins >= 5:
            lines.append(f'• Проба из РФ «{esc(probe)}» не присылала результаты — {minutes(mins)}')
    return lines, short


def build_text(d, extras, geo_run, cfg):
    lines = ['📊 <b>Сводка за сутки</b>', f'<i>{now():%d.%m.%Y %H:%M} UTC</i>', '']
    if not d['info']:
        lines += ['❗️ <b>Нет данных о нодах в Prometheus</b> — проверьте: '
                  '<code>docker compose exec reporter python -m rwmon check</code>', '']

    lines += geocheck.telegram_section(geo_run)
    if cfg.rkn_enabled:
        lines += rkn.telegram_section(rkn.load_last(cfg))
        if cfg.rkn_token:
            lines += scan.telegram_section(scan.load(cfg))
    lines.append('')

    # Сбои
    problems, short = problem_lines(d, cfg)
    if problems:
        lines.append('⚠️ <b>Сбои за сутки</b>')
    else:
        lines.append('✅ <b>Сбоев за сутки не было</b>' if not short else '✅ <b>Серьёзных сбоев за сутки не было</b>')
    lines += problems
    if short:
        lines.append(f'<i>{"и ещё " if problems else ""}{short} коротких (до {cfg.short_minutes} мин) — '
                     'перезапуски и минутные обрывы, без подробностей</i>')
    if d.get('site_up'):
        parts = []
        for (site,), up in sorted(d['site_up'].items()):
            days = (d.get('site_cert') or {}).get((site,))
            cert = f', сертификат {int(days)} дн.' if days is not None else ''
            parts.append(f'{esc(site)} {"✅" if up else "❌"}{cert}')
        lines += ['', '🌐 ' + ' · '.join(parts)]

    # По панелям
    for p in cfg.panels:
        pid = p.id
        lines += ['', f'🗂 <b>{esc(p.title)}</b>']
        st = {s: v for (x, s), v in d['status'].items() if x == pid}
        on = {s: v for (x, s), v in d['online'].items() if x == pid}
        total = d['total'].get((pid,))
        if st or on:
            lines.append(f'👥 онлайн <b>{int(on.get("onlineNow", 0))}</b> · за сутки {int(on.get("lastDay", 0))}'
                         f' · активных <b>{int(st.get("ACTIVE", 0))}</b> · истёкших {int(st.get("EXPIRED", 0))}'
                         + (f' · всего {int(total)}' if total is not None else ''))
        dg = (extras.get(pid) or {}).get('digest')
        if dg:
            u = dg.get('users') or {}
            lines.append(f'🆕 новых за сутки: {u.get("createdCount", 0)} · истекло: {u.get("expiredCount", 0)}')
        nodes = sorted(((uid, m) for (x, uid), m in d['info'].items() if x == pid),
                       key=lambda kv: kv[1].get('node_name', ''))
        for uid, m in nodes:
            k = (pid, uid)
            parts = [f'{int(d["now"].get(k, 0))} / {int(d["peak"].get(k, 0))}', gb(d['traffic'].get(k, 0))]
            parts += [f'{esc(t)} {gb(v)}' for t, v in sorted((d['outbound'].get(k) or {}).items())]
            lines.append(f'• {flag(m.get("country"))}{esc(m.get("node_name", uid))} — ' + ' · '.join(parts))
        if nodes:
            lines.append('<i>клиентов сейчас / пик за сутки · трафик клиентов · аутбаунды</i>')
    return '\n'.join(lines)


def _node_name(info, cfg):
    name = info.get('node_name', '?')
    return f'{name} · {info.get("panel_title")}' if cfg.multi else name


def send(prom, clients, cfg, dry_run=False, done=None):
    """Отправить сводку во все чаты: короткое сообщение + полный HTML-отчёт файлом.
    С ботом ([bot]) — rich-сообщение с раскрывающимися блоками, без бота — как раньше.
    done — список уже доставленных частей («чат:text», «чат:doc») за сегодня:
    при повторе после сбоя они не дублируются."""
    from . import alertfmt, bot as botmod, report
    from .config import Telegram as TgConfig
    if cfg.bot and not botmod.daily_enabled(cfg) and not dry_run:
        log('report', 'сводка выключена в /settings бота — не отправляю')
        return None, None
    data = collect(prom, cfg)
    extras = {p.id: panel_extras(clients[p.id]) for p in cfg.panels}
    geo_run = geocheck.load_last(cfg)
    today = now().strftime('%Y-%m-%d')
    if geo_run and geo_run.get('date') != today:
        geo_run = None                    # вчерашний прогон в сегодняшнюю сводку не берём
    rkn_data = rkn.load_last(cfg) if cfg.rkn_enabled else None
    muted = botmod.rkn_muted(cfg)
    try:
        tl = report.timeline(prom, data, cfg)
    except Exception as e:                # без ленты отчёт всё равно нужен
        log('report', f'лента сбоев не собралась: {e}')
        tl = None
    html = report.full_html(data, extras, geo_run, rkn_data, cfg, tl, muted)
    fname = f'monitoring-{today}.html'
    body = report.summary_rich(data, extras, geo_run, rkn_data, cfg, muted) if cfg.bot else None
    text = alertfmt.plain(body) if body else build_text(data, extras, geo_run, cfg)
    if dry_run:
        print(text)
        print(f'\n[+ файл {fname}, {len(html) // 1024} КБ]')
        return text, html
    done = [] if done is None else done
    errors = []
    chats = {}
    for tg in cfg.chats():                 # с ботом — один бот на все чаты
        tg = TgConfig(cfg.bot.token, tg.chat_id, tg.topic_id) if cfg.bot else tg
        chats.setdefault((tg.chat_id, tg.topic_id), tg)
    for tg in chats.values():
        chat = f'{tg.chat_id}/{tg.topic_id}'
        sender = Telegram(tg)
        if cfg.bot:
            api = botmod.Api(cfg.bot.token)
            send_text = (lambda api=api, tg=tg: api.send(tg.chat_id, tg.topic_id, body, []))
        else:
            send_text = (lambda sender=sender: sender.send(text))
        parts = [('text', send_text),
                 ('doc', lambda sender=sender: sender.send_document(fname, html, caption='📄 Полный отчёт за сутки'))]
        for part, fn in parts:
            key = f'{chat}:{part}'
            if key in done:
                continue
            try:
                fn()
                done.append(key)
            except ApiError as e:
                errors.append(f'{chat}: {e}')
                break                     # файл без текста не шлём — повторим оба позже
    if errors:
        raise ApiError('не доставлено: ' + '; '.join(errors))
    log('report', f'сводка отправлена в {len(chats)} чат(а)')
    return text, html
