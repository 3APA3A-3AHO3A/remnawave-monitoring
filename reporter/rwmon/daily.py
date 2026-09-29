"""Ежедневная сводка: одна на все панели, уходит во все чаты панелей.

Порядок: GeoCheck (изменения наверху) → сбои за сутки → по каждой панели
пользователи и ноды → ближайшие оплаты серверов (если ведутся в панели).
"""
from datetime import timedelta

from . import geocheck
from .clients import ApiError, Telegram
from .util import esc, gb, log, minutes, now, promql_regex

CHECK_NAMES = {'xray': 'Подключение', 'warp': 'WARP', 'psiphon': 'Psiphon'}
BILLING_DAYS = 7


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
        'offline': _by(prom, 'sum by (panel, node_uuid) '
                             '(sum_over_time((rwmon_node_connected == bool 0)[24h:1m]))', *pn),
        'outbound': {},
        'status': _by(prom, 'rwmon_users', 'panel', 'status'),
        'online': _by(prom, 'rwmon_users_online', 'panel', 'period'),
        'total': _by(prom, 'rwmon_users_total', 'panel'),
        'panel_up': _by(prom, 'min_over_time(rwmon_panel_up[24h])', 'panel'),
        'checks': [],
        'sites_down': _by(prom, 'sum by (site) (sum_over_time((rwmon_site_up == bool 0)[24h:1m]))', 'site'),
        'sites_ru_down': _by(prom, 'sum by (site) (sum_over_time((max by (site) '
                                   '(probe_success{kind="http"}) == bool 0)[24h:1m]))', 'site'),
        'site_cert': _by(prom, '(rwmon_site_cert_expiry_timestamp_seconds - time()) / 86400', 'site'),
        'site_up': _by(prom, 'rwmon_site_up', 'site'),
        'probe_blocked': [],
    }
    for m, v in prom.query('rwmon_host * on (address) group_left () sum by (address) (sum_over_time('
                           '(max by (address) (probe_success{kind="tcp"}) == bool 0)[24h:1m]))'):
        if v > 0:
            d['probe_blocked'].append((m.get('panel', ''), m.get('host', '?'), v))
    for m, v in prom.query(
            f'sum by (panel, node_uuid, tag) (increase(rwmon_node_outbound_upload_bytes{{tag=~{tags}}}[24h])'
            f' + increase(rwmon_node_outbound_download_bytes{{tag=~{tags}}}[24h]))'):
        d['outbound'].setdefault((m.get('panel'), m.get('node_uuid')), {})[m.get('tag')] = v
    for check in CHECK_NAMES:                     # сколько минут за сутки проверка не проходила
        hosts = 'rwmon_host' if check == 'xray' else 'rwmon_host{lite="0"}'
        for m, v in prom.query(
                f'{hosts} * on (name) group_left () '
                f'sum by (name) (sum_over_time((xray_proxy_status{{check="{check}"}} == bool 0)[24h:1m]))'):
            if v > 0:
                d['checks'].append((m.get('panel', ''), m.get('host', '?'), check, v))
    return d


def panel_extras(rw):
    """Из API: новые/истёкшие за сутки и ближайшие оплаты. Нет прав — тихо пропускаем."""
    out = {'digest': None, 'billing': []}
    end = now().replace(microsecond=0)
    try:
        out['digest'] = rw.digest((end - timedelta(days=1)).isoformat(), end.isoformat())
    except ApiError:
        pass
    try:
        soon = end + timedelta(days=BILLING_DAYS)
        for b in rw.billing_nodes().get('billingNodes') or []:
            at = b.get('nextBillingAt') or ''
            if at and at[:19] <= soon.strftime('%Y-%m-%dT%H:%M:%S'):
                name = (b.get('node') or {}).get('name') or b.get('name') or '?'
                out['billing'].append((at[:10], name, (b.get('provider') or {}).get('name', '')))
    except ApiError:
        pass
    return out


def build_text(d, extras, geo_run, cfg):
    lines = ['📊 <b>Сводка за сутки</b>', f'<i>{now():%d.%m.%Y %H:%M} UTC</i>', '']
    if not d['info']:
        lines += ['❗️ <b>Нет данных о нодах в Prometheus</b> — проверьте: '
                  '<code>docker compose exec reporter python -m rwmon check</code>', '']

    lines += geocheck.telegram_section(geo_run)
    lines.append('')

    # Сбои
    problems = []
    for p in cfg.panels:
        if d['panel_up'].get((p.id,), 1) < 1:
            problems.append(f'• {esc(p.title)} — API панели был недоступен')
    for (pid, uid), mins in sorted(d['offline'].items()):
        info = d['info'].get((pid, uid))
        if mins >= 1 and info:
            problems.append(f'• {esc(_node_name(info, cfg))} — отключалась от панели, {minutes(mins)}')
    titles = {p.id: p.title for p in cfg.panels}
    for pid, host, check, mins in sorted(d['checks'], key=lambda x: (x[1], x[0], x[2])):
        where = f' · {titles.get(pid, pid)}' if cfg.multi else ''
        problems.append(f'• {esc(host)}{esc(where)} · {CHECK_NAMES.get(check, check)} — '
                        f'не проходила проверка, {minutes(mins)}')
    for pid, host, mins in sorted(d.get('probe_blocked') or [], key=lambda x: (x[1], x[0])):
        where = f' · {titles.get(pid, pid)}' if cfg.multi else ''
        problems.append(f'• {esc(host)}{esc(where)} — не открывался из РФ, {minutes(mins)}')
    for (site,), mins in sorted((d.get('sites_down') or {}).items()):
        if mins >= 1:
            problems.append(f'• 🌐 {esc(site)} — не открывался, {minutes(mins)}')
    for (site,), mins in sorted((d.get('sites_ru_down') or {}).items()):
        if mins >= 1:
            problems.append(f'• 🌐 {esc(site)} — не открывался из РФ, {minutes(mins)}')
    lines.append('⚠️ <b>Сбои за сутки</b>' if problems else '✅ <b>Сбоев за сутки не было</b>')
    lines += problems
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
        for day, name, provider in sorted((extras.get(pid) or {}).get('billing') or []):
            lines.append(f'💳 оплата {day[8:10]}.{day[5:7]} — {esc(name)}' + (f' ({esc(provider)})' if provider else ''))
    return '\n'.join(lines)


def _node_name(info, cfg):
    name = info.get('node_name', '?')
    return f'{name} · {info.get("panel_title")}' if cfg.multi else name


def send(prom, clients, cfg, dry_run=False, done=None):
    """Отправить сводку во все чаты. done — список уже доставленных частей
    («чат:text», «чат:doc») за сегодня: при повторе после сбоя они не дублируются."""
    data = collect(prom, cfg)
    extras = {p.id: panel_extras(clients[p.id]) for p in cfg.panels}
    geo_run = geocheck.load_last(cfg)
    today = now().strftime('%Y-%m-%d')
    if geo_run and geo_run.get('date') != today:
        geo_run = None                    # вчерашний прогон в сегодняшнюю сводку не берём
    text = build_text(data, extras, geo_run, cfg)
    html = None
    if geo_run and geo_run.get('results'):
        html = geocheck.html_report(geo_run, cfg, f'GeoCheck · {today}')
    if dry_run:
        print(text)
        if html:
            print(f'\n[+ файл geocheck-{today}.html, {len(html) // 1024} КБ]')
        return text, html
    done = [] if done is None else done
    errors = []
    for tg in cfg.chats():
        chat = f'{tg.chat_id}/{tg.topic_id}'
        bot = Telegram(tg)
        parts = [('text', lambda: bot.send(text))]
        if html:
            parts.append(('doc', lambda: bot.send_document(f'geocheck-{today}.html', html,
                                                           caption='🌍 Полный отчёт GeoCheck')))
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
    log('report', f'сводка отправлена в {len(cfg.chats())} чат(а)')
    return text, html
