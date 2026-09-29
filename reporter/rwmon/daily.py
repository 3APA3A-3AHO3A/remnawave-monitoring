"""Ежедневная сводка: одна на все панели, уходит во все чаты панелей.

Порядок: GeoCheck (изменения наверху) → сбои за сутки → по каждой панели
пользователи и ноды → ближайшие оплаты серверов (если ведутся в панели).
"""
from datetime import timedelta

from . import geocheck
from .clients import ApiError, Telegram
from .util import esc, gb, log, minutes, now

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
    tags = '|'.join(cfg.outbound_tags)
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
    }
    for m, v in prom.query(
            f'sum by (panel, node_uuid, tag) (increase(rwmon_node_outbound_upload_bytes{{tag=~"{tags}"}}[24h])'
            f' + increase(rwmon_node_outbound_download_bytes{{tag=~"{tags}"}}[24h]))'):
        d['outbound'].setdefault((m.get('panel'), m.get('node_uuid')), {})[m.get('tag')] = v
    for m, v in prom.query('sum by (panel, check, name) '
                           '(sum_over_time((xray_proxy_status == bool 0)[24h:1m]))'):
        if v > 0:
            d['checks'].append((m.get('panel', ''), m.get('name', '?'), m.get('check', '?'), v))
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
    for pid, name, check, mins in sorted(d['checks'], key=lambda x: (x[1], x[2])):
        problems.append(f'• {esc(name)} · {CHECK_NAMES.get(check, check)} — не проходила проверка, {minutes(mins)}')
    lines.append('⚠️ <b>Сбои за сутки</b>' if problems else '✅ <b>Сбоев за сутки не было</b>')
    lines += problems

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


def send(prom, clients, cfg, dry_run=False):
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
    errors = []
    for tg in cfg.chats():
        try:
            bot = Telegram(tg)
            bot.send(text)
            if html:
                bot.send_document(f'geocheck-{today}.html', html, caption='🌍 Полный отчёт GeoCheck')
        except ApiError as e:
            errors.append(str(e))
    if errors and len(errors) == len(cfg.chats()):
        raise ApiError('; '.join(errors))
    for e in errors:
        log('report', f'в один из чатов не отправлено: {e}')
    log('report', f'сводка отправлена в {len(cfg.chats()) - len(errors)} чат(а)')
    return text, html
