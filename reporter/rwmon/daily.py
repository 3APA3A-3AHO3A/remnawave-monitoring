"""Ежедневная сводка в Telegram: GeoCheck, сбои, пользователи, ноды."""
from . import geocheck
from .util import esc, gb, log, minutes, now


def flag(cc):
    cc = (cc or '').upper()
    if len(cc) != 2 or not cc.isalpha():
        return ''
    return chr(0x1F1E6 + ord(cc[0]) - 65) + chr(0x1F1E6 + ord(cc[1]) - 65) + ' '


def collect(prom, cfg):
    """Все цифры за последние 24 часа одним набором запросов к Prometheus."""
    tags = cfg.outbound_tags
    d = {
        'now': prom.by('remnawave_node_online_users', 'node_uuid'),
        'peak': prom.by('max_over_time(remnawave_node_online_users[24h])', 'node_uuid'),
        'traffic': prom.by('sum by (node_uuid) (increase(remnawave_node_inbound_upload_bytes[24h])'
                           ' + increase(remnawave_node_inbound_download_bytes[24h]))', 'node_uuid'),
        'offline': prom.by('sum by (node_uuid) (sum_over_time((remnawave_node_status == bool 0)[24h:1m]))',
                           'node_uuid'),
        'status': prom.by('remnawave_users_status', 'status'),
        'online': prom.by('remnawave_users_online_stats', 'metricType'),
        'total': prom.by('remnawave_users_total', 'type').get('all'),
        'total_before': prom.by('remnawave_users_total offset 24h', 'type').get('all'),
        'outbound': {},
        'checks': [],
    }
    for m, v in prom.query(
            f'sum by (node_uuid, tag) (increase(remnawave_node_outbound_upload_bytes{{tag=~"{tags}"}}[24h])'
            f' + increase(remnawave_node_outbound_download_bytes{{tag=~"{tags}"}}[24h]))'):
        d['outbound'].setdefault(m.get('node_uuid'), {})[m.get('tag')] = v
    for m, v in prom.query('sum by (check, name) (sum_over_time((xray_proxy_status == bool 0)[24h:1m]))'):
        if v > 0:
            d['checks'].append((m.get('name', '?'), m.get('check', '?'), v))
    return d


CHECK_NAMES = {'xray': 'Xray', 'warp': 'WARP', 'psiphon': 'Psiphon'}


def build_text(d, nodes, geo_run, cfg):
    stamp = now()
    head = '📊 <b>Сводка за сутки</b>'
    if cfg.panel_name:
        head += f' · {esc(cfg.panel_name)}'
    lines = [head, f'<i>{stamp:%d.%m.%Y %H:%M} UTC</i>', '']
    if not d['status'] and not d['peak']:
        lines += ['❗️ <b>Нет метрик панели в Prometheus</b> — цифры ниже пустые. '
                  'Проверьте: <code>docker compose exec reporter python -m rwmon check</code>', '']

    # GeoCheck — наверху, изменения подсвечены
    lines += geocheck.telegram_section(geo_run)
    lines.append('')

    # Сбои
    active = [n for n in nodes if not n.get('isDisabled')]
    problems = []
    for n in active:
        off = d['offline'].get(n['uuid'], 0)
        if off >= 1:
            problems.append(f'• {esc(n["name"])} — отключалась от панели, {minutes(off)}')
    for name, check, mins in sorted(d['checks']):
        problems.append(f'• {esc(name)} · {CHECK_NAMES.get(check, check)} — не проходила проверка, {minutes(mins)}')
    if problems:
        lines.append('⚠️ <b>Сбои за сутки</b>')
        lines += problems
    else:
        lines.append('✅ <b>Сбоев за сутки не было</b>')
    lines.append('')

    # Пользователи
    st, on = d['status'], d['online']
    total, before = d['total'], d['total_before']
    growth = ''
    if total is not None and before is not None and total != before:
        growth = f' ({int(total - before):+d} за сутки)'
    lines.append('👥 <b>Пользователи</b>')
    lines.append(f'Онлайн сейчас: <b>{int(on.get("onlineNow", 0))}</b> · заходили за сутки: '
                 f'<b>{int(on.get("lastDay", 0))}</b> · за неделю: {int(on.get("lastWeek", 0))}')
    lines.append(f'Активных: <b>{int(st.get("ACTIVE", 0))}</b> · истёкших: {int(st.get("EXPIRED", 0))} · '
                 f'лимит: {int(st.get("LIMITED", 0))} · отключённых: {int(st.get("DISABLED", 0))}')
    if total is not None:
        lines.append(f'Всего: {int(total)}{growth}')
    lines.append('')

    # Ноды
    lines.append('🖥 <b>Ноды</b> <i>(сейчас / пик за сутки · трафик клиентов)</i>')
    for n in sorted(active, key=lambda x: x.get('name', '')):
        uid = n['uuid']
        if uid not in d['peak'] and uid not in d['traffic']:
            lines.append(f'• {flag(n.get("countryCode"))}{esc(n["name"])} — нет данных')
            continue
        parts = [f'{int(d["now"].get(uid, 0))} / {int(d["peak"].get(uid, 0))}',
                 gb(d['traffic'].get(uid, 0))]
        for tag, v in sorted((d['outbound'].get(uid) or {}).items()):
            parts.append(f'{esc(tag)} {gb(v)}')
        lines.append(f'• {flag(n.get("countryCode"))}{esc(n["name"])} — ' + ' · '.join(parts))
    return '\n'.join(lines)


def send(prom, rw, tg, cfg, dry_run=False):
    nodes = rw.nodes()
    data = collect(prom, cfg)
    geo_run = geocheck.load_last(cfg)
    today = now().strftime('%Y-%m-%d')
    if geo_run and geo_run.get('date') != today:
        geo_run = None                    # вчерашний прогон в сегодняшнюю сводку не берём
    text = build_text(data, nodes, geo_run, cfg)
    html = None
    if geo_run and geo_run.get('results'):
        title = 'GeoCheck' + (f' · {cfg.panel_name}' if cfg.panel_name else '') + f' · {today}'
        html = geocheck.html_report(geo_run, cfg, title)
    if dry_run:
        print(text)
        if html:
            print(f'\n[+ файл geocheck-{today}.html, {len(html) // 1024} КБ]')
        return text, html
    tg.send(text)
    if html:
        tg.send_document(f'geocheck-{today}.html', html, caption='🌍 Полный отчёт GeoCheck')
    log('report', 'сводка отправлена')
    return text, html
