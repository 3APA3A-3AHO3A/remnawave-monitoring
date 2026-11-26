"""Ежедневная сводка для бота (короткая, подробности — в сворачиваемых блоках)
и единый HTML-отчёт за сутки: ноды и трафик, лента сбоев, GeoCheck, сайты,
сертификаты, блокировки РКН. Данные собирает daily.collect()."""
import base64
import os
import time
from datetime import datetime, timezone

from . import alertfmt as F, geocheck
from .daily import check_names, flag, merged_name, problem_lines
from .util import esc, gb, log, now

DAY = 86400
STEP = 120                        # шаг ленты сбоев, секунд


# ── общие кусочки ───────────────────────────────────────────

def nodes(d, pid):
    """Ноды панели с цифрами за сутки, по алфавиту."""
    out = []
    for (x, uid), m in d['info'].items():
        if x != pid:
            continue
        k = (pid, uid)
        out.append({'name': m.get('node_name', uid), 'country': m.get('country', ''),
                    'now': int(d['now'].get(k, 0)), 'peak': int(d['peak'].get(k, 0)),
                    'down': d.get('down', {}).get(k, 0), 'up': d.get('up', {}).get(k, 0),
                    'net_rx': d.get('net_rx', {}).get(k), 'net_tx': d.get('net_tx', {}).get(k),
                    'traffic': d['traffic'].get(k, 0), 'outbound': d['outbound'].get(k) or {}})
    return sorted(out, key=lambda n: n['name'])


def users(d, extras, pid):
    st = {s: v for (x, s), v in d['status'].items() if x == pid}
    on = {s: v for (x, s), v in d['online'].items() if x == pid}
    dg = ((extras.get(pid) or {}).get('digest') or {}).get('users') or {}
    return {'online': int(on.get('onlineNow', 0)), 'day': int(on.get('lastDay', 0)),
            'active': int(st.get('ACTIVE', 0)), 'expired': int(st.get('EXPIRED', 0)),
            'total': d['total'].get((pid,)), 'new': dg.get('createdCount'), 'gone': dg.get('expiredCount')}


def _longest(d, cfg):
    """Самый долгий сбой за сутки: (название, минуты) или None. Один сервер в двух панелях — одной строкой."""
    hosts, best = {}, None
    for pid, host, name, check, mins in list(d['checks']) + list(d.get('states') or []):
        h = hosts.setdefault((name or f'{pid}:{host}', check), {'hosts': [], 'mins': mins})
        h['hosts'].append((pid, host))
    for h in hosts.values():
        if not best or h['mins'] > best[1]:
            best = (merged_name(h['hosts'], cfg), h['mins'])
    for (pid, uid), mins in d['offline'].items():
        info = d['info'].get((pid, uid))
        if info and mins >= 1 and (not best or mins > best[1]):
            best = (info.get('node_name', uid), mins)
    return best


def _cert_min(d):
    vals = [v for v in (d.get('site_cert') or {}).values() if v is not None]
    return int(min(vals)) if vals else None


def _sites_bad(d):
    return [site for (site,), up in (d.get('site_up') or {}).items() if not up]


def _geo_counts(geo_run):
    if not geo_run:
        return None
    rs = list(geo_run['results'].values())
    return {'changed': sum(len(r.get('changes') or []) for r in rs),
            'minor': sum(len(r.get('minor') or []) for r in rs),
            'new_bad': sum(len(r.get('attention_new') or []) for r in rs),
            'failed': sum(1 for r in rs if not r['ok']), 'nodes': len(rs)}


def rkn_blocked(rkn_data, muted=lambda item: False):
    items = (rkn_data or {}).get('items') or []
    blocked = [x for x in items if x.get('blocked')]
    return [x for x in blocked if not muted(x)], [x for x in blocked if muted(x)], items


# ── сводка в Telegram (rich) ────────────────────────────────

OVERLOAD_MIN = 15       # перегрузка короче — не повод для «внимания»
CERT_WARN_DAYS = 30


def _node_label(d, key, cfg):
    m = d['info'].get(key) or {}
    name = m.get('node_name') or key[1]
    return f'{name} ({m.get("panel_title", key[0])})' if cfg.multi else name


def attention(d, geo_run, rkn_data, scan_data, cfg, rkn_muted=lambda item: False):
    """Что требует внимания — короткие строки (HTML), самое важное первым."""
    from .render import GEODATA_STALE_DAYS
    out = []
    bad_sites = _sites_bad(d)
    if bad_sites:
        out.append('не открываются сайты: ' + esc(', '.join(bad_sites)))
    if cfg.rkn_enabled and rkn_data:
        live, _, _ = rkn_blocked(rkn_data, rkn_muted)
        if live:
            out.append('в списках блокировок: ' + esc(', '.join(x['name'] for x in live)))
    blocked = [x for x in ((scan_data or {}).get('items') or {}).values() if x.get('blocked')]
    if blocked:
        out.append('сканеры в сетях РФ видят блокировку: ' + esc(', '.join(sorted(x['name'] for x in blocked))))
    for key, mins in sorted((d.get('overload') or {}).items(), key=lambda kv: -kv[1]):
        if mins >= OVERLOAD_MIN and key in d['info']:
            out.append(f'нода {esc(_node_label(d, key, cfg))} перегружалась {F.duration(mins * 60)} за сутки')
    old = [(k, v) for k, v in (d.get('geo_age') or {}).items() if v > GEODATA_STALE_DAYS and k in d['info']]
    if old:
        out.append('geo-базы не обновляются: ' + esc(', '.join(f'{_node_label(d, k, cfg)} — {int(v)} дн.'
                                                                for k, v in sorted(old))))
    reboot = sorted(_node_label(d, k, cfg) for k, v in (d.get('reboot') or {}).items() if v and k in d['info'])
    if reboot:
        out.append('нужна перезагрузка после обновлений: ' + esc(', '.join(reboot)))
    cert = _cert_min(d)
    if cert is not None and cert < CERT_WARN_DAYS:
        out.append(f'сертификат сайта истекает через {cert} дн.')
    geo = _geo_counts(geo_run)
    if geo and geo['new_bad']:
        out.append(f'GeoCheck: новых проблем {geo["new_bad"]}')
    return out


def _work_line(windows):
    if not windows:
        return ''
    spans = ', '.join(f'{F.tg_time(a)}–{F.tg_time(b)}' for a, b in windows)
    return f'<p>🛠 Работы: {spans} — сбои в это время из-за работ</p>'

def _num(n):
    return '—' if n is None else str(int(n))


def summary_rich(d, extras, geo_run, rkn_data, cfg, rkn_muted=lambda item: False, scan_data=None, work=()):
    out = [f'<h3>📊 Сводка за {now():%d.%m}</h3>']
    if not d['info']:
        out.append('<p>❗️ <b>Нет данных о нодах в Prometheus</b> — проверьте: '
                   '<code>docker compose exec reporter python -m rwmon check</code></p>')
    att = attention(d, geo_run, rkn_data, scan_data, cfg, rkn_muted)
    problems, short = problem_lines(d, cfg)
    if att:
        out.append(f'<p>⚠️ <b>Требует внимания: {len(att)}</b></p><ul>'
                   + ''.join(f'<li>{x}</li>' for x in att) + '</ul>')
    elif not problems:
        out.append('<p>✅ <b>Всё в порядке</b></p>')
    rows = ''.join(
        f'<tr><td>{esc(p.title)}</td><td align="right">{u["online"]}</td><td align="right">{u["day"]}</td>'
        f'<td align="right">↓{gb(sum(n["down"] for n in ns))}</td>'
        f'<td align="right">↑{gb(sum(n["up"] for n in ns))}</td></tr>'
        for p in cfg.panels for u, ns in [(users(d, extras, p.id), nodes(d, p.id))])
    out.append('<table bordered compact><tr><th>Панель</th><th>онлайн</th><th>за сутки</th>'
               f'<th>к клиентам</th><th>от клиентов</th></tr>{rows}</table>')

    if problems:
        top = _longest(d, cfg)
        out.append(f'<p>⚠️ <b>Сбои: {len(problems)}</b>'
                   + (f' · дольше всего {esc(top[0])} — {F.duration(top[1] * 60)}' if top else '') + '</p>')
    else:
        out.append('<p>✅ Сбоев за сутки не было' + (f' (коротких: {short})' if short else '') + '</p>')
    out.append(_work_line(work))

    bad_sites, cert = _sites_bad(d), _cert_min(d)
    if d.get('site_up'):
        if bad_sites:
            out.append('<p>🌐 Не открываются: ' + esc(', '.join(bad_sites)) + '</p>')
        else:
            out.append('<p>🌐 Сайты в норме' + (f' · ближайший сертификат {cert} дн.' if cert is not None else '') + '</p>')
    geo = _geo_counts(geo_run)
    parts = []
    if geo is None:
        parts.append('GeoCheck сегодня не запускался')
    else:
        parts.append('GeoCheck: ' + (f'изменений {geo["changed"]}' if geo['changed'] else 'важных изменений нет')
                     + (f', новых проблем {geo["new_bad"]}' if geo['new_bad'] else ''))
    if cfg.rkn_enabled and rkn_data:
        live, hushed, _ = rkn_blocked(rkn_data, rkn_muted)
        parts.append('РКН: ' + (f'в списках {len(live)}' if live else 'чисто')
                     + (f' (заглушено {len(hushed)})' if hushed else ''))
    out.append('<p>🌍 ' + esc(' · '.join(parts)) + '</p>')

    for p in cfg.panels:
        ns = nodes(d, p.id)
        if not ns:
            continue
        u = users(d, extras, p.id)
        trs = ''.join(
            f'<tr><td>{esc(flag(n["country"]))}{esc(n["name"])}</td><td align="right">{n["now"]}/{n["peak"]}</td>'
            f'<td align="right">{gb(n["down"])}</td><td align="right">{gb(n["up"])}</td>'
            f'<td align="right">{gb(sum(n["outbound"].values())) if n["outbound"] else "—"}</td></tr>' for n in ns)
        head = (f'активных {u["active"]} · истёкших {u["expired"]}'
                + (f' · всего {_num(u["total"])}' if u['total'] is not None else '')
                + (f' · новых за сутки {u["new"]}, истекло {u["gone"]}' if u['new'] is not None else ''))
        out.append(f'<details><summary>Ноды {esc(p.title)} ({len(ns)})</summary><p>{esc(head)}</p>'
                   '<table bordered striped compact><tr><th>Нода</th><th>сейчас/пик</th><th>↓ клиентам</th>'
                   f'<th>↑ от клиентов</th><th>аутбаунды</th></tr>{trs}</table></details>')

    if problems or short:
        items = ''.join(f'<li>{line.removeprefix("• ")}</li>' for line in problems)
        if short:
            items += f'<li>и ещё {short} коротких (до {cfg.short_minutes} мин) — перезапуски и минутные обрывы</li>'
        out.append(f'<details><summary>Сбои за сутки ({len(problems)})</summary><ul>{items}</ul></details>')

    # «как и вчера» — то, что не меняется изо дня в день: в файле отчёта, в сводке не повторяем
    extra = [x for x in (geocheck.telegram_section(geo_run) if geo_run else []) if 'Как и вчера' not in x]
    if cfg.rkn_enabled and rkn_data:
        live, hushed, items = rkn_blocked(rkn_data, rkn_muted)
        for x in live:
            extra.append(f'🚫 {esc(x["name"])} <code>{esc(x["target"])}</code> — {esc(x.get("why", ""))}')
        for x in hushed:
            extra.append(f'🔕 {esc(x["name"])} — в списках, заглушено')
    if scan_data:
        from . import scan
        extra += [x for x in scan.telegram_section(scan_data) if x]
    if extra:
        out.append('<details><summary>GeoCheck и блокировки</summary><p>'
                   + '<br>'.join(line for line in extra if line) + '</p></details>')
    out.append('<footer>Полный отчёт — файлом ниже</footer>')
    return ''.join(out)


# ── лента сбоев ─────────────────────────────────────────────

def _segments(values, end):
    """Точки (время, значение) → отрезки, где значение было 0."""
    segs, start, last = [], None, None
    for t, v in values:
        if v == 0 and start is None:
            start = t
        elif v != 0 and start is not None:
            segs.append((start, t))
            start = None
        last = t
    if start is not None:
        segs.append((start, min(end, (last or start) + STEP)))
    return segs


def timeline(prom, d, cfg, end=None):
    """[(подпись, [(начало, конец)])] — что и когда не работало за сутки."""
    end = end or time.time()
    start = end - DAY
    rows = []

    def series(expr):
        try:
            return prom.query_range(expr, start, end, STEP)
        except Exception as e:
            log('report', f'лента сбоев: {e}')
            return []

    names = check_names(cfg)
    want = {}
    for pid, host, name, check, mins in d['checks']:
        if mins > cfg.short_minutes:
            want.setdefault((name, check), []).append((pid, host))
    if want:
        for m, vals in series('min by (name, check) (xray_proxy_status)'):
            hosts = want.get((m.get('name'), m.get('check')))
            if hosts:
                rows.append((f'{merged_name(hosts, cfg)} · {names.get(m["check"], m["check"])}',
                             _segments(vals, end)))
    hosts_bad = {}                       # итог по хосту: отрезки, когда хост не работал
    for pid, host, name, code, mins in d.get('states') or []:
        hosts_bad.setdefault(name, set()).add((pid, host))
    if hosts_bad:
        for m, vals in series('max by (name) (rwmon_host_state) == bool 0'):
            hosts = hosts_bad.get(m.get('name'))
            segs = _segments(vals, end)
            if hosts and segs and sum(b - a for a, b in segs) > cfg.short_minutes * 60:
                rows.append((f'{merged_name(sorted(hosts), cfg)} · хост не работал', segs))
    if any(v >= 1 for v in d['offline'].values()):
        for m, vals in series('rwmon_node_connected'):
            info = d['info'].get((m.get('panel'), m.get('node_uuid')))
            segs = _segments(vals, end)
            if info and segs:
                name = info.get('node_name', '?') + (f' · {info.get("panel_title")}' if cfg.multi else '')
                rows.append((f'{name} · нода отключалась', segs))
    if any(v >= 1 for v in (d.get('sites_down') or {}).values()):
        for m, vals in series('rwmon_site_up'):
            segs = _segments(vals, end)
            if segs:
                rows.append((f'{m.get("site", "?")} · сайт', segs))
    if any(v >= 1 for v in (d.get('panel_down') or {}).values()):
        for m, vals in series('rwmon_panel_up'):
            segs = _segments(vals, end)
            if segs and sum(b - a for a, b in segs) > cfg.panel_down_minutes * 60:
                rows.append((f'{m.get("panel_title") or m.get("panel", "?")} · API панели', segs))
    rows = [r for r in rows if r[1]]
    rows.sort(key=lambda r: -sum(b - a for a, b in r[1]))
    return rows, start, end


# ── полный HTML-отчёт ───────────────────────────────────────

CSS = """
:root{color-scheme:light dark;--bg:#f5f6f8;--card:#fff;--line:#e4e7eb;--text:#1b2027;--muted:#6b7580;
--ok:#1f8a4c;--okbg:#e3f4ea;--bad:#c62f2f;--badbg:#fbe6e6;--warn:#9a6200;--warnbg:#fdf0d5;--acc:#2563c9;--track:#eef0f3}
@media (prefers-color-scheme:dark){:root{--bg:#0f1318;--card:#171c22;--line:#272e37;--text:#dde2e8;--muted:#8a95a2;
--ok:#4cc985;--okbg:#173626;--bad:#ff7b7b;--badbg:#3b1d1d;--warn:#f0b54a;--warnbg:#3a2c12;--acc:#6ea8ff;--track:#222932}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1180px;margin:0 auto;padding:20px 16px 48px}
h1{font-size:22px;font-weight:600;margin:0}h2{font-size:16px;font-weight:600;margin:28px 0 10px;display:flex;gap:8px;align-items:center}
.muted{color:var(--muted)}.top{display:flex;justify-content:space-between;align-items:baseline;flex-wrap:wrap;gap:8px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin:14px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 14px}
.card .l{font-size:12px;color:var(--muted)}.card .v{font-size:22px;font-weight:600;margin-top:2px}
.card .s{font-size:12px;color:var(--muted)}
.box{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:4px 0;overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{padding:7px 12px;border-bottom:1px solid var(--line);text-align:right;white-space:nowrap}
th{color:var(--muted);font-weight:500;font-size:12px}tr:last-child td{border-bottom:0}
th:first-child,td:first-child{text-align:left}td.l,th.l{text-align:left;white-space:normal}
.bar{height:6px;border-radius:3px;background:var(--acc);opacity:.75;min-width:2px}
.chip{display:inline-block;font-size:12px;padding:1px 8px;border-radius:6px;margin:1px 2px 1px 0;white-space:nowrap}
.ok{background:var(--okbg);color:var(--ok)}.bad{background:var(--badbg);color:var(--bad)}
.warn{background:var(--warnbg);color:var(--warn)}.gray{background:var(--track);color:var(--muted)}
.tl{display:grid;grid-template-columns:minmax(160px,300px) 1fr auto;gap:6px 12px;align-items:center;padding:10px 14px}
.track{position:relative;height:12px;background:var(--track);border-radius:4px}
.seg{position:absolute;top:0;height:12px;border-radius:3px;background:var(--bad)}
.ticks{display:flex;justify-content:space-between;font-size:11px;color:var(--muted)}
details{margin:6px 0}summary{cursor:pointer;padding:8px 14px;font-weight:500}
details .inner{padding:0 14px 12px}img{max-width:100%;height:auto;border-radius:8px;margin-top:8px}
ul{margin:6px 0;padding-left:20px}.panel-users{padding:10px 14px;font-size:13px;color:var(--muted)}
"""


def _chip(text, kind='gray'):
    return f'<span class="chip {kind}">{esc(text)}</span>'


def _hm(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime('%H:%M')


def _timeline_html(rows, start, end):
    if not rows:
        return '<div class="box"><div class="panel-users">Сбоев дольше пары минут не было.</div></div>'
    span = end - start
    out = ['<div class="box"><div class="tl">']
    for label, segs in rows[:40]:
        bars = ''.join(f'<div class="seg" style="left:{(a - start) / span * 100:.2f}%;'
                       f'width:{max(0.3, (b - a) / span * 100):.2f}%" title="{_hm(a)}–{_hm(b)} UTC"></div>'
                       for a, b in segs)
        total = sum(b - a for a, b in segs)
        out.append(f'<div>{esc(label)}</div><div class="track">{bars}</div>'
                   f'<div class="muted">{F.duration(total)}</div>')
    ticks = ''.join(f'<span>{_hm(start + span * i / 4)}</span>' for i in range(5))
    out.append(f'<div></div><div class="ticks">{ticks}</div><div class="muted">UTC</div></div></div>')
    return ''.join(out)


def _nodes_html(d, cfg, extras, pid, title):
    ns = nodes(d, pid)
    u = users(d, extras, pid)
    tags = sorted({t for n in ns for t in n['outbound']})
    peak = max([n['down'] + n['up'] for n in ns] or [1]) or 1
    head = ''.join(f'<th>{esc(t)}</th>' for t in tags)
    rows = []
    for n in ns:
        net = (f'{gb(n["net_rx"])} / {gb(n["net_tx"])}' if n['net_rx'] is not None else '—')
        cells = ''.join(f'<td>{gb(n["outbound"].get(t)) if t in n["outbound"] else "—"}</td>' for t in tags)
        width = (n['down'] + n['up']) / peak * 100
        rows.append(f'<tr><td>{esc(flag(n["country"]))}{esc(n["name"])}</td><td>{n["now"]} / {n["peak"]}</td>'
                    f'<td>{gb(n["down"])}</td><td>{gb(n["up"])}</td>{cells}<td>{net}</td>'
                    f'<td style="width:120px"><div class="bar" style="width:{width:.0f}%"></div></td></tr>')
    info = (f'онлайн <b>{u["online"]}</b> · за сутки {u["day"]} · активных <b>{u["active"]}</b> · '
            f'истёкших {u["expired"]}' + (f' · всего {_num(u["total"])}' if u['total'] is not None else '')
            + (f' · новых за сутки {u["new"]}, истекло {u["gone"]}' if u['new'] is not None else ''))
    return (f'<h2>{esc(title)}</h2><div class="box"><div class="panel-users">{info}</div>'
            '<table><tr><th>Нода</th><th>клиенты сейчас / пик</th><th>↓ клиентам</th><th>↑ от клиентов</th>'
            f'{head}<th>сеть сервера ↓ / ↑</th><th></th></tr>{"".join(rows)}</table></div>')


def _bad_value(c, bad_countries):
    v = c['value']
    return (c['kind'] == 'country' and v in bad_countries) or v.startswith('blocked')


def _geo_html(geo_run, cfg):
    if not geo_run:
        return '<h2>GeoCheck</h2><div class="box"><div class="panel-users">Сегодня не запускался.</div></div>'
    folder = os.path.join(cfg.data_dir, 'geocheck')
    results = sorted(geo_run['results'].items(), key=lambda kv: kv[1]['name'])
    out = [f'<h2>GeoCheck — как сервисы видят ноды</h2>'
           f'<div class="muted" style="margin:-4px 0 8px">{esc(geo_run["finished"][:16].replace("T", " "))} UTC</div>']
    rows = []
    for _, r in results:
        if not r['ok']:
            rows.append(f'<tr><td>{esc(r["name"])}</td><td class="l" colspan="4">{_chip("не выполнился", "bad")} '
                        f'{esc(r.get("error") or "")}</td></tr>')
            continue
        s = r['summary']
        attention = ''.join(_chip(x, 'warn') for x in r.get('attention') or [])
        changes = ''.join(_chip(f'{n}: {a} → {b}', 'bad') for n, a, b in r.get('changes') or [])
        changes += ''.join(_chip(f'{n}: {a} → {b}', 'gray') for n, a, b in r.get('minor') or [])
        blocked = ''.join(_chip(c['name'], 'bad') for c in s['checks'].values()
                          if c['group'] in geocheck.MAIN_GROUPS and c['value'].startswith('blocked'))
        cons = s.get('consensus') or ''
        cons_kind = 'bad' if cons.split()[:1] and cons.split()[0] in cfg.bad_countries else 'ok'
        rows.append(f'<tr><td>{esc(r["name"])}<div class="muted">{esc(s["ip"])} · {esc(s["network"])}</div></td>'
                    f'<td class="l">{_chip(cons, cons_kind) if cons else ""}{attention}</td>'
                    f'<td class="l">{changes or "<span class=muted>—</span>"}</td>'
                    f'<td class="l">{blocked or "<span class=muted>—</span>"}</td></tr>')
    out.append('<div class="box"><table><tr><th>Нода</th><th class="l">страна по сервисам</th>'
               f'<th class="l">изменения со вчера</th><th class="l">недоступно</th></tr>{"".join(rows)}</table></div>')

    # все сервисы по всем нодам — одной таблицей, свёрнуто
    ok = [(u, r) for u, r in results if r['ok']]
    cols = {}
    for _, r in ok:
        for key, c in r['summary']['checks'].items():
            if c['group'] in geocheck.MAIN_GROUPS:
                cols.setdefault(key, c['name'])
    if cols:
        head = ''.join(f'<th>{esc(n)}</th>' for n in cols.values())
        body = []
        for _, r in ok:
            cells = []
            for key in cols:
                c = r['summary']['checks'].get(key)
                if not c:
                    cells.append('<td class="muted">—</td>')
                else:
                    kind = 'bad' if _bad_value(c, cfg.bad_countries) else (
                        'ok' if c['value'].startswith('available') or c['value'] in ('yes', 'clean') else 'gray')
                    cells.append(f'<td>{_chip(c["value"], kind)}</td>')
            body.append(f'<tr><td>{esc(r["name"])}</td>{"".join(cells)}</tr>')
        out.append('<details class="box"><summary>Все сервисы по всем нодам</summary>'
                   f'<div style="overflow-x:auto"><table><tr><th>Нода</th>{head}</tr>{"".join(body)}</table></div>'
                   '</details>')

    for uid, r in ok:
        s = r['summary']
        groups = {}
        for c in s['checks'].values():
            groups.setdefault(geocheck.GROUPS.get(c['group'], c['group']), []).append(c)
        inner = ''.join(f'<p class="muted" style="margin:8px 0 2px">{esc(g)}</p>'
                        + ''.join(_chip(f'{c["name"]}: {c["value"]}',
                                        'bad' if _bad_value(c, cfg.bad_countries) else 'gray') for c in cs)
                        for g, cs in groups.items())
        path = geocheck.image_path(folder, uid)
        if cfg.attach_images and os.path.exists(path):
            with open(path, 'rb') as f:
                inner += (f'<img alt="GeoCheck {esc(r["name"])}" loading="lazy" '
                          f'src="data:image/svg+xml;base64,{base64.b64encode(f.read()).decode()}">')
        out.append(f'<details class="box"><summary>{esc(r["name"])} — {esc(s["ip"])} '
                   f'<span class="muted">{esc(s["place"])} · {esc(s["type"])}</span></summary>'
                   f'<div class="inner">{inner}</div></details>')
    return ''.join(out)


def _sites_html(d, rkn_data, cfg, rkn_muted):
    out = []
    if d.get('site_up'):
        rows = []
        for (site,), up in sorted(d['site_up'].items()):
            days = (d.get('site_cert') or {}).get((site,))
            down = (d.get('sites_down') or {}).get((site,), 0)
            ru = (d.get('sites_ru_down') or {}).get((site,), 0)
            cert = '—' if days is None else _chip(f'{int(days)} дн.', 'ok' if days >= 14 else 'bad')
            rows.append(f'<tr><td>{esc(site)}</td><td>{_chip("работает", "ok") if up else _chip("не открывается", "bad")}</td>'
                        f'<td>{F.duration(down * 60) if down >= 1 else "—"}</td>'
                        f'<td>{F.duration(ru * 60) if ru >= 1 else "—"}</td><td>{cert}</td></tr>')
        out.append('<h2>Сайты и сертификаты</h2><div class="box"><table><tr><th>Сайт</th><th>сейчас</th>'
                   f'<th>не открывался</th><th>из РФ не открывался</th><th>сертификат</th></tr>{"".join(rows)}</table></div>')
    if cfg.rkn_enabled and rkn_data:
        live, hushed, items = rkn_blocked(rkn_data, rkn_muted)
        rows = []
        for x in sorted(items, key=lambda x: (not x.get('blocked'), x.get('kind', ''), x.get('name', ''))):
            if not x.get('ok'):
                st = _chip('не проверено', 'gray')
            elif x.get('blocked'):
                st = _chip('заглушено', 'gray') if x in hushed else _chip('в списках', 'bad')
            elif x.get('cdn'):
                st = _chip(f'за CDN {x["cdn"]}', 'warn')
            else:
                st = _chip('чисто', 'ok')
            rows.append(f'<tr><td>{esc(x.get("name", ""))}</td><td>{esc(x.get("target", ""))}</td>'
                        f'<td>{"нода" if x.get("kind") == "node" else "домен"}</td><td>{st}</td>'
                        f'<td class="l">{esc(x.get("why", ""))}</td></tr>')
        out.append(f'<h2>Блокировки РКН <span class="muted" style="font-weight:400">cheburcheck, '
                   f'{esc(rkn_data.get("time", ""))} UTC</span></h2><div class="box"><table><tr><th>Что</th>'
                   f'<th>адрес</th><th>тип</th><th>статус</th><th class="l">причина</th></tr>{"".join(rows)}</table></div>')
    return ''.join(out)


def full_html(d, extras, geo_run, rkn_data, cfg, tl=None, rkn_muted=lambda item: False):
    title = f'Мониторинг · {now():%d.%m.%Y}'
    all_nodes = [n for p in cfg.panels for n in nodes(d, p.id)]
    down = sum(n['down'] for n in all_nodes)
    up = sum(n['up'] for n in all_nodes)
    online = sum(users(d, extras, p.id)['online'] for p in cfg.panels)
    problems, short = problem_lines(d, cfg)
    cert = _cert_min(d)
    geo = _geo_counts(geo_run)
    cards = [('онлайн сейчас', str(online), f'нод: {len(all_nodes)}'),
             ('трафик ↓ / ↑', f'{gb(down)} / {gb(up)}', 'к клиентам / от клиентов, за сутки'),
             ('сбоев за сутки', str(len(problems)), f'и коротких: {short}' if short else 'дольше пары минут'),
             ('ближайший сертификат', f'{cert} дн.' if cert is not None else '—', 'сайты и панели'),
             ('GeoCheck', f'{geo["changed"]} изм.' if geo else '—',
              f'нод: {geo["nodes"]}' if geo else 'сегодня не запускался')]
    out = [f'<!doctype html><html lang="ru"><head><meta charset="utf-8">'
           f'<meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)}</title>'
           f'<style>{CSS}</style></head><body><main>',
           f'<div class="top"><h1>{esc(title)}</h1><span class="muted">за сутки до {now():%H:%M} UTC</span></div>',
           '<div class="cards">' + ''.join(f'<div class="card"><div class="l">{esc(a)}</div><div class="v">{esc(b)}</div>'
                                           f'<div class="s">{esc(c)}</div></div>' for a, b, c in cards) + '</div>']
    out.append('<h2>Сбои за сутки</h2>')
    if tl is not None:
        out.append(_timeline_html(*tl))
    if problems or short:
        items = ''.join(f'<li>{line.removeprefix("• ")}</li>' for line in problems)
        if short:
            items += f'<li class="muted">и ещё {short} коротких (до {cfg.short_minutes} мин)</li>'
        out.append(f'<details class="box"><summary>Списком</summary><div class="inner"><ul>{items}</ul></div></details>')
    for p in cfg.panels:
        out.append(_nodes_html(d, cfg, extras, p.id, f'Ноды · {p.title}'))
    out.append(_geo_html(geo_run, cfg))
    out.append(_sites_html(d, rkn_data, cfg, rkn_muted))
    out.append('</main></body></html>')
    return '\n'.join(out)
