"""GeoCheck всех нод: как внешние сервисы видят IP каждой ноды.

GeoCheck запускает сама панель на ноде (кнопка GeoCheck в карточке ноды),
мы только вызываем его через API раз в сутки, сравниваем с прошлым
результатом и подсвечиваем изменения.
"""
import base64
import os
from concurrent.futures import ThreadPoolExecutor

from .util import esc, log, now, read_json, write_json

GROUPS = {'services': 'Сервисы', 'geoip': 'GeoIP-базы', 'cdn': 'CDN', 'stash': 'Доступ'}
# изменения в этих группах — главные, в остальных — второстепенные
MAIN_GROUPS = ('services', 'stash')
RISK_JUMP = 20


# ── разбор отчёта ────────────────────────────────────────────

def summarize(report):
    """Полный JSON geocheck → короткая сводка, которую удобно сравнивать."""
    report = report or {}
    ident = report.get('identity') or {}
    rep = report.get('reputation') or {}
    s = {
        'ip': ident.get('ipv4') or ident.get('ipv6') or '',
        'network': ' '.join(x for x in (f'AS{ident["asn"]}' if ident.get('asn') else '',
                                         ident.get('as_name') or ident.get('org') or '') if x),
        'type': rep.get('type') or '',
        'risk': rep.get('risk') if isinstance(rep.get('risk'), int) else None,
        'place': ', '.join(x for x in (rep.get('city'), rep.get('country_code')) if x),
        'consensus': '',
        'checks': {},
    }
    cons = (report.get('consensus') or {}).get('ipv4') or []
    if cons:
        top = cons[0]
        s['consensus'] = f'{top.get("code", "?")} {round(top.get("percent", 0))}%'

    geo = report.get('geo') or {}
    for group in ('services', 'geoip', 'cdn'):
        for c in geo.get(group) or []:
            v = (c.get('ipv4') or {})
            if v.get('error') or not v.get('value'):
                continue
            kind = c.get('kind') or ''
            value = v['value'].upper() if kind == 'country' else v['value'].lower()
            s['checks'][f'{group}:{c.get("id")}'] = {
                'name': c.get('name') or c.get('id'), 'group': group, 'kind': kind, 'value': value}

    for c in report.get('stash_checks') or []:
        state = (c.get('state') or '').lower()
        if not state or state == 'error' or c.get('error'):
            continue
        value = state + (f' ({c["region"].upper()})' if c.get('region') else '')
        s['checks'][f'stash:{c.get("id")}'] = {
            'name': c.get('name') or c.get('id'), 'group': 'stash', 'kind': 'access', 'value': value}
    return s


def compare(prev, cur):
    """Что изменилось со вчера. Возвращает (главное, второстепенное)."""
    main, minor = [], []
    if not prev:
        return main, minor
    if prev.get('ip') and cur.get('ip') and prev['ip'] != cur['ip']:
        main.append(('IP', prev['ip'], cur['ip']))
    if prev.get('type') and cur.get('type') and prev['type'] != cur['type']:
        main.append(('Тип IP', prev['type'], cur['type']))
    pr, cr = prev.get('risk'), cur.get('risk')
    if isinstance(pr, int) and isinstance(cr, int) and abs(cr - pr) >= RISK_JUMP:
        main.append(('Риск IP', str(pr), str(cr)))
    if prev.get('consensus') and cur.get('consensus'):
        if prev['consensus'].split()[0] != cur['consensus'].split()[0]:
            minor.append(('Консенсус GeoIP', prev['consensus'], cur['consensus']))
    old = prev.get('checks') or {}
    for key, c in (cur.get('checks') or {}).items():
        before = (old.get(key) or {}).get('value')
        if before and before != c['value']:
            (main if c['group'] in MAIN_GROUPS else minor).append((c['name'], before, c['value']))
    return main, minor


def attention(summary, bad_countries):
    """Что плохо прямо сейчас, даже если не менялось: сервис видит ноду в «плохой» стране."""
    out = []
    for c in (summary.get('checks') or {}).values():
        if c['group'] == 'services' and c['kind'] == 'country' and c['value'] in bad_countries:
            out.append(f'{c["name"]} видит {c["value"]}')
    return out


# ── запуск ───────────────────────────────────────────────────

def pick_nodes(nodes, exclude):
    out = []
    for n in nodes:
        if n.get('isDisabled') or not n.get('isConnected'):
            continue
        names = {(n.get('name') or '').lower()} | {t.lower() for t in n.get('tags') or []}
        if names & exclude:
            continue
        out.append(n)
    return out


def image_path(folder, key):
    return os.path.join(folder, 'images', key.replace(':', '_') + '.svg')


def run(cfg, clients):
    """GeoCheck всех нод всех панелей. clients — {panel.id: Remnawave}."""
    folder = os.path.join(cfg.data_dir, 'geocheck')
    baseline = read_json(os.path.join(folder, 'baseline.json'), {})
    jobs = []
    for p in cfg.panels:
        try:
            nodes = pick_nodes(clients[p.id].nodes(), p.exclude_nodes | p.geocheck_exclude)
        except Exception as e:
            log('geocheck', f'[{p.title}] список нод не получен: {e}')
            continue
        jobs += [(p, n) for n in nodes]
    log('geocheck', f'запускаю на {len(jobs)} нодах')

    def one(job):
        p, node = job
        try:
            return p, node, clients[p.id].geocheck(node['uuid']), None
        except Exception as e:           # одна упавшая нода не мешает остальным
            return p, node, None, str(e)

    results = {}
    with ThreadPoolExecutor(max_workers=4) as pool:
        for p, node, res, err in pool.map(one, jobs):
            uid = node['uuid']
            key = f'{p.id}:{uid}'
            name = node.get('name') or uid
            if cfg.multi:
                name += f' · {p.title}'
            item = {'name': name, 'panel': p.id, 'country': node.get('countryCode') or '',
                    'ok': err is None, 'error': err}
            if err is None:
                summary = summarize(res.get('rawReport'))
                prev = baseline.get(key) or baseline.get(uid)     # uid — формат до нескольких панелей
                main, minor = compare(prev, summary)
                item.update(summary=summary, changes=main, minor=minor,
                            attention=attention(summary, cfg.bad_countries),
                            first=prev is None)
                baseline.pop(uid, None)
                baseline[key] = summary
                image = (res.get('image') or {}).get('data')
                path = image_path(folder, key)
                if image:
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, 'wb') as f:
                        f.write(base64.b64decode(image))
                elif os.path.exists(path):
                    os.remove(path)          # не показывать вчерашнюю картинку
            else:
                log('geocheck', f'{name}: {err}')
            results[key] = item

    run_data = {'date': now().strftime('%Y-%m-%d'), 'finished': now().isoformat(), 'results': results}
    write_json(os.path.join(folder, 'baseline.json'), baseline)
    write_json(os.path.join(folder, 'last-run.json'), run_data)
    write_json(os.path.join(folder, 'history', run_data['date'] + '.json'),
               {k: r.get('summary') for k, r in results.items()})
    _prune(os.path.join(folder, 'history'), keep=60)
    ok = sum(1 for r in results.values() if r['ok'])
    log('geocheck', f'готово: {ok} из {len(results)}')
    return run_data


def _prune(folder, keep):
    try:
        files = sorted(f for f in os.listdir(folder) if f.endswith('.json'))
    except FileNotFoundError:
        return
    for f in files[:-keep]:
        os.remove(os.path.join(folder, f))


def load_last(cfg):
    return read_json(os.path.join(cfg.data_dir, 'geocheck', 'last-run.json'), None)


# ── текст для Telegram ───────────────────────────────────────

def telegram_section(run_data):
    """Блок «GeoCheck» для ежедневной сводки."""
    if not run_data:
        return ['🌍 <b>GeoCheck</b>: сегодня не запускался']
    results = sorted(run_data['results'].values(), key=lambda r: r['name'])
    lines = []
    changed = [r for r in results if r.get('changes')]
    if changed:
        lines.append('🔴 <b>GeoCheck: изменения за сутки</b>')
        for r in changed:
            parts = [f'{esc(n)} {esc(a)} → <b>{esc(b)}</b>' for n, a, b in r['changes']]
            lines.append(f'• <b>{esc(r["name"])}</b>: ' + '; '.join(parts))
    bad = [r for r in results if r.get('attention')]
    if bad:
        lines.append('⚠️ <b>Требует внимания</b>')
        for r in bad:
            lines.append(f'• <b>{esc(r["name"])}</b>: ' + ', '.join(esc(x) for x in r['attention']))
    failed = [r for r in results if not r['ok']]
    if failed:
        lines.append('⚪️ GeoCheck не выполнился: ' + ', '.join(esc(r['name']) for r in failed))
    minor = sum(len(r.get('minor') or []) for r in results)
    ok = len(results) - len(failed)
    if not changed and not bad:
        first = all(r.get('first') for r in results if r['ok'])
        note = 'первый прогон, сравнивать пока не с чем' if first and ok else 'важных изменений нет'
        lines.append(f'🌍 <b>GeoCheck</b>: {ok} нод, {note}')
    if minor:
        lines.append(f'<i>Мелкие изменения в GeoIP-базах и CDN: {minor} — в файле отчёта</i>')
    return lines


# ── HTML-отчёт ───────────────────────────────────────────────

CSS = """
:root{color-scheme:dark light;--bg:#0f141a;--card:#161d25;--line:#26313d;--text:#d8dee6;--muted:#8793a1;
--ok:#3ecf8e;--bad:#ff6b6b;--chg:#ffd166;--accent:#4dabf7}
@media (prefers-color-scheme: light){:root{--bg:#f6f7f9;--card:#fff;--line:#e2e6ea;--text:#1d232a;--muted:#667380}}
*{box-sizing:border-box}body{margin:0;padding:16px;background:var(--bg);color:var(--text);
font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
h1{font-size:20px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 8px}.muted{color:var(--muted)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin:10px 0}
.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--card)}
table{border-collapse:collapse;font-size:13px;white-space:nowrap}
th,td{padding:6px 10px;border-bottom:1px solid var(--line);text-align:left}
th{position:sticky;top:0;background:var(--card);color:var(--muted);font-weight:600}
td:first-child,th:first-child{position:sticky;left:0;background:var(--card);font-weight:600}
.chg{background:color-mix(in srgb,var(--chg) 22%,transparent)}
.bad{color:var(--bad);font-weight:600}.ok{color:var(--ok)}
ul{margin:6px 0;padding-left:20px}details{margin:8px 0}summary{cursor:pointer;font-weight:600}
img{max-width:100%;height:auto;border-radius:8px;margin-top:8px}
"""


def _cell_class(check, changed_names, bad_countries):
    cls = []
    if check['name'] in changed_names:
        cls.append('chg')
    v = check['value']
    if (check['kind'] == 'country' and v in bad_countries) or v.startswith('blocked'):
        cls.append('bad')
    elif v.startswith('available') or v in ('yes', 'clean'):
        cls.append('ok')
    return ' '.join(cls)


def html_report(run_data, cfg, title):
    folder = os.path.join(cfg.data_dir, 'geocheck')
    results = sorted(run_data['results'].items(), key=lambda kv: kv[1]['name'])
    ok = [(u, r) for u, r in results if r['ok']]

    # колонки таблицы: сервисы и проверки доступа в порядке появления
    cols = {}
    for _, r in ok:
        for key, c in r['summary']['checks'].items():
            if c['group'] in MAIN_GROUPS:
                cols.setdefault(key, c['name'])

    out = [f'<!doctype html><html lang="ru"><head><meta charset="utf-8">'
           f'<meta name="viewport" content="width=device-width,initial-scale=1">'
           f'<title>{esc(title)}</title><style>{CSS}</style></head><body>',
           f'<h1>{esc(title)}</h1><div class="muted">{esc(run_data["finished"][:16].replace("T", " "))} UTC · '
           f'нод: {len(results)}, успешно: {len(ok)}</div>']

    changes = [(r['name'], r.get('changes') or [], r.get('minor') or []) for _, r in ok]
    if any(c or m for _, c, m in changes):
        out.append('<h2>Изменения со вчера</h2><div class="card">')
        for name, main, minor in changes:
            if not (main or minor):
                continue
            out.append(f'<b>{esc(name)}</b><ul>')
            for n, a, b in main:
                out.append(f'<li class="bad">{esc(n)}: {esc(a)} → {esc(b)}</li>')
            for n, a, b in minor:
                out.append(f'<li>{esc(n)}: {esc(a)} → {esc(b)}</li>')
            out.append('</ul>')
        out.append('</div>')

    out.append('<h2>Как сервисы видят ноды</h2><div class="wrap"><table><tr><th>Нода</th>'
               '<th>IP</th><th>Сеть</th><th>Тип / риск</th><th>Консенсус</th>')
    out += [f'<th>{esc(n)}</th>' for n in cols.values()]
    out.append('</tr>')
    for _, r in ok:
        s = r['summary']
        changed = {n for n, _, _ in (r.get('changes') or []) + (r.get('minor') or [])}
        risk = '' if s.get('risk') is None else f' / {s["risk"]}'
        out.append(f'<tr><td>{esc(r["name"])}</td><td>{esc(s["ip"])}</td><td>{esc(s["network"])}</td>'
                   f'<td>{esc(s["type"])}{risk}</td><td>{esc(s["consensus"])}</td>')
        for key in cols:
            c = s['checks'].get(key)
            if not c:
                out.append('<td class="muted">—</td>')
            else:
                out.append(f'<td class="{_cell_class(c, changed, cfg.bad_countries)}">{esc(c["value"])}</td>')
        out.append('</tr>')
    for _, r in results:
        if not r['ok']:
            out.append(f'<tr><td>{esc(r["name"])}</td><td colspan="{4 + len(cols)}" class="bad">'
                       f'не выполнился: {esc(r["error"])}</td></tr>')
    out.append('</table></div>')

    out.append('<h2>Подробно по нодам</h2>')
    for uid, r in ok:
        s = r['summary']
        out.append(f'<details><summary>{esc(r["name"])} — {esc(s["ip"])} {esc(s["place"])}</summary>'
                   '<div class="card"><div class="wrap"><table><tr><th>Проверка</th><th>Группа</th>'
                   '<th>Результат</th></tr>')
        for c in s['checks'].values():
            out.append(f'<tr><td>{esc(c["name"])}</td><td>{GROUPS.get(c["group"], c["group"])}</td>'
                       f'<td class="{_cell_class(c, set(), cfg.bad_countries)}">{esc(c["value"])}</td></tr>')
        out.append('</table></div>')
        path = image_path(folder, uid)
        if cfg.attach_images and os.path.exists(path):
            with open(path, 'rb') as f:
                data = base64.b64encode(f.read()).decode()
            out.append(f'<img alt="GeoCheck {esc(r["name"])}" loading="lazy" '
                       f'src="data:image/svg+xml;base64,{data}">')
        out.append('</div></details>')
    out.append('</body></html>')
    return '\n'.join(out)
