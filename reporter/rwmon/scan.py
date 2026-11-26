"""Сканеры cheburcheck в сетях операторов РФ: как адрес открывается у реальных провайдеров.

Списки блокировок (rkn.py) говорят, попал ли адрес в реестр. Сканеры — открывается ли он
на деле: каждый стоит в сети одного провайдера (МТС, Ростелеком, Уфанет…) и отдаёт вердикт —
ok, tspu_block (режет ТСПУ), sni_block (режут по имени сайта), dns_spoofing, cdn_block.

Проверка сканерами нужна API-токен ([rkn] token), кредитов она не тратит, но частота
запросов ограничена. Поэтому адреса идут по одному, по кругу, раз в probe_interval_minutes:
каждый раз берём тот, что проверяли давнее всех. Ответ 429 (слишком часто) — пауза
удваивается (до 6 часов), пока сервис снова не ответит. Адресов немного, и круг за сутки
обычно замыкается; сохранённое измерение у cheburcheck живёт 3 часа, так что чаще и не нужно.

Блокировкой считаем, когда её видят хотя бы MIN_BAD сканеров: одиночный вердикт бывает
ложным (сканер в сети с кривым DNS или упавшим маршрутом).
"""
import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import rkn
from .util import esc, log, now, read_json, write_json

BAD = {'tspu_block': 'ТСПУ', 'sni_block': 'по SNI', 'dns_spoofing': 'подмена DNS', 'cdn_block': 'CDN'}
MIN_BAD = 2                 # столько сканеров должны видеть блокировку
STREAM_TIMEOUT = 150        # сколько ждём событие done, секунд
BACKOFF_MAX = 6 * 3600
KEEP = 3 * 86400            # результаты старше не показываем: адрес, видимо, убрали из проверок


class RateLimited(Exception):
    pass


def path(cfg):
    return os.path.join(cfg.data_dir, 'rkn', 'scan.json')


def load(cfg):
    return read_json(path(cfg), {}) or {}


def _req(url, token=None, accept='application/json'):
    h = {'Accept': accept, 'User-Agent': 'remnawave-monitoring'}
    if token:
        h['Authorization'] = f'Bearer {token}'
    return urllib.request.Request(url, headers=h)


def events(lines, deadline=None):
    """Строки text/event-stream → (событие, данные) по одному. deadline — time.time(), после
    которого бросаем чтение: сервер шлёт «пинги», и без срока поток мог бы не кончиться."""
    ev, data = None, []
    for raw in lines:
        if deadline and time.time() > deadline:
            return
        line = raw.decode('utf-8', 'replace') if isinstance(raw, bytes) else raw
        line = line.rstrip('\r\n')
        if not line:
            if ev or data:
                try:
                    yield ev or 'message', json.loads('\n'.join(data)) if data else {}
                except ValueError:
                    pass
            ev, data = None, []
        elif line.startswith(':'):
            continue                           # комментарий-«пинг» сервера
        elif line.startswith('event:'):
            ev = line[6:].strip()
        elif line.startswith('data:'):
            data.append(line[5:].lstrip())
    if ev or data:
        try:
            yield ev or 'message', json.loads('\n'.join(data)) if data else {}
        except ValueError:
            pass


def probe(target, token, check=None, stream=None):
    """Один адрес через все доступные сканеры → {'online', 'results': [...]}.
    check/stream — для тестов."""
    try:
        res = check(target) if check else rkn._get('/check?target=' + urllib.parse.quote(target, safe=''))
    except urllib.error.HTTPError as e:
        if e.code == 429:
            raise RateLimited() from e
        raise
    cid = (res or {}).get('id')
    if not cid:
        raise RuntimeError('cheburcheck не дал id проверки')
    url = f'{rkn.API}/probe/{urllib.parse.quote(cid, safe="")}'
    out = {'online': 0, 'results': []}
    try:
        lines = stream(url) if stream else urllib.request.urlopen(
            _req(url, token, 'text/event-stream'), timeout=STREAM_TIMEOUT)
    except urllib.error.HTTPError as e:
        if e.code == 429:
            raise RateLimited() from e
        raise
    try:
        for ev, d in events(lines, time.time() + STREAM_TIMEOUT):
            if ev == 'started':
                out['online'] = int(d.get('online_probes') or 0)
            elif ev == 'result':
                out['results'].append({
                    'provider': str(d.get('provider') or f'сканер {d.get("probe_id", "?")}'),
                    'region': str(d.get('region') or ''),
                    'verdicts': [str(v) for v in (d.get('verdicts') or [])]})
            elif ev == 'done':
                break
    finally:
        close = getattr(lines, 'close', None)
        if close:
            close()
    return out


def summarize(raw):
    """Ответы сканеров → итог: сколько ok, у кого какая блокировка."""
    res = raw.get('results') or []
    by = {}
    ok = uncertain = 0
    for r in res:
        bad = [v for v in r['verdicts'] if v in BAD]
        who = r['provider'] + (f' ({r["region"]})' if r['region'] else '')
        for v in bad:
            by.setdefault(v, []).append(who)
        if not bad:
            if 'ok' in r['verdicts'] or 'whitelist' in r['verdicts']:
                ok += 1
            else:
                uncertain += 1
    bad_n = sum(1 for r in res if any(v in BAD for v in r['verdicts']))
    return {'answered': len(res), 'online': raw.get('online', 0), 'ok': ok, 'uncertain': uncertain,
            'bad': bad_n, 'by': {k: sorted(set(v)) for k, v in by.items()}, 'blocked': bad_n >= MIN_BAD}


def why(item):
    """«ТСПУ: МТС (Москва), Билайн; по SNI: …» — для алерта и сводки."""
    parts = []
    for v in BAD:
        who = (item.get('by') or {}).get(v)
        if who:
            parts.append(f'{BAD[v]}: ' + ', '.join(who[:4]) + (f' и ещё {len(who) - 4}' if len(who) > 4 else ''))
    return '; '.join(parts)


def kinds(item):
    """Только виды блокировки («ТСПУ, по SNI») — для метки алерта: список провайдеров меняется
    от проверки к проверке, и в метке он плодил бы ложные «восстановилось/снова упало»."""
    return ', '.join(BAD[v] for v in BAD if (item.get('by') or {}).get(v))


def pick(tgts, items):
    """Следующий адрес: тот, что не проверяли дольше всех (новые — первыми)."""
    if not tgts:
        return None
    return min(tgts, key=lambda t: (items.get(t['target'], {}).get('ts', 0), t['target']))


def step(cfg, clients, data, probe_fn=None):
    """Один шаг: проверить очередной адрес. Возвращает паузу до следующего шага, секунд."""
    interval = cfg.rkn_probe_interval
    items = data.setdefault('items', {})
    tgts = rkn.targets(cfg, clients)
    current = {t['target'] for t in tgts}
    for k in [k for k, v in items.items() if k not in current or time.time() - v.get('ts', 0) > KEEP]:
        items.pop(k)
    t = pick(tgts, items)
    if not t:
        return interval
    try:
        raw = (probe_fn or (lambda x: probe(x, cfg.rkn_token)))(t['target'])
    except RateLimited:
        data['backoff'] = min(max(data.get('backoff', 0) * 2, interval), BACKOFF_MAX)
        log('scan', f'cheburcheck просит реже (429) — следующая проверка через {data["backoff"] // 60} мин')
        return data['backoff']
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            log('scan', f'токен не принят ({e.code}) — проверьте [rkn] token; повторю через 6 ч')
            return BACKOFF_MAX
        raise
    data['backoff'] = 0
    s = summarize(raw)
    if not s['answered']:
        log('scan', f'{t["target"]}: ни один сканер не ответил')
        return interval
    items[t['target']] = dict(s, name=t['name'], kind=t['kind'], ts=time.time(),
                              time=now().strftime('%Y-%m-%d %H:%M'))
    log('scan', f'{t["target"]}: ответили {s["answered"]} из {s["online"]}, ok {s["ok"]}'
                + (f', блокировка: {why(s)}' if s['bad'] else ''))
    return interval


def loop(cfg, clients, stop=None):
    """Поток: шаги по кругу. Первый — через минуту, когда reporter уже собрал хосты."""
    time.sleep(60)
    data = load(cfg)
    while not (stop and stop.is_set()):
        try:
            wait = step(cfg, clients, data)
            write_json(path(cfg), data)
        except Exception as e:
            log('scan', f'ошибка: {e} — повторю через {cfg.rkn_probe_interval // 60} мин')
            wait = cfg.rkn_probe_interval
        time.sleep(wait)


def start(cfg, clients):
    if cfg.rkn_enabled and cfg.rkn_token:
        threading.Thread(target=loop, args=(cfg, clients), daemon=True, name='scan').start()
        log('scan', f'сканеры cheburcheck: адрес раз в {cfg.rkn_probe_interval // 60} мин')


def lines(data, out):
    """Метрики: по строке на адрес — сколько сканеров видят блокировку и итог."""
    for target, x in (data.get('items') or {}).items():
        name = x['name'] if x['name'] == target else f'{x["name"]} · {target}'
        labels = {'target': target, 'kind': x.get('kind', ''), 'name': name,
                  'why': kinds(x) if x.get('blocked') else ''}
        out.add('rwmon_rkn_scan_blocked', labels, 1 if x.get('blocked') else 0)
        out.add('rwmon_rkn_scan_info', {'target': target, 'name': name, 'who': why(x)}, 1)
        out.add('rwmon_rkn_scan_bad', {'target': target, 'name': name}, x.get('bad', 0))
        out.add('rwmon_rkn_scan_ok', {'target': target, 'name': name}, x.get('ok', 0))
        out.add('rwmon_rkn_scan_answered', {'target': target, 'name': name}, x.get('answered', 0))
        out.add('rwmon_rkn_scan_timestamp_seconds', {'target': target, 'name': name}, x.get('ts', 0))


def telegram_section(data):
    """Блок для ежедневной сводки."""
    items = (data or {}).get('items') or {}
    if not items:
        return []
    day = [x for x in items.values() if time.time() - x.get('ts', 0) <= 86400]
    blocked = sorted((x for x in items.values() if x.get('blocked')), key=lambda x: x['name'])
    lines = ['', '<b>📡 Сканеры в сетях РФ</b> (cheburcheck)']
    for x in blocked:
        kind = 'нода' if x.get('kind') == 'node' else 'домен'
        lines.append(f'• {kind} {esc(x["name"])}: блокируют {x["bad"]} из {x["answered"]} — {esc(why(x))}')
    if not blocked:
        lines.append(f'• блокировок не видят, адресов: {len(items)}'
                     + (f' (за сутки проверено {len(day)})' if len(day) != len(items) else ''))
    elif len(day) != len(items):
        lines.append(f'<i>за сутки проверено {len(day)} из {len(items)} адресов</i>')
    return lines
