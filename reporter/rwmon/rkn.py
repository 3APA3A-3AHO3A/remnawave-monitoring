"""Блокировки РФ: IP нод и домены сервиса по спискам блокировок через cheburcheck.ru.

cheburcheck.ru — открытый сервис (github.com/LowderPlay/cheburcheck): проверяет домен
или IP по реестру РКН, заблокированным подсетям и CDN (базы antifilter и др.).
Мы раз в несколько часов прогоняем через него IP всех нод и домены, на которые
ходят клиенты (адреса и SNI хостов, сайты из [[site]]), и подсвечиваем то, что
попало в списки. Уходят только IP и домены — без ключей и ссылок подписки.

Сканеры cheburcheck (проверка изнутри сетей операторов РФ) требуют API-токена —
он выдаётся по заявке; без токена — только списки.
"""
import ipaddress
import json
import os
import time
import urllib.parse
import urllib.request

from . import exporter, links
from .util import esc, log, now, read_json, resolve_ip, write_json

API = 'https://cheburcheck.ru/api/v1'
PAUSE = 2.5                 # между запросами: у /check лимит 30 в минуту
TIMEOUT = 20


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _public(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved)


def host_of(address):
    """'host:port', 'https://host/path', '[v6]:port' → host."""
    a = str(address or '').strip()
    if '://' in a:
        a = urllib.parse.urlsplit(a).hostname or ''
    elif a.startswith('['):
        a = a[1:].split(']', 1)[0]
    elif a.count(':') == 1:
        a = a.rsplit(':', 1)[0]
    return a.strip().lower().rstrip('.')


def targets(cfg, clients, state=None):
    """Что проверять: [{'target', 'kind': 'node'|'domain', 'name'}] без повторов.
    Ноды — по IP из панелей (частные адреса пропускаем), домены — адреса и SNI
    хостов для проверок, сайты из [[site]] и [rkn] extra."""
    state = {} if state is None else state
    out, seen = [], set()

    def add(target, kind, name):
        if target and target not in seen:
            seen.add(target)
            out.append({'target': target, 'kind': kind, 'name': name})
        elif target in seen:
            for t in out:
                if t['target'] == target and name not in t['name'].split(' / '):
                    t['name'] += f' / {name}'

    for p in cfg.panels:
        try:
            nodes = clients[p.id].nodes() or []
        except Exception as e:
            log('rkn', f'[{p.title}] ноды не получены: {e}')
            continue
        for n in nodes:
            if not isinstance(n, dict) or not exporter.node_is_watched(n, p):
                continue
            ip = resolve_ip(host_of(n.get('address')), state)
            if ip and _public(ip):
                add(ip, 'node', n.get('name') or ip)
    domains = list(links.DOMAINS) + [host_of(s.url) for s in cfg.sites] + list(cfg.rkn_extra)
    for d in domains:
        d = host_of(d)
        if not d:
            continue
        if _is_ip(d):
            if _public(d):
                add(d, 'node', d)
        else:
            add(d, 'domain', d)
    return out


def _get(path):
    req = urllib.request.Request(API + path, headers={'Accept': 'application/json',
                                                      'User-Agent': 'remnawave-monitoring'})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode('utf-8'))


def reasons(res):
    """Ответ /check → список причин блокировки (пусто — не в списках)."""
    res = res or {}
    out = []
    if res.get('rkn_domain'):
        out.append('домен в реестре РКН')
    subnets = [str(s) for s in (res.get('blocked_subnets') or []) if s]
    if subnets:
        out.append('подсеть в списках: ' + ', '.join(subnets[:3]) + (' …' if len(subnets) > 3 else ''))
    cdn = [str(k) for k, v in (res.get('cdn_providers') or {}).items() if v]
    if cdn and res.get('blocked'):
        out.append('заблокированный CDN: ' + ', '.join(cdn))
    if res.get('blocked') and not out:
        out.append('в списках блокировок')
    return out


def run(cfg, clients, check=None):
    """Проверить все цели и сохранить rkn/last.json. check — для тестов."""
    check = check or (lambda t: _get('/check?target=' + urllib.parse.quote(t, safe='')))
    items, errors = [], 0
    for i, t in enumerate(targets(cfg, clients)):
        if i:
            time.sleep(PAUSE)
        try:
            res = check(t['target'])
        except Exception as e:
            errors += 1
            log('rkn', f'{t["target"]}: {e}')
            items.append(dict(t, ok=False))
            continue
        why = reasons(res)
        items.append(dict(t, ok=True, blocked=bool(why), why='; '.join(why)))
    if items and errors == len(items):
        raise RuntimeError('cheburcheck.ru не ответил ни на одну цель')
    data = {'time': now().strftime('%Y-%m-%d %H:%M'), 'ts': time.time(), 'items': items}
    write_json(path(cfg), data)
    blocked = [x for x in items if x.get('blocked')]
    log('rkn', f'проверено {len(items) - errors} из {len(items)}, в списках: '
               + (', '.join(x['target'] for x in blocked) or 'ничего'))
    return data


def path(cfg):
    return os.path.join(cfg.data_dir, 'rkn', 'last.json')


def load_last(cfg):
    return read_json(path(cfg), None)


def telegram_section(data):
    """Блок для ежедневной сводки."""
    if not data:
        return []
    items = data.get('items') or []
    blocked = [x for x in items if x.get('blocked')]
    failed = [x for x in items if not x.get('ok')]
    lines = ['', '<b>🚫 Блокировки РФ</b> (cheburcheck, ' + esc(data.get('time', '')) + ' UTC)']
    for x in blocked:
        kind = 'нода' if x['kind'] == 'node' else 'домен'
        lines.append(f'• {kind} {esc(x["name"])} <code>{esc(x["target"])}</code> — {esc(x.get("why", ""))}')
    if not blocked:
        lines.append(f'• ни один из {len(items) - len(failed)} адресов не в списках')
    if failed:
        lines.append(f'<i>не проверены: {len(failed)}</i>')
    return lines
