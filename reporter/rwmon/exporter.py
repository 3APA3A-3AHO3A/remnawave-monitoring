"""Метрики всех панелей для Prometheus.

Раз в poll_interval секунд reporter опрашивает API каждой панели и держит
в памяти готовый текст в формате Prometheus; Prometheus забирает его с
http://127.0.0.1:<reporter_port>/metrics. У каждой строки есть метки
panel (id из config.toml) и panel_title (подпись).

Трафик по инбаундам и аутбаундам: если у панели задан metrics_url — точные
счётчики из её /metrics; иначе из API (System → Get Nodes Metrics), где панель
отдаёт числа уже округлёнными («12.34 GiB»). Для графиков и сводки этого
хватает, а алерт «аутбаунд не отвечает» работает только с точными данными.

Выключенные в панели ноды и ноды из exclude_nodes не выгружаются вовсе —
их нет ни на графиках, ни в алертах.
"""
import ipaddress
import json
import os
import re
import socket
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import egress, feed, links, rkn
from .clients import DNS_RETRY_DELAY, ApiError, Prometheus, Remnawave, is_dns_error
from .util import log, read_json, resolve_ip

HELP = {
    'rwmon_panel_up': ('gauge', 'API панели отвечает (1) или нет (0)'),
    'rwmon_panel_info': ('gauge', 'Версия панели'),
    'rwmon_node_info': ('gauge', 'Нода: имя и страна'),
    'rwmon_node_connected': ('gauge', 'Нода подключена к панели'),
    'rwmon_node_online_users': ('gauge', 'Клиентов на ноде сейчас'),
    'rwmon_node_cpu_load5': ('gauge', 'Load average 5 мин на одно ядро'),
    'rwmon_node_memory_used_ratio': ('gauge', 'Доля занятой памяти'),
    'rwmon_node_inbound_upload_bytes': ('counter', 'Трафик клиентов: от клиента, по инбаундам'),
    'rwmon_node_inbound_download_bytes': ('counter', 'Трафик клиентов: к клиенту, по инбаундам'),
    'rwmon_node_outbound_upload_bytes': ('counter', 'Запросы в аутбаунд'),
    'rwmon_node_outbound_download_bytes': ('counter', 'Ответы из аутбаунда'),
    'rwmon_node_network_rx_bytes_per_second': ('gauge', 'Сеть сервера ноды: принято, байт/с'),
    'rwmon_node_network_tx_bytes_per_second': ('gauge', 'Сеть сервера ноды: отправлено, байт/с'),
    'rwmon_node_network_rx_bytes': ('counter', 'Сеть сервера ноды: принято всего'),
    'rwmon_node_network_tx_bytes': ('counter', 'Сеть сервера ноды: отправлено всего'),
    'rwmon_node_uptime_seconds': ('gauge', 'Сколько секунд работает сервер ноды'),
    'rwmon_node_xray_uptime_seconds': ('gauge', 'Сколько секунд работает Xray на ноде'),
    'rwmon_node_version': ('gauge', 'Версии Xray и ноды'),
    'rwmon_node_traffic_used_bytes': ('gauge', 'Трафик ноды за расчётный период (учёт в панели)'),
    'rwmon_node_traffic_limit_bytes': ('gauge', 'Лимит трафика ноды (учёт в панели)'),
    'rwmon_node_address': ('gauge', 'IP ноды (для сопоставления с хостами и пробами из РФ)'),
    'rwmon_geocheck': ('gauge', 'GeoCheck: как сервис видит ноду (value)'),
    'rwmon_geocheck_info': ('gauge', 'GeoCheck: IP, сеть, тип IP ноды'),
    'rwmon_geocheck_risk': ('gauge', 'GeoCheck: риск IP, 0–100'),
    'rwmon_geocheck_timestamp_seconds': ('gauge', 'Когда был последний GeoCheck'),
    'rwmon_rkn_blocked': ('gauge', 'Блокировки РФ (cheburcheck): IP ноды или домен в списках (1) или нет (0)'),
    'rwmon_rkn_timestamp_seconds': ('gauge', 'Когда была последняя проверка блокировок РФ'),
    'rwmon_site_up': ('gauge', 'Сайт открывается (1) или нет (0)'),
    'rwmon_site_status_code': ('gauge', 'HTTP-код ответа сайта'),
    'rwmon_site_response_seconds': ('gauge', 'Время ответа сайта'),
    'rwmon_site_cert_expiry_timestamp_seconds': ('gauge', 'Когда истекает сертификат сайта'),
    'rwmon_address_info': ('gauge', 'Какие хосты смотрят на этот адрес (для проб из РФ)'),
    'rwmon_panel_hosts': ('gauge', 'Сколько хостов панели проверяется'),
    'rwmon_host': ('gauge', 'Хост панели и имя его проверки (name) в xray-checker'),
    'rwmon_exit_info': ('gauge', 'Страна и сеть IP выхода проверок (DB-IP Lite)'),
    'rwmon_host_state': ('gauge', 'Итог по хосту: 0 работает, 1 не открывается из РФ, 2 не работает вход, '
                                  '3 нода не отвечает, 4 не работает из РФ, а вход из-за границы не проверить'),
    'rwmon_ru_probe_up': ('gauge', 'Проба из РФ присылает результаты (1) или давно молчит (0)'),
    'rwmon_ru_probe_age_seconds': ('gauge', 'Сколько секунд назад проба из РФ присылала результаты'),
    'rwmon_ru_probe_hosts': ('gauge', 'Сколько хостов проба из РФ проверяет'),
    'rwmon_ru_status': ('gauge', 'Проверка из РФ: хост работает (1) или нет (0), по каждой пробе'),
    'rwmon_ru_latency_ms': ('gauge', 'Проверка из РФ: время ответа через хост, мс'),
    'rwmon_ru_error_code': ('gauge', 'Проверка из РФ: причина сбоя числом (как xray_proxy_error_code)'),
    'rwmon_users': ('gauge', 'Пользователи по статусам'),
    'rwmon_users_online': ('gauge', 'Пользователи онлайн: сейчас / за сутки / за неделю'),
    'rwmon_users_total': ('gauge', 'Всего пользователей'),
    'rwmon_panel_traffic_exact': ('gauge', 'Трафик точный (из /metrics панели) — 1, приблизительный (из API) — 0'),
    'rwmon_panel_last_poll_seconds': ('gauge', 'Время последнего успешного опроса панели'),
    'rwmon_panel_process_memory_bytes': ('gauge', 'Процесс панели: занятая память (RSS)'),
    'rwmon_panel_process_heap_bytes': ('gauge', 'Процесс панели: память под данные JavaScript (heap)'),
    'rwmon_panel_process_lag_ms': ('gauge', 'Процесс панели: задержка очереди дел, мс (99-й перцентиль)'),
    'rwmon_panel_process_uptime_seconds': ('gauge', 'Процесс панели: сколько секунд работает без перезапуска'),
    'rwmon_panel_process_handles': ('gauge', 'Процесс панели: открытые соединения и таймеры'),
}


def _esc(v):
    return str(v).replace('\\', '\\\\').replace('"', '\\"').replace('\n', ' ')


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


class Lines:
    def __init__(self):
        self.rows = {}

    def add(self, name, labels, value):
        value = _num(value)
        if value is None:
            return
        lab = ','.join(f'{k}="{_esc(v)}"' for k, v in labels.items())
        num = str(int(value)) if value.is_integer() else repr(value)   # без потери точности
        self.rows.setdefault(name, []).append(f'{name}{{{lab}}} {num}')

    def merge(self, other):
        for name, rows in other.rows.items():
            self.rows.setdefault(name, []).extend(rows)

    def text(self):
        out = []
        for name, rows in self.rows.items():
            kind, help_ = HELP.get(name, ('gauge', ''))
            out += [f'# HELP {name} {help_}', f'# TYPE {name} {kind}', *rows]
        return '\n'.join(out) + '\n'


UNITS = {'': 1, 'B': 1, 'K': 1024, 'M': 1024 ** 2, 'G': 1024 ** 3, 'T': 1024 ** 4, 'P': 1024 ** 5}
TRAFFIC = ('inbound_upload', 'inbound_download', 'outbound_upload', 'outbound_download')


def parse_size(text):
    """«12.34 GiB» → байты. API панели отдаёт трафик только так, с округлением."""
    m = re.fullmatch(r'\s*([\d.]+)\s*([KMGTP]?)i?B?\s*', str(text), re.I)
    if not m:
        return _num(text)
    return float(m[1]) * UNITS[m[2].upper()]


def traffic_from_api(nodes_metrics):
    """System → Get Nodes Metrics: [(метрика, node_uuid, tag, байты)], приблизительно."""
    rows = []
    for m in nodes_metrics:
        for kind, key in (('inbound', 'inboundsStats'), ('outbound', 'outboundsStats')):
            for st in m.get(key) or []:
                for d in ('upload', 'download'):
                    v = parse_size(st.get(d))
                    if v is not None:
                        rows.append((f'rwmon_node_{kind}_{d}_bytes', m.get('nodeUuid'), st.get('tag', ''), v))
    return rows


_SAMPLE = re.compile(r'^remnawave_node_(%s)_bytes\{(.*)\}\s+(\S+)' % '|'.join(TRAFFIC))
_LABEL = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')


def parse_panel_metrics(text):
    """/metrics панели: точные счётчики трафика по нодам и тегам."""
    rows = []
    for line in text.splitlines():
        m = _SAMPLE.match(line)
        if not m:
            continue
        labels = dict(_LABEL.findall(m[2]))
        v = _num(m[3])
        if v is not None and labels.get('node_uuid'):
            rows.append((f'rwmon_node_{m[1]}_bytes', labels['node_uuid'], labels.get('tag', ''), v))
    return rows


def is_public_ip(ip):
    """Публичный адрес: у ноды на сервере самой панели адрес внутренний (172.18.0.1) —
    её node_exporter с сервера мониторинга не достать."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def node_targets_file(cfg):
    return os.path.join(os.path.dirname(cfg.links_file) or '.', 'nodes.json')


def write_node_targets(cfg, by_panel):
    """Список нод для Prometheus (file_sd): IP:порт node_exporter с метками panel и node_uuid —
    по ним графики находят название ноды в rwmon_node_info. Одна нода в двух панелях — один раз."""
    seen, groups = set(), []
    for pid in sorted(by_panel):
        for ip, labels in sorted(by_panel[pid].items()):
            if ip in seen:
                continue
            seen.add(ip)
            groups.append({'targets': [f'{ip}:{cfg.node_exporter_port}'], 'labels': dict(labels)})
    return links.write_if_changed(node_targets_file(cfg), json.dumps(groups, ensure_ascii=False))


def node_is_watched(node, panel):
    if node.get('isDisabled'):
        return False
    names = {(node.get('name') or '').lower()} | {t.lower() for t in node.get('tags') or []}
    return not (names & panel.exclude_nodes)


def collect_panel(panel, rw, lines, state, multi=False, node_ips=None, node_targets=None):
    """Опрос одной панели. Ошибка отдельного запроса не мешает остальным.
    node_ips — сюда пишется «IP ноды → её название», по нему хосты узнают свою ноду.
    node_targets — «публичный IP ноды → метки» для node_exporter (Prometheus file_sd)."""
    base = {'panel': panel.id, 'panel_title': panel.title}
    try:
        nodes = rw.nodes()
    except ApiError as e:
        _warn(state, panel.id + ':nodes', e)
        lines.add('rwmon_panel_up', base, 0)
        return False
    lines.add('rwmon_panel_up', base, 1)
    lines.add('rwmon_panel_last_poll_seconds', base, time.time())

    watched = {}
    for n in nodes:
        if not isinstance(n, dict) or not n.get('uuid') or not node_is_watched(n, panel):
            continue
        uid = n['uuid']
        watched[uid] = n
        nl = dict(base, node_uuid=uid)
        name = n.get('name') or uid
        lines.add('rwmon_node_info', dict(nl, node_name=name, node=f'{name} · {panel.title}' if multi else name,
                                          country=(n.get('countryCode') or '').upper()), 1)
        ip = resolve_ip(str(n.get('address') or ''), state)
        if ip:
            lines.add('rwmon_node_address', dict(nl, ip=ip), 1)
            if node_ips is not None:
                node_ips.setdefault(ip, f'{name} · {panel.title}' if multi else name)
            if node_targets is not None and is_public_ip(ip):
                node_targets.setdefault(ip, {'panel': panel.id, 'node_uuid': uid})
        lines.add('rwmon_node_connected', nl, 1 if n.get('isConnected') else 0)
        lines.add('rwmon_node_online_users', nl, n.get('usersOnline', 0) if n.get('isConnected') else 0)
        system = n.get('system') or {}
        info, st = system.get('info') or {}, system.get('stats') or {}
        cpus, load = info.get('cpus'), st.get('loadAvg') or []
        if cpus and len(load) > 1:
            lines.add('rwmon_node_cpu_load5', nl, load[1] / cpus)
        if info.get('memoryTotal') and st.get('memoryUsed') is not None:
            lines.add('rwmon_node_memory_used_ratio', nl, st['memoryUsed'] / info['memoryTotal'])
        lines.add('rwmon_node_uptime_seconds', nl, st.get('uptime'))
        if n.get('isConnected'):
            lines.add('rwmon_node_xray_uptime_seconds', nl, n.get('xrayUptime'))
        versions = n.get('versions') or {}
        if versions:
            lines.add('rwmon_node_version', dict(nl, xray=versions.get('xray', ''),
                                                 node=versions.get('node', '')), 1)
        if n.get('isTrafficTrackingActive') and n.get('trafficLimitBytes'):
            lines.add('rwmon_node_traffic_used_bytes', nl, n.get('trafficUsedBytes'))
            lines.add('rwmon_node_traffic_limit_bytes', nl, n.get('trafficLimitBytes'))
        net = st.get('interface') or {}
        if net and n.get('isConnected'):
            lines.add('rwmon_node_network_rx_bytes_per_second', nl, net.get('rxBytesPerSec'))
            lines.add('rwmon_node_network_tx_bytes_per_second', nl, net.get('txBytesPerSec'))
            lines.add('rwmon_node_network_rx_bytes', nl, net.get('rxTotal'))
            lines.add('rwmon_node_network_tx_bytes', nl, net.get('txTotal'))

    # Точные и округлённые счётчики в одну серию не смешиваем: округлённое значение
    # меньше точного, Prometheus принял бы это за сброс счётчика и насчитал бы лишний трафик.
    exact = 1 if panel.metrics_url else 0
    if exact:
        try:
            rows = parse_panel_metrics(rw.raw_metrics())
            state.pop(panel.id + ':raw', None)
        except ApiError as e:
            _warn(state, panel.id + ':raw', f'{e} — трафик в этот раз пропускаю')
            rows = []
    else:
        try:
            rows = traffic_from_api(rw.nodes_metrics())
            state.pop(panel.id + ':metrics', None)
        except ApiError as e:
            _warn(state, panel.id + ':metrics', e)
            rows = []
    for name, uid, tag, value in rows:
        if uid in watched:
            lines.add(name, dict(base, node_uuid=uid, tag=tag), value)
    lines.add('rwmon_panel_traffic_exact', base, exact)

    try:
        s = rw.stats()
        users = s.get('users') or {}
        for status, count in (users.get('statusCounts') or {}).items():
            lines.add('rwmon_users', dict(base, status=status), count)
        lines.add('rwmon_users_total', base, users.get('totalUsers'))
        for period, count in (s.get('onlineStats') or {}).items():
            lines.add('rwmon_users_online', dict(base, period=period), count)
        state.pop(panel.id + ':stats', None)
    except ApiError as e:
        _warn(state, panel.id + ':stats', e)

    version = state.get(panel.id + ':version')
    if version is None or time.time() - state.get(panel.id + ':version_at', 0) > 3600:
        try:
            version = str((rw.metadata() or {}).get('version') or '')
        except ApiError:
            version = version or ''
        state[panel.id + ':version'], state[panel.id + ':version_at'] = version, time.time()
    if version:
        lines.add('rwmon_panel_info', dict(base, version=version), 1)

    try:
        health_lines(base, rw.health(), lines)
        state.pop(panel.id + ':health', None)
    except ApiError as e:                # старые версии панели этого не умеют — просто пропускаем
        _warn(state, panel.id + ':health', e)
    state.pop(panel.id + ':nodes', None)
    return True


HEALTH_FIELDS = (('rwmon_panel_process_memory_bytes', 'rss'),
                 ('rwmon_panel_process_heap_bytes', 'heapUsed'),
                 ('rwmon_panel_process_lag_ms', 'eventLoopP99Ms'),
                 ('rwmon_panel_process_uptime_seconds', 'uptime'),
                 ('rwmon_panel_process_handles', 'activeHandles'))


def health_lines(base, metrics, lines):
    """Здоровье процессов панели. pid в метки не кладём: после перезапуска он другой,
    и Prometheus увидел бы новую серию вместо сброса uptime."""
    for m in metrics:
        if not isinstance(m, dict) or not m.get('instanceType'):
            continue
        pl = dict(base, process=str(m['instanceType']), instance=str(m.get('instanceId', '0')))
        for name, key in HEALTH_FIELDS:
            if isinstance(m.get(key), (int, float)):
                lines.add(name, pl, m[key])


def exit_lines(prom, lookup, lines, state):
    """rwmon_exit_info{ip, country, asn, as_org} по IP выхода проверок (xray_proxy_exit_ip):
    по ним правила egress_country / egress_asn видят, где оказался трафик."""
    try:
        ips = {m.get('ip') for m, _ in prom.query('max by (ip) (xray_proxy_exit_ip)') if m.get('ip')}
    except Exception as e:
        _warn(state, 'exit-ip', f'IP выхода проверок из Prometheus: {e}')
        return
    for ip in sorted(ips):
        info = lookup.get(ip)
        if info is None:
            return                    # баз DB-IP ещё нет — подождём, пока reporter их скачает
        country, asn, org = info
        lines.add('rwmon_exit_info', {'ip': ip, 'country': country or '?', 'asn': str(asn or 0),
                                      'as_org': org}, 1)


def rkn_lines(data, lines):
    """Блокировки РФ: по строке на каждый проверенный адрес; name — как подписать в алерте."""
    if not data:
        return
    for x in data.get('items') or []:
        if not x.get('ok'):
            continue
        name = x['name'] if x['name'] == x['target'] else f'{x["name"]} · {x["target"]}'
        lines.add('rwmon_rkn_blocked', {'target': x['target'], 'kind': x['kind'], 'name': name,
                                        'why': x.get('why', '')}, 1 if x.get('blocked') else 0)
    lines.add('rwmon_rkn_timestamp_seconds', {}, data.get('ts'))


def geocheck_lines(run, lines, cfg):
    """Последний GeoCheck в Prometheus — для таблиц «кто как видит ноду» в Grafana."""
    if not run:
        return
    try:
        ts = datetime.fromisoformat(run.get('finished', '')).timestamp()
    except ValueError:
        ts = None
    titles = {p.id: p.title for p in cfg.panels}
    for key, r in (run.get('results') or {}).items():
        pid, _, uid = key.partition(':')
        if not uid:                   # прогон версии для одной панели: ключ — просто uuid ноды
            pid, uid = cfg.panels[0].id, key
        if not r.get('summary'):
            continue
        base = {'panel': pid, 'panel_title': titles.get(pid, pid), 'node_uuid': uid}
        sm = r['summary']
        lines.add('rwmon_geocheck_info', dict(base, ip=sm.get('ip', ''), network=sm.get('network', ''),
                                              ip_type=sm.get('type', ''), place=sm.get('place', ''),
                                              consensus=sm.get('consensus', '')), 1)
        lines.add('rwmon_geocheck_risk', base, sm.get('risk'))
        lines.add('rwmon_geocheck_timestamp_seconds', base, ts)
        for c in (sm.get('checks') or {}).values():
            lines.add('rwmon_geocheck', dict(base, group=c.get('group', ''), service=c.get('name', ''),
                                             value=c.get('value', '')), 1)


def check_site(site, timeout=15):
    """Открыть страницу как браузер: код ответа, время, ключевое слово и срок сертификата."""
    out = {'up': 0, 'code': None, 'seconds': None, 'cert': None}
    req = urllib.request.Request(site.url, headers=BROWSER)
    for attempt in (1, 2):
        started = time.time()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read(512 * 1024).decode('utf-8', 'replace')
                out['code'] = r.status
                out['up'] = int((site.any_status or 200 <= r.status < 400)
                                and (not site.keyword or site.keyword in body))
        except urllib.error.HTTPError as e:
            out['code'] = e.code
            out['up'] = int(site.any_status and not site.keyword)  # сервер ответил — для any_status этого хватает
        except Exception as e:
            if attempt == 1 and is_dns_error(e):      # мгновенный сбой DNS — пробуем ещё раз
                time.sleep(DNS_RETRY_DELAY)
                continue
        break
    out['seconds'] = time.time() - started
    host = urllib.parse.urlsplit(site.url)
    if host.scheme == 'https':
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host.hostname, host.port or 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host.hostname) as tls:
                    out['cert'] = ssl.cert_time_to_seconds(tls.getpeercert()['notAfter'])
        except Exception:
            pass                     # сертификат не прошёл проверку — сайт и так будет «не открывается»
    return out


def site_lines(results, lines):
    """results — [(Site, результат check_site)]."""
    for site, r in results:
        base = {'site': site.name}          # без url: в нём может быть секретная ссылка подписки
        lines.add('rwmon_site_up', base, r['up'])
        lines.add('rwmon_site_status_code', base, r['code'])
        lines.add('rwmon_site_response_seconds', base, r['seconds'])
        lines.add('rwmon_site_cert_expiry_timestamp_seconds', base, r['cert'])


def host_exit(h, panels, node_ips, state):
    """Куда ведёт хост: из host_exit панели, иначе нода с тем же IP (в любой панели), иначе пусто."""
    for p in panels:
        if p.id == h['panel'] and h['host'] in p.host_exit:
            return p.host_exit[h['host']]
    if not node_ips:
        return ''
    server = (h.get('address') or '').rsplit(':', 1)[0].strip('[]')
    return node_ips.get(resolve_ip(server, state), '') if server else ''


def _node_panel(match, own, by_panel):
    """Первая панель (своя — первой), где есть нода, подходящая под match(ip, название)."""
    order = [own] + [p for p in by_panel if p != own]
    for pid in order:
        if any(match(ip, name) for ip, name in (by_panel.get(pid) or {}).items()):
            return pid
    return ''


def host_owner(h, panels, by_panel, state):
    """Панель-владелец хоста — та, где зарегистрирована его нода: по host_exit,
    иначе по IP адреса хоста. Не нашлась — панель самого хоста.
    by_panel — {панель: {IP ноды: название}}."""
    own = h['panel']
    if not by_panel:
        return own
    for p in panels:
        if p.id == own and h['host'] in p.host_exit:
            target = p.host_exit[h['host']]
            pid = _node_panel(lambda ip, name: name == target or name.startswith(target + ' · '), own, by_panel)
            return pid or own
    server = (h.get('address') or '').rsplit(':', 1)[0].strip('[]')
    ip = resolve_ip(server, state) if server else ''
    return (_node_panel(lambda node_ip, name: node_ip == ip, own, by_panel) if ip else '') or own


def host_lines(hosts, lines, panels=(), node_ips=None, state=None, by_panel=None, check_ids=('warp', 'psiphon')):
    """rwmon_host — по строке на хост каждой панели. Хост, общий для нескольких панелей,
    даёт несколько строк; ровно у одной primary="1" — у строки панели-владельца ноды
    (owner), а если у владельца такого хоста нет — у первой. Алерты о хостах берут только
    её и уходят в чат владельца: один сбой — одно сообщение."""
    state = {} if state is None else state
    for p in panels:              # сколько хостов панели проверяется — 0 тоже важен
        lines.add('rwmon_panel_hosts', {'panel': p.id, 'panel_title': p.title},
                  sum(1 for h in hosts if h['panel'] == p.id))
    names = {}
    for h in hosts:                   # один адрес — все названия хостов на нём (для проб из РФ)
        if h.get('address'):
            label = f'{h["host"]} · {h["panel_title"]}' if len(panels) > 1 else h['host']
            names.setdefault(h['address'], []).append(label)
    for address, hs in names.items():
        lines.add('rwmon_address_info', {'address': address, 'hosts': ', '.join(sorted(set(hs)))}, 1)
    owners, primary = {}, {}
    for i, h in enumerate(hosts):
        owner = owners.setdefault(h['name'], host_owner(h, panels, by_panel, state))
        if h['panel'] == owner or h['name'] not in primary:
            if h['name'] not in primary or hosts[primary[h['name']]]['panel'] != owner:
                primary[h['name']] = i
    for i, h in enumerate(hosts):
        labels = {'panel': h['panel'], 'panel_title': h['panel_title'], 'host': h['host'],
                  'name': h['name'], 'lite': '1' if h['lite'] else '0', 'address': h.get('address', ''),
                  'owner': owners[h['name']], 'primary': '1' if primary[h['name']] == i else '0'}
        # какие проверки маршрутов нужны хосту: метка на каждую проверку, warp="1";
        # у записи из старого кэша без 'checks' — как раньше: полному хосту все
        checks = h['checks'] if 'checks' in h else ([] if h['lite'] else list(check_ids))
        for c in check_ids:
            labels[c] = '1' if c in checks else '0'
        labels['entry'] = '1' if h.get('entry') else '0'     # есть отдельная проверка «через вход»
        labels['ru'] = '1' if h.get('ru') else '0'           # проверяется из РФ
        target = host_exit(h, panels, node_ips, state)
        if target:                    # в алерте: «LTE 3 · OVRO → CDN 1 · FixErrorVPN»
            labels['exit'] = target
        lines.add('rwmon_host', labels, 1)


# ── итог по хосту ────────────────────────────────────────────

OK, RU_BLOCKED, ENTRY_DOWN, NODE_DOWN, ENTRY_UNSEEN = 0, 1, 2, 3, 4


def ru_lines(cfg, store, lines, now=None):
    """Результаты проб из РФ (feed.py) → метрики. Возвращает {проба: результаты} только
    свежих проб: у молчащей пробы результатов нет — итог считается без неё."""
    now = now or time.time()
    data, _ = store.snapshot()
    fresh = {}
    for p in cfg.probes:
        t, res = data.get(p.name, (0, {}))
        up = bool(t) and now - t < feed.FRESH
        lines.add('rwmon_ru_probe_up', {'probe': p.name}, 1 if up else 0)
        if t:
            lines.add('rwmon_ru_probe_age_seconds', {'probe': p.name}, round(now - t))
        if not up:
            continue
        fresh[p.name] = res
        lines.add('rwmon_ru_probe_hosts', {'probe': p.name}, len(res))
        for name, r in res.items():
            lb = {'probe': p.name, 'name': name}
            lines.add('rwmon_ru_status', lb, r.get('status', 0))
            if 'latency_ms' in r:
                lines.add('rwmon_ru_latency_ms', lb, r['latency_ms'])
            if 'error_code' in r:
                lines.add('rwmon_ru_error_code', lb, r['error_code'])
    return fresh


def host_state(h, ru, node, entry, entry_seen=True):
    """Итог по хосту. ru — из РФ: 1 открылся хоть с одной пробы, 0 ни с одной, None — нет
    данных (хост из РФ не проверяется или пробы молчат). node / entry — с сервера мониторинга
    напрямую на ноду и через вход (у хостов без отдельного входа entry = node).
    entry_seen — вход хоть раз открывался из-за границы за сутки: у прокладок, до которых
    из-за границы не достучаться, «вход не отвечает» ничего не говорит."""
    if ru == 1:
        return OK
    if node == 0:
        return NODE_DOWN
    if ru == 0:
        if entry == 0 and h.get('entry'):
            return ENTRY_DOWN if entry_seen else ENTRY_UNSEEN
        return RU_BLOCKED
    # из РФ данных нет — решаем по серверу мониторинга
    if entry == 0 and h.get('entry') and entry_seen:
        return ENTRY_DOWN
    return OK


def nl_results(prom, state):
    """С сервера мониторинга: {(проверка, имя): 0/1} и имена, чей вход за сутки ни разу не открылся."""
    try:
        now = {(m.get('check'), m.get('name')): int(v) for m, v in
               prom.query('max by (check, name) (xray_proxy_status{check=~"xray|entry"})')}
        never = {m.get('name') for m, v in
                 prom.query('max by (name) (max_over_time(xray_proxy_status{check="entry"}[24h])) == 0')}
    except Exception as e:
        _warn(state, 'nl-results', f'результаты проверок из Prometheus: {e}')
        return None, set()
    state.pop('nl-results', None)
    return now, never


def state_lines(hosts, fresh, nl, never, lines):
    """rwmon_host_state по каждому имени проверки."""
    done = set()
    for h in hosts:
        name = h['name']
        if name in done:
            continue
        done.add(name)
        ru = None
        if h.get('ru'):
            vals = [res[name].get('status', 0) for res in fresh.values() if name in res]
            ru = (1 if max(vals) >= 1 else 0) if vals else None
        node = nl.get(('xray', name))
        entry = nl.get(('entry', name)) if h.get('entry') else node
        if ru is None and node is None:
            continue                     # ни одного результата — итог не считаем
        lines.add('rwmon_host_state', {'name': name}, host_state(h, ru, node, entry, name not in never))


SITE_EVERY = 60     # как часто проверять сайты, секунд
# Представляемся обычным Chrome: страница подписки Remnawave на «полубраузер»
# (например «Mozilla/5.0 rwmon») отвечает 502, а на настоящий браузер — 200.
BROWSER = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/130.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'ru,en;q=0.9',
}


def _warn(state, key, err):
    """Одна и та же ошибка пишется в журнал один раз, а не каждые 30 секунд."""
    msg = str(err)
    if state.get(key) != msg:
        log('metrics', msg)
        state[key] = msg


class Exporter:
    def __init__(self, cfg):
        self.cfg = cfg
        self.bot = None                 # bot.Bot, если в config.toml есть [bot]
        self.clients = {p.id: Remnawave(p) for p in cfg.panels}
        self.text = '# нет данных — первый опрос ещё не завершён\n'
        self.state = {}
        self.sites = {}
        self.node_ips = {}            # панель → {IP ноды: название}; при сбое панели остаётся прошлый
        self.node_targets = {}        # панель → {IP ноды: метки} для node_exporter; при сбое — прошлый
        self.prom = Prometheus(cfg.prometheus_url)
        self.ru = feed.Store()          # результаты проб из РФ (приходят через feed.py)
        self.exit_lookup = egress.Lookup(cfg) if egress.needed(cfg) else None

    def poll_once(self):
        lines = Lines()
        for p in self.cfg.panels:
            part, ips, targets = Lines(), {}, {}
            try:
                if collect_panel(p, self.clients[p.id], part, self.state, multi=self.cfg.multi, node_ips=ips,
                                 node_targets=targets):
                    self.node_ips[p.id] = ips
                    self.node_targets[p.id] = targets
            except Exception as e:       # неожиданный ответ одной панели не должен замораживать остальные
                _warn(self.state, p.id + ':crash', f'[{p.title}] ошибка разбора ответа панели: {e!r}')
                part = Lines()
                part.add('rwmon_panel_up', {'panel': p.id, 'panel_title': p.title}, 0)
            else:
                self.state.pop(p.id + ':crash', None)
            lines.merge(part)
        node_ips = {}
        for ips in self.node_ips.values():
            for ip, name in ips.items():
                node_ips.setdefault(ip, name)
        if self.cfg.node_exporter_port:
            write_node_targets(self.cfg, self.node_targets)
        host_lines(links.HOSTS, lines, self.cfg.panels, node_ips, self.state, by_panel=self.node_ips,
                   check_ids=[c.id for c in self.cfg.route_checks])
        fresh = ru_lines(self.cfg, self.ru, lines)
        nl, never = nl_results(self.prom, self.state)
        if nl is not None:
            state_lines(links.HOSTS, fresh, nl, never, lines)
        site_lines(list(self.sites.values()), lines)
        if self.exit_lookup is not None:
            exit_lines(self.prom, self.exit_lookup, lines, self.state)
        try:
            geocheck_lines(self._geocheck(), lines, self.cfg)
        except Exception as e:
            _warn(self.state, 'geocheck', f'GeoCheck для Grafana: {e!r}')
        if self.cfg.rkn_enabled:
            rkn_lines(rkn.load_last(self.cfg), lines)
        self.text = lines.text()

    def _geocheck(self):
        """Последний прогон GeoCheck; файл перечитываем, только если он изменился."""
        path = os.path.join(self.cfg.data_dir, 'geocheck', 'last-run.json')
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            return None
        if self.state.get('geocheck_mtime') != mtime:
            self.state['geocheck_run'] = read_json(path, None)
            self.state['geocheck_mtime'] = mtime
        return self.state.get('geocheck_run')

    def site_loop(self):
        while True:
            for site in self.cfg.sites:
                try:
                    self.sites[site.name] = (site, check_site(site))
                except Exception as e:       # проверка сайта не должна ронять reporter
                    _warn(self.state, 'site:' + site.name, f'сайт {site.name}: {e!r}')
            time.sleep(SITE_EVERY)

    def loop(self):
        while True:
            started = time.time()
            try:
                self.poll_once()
            except Exception as e:           # экспортёр не должен падать никогда
                log('metrics', f'ошибка опроса: {e}')
            time.sleep(max(1, self.cfg.poll_interval - (time.time() - started)))

    def start(self):
        exporter = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                """Алерты от Grafana для бота (contact point rwmon-bot)."""
                if self.path.split('?')[0] != '/alert' or exporter.bot is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                try:
                    payload = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
                    exporter.bot.on_alert(payload)
                    self.send_response(200)
                except Exception as e:
                    log('bot', f'алерт от Grafana не обработан: {e}')
                    self.send_response(500)
                self.end_headers()

            def do_GET(self):
                if self.path.split('?')[0] != '/metrics':
                    self.send_response(404)
                    self.end_headers()
                    return
                body = exporter.text.encode()
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', self.cfg.reporter_port), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        if self.cfg.sites:
            threading.Thread(target=self.site_loop, daemon=True).start()
        feed.start(self.cfg, self.ru)
        threading.Thread(target=self.loop, daemon=True).start()
        log('metrics', f'метрики панелей: http://127.0.0.1:{self.cfg.reporter_port}/metrics, '
                       f'опрос раз в {self.cfg.poll_interval} с')
