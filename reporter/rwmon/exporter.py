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

from . import links
from .clients import ApiError, Remnawave
from .util import log, read_json

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
    'rwmon_site_up': ('gauge', 'Сайт открывается (1) или нет (0)'),
    'rwmon_site_status_code': ('gauge', 'HTTP-код ответа сайта'),
    'rwmon_site_response_seconds': ('gauge', 'Время ответа сайта'),
    'rwmon_site_cert_expiry_timestamp_seconds': ('gauge', 'Когда истекает сертификат сайта'),
    'rwmon_address_info': ('gauge', 'Какие хосты смотрят на этот адрес (для проб из РФ)'),
    'rwmon_panel_hosts': ('gauge', 'Сколько хостов панели проверяется'),
    'rwmon_host': ('gauge', 'Хост панели и имя его проверки (name) в xray-checker'),
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


def node_is_watched(node, panel):
    if node.get('isDisabled'):
        return False
    names = {(node.get('name') or '').lower()} | {t.lower() for t in node.get('tags') or []}
    return not (names & panel.exclude_nodes)


def resolve_ip(address, state):
    """Адрес ноды → IPv4 (для сопоставления нод с хостами и пробами). Кэш на час."""
    if not address:
        return ''
    try:
        ipaddress.ip_address(address)
        return address
    except ValueError:
        pass
    cached = state.get('ip:' + address)
    if cached and time.time() - cached[1] < 3600:
        return cached[0]
    try:
        ip = socket.getaddrinfo(address, None, socket.AF_INET)[0][4][0]
    except OSError:
        ip = cached[0] if cached else ''
    state['ip:' + address] = (ip, time.time())
    return ip


def collect_panel(panel, rw, lines, state, multi=False):
    """Опрос одной панели. Ошибка отдельного запроса не мешает остальным."""
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
    started = time.time()
    req = urllib.request.Request(site.url, headers=BROWSER)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(512 * 1024).decode('utf-8', 'replace')
            out['code'] = r.status
            out['up'] = int((site.any_status or 200 <= r.status < 400)
                            and (not site.keyword or site.keyword in body))
    except urllib.error.HTTPError as e:
        out['code'] = e.code
        out['up'] = int(site.any_status and not site.keyword)     # сервер ответил — для any_status этого хватает
    except Exception:
        pass
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


def host_lines(hosts, lines, panels=()):
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
    for h in hosts:
        lines.add('rwmon_host', {'panel': h['panel'], 'panel_title': h['panel_title'], 'host': h['host'],
                                 'name': h['name'], 'lite': '1' if h['lite'] else '0',
                                 'address': h.get('address', '')}, 1)


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
        self.clients = {p.id: Remnawave(p) for p in cfg.panels}
        self.text = '# нет данных — первый опрос ещё не завершён\n'
        self.state = {}
        self.sites = {}

    def poll_once(self):
        lines = Lines()
        for p in self.cfg.panels:
            part = Lines()
            try:
                collect_panel(p, self.clients[p.id], part, self.state, multi=self.cfg.multi)
            except Exception as e:       # неожиданный ответ одной панели не должен замораживать остальные
                _warn(self.state, p.id + ':crash', f'[{p.title}] ошибка разбора ответа панели: {e!r}')
                part = Lines()
                part.add('rwmon_panel_up', {'panel': p.id, 'panel_title': p.title}, 0)
            else:
                self.state.pop(p.id + ':crash', None)
            lines.merge(part)
        host_lines(links.HOSTS, lines, self.cfg.panels)
        site_lines(list(self.sites.values()), lines)
        try:
            geocheck_lines(self._geocheck(), lines, self.cfg)
        except Exception as e:
            _warn(self.state, 'geocheck', f'GeoCheck для Grafana: {e!r}')
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
        threading.Thread(target=self.loop, daemon=True).start()
        log('metrics', f'метрики панелей: http://127.0.0.1:{self.cfg.reporter_port}/metrics, '
                       f'опрос раз в {self.cfg.poll_interval} с')
