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
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import links
from .clients import ApiError, Remnawave
from .util import log

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
    'rwmon_host': ('gauge', 'Хост панели и имя его проверки (name) в xray-checker'),
    'rwmon_users': ('gauge', 'Пользователи по статусам'),
    'rwmon_users_online': ('gauge', 'Пользователи онлайн: сейчас / за сутки / за неделю'),
    'rwmon_users_total': ('gauge', 'Всего пользователей'),
    'rwmon_panel_traffic_exact': ('gauge', 'Трафик точный (из /metrics панели) — 1, приблизительный (из API) — 0'),
    'rwmon_panel_last_poll_seconds': ('gauge', 'Время последнего успешного опроса панели'),
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


def collect_panel(panel, rw, lines, state):
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
        if not node_is_watched(n, panel):
            continue
        uid = n['uuid']
        watched[uid] = n
        nl = dict(base, node_uuid=uid)
        lines.add('rwmon_node_info', dict(nl, node_name=n.get('name', uid),
                                          country=(n.get('countryCode') or '').upper()), 1)
        lines.add('rwmon_node_connected', nl, 1 if n.get('isConnected') else 0)
        lines.add('rwmon_node_online_users', nl, n.get('usersOnline', 0) if n.get('isConnected') else 0)
        system = n.get('system') or {}
        info, st = system.get('info') or {}, system.get('stats') or {}
        cpus, load = info.get('cpus'), st.get('loadAvg') or []
        if cpus and len(load) > 1:
            lines.add('rwmon_node_cpu_load5', nl, load[1] / cpus)
        if info.get('memoryTotal') and st.get('memoryUsed') is not None:
            lines.add('rwmon_node_memory_used_ratio', nl, st['memoryUsed'] / info['memoryTotal'])
        net = st.get('interface') or {}
        if net and n.get('isConnected'):
            lines.add('rwmon_node_network_rx_bytes_per_second', nl, net.get('rxBytesPerSec'))
            lines.add('rwmon_node_network_tx_bytes_per_second', nl, net.get('txBytesPerSec'))
            lines.add('rwmon_node_network_rx_bytes', nl, net.get('rxTotal'))
            lines.add('rwmon_node_network_tx_bytes', nl, net.get('txTotal'))

    exact = 0
    if panel.metrics_url:
        try:
            rows = parse_panel_metrics(rw.raw_metrics())
            exact = 1
            state.pop(panel.id + ':raw', None)
        except ApiError as e:
            _warn(state, panel.id + ':raw', f'{e} — беру приблизительный трафик из API')
    if not exact:
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
            version = rw.metadata().get('version', '')
        except ApiError:
            version = version or ''
        state[panel.id + ':version'], state[panel.id + ':version_at'] = version, time.time()
    if version:
        lines.add('rwmon_panel_info', dict(base, version=version), 1)
    state.pop(panel.id + ':nodes', None)
    return True


def host_lines(hosts, lines):
    for h in hosts:
        lines.add('rwmon_host', {'panel': h['panel'], 'panel_title': h['panel_title'], 'host': h['host'],
                                 'name': h['name'], 'lite': '1' if h['lite'] else '0'}, 1)


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
        self.ok = {}

    def poll_once(self):
        lines = Lines()
        for p in self.cfg.panels:
            self.ok[p.id] = collect_panel(p, self.clients[p.id], lines, self.state)
        host_lines(links.HOSTS, lines)
        self.text = lines.text()

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
        threading.Thread(target=self.loop, daemon=True).start()
        log('metrics', f'метрики панелей: http://127.0.0.1:{self.cfg.reporter_port}/metrics, '
                       f'опрос раз в {self.cfg.poll_interval} с')
