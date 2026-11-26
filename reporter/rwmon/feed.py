"""Связь с пробами из РФ (папка probe/).

Проба сама приходит на сервер мониторинга по HTTPS (порт [checks] ru_port, 9116):
  GET  /ru/hosts.json — список хостов для проверки (его пишет links.py);
  POST /ru/metrics    — результаты своей проверки (метрики xray-checker как текст).
Вход — логин и пароль пробы из её блока [[probe]]: какая проба пришла, узнаём по паролю.
Сертификат самоподписанный: проба при установке запоминает его ключ (pinning),
поэтому подменить сервер мониторинга нельзя.

Результаты хранятся в памяти: reporter отдаёт их в Prometheus (exporter.ru_lines),
а если проба давно не приходила — считается, что данных из РФ от неё нет.
"""
import base64
import hashlib
import hmac
import os
import re
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import links
from .util import log

MAX_BODY = 4 * 1024 * 1024
FRESH = 180          # результаты пробы старше — устарели (проба присылает их раз в минуту)
KEEP = ('xray_proxy_status', 'xray_proxy_latency_ms', 'xray_proxy_error_code')

_LINE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{(.*)\})?\s+(\S+)')
_LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')


def parse_metrics(text):
    """Метрики xray-checker (текстовый формат Prometheus) → {имя проверки: {метрика: число}}."""
    out = {}
    for line in text.splitlines():
        if not line or line[0] == '#':
            continue
        m = _LINE.match(line)
        if not m or m.group(1) not in KEEP:
            continue
        labels = {k: bytes(v, 'utf-8').decode('unicode_escape').encode('latin-1').decode('utf-8')
                  for k, v in _LABEL.findall(m.group(3) or '')}
        name = labels.get('name', '')
        if not name or name == links.EMPTY_NAME:
            continue
        try:
            value = float(m.group(4))
        except ValueError:
            continue
        # при обновлении списка у одного имени ненадолго бывает две серии — берём лучшую
        cur = out.setdefault(name, {})
        metric = m.group(1).removeprefix('xray_proxy_')
        cur[metric] = max(cur.get(metric, value), value) if metric == 'status' else value
    return out


class Store:
    """Последние результаты каждой пробы: {проба: (время, {имя: {status, latency_ms, error_code}})}."""

    def __init__(self):
        self.lock = threading.Lock()
        self.data = {}
        self.seen = {}           # проба → когда последний раз приходила за списком

    def put(self, probe, results, now=None):
        with self.lock:
            self.data[probe] = (now or time.time(), results)

    def touch(self, probe, now=None):
        with self.lock:
            self.seen[probe] = now or time.time()

    def snapshot(self):
        with self.lock:
            return dict(self.data), dict(self.seen)


# ── сертификат ───────────────────────────────────────────────

def cert_paths(cfg):
    folder = os.path.join(cfg.data_dir, 'ru-feed')
    return os.path.join(folder, 'tls.crt'), os.path.join(folder, 'tls.key')


def ensure_cert(cfg):
    """Самоподписанный сертификат на 10 лет; создаётся один раз и хранится в /data."""
    crt, key = cert_paths(cfg)
    if os.path.exists(crt) and os.path.exists(key):
        return crt, key
    os.makedirs(os.path.dirname(crt), mode=0o700, exist_ok=True)
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
                    '-nodes', '-days', '3650', '-subj', '/CN=rwmon-monitoring', '-keyout', key, '-out', crt],
                   check=True, capture_output=True)
    os.chmod(key, 0o600)
    return crt, key


def pin(crt):
    """sha256 открытого ключа в формате curl --pinnedpubkey: sha256//<base64>."""
    pub = subprocess.run(['openssl', 'x509', '-in', crt, '-pubkey', '-noout'], check=True,
                         capture_output=True).stdout
    der = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'der'], input=pub, check=True,
                         capture_output=True).stdout
    return 'sha256//' + base64.b64encode(hashlib.sha256(der).digest()).decode()


# ── сервер ───────────────────────────────────────────────────

def who(cfg, header):
    """Какая проба пришла: по логину и паролю из заголовка Authorization (Basic)."""
    if not header or not header.startswith('Basic '):
        return None
    try:
        user, _, password = base64.b64decode(header[6:]).decode().partition(':')
    except Exception:
        return None
    for p in cfg.probes:
        if p.password and hmac.compare_digest(p.password, password) and (not p.user or p.user == user):
            return p.name
    return None


def start(cfg, store):
    """HTTPS-сервер для проб. Без [[probe]] не запускается."""
    if not cfg.probes:
        return None
    try:
        crt, key = ensure_cert(cfg)
        log('ru', f'пробы из РФ: порт {cfg.ru_port}, ключ сертификата {pin(crt)}')
    except (OSError, subprocess.CalledProcessError) as e:
        log('ru', f'сертификат для проб не создан ({e}) — проверка из РФ не работает')
        return None

    class Handler(BaseHTTPRequestHandler):
        timeout = 20             # медленный или чужой клиент не держит поток вечно

        def _deny(self, code=401):
            self.send_response(code)
            if code == 401:
                self.send_header('WWW-Authenticate', 'Basic realm="rwmon"')
            self.end_headers()

        def do_GET(self):
            probe = who(cfg, self.headers.get('Authorization'))
            if probe is None:
                return self._deny()
            if self.path.split('?')[0] != '/ru/hosts.json':
                return self._deny(404)
            try:
                with open(links.ru_file(cfg), 'rb') as f:
                    body = f.read()
            except OSError:
                body = links.dump([]).encode()        # список ещё не собран — заглушка
            store.touch(probe)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            probe = who(cfg, self.headers.get('Authorization'))
            if probe is None:
                return self._deny()
            if self.path.split('?')[0] != '/ru/metrics':
                return self._deny(404)
            size = int(self.headers.get('Content-Length') or 0)
            if size <= 0 or size > MAX_BODY:
                return self._deny(413)
            text = self.rfile.read(size).decode('utf-8', 'replace')
            store.put(probe, parse_metrics(text))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *args):
            pass

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(crt, key)
    server = ThreadingHTTPServer(('0.0.0.0', cfg.ru_port), Handler)
    # рукопожатие TLS — в потоке соединения, а не в общем цикле приёма
    server.socket = ctx.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
