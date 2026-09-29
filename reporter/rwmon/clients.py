"""Обращения к внешним сервисам: API панели, Prometheus, Telegram.
Только стандартная библиотека Python — без лишних зависимостей."""
import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

USER_AGENT = 'rwmon-reporter/1.0'


class ApiError(Exception):
    pass


def _open(req, timeout):
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', 'replace')[:300]
        raise ApiError(f'{req.full_url.split("?")[0]} → HTTP {e.code}: {body}') from None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise ApiError(f'{req.full_url.split("?")[0]} → нет ответа: {e}') from None


# ── Remnawave ────────────────────────────────────────────────

class Remnawave:
    """API одной панели. panel — config.Panel."""

    def __init__(self, panel):
        self.panel = panel
        self.base = panel.api_url
        self.headers = {
            'Authorization': 'Bearer ' + panel.api_token,
            'Accept': 'application/json',
            'User-Agent': USER_AGENT,
            # бэкенд панели без этих заголовков не отвечает на прямые запросы по http
            'X-Forwarded-For': '127.0.0.1',
            'X-Forwarded-Proto': 'https',
        }
        self.headers.update(panel.headers)

    def _call(self, method, path, body=None, timeout=30):
        data = None
        headers = dict(self.headers)
        if body is not None:
            data = json.dumps(body).encode()
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            raw = _open(req, timeout)
        except ApiError as e:
            raise ApiError(f'[{self.panel.title}] {e}') from None
        try:
            return json.loads(raw)['response']
        except (ValueError, KeyError, TypeError):
            raise ApiError(f'[{self.panel.title}] {path}: неожиданный ответ панели') from None

    def raw_metrics(self, timeout=20):
        """Текст /metrics самой панели (точные счётчики трафика). Нужен metrics_url."""
        p = self.panel
        headers = {'User-Agent': USER_AGENT}
        if p.metrics_user:
            cred = f'{p.metrics_user}:{p.metrics_password}'.encode()
            headers['Authorization'] = 'Basic ' + base64.b64encode(cred).decode()
        req = urllib.request.Request(p.metrics_url, headers=headers)
        try:
            return _open(req, timeout).decode('utf-8', 'replace')
        except ApiError as e:
            raise ApiError(f'[{p.title}] метрики панели: {e}') from None

    def nodes(self):
        return self._call('GET', '/api/nodes')

    def user_by_username(self, username):
        return self._call('GET', '/api/users/by-username/' + urllib.parse.quote(username))

    def raw_subscription(self, short_uuid):
        return self._call('GET', f'/api/subscriptions/by-short-uuid/{urllib.parse.quote(short_uuid)}/raw')

    def connection_keys(self, user_id):
        return self._call('GET', f'/api/subscriptions/connection-keys/{user_id}')

    def nodes_metrics(self):
        """Клиенты и трафик по инбаундам/аутбаундам каждой ноды (то же, что /metrics панели)."""
        return (self._call('GET', '/api/system/nodes/metrics') or {}).get('nodes') or []

    def stats(self):
        return self._call('GET', '/api/system/stats')

    def digest(self, start, end):
        q = urllib.parse.urlencode({'start': start, 'end': end})
        return self._call('GET', '/api/system/stats/digest?' + q)

    def metadata(self):
        return self._call('GET', '/api/system/metadata')

    def health(self):
        """Память, задержка и время работы процессов самой панели (api, scheduler, processor)."""
        return (self._call('GET', '/api/system/health') or {}).get('runtimeMetrics') or []

    def billing_nodes(self):
        return self._call('GET', '/api/infra-billing/nodes')

    def geocheck(self, node_uuid, timeout=180, poll=3):
        """Запускает GeoCheck на ноде и ждёт результат (на ноде это до минуты)."""
        job = self._call('POST', f'/api/connections/geocheck/{node_uuid}', body={})['jobId']
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            time.sleep(poll)
            res = self._call('GET', f'/api/connections/geocheck/{urllib.parse.quote(str(job))}')
            if res.get('isFailed'):
                raise ApiError('панель сообщила об ошибке задания')
            if res.get('isCompleted'):
                result = res.get('result') or {}
                if not result.get('success'):
                    raise ApiError(result.get('message') or 'GeoCheck завершился неудачно')
                return result
        raise ApiError(f'нода не ответила за {timeout} с')


# ── Prometheus ───────────────────────────────────────────────

class Prometheus:
    def __init__(self, url):
        self.url = url

    def query(self, expr, at=None):
        """Мгновенный запрос. Возвращает список (метки, значение)."""
        params = {'query': expr}
        if at is not None:
            params['time'] = f'{at:.3f}'
        req = urllib.request.Request(
            self.url + '/api/v1/query?' + urllib.parse.urlencode(params),
            headers={'User-Agent': USER_AGENT})
        data = json.loads(_open(req, 30))
        if data.get('status') != 'success':
            raise ApiError(f'Prometheus: {data.get("error")}')
        out = []
        for item in data['data']['result']:
            try:
                out.append((item['metric'], float(item['value'][1])))
            except (KeyError, ValueError, IndexError):
                pass
        return out

    def targets(self, job):
        """Состояние опроса целей: [(адрес, 'up'/'down'/'unknown', текст ошибки)]."""
        req = urllib.request.Request(self.url + '/api/v1/targets?state=active',
                                     headers={'User-Agent': USER_AGENT})
        data = json.loads(_open(req, 30))
        return [(t.get('scrapeUrl', ''), t.get('health', ''), t.get('lastError', ''))
                for t in data['data']['activeTargets'] if t.get('labels', {}).get('job') == job]

    def by(self, expr, label, at=None):
        """Запрос, результат которого — словарь {значение метки: число}."""
        return {m.get(label, ''): v for m, v in self.query(expr, at)}


# ── Telegram ─────────────────────────────────────────────────

class Telegram:
    LIMIT = 4000   # у Telegram 4096, оставляем запас

    def __init__(self, tg):
        """tg — config.Telegram (бот, чат, топик)."""
        self.api = f'https://api.telegram.org/bot{tg.bot_token}/'
        self.chat = tg.chat_id
        self.topic = tg.topic_id

    def _base(self):
        params = {'chat_id': self.chat}
        if self.topic:
            params['message_thread_id'] = self.topic
        return params

    def _post(self, method, data, content_type):
        req = urllib.request.Request(self.api + method, data=data,
                                     headers={'Content-Type': content_type, 'User-Agent': USER_AGENT})
        try:
            res = json.loads(_open(req, 60))
        except ApiError as e:
            raise ApiError(str(e).replace(self.api, 'telegram/')) from None
        if not res.get('ok'):
            raise ApiError(f'Telegram: {res.get("description")}')
        return res['result']

    def get_me(self):
        return self._post('getMe', b'{}', 'application/json')

    def send(self, text):
        """Длинный текст режем по строкам на несколько сообщений."""
        for chunk in split_message(text, self.LIMIT):
            params = self._base()
            params.update({'text': chunk, 'parse_mode': 'HTML',
                           'disable_web_page_preview': True})
            self._post('sendMessage', json.dumps(params).encode(), 'application/json')

    def send_document(self, filename, content, caption=''):
        boundary = uuid.uuid4().hex
        params = self._base()
        if caption:
            params.update({'caption': caption[:1000], 'parse_mode': 'HTML'})
        body = bytearray()
        for k, v in params.items():
            body += (f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n'
                     f'{v}\r\n').encode()
        body += (f'--{boundary}\r\nContent-Disposition: form-data; name="document"; '
                 f'filename="{filename}"\r\nContent-Type: text/html\r\n\r\n').encode()
        body += content if isinstance(content, bytes) else content.encode()
        body += f'\r\n--{boundary}--\r\n'.encode()
        self._post('sendDocument', bytes(body), f'multipart/form-data; boundary={boundary}')


def split_message(text, limit):
    """Разбить длинный текст на сообщения по строкам, сохраняя порядок.
    Строку длиннее limit режем на куски; пустых сообщений не бывает."""
    chunks, cur = [], None
    for line in text.split('\n'):
        pieces = [line[i:i + limit] for i in range(0, len(line), limit)] or ['']
        for piece in pieces:
            if cur is None:
                cur = piece
            elif len(cur) + 1 + len(piece) <= limit:
                cur += '\n' + piece
            else:
                chunks.append(cur)
                cur = piece
    if cur is not None:
        chunks.append(cur)
    return [c for c in chunks if c.strip()]
