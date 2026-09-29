"""Генерация конфигов Prometheus и Grafana из config.toml.

Запускается отдельным контейнером `config` перед Prometheus и Grafana
(см. docker-compose.yml). Руками эти файлы не правятся: поменяли
config.toml → перезапустили (`./apply.sh`).

Файлы пишутся в JSON — это тоже корректный YAML, лишние библиотеки не нужны.
"""
import json
import os
import re
import shutil

OUT = os.environ.get('RWMON_GENERATED', '/generated')
SRC = os.environ.get('RWMON_SRC', '/src')
DS = 'rwmon-prometheus'
CHECKERS = (('xray', 2112), ('warp', 2113), ('psiphon', 2114))


def _write(path, data):
    path = os.path.join(OUT, path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        if isinstance(data, str):
            f.write(data)
        else:
            json.dump(data, f, ensure_ascii=False, indent=2)
    os.chmod(path, 0o644)


def re2_escape(text):
    """Экранирование для регулярок Prometheus (RE2): только спецсимволы."""
    return re.sub(r'([\\.^$|?*+()\[\]{}])', r'\\\1', text)


# ── Prometheus ───────────────────────────────────────────────

def prometheus(cfg):
    return {
        'global': {'scrape_interval': '30s', 'evaluation_interval': '30s'},
        'scrape_configs': [
            {'job_name': 'reporter', 'static_configs': [{'targets': [f'127.0.0.1:{cfg.reporter_port}']}]},
            {'job_name': 'xray-checker', 'scrape_interval': '60s',
             'static_configs': [{'targets': [f'127.0.0.1:{port}'], 'labels': {'check': check}}
                                for check, port in CHECKERS],
             # к какой панели относится проверка, знает rwmon_host (см. links.py)
             'metric_relabel_configs': [{'action': 'labeldrop', 'regex': 'sub_name|group_name'}]},
        ],
    }


# ── Grafana: алерты ──────────────────────────────────────────

NAMES = '* on (panel, node_uuid) group_left (node_name, panel_title) topk by (panel, node_uuid) (1, rwmon_node_info)'


def _rule(uid, title, expr, for_, summary, recovered, description, scope, severity='critical', window=900):
    return {
        'uid': uid, 'title': title, 'condition': 'C',
        'data': [
            {'refId': 'A', 'relativeTimeRange': {'from': window, 'to': 0}, 'datasourceUid': DS,
             'model': {'refId': 'A', 'expr': expr.strip(), 'instant': True, 'range': False,
                       'intervalMs': 1000, 'maxDataPoints': 43200}},
            {'refId': 'B', 'datasourceUid': '__expr__',
             'model': {'refId': 'B', 'type': 'reduce', 'expression': 'A', 'reducer': 'last',
                       'settings': {'mode': 'dropNN'}}},
            {'refId': 'C', 'datasourceUid': '__expr__',
             'model': {'refId': 'C', 'type': 'threshold', 'expression': 'B',
                       'conditions': [{'evaluator': {'type': 'gt', 'params': [0]}}]}},
        ],
        'noDataState': 'OK', 'execErrState': 'Error', 'for': for_,
        'labels': {'severity': severity, 'scope': scope},
        'annotations': {'summary': summary, 'recovered': recovered, 'description': description},
        'isPaused': False,
    }


def host_checks(check, cond='== 0'):
    """Результат проверки по каждому хосту каждой панели: rwmon_host × xray_proxy_status.
    Один хост, общий для двух панелей, даёт две строки — по одной на панель."""
    hosts = 'rwmon_host' if check == 'xray' else 'rwmon_host{lite="0"}'
    return f'{hosts} * on (name) group_left (check) (xray_proxy_status{{check="{check}"}} {cond})'


def _checker(check):
    if check == 'xray':
        return f'({host_checks("xray")}) * 0 + 1'
    # если хост не отвечает целиком — об этом уже скажет проверка «Подключение»
    return (f'(({host_checks(check)}) unless on (name) '
            f'(xray_proxy_status{{check="xray"}} == 0)) * 0 + 1')


UNCHECKED = ('(rwmon_host unless on (name) xray_proxy_status{check="xray"})'
             ' or (rwmon_host{lite="0"} unless on (name) xray_proxy_status{check="warp"})'
             ' or (rwmon_host{lite="0"} unless on (name) xray_proxy_status{check="psiphon"})')


def rules(cfg):
    for_check = f'{cfg.check_interval // 60 + 1}m'      # две проверки подряд
    tags = '|'.join(re2_escape(t) for t in cfg.outbound_tags)
    up = f'sum by (panel, node_uuid, tag) (increase(rwmon_node_outbound_upload_bytes{{tag=~"{tags}"}}[15m]))'
    down = f'sum by (panel, node_uuid, tag) (increase(rwmon_node_outbound_download_bytes{{tag=~"{tags}"}}[15m]))'
    r = [
        _rule('rwmon-clients-dropped', 'Клиенты пропали с ноды', f'''
(
  (
    max_over_time(rwmon_node_online_users[5m]) <= {cfg.clients_drop_max_now:g}
    and on (panel, node_uuid) avg_over_time(rwmon_node_online_users[1h] offset 10m) >= {cfg.clients_drop_min_avg:g}
    and on (panel, node_uuid) rwmon_node_connected == 1
  ) * 0 + 1
) {NAMES}''', '2m', 'Клиенты пропали с ноды', 'Клиенты вернулись на ноду',
              'Нода подключена к панели, но клиентов на ней почти не осталось, хотя час назад были. '
              'Возможна блокировка IP ноды.', 'all'),
        _rule('rwmon-xray-down', 'Xray не принимает клиентов', _checker('xray'), for_check,
              'Нода не принимает клиентов', 'Нода снова принимает клиентов',
              'Проверка подключается к хосту как обычный клиент и не может открыть страницу. '
              'Две проверки подряд.', 'host'),
        _rule('rwmon-warp-down', 'WARP не работает', _checker('warp'), for_check,
              'WARP не работает', 'WARP снова работает',
              'Через ноду не открывается адрес, который она отправляет в WARP. Две проверки подряд.', 'host'),
        _rule('rwmon-psiphon-down', 'Psiphon не работает', _checker('psiphon'), for_check,
              'Psiphon не работает', 'Psiphon снова работает',
              'Через ноду не открывается адрес, который она отправляет в Psiphon: Gemini на этой ноде '
              'не работает. Две проверки подряд.', 'host'),
        _rule('rwmon-outbound-no-response', 'Аутбаунд не отвечает', f'''
(
  (
    {up} > 20480
    and on (panel, node_uuid, tag)
    {down} < 0.1 * {up}
  ) * 0 + 1
  and on (panel) (rwmon_panel_traffic_exact == 1)
) {NAMES}''', '10m', 'Аутбаунд не отвечает клиентам', 'Аутбаунд снова отвечает',
              'За 15 минут клиенты отправили запросы в этот аутбаунд, а ответов почти нет. '
              '(Работает для панелей с metrics_url — там трафик точный.)', 'all',
              severity='warning', window=1800),
        # uid от правила прошлой версии («нет метрик панели») — оно заменяется этим
        _rule('rwmon-panel-metrics', 'Панель недоступна по API',
              '(rwmon_panel_up == 0) * 0 + 1', '5m',
              'API панели не отвечает', 'API панели снова отвечает',
              'reporter не может получить данные панели: проверьте панель, адрес api_url и токен.', 'all'),
        _rule('rwmon-reporter-down', 'reporter не отвечает', '(up{job="reporter"} == 0) * 0 + 1', '3m',
              'reporter не отвечает — данные панелей не собираются', 'reporter снова работает',
              'Посмотрите журнал: docker compose logs --tail 50 reporter', 'all'),
        _rule('rwmon-hosts-unchecked', 'Хосты не проверяются', UNCHECKED, '20m',
              'Хосты не проверяются', 'Хосты снова проверяются',
              'Хост есть в панели, но результатов проверки нет. Обычно это значит, что xray-checker '
              'не смог загрузить новый список хостов: docker compose logs --tail 30 checker-xray',
              'all', severity='warning'),
        _rule('rwmon-checker-down', 'Не работает проверка хостов', '(up{job="xray-checker"} == 0) * 0 + 1', '5m',
              'Контейнер проверки хостов не отвечает', 'Проверка хостов снова работает',
              'docker compose logs --tail 50 checker-xray checker-warp checker-psiphon', 'all',
              severity='warning'),
    ]
    return {'apiVersion': 1, 'groups': [{'orgId': 1, 'name': 'remnawave', 'folder': 'Remnawave',
                                         'interval': '1m', 'rules': r}]}


def receivers(cfg):
    """Контакт Telegram на каждый разный чат: {ключ чата: (имя, uid, telegram)}.
    Первый — с именем и uid как в версии для одной панели, чтобы Grafana обновила
    существующий контакт, а не создала второй."""
    out = {}
    for p in cfg.panels:
        key = p.telegram.key
        if key not in out:
            if not out:
                out[key] = ('telegram', 'rwmon-telegram', p.telegram)
            else:
                out[key] = (f'telegram-{p.id}', f'rwmon-tg-{p.id}', p.telegram)
    return out


def contact_points(cfg):
    items = []
    for name, uid, tg in receivers(cfg).values():
        settings = {'bottoken': tg.bot_token, 'chatid': tg.chat_id,
                    'parse_mode': 'HTML', 'disable_web_page_preview': True,
                    'message': '{{ template "rwmon.message" . }}'}
        if tg.topic_id:
            settings['message_thread_id'] = tg.topic_id
        items.append({'orgId': 1, 'name': name,
                      'receivers': [{'uid': uid, 'type': 'telegram',
                                     'disableResolveMessage': False, 'settings': settings}]})
    return {'apiVersion': 1, 'contactPoints': items}


def policies(cfg):
    """Хосты — в чат своей панели; всё остальное — по разу в каждый чат."""
    rcv = receivers(cfg)
    routes = [{'receiver': rcv[p.telegram.key][0],
               'object_matchers': [['scope', '=', 'host'], ['panel', '=', p.id]]} for p in cfg.panels]
    routes += [{'receiver': name, 'object_matchers': [['scope', '!=', 'host']], 'continue': True}
               for name, _, _ in rcv.values()]
    return {'apiVersion': 1, 'policies': [{
        'orgId': 1, 'receiver': routes[0]['receiver'],
        'group_by': ['grafana_folder', 'alertname'],
        'group_wait': '30s', 'group_interval': '2m', 'repeat_interval': '12h',
        'routes': routes}]}


def templates(cfg):
    with open(os.path.join(SRC, 'grafana', 'telegram.tmpl'), encoding='utf-8') as f:
        text = f.read()
    text = text[text.index('{{ define'):]                     # без поясняющего комментария
    text = text.replace('__MULTI__', 'true' if cfg.multi else 'false')
    return {'apiVersion': 1, 'templates': [{'orgId': 1, 'name': 'rwmon', 'template': text}]}


# ── xray-checker ─────────────────────────────────────────────

def _sh(v):
    return "'" + str(v).replace("'", "'\\''") + "'"


def checker_env(cfg, check, port):
    """Переменные для контейнера проверки (читаются через `. файл` в sh)."""
    urls = {'xray': cfg.url_xray, 'warp': cfg.url_warp, 'psiphon': cfg.url_psiphon}
    env = {
        'TZ': 'UTC',
        # «Подключение» проверяет и лёгкие хосты, WARP и Psiphon — только полные
        'SUBSCRIPTION_URL': 'file:///links/' + ('monitor-xray.txt' if check == 'xray' else 'monitor.txt'),
        'SUBSCRIPTION_UPDATE': 'true',
        'SUBSCRIPTION_UPDATE_INTERVAL': '300',
        'PROXY_CHECK_INTERVAL': cfg.check_interval,
        'PROXY_TIMEOUT': '20',
        'METRICS_HOST': '127.0.0.1',
        'METRICS_PORT': port,
        'XRAY_START_PORT': {'xray': 21000, 'warp': 22000, 'psiphon': 23000}[check],
        'LOG_LEVEL': 'warn',
    }
    if check == 'xray':
        env.update(PROXY_CHECK_METHOD='status', PROXY_STATUS_CHECK_URL=urls[check])
    else:
        env.update(PROXY_CHECK_METHOD='ip', PROXY_IP_CHECK_URL=urls[check])
    return ''.join(f'{k}={_sh(v)}\n' for k, v in env.items())


def render(cfg):
    if os.path.isdir(OUT):
        for name in os.listdir(OUT):
            shutil.rmtree(os.path.join(OUT, name), ignore_errors=True)
    _write('prometheus/prometheus.yml', prometheus(cfg))
    _write('grafana/datasources/prometheus.yml', {'apiVersion': 1, 'datasources': [{
        'name': 'Prometheus', 'uid': DS, 'type': 'prometheus', 'access': 'proxy',
        'url': f'http://127.0.0.1:{cfg.prometheus_port}', 'isDefault': True, 'editable': False,
        'jsonData': {'timeInterval': '30s'}}]})
    _write('grafana/dashboards/dashboards.yml', {'apiVersion': 1, 'providers': [{
        'name': 'remnawave-monitoring', 'folder': 'Remnawave', 'type': 'file',
        'disableDeletion': True, 'allowUiUpdates': False,
        'options': {'path': '/etc/grafana/dashboards'}}]})
    _write('grafana/alerting/rules.yml', rules(cfg))
    _write('grafana/alerting/contact-points.yml', contact_points(cfg))
    _write('grafana/alerting/policies.yml', policies(cfg))
    _write('grafana/alerting/templates.yml', templates(cfg))
    for check, port in CHECKERS:
        _write(f'checkers/{check}.env', checker_env(cfg, check, port))
    os.makedirs(os.path.join(OUT, 'grafana', 'plugins'), exist_ok=True)
    for d, _, _ in os.walk(OUT):
        os.chmod(d, 0o755)
    print('конфиги Prometheus и Grafana собраны для панелей: ' +
          ', '.join(f'{p.title} ({p.id})' for p in cfg.panels))
