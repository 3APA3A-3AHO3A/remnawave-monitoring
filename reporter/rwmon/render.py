"""Генерация конфигов Prometheus и Grafana из config.toml.

Запускается отдельным контейнером `config` перед Prometheus и Grafana
(см. docker-compose.yml). Руками эти файлы не правятся: поменяли
config.toml → перезапустили (`./apply.sh`).

Файлы пишутся в JSON — это тоже корректный YAML, лишние библиотеки не нужны.
"""
import json
import math
import os
import shutil

from .util import promql_regex

OUT = os.environ.get('RWMON_GENERATED', '/generated')
SRC = os.environ.get('RWMON_SRC', '/src')
DS = 'rwmon-prometheus'
CHECKERS = (('xray', 2112), ('warp', 2113), ('psiphon', 2114))


def _write(path, data, mode=0o644, owner=None):
    path = os.path.join(OUT, path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        if isinstance(data, str):
            f.write(data)
        else:
            json.dump(data, f, ensure_ascii=False, indent=2)
    os.chmod(path, mode)
    if owner is not None:
        try:
            os.chown(path, owner, owner)
        except PermissionError:          # не root (тесты) — оставляем как есть
            pass


# ── Prometheus ───────────────────────────────────────────────

def probe_jobs(cfg):
    """Пробы из РФ (blackbox exporter на RU-нодах): Prometheus просит пробу открыть
    каждый адрес из списка, который пишет reporter (/links/probe-*.json)."""
    jobs = []
    for p in cfg.probes:
        scheme, _, hostport = p.url.partition('://')
        for kind, module, file in (('tcp', 'tcp_connect', 'probe-tcp.json'), ('http', 'http_2xx', 'probe-http.json')):
            job = {
                'job_name': f'probe-{p.name}-{kind}', 'metrics_path': '/probe', 'params': {'module': [module]},
                'scheme': scheme, 'scrape_interval': '60s', 'scrape_timeout': '20s',
                'tls_config': {'insecure_skip_verify': True},     # у пробы самоподписанный сертификат
                'file_sd_configs': [{'files': [f'/links/{file}'], 'refresh_interval': '1m'}],
                'relabel_configs': [
                    {'source_labels': ['__address__'], 'target_label': '__param_target'},
                    # у сайтов с any_status свой модуль пробы (любой HTTP-ответ = сайт жив)
                    {'source_labels': ['module'], 'regex': '(.+)', 'target_label': '__param_module'},
                    {'action': 'labeldrop', 'regex': 'module'},
                    {'source_labels': ['__param_target'], 'target_label': 'address'},
                    {'target_label': 'instance', 'replacement': p.name},
                    {'target_label': 'probe', 'replacement': p.name},
                    {'target_label': 'kind', 'replacement': kind},
                    {'target_label': '__address__', 'replacement': hostport},
                ],
            }
            if p.user:
                job['basic_auth'] = {'username': p.user, 'password': p.password}
            jobs.append(job)
    return jobs


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
        ] + probe_jobs(cfg),
    }


# ── Grafana: алерты ──────────────────────────────────────────

NAMES = '* on (panel, node_uuid) group_left (node_name, panel_title) topk by (panel, node_uuid) (1, rwmon_node_info)'


def _rule(uid, title, expr, for_, summary, recovered, description, scope, severity='critical', window=900,
          paused=False, labels=None):
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
        'labels': {'severity': severity, 'scope': scope, **(labels or {})},
        'annotations': {'summary': summary, 'recovered': recovered, 'description': description},
        'isPaused': paused,
    }


def host_checks(check, cond='== 0'):
    """Результат проверки по каждому хосту каждой панели: rwmon_host × xray_proxy_status.
    Один хост, общий для двух панелей, даёт две строки — по одной на панель."""
    hosts = 'rwmon_host' if check == 'xray' else 'rwmon_host{lite="0"}'
    # max by: при обновлении списка у одного имени ненадолго бывает две серии
    return f'{hosts} * on (name) group_left (check) (max by (name, check) (xray_proxy_status{{check="{check}"}}) {cond})'


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
    # две неудачные проверки подряд: интервал + минута на опрос результата
    for_check = f'{math.ceil((cfg.check_interval + 60) / 60)}m'
    tags = promql_regex(cfg.outbound_tags)
    up = f'sum by (panel, node_uuid, tag) (increase(rwmon_node_outbound_upload_bytes{{tag=~{tags}}}[15m]))'
    down = f'sum by (panel, node_uuid, tag) (increase(rwmon_node_outbound_download_bytes{{tag=~{tags}}}[15m]))'
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
              severity='warning', window=1800,
              # Выключено: за аутбаундами стоят балансировщики с резервом, отказ одного выхода
              # клиентов не задевает, а отправка файла (много вверх, мало вниз) выглядит так же,
              # как поломка. Что цепочка WARP/Psiphon не работает целиком, ловят активные
              # проверки ниже. Правило остаётся в Grafana — можно включить руками.
              paused=True),
        # uid от правила прошлой версии («нет метрик панели») — оно заменяется этим
        _rule('rwmon-panel-metrics', 'Панель недоступна по API',
              '(rwmon_panel_up == 0) * 0 + 1', '5m',
              'API панели не отвечает', 'API панели снова отвечает',
              'reporter не может получить данные панели: проверьте панель, адрес api_url и токен.', 'all'),
        _rule('rwmon-panel-slow', 'Панель тормозит',
              f'(avg_over_time(rwmon_panel_process_lag_ms[5m]) > {cfg.panel_lag_ms:g}) * 0 + 1', '5m',
              'Панель тормозит', 'Панель снова работает быстро',
              f'Процесс панели дольше 5 минут отвечает с задержкой больше {cfg.panel_lag_ms:g} мс: '
              'админка, бот и выдача подписок могут подвисать. Обычно это нехватка CPU на сервере панели '
              'или тяжёлая задача (массовые изменения пользователей). Графики — Grafana, «Здоровье панелей».',
              'all', severity='warning', window=1200),
        _rule('rwmon-panel-restart', 'Процесс панели перезапустился',
              '(resets(rwmon_panel_process_uptime_seconds[15m]) > 0) * 0 + 1', '0s',
              'Процесс панели перезапустился', 'Процесс панели работает без перезапусков 15 минут',
              'Время работы процесса сбросилось в ноль. Если вы обновляли или перезапускали панель — '
              'всё в порядке. Если нет — процесс упал: docker logs --tail 100 remnawave',
              'all', severity='warning', window=1200),
        _rule('rwmon-panel-memory', 'Панель ест много памяти',
              f'(avg_over_time(rwmon_panel_process_memory_bytes[15m]) > {cfg.panel_memory_mb:g} * 1048576) * 0 + 1',
              '15m', 'Панель ест много памяти', 'Память панели в норме',
              f'Процесс панели занимает больше {cfg.panel_memory_mb:g} МБ дольше 15 минут. Если на графике '
              'память растёт день за днём — это утечка, панель скоро упадёт; поможет перезапуск '
              '(docker compose restart remnawave) и обновление панели.',
              'all', severity='warning', window=1800),
        _rule('rwmon-reporter-down', 'reporter не отвечает', '(up{job="reporter"} == 0) * 0 + 1', '3m',
              'reporter не отвечает — данные панелей не собираются', 'reporter снова работает',
              'Посмотрите журнал: docker compose logs --tail 50 reporter', 'all'),
        _rule('rwmon-hosts-unchecked', 'Хосты не проверяются', UNCHECKED, '20m',
              'Хосты не проверяются', 'Хосты снова проверяются',
              'Хост есть в панели, но результатов проверки нет. Обычно это значит, что xray-checker '
              'не смог загрузить новый список хостов: docker compose logs --tail 30 checker-xray',
              'all', severity='warning'),
        _rule('rwmon-panel-no-hosts', 'У панели нет хостов для проверки', '(rwmon_panel_hosts == 0) * 0 + 1',
              '30m', 'Нет хостов для проверки', 'Хосты для проверки снова есть',
              'У служебного пользователя панели нет хостов с тегами проверки (или пользователь пропал '
              'из сквадов) — проверки для этой панели не идут.', 'all', severity='warning'),
        _rule('rwmon-node-overload', 'Нода перегружена', f'''
(
  (
    (avg_over_time(rwmon_node_cpu_load5[15m]) > 0.9)
    or on (panel, node_uuid) (avg_over_time(rwmon_node_memory_used_ratio[15m]) > 0.9)
  ) * 0 + 1
) {NAMES}''', '15m', 'Нода перегружена', 'Нагрузка на ноде снизилась',
              'Уже 15 минут load average выше 0.9 на ядро или занято больше 90% памяти.', 'all',
              severity='warning', window=1800),
        _rule('rwmon-probe-blocked', 'Хост не открывается из РФ',
              '(rwmon_host * on (address) group_left () (max by (address) (probe_success{kind="tcp"}) == 0)) * 0 + 1',
              '5m', 'Хост не открывается из РФ', 'Хост снова открывается из РФ',
              'Ни одна проба из РФ не может установить соединение с адресом хоста. '
              'Похоже на блокировку IP или порта.', 'host'),
        _rule('rwmon-probe-down', 'Проба из РФ не отвечает',
              '(max by (probe) (up{kind="tcp"}) == 0) * 0 + 1', '10m',
              'Проба из РФ не отвечает', 'Проба из РФ снова работает',
              'Мониторинг не может опросить blackbox exporter на RU-ноде: нода, контейнер или файрвол.',
              'all', severity='warning'),
        _rule('rwmon-site-down', 'Сайт не открывается', '(rwmon_site_up == 0) * 0 + 1', '3m',
              'Сайт не открывается', 'Сайт снова открывается',
              'Страница не отвечает или отдаёт код ошибки (4xx/5xx); если задан keyword — его нет на странице. '
              'Код ответа — в Grafana, таблица «Сайты». Проверка с сервера мониторинга.',
              'all'),
        _rule('rwmon-site-down-ru', 'Сайт не открывается из РФ',
              '(max by (site) (probe_success{kind="http"}) == 0) * 0 + 1', '5m',
              'Сайт не открывается из РФ', 'Сайт снова открывается из РФ',
              'Ни одна проба из РФ не может открыть страницу.', 'all'),
        _rule('rwmon-site-cert', 'Сертификат скоро истекает',
              '((rwmon_site_cert_expiry_timestamp_seconds - time()) < 14 * 86400) * 0 + 1', '1h',
              'Сертификат истекает меньше чем через 14 дней', 'Сертификат обновлён',
              'Проверьте автопродление сертификата (certbot / acme.sh).', 'all', severity='warning',
              labels={'repeat': 'daily'}),
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
    """Хосты — в чат своей панели; всё остальное — по разу в каждый чат.
    Пока алерт горит, он повторяется раз в repeat_minutes; правила с меткой
    repeat=daily (сертификат) — раз в сутки."""
    rcv = receivers(cfg)
    daily = [{'object_matchers': [['repeat', '=', 'daily']], 'repeat_interval': '24h'}]
    routes = [{'receiver': rcv[p.telegram.key][0],
               'object_matchers': [['scope', '=', 'host'], ['panel', '=', p.id]]} for p in cfg.panels]
    routes += [{'receiver': name, 'object_matchers': [['scope', '!=', 'host']], 'continue': True,
                'routes': daily} for name, _, _ in rcv.values()]
    return {'apiVersion': 1, 'policies': [{
        'orgId': 1, 'receiver': routes[0]['receiver'],
        'group_by': ['grafana_folder', 'alertname'],
        'group_wait': '30s', 'group_interval': '2m', 'repeat_interval': f'{cfg.repeat_minutes}m',
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
        'PROXY_CHECK_ATTEMPTS': cfg.check_attempts,
        'PROXY_CHECK_RETRY_DELAY': cfg.check_retry_delay,
        'PROXY_CHECK_CONCURRENCY': cfg.check_concurrency,
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
    # пароли проб: читает только Prometheus (он работает как nobody, uid 65534)
    _write('prometheus/prometheus.yml', prometheus(cfg), mode=0o600 if cfg.probes else 0o644,
           owner=65534 if cfg.probes else None)
    _write('grafana/datasources/prometheus.yml', {'apiVersion': 1, 'datasources': [{
        'name': 'Prometheus', 'uid': DS, 'type': 'prometheus', 'access': 'proxy',
        'url': f'http://127.0.0.1:{cfg.prometheus_port}', 'isDefault': True, 'editable': False,
        'jsonData': {'timeInterval': '30s'}}]})
    _write('grafana/dashboards/dashboards.yml', {'apiVersion': 1, 'providers': [{
        'name': 'remnawave-monitoring', 'folder': 'Remnawave', 'type': 'file',
        'disableDeletion': True, 'allowUiUpdates': False,
        'options': {'path': '/etc/grafana/dashboards'}}]})
    _write('grafana/alerting/rules.yml', rules(cfg))
    # токены ботов: читать может только Grafana (группа root), а не контейнеры проверок
    _write('grafana/alerting/contact-points.yml', contact_points(cfg), mode=0o640)
    _write('grafana/alerting/policies.yml', policies(cfg))
    _write('grafana/alerting/templates.yml', templates(cfg))
    for check, port in CHECKERS:
        _write(f'checkers/{check}.env', checker_env(cfg, check, port))
    os.makedirs(os.path.join(OUT, 'grafana', 'plugins'), exist_ok=True)
    for d, _, _ in os.walk(OUT):
        os.chmod(d, 0o755)
    print('конфиги Prometheus и Grafana собраны для панелей: ' +
          ', '.join(f'{p.title} ({p.id})' for p in cfg.panels))
