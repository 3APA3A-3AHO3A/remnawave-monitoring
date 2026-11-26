"""Генератор дашборда grafana/dashboards/remnawave-overview.json.

Дашборд правится здесь, а не в JSON:  python3 grafana/dashboard.py
Grafana читает только готовый JSON; этот файл ей не нужен.

Устройство (сверху вниз):
  переменные «Панель», «Нода», «Аутбаунд»;
  цифры: пользователи, ноды, хосты, пробы из РФ, сеть, трафик;
  «Сейчас не работает», пробы из РФ, панели; сайты и блокировки РКН;
  «Хосты» — строка на хост: итог и все проверки (из РФ с каждой пробы, с сервера
  мониторинга через вход и на ноду, проверки маршрутов), история итога;
  «Ноды» — строка на ноду; три общих графика; «Каждая нода отдельно»;
  свёрнутые блоки с подробностями: выходы по нодам, сравнение нод, серверы нод,
  проверки подробно, здоровье панелей, GeoCheck.
"""
import json
import os

DS = {'type': 'prometheus', 'uid': 'rwmon-prometheus'}
F = 'panel_title=~"$panel"'
# фильтр по выбранным нодам + имя ноды: умножение на rwmon_node_info
NODE = f'topk by (panel, node_uuid) (1, rwmon_node_info{{{F}, node=~"$node"}})'
BY_NODE = f'* on (panel, node_uuid) group_left (node_name, panel_title) {NODE}'
CHECKS = (('warp', 'WARP'), ('psiphon', 'Psiphon'))      # проверки маршрутов: [[check]] в config.toml

GREEN, RED, YELLOW, BLUE, GREY = 'green', 'red', 'yellow', 'blue', 'text'
OK_MAP = [{'type': 'value', 'options': {'1': {'text': 'OK', 'color': GREEN, 'index': 0},
                                        '0': {'text': 'СБОЙ', 'color': RED, 'index': 1}}},
          {'type': 'special', 'options': {'match': 'null', 'result': {'text': '—', 'color': '#5a6270', 'index': 2}}}]


def hosts(check):
    """rwmon_host нужной панели: «на ноду» — все хосты, «через вход» — у кого вход не сама нода,
    проверки маршрутов — кому нужны (у лёгких LTE и хостов с тегом-исключением их нет)."""
    if check == 'xray':
        return f'rwmon_host{{{F}}}'
    if check == 'entry':
        return f'rwmon_host{{{F}, entry="1"}}'
    return f'rwmon_host{{{F}, {check}="1"}}'


def host_status(check):
    # max by: при обновлении списка у одного имени ненадолго бывает две серии
    return f'{hosts(check)} * on (name) group_left (check) max by (name, check) (xray_proxy_status{{check="{check}"}})'


# ── конструкторы панелей ─────────────────────────────────────

_id = [0]


def _next():
    _id[0] += 1
    return _id[0]


def target(expr, ref, legend='', instant=False, fmt='time_series'):
    t = {'refId': ref, 'datasource': DS, 'expr': expr, 'legendFormat': legend,
         'range': not instant, 'instant': instant}
    if fmt != 'time_series':
        t['format'] = fmt
    return t


def stat(title, x, targets, unit='none', desc='', steps=None, overrides=None, decimals=0, w=4):
    """Цифра сверху. Две цифры — друг под другом с подписью слева: так длинные значения
    (230.8 Mb/s) не слипаются в узкой плашке."""
    two = len(targets) > 1
    return {
        'id': _next(), 'type': 'stat', 'title': title, 'description': desc, 'datasource': DS,
        'gridPos': {'h': 4, 'w': w, 'x': x, 'y': 0},
        'targets': targets,
        'options': {'reduceOptions': {'calcs': ['lastNotNull'], 'fields': '', 'values': False},
                    'colorMode': 'value', 'graphMode': 'none', 'justifyMode': 'center' if not two else 'auto',
                    'textMode': 'value_and_name' if two else 'value',
                    'orientation': 'horizontal' if two else 'vertical', 'wideLayout': True,
                    'showPercentChange': False,
                    'text': {'titleSize': 12, 'valueSize': 18 if two else 30}},
        'fieldConfig': {'defaults': {'unit': unit, 'decimals': decimals,
                                     'color': {'mode': 'thresholds'},
                                     'thresholds': {'mode': 'absolute',
                                                    'steps': steps or [{'color': GREEN, 'value': None}]}},
                        'overrides': overrides or []},
    }


def by_ref(ref, **props):
    return {'matcher': {'id': 'byFrameRefID', 'options': ref},
            'properties': [{'id': k.replace('__', '.'), 'value': v} for k, v in props.items()]}


def by_name(name, **props):
    return {'matcher': {'id': 'byName', 'options': name},
            'properties': [{'id': k.replace('__', '.'), 'value': v} for k, v in props.items()]}


def by_regex(regex, **props):
    return {'matcher': {'id': 'byRegexp', 'options': regex},
            'properties': [{'id': k.replace('__', '.'), 'value': v} for k, v in props.items()]}


def red_if_positive():
    return [{'color': GREEN, 'value': None}, {'color': RED, 'value': 1}]


def table(title, pos, targets, transformations, overrides, desc='', sort=None, footer=False):
    return {
        'id': _next(), 'type': 'table', 'title': title, 'description': desc, 'datasource': DS,
        'gridPos': pos, 'targets': targets, 'transformations': transformations,
        'options': {'showHeader': True, 'cellHeight': 'sm', 'sortBy': sort or [],
                    'footer': {'show': footer}},
        'fieldConfig': {'defaults': {'custom': {'align': 'auto', 'filterable': False, 'wrapHeaderText': True,
                                                'cellOptions': {'type': 'auto'}},
                                     'noValue': '—'},
                        'overrides': overrides},
    }


def timeseries(title, pos, targets, unit, desc='', stack=False, overrides=None, legend='list',
               fill=15, placement='bottom'):
    return {
        'id': _next(), 'type': 'timeseries', 'title': title, 'description': desc, 'datasource': DS,
        'gridPos': pos, 'targets': targets,
        'options': {'legend': {'displayMode': legend, 'placement': placement, 'showLegend': True,
                               'calcs': ['lastNotNull', 'max'] if legend == 'table' else []},
                    'tooltip': {'mode': 'multi', 'sort': 'desc'}},
        'fieldConfig': {'defaults': {'unit': unit, 'min': None if unit in ('bps',) else 0,
                                     'custom': {'lineWidth': 2 if not stack else 1, 'fillOpacity': fill,
                                                'gradientMode': 'opacity', 'showPoints': 'never',
                                                'spanNulls': 120000,
                                                'stacking': {'mode': 'normal' if stack else 'none'},
                                                'axisSoftMin': 0}},
                        'overrides': overrides or []},
    }


def negative_tx():
    """Отправку (TX, запросы) рисуем вниз от нуля пунктиром — так приём и отправка не мешают друг другу."""
    return [by_regex('.*(↑|TX|запрос).*', custom__transform='negative-Y',
                     custom__lineStyle={'fill': 'dash', 'dash': [6, 4]}, custom__fillOpacity=0)]


def smooth(metric, flt):
    """Среднее значение за шаг графика: линии без «зубьев» от опроса раз в 30 секунд."""
    return f'avg_over_time({metric}{{{flt}}}[$__interval])'


def history(title, pos, expr, legend, desc):
    """Полоски «OK/СБОЙ» по времени — только для тех, у кого были сбои."""
    return {
        'id': _next(), 'type': 'state-timeline', 'title': title, 'description': desc, 'datasource': DS,
        'gridPos': pos, 'targets': [target(expr, 'A', legend)],
        'options': {'showValue': 'never', 'mergeValues': True, 'rowHeight': 0.8, 'alignValue': 'left',
                    'legend': {'showLegend': False}, 'tooltip': {'mode': 'single'}},
        'fieldConfig': {'defaults': {'color': {'mode': 'thresholds'},
                                     'thresholds': {'mode': 'absolute', 'steps': [
                                         {'color': RED, 'value': None}, {'color': GREEN, 'value': 1}]},
                                     'mappings': OK_MAP[:1], 'noValue': 'Сбоев не было'},
                        'overrides': []},
    }


def row(title, y, panels):
    return {'id': _next(), 'type': 'row', 'title': title, 'collapsed': True,
            'gridPos': {'h': 1, 'w': 24, 'x': 0, 'y': y}, 'panels': panels}


# ── итог по хосту ────────────────────────────────────────────

# rwmon_host_state (считает reporter, exporter.host_state): число → слово и цвет
STATES = [
    (0, 'работает', GREEN),
    (1, 'блокировка в РФ?', 'orange'),
    (2, 'сломан вход', RED),
    (3, 'нода не отвечает', 'dark-red'),
    (4, 'вход или блокировка', 'orange'),
]
STATE_MAP = [{'type': 'value', 'options': {str(v): {'text': t, 'color': c, 'index': i}
                                           for i, (v, t, c) in enumerate(STATES)}}]


def hq(expr, check='xray'):
    """Значение по имени проверки → строка таблицы «Хосты»: одинаковые метки у всех запросов,
    поэтому Grafana склеивает их в одну строку на хост каждой панели."""
    return f'max by (panel_title, host, name, exit) ({hosts(check)} * on (name) group_left () ({expr}))'


def state_history(title, pos, expr, legend, desc):
    """Полосы итога по времени: зелёным — работал, цветом — что было не так."""
    return {
        'id': _next(), 'type': 'state-timeline', 'title': title, 'description': desc, 'datasource': DS,
        'gridPos': pos, 'targets': [target(expr, 'A', legend)],
        'options': {'showValue': 'never', 'mergeValues': True, 'rowHeight': 0.8, 'alignValue': 'left',
                    'legend': {'showLegend': True, 'displayMode': 'list', 'placement': 'bottom'},
                    'tooltip': {'mode': 'single'}},
        'fieldConfig': {'defaults': {'color': {'mode': 'thresholds'},
                                     'thresholds': {'mode': 'absolute', 'steps': [
                                         {'color': GREEN, 'value': None}, {'color': RED, 'value': 1}]},
                                     'mappings': STATE_MAP, 'noValue': 'За период все хосты работали'},
                        'overrides': []},
    }


def legend_right(panels):
    for c in panels:
        c['options']['legend']['sortBy'] = 'Last *'
        c['options']['legend']['sortDesc'] = True


def limit_90(panels):
    """Красная пунктирная линия на 90% и шкала до 100%."""
    for c in panels:
        c['fieldConfig']['defaults']['thresholds'] = {'mode': 'absolute', 'steps': [
            {'color': 'transparent', 'value': None}, {'color': RED, 'value': 0.9}]}
        c['fieldConfig']['defaults']['custom']['thresholdsStyle'] = {'mode': 'dashed'}
        c['fieldConfig']['defaults']['max'] = 1


# ── сам дашборд ──────────────────────────────────────────────

def build(checks=None, servers=False, probes=()):
    """checks — [(id, подпись)] проверок маршрутов из config.toml (render.py собирает дашборд
    при ./apply.sh). Без них — WARP и Psiphon, как в готовом JSON репозитория.
    servers — блок «Серверы нод» и колонки диска по node_exporter ([node_exporter] в config.toml).
    probes — названия проб из РФ ([[probe]]): по колонке на пробу в «Хостах»; без них — одна «из РФ»."""
    global CHECKS
    if checks is not None:
        CHECKS = tuple(checks)
    _id[0] = 0
    p = []

    # ── 1. Цифры сверху ──
    host_state = f'(rwmon_host{{{F}}} * on (name) group_left () max by (name) (rwmon_host_state))'
    p.append(stat('Пользователи', 0, [
        target(f'sum(rwmon_node_online_users{{{F}}})', 'A', 'онлайн', instant=True),
        target(f'sum(rwmon_users{{status="ACTIVE", {F}}})', 'B', 'подписок', instant=True),
    ], overrides=[by_ref('B', color={'mode': 'fixed', 'fixedColor': GREY})],
        desc='Онлайн — клиентов на нодах выбранных панелей прямо сейчас; подписок — активных'))
    p.append(stat('Ноды', 4, [
        target(f'sum(rwmon_node_connected{{{F}}})', 'A', 'на связи', instant=True),
        target(f'count(rwmon_node_connected{{{F}}} == 0) or vector(0)', 'B', 'отключены', instant=True),
    ], overrides=[by_ref('B', thresholds={'mode': 'absolute', 'steps': red_if_positive()})],
        desc='Выключенные в панели ноды и ноды из exclude_nodes не считаются'))
    p.append(stat('Хосты', 8, [
        target(f'count(count by (name) ({host_state} == 0)) or vector(0)', 'A', 'работают', instant=True),
        target(f'count(count by (name) ({host_state} > 0)) or vector(0)', 'B', 'не работают', instant=True),
    ], overrides=[by_ref('B', thresholds={'mode': 'absolute', 'steps': red_if_positive()})],
        desc='Итог по хостам с тегами проверки: работает — открывается из РФ (а хосты МСК-нод — '
             'с сервера мониторинга). Почему не работает — в таблице «Хосты»'))
    p.append(stat('Пробы РФ', 12, [
        target('sum(rwmon_ru_probe_up) or vector(0)', 'A', 'на связи', instant=True),
        target('count(rwmon_ru_probe_up == 0) or vector(0)', 'B', 'молчат', instant=True),
    ], overrides=[by_ref('B', thresholds={'mode': 'absolute', 'steps': red_if_positive()})],
        desc='Серверы в России, которые проверяют хосты как клиент из РФ ([[probe]], папка probe/)'))
    p.append(stat('Сеть нод', 16, [
        target(f'sum(rwmon_node_network_rx_bytes_per_second{{{F}}}) * 8', 'A', '↓ RX', instant=True),
        target(f'sum(rwmon_node_network_tx_bytes_per_second{{{F}}}) * 8', 'B', '↑ TX', instant=True),
    ], unit='bps', decimals=1, steps=[{'color': BLUE, 'value': None}],
        desc='Скорость сетевых интерфейсов всех серверов нод сейчас: RX — принято сервером, TX — отправлено'))
    p.append(stat('Трафик', 20, [
        target(f'sum(increase(rwmon_node_inbound_download_bytes{{{F}}}[$__range]))', 'A', '↓ клиентам',
               instant=True),
        target(f'sum(increase(rwmon_node_inbound_upload_bytes{{{F}}}[$__range]))', 'B', '↑ от клиентов',
               instant=True),
    ], unit='decbytes', decimals=1, steps=[{'color': GREY, 'value': None}],
        desc='Трафик клиентов через все ноды за выбранный период: скачали (к клиентам) и отправили (от клиентов)'))
    y = 4

    # ── 2. Сейчас не работает · пробы из РФ · панели ──
    # строка на хост с итогом > 0 и на хост, у которого не проходит проверка маршрута;
    # «what» — что именно: итог по хосту (host) или id проверки маршрута
    def since(cond):
        """Сколько секунд назад было «хорошо» в пределах суток; не было ни разу — сутки."""
        return f'((time() - max by (name) (max_over_time(timestamp({cond})[1d:1m]))) or on (name) (max by (name) (rwmon_host_state) * 0 + 86400))'
    down_a, down_b = [], []
    bad_state = 'max by (name) (rwmon_host_state) > 0'
    down_a.append(f'label_replace(max by (panel_title, host) ({hosts("xray")} * on (name) group_left () ({bad_state})), '
                  f'"what", "host", "", "")')
    down_b.append(f'label_replace(max by (panel_title, host) ({hosts("xray")} * on (name) group_left () '
                  f'({since("rwmon_host_state == 0")} and on (name) ({bad_state}))), "what", "host", "", "")')
    for i, (c, _) in enumerate(CHECKS):
        bad = f'max by (name) (xray_proxy_status{{check="{c}"}}) == 0'
        down_a.append(f'label_replace(max by (panel_title, host) ({hosts(c)} * on (name) group_left () ({bad})) * 0 '
                      f'+ {10 + i}, "what", "{c}", "", "")')
        ok_at = f'max by (name) (max_over_time(timestamp(xray_proxy_status{{check="{c}"}} == 1)[1d:1m]))'
        down_b.append(f'label_replace(max by (panel_title, host) ({hosts(c)} * on (name) group_left () '
                      f'(((time() - {ok_at}) or on (name) (({bad}) * 0 + 86400)) and on (name) ({bad}))), '
                      f'"what", "{c}", "", "")')
    what_map = [{'type': 'value', 'options': {
        **{str(v): {'text': t, 'color': col} for v, t, col in STATES if v},
        **{str(10 + i): {'text': f'{t} не работает', 'color': 'orange'} for i, (_, t) in enumerate(CHECKS)}}}]
    p.append(table('Сейчас не работает', {'h': 8, 'w': 10, 'x': 0, 'y': y}, [
        target(' or '.join(down_a), 'A', instant=True, fmt='table'),
        target(' or '.join(down_b), 'B', instant=True, fmt='table'),
    ], [
        {'id': 'merge', 'options': {}},
        {'id': 'organize', 'options': {
            'excludeByName': {'Time': True, 'what': True},
            'indexByName': {'host': 0, 'panel_title': 1, 'Value #A': 2, 'Value #B': 3},
            'renameByName': {'panel_title': 'Панель', 'host': 'Хост', 'Value #A': 'Что', 'Value #B': 'сколько'}}},
    ], [
        by_name('Хост', custom__minWidth=120),
        by_name('Панель', custom__width=95, color={'mode': 'fixed', 'fixedColor': GREY},
                custom__cellOptions={'type': 'color-text'}),
        by_name('Что', custom__minWidth=150, custom__cellOptions={'type': 'color-background', 'mode': 'basic'},
                mappings=what_map),
        by_name('сколько', unit='dtdurations', decimals=0, custom__width=95, custom__align='right'),
    ], desc='Хосты, которые не работают прямо сейчас, и сколько уже (в пределах суток). «Что» — итог: '
            'блокировка в РФ (из России не открывается, а вход и нода работают), сломан вход (прокладка, CDN), '
            'нода не отвечает. Ниже — проверки маршрутов (WARP, Psiphon), если не проходят.',
        sort=[{'displayName': 'сколько', 'desc': True}]))
    p[-1]['fieldConfig']['defaults']['noValue'] = 'Всё работает'

    p.append(table('Пробы из РФ', {'h': 8, 'w': 7, 'x': 10, 'y': y}, [
        target('max by (probe) (rwmon_ru_probe_up)', 'A', instant=True, fmt='table'),
        target('max by (probe) (rwmon_ru_probe_hosts)', 'B', instant=True, fmt='table'),
        target('(count by (probe) (rwmon_ru_status == 0)) or (max by (probe) (rwmon_ru_probe_up) * 0)', 'C',
               instant=True, fmt='table'),
        target('max by (probe) (rwmon_ru_probe_age_seconds)', 'D', instant=True, fmt='table'),
    ], [
        {'id': 'merge', 'options': {}},
        {'id': 'organize', 'options': {
            'excludeByName': {'Time': True},
            'indexByName': {'probe': 0, 'Value #A': 1, 'Value #B': 2, 'Value #C': 3, 'Value #D': 4},
            'renameByName': {'probe': 'Проба', 'Value #A': 'связь', 'Value #B': 'хостов',
                             'Value #C': 'не открылось', 'Value #D': 'данные'}}},
    ], [
        by_name('связь', custom__align='center', custom__cellOptions={'type': 'color-text'},
                mappings=[{'type': 'value', 'options': {'1': {'text': 'OK', 'color': GREEN},
                                                        '0': {'text': 'молчит', 'color': RED}}}]),
        by_name('хостов', decimals=0, custom__align='right'),
        by_name('не открылось', decimals=0, custom__align='right',
                custom__cellOptions={'type': 'color-text'},
                thresholds={'mode': 'absolute', 'steps': red_if_positive()}),
        by_name('данные', unit='s', decimals=0, custom__align='right',
                custom__cellOptions={'type': 'color-text'},
                thresholds={'mode': 'absolute', 'steps': [{'color': 'text', 'value': None},
                                                          {'color': YELLOW, 'value': 120},
                                                          {'color': RED, 'value': 180}]}),
    ], desc='Серверы в России, которые проверяют хосты как клиент из РФ. «Хостов» — сколько проверяет '
            '(МСК-ноды из РФ не проверяются — их проверяет сервер мониторинга). «Не открылось» — сколько хостов '
            'не открылись с этой пробы в последней проверке. «Данные» — сколько секунд назад проба присылала '
            'результаты (раз в минуту; дольше 3 минут — молчит).',
        sort=[{'displayName': 'Проба', 'desc': False}]))
    p[-1]['fieldConfig']['defaults']['noValue'] = 'Пробы не подключены — README, «Проверка из РФ»'

    p.append(table('Панели', {'h': 8, 'w': 7, 'x': 17, 'y': y}, [
        target(f'max by (panel_title) (rwmon_panel_up{{{F}}})', 'A', instant=True, fmt='table'),
        target(f'max by (panel_title, version) (rwmon_panel_info{{{F}}})', 'B', instant=True, fmt='table'),
        target(f'sum by (panel_title) (rwmon_users_total{{{F}}})', 'D', instant=True, fmt='table'),
        target(f'min by (panel_title) (rwmon_panel_process_uptime_seconds{{{F}}})', 'U', instant=True, fmt='table'),
        target(f'max by (panel_title) (rwmon_panel_process_lag_ms{{{F}}})', 'L', instant=True, fmt='table'),
    ], [
        {'id': 'merge', 'options': {}},
        {'id': 'organize', 'options': {
            'excludeByName': {'Time': True, 'Value #B': True},
            'indexByName': {'panel_title': 0, 'Value #A': 1, 'version': 2, 'Value #D': 3, 'Value #U': 4,
                            'Value #L': 5},
            'renameByName': {'panel_title': 'Панель', 'Value #A': 'API', 'version': 'версия',
                             'Value #D': 'польз.', 'Value #U': 'без рестарта', 'Value #L': 'задержка'}}},
    ], [
        by_name('Панель', custom__minWidth=90),
        by_name('API', custom__align='center', custom__cellOptions={'type': 'color-text'},
                mappings=[{'type': 'value', 'options': {'1': {'text': 'OK', 'color': GREEN},
                                                        '0': {'text': 'НЕТ', 'color': RED}}}]),
        by_name('польз.', decimals=0, custom__align='right'),
        by_name('без рестарта', unit='dtdurations', decimals=0, custom__align='right',
                custom__cellOptions={'type': 'color-text'},
                thresholds={'mode': 'absolute', 'steps': [{'color': YELLOW, 'value': None},
                                                          {'color': 'text', 'value': 3600}]}),
        by_name('задержка', unit='ms', decimals=0, custom__align='right',
                custom__cellOptions={'type': 'color-text'},
                thresholds={'mode': 'absolute', 'steps': [{'color': 'text', 'value': None},
                                                          {'color': YELLOW, 'value': 50},
                                                          {'color': RED, 'value': 200}]}),
    ], desc='«Без рестарта» — сколько работает самый «молодой» процесс панели (жёлтым — меньше часа). '
            '«Задержка» — насколько подтормаживает самый медленный процесс: до 50 мс норма, от 200 мс '
            'админка и подписки начинают подвисать. Подробно — блок «Здоровье панелей»'))
    y += 8

    # ── 3. Сайты · блокировки РКН ──
    p.append(table('Сайты', {'h': 7, 'w': 12, 'x': 0, 'y': y}, [
        target('max by (site) (rwmon_site_up)', 'A', instant=True, fmt='table'),
        target('max by (site) (probe_success{kind="http"})', 'B', instant=True, fmt='table'),
        target('max by (site) (rwmon_site_status_code)', 'E', instant=True, fmt='table'),
        target('max by (site) (rwmon_site_response_seconds)', 'C', instant=True, fmt='table'),
        target('max by (site) (rwmon_site_cert_expiry_timestamp_seconds - time())', 'D', instant=True, fmt='table'),
    ], [
        {'id': 'merge', 'options': {}},
        {'id': 'organize', 'options': {
            'excludeByName': {'Time': True},
            'indexByName': {'site': 0, 'Value #A': 1, 'Value #B': 2, 'Value #E': 3, 'Value #C': 4, 'Value #D': 5},
            'renameByName': {'site': 'Сайт', 'Value #A': 'открывается', 'Value #B': 'из РФ', 'Value #E': 'код',
                             'Value #C': 'ответ', 'Value #D': 'сертификат'}}},
    ], [
        by_name('Сайт', custom__minWidth=150),
        *[by_name(n, custom__width=92, custom__align='center', mappings=OK_MAP,
                  custom__cellOptions={'type': 'color-text'})
          for n in ('открывается', 'из РФ')],
        by_name('код', decimals=0, custom__width=52, custom__align='right', custom__cellOptions={'type': 'color-text'},
                thresholds={'mode': 'absolute', 'steps': [{'color': RED, 'value': None},
                                                          {'color': 'text', 'value': 200},
                                                          {'color': RED, 'value': 400}]}),
        by_name('ответ', unit='s', decimals=2, custom__width=68, custom__align='right'),
        by_name('сертификат', unit='dtdurations', decimals=0, custom__width=95, custom__align='right',
                custom__cellOptions={'type': 'color-text'},
                thresholds={'mode': 'absolute', 'steps': [{'color': RED, 'value': None},
                                                          {'color': YELLOW, 'value': 7 * 86400},
                                                          {'color': 'text', 'value': 14 * 86400}]}),
    ], desc='Сайты из [[site]] в config.toml: проверка с сервера мониторинга и с проб в России, '
            'код и время ответа, сколько осталось до конца сертификата'))
    p[-1]['fieldConfig']['defaults']['noValue'] = 'Добавьте [[site]] в config.toml'

    p.append(table('Блокировки РКН', {'h': 7, 'w': 12, 'x': 12, 'y': y}, [
        target('max by (name, kind, why) (rwmon_rkn_blocked)', 'A', instant=True, fmt='table'),
    ], [
        {'id': 'organize', 'options': {
            'excludeByName': {'Time': True},
            'indexByName': {'Value': 0, 'name': 1, 'kind': 2, 'why': 3},
            'renameByName': {'Value': 'статус', 'name': 'Что', 'kind': 'тип', 'why': 'причина'}}},
    ], [
        by_name('статус', custom__width=95, custom__align='center',
                custom__cellOptions={'type': 'color-text'},
                mappings=[{'type': 'value', 'options': {'1': {'text': 'в списках', 'color': RED, 'index': 0},
                                                        '0': {'text': 'чисто', 'color': GREEN, 'index': 1}}}]),
        by_name('Что', custom__minWidth=150),
        by_name('тип', custom__width=70, color={'mode': 'fixed', 'fixedColor': GREY},
                custom__cellOptions={'type': 'color-text'},
                mappings=[{'type': 'value', 'options': {'node': {'text': 'нода'}, 'domain': {'text': 'домен'},
                                                        'extra': {'text': 'доп.'}}}]),
        by_name('причина', custom__minWidth=160),
    ], desc='IP нод и домены сервиса по спискам блокировок РФ (cheburcheck.ru, раз в несколько часов; '
            'блок [rkn] в config.toml). «В списках» — адрес в реестре РКН, в заблокированной подсети или CDN.',
        sort=[{'displayName': 'статус', 'desc': True}]))
    p[-1]['fieldConfig']['defaults']['noValue'] = 'Проверки блокировок нет — блок [rkn] в config.toml'
    y += 7

    # ── 4. Хосты: строка на хост — итог и все проверки ──
    cols = [('S', 'Итог', hq('max by (name) (rwmon_host_state)'))]
    if probes:
        cols += [(f'P{i}', pr, hq(f'max by (name) (rwmon_ru_status{{probe="{pr}"}})'))
                 for i, pr in enumerate(probes)]
    else:
        cols.append(('P0', 'из РФ', hq('max by (name) (rwmon_ru_status)')))
    cols += [('N', 'NL · вход', hq('max by (name) (xray_proxy_status{check="entry"})', 'entry')),
             ('X', 'NL · нода', hq('max by (name) (xray_proxy_status{check="xray"})'))]
    cols += [(f'R{i}', t, hq(f'max by (name) (xray_proxy_status{{check="{c}"}})', c))
             for i, (c, t) in enumerate(CHECKS)]
    cols.append(('L', 'из РФ, мс', hq('min by (name) (rwmon_ru_latency_ms > 0)')))
    order = {'host': 0, 'panel_title': 1, 'exit': 2,
             **{f'Value #{ref}': 3 + i for i, (ref, _, _) in enumerate(cols)}}
    rename = {'host': 'Хост', 'panel_title': 'Панель', 'exit': '→ нода',
              **{f'Value #{ref}': title for ref, title, _ in cols}}
    ok_cols = [title for ref, title, _ in cols if ref not in ('S', 'L')]
    p.append(table('Хосты', {'h': 18, 'w': 24, 'x': 0, 'y': y},
                   [target(expr, ref, instant=True, fmt='table') for ref, _, expr in cols], [
        {'id': 'merge', 'options': {}},
        {'id': 'organize', 'options': {'excludeByName': {'Time': True, 'name': True},
                                       'indexByName': order, 'renameByName': rename}},
    ], [
        by_name('Хост', custom__minWidth=150),
        by_name('Панель', custom__width=105, color={'mode': 'fixed', 'fixedColor': GREY},
                custom__cellOptions={'type': 'color-text'}),
        by_name('→ нода', custom__minWidth=170, color={'mode': 'fixed', 'fixedColor': GREY},
                custom__cellOptions={'type': 'color-text'}),
        by_name('Итог', custom__width=165, custom__align='center',
                custom__cellOptions={'type': 'color-background', 'mode': 'basic'}, mappings=STATE_MAP),
        *[by_name(n, custom__width=82, custom__align='center', mappings=OK_MAP,
                  custom__cellOptions={'type': 'color-text'}) for n in ok_cols],
        by_name('из РФ, мс', unit='ms', decimals=0, custom__width=85, custom__align='right',
                custom__cellOptions={'type': 'color-text'},
                thresholds={'mode': 'absolute', 'steps': [{'color': 'text', 'value': None},
                                                          {'color': YELLOW, 'value': 1500},
                                                          {'color': RED, 'value': 4000}]}),
    ], desc='Строка — хост панели. Итог: работает — открывается из РФ хотя бы с одной пробы (хосты МСК-нод — '
            'с сервера мониторинга); блокировка в РФ — из России не открывается, а вход и нода работают; '
            'сломан вход — не работает прокладка или CDN, нода жива; нода не отвечает — не открывается даже '
            'напрямую. Колонки проб — проверка из России как приложение клиента. NL · вход — с сервера '
            'мониторинга по адресу из подписки (только у хостов, где вход не сама нода), NL · нода — напрямую '
            'на ноду. Дальше — проверки маршрутов. «—» — эта проверка хосту не нужна. «→ нода» — куда ведёт хост.',
        sort=[{'displayName': 'Итог', 'desc': True}]))
    y += 18

    p.append(state_history('История хостов', {'h': 14, 'w': 24, 'x': 0, 'y': y},
                           f'max by (name) ({host_state})', '{{name}}',
                           'Итог по каждому хосту во времени: зелёным — работал, цветом — что было не так '
                           '(как в таблице «Хосты»). Наведите на полосу — увидите, когда и сколько'))
    y += 14

    # ── 5. Ноды: всё про ноду в одной строке ──
    def node_q(expr, ref, instant=True):
        return target(f'sum by (panel_title, node_name) (({expr}) {BY_NODE})', ref, instant=instant,
                      fmt='table' if instant else 'time_series')

    def srv(expr):                         # node_exporter → одна серия на ноду
        return f'max by (panel, node_uuid) ({expr})'
    cpu = srv('1 - avg by (panel, node_uuid) (rate(node_cpu_seconds_total{mode="idle"}[5m]))')
    ram = srv('1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes')
    swap = srv('(1 - node_memory_SwapFree_bytes / node_memory_SwapTotal_bytes) and node_memory_SwapTotal_bytes > 0')
    disk = srv('1 - node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}')
    ct = srv('node_nf_conntrack_entries / node_nf_conntrack_entries_limit')
    pct = lambda n, warn, w=58: by_name(n, unit='percentunit', decimals=0, custom__width=w, custom__align='right',
                                        custom__cellOptions={'type': 'color-text'},
                                        thresholds={'mode': 'absolute', 'steps': [{'color': 'text', 'value': None},
                                                                                  {'color': YELLOW, 'value': warn},
                                                                                  {'color': RED, 'value': 0.9}]})
    ncols = [('S', 'Связь', node_q(f'rwmon_node_connected{{{F}}}', 'S')),
             ('A', 'Онлайн', node_q(f'rwmon_node_online_users{{{F}}}', 'A')),
             ('P', 'пик', node_q(f'max_over_time(rwmon_node_online_users{{{F}}}[$__range])', 'P')),
             ('G', 'CPU', node_q(f'rwmon_node_cpu_load5{{{F}}}', 'G')),
             ('H', 'RAM', node_q(f'rwmon_node_memory_used_ratio{{{F}}}', 'H'))]
    if servers:
        ncols += [('D', 'Диск', node_q(disk, 'D')), ('N', 'conntrack', node_q(ct, 'N'))]
    ncols += [('C', '↓ RX', node_q(f'rwmon_node_network_rx_bytes_per_second{{{F}}} * 8', 'C')),
              ('O', '↑ TX', node_q(f'rwmon_node_network_tx_bytes_per_second{{{F}}} * 8', 'O')),
              ('E', 'трафик', node_q(f'sum by (panel, node_uuid) (increase(rwmon_node_inbound_upload_bytes{{{F}}}'
                                     f'[$__range]) + increase(rwmon_node_inbound_download_bytes{{{F}}}[$__range]))', 'E')),
              ('L', 'лимит', node_q(f'rwmon_node_traffic_used_bytes{{{F}}} / rwmon_node_traffic_limit_bytes{{{F}}}', 'L')),
              ('U', 'Сервер', node_q(f'rwmon_node_uptime_seconds{{{F}}}', 'U')),
              ('X', 'Xray', node_q(f'rwmon_node_xray_uptime_seconds{{{F}}}', 'X'))]
    ntargets = [t for _, _, t in ncols] + [
        target(f'max by (panel_title, node_name, xray) (rwmon_node_version{{{F}}} {BY_NODE})', 'V',
               instant=True, fmt='table')]
    nkey = lambda ref: f'Value #{ref}'
    norder = {'panel_title': 0, 'node_name': 1, **{nkey(ref): 2 + i for i, (ref, _, _) in enumerate(ncols)},
              'xray': 2 + len(ncols)}
    p.append(table('Ноды', {'h': 15, 'w': 24, 'x': 0, 'y': y}, ntargets, [
        # без графиков в ячейках: timeSeriesTable мешает merge, и Grafana показывала только первую таблицу
        {'id': 'merge', 'options': {}},
        {'id': 'organize', 'options': {
            'excludeByName': {'Time': True, 'Value #V': True},
            'indexByName': norder,
            'renameByName': {'panel_title': 'Панель', 'node_name': 'Нода', 'xray': 'версия Xray',
                             **{nkey(ref): title for ref, title, _ in ncols}}}},
    ], [
        by_name('Панель', custom__width=105, color={'mode': 'fixed', 'fixedColor': GREY},
                custom__cellOptions={'type': 'color-text'}),
        by_name('Нода', custom__minWidth=140),
        by_name('Связь', custom__width=60, custom__cellOptions={'type': 'color-text'}, custom__align='center',
                mappings=[{'type': 'value', 'options': {'1': {'text': 'да', 'color': GREEN},
                                                        '0': {'text': 'нет', 'color': RED}}}]),
        by_name('Онлайн', decimals=0, custom__width=70, custom__align='right'),
        by_name('пик', decimals=0, custom__width=60, custom__align='right', color={'mode': 'fixed', 'fixedColor': GREY},
                custom__cellOptions={'type': 'color-text'}),
        pct('CPU', 0.7), pct('RAM', 0.8), pct('лимит', 0.8), pct('Диск', 0.8), pct('conntrack', 0.7, 80),
        by_name('↓ RX', unit='bps', decimals=1, custom__width=92, custom__align='right'),
        by_name('↑ TX', unit='bps', decimals=1, custom__width=92, custom__align='right'),
        by_name('трафик', unit='decbytes', decimals=1, custom__width=82, custom__align='right'),
        by_name('Сервер', unit='dtdurations', decimals=0, custom__width=88, custom__align='right',
                color={'mode': 'fixed', 'fixedColor': GREY}, custom__cellOptions={'type': 'color-text'}),
        by_name('Xray', unit='dtdurations', decimals=0, custom__width=88, custom__align='right',
                custom__cellOptions={'type': 'color-text'},
                thresholds={'mode': 'absolute', 'steps': [{'color': YELLOW, 'value': None},
                                                          {'color': 'text', 'value': 86400}]}),
        by_name('версия Xray', custom__width=85, color={'mode': 'fixed', 'fixedColor': GREY},
                custom__cellOptions={'type': 'color-text'}),
    ], desc='Связь — нода подключена к панели. Пик — больше всего клиентов за выбранный период. CPU — load average на ядро, RAM — занятая память (по данным панели)'
            + ('; Диск и conntrack — по node_exporter на ноде (корневой раздел и таблица соединений ядра)'
               if servers else '')
            + '. RX/TX — сеть сервера сейчас, трафик — клиентов за выбранный период, лимит — расход трафика ноды, '
            'если он задан в панели. Сервер и Xray — сколько работают без перезапуска (жёлтым — Xray перезапускался '
            'меньше суток назад).',
        sort=[{'displayName': 'Онлайн', 'desc': True}]))
    y += 15

    # ── 6. Три общих графика ──
    p.append(timeseries('Клиенты онлайн', {'h': 8, 'w': 8, 'x': 0, 'y': y}, [
        target(f'sum by (panel_title) (rwmon_node_online_users{{{F}}})', 'A', '{{panel_title}}'),
    ], 'none', stack=True, fill=35, desc='По панелям, слоями: высота — сколько всего клиентов'))
    p.append(timeseries('Сеть всех нод', {'h': 8, 'w': 8, 'x': 8, 'y': y}, [
        target(f'sum by (panel_title) ({smooth("rwmon_node_network_rx_bytes_per_second", F)}) * 8', 'A',
               '{{panel_title}} ↓ RX'),
        target(f'sum by (panel_title) ({smooth("rwmon_node_network_tx_bytes_per_second", F)}) * 8', 'B',
               '{{panel_title}} ↑ TX'),
    ], 'bps', overrides=negative_tx(),
        desc='Вверх от нуля — принято серверами (RX), вниз пунктиром — отправлено (TX). '
             'Сглажено: среднее за шаг графика'))
    p[-1]['interval'] = '2m'
    p.append(timeseries('Аутбаунды: $outbound', {'h': 8, 'w': 8, 'x': 16, 'y': y}, [
        target(f'sum by (tag) (rate(rwmon_node_outbound_download_bytes{{tag=~"$outbound", {F}}}[5m])) * 8',
               'A', '{{tag}} ответы'),
        target(f'sum by (tag) (rate(rwmon_node_outbound_upload_bytes{{tag=~"$outbound", {F}}}[5m])) * 8',
               'B', '{{tag}} запросы'),
    ], 'bps', overrides=negative_tx(),
        desc='Все ноды вместе. Вверх — ответы из аутбаунда, вниз — запросы в него. '
             'Если запросы есть, а ответов нет — аутбаунд сломан'))
    y += 8

    # ── 7. Каждая нода отдельно: карточка на ноду — сеть сервера ──
    one = f'topk by (panel, node_uuid) (1, rwmon_node_info{{{F}, node=~"$node"}})'
    one_by = f'* on (panel, node_uuid) group_left (node) {one}'
    p.append({'id': _next(), 'type': 'row', 'title': 'Каждая нода отдельно', 'collapsed': False,
              'gridPos': {'h': 1, 'w': 24, 'x': 0, 'y': y}, 'panels': []})
    card = timeseries('$node', {'h': 6, 'w': 6, 'x': 0, 'y': y + 1}, [
        target(f'sum by (node) (({smooth("rwmon_node_network_rx_bytes_per_second", F)} * 8) {one_by})',
               'A', '↓ принято'),
        target(f'sum by (node) (({smooth("rwmon_node_network_tx_bytes_per_second", F)} * 8) {one_by})',
               'B', '↑ отправлено'),
    ], 'bps', fill=30, overrides=[
        by_name('↓ принято', color={'mode': 'fixed', 'fixedColor': GREEN}),
        by_name('↑ отправлено', color={'mode': 'fixed', 'fixedColor': YELLOW}, custom__transform='negative-Y'),
    ], desc='Сеть сервера ноды: вверх (зелёным) — принято, вниз (жёлтым) — отправлено. '
            'Сглажено: среднее за шаг графика. Показываются ноды, выбранные вверху в «Нода».')
    card['interval'] = '2m'
    card.update({'repeat': 'node', 'repeatDirection': 'h', 'maxPerRow': 4})
    card['options']['legend'] = {'showLegend': False, 'displayMode': 'hidden', 'placement': 'bottom', 'calcs': []}
    card['options']['tooltip'] = {'mode': 'multi', 'sort': 'none'}
    card['fieldConfig']['defaults']['custom']['lineWidth'] = 1.5
    p.append(card)
    y += 7

    # ── свёрнутые блоки с подробностями ──
    # Выходы по нодам: такие же карточки, но только выходы из фильтра «Аутбаунд»
    ocard = timeseries('$node', {'h': 7, 'w': 6, 'x': 0, 'y': y + 1}, [
        target(f'sum by (tag) ((rate(rwmon_node_outbound_download_bytes{{tag=~"$outbound", {F}}}[5m]) * 8) '
               f'{one_by})', 'A', '{{tag}} ответы'),
        target(f'sum by (tag) ((rate(rwmon_node_outbound_upload_bytes{{tag=~"$outbound", {F}}}[5m]) * 8) '
               f'{one_by})', 'B', '{{tag}} запросы'),
    ], 'bps', fill=20, overrides=negative_tx() + [
        by_regex('^WARP .*', color={'mode': 'fixed', 'fixedColor': 'orange'}),
        # через Psiphon идёт в десятки раз меньше, чем через WARP — своя шкала справа, иначе линия в нуле
        by_regex('^psiphon.*', color={'mode': 'fixed', 'fixedColor': 'purple'}, custom__axisPlacement='right'),
    ], desc='Трафик ноды через выходы, выбранные вверху в «Аутбаунд»: вверх — ответы из выхода, '
            'вниз пунктиром — запросы в него. Psiphon — по правой шкале: через него идёт намного меньше. '
            'Запросы есть, а ответов нет — выход на этой ноде сломан. '
            'Пусто — через выход на этой ноде никто не ходил.')
    ocard.update({'repeat': 'node', 'repeatDirection': 'h', 'maxPerRow': 4})
    ocard['options']['legend'] = {'showLegend': True, 'displayMode': 'list', 'placement': 'bottom', 'calcs': []}
    ocard['options']['tooltip'] = {'mode': 'multi', 'sort': 'none'}
    ocard['fieldConfig']['defaults']['custom']['lineWidth'] = 1.5
    ocard['fieldConfig']['defaults']['custom']['axisCenteredZero'] = True   # ноль обеих шкал на одной высоте
    ocard['fieldConfig']['defaults']['noValue'] = 'Нет трафика через выбранные выходы'
    p.append(row('Выходы по нодам: $outbound', y, [ocard]))
    y += 1

    # Сравнение нод: все выбранные ноды на одном графике — видно, какая выделяется
    def node_ts(expr, ref, legend='{{node_name}} · {{panel_title}}'):
        return target(f'sum by (panel_title, node_name) (({expr}) {BY_NODE})', ref, legend)
    compare = [
        timeseries('Клиенты на нодах', {'h': 8, 'w': 12, 'x': 0, 'y': y + 1},
                   [node_ts(f'rwmon_node_online_users{{{F}}}', 'A')], 'none', legend='table',
                   placement='right', fill=0),
        timeseries('Трафик клиентов: к клиентам ↑ / от клиентов ↓', {'h': 8, 'w': 12, 'x': 12, 'y': y + 1}, [
            node_ts(f'sum by (panel, node_uuid) (rate(rwmon_node_inbound_download_bytes{{{F}}}[5m])) * 8', 'A'),
            node_ts(f'sum by (panel, node_uuid) (rate(rwmon_node_inbound_upload_bytes{{{F}}}[5m])) * 8', 'B',
                    '{{node_name}} · {{panel_title}} ↑ от клиентов'),
        ], 'bps', overrides=negative_tx(), legend='table', placement='right', fill=0),
        timeseries('CPU: load average на ядро', {'h': 8, 'w': 12, 'x': 0, 'y': y + 9},
                   [node_ts(f'rwmon_node_cpu_load5{{{F}}}', 'A')], 'percentunit', legend='table',
                   placement='right', fill=0),
        timeseries('Память', {'h': 8, 'w': 12, 'x': 12, 'y': y + 9},
                   [node_ts(f'rwmon_node_memory_used_ratio{{{F}}}', 'A')], 'percentunit', legend='table',
                   placement='right', fill=0),
        timeseries('Аутбаунды $outbound: ответы ↑ / запросы ↓', {'h': 8, 'w': 24, 'x': 0, 'y': y + 17}, [
            target(f'sum by (panel_title, node_name, tag) ((rate(rwmon_node_outbound_download_bytes'
                   f'{{tag=~"$outbound", {F}}}[5m]) * 8) {BY_NODE})', 'A', '{{node_name}} · {{tag}}'),
            target(f'sum by (panel_title, node_name, tag) ((rate(rwmon_node_outbound_upload_bytes'
                   f'{{tag=~"$outbound", {F}}}[5m]) * 8) {BY_NODE})', 'B', '{{node_name}} · {{tag}} ↑ запросы'),
        ], 'bps', overrides=negative_tx(), legend='table', placement='right', fill=0),
    ]
    limit_90(compare[2:4])
    legend_right(compare)
    p.append(row('Сравнение нод', y, compare))
    y += 1

    # Серверы нод по node_exporter: железо, которого не видно из API панели
    if servers:
        free = srv('node_filesystem_avail_bytes{mountpoint="/"}')
        boot = srv('time() - node_boot_time_seconds')
        up = srv('up{job="node"}')
        io = srv('sum by (panel, node_uuid) (rate(node_disk_read_bytes_total[5m]) + rate(node_disk_written_bytes_total[5m]))')
        servers_table = table('Серверы нод', {'h': 12, 'w': 24, 'x': 0, 'y': y + 1}, [
            node_q(up, 'S'), node_q(cpu, 'C'), node_q(ram, 'M'), node_q(swap, 'W'), node_q(disk, 'D'),
            node_q(free, 'F'), node_q(ct, 'N'), node_q(io, 'I'), node_q(boot, 'B'),
        ], [
            {'id': 'merge', 'options': {}},
            {'id': 'organize', 'options': {
                'excludeByName': {'Time': True},
                'indexByName': {'panel_title': 0, 'node_name': 1, 'Value #S': 2, 'Value #C': 3, 'Value #M': 4,
                                'Value #W': 5, 'Value #D': 6, 'Value #F': 7, 'Value #N': 8, 'Value #I': 9,
                                'Value #B': 10},
                'renameByName': {'panel_title': 'Панель', 'node_name': 'Нода', 'Value #S': 'Метрики',
                                 'Value #C': 'CPU', 'Value #M': 'RAM', 'Value #W': 'Swap', 'Value #D': 'Диск',
                                 'Value #F': 'свободно', 'Value #N': 'conntrack', 'Value #I': 'диск I/O',
                                 'Value #B': 'без перезагрузки'}}},
        ], [
            by_name('Панель', custom__width=105, color={'mode': 'fixed', 'fixedColor': GREY},
                    custom__cellOptions={'type': 'color-text'}),
            by_name('Нода', custom__minWidth=140),
            by_name('Метрики', custom__width=75, custom__align='center', custom__cellOptions={'type': 'color-text'},
                    mappings=[{'type': 'value', 'options': {'1': {'text': 'есть', 'color': GREEN},
                                                            '0': {'text': 'нет', 'color': RED}}}]),
            pct('CPU', 0.7, 70), pct('RAM', 0.8, 70), pct('Swap', 0.5, 70), pct('Диск', 0.8, 70),
            pct('conntrack', 0.7, 80),
            by_name('свободно', unit='bytes', decimals=1, custom__width=90, custom__align='right'),
            by_name('диск I/O', unit='Bps', decimals=1, custom__width=95, custom__align='right'),
            by_name('без перезагрузки', unit='dtdurations', decimals=0, custom__width=120, custom__align='right',
                    color={'mode': 'fixed', 'fixedColor': GREY}, custom__cellOptions={'type': 'color-text'}),
        ], desc='Данные node_exporter на самих нодах. CPU — занятость процессора (не load average), '
                'RAM — занято с учётом кэша, Диск — корневой раздел, conntrack — заполненность таблицы '
                'соединений ядра (близко к 100% — новые соединения начнут теряться). '
                'Метрики «нет» — сервер мониторинга не достучался до node_exporter (порт закрыт или служба не работает).',
            sort=[{'displayName': 'Диск', 'desc': True}])
        graphs = [timeseries(title, {'h': 8, 'w': 12, 'x': 12 * (i % 2), 'y': y + 13 + 8 * (i // 2)},
                             [node_ts(expr, 'A')], 'percentunit', legend='table', placement='right', fill=0)
                  for i, (title, expr) in enumerate((('CPU: занятость процессора', cpu), ('Память', ram),
                                                     ('Диск: корневой раздел', disk),
                                                     ('conntrack: таблица соединений', ct)))]
        limit_90(graphs)
        legend_right(graphs)
        p.append(row('Серверы нод: процессор, память, диск', y, [servers_table] + graphs))
        y += 1

    # Проверки подробно: из РФ по пробам и с сервера мониторинга
    detail = [
        history('Из РФ: история по хостам', {'h': 12, 'w': 24, 'x': 0, 'y': y + 1},
                'min by (name) (rwmon_ru_status)', '{{name}}',
                'Открывался ли хост из России: красным — хотя бы с одной пробы не открылся '
                '(худший результат проб). По пробам отдельно — в подсказке графика ниже.'),
        timeseries('Из РФ: время ответа через хост', {'h': 9, 'w': 24, 'x': 0, 'y': y + 13}, [
            target('max by (name, probe) (rwmon_ru_latency_ms > 0)', 'A', '{{name}} · {{probe}}'),
        ], 'ms', legend='table', placement='right', fill=0,
            desc='Сколько занимает проверка из России: подключение к хосту и загрузка страницы, по каждой пробе'),
        history('С сервера мониторинга: история по хостам', {'h': 12, 'w': 24, 'x': 0, 'y': y + 22},
                'min by (name) (xray_proxy_status{name!="rwmon-empty"})', '{{name}}',
                'Худший результат проверок с сервера мониторинга: через вход, на ноду и проверок маршрутов '
                '(WARP, Psiphon). Красным — хоть одна не прошла; какая — в таблице «Хосты»'),
        timeseries('С сервера мониторинга: время ответа на ноду', {'h': 9, 'w': 24, 'x': 0, 'y': y + 34}, [
            target(f'max by (host, panel_title) ({hosts("xray")} * on (name) group_left () '
                   f'max by (name) (xray_proxy_latency_ms{{check="xray"}} > 0))', 'A', '{{host}} · {{panel_title}}'),
        ], 'ms', legend='table', placement='right', fill=0,
            desc='Сколько занимает проверка «на ноду» с сервера мониторинга'),
    ]
    legend_right([detail[1], detail[3]])
    p.append(row('Проверки подробно: из РФ и с сервера мониторинга', y, detail))
    y += 1

    # Здоровье самой панели: процессы api / scheduler / processor
    proc = '{{panel_title}} · {{process}}'
    health = [
        timeseries('Память процессов панели', {'h': 8, 'w': 8, 'x': 0, 'y': y + 1}, [
            target(f'max by (panel_title, process) (rwmon_panel_process_memory_bytes{{{F}}})', 'A', proc),
        ], 'bytes', legend='table', placement='bottom', fill=0,
            desc='Сколько памяти занимает каждый процесс. Норма — ровная линия; если растёт день за днём '
                 'и не падает — утечка. Красная линия — порог алерта по умолчанию (panel_memory_mb = 1024)'),
        timeseries('Задержка процессов панели', {'h': 8, 'w': 8, 'x': 8, 'y': y + 1}, [
            target(f'max by (panel_title, process) (rwmon_panel_process_lag_ms{{{F}}})', 'A', proc),
        ], 'ms', legend='table', placement='bottom', fill=0,
            desc='Насколько процесс не успевает разбирать свою очередь дел (99-й перцентиль). До 50 мс — норма. '
                 'Красная линия — порог алерта «Панель тормозит» по умолчанию (panel_lag_ms = 200)'),
        timeseries('Работает без перезапуска', {'h': 8, 'w': 8, 'x': 16, 'y': y + 1}, [
            target(f'max by (panel_title, process) (rwmon_panel_process_uptime_seconds{{{F}}})', 'A', proc),
        ], 's', legend='table', placement='bottom', fill=0,
            desc='Линия растёт, пока процесс работает; падение в ноль — перезапуск (обновление панели или падение)'),
    ]
    for c, limit in ((health[0], 1024 * 1048576), (health[1], 200)):
        c['fieldConfig']['defaults']['thresholds'] = {'mode': 'absolute', 'steps': [
            {'color': 'transparent', 'value': None}, {'color': RED, 'value': limit}]}
        c['fieldConfig']['defaults']['custom']['thresholdsStyle'] = {'mode': 'dashed'}
    for c in health:
        c['options']['legend']['calcs'] = ['lastNotNull', 'max']
    p.append(row('Здоровье панелей', y, health))
    y += 1

    # GeoCheck: кто как видит ноды
    geo_node = f'* on (panel, node_uuid) group_left (node) topk by (panel, node_uuid) (1, rwmon_node_info{{{F}, node=~"$node"}})'

    # Короткие подписи колонок: длинные названия сервисов не влезают в узкие колонки
    short = {'Google Search captcha': 'Google капча', 'YouTube Premium': 'YT Premium',
             'YouTube Music': 'YT Music', 'Spotify signup': 'Spotify рег.',
             'Reddit guest access': 'Reddit гость', 'Ookla Speedtest': 'Speedtest',
             'Microsoft (Bing)': 'Bing', 'Amazon Prime Video': 'Prime Video',
             'ChatGPT (web)': 'ChatGPT сайт', 'ChatGPT (app)': 'ChatGPT прил.',
             'Cloudflare edge': 'CF edge', 'YouTube / GGC edge': 'YT GGC', 'Netflix Open Connect': 'Netflix OC',
             'rdap.db.ripe.net': 'RIPE'}

    def geo_matrix(title, pos, groups, mappings, desc):
        rename = {'node\\service': 'Нода', **short}
        return table(title, pos, [
            target(f'max by (node, service, value) (rwmon_geocheck{{group=~"{groups}", {F}}} {geo_node})',
                   'A', instant=True, fmt='table'),
        ], [
            {'id': 'groupingToMatrix', 'options': {'columnField': 'service', 'rowField': 'node',
                                                   'valueField': 'value', 'emptyValue': 'null'}},
            {'id': 'organize', 'options': {'renameByName': rename}},
        ], [
            by_name('Нода', custom__width=190),
            by_regex('^(?!Нода$).*', custom__align='center', custom__minWidth=58,
                     custom__cellOptions={'type': 'color-background', 'mode': 'basic'},
                     color={'mode': 'fixed', 'fixedColor': 'transparent'}, mappings=mappings),
        ], desc=desc, sort=[{'displayName': 'Нода', 'desc': False}])
    bad = [{'type': 'regex', 'options': {'pattern': '^(RU|BY)$', 'result': {'color': 'dark-red', 'index': 0}}}]
    # «available (CA)» → «✓ CA», «blocked (RUS)» → «✗ RUS»: короче и читается с одного взгляда
    ok_re, no_re = '(?:available|yes|ok)', '(?:blocked|unavailable|no|restricted|denied)'
    access = [
        {'type': 'regex', 'options': {'pattern': f'^{ok_re}\\s*\\((\\w+)\\)$',
                                      'result': {'text': '✓ $1', 'color': 'dark-green', 'index': 0}}},
        {'type': 'regex', 'options': {'pattern': f'^{ok_re}.*',
                                      'result': {'text': '✓', 'color': 'dark-green', 'index': 1}}},
        {'type': 'regex', 'options': {'pattern': f'^{no_re}\\s*\\((\\w+)\\)$',
                                      'result': {'text': '✗ $1', 'color': 'dark-red', 'index': 2}}},
        {'type': 'regex', 'options': {'pattern': f'^{no_re}.*',
                                      'result': {'text': '✗', 'color': 'dark-red', 'index': 3}}},
    ]
    geo = [
        table('IP нод', {'h': 12, 'w': 24, 'x': 0, 'y': y + 1}, [
            target(f'max by (node, ip, network, ip_type, place, consensus) (rwmon_geocheck_info{{{F}}} {geo_node})',
                   'A', instant=True, fmt='table'),
            target(f'max by (node) (rwmon_geocheck_risk{{{F}}} {geo_node})', 'B', instant=True, fmt='table'),
            target(f'max by (node) (time() - rwmon_geocheck_timestamp_seconds{{{F}}} {geo_node})', 'C',
                   instant=True, fmt='table'),
        ], [
            {'id': 'merge', 'options': {}},
            {'id': 'organize', 'options': {
                'excludeByName': {'Time': True, 'Value #A': True},
                'indexByName': {'node': 0, 'ip': 1, 'network': 2, 'ip_type': 3, 'place': 4, 'consensus': 5,
                                'Value #B': 6, 'Value #C': 7},
                'renameByName': {'node': 'Нода', 'ip': 'IP', 'network': 'Сеть', 'ip_type': 'Тип IP',
                                 'place': 'Место', 'consensus': 'Консенсус GeoIP', 'Value #B': 'риск',
                                 'Value #C': 'проверено'}}},
        ], [
            by_name('Нода', custom__width=190),
            by_name('IP', custom__width=140),
            by_name('риск', custom__width=70, custom__cellOptions={'type': 'color-text'},
                    thresholds={'mode': 'absolute', 'steps': [{'color': 'text', 'value': None},
                                                              {'color': YELLOW, 'value': 30},
                                                              {'color': RED, 'value': 60}]}),
            by_name('проверено', unit='dtdurations', decimals=0, custom__width=110,
                    color={'mode': 'fixed', 'fixedColor': GREY}, custom__cellOptions={'type': 'color-text'}),
        ], desc='IP, сеть и тип IP по последнему GeoCheck. Риск — оценка репутации IP (0–100)',
            sort=[{'displayName': 'Нода', 'desc': False}]),
        geo_matrix('Как сервисы видят ноды', {'h': 16, 'w': 24, 'x': 0, 'y': y + 13}, 'services', bad,
                   'Страна, которую определяет каждый сервис (последний GeoCheck). Красным — RU и BY. '
                   'yes/no — ответы на вопросы вроде «показывает ли Google капчу»'),
        geo_matrix('Доступ к сервисам', {'h': 16, 'w': 24, 'x': 0, 'y': y + 29}, 'stash', access,
                   'Открывается ли сервис с IP ноды: ✓ — да, ✗ — нет, рядом — регион, который он определил'),
        geo_matrix('GeoIP-базы и CDN', {'h': 16, 'w': 24, 'x': 0, 'y': y + 45}, 'geoip|cdn', bad,
                   'Что о стране IP ноды записано в базах GeoIP и что видят CDN'),
    ]
    p.append(row('GeoCheck: как видят ноды', y, geo))

    variables = [
        {'name': 'panel', 'label': 'Панель', 'type': 'query', 'datasource': DS,
         'query': {'query': 'label_values(rwmon_panel_up, panel_title)', 'refId': 'panel', 'qryType': 1},
         'definition': 'label_values(rwmon_panel_up, panel_title)',
         'multi': True, 'includeAll': True, 'allValue': '.*', 'refresh': 2, 'sort': 1,
         'current': {'selected': True, 'text': ['All'], 'value': ['$__all']}},
        {'name': 'node', 'label': 'Нода', 'type': 'query', 'datasource': DS,
         'query': {'query': 'label_values(rwmon_node_info{panel_title=~"$panel"}, node)',
                   'refId': 'node', 'qryType': 1},
         'definition': 'label_values(rwmon_node_info{panel_title=~"$panel"}, node)',
         'multi': True, 'includeAll': True, 'allValue': '.*', 'refresh': 2, 'sort': 1,
         'current': {'selected': True, 'text': ['All'], 'value': ['$__all']}},
        {'name': 'outbound', 'label': 'Аутбаунд', 'type': 'query', 'datasource': DS,
         'query': {'query': 'label_values(rwmon_node_outbound_upload_bytes, tag)', 'refId': 'outbound',
                   'qryType': 1},
         'definition': 'label_values(rwmon_node_outbound_upload_bytes, tag)',
         'regex': '/^(?!BLOCK$|RW_TB_OUTBOUND_BLOCK$|DIRECT$|api$|API$).*/',
         'multi': True, 'includeAll': False, 'refresh': 2, 'sort': 1,
         'current': {'selected': True, 'text': ['WARP', 'psiphon-out'], 'value': ['WARP', 'psiphon-out']}},
    ]
    return {
        'uid': 'rwmon-overview', 'title': 'Remnawave — обзор', 'tags': ['remnawave'],
        'timezone': 'utc', 'schemaVersion': 39, 'version': 3, 'editable': False, 'graphTooltip': 1,
        'time': {'from': 'now-24h', 'to': 'now'}, 'refresh': '1m',
        'templating': {'list': variables}, 'panels': p,
    }


if __name__ == '__main__':
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dashboards', 'remnawave-overview.json')
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(build(), f, ensure_ascii=False, indent=2)
        f.write('\n')
    print('записано:', out)
