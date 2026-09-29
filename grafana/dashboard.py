"""Генератор дашборда grafana/dashboards/remnawave-overview.json.

Дашборд правится здесь, а не в JSON:  python3 grafana/dashboard.py
Grafana читает только готовый JSON; этот файл ей не нужен.

Устройство:
  переменные «Панель», «Нода», «Аутбаунд»;
  6 цифр сверху; таблица нод (всё про ноду в одной строке);
  «Сейчас не работает», состояние панелей и сайтов;
  три общих графика (по панелям); маленький график сети на каждую ноду;
  свёрнутые блоки «Нода подробно», «Проверки хостов», «Проба из РФ», «GeoCheck».
"""
import json
import os

DS = {'type': 'prometheus', 'uid': 'rwmon-prometheus'}
F = 'panel_title=~"$panel"'
# фильтр по выбранным нодам + имя ноды: умножение на rwmon_node_info
NODE = f'topk by (panel, node_uuid) (1, rwmon_node_info{{{F}, node=~"$node"}})'
BY_NODE = f'* on (panel, node_uuid) group_left (node_name, panel_title) {NODE}'
CHECKS = (('xray', 'Подключение'), ('warp', 'WARP'), ('psiphon', 'Psiphon'))

GREEN, RED, YELLOW, BLUE, GREY = 'green', 'red', 'yellow', 'blue', 'text'
OK_MAP = [{'type': 'value', 'options': {'1': {'text': 'OK', 'color': GREEN, 'index': 0},
                                        '0': {'text': 'СБОЙ', 'color': RED, 'index': 1}}},
          {'type': 'special', 'options': {'match': 'null', 'result': {'text': '·', 'color': 'transparent', 'index': 2}}}]


def hosts(check):
    """rwmon_host нужной панели: у лёгких (LTE) хостов проверяется только подключение."""
    return f'rwmon_host{{{F}}}' if check == 'xray' else f'rwmon_host{{{F}, lite="0"}}'


def host_status(check):
    # max by: при обновлении списка у одного имени ненадолго бывает две серии
    return f'{hosts(check)} * on (name) group_left (check) max by (name, check) (xray_proxy_status{{check="{check}"}})'


def node_check(check):
    """Проверка хостов, которые смотрят на IP ноды: худший результат по этим хостам."""
    per_ip = (f'min by (ip) (label_replace(max by (name, address) (xray_proxy_status{{check="{check}"}}), '
              f'"ip", "$1", "address", "(.+):[0-9]+"))')
    return f'({per_ip}) * on (ip) group_right () rwmon_node_address{{{F}}}'


def node_probe():
    """Открывается ли IP ноды из РФ: хоть одна проба смогла — значит открывается."""
    per_ip = ('min by (ip) (label_replace(max by (address) (probe_success{kind="tcp"}), '
              '"ip", "$1", "address", "(.+):[0-9]+"))')
    return f'({per_ip}) * on (ip) group_right () rwmon_node_address{{{F}}}'


def failing():
    return ' or '.join(f'({host_status(c)} == 0)' for c, _ in CHECKS)


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


def stat(title, x, targets, unit='none', desc='', steps=None, overrides=None, decimals=0):
    return {
        'id': _next(), 'type': 'stat', 'title': title, 'description': desc, 'datasource': DS,
        'gridPos': {'h': 4, 'w': 4, 'x': x, 'y': 0},
        'targets': targets,
        'options': {'reduceOptions': {'calcs': ['lastNotNull'], 'fields': '', 'values': False},
                    'colorMode': 'value', 'graphMode': 'none', 'justifyMode': 'center',
                    'textMode': 'value_and_name' if len(targets) > 1 else 'value',
                    'orientation': 'vertical', 'wideLayout': True, 'showPercentChange': False,
                    'text': {'titleSize': 12, 'valueSize': 30}},
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
        'fieldConfig': {'defaults': {'custom': {'align': 'auto', 'filterable': False,
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


# ── сам дашборд ──────────────────────────────────────────────

def build():
    p = []
    y = 0

    # 1. Цифры сверху
    p.append(stat('Онлайн', 0, [target(f'sum(rwmon_node_online_users{{{F}}})', 'A', instant=True)],
                  desc='Клиентов на нодах выбранных панелей прямо сейчас'))
    p.append(stat('Ноды', 4, [
        target(f'sum(rwmon_node_connected{{{F}}})', 'A', 'на связи', instant=True),
        target(f'count(rwmon_node_connected{{{F}}} == 0) or vector(0)', 'B', 'отключены', instant=True),
    ], overrides=[by_ref('B', thresholds={'mode': 'absolute', 'steps': red_if_positive()})],
        desc='Выключенные в панели ноды и ноды из exclude_nodes не считаются'))
    p.append(stat('Хосты', 8, [
        target(f'count(count by (panel, host) (rwmon_host{{{F}}}))', 'A', 'всего', instant=True),
        target(f'count(count by (panel, host) ({failing()})) or vector(0)', 'B', 'со сбоем', instant=True),
    ], overrides=[by_ref('A', color={'mode': 'fixed', 'fixedColor': GREY}),
                  by_ref('B', thresholds={'mode': 'absolute', 'steps': red_if_positive()})],
        desc='Хосты с тегами MONITORING / MONITORING_LITE. Сбой — не проходит хотя бы одна проверка'))
    p.append(stat('Сеть нод сейчас', 12, [
        target(f'sum(rwmon_node_network_rx_bytes_per_second{{{F}}}) * 8', 'A', '↓ RX', instant=True),
        target(f'sum(rwmon_node_network_tx_bytes_per_second{{{F}}}) * 8', 'B', '↑ TX', instant=True),
    ], unit='bps', decimals=1, steps=[{'color': BLUE, 'value': None}],
        desc='Скорость сетевых интерфейсов всех серверов нод: RX — принято сервером, TX — отправлено'))
    p.append(stat('Трафик клиентов', 16, [target(
        f'sum(increase(rwmon_node_inbound_upload_bytes{{{F}}}[$__range]) '
        f'+ increase(rwmon_node_inbound_download_bytes{{{F}}}[$__range]))', 'A', instant=True)],
        unit='decbytes', decimals=1, steps=[{'color': GREY, 'value': None}],
        desc='Сколько клиенты скачали и отправили через все ноды за выбранный период'))
    p.append(stat('Подписки', 20, [
        target(f'sum(rwmon_users{{status="ACTIVE", {F}}})', 'A', 'активных', instant=True),
        target(f'sum(rwmon_users_online{{period="lastDay", {F}}})', 'B', 'были онлайн за сутки', instant=True),
    ], overrides=[by_ref('B', color={'mode': 'fixed', 'fixedColor': GREY})]))
    y = 4

    # 2. Таблица нод: всё про ноду в одной строке
    def node_q(expr, ref, instant=True):
        return target(f'sum by (panel_title, node_name) (({expr}) {BY_NODE})', ref, instant=instant,
                      fmt='table' if instant else 'time_series')
    nodes = table('Ноды', {'h': 15, 'w': 24, 'x': 0, 'y': y}, [
        node_q(f'rwmon_node_connected{{{F}}}', 'S'),
        node_q(f'rwmon_node_online_users{{{F}}}', 'A'),
        node_q(f'rwmon_node_online_users{{{F}}}', 'T1', instant=False),
        *[node_q(node_check(c), 'K' + c) for c, _ in CHECKS],
        node_q(node_probe(), 'R'),
        node_q(f'rwmon_node_uptime_seconds{{{F}}}', 'U'),
        node_q(f'rwmon_node_xray_uptime_seconds{{{F}}}', 'X'),
        target(f'max by (panel_title, node_name, xray) (rwmon_node_version{{{F}}} {BY_NODE})', 'V',
               instant=True, fmt='table'),
        node_q(f'rwmon_node_cpu_load5{{{F}}}', 'G'),
        node_q(f'rwmon_node_memory_used_ratio{{{F}}}', 'H'),
        node_q(f'rwmon_node_network_rx_bytes_per_second{{{F}}} * 8', 'C'),
        node_q(f'rwmon_node_network_tx_bytes_per_second{{{F}}} * 8', 'D'),
        node_q(f'sum by (panel, node_uuid) (increase(rwmon_node_inbound_upload_bytes{{{F}}}[$__range]) '
               f'+ increase(rwmon_node_inbound_download_bytes{{{F}}}[$__range]))', 'E'),
        node_q(f'rwmon_node_traffic_used_bytes{{{F}}} / rwmon_node_traffic_limit_bytes{{{F}}}', 'L'),
    ], [
        {'id': 'timeSeriesTable', 'options': {}},
        {'id': 'merge', 'options': {}},
        {'id': 'organize', 'options': {
            'excludeByName': {'Time': True, 'Value #V': True},
            'indexByName': {'panel_title': 0, 'node_name': 1, 'Value #S': 2, 'Value #A': 3, 'Trend #T1': 4,
                            'Value #Kxray': 5, 'Value #Kwarp': 6, 'Value #Kpsiphon': 7, 'Value #R': 8,
                            'Value #U': 9, 'Value #X': 10, 'xray': 11, 'Value #G': 12, 'Value #H': 13,
                            'Value #C': 14, 'Value #D': 15, 'Value #E': 16, 'Value #L': 17},
            'renameByName': {'panel_title': 'Панель', 'node_name': 'Нода', 'Value #S': 'Связь',
                             'Value #A': 'Онлайн', 'Trend #T1': 'онлайн за период',
                             'Value #Kxray': 'Подкл.', 'Value #Kwarp': 'WARP', 'Value #Kpsiphon': 'Psiphon',
                             'Value #R': 'Из РФ', 'Value #U': 'Сервер', 'Value #X': 'Xray', 'xray': 'версия',
                             'Value #G': 'CPU', 'Value #H': 'RAM', 'Value #C': '↓ RX', 'Value #D': '↑ TX',
                             'Value #E': 'трафик', 'Value #L': 'лимит'}}},
    ], [
        by_name('Панель', custom__width=105, color={'mode': 'fixed', 'fixedColor': GREY},
                custom__cellOptions={'type': 'color-text'}),
        by_name('Нода', custom__minWidth=130),
        by_name('Связь', custom__width=60, custom__cellOptions={'type': 'color-text'}, custom__align='center',
                mappings=[{'type': 'value', 'options': {'1': {'text': 'да', 'color': GREEN},
                                                        '0': {'text': 'нет', 'color': RED}}}]),
        by_name('Онлайн', decimals=0, custom__width=70, custom__align='right'),
        by_name('онлайн за период', custom__cellOptions={'type': 'sparkline', 'hideValue': True},
                color={'mode': 'fixed', 'fixedColor': GREEN}, custom__minWidth=120),
        *[by_name(n, custom__width=72, custom__align='center', mappings=OK_MAP,
                  custom__cellOptions={'type': 'color-background', 'mode': 'basic'})
          for n in ('Подкл.', 'WARP', 'Psiphon', 'Из РФ')],
        by_name('Сервер', unit='dtdurations', decimals=0, custom__width=90, custom__align='right',
                color={'mode': 'fixed', 'fixedColor': GREY}, custom__cellOptions={'type': 'color-text'}),
        by_name('Xray', unit='dtdurations', decimals=0, custom__width=90, custom__align='right',
                custom__cellOptions={'type': 'color-text'},
                thresholds={'mode': 'absolute', 'steps': [{'color': YELLOW, 'value': None},
                                                          {'color': 'text', 'value': 86400}]}),
        by_name('версия', custom__width=75, color={'mode': 'fixed', 'fixedColor': GREY},
                custom__cellOptions={'type': 'color-text'}),
        *[by_name(n, unit='percentunit', decimals=0, custom__width=58, custom__align='right',
                  custom__cellOptions={'type': 'color-text'},
                  thresholds={'mode': 'absolute', 'steps': [{'color': 'text', 'value': None},
                                                            {'color': YELLOW, 'value': t},
                                                            {'color': RED, 'value': 0.9}]})
          for n, t in (('CPU', 0.7), ('RAM', 0.8), ('лимит', 0.8))],
        by_name('↓ RX', unit='bps', decimals=1, custom__width=95, custom__align='right'),
        by_name('↑ TX', unit='bps', decimals=1, custom__width=95, custom__align='right'),
        by_name('трафик', unit='decbytes', decimals=1, custom__width=85, custom__align='right'),
    ], desc='Связь — нода подключена к панели. Подкл./WARP/Psiphon — проверки хостов, которые смотрят на IP '
            'этой ноды; «Из РФ» — открывается ли нода с проб в России. Сервер и Xray — сколько работают без '
            'перезапуска (жёлтым — Xray перезапускался меньше суток назад). CPU — load average на ядро. '
            'Трафик — клиентов за выбранный период, лимит — расход трафика ноды, если он задан в панели.',
        sort=[{'displayName': 'Онлайн', 'desc': True}])
    p.append(nodes)
    y += 15

    # 3. Сейчас не работает, панели, сайты
    # хост не проходит проверку → сколько секунд назад она проходила последний раз
    # (не проходила ни разу за сутки — показываем «1 день»)
    down = ' or '.join(
        f'({hosts(c)} * on (name) group_left (check) '
        f'((time() - max by (name, check) (max_over_time(timestamp(xray_proxy_status{{check="{c}"}} == 1)[1d:1m]))) '
        f'and on (name) (max by (name) (xray_proxy_status{{check="{c}"}}) == 0)))'
        f' or (({host_status(c)} == 0) * 0 + 86400)'
        for c, _ in CHECKS)
    down += (f' or (label_replace(rwmon_host{{{F}}} * on (address) group_left () '
             f'(max by (address) (probe_success{{kind="tcp"}}) == 0), "check", "ru", "", "") * 0 + 0)')
    p.append(table('Сейчас не работает', {'h': 8, 'w': 10, 'x': 0, 'y': y}, [
        target(down, 'A', instant=True, fmt='table'),
    ], [
        {'id': 'organize', 'options': {
            'includeByName': {'panel_title': True, 'host': True, 'check': True, 'Value': True},
            'indexByName': {'panel_title': 0, 'host': 1, 'check': 2, 'Value': 3},
            'renameByName': {'panel_title': 'Панель', 'host': 'Хост', 'check': 'Проверка',
                             'Value': 'не работает'}}},
    ], [
        by_name('Панель', custom__width=100, color={'mode': 'fixed', 'fixedColor': GREY},
                custom__cellOptions={'type': 'color-text'}),
        by_name('Проверка', custom__width=110, custom__cellOptions={'type': 'color-background'},
                color={'mode': 'fixed', 'fixedColor': 'dark-red'},
                mappings=[{'type': 'value', 'options': {**{c: {'text': t} for c, t in CHECKS},
                                                        'ru': {'text': 'из РФ'}}}]),
        by_name('не работает', unit='dtdurations', custom__width=110,
                mappings=[{'type': 'value', 'options': {'0': {'text': '—'}}}]),
    ], desc='Хосты, которые не проходят проверку прямо сейчас, и сколько времени назад проверка '
            'проходила последний раз (в пределах суток). «из РФ» — ни одна проба в России не может '
            'открыть соединение с хостом.', sort=[{'displayName': 'не работает', 'desc': True}]))
    p[-1]['fieldConfig']['defaults']['noValue'] = 'Всё работает'

    p.append(table('Панели', {'h': 8, 'w': 6, 'x': 10, 'y': y}, [
        target(f'max by (panel_title) (rwmon_panel_up{{{F}}})', 'A', instant=True, fmt='table'),
        target(f'max by (panel_title, version) (rwmon_panel_info{{{F}}})', 'B', instant=True, fmt='table'),
        target(f'max by (panel_title) (rwmon_panel_traffic_exact{{{F}}})', 'C', instant=True, fmt='table'),
        target(f'sum by (panel_title) (rwmon_users_total{{{F}}})', 'D', instant=True, fmt='table'),
    ], [
        {'id': 'merge', 'options': {}},
        {'id': 'organize', 'options': {
            'excludeByName': {'Time': True, 'Value #B': True},
            'indexByName': {'panel_title': 0, 'Value #A': 1, 'version': 2, 'Value #D': 3, 'Value #C': 4},
            'renameByName': {'panel_title': 'Панель', 'Value #A': 'API', 'version': 'версия',
                             'Value #D': 'польз.', 'Value #C': 'трафик'}}},
    ], [
        by_name('API', custom__width=55, custom__cellOptions={'type': 'color-background'},
                mappings=[{'type': 'value', 'options': {'1': {'text': 'OK', 'color': GREEN},
                                                        '0': {'text': 'НЕТ', 'color': RED}}}]),
        by_name('трафик', mappings=[{'type': 'value', 'options': {'1': {'text': 'точный'},
                                                                  '0': {'text': '≈ из API'}}}]),
        by_name('польз.', decimals=0),
    ], desc='Трафик «из API» округлён панелью — для точного укажите metrics_url в config.toml'))

    p.append(table('Сайты', {'h': 8, 'w': 8, 'x': 16, 'y': y}, [
        target('max by (site) (rwmon_site_up)', 'A', instant=True, fmt='table'),
        target('max by (site) (probe_success{kind="http"})', 'B', instant=True, fmt='table'),
        target('max by (site) (rwmon_site_response_seconds)', 'C', instant=True, fmt='table'),
        target('max by (site) (rwmon_site_cert_expiry_timestamp_seconds - time())', 'D', instant=True, fmt='table'),
        target('max by (site) (rwmon_site_status_code)', 'E', instant=True, fmt='table'),
    ], [
        {'id': 'merge', 'options': {}},
        {'id': 'organize', 'options': {
            'excludeByName': {'Time': True},
            'indexByName': {'site': 0, 'Value #A': 1, 'Value #B': 2, 'Value #E': 3, 'Value #C': 4, 'Value #D': 5},
            'renameByName': {'site': 'Сайт', 'Value #A': 'открывается', 'Value #B': 'из РФ', 'Value #E': 'код',
                             'Value #C': 'ответ', 'Value #D': 'сертификат'}}},
    ], [
        *[by_name(n, custom__width=90, custom__align='center', mappings=OK_MAP,
                  custom__cellOptions={'type': 'color-background', 'mode': 'basic'})
          for n in ('открывается', 'из РФ')],
        by_name('код', decimals=0, custom__width=55, custom__cellOptions={'type': 'color-text'},
                thresholds={'mode': 'absolute', 'steps': [{'color': RED, 'value': None},
                                                          {'color': 'text', 'value': 200},
                                                          {'color': RED, 'value': 400}]}),
        by_name('ответ', unit='s', decimals=2, custom__width=70),
        by_name('сертификат', unit='dtdurations', decimals=0, custom__cellOptions={'type': 'color-text'},
                thresholds={'mode': 'absolute', 'steps': [{'color': RED, 'value': None},
                                                          {'color': YELLOW, 'value': 7 * 86400},
                                                          {'color': 'text', 'value': 14 * 86400}]}),
    ], desc='Сайты из [[site]] в config.toml: проверка с сервера мониторинга и с проб в России, '
            'время ответа и сколько осталось до конца сертификата'))
    p[-1]['fieldConfig']['defaults']['noValue'] = 'Добавьте [[site]] в config.toml'
    y += 8

    # 4. Три простых графика
    p.append(timeseries('Клиенты онлайн', {'h': 8, 'w': 8, 'x': 0, 'y': y}, [
        target(f'sum by (panel_title) (rwmon_node_online_users{{{F}}})', 'A', '{{panel_title}}'),
    ], 'none', stack=True, fill=35, desc='По панелям, слоями: высота — сколько всего клиентов'))
    p.append(timeseries('Сеть всех нод', {'h': 8, 'w': 8, 'x': 8, 'y': y}, [
        target(f'sum by (panel_title) (rwmon_node_network_rx_bytes_per_second{{{F}}}) * 8', 'A',
               '{{panel_title}} ↓ RX'),
        target(f'sum by (panel_title) (rwmon_node_network_tx_bytes_per_second{{{F}}}) * 8', 'B',
               '{{panel_title}} ↑ TX'),
    ], 'bps', overrides=negative_tx(),
        desc='Вверх от нуля — принято серверами (RX), вниз пунктиром — отправлено (TX)'))
    p.append(timeseries('Аутбаунды: $outbound', {'h': 8, 'w': 8, 'x': 16, 'y': y}, [
        target(f'sum by (tag) (rate(rwmon_node_outbound_download_bytes{{tag=~"$outbound", {F}}}[5m])) * 8',
               'A', '{{tag}} ответы'),
        target(f'sum by (tag) (rate(rwmon_node_outbound_upload_bytes{{tag=~"$outbound", {F}}}[5m])) * 8',
               'B', '{{tag}} запросы'),
    ], 'bps', overrides=negative_tx(),
        desc='Все ноды вместе. Вверх — ответы из аутбаунда, вниз — запросы в него. '
             'Если запросы есть, а ответов нет — аутбаунд сломан'))
    y += 8

    # 5. Сеть по нодам: маленький график на каждую ноду (повторяется по переменной «Нода»)
    one = f'topk by (panel, node_uuid) (1, rwmon_node_info{{{F}, node=~"$node"}})'
    one_by = f'* on (panel, node_uuid) group_left (node) {one}'
    p.append({'id': _next(), 'type': 'row', 'title': 'Сеть по нодам', 'collapsed': False,
              'gridPos': {'h': 1, 'w': 24, 'x': 0, 'y': y}, 'panels': []})
    small = timeseries('$node', {'h': 7, 'w': 6, 'x': 0, 'y': y + 1}, [
        target(f'sum by (node) ((rwmon_node_network_rx_bytes_per_second{{{F}}} * 8) {one_by})', 'A', 'RX'),
        target(f'sum by (node) ((rwmon_node_network_tx_bytes_per_second{{{F}}} * 8) {one_by})', 'B', 'TX'),
        target(f'sum by (tag) ((rate(rwmon_node_outbound_download_bytes{{tag=~"$outbound", {F}}}[5m]) * 8) '
               f'{one_by})', 'C', '{{tag}}'),
    ], 'bps', fill=20, overrides=[
        by_name('RX', color={'mode': 'fixed', 'fixedColor': GREEN}),
        by_name('TX', color={'mode': 'fixed', 'fixedColor': YELLOW}, custom__transform='negative-Y'),
        by_regex('^(?!RX$|TX$).*', custom__fillOpacity=0, custom__lineStyle={'fill': 'dash', 'dash': [6, 4]}),
    ], desc='Сеть сервера ноды: вверх — принято (RX), вниз — отправлено (TX). Пунктиром — сколько '
            'пришло из выбранных аутбаундов (WARP, Psiphon)')
    small.update({'repeat': 'node', 'repeatDirection': 'h', 'maxPerRow': 4})
    small['options']['tooltip'] = {'mode': 'multi', 'sort': 'none'}
    p.append(small)
    y += 8

    # 6. Нода подробно
    def node_ts(expr, ref, legend='{{node_name}} · {{panel_title}}'):
        return target(f'sum by (panel_title, node_name) (({expr}) {BY_NODE})', ref, legend)
    detail = [
        timeseries('Клиенты', {'h': 8, 'w': 12, 'x': 0, 'y': y + 1},
                   [node_ts(f'rwmon_node_online_users{{{F}}}', 'A')], 'none', legend='table', placement='right'),
        timeseries('Трафик клиентов', {'h': 8, 'w': 12, 'x': 12, 'y': y + 1}, [
            node_ts(f'sum by (panel, node_uuid) (rate(rwmon_node_inbound_download_bytes{{{F}}}[5m])) * 8', 'A',
                    '{{node_name}} · {{panel_title}} к клиентам'),
            node_ts(f'sum by (panel, node_uuid) (rate(rwmon_node_inbound_upload_bytes{{{F}}}[5m])) * 8', 'B',
                    '{{node_name}} · {{panel_title}} ↑ от клиентов'),
        ], 'bps', overrides=negative_tx(), legend='table', placement='right'),
        timeseries('CPU: load average на ядро', {'h': 7, 'w': 12, 'x': 0, 'y': y + 9},
                   [node_ts(f'rwmon_node_cpu_load5{{{F}}}', 'A')], 'percentunit', legend='table',
                   placement='right'),
        timeseries('Память', {'h': 7, 'w': 12, 'x': 12, 'y': y + 9},
                   [node_ts(f'rwmon_node_memory_used_ratio{{{F}}}', 'A')], 'percentunit', legend='table',
                   placement='right'),
    ]
    p.append(row('Нода подробно: $node', y, detail))
    y += 1

    # 7. Проверки хостов
    grids = []
    for i, (c, title) in enumerate(CHECKS):
        grids.append(table(title, {'h': 12, 'w': 8, 'x': 8 * i, 'y': y + 1}, [
            target(f'max by (panel_title, host) ({host_status(c)})', 'A', instant=True, fmt='table'),
        ], [
            {'id': 'groupingToMatrix', 'options': {'columnField': 'panel_title', 'rowField': 'host',
                                                   'valueField': 'Value', 'emptyValue': 'null'}},
            {'id': 'organize', 'options': {'renameByName': {'host\\panel_title': 'Хост'}}},
        ], [
            by_regex('^(?!Хост$).*', custom__cellOptions={'type': 'color-background'},
                     custom__align='center', mappings=OK_MAP, custom__width=110),
        ], desc='Строка — хост, колонка — панель. Одинаковые хосты разных панелей проверяются один раз'
                + ('' if c == 'xray' else '. Лёгкие (LTE) хосты здесь не проверяются'),
            sort=[{'displayName': 'Хост', 'desc': False}]))
    grids.append(history('История сбоев', {'h': 10, 'w': 24, 'x': 0, 'y': y + 13}, ' or '.join(
        f'({host_status(c)}) and on (name) (min by (name) (min_over_time(xray_proxy_status{{check="{c}"}}'
        f'[$__range] @ end())) == 0)' for c, _ in CHECKS), '{{host}} · {{panel_title}} · {{check}}',
        'Только хосты, у которых за выбранный период были сбои'))
    p.append(row('Проверки хостов', y, grids))
    y += 1

    # 8. Проба из РФ
    ru = [
        history('Не открывалось из РФ', {'h': 10, 'w': 24, 'x': 0, 'y': y + 1},
                '(max by (address, probe) (probe_success{kind="tcp"}) * on (address) group_left (hosts) '
                'rwmon_address_info) and on (address, probe) (min by (address, probe) '
                '(min_over_time(probe_success{kind="tcp"}[$__range] @ end())) == 0)',
                '{{hosts}} ({{address}}) · {{probe}}',
                'Адреса хостов, которые хотя бы раз за период не открылись с какой-нибудь пробы в России. '
                'Если сбой на одной пробе — скорее всего, проблема у самой RU-ноды; если на всех — блокировка.'),
        timeseries('Время соединения из РФ', {'h': 8, 'w': 24, 'x': 0, 'y': y + 11}, [
            target('max by (address, probe) (probe_duration_seconds{kind="tcp"}) * on (address) '
                   'group_left (hosts) rwmon_address_info', 'A', '{{hosts}} · {{probe}}'),
        ], 's', legend='table', placement='right', fill=0,
            desc='Сколько занимает установка соединения с проб в России до каждого адреса'),
    ]
    p.append(row('Проба из РФ', y, ru))
    y += 1

    # 9. GeoCheck: кто как видит ноды
    geo_node = f'* on (panel, node_uuid) group_left (node) topk by (panel, node_uuid) (1, rwmon_node_info{{{F}, node=~"$node"}})'

    def geo_matrix(title, pos, groups, mappings, desc):
        return table(title, pos, [
            target(f'max by (node, service, value) (rwmon_geocheck{{group=~"{groups}", {F}}} {geo_node})',
                   'A', instant=True, fmt='table'),
        ], [
            {'id': 'groupingToMatrix', 'options': {'columnField': 'service', 'rowField': 'node',
                                                   'valueField': 'value', 'emptyValue': 'null'}},
            {'id': 'organize', 'options': {'renameByName': {'node\\service': 'Нода'}}},
        ], [
            by_name('Нода', custom__minWidth=140),
            by_regex('^(?!Нода$).*', custom__align='center', custom__width=90,
                     custom__cellOptions={'type': 'color-background', 'mode': 'basic'},
                     color={'mode': 'fixed', 'fixedColor': 'transparent'}, mappings=mappings),
        ], desc=desc, sort=[{'displayName': 'Нода', 'desc': False}])
    bad = [{'type': 'regex', 'options': {'pattern': '^(RU|BY)$', 'result': {'color': 'dark-red', 'index': 0}}}]
    access = [{'type': 'regex', 'options': {'pattern': '^(available|yes|ok).*', 'result': {'color': 'dark-green', 'index': 0}}},
              {'type': 'regex', 'options': {'pattern': '^(blocked|unavailable|no|restricted|denied).*',
                                            'result': {'color': 'dark-red', 'index': 1}}}]
    geo = [
        geo_matrix('Как сервисы видят ноды', {'h': 10, 'w': 24, 'x': 0, 'y': y + 1}, 'services', bad,
                   'Страна, которую определяет каждый сервис (последний GeoCheck). Красным — RU и BY'),
        geo_matrix('Доступ к сервисам', {'h': 10, 'w': 24, 'x': 0, 'y': y + 11}, 'stash', access,
                   'Открывается ли сервис с IP ноды (Netflix, ChatGPT и т.п.) и в каком регионе'),
        geo_matrix('GeoIP-базы и CDN', {'h': 10, 'w': 24, 'x': 0, 'y': y + 21}, 'geoip|cdn', bad,
                   'Что о стране IP ноды записано в базах GeoIP и что видят CDN'),
        table('IP нод', {'h': 10, 'w': 24, 'x': 0, 'y': y + 31}, [
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
            by_name('риск', custom__width=70, custom__cellOptions={'type': 'color-text'},
                    thresholds={'mode': 'absolute', 'steps': [{'color': 'text', 'value': None},
                                                              {'color': YELLOW, 'value': 30},
                                                              {'color': RED, 'value': 60}]}),
            by_name('проверено', unit='dtdurations', decimals=0, custom__width=110,
                    color={'mode': 'fixed', 'fixedColor': GREY}, custom__cellOptions={'type': 'color-text'}),
        ], desc='IP, сеть и тип IP по последнему GeoCheck. Риск — оценка репутации IP (0–100)',
            sort=[{'displayName': 'Нода', 'desc': False}]),
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
