"""Список хостов для xray-checker.

У каждой панели берём подписку служебного пользователя в формате Xray JSON
(как её получают приложения, вместе с мапперами хостов) и оставляем только
хосты с тегами host_tag (все три проверки) и host_tag_lite (только «Подключение»).
Тег-исключение (host_tag_no_warp / host_tag_no_psiphon) рядом с host_tag убирает
проверку, которой на этой ноде нечего проверять: например, на ноде нет Psiphon.
Теги и названия хостов берём из /raw, сами настройки подключения — из JSON.

Если в двух панелях один и тот же хост (тот же сервер, порт и способ
подключения — так бывает, когда панели делят ноды через маппер UUID; UUID, fp,
sni и название при этом могут отличаться), он проверяется один раз,
а результат засчитывается обеим панелям. Какой хост какой панели чем проверяется,
reporter отдаёт в Prometheus метрикой rwmon_host — по ней алерты и дашборд
понимают, к какой панели относится проверка.

Результат — файлы со списком конфигов Xray JSON (по одному outbound на
проверку, название — в remarks), по файлу на каждую проверку; их читают
контейнеры xray-checker.

Кто что проверяет (3.0):
  - из РФ — пробы (probe/): каждый хост как в подписке, как телефон в России. Список
    им отдаёт reporter (feed.py), файл ru-hosts.json. Хосты, которые ведут на сам
    сервер пробы (МСК-ноды), из РФ не проверяются — их проверяет сервер мониторинга;
  - с сервера мониторинга «на ноду» (проверка xray) — на ноду напрямую, в обход входа,
    если вход хоста — не сама нода (прокладка, CDN): жив ли сервер;
  - с сервера мониторинга «через вход» (проверка entry) — у тех же хостов по адресу
    из подписки: работает ли вход (прокладка, CDN), если смотреть не из РФ.
"""
import copy
import ipaddress
import json
import os
import tempfile

from .util import log, resolve_ip

# Аутбаунды, которые не ведут на сервер: прямой выход, блок, DNS
SERVICE_PROTOCOLS = ('freedom', 'blackhole', 'dns', 'loopback')


def proxy_outbound(config):
    """Аутбаунд хоста из конфига подписки: панель ставит его с тегом proxy,
    остальные (direct, block) — из шаблона. Если тега нет — первый «настоящий»."""
    outbounds = [o for o in (config.get('outbounds') or []) if isinstance(o, dict)]
    for o in outbounds:
        if o.get('tag') == 'proxy':
            return o
    for o in outbounds:
        if o.get('protocol') and o.get('protocol') not in SERVICE_PROTOCOLS:
            return o
    return None


def server_of(outbound):
    """(адрес, порт) сервера из аутбаунда: vnext у VLESS/VMess, servers у
    Trojan/Shadowsocks, address/port прямо в settings у Hysteria."""
    s = outbound.get('settings') or {}
    for key in ('vnext', 'servers'):
        items = s.get(key)
        if isinstance(items, list) and items and isinstance(items[0], dict):
            return str(items[0].get('address', '')), items[0].get('port') or ''
    return str(s.get('address', '')), s.get('port') or ''


def fix_outbound(outbound):
    """Hysteria2 работает только поверх HTTP/3. Если панель не указала alpn,
    Xray предлагает серверу h2/http1.1, и сервер рвёт соединение (EOF).
    Клиентские приложения подставляют h3 сами — мы делаем то же самое."""
    ob = copy.deepcopy(outbound)
    ss = ob.get('streamSettings') or {}
    if ob.get('protocol') == 'hysteria' or ss.get('network') == 'hysteria':
        if ss.get('security', 'tls') == 'tls':
            tls = ss.setdefault('tlsSettings', {})
            if not tls.get('alpn'):
                tls['alpn'] = ['h3']
            ob['streamSettings'] = ss
    return ob


def _transport(ss):
    """Путь, хост и режим транспорта — то, что определяет, куда идёт подключение."""
    net = ss.get('network') or 'tcp'
    t = ss.get(f'{net}Settings') or {}
    if net in ('tcp', 'raw'):
        header = (t.get('header') or {})
        return {'header': header.get('type', '')}
    if net == 'grpc':
        return {'serviceName': t.get('serviceName', '')}
    keep = {k: t.get(k) for k in ('path', 'host', 'mode') if t.get(k)}
    headers = t.get('headers') or {}
    if not keep.get('host') and headers.get('Host'):
        keep['host'] = headers['Host']
    return keep


def connection_key(outbound):
    """Ключ хоста: протокол, адрес, порт и основные параметры подключения
    (транспорт, путь, ключ Reality…). UUID/пароль не учитываются: у служебных
    пользователей разных панелей они свои, а нода и её WARP/Psiphon от этого
    работают одинаково. Название, отпечаток браузера (fp), SNI и shortId тоже
    не учитываются."""
    host, port = server_of(outbound)
    ss = outbound.get('streamSettings') or {}
    key = {
        'protocol': outbound.get('protocol', ''),
        'server': f'{host}:{port}',
        'network': ss.get('network') or 'tcp',
        'security': ss.get('security') or 'none',
        'pbk': (ss.get('realitySettings') or {}).get('publicKey', ''),
        'transport': _transport(ss),
    }
    vnext = (outbound.get('settings') or {}).get('vnext') or []
    if vnext and isinstance(vnext[0], dict) and vnext[0].get('users'):
        user = vnext[0]['users'][0] or {}
        key['flow'] = user.get('flow', '')
        key['encryption'] = user.get('encryption', '')
    return json.dumps(key, sort_keys=True, ensure_ascii=False)


# Протоколы и транспорты поверх UDP: TCP-пробой их не проверить (порт не
# принимает TCP — проба покажет «не открывается», хотя всё работает), поэтому
# в пробы из РФ не берём.
UDP_PROTOCOLS = ('hysteria', 'hysteria2', 'tuic', 'wireguard')
UDP_NETWORKS = ('hysteria', 'kcp', 'mkcp', 'quic')


def is_udp(outbound):
    ss = outbound.get('streamSettings') or {}
    return outbound.get('protocol') in UDP_PROTOCOLS or ss.get('network') in UDP_NETWORKS


def outbound_address(outbound):
    """Адрес хоста «сервер:порт» — так же его показывает xray-checker."""
    host, port = server_of(outbound)
    if not host:
        return ''
    if ':' in host and not host.startswith('['):
        host = f'[{host}]'                     # IPv6
    return f'{host}:{port or 443}'


def set_server(outbound, host, port):
    """Копия аутбаунда с другим адресом и портом сервера."""
    ob = copy.deepcopy(outbound)
    s = ob.setdefault('settings', {})
    for key in ('vnext', 'servers'):
        items = s.get(key)
        if isinstance(items, list) and items and isinstance(items[0], dict):
            items[0]['address'], items[0]['port'] = host, port
            return ob
    s['address'], s['port'] = host, port
    return ob


def _uuid(x):
    return str(x.get('uuid') or x.get('nodeUuid') or '') if isinstance(x, dict) else str(x or '')


def node_targets(rw, names, state):
    """Куда хосты ведут на самом деле: {название: (IP ноды, порт inbound)}. Только хосты
    с одной нодой и inbound с TLS/Reality: inbound без шифрования стоит за обратным
    прокси (nginx/CDN), напрямую к нему не подключиться."""
    try:
        hosts, nodes, profiles = rw.hosts(), rw.nodes() or [], rw.config_profiles()
    except Exception as e:
        panel = getattr(rw, 'panel', None)
        key = f'hosts-api:{getattr(panel, "id", "")}'
        if state.get(key) != str(e):
            state[key] = str(e)
            log('links', f'[{getattr(panel, "title", "?")}] хосты/ноды/профили не получены ({e}) — хосты за '
                         'прокладкой и CDN проверяются только через вход. Дайте токену право читать хосты '
                         'и конфиг-профили.')
        return {}
    ips = {_uuid(n): resolve_ip(str(n.get('address') or ''), state) for n in nodes if isinstance(n, dict)}
    inbounds = {_uuid(ib): ib for pr in profiles if isinstance(pr, dict)
                for ib in (pr.get('inbounds') or []) if isinstance(ib, dict)}
    out = {}
    for h in hosts:
        if not isinstance(h, dict) or h.get('remark') not in names:
            continue
        ids = [_uuid(n) for n in (h.get('nodes') or [])]
        ib = inbounds.get(str((h.get('inbound') or {}).get('configProfileInboundUuid') or ''))
        if len(ids) != 1 or not ib or (ib.get('security') or 'none') == 'none':
            continue
        ip, port = ips.get(ids[0]), ib.get('port')
        if ip and port:
            out[h['remark']] = (ip, int(port))
    return out


def check_config(name, outbound):
    """Конфиг для xray-checker: одна проверка — один аутбаунд, название в remarks."""
    ob = dict(outbound)
    ob['tag'] = 'proxy'
    return {'remarks': name, 'outbounds': [ob]}


def select_hosts(raw_configs, json_configs, tag):
    """raw_configs — resolvedProxyConfigs из /raw (теги и названия хостов),
    json_configs — подписка в формате Xray JSON.
    Возвращает ([(аутбаунд, название)], названия, которых нет в JSON)."""
    wanted = {}
    for c in raw_configs:
        meta = c.get('metadata') or {}
        if tag in (meta.get('tags') or []) and not meta.get('isDisabled'):
            for name in (c.get('finalRemark'), meta.get('remark')):
                if name:
                    wanted[name] = meta.get('remark') or name

    pairs, seen = [], set()
    for config in json_configs:
        if not isinstance(config, dict):
            continue
        remark = config.get('remarks') or ''
        if remark not in wanted:
            continue
        ob = proxy_outbound(config)
        if ob is None:
            continue
        ob = fix_outbound(ob)
        key = json.dumps(ob, sort_keys=True)
        if key not in seen:
            seen.add(key)
            pairs.append((ob, wanted[remark]))
    missing = sorted(set(wanted.values()) - {n for _, n in pairs})
    return pairs, missing


def host_skips(raw_configs, skip_tags):
    """Какие проверки пропустить у хоста: {название: [проверки]}.
    skip_tags — {тег-исключение: проверка}, см. Panel.skip_tags()."""
    skips = {}
    for c in raw_configs:
        meta = c.get('metadata') or {}
        tags = meta.get('tags') or []
        skip = sorted({check for tag, check in skip_tags.items() if tag and tag in tags})
        if skip:
            for name in (c.get('finalRemark'), meta.get('remark')):
                if name:
                    skips[meta.get('remark') or name] = skip
    return skips


def write_if_changed(path, text):
    try:
        with open(path, encoding='utf-8') as f:
            if f.read() == text:
                return False
    except FileNotFoundError:
        pass
    folder = os.path.dirname(path) or '.'
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix='.tmp-')
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(text)
    os.chmod(tmp, 0o644)       # xray-checker работает под другим пользователем
    os.replace(tmp, path)
    return True


def panel_links(rw, panel, route_checks=(), bypass=False, state=None):
    """Хосты одной панели: [{'outbound', 'host', 'lite', 'skip'}] — полные, потом лёгкие.
    skip — проверки маршрутов, которые у полного хоста отключены тегом-исключением."""
    user = rw.user_by_username(panel.monitor_user)
    raw = rw.raw_subscription(user['shortUuid'])
    configs = raw.get('resolvedProxyConfigs') or []
    sub = rw.json_subscription(user['shortUuid'])
    full, missing = select_hosts(configs, sub, panel.host_tag)
    lite, lite_missing = select_hosts(configs, sub, panel.host_tag_lite)
    full_keys = {connection_key(ob) for ob, _ in full}
    lite = [(ob, name) for ob, name in lite if connection_key(ob) not in full_keys]
    if missing or lite_missing:
        log('links', f'[{panel.title}] этих хостов нет в JSON-подписке (скрыты или исключены '
                     'из типа «Xray JSON»): ' + ', '.join(missing + lite_missing))
    if not full and not lite:
        hint = ''
        if missing or lite_missing:
            # хосты с тегами есть, но в JSON-подписке ни одного: вместо серверов
            # панель отдала заглушки («лимит устройств», «подписка отключена»…)
            hint = (' в JSON-подписке — проверьте, что пользователь активен и у него '
                    'не исчерпан лимит устройств (HWID)')
        log('links', f'[{panel.title}] у пользователя «{panel.monitor_user}» нет хостов с тегами '
                     f'{panel.host_tag} / {panel.host_tag_lite}' + hint)
    skips = host_skips(configs, panel.skip_tags(route_checks))
    entries = ([{'outbound': ob, 'host': name, 'lite': False, 'skip': skips.get(name, [])} for ob, name in full] +
               [{'outbound': ob, 'host': name, 'lite': True, 'skip': []} for ob, name in lite])
    if bypass:
        state = {} if state is None else state
        targets = node_targets(rw, {e['host'] for e in entries}, state)
        for e in entries:
            t = targets.get(e['host'])
            server = outbound_address(e['outbound']).rsplit(':', 1)[0].strip('[]')
            e['server_ip'] = resolve_ip(server, state) if server else ''
            if t:
                e['node_ip'] = t[0]
            if t and e['server_ip'] != t[0]:
                e['direct'] = set_server(e['outbound'], *t)
    return entries


# Какие хосты каких панелей чем проверяются: [{panel, panel_title, host, name, lite, checks}].
# checks — какие проверки маршрутов ([[check]]) нужны этому хосту в этой панели.
# name — название в проверке (метка name у xray_proxy_status). Читает exporter.
HOSTS = []
DOMAINS = []       # домены, на которые ходят клиенты: адреса и SNI хостов (для проверки блокировок РФ)


def node_map(cfg, clients, state, need_profiles=True):
    """Ноды всех панелей: [{'panel', 'name', 'ip', 'profiles'}], profiles — UUID и имя
    конфиг-профиля ноды. По ним проверки маршрутов выбирают хосты (profiles = [...])."""
    nodes = []
    for p in cfg.panels:
        rw = clients.get(p.id)
        if rw is None:
            continue
        try:
            raw = rw.nodes() or []
        except Exception as e:
            log('links', f'[{p.title}] список нод не получен: {e}')
            continue
        names = {}
        if need_profiles:
            try:
                names = {str(x.get('uuid')): str(x.get('name') or '') for x in rw.config_profiles()}
            except Exception as e:
                key = f'profiles:{p.id}'
                if state.get(key) != str(e):
                    state[key] = str(e)
                    log('links', f'[{p.title}] имена конфиг-профилей не получены ({e}) — проверки с profiles '
                                 'увидят только UUID профилей. Дайте токену право читать конфиг-профили.')
        for n in raw:
            if not isinstance(n, dict):
                continue
            uuid = str(n.get('configProfileUuid') or (n.get('configProfile') or {}).get('activeConfigProfileUuid') or '')
            nodes.append({'panel': p.id, 'name': str(n.get('name') or ''),
                          'ip': resolve_ip(str(n.get('address') or ''), state),
                          'profiles': sorted({v for v in (uuid, names.get(uuid, '')) if v})})
    return nodes


def exit_node(p, e, nodes, state):
    """Нода, куда ведёт хост: по host_exit панели (название ноды, можно с « · панель»),
    иначе по IP адреса хоста. Не нашлась — None."""
    target = p.host_exit.get(e['host'])
    if target:
        for n in sorted(nodes, key=lambda n: n['panel'] != p.id):
            if target in (n['name'], f"{n['name']} · {p.title}") or target.startswith(n['name'] + ' · '):
                return n
        return None
    server = outbound_address(e['outbound']).rsplit(':', 1)[0].strip('[]')
    ip = resolve_ip(server, state) if server else ''
    if not ip:
        return None
    return next((n for n in sorted(nodes, key=lambda n: n['panel'] != p.id) if n['ip'] == ip), None)


def entry_checks(e, p=None, route_checks=(), nodes=(), state=None):
    """Какие проверки маршрутов нужны записи хоста: только полным хостам, без тега-исключения,
    и если проверка подходит хосту по названию или по профилю его ноды."""
    if e.get('lite'):
        return set()
    skip = set(e.get('skip') or [])
    out = set()
    for c in route_checks:
        if c.id in skip:
            continue
        names = []
        if c.profiles and p is not None:
            n = exit_node(p, e, nodes, {} if state is None else state)
            names = n['profiles'] if n else []
        if c.applies(e['host'], names):
            out.add(c.id)
    return out


def combine(per_panel, route_checks=(), nodes=(), state=None):
    """Склеить хосты всех панелей. Одинаковый хост (см. connection_key)
    проверяется один раз, а результат относится ко всем панелям, где он есть.
    Проверки маршрутов у общего хоста — объединение того, что нужно панелям:
    если одной панели Psiphon на этом хосте нужен, он проверяется.
    per_panel — [(panel, entries)]. Возвращает (проверки, хосты)."""
    state = {} if state is None else state
    checks, hosts, used = {}, [], set()
    for p, entries in per_panel:
        for e in entries:
            key = connection_key(e['outbound'])
            c = checks.get(key)
            if c is None:
                name = e['host'] + p.host_suffix
                base, n = name, 2
                while name in used:                  # разные хосты с одним названием
                    name, n = f'{base} #{n}', n + 1
                used.add(name)
                # «на ноду» с сервера мониторинга — напрямую, если вход не она
                c = checks[key] = {'name': name, 'config': check_config(name, e.get('direct') or e['outbound']),
                                   'outbound': e['outbound'], 'lite': e['lite'],
                                   'address': outbound_address(e['outbound']),
                                   'entry': bool(e.get('direct')),
                                   'ips': {ip for ip in (e.get('server_ip'), e.get('node_ip')) if ip},
                                   'udp': is_udp(e['outbound']), 'checks': set(), 'hosts': set()}
            elif not e['lite']:
                c['lite'] = False                    # полная проверка покрывает лёгкую
            c['hosts'].add(e['host'])              # названия хоста во всех панелях
            mine = entry_checks(e, p, route_checks, nodes, state)
            c['checks'] |= mine
            hosts.append({'panel': p.id, 'panel_title': p.title, 'host': e['host'],
                          'name': c['name'], 'lite': e['lite'], 'address': c['address'],
                          'entry': c['entry'], 'checks': sorted(mine)})
    return list(checks.values()), hosts


def client_domains(per_panel):
    """Домены из адресов и SNI хостов всех панелей — без IP, по алфавиту."""
    out = set()
    for _, entries in per_panel:
        for e in entries:
            ob = e['outbound']
            ss = ob.get('streamSettings') or {}
            sec = ss.get('realitySettings') or ss.get('tlsSettings') or {}
            for name in (outbound_address(ob).rsplit(':', 1)[0].strip('[]'), sec.get('serverName')):
                name = str(name or '').strip().lower().rstrip('.')
                if name and not _is_ip(name) and '.' in name:
                    out.add(name)
    return sorted(out)


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def check_links_file(cfg, check):
    """Список хостов для проверки маршрута: /links/monitor-<id проверки>.txt."""
    folder = os.path.dirname(cfg.links_file) or '.'
    return os.path.join(folder, f'monitor-{check}.txt')


# Заглушка вместо пустого списка: xray-checker с пустым списком не запускается.
# Имени нет в rwmon_host, поэтому ни в алерты, ни в дашборд заглушка не попадает.
EMPTY_NAME = 'rwmon-empty'
EMPTY = [{'remarks': EMPTY_NAME, 'outbounds': [{'tag': 'proxy', 'protocol': 'vless', 'settings': {'vnext': [
    {'address': '127.0.0.1', 'port': 9, 'users': [{'id': '00000000-0000-0000-0000-000000000000',
                                                  'encryption': 'none'}]}]}}]}]


def dump(configs):
    return json.dumps(configs or EMPTY, ensure_ascii=False, indent=1) + '\n'


def ru_file(cfg):
    """Список хостов для проб из РФ — его отдаёт reporter (feed.py)."""
    return os.path.join(os.path.dirname(cfg.links_file) or '.', 'ru-hosts.json')


def checked_from_ru(check, probe_ips):
    """Хост проверяется из РФ, если не ведёт на сервер одной из проб: МСК-ноду
    проверять с неё самой бессмысленно — её проверяет сервер мониторинга."""
    return not (check.get('ips', set()) & probe_ips)


def write_probe_targets(cfg, checks):
    """Сайты для проб из РФ (Prometheus file_sd, blackbox exporter)."""
    folder = os.path.dirname(cfg.links_file) or '.'
    write_if_changed(os.path.join(folder, 'probe-http.json'), json.dumps(
        [{'targets': [s.url], 'labels': {'site': s.name, 'module': 'http_any' if s.any_status else 'http_2xx'}}
         for s in cfg.sites], ensure_ascii=False))


def refresh(cfg, clients, state=None):
    """Обновить списки проверок по всем панелям. Если панель не ответила —
    её хосты берём из прошлого удачного списка, чтобы проверки не пропали."""
    global HOSTS, DOMAINS
    state = {} if state is None else state
    folder = os.path.dirname(cfg.links_file) or '.'
    per_panel = []
    for p in cfg.panels:
        cache = os.path.join(folder, f'.panel-{p.id}.json')
        try:
            entries = panel_links(clients[p.id], p, cfg.route_checks, bypass=True, state=state)
            write_if_changed(cache, json.dumps(entries, ensure_ascii=False))
        except Exception as e:
            log('links', f'[{p.title}] список хостов не обновлён: {e}')
            try:
                with open(cache, encoding='utf-8') as f:
                    entries = json.load(f)
                if not isinstance(entries, list) or any(
                        not isinstance(e, dict) or not isinstance(e.get('outbound'), dict) for e in entries):
                    entries = []                     # кэш старого формата (со ссылками)
            except (OSError, ValueError):
                entries = []
        per_panel.append((p, entries))
    need_nodes = any(c.profiles for c in cfg.route_checks)
    nodes = node_map(cfg, clients, state) if need_nodes else []
    checks, HOSTS = combine(per_panel, cfg.route_checks, nodes, state)
    DOMAINS = client_domains(per_panel)
    full = [c['config'] for c in checks if not c['lite']]
    lite = [c['config'] for c in checks if c['lite']]
    # monitor.txt — прежний общий список полных хостов: его читают проверки, пока после
    # обновления не выполнен ./apply.sh (тот переключает их на свои списки ниже)
    changed = write_if_changed(cfg.links_file, dump(full))
    changed |= write_if_changed(cfg.links_file_xray, dump(full + lite))
    for rc in cfg.route_checks:                  # проверки маршрутов — только хосты, которым они нужны
        changed |= write_if_changed(check_links_file(cfg, rc.id),
                                    dump([c['config'] for c in checks if rc.id in c['checks']]))
    # «через вход» с сервера мониторинга — только у хостов, чей вход не сама нода
    changed |= write_if_changed(check_links_file(cfg, 'entry'),
                                dump([check_config(c['name'], c['outbound']) for c in checks if c['entry']]))
    # из РФ — все хосты как в подписке, кроме тех, что ведут на сами пробы
    probe_ips = {resolve_ip(p.host, state) or p.host for p in cfg.probes}
    ru = {c['name'] for c in checks if checked_from_ru(c, probe_ips)}
    for h in HOSTS:
        h['ru'] = bool(cfg.probes) and h['name'] in ru
    if cfg.probes:
        changed |= write_if_changed(ru_file(cfg), dump([check_config(c['name'], c['outbound'])
                                                         for c in checks if c['name'] in ru]))
    write_probe_targets(cfg, checks)
    if changed:
        shared = len(HOSTS) - len(checks)
        log('links', f'список обновлён: {len(full)} полных + {len(lite)} лёгких проверок'
                     + (f', одинаковых хостов в разных панелях: {shared}' if shared else ''))
    return per_panel, checks
