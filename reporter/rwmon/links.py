"""Список хостов для xray-checker.

У каждой панели берём подписку служебного пользователя в формате Xray JSON
(как её получают приложения, вместе с мапперами хостов) и оставляем только
хосты с тегами host_tag (все три проверки) и host_tag_lite (только «Подключение»).
Теги и названия хостов берём из /raw, сами настройки подключения — из JSON.

Если в двух панелях один и тот же хост (тот же сервер, порт и способ
подключения — так бывает, когда панели делят ноды через маппер UUID; UUID, fp,
sni и название при этом могут отличаться), он проверяется один раз,
а результат засчитывается обеим панелям. Какой хост какой панели чем проверяется,
reporter отдаёт в Prometheus метрикой rwmon_host — по ней алерты и дашборд
понимают, к какой панели относится проверка.

Результат — два файла со списком конфигов Xray JSON (по одному outbound на
проверку, название — в remarks), их читают контейнеры xray-checker.
"""
import copy
import json
import os
import tempfile

from .util import log

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


def panel_links(rw, panel):
    """Хосты одной панели: [{'outbound', 'host', 'lite'}] — полные, потом лёгкие."""
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
    return ([{'outbound': ob, 'host': name, 'lite': False} for ob, name in full] +
            [{'outbound': ob, 'host': name, 'lite': True} for ob, name in lite])


# Какие хосты каких панелей чем проверяются: [{panel, panel_title, host, name, lite}].
# name — название в проверке (метка name у xray_proxy_status). Читает exporter.
HOSTS = []


def combine(per_panel):
    """Склеить хосты всех панелей. Одинаковый хост (см. connection_key)
    проверяется один раз, а результат относится ко всем панелям, где он есть.
    per_panel — [(panel, entries)]. Возвращает (проверки, хосты)."""
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
                c = checks[key] = {'name': name, 'config': check_config(name, e['outbound']),
                                   'lite': e['lite'], 'address': outbound_address(e['outbound']),
                                   'udp': is_udp(e['outbound'])}
            elif not e['lite']:
                c['lite'] = False                    # полная проверка покрывает лёгкую
            hosts.append({'panel': p.id, 'panel_title': p.title, 'host': e['host'],
                          'name': c['name'], 'lite': e['lite'], 'address': c['address']})
    return list(checks.values()), hosts


def write_probe_targets(cfg, checks):
    """Списки для проб из РФ (Prometheus file_sd): адреса хостов и сайты."""
    folder = os.path.dirname(cfg.links_file) or '.'
    addresses = sorted({c['address'] for c in checks if c.get('address') and not c.get('udp')})
    write_if_changed(os.path.join(folder, 'probe-tcp.json'),
                     json.dumps([{'targets': addresses, 'labels': {}}], ensure_ascii=False))
    write_if_changed(os.path.join(folder, 'probe-http.json'), json.dumps(
        [{'targets': [s.url], 'labels': {'site': s.name, 'module': 'http_any' if s.any_status else 'http_2xx'}}
         for s in cfg.sites], ensure_ascii=False))


def refresh(cfg, clients):
    """Обновить списки проверок по всем панелям. Если панель не ответила —
    её хосты берём из прошлого удачного списка, чтобы проверки не пропали."""
    global HOSTS
    folder = os.path.dirname(cfg.links_file) or '.'
    per_panel = []
    for p in cfg.panels:
        cache = os.path.join(folder, f'.panel-{p.id}.json')
        try:
            entries = panel_links(clients[p.id], p)
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
    checks, HOSTS = combine(per_panel)
    full = [c['config'] for c in checks if not c['lite']]
    lite = [c['config'] for c in checks if c['lite']]
    dump = lambda configs: json.dumps(configs, ensure_ascii=False, indent=1) + '\n'
    changed = write_if_changed(cfg.links_file, dump(full))
    changed |= write_if_changed(cfg.links_file_xray, dump(full + lite))
    write_probe_targets(cfg, checks)
    if changed:
        shared = len(HOSTS) - len(checks)
        log('links', f'список обновлён: {len(full)} полных + {len(lite)} лёгких проверок'
                     + (f', одинаковых хостов в разных панелях: {shared}' if shared else ''))
    return per_panel, checks
