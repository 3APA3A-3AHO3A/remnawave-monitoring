"""Список хостов для xray-checker.

У каждой панели берём подписку служебного пользователя и оставляем только
хосты с тегами host_tag (все три проверки) и host_tag_lite (только «Подключение»).

Если в двух панелях один и тот же хост (тот же сервер, порт, пользователь и
способ подключения — так бывает, когда панели делят ноды через маппер UUID;
fp, sni и название при этом могут отличаться), он проверяется один раз,
а результат засчитывается обеим панелям. Какой хост какой панели чем проверяется,
reporter отдаёт в Prometheus метрикой rwmon_host — по ней алерты и дашборд
понимают, к какой панели относится проверка.

Результат — два файла со ссылками, их читают контейнеры xray-checker.
"""
import base64
import json
import os
import tempfile
import urllib.parse

from .util import log


def link_remark(link):
    """Название хоста из ссылки: для vmess — поле ps, для остальных — часть после #."""
    if link.startswith('vmess://'):
        try:
            payload = link[8:]
            payload += '=' * (-len(payload) % 4)
            return json.loads(base64.b64decode(payload)).get('ps', '')
        except ValueError:
            return ''
    if '#' in link:
        return urllib.parse.unquote(link.rsplit('#', 1)[1])
    return ''


def fix_link(link):
    """Hysteria2 работает только поверх HTTP/3, но панель не пишет alpn в ссылку.
    Xray без alpn предлагает серверу h2/http1.1, и сервер рвёт соединение (EOF).
    Клиентские приложения подставляют h3 сами — мы делаем то же самое."""
    if link.startswith(('hysteria2://', 'hy2://')):
        base, sep, remark = link.partition('#')
        if 'alpn=' not in base:
            base += ('&' if '?' in base else '?') + 'alpn=h3'
        return base + sep + remark
    return link


def set_remark(link, name):
    """Поставить хосту в ссылке новое название (для vmess — поле ps)."""
    if link.startswith('vmess://'):
        try:
            payload = link[8:] + '=' * (-len(link[8:]) % 4)
            data = json.loads(base64.b64decode(payload))
            data['ps'] = name
            return 'vmess://' + base64.b64encode(json.dumps(data, ensure_ascii=False).encode()).decode()
        except ValueError:
            return link
    return link.partition('#')[0] + '#' + urllib.parse.quote(name, safe='')


def rename(link, suffix):
    """Дописать к названию хоста в ссылке подпись панели."""
    return set_remark(link, link_remark(link) + suffix) if suffix else link


# Параметры ссылки, которые определяют, куда и как идёт подключение. Остальные
# (fp, sni, sid, alpn, extra…) у одного и того же хоста в разных панелях могут
# отличаться, но на результат проверки «работает ли нода» не влияют.
KEY_PARAMS = ('type', 'security', 'path', 'serviceName', 'mode', 'flow', 'encryption',
              'headerType', 'host', 'obfs', 'pbk')


def connection_key(link):
    """Ключ хоста: адрес, порт, пользователь и основные параметры подключения.
    У одинаковых хостов разных панелей он совпадает, даже если название,
    отпечаток браузера (fp) или SNI отличаются."""
    if link.startswith('vmess://'):
        try:
            payload = link[8:] + '=' * (-len(link[8:]) % 4)
            data = json.loads(base64.b64decode(payload))
            keep = ('add', 'port', 'id', 'net', 'type', 'path', 'host', 'tls')
            return 'vmess://' + json.dumps({k: str(data.get(k, '')) for k in keep}, sort_keys=True)
        except ValueError:
            return link
    u = urllib.parse.urlsplit(link.partition('#')[0])
    query = urllib.parse.parse_qs(u.query)
    params = '&'.join(f'{k}={query[k][0]}' for k in KEY_PARAMS if k in query)
    return f'{u.scheme}://{u.netloc}{u.path.rstrip("/")}?{params}'


def select_links(raw_configs, keys, tag):
    """raw_configs — resolvedProxyConfigs из /raw, keys — ответ connection-keys.
    Возвращает ([(ссылка, название)], названия без найденной ссылки)."""
    wanted = {}
    for c in raw_configs:
        meta = c.get('metadata') or {}
        if tag in (meta.get('tags') or []) and not meta.get('isDisabled'):
            for name in (c.get('finalRemark'), meta.get('remark')):
                if name:
                    wanted[name] = meta.get('remark') or name

    pairs, seen = [], set()
    for link in (keys.get('enabledKeys') or []) + (keys.get('hiddenKeys') or []):
        remark = link_remark(link)
        if remark in wanted and fix_link(link) not in seen:
            seen.add(fix_link(link))
            pairs.append((fix_link(link), wanted[remark]))
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
    """Хосты одной панели: [{'link', 'host', 'lite'}] — полные, потом лёгкие."""
    user = rw.user_by_username(panel.monitor_user)
    raw = rw.raw_subscription(user['shortUuid'])
    keys = rw.connection_keys(user['id'])
    configs = raw.get('resolvedProxyConfigs') or []
    full, missing = select_links(configs, keys, panel.host_tag)
    lite, lite_missing = select_links(configs, keys, panel.host_tag_lite)
    full_links = {link for link, _ in full}
    lite = [(link, name) for link, name in lite if link not in full_links]
    if missing or lite_missing:
        log('links', f'[{panel.title}] не нашёл ссылку для хостов: ' + ', '.join(missing + lite_missing))
    if not full and not lite:
        log('links', f'[{panel.title}] у пользователя «{panel.monitor_user}» нет хостов с тегами '
                     f'{panel.host_tag} / {panel.host_tag_lite}')
    return ([{'link': link, 'host': name, 'lite': False} for link, name in full] +
            [{'link': link, 'host': name, 'lite': True} for link, name in lite])


# Какие хосты каких панелей чем проверяются: [{panel, panel_title, host, name, lite}].
# name — название в проверке (метка name у xray_proxy_status). Читает exporter.
HOSTS = []


def combine(per_panel):
    """Склеить хосты всех панелей. Одинаковый хост (та же ссылка без названия)
    проверяется один раз, а результат относится ко всем панелям, где он есть.
    per_panel — [(panel, entries)]. Возвращает (проверки, хосты)."""
    checks, hosts, used = {}, [], set()
    for p, entries in per_panel:
        for e in entries:
            key = connection_key(e['link'])
            c = checks.get(key)
            if c is None:
                name = e['host'] + p.host_suffix
                base, n = name, 2
                while name in used:                  # разные хосты с одним названием
                    name, n = f'{base} #{n}', n + 1
                used.add(name)
                c = checks[key] = {'name': name, 'link': set_remark(e['link'], name), 'lite': e['lite']}
            elif not e['lite']:
                c['lite'] = False                    # полная проверка покрывает лёгкую
            hosts.append({'panel': p.id, 'panel_title': p.title, 'host': e['host'],
                          'name': c['name'], 'lite': e['lite']})
    return list(checks.values()), hosts


def refresh(cfg, clients):
    """Обновить файлы ссылок по всем панелям. Если панель не ответила —
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
                if not isinstance(entries, list) or (entries and not isinstance(entries[0], dict)):
                    entries = []                     # кэш старого формата
            except (OSError, ValueError):
                entries = []
        per_panel.append((p, entries))
    checks, HOSTS = combine(per_panel)
    full = [c['link'] for c in checks if not c['lite']]
    lite = [c['link'] for c in checks if c['lite']]
    changed = write_if_changed(cfg.links_file, '\n'.join(full) + '\n')
    changed |= write_if_changed(cfg.links_file_xray, '\n'.join(full + lite) + '\n')
    if changed:
        shared = len(HOSTS) - len(checks)
        log('links', f'список обновлён: {len(full)} полных + {len(lite)} лёгких проверок'
                     + (f', одинаковых хостов в разных панелях: {shared}' if shared else ''))
    return per_panel, checks
