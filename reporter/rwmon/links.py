"""Список хостов для xray-checker.

Берём подписку служебного пользователя и оставляем в ней только хосты
с тегом MONITOR_HOST_TAG. Результат — обычный файл со ссылками vless://…,
его читают три контейнера xray-checker.
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


def select_links(raw_configs, keys, tag):
    """raw_configs — resolvedProxyConfigs из /raw, keys — ответ connection-keys.
    Возвращает (ссылки, названия, названия без найденной ссылки)."""
    wanted = {}
    for c in raw_configs:
        meta = c.get('metadata') or {}
        if tag in (meta.get('tags') or []) and not meta.get('isDisabled'):
            for name in (c.get('finalRemark'), meta.get('remark')):
                if name:
                    wanted[name] = meta.get('remark') or name

    links, found = [], set()
    for link in (keys.get('enabledKeys') or []) + (keys.get('hiddenKeys') or []):
        remark = link_remark(link)
        if remark in wanted and fix_link(link) not in links:
            links.append(fix_link(link))
            found.add(wanted[remark])
    missing = sorted(set(wanted.values()) - found)
    return links, sorted(found), missing


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


def refresh(rw, cfg):
    """Пишет два файла:
    monitor.txt      — хосты с тегом MONITORING: все три проверки (Xray, WARP, Psiphon);
    monitor-xray.txt — они же плюс хосты с тегом MONITORING_LITE: только «Xray жив».
    LITE — для хостов с лимитом трафика (LTE, цепочки через CDN): одна лёгкая проверка."""
    user = rw.user_by_username(cfg.monitor_username)
    raw = rw.raw_subscription(user['shortUuid'])
    keys = rw.connection_keys(user['id'])
    configs = raw.get('resolvedProxyConfigs') or []
    full, names, missing = select_links(configs, keys, cfg.monitor_host_tag)
    lite, lite_names, lite_missing = select_links(configs, keys, cfg.monitor_host_tag_lite)
    lite = [x for x in lite if x not in full]
    lite_names = [n for n in lite_names if n not in names]
    if missing or lite_missing:
        log('links', 'не нашёл ссылку для хостов: ' + ', '.join(missing + lite_missing))
    if not full and not lite:
        log('links', f'у пользователя «{cfg.monitor_username}» нет хостов с тегами '
                     f'{cfg.monitor_host_tag} / {cfg.monitor_host_tag_lite} — проверять нечего')
    changed = write_if_changed(cfg.links_file, '\n'.join(full) + '\n')
    changed |= write_if_changed(cfg.links_file_xray, '\n'.join(full + lite) + '\n')
    if changed:
        log('links', f'список обновлён: {len(full)} полных + {len(lite)} лёгких — '
                     + ', '.join(names + [f'{n} (лёгкая)' for n in lite_names]))
    return names + [f'{n} (только Xray)' for n in lite_names]
