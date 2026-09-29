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
        if remark in wanted and link not in links:
            links.append(link)
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
    user = rw.user_by_username(cfg.monitor_username)
    raw = rw.raw_subscription(user['shortUuid'])
    keys = rw.connection_keys(user['id'])
    links, names, missing = select_links(raw.get('resolvedProxyConfigs') or [], keys,
                                         cfg.monitor_host_tag)
    if missing:
        log('links', 'не нашёл ссылку для хостов: ' + ', '.join(missing))
    if not links:
        log('links', f'у пользователя «{cfg.monitor_username}» нет хостов с тегом '
                     f'{cfg.monitor_host_tag} — проверять нечего')
    if write_if_changed(cfg.links_file, '\n'.join(links) + '\n'):
        log('links', f'список обновлён: {len(links)} хостов — ' + ', '.join(names))
    return names
