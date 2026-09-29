"""Список хостов для xray-checker.

У каждой панели берём подписку служебного пользователя и оставляем только
хосты с тегами host_tag (все три проверки) и host_tag_lite (только «Xray жив»).
К названиям хостов добавляется host_suffix панели, чтобы одинаковые хосты
разных панелей не смешались. Результат — два файла со ссылками, их читают
контейнеры xray-checker.
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


def rename(link, suffix):
    """Дописать к названию хоста в ссылке подпись панели."""
    if not suffix:
        return link
    if link.startswith('vmess://'):
        try:
            payload = link[8:] + '=' * (-len(link[8:]) % 4)
            data = json.loads(base64.b64decode(payload))
            data['ps'] = data.get('ps', '') + suffix
            return 'vmess://' + base64.b64encode(json.dumps(data, ensure_ascii=False).encode()).decode()
        except ValueError:
            return link
    base, _, remark = link.partition('#')
    return base + '#' + urllib.parse.quote(urllib.parse.unquote(remark) + suffix, safe='')


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


def panel_links(rw, panel):
    """Ссылки одной панели: (полные, лёгкие, названия, лёгкие названия)."""
    user = rw.user_by_username(panel.monitor_user)
    raw = rw.raw_subscription(user['shortUuid'])
    keys = rw.connection_keys(user['id'])
    configs = raw.get('resolvedProxyConfigs') or []
    full, names, missing = select_links(configs, keys, panel.host_tag)
    lite, lite_names, lite_missing = select_links(configs, keys, panel.host_tag_lite)
    lite = [x for x in lite if x not in full]
    lite_names = [n for n in lite_names if n not in names]
    if missing or lite_missing:
        log('links', f'[{panel.title}] не нашёл ссылку для хостов: ' + ', '.join(missing + lite_missing))
    if not full and not lite:
        log('links', f'[{panel.title}] у пользователя «{panel.monitor_user}» нет хостов с тегами '
                     f'{panel.host_tag} / {panel.host_tag_lite}')
    sfx = panel.host_suffix
    return ([rename(x, sfx) for x in full], [rename(x, sfx) for x in lite],
            [n + sfx for n in names], [n + sfx for n in lite_names])


def refresh(cfg, clients):
    """Обновить файлы ссылок по всем панелям. Если панель не ответила —
    её хосты берём из прошлого удачного списка, чтобы проверки не пропали."""
    folder = os.path.dirname(cfg.links_file) or '.'
    full_all, lite_all, report = [], [], []
    for p in cfg.panels:
        cache = os.path.join(folder, f'.panel-{p.id}.json')
        try:
            full, lite, names, lite_names = panel_links(clients[p.id], p)
            write_if_changed(cache, json.dumps([full, lite, names, lite_names], ensure_ascii=False))
        except Exception as e:
            log('links', f'[{p.title}] список хостов не обновлён: {e}')
            try:
                with open(cache, encoding='utf-8') as f:
                    full, lite, names, lite_names = json.load(f)
            except (OSError, ValueError):
                full, lite, names, lite_names = [], [], [], []
        full_all += full
        lite_all += lite
        report.append((p, names, lite_names))
    changed = write_if_changed(cfg.links_file, '\n'.join(full_all) + '\n')
    changed |= write_if_changed(cfg.links_file_xray, '\n'.join(full_all + lite_all) + '\n')
    if changed:
        log('links', 'список обновлён: ' + '; '.join(
            f'{p.title} — {len(n)} полных + {len(ln)} лёгких' for p, n, ln in report))
    return report
