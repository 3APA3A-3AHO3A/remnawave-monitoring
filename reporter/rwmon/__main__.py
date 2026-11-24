"""rwmon-reporter — мониторинг панелей Remnawave.

  run       — работать постоянно (так запускается контейнер reporter)
  render    — собрать конфиги Prometheus и Grafana из config.toml (контейнер config)
  check     — проверить доступ к панелям, Prometheus и Telegram
  links     — обновить список хостов для проверок прямо сейчас
  geocheck  — прогнать GeoCheck сейчас (--send — сразу отправить сводку)
  report    — собрать ежедневную сводку сейчас (--dry-run — только показать)
  migrate   — напечатать config.toml из старого .env (переход с версии для одной панели)
  migrate-checks — напечатать блоки [[check]] вместо [checks] url_warp / url_psiphon (переход на 2.0)

Пример:  docker compose exec reporter python -m rwmon report --dry-run
"""
import json
import os
import sys
import threading
import time
import urllib.request

from . import config, daily, egress, exporter, geocheck, links
from .clients import Prometheus, Remnawave, Telegram
from .util import log, now, read_json, write_json

TICK = 20            # как часто просыпается планировщик, секунд
RETRY_AFTER = 600    # если задача упала — повторить через 10 минут
PING_EVERY = 300     # отметка для внешнего сторожа (healthcheck)


def due(state, key, hm):
    """Пора ли выполнять ежедневную задачу: время наступило и сегодня её ещё не было."""
    t = now()
    if state.get(key) == t.strftime('%Y-%m-%d'):
        return False
    if time.time() < state.get(key + '_retry', 0):
        return False
    return (t.hour, t.minute) >= hm


def pinger(url):
    """Отметки для внешнего сторожа — в своём потоке, чтобы долгий GeoCheck их не задерживал."""
    while True:
        try:
            urllib.request.urlopen(url, timeout=10).read()
        except Exception as e:
            log('healthcheck', f'не удалось отметиться: {e}')
        time.sleep(PING_EVERY)


def run_forever(cfg):
    metrics = exporter.Exporter(cfg)
    metrics.start()
    clients = metrics.clients
    prom = Prometheus(cfg.prometheus_url)
    state_path = os.path.join(cfg.data_dir, 'state.json')
    state = read_json(state_path, {})
    links_state = {}        # кэш IP нод и сообщений об ошибках списка хостов (в файл не пишется)
    next_links = 0
    if cfg.healthcheck_url:
        threading.Thread(target=pinger, args=(cfg.healthcheck_url,), daemon=True).start()
    log('main', f'запущен для панелей: {", ".join(p.title for p in cfg.panels)}; '
                f'GeoCheck в {cfg.geocheck_time[0]:02d}:{cfg.geocheck_time[1]:02d}, '
                f'сводка в {cfg.report_time[0]:02d}:{cfg.report_time[1]:02d} UTC')

    def task(key, fn):
        try:
            fn()
            state[key] = now().strftime('%Y-%m-%d')
            state.pop(key + '_retry', None)
        except Exception as e:
            log(key, f'ошибка: {e} — повторю через {RETRY_AFTER // 60} мин')
            state[key + '_retry'] = time.time() + RETRY_AFTER
        write_json(state_path, state)

    while True:
        if time.time() >= next_links:
            try:
                links.refresh(cfg, clients, links_state)
            except Exception as e:
                log('links', f'ошибка: {e}')
            try:                                  # базы страны/сети выхода — раз в месяц
                egress.update(cfg, links_state)
            except Exception as e:
                log('geoip', f'ошибка: {e}')
            next_links = time.time() + cfg.links_interval
        if due(state, 'geocheck', cfg.geocheck_time):
            task('geocheck', lambda: geocheck.run(cfg, clients))
        if due(state, 'report', cfg.report_time):
            today = now().strftime('%Y-%m-%d')
            parts = state.setdefault('report_parts', {})
            for day in [d for d in parts if d != today]:
                parts.pop(day)                     # доставленные части прошлых дней не нужны
            task('report', lambda: daily.send(prom, clients, cfg, done=parts.setdefault(today, [])))
        time.sleep(TICK)


def check(cfg):
    ok = True

    def step(title, fn):
        nonlocal ok
        try:
            print(f'  ✓ {title}: {fn()}')
        except Exception as e:
            ok = False
            print(f'  ✗ {title}: {e}')

    prom = Prometheus(cfg.prometheus_url)
    for p in cfg.panels:
        rw = Remnawave(p)
        print(f'{p.title} ({p.id}), {p.api_url}')
        step('ноды', lambda: f'{len(rw.nodes())} шт.')
        step('клиенты и трафик нод (System → Get Nodes Metrics)', lambda: f'{len(rw.nodes_metrics())} нод')
        if p.metrics_url:
            step('точный трафик (metrics_url)',
                 lambda: f'{len(exporter.parse_panel_metrics(rw.raw_metrics()))} счётчиков')
        step('пользователи (System → Get Stats)',
             lambda: f'всего {rw.stats().get("users", {}).get("totalUsers", "?")}')
        step(f'хосты для проверок (пользователь «{p.monitor_user}»)', lambda: _hosts(rw, p, cfg.route_checks))
        step('Telegram-бот', lambda: '@' + Telegram(p.telegram).get_me().get('username', '?'))

    def reporter_metrics():
        states = prom.targets('reporter')
        if not states:
            raise RuntimeError('Prometheus не знает о reporter — перезапустите: ./apply.sh')
        url, health, error = states[0]
        if health == 'up':
            return 'есть'
        if health == 'unknown':
            raise RuntimeError('Prometheus ещё не успел опросить reporter — повторите через минуту')
        raise RuntimeError(f'{url}: {error}')

    if egress.needed(cfg):
        def geoip():
            have = [k for k in egress.KINDS if os.path.exists(egress.path(cfg, k))]
            if len(have) < len(egress.KINDS):
                raise RuntimeError('ещё не скачаны — reporter скачает их сам в течение 10 минут после запуска '
                                   '(нужен доступ к download.db-ip.com)')
            days = (time.time() - min(os.path.getmtime(egress.path(cfg, k)) for k in have)) / 86400
            return f'страна и сеть, обновлены {days:.0f} дн. назад'
        print('Страна и сеть выхода (egress_country / egress_asn)')
        step('базы DB-IP Lite', geoip)

    print('Сервер')
    n = 1 + len(cfg.route_checks)
    step(f'порты проверок 21000–{20999 + 1000 * n}', lambda: ports_check(count=n))

    print('Prometheus')
    step('метрики панелей от reporter', reporter_metrics)
    step('проверки хостов', lambda: f'{len(prom.query("xray_proxy_status"))} результатов '
                                     '(первые появляются через 5–10 минут после запуска)')
    return 0 if ok else 1


def port_ranges(count):
    """Порты Xray проверок: «Подключение» — 21000–21999, каждая проверка маршрута — следующая тысяча
    (см. render.checkers)."""
    return [(21000 + 1000 * k, 21999 + 1000 * k) for k in range(count)]


def _parse_ports(text):
    out = set()
    for part in text.replace(' ', ',').split(','):
        if '-' in part:
            a, b = part.split('-')
            out.update(range(int(a), int(b) + 1))
        elif part.strip():
            out.add(int(part))
    return out


def ports_check(proc='/proc/sys/net/ipv4', count=3):
    """Проверкам нужны порты 21000+, 22000+… на 127.0.0.1 — по тысяче на проверку. Если система раздаёт
    эти же порты исходящим соединениям, проверка однажды не сможет запуститься
    («address already in use») и молча перестанет проверять новые хосты."""
    with open(f'{proc}/ip_local_port_range') as f:
        low, high = map(int, f.read().split())
    try:
        with open(f'{proc}/ip_local_reserved_ports') as f:
            reserved = _parse_ports(f.read().strip())
    except OSError:
        reserved = set()
    ranges = port_ranges(count)
    clash = [f'{a}–{b}' for a, b in ranges
             if a <= high and b >= low and not set(range(a, b + 1)) <= reserved]
    if clash:
        raise RuntimeError(
            f'система раздаёт исходящим соединениям порты {low}–{high}, и среди них порты проверок '
            f'{", ".join(clash)}. Закрепите их: echo "net.ipv4.ip_local_reserved_ports = '
            f'{",".join(f"{a}-{b}" for a, b in ranges)}" | sudo tee /etc/sysctl.d/90-rwmon.conf '
            '&& sudo sysctl -p /etc/sysctl.d/90-rwmon.conf')
    if low > ranges[-1][1] or high < 21000:
        return 'свободны'
    return 'закреплены за проверками'


def _hosts(rw, p, route_checks=()):
    entries = links.panel_links(rw, p, route_checks)
    lite = [e['host'] for e in entries if e['lite']]
    parts = [f'{len(entries) - len(lite)} полных']
    if lite:
        parts.append(f'{len(lite)} лёгких ({", ".join(lite)})')
    for c in route_checks:
        check, title = c.id, c.title
        skipped = [e['host'] for e in entries if not e['lite'] and check in (e.get('skip') or [])]
        if skipped:
            parts.append(f'без {title}: {", ".join(skipped)}')
    return ', '.join(parts)


# ── переход на [[check]] (2.0) ───────────────────────────────

def _toml_list(values):
    return '[' + ', '.join(json.dumps(v, ensure_ascii=False) if isinstance(v, str) else str(v)
                           for v in sorted(values)) + ']'


def migrate_checks(cfg):
    """Блоки [[check]] для текущих настроек: те же проверки, что работают сейчас.
    Вставить в config.toml вместо url_warp / url_psiphon, затем ./apply.sh."""
    out = ['# Проверки маршрутов. Вставьте в config.toml (url_warp и url_psiphon в [checks] после этого',
           '# не нужны) и выполните ./apply.sh. Хосты выбираются по профилю ноды (profiles) или по',
           '# названию (hosts); без них — все полные хосты. Тег skip_tag на хосте снимает с него проверку.']
    tags = {}
    for p in cfg.panels:
        for tag, cid in p.skip_tags(cfg.route_checks).items():
            tags.setdefault(cid, set()).add(tag)
    for c in cfg.route_checks:
        out += ['', '[[check]]', f'id = {_toml_str(c.id)}', f'title = {_toml_str(c.title)}', f'url = {_toml_str(c.url)}']
        if c.egress:
            out.append(f'egress = {_toml_str(c.egress)}' +
                       ('                    # выход не с IP ноды' if c.egress == 'other' else ''))
        if c.egress_country:
            out.append(f'egress_country = {_toml_list(c.egress_country)}')
        if c.egress_asn:
            out.append(f'egress_asn = {_toml_list(c.egress_asn)}')
        if c.profiles:
            out.append(f'profiles = {_toml_list(c.profiles)}')
        if c.hosts:
            out.append(f'hosts = {_toml_list(c.hosts)}')
        tag = sorted(tags.get(c.id) or {c.skip_tag})[0]
        if tag:
            out.append(f'skip_tag = {_toml_str(tag)}')
        if c.alert:
            out.append(f'alert = {_toml_str(c.alert)}')
    return '\n'.join(out)


# ── переход со старого .env ──────────────────────────────────

def _toml_str(v):
    return json.dumps(str(v), ensure_ascii=False)


def migrate(env=os.environ):
    def g(key, default=None):
        """docker run --env-file не снимает кавычки — снимаем сами."""
        v = env.get(key, default)
        if isinstance(v, str) and len(v) >= 2 and v[0] == v[-1] and v[0] in '"\'':
            v = v[1:-1]
        return v
    lst = lambda v: '[' + ', '.join(_toml_str(x.strip()) for x in (v or '').split(',') if x.strip()) + ']'
    tags = [t for t in (g('OUTBOUND_TAGS') or 'psiphon-out|WARP').split('|') if t]
    metrics = '# metrics_url = ""'
    if g('RW_METRICS_PASS'):
        # раньше Prometheus читал /metrics панели напрямую — сохраняем точный трафик
        metrics = (f'metrics_url = {_toml_str("http://127.0.0.1:" + (g("RW_METRICS_PORT") or "3001") + "/metrics")}\n'
                   f'metrics_user = {_toml_str(g("RW_METRICS_USER") or "admin")}\n'
                   f'metrics_password = {_toml_str(g("RW_METRICS_PASS"))}')
    print(f'''# config.toml — перенесено из .env. Проверьте и дополните.

[schedule]
report_time = {_toml_str(g('REPORT_TIME', '15:00'))}
geocheck_time = {_toml_str(g('GEOCHECK_TIME', '14:30'))}

[checks]
interval = {int(g('CHECK_INTERVAL') or 300)}
url_xray = {_toml_str(g('CHECK_URL_XRAY') or 'https://www.google.com/generate_204')}
url_warp = {_toml_str(g('CHECK_URL_WARP') or 'https://icanhazip.com')}
url_psiphon = {_toml_str(g('CHECK_URL_PSIPHON') or 'http://ip-api.com/line/?fields=query')}

[alerts]
clients_drop_min_avg = {g('CLIENTS_DROP_MIN_AVG') or 3}
clients_drop_max_now = {g('CLIENTS_DROP_MAX_NOW') or 1}
outbound_tags = [{', '.join(_toml_str(t) for t in tags)}]

[geocheck]
bad_countries = {lst(g('GEOCHECK_BAD_COUNTRIES') or 'RU,BY')}
attach_images = {str((g('GEOCHECK_ATTACH_IMAGES') or 'true').lower() in ('1', 'true', 'yes')).lower()}

[[panel]]
id = "main"
title = {_toml_str(g('PANEL_NAME') or 'Основная')}
api_url = {_toml_str(g('RW_API_URL') or 'http://127.0.0.1:3000')}
api_token = {_toml_str(g('RW_API_TOKEN', ''))}
monitor_user = {_toml_str(g('MONITOR_USERNAME') or 'monitoring')}
host_tag = {_toml_str(g('MONITOR_HOST_TAG') or 'MONITORING')}
host_tag_lite = {_toml_str(g('MONITOR_HOST_TAG_LITE') or 'MONITORING_LITE')}
exclude_nodes = []                # например ["Panel"] — ноды, за которыми не следить
geocheck_exclude = {lst(g('GEOCHECK_EXCLUDE'))}
{metrics}
[panel.telegram]
bot_token = {_toml_str(g('TG_BOT_TOKEN', ''))}
chat_id = {_toml_str(g('TG_CHAT_ID', ''))}
topic_id = {_toml_str(g('TG_TOPIC_ID', ''))}

# Вторая панель — раскомментируйте и заполните:
# [[panel]]
# id = "reserve"
# title = "Резерв"
# api_url = "https://panel.example.com"
# api_token = ""
# monitor_user = "monitoring"
# host_tag = "MONITORING"
# host_tag_lite = "MONITORING_LITE"
# host_suffix = " · R"
# exclude_nodes = []
# geocheck_exclude = []
# [panel.telegram]
# bot_token = ""
# chat_id = ""
# topic_id = ""
''')


def main(argv):
    cmd = argv[1] if len(argv) > 1 else 'run'
    if cmd == 'migrate':
        migrate()
        return 0
    if cmd == 'migrate-checks':
        print(migrate_checks(config.load()))
        return 0
    if cmd in ('-h', '--help', 'help'):
        print(__doc__)
        return 0
    cfg = config.load()
    clients = {p.id: Remnawave(p) for p in cfg.panels}
    if cmd == 'run':
        run_forever(cfg)
    elif cmd == 'render':
        from .render import render
        render(cfg)
    elif cmd == 'check':
        return check(cfg)
    elif cmd == 'links':
        per_panel, checks = links.refresh(cfg, clients)
        by_name = {c['name']: c for c in checks}
        for p, entries in per_panel:
            print(f'{p.title}:')
            for h in (h for h in links.HOSTS if h['panel'] == p.id):
                notes = []
                if h['lite']:
                    notes.append('только «Подключение»')
                else:
                    off = [c.title for c in cfg.route_checks if c.id not in h['checks']]
                    if off:
                        notes.append('без ' + ' и '.join(off))
                if h['name'] != h['host'] + p.host_suffix:
                    notes.append(f'общая проверка с «{h["name"]}»')
                print(f'  {h["host"]}' + (f' ({"; ".join(notes)})' if notes else ''))
            if not entries:
                print('  — хостов нет')
        print(f'Всего проверок: {len(checks)} ({sum(1 for c in checks if not c["lite"])} полных), '
              f'хостов в панелях: {len(links.HOSTS)}')
    elif cmd == 'geocheck':
        geocheck.run(cfg, clients)
        if '--send' in argv:
            daily.send(Prometheus(cfg.prometheus_url), clients, cfg)
        else:
            print('\n'.join(geocheck.telegram_section(geocheck.load_last(cfg))))
    elif cmd == 'report':
        daily.send(Prometheus(cfg.prometheus_url), clients, cfg, dry_run='--dry-run' in argv)
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
