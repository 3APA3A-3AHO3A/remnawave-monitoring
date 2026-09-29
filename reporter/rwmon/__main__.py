"""rwmon-reporter — мониторинг панелей Remnawave.

  run       — работать постоянно (так запускается контейнер reporter)
  render    — собрать конфиги Prometheus и Grafana из config.toml (контейнер config)
  check     — проверить доступ к панелям, Prometheus и Telegram
  links     — обновить список хостов для проверок прямо сейчас
  geocheck  — прогнать GeoCheck сейчас (--send — сразу отправить сводку)
  report    — собрать ежедневную сводку сейчас (--dry-run — только показать)
  migrate   — напечатать config.toml из старого .env (переход с версии для одной панели)

Пример:  docker compose exec reporter python -m rwmon report --dry-run
"""
import json
import os
import sys
import time
import urllib.request

from . import config, daily, exporter, geocheck, links
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


def ping(url):
    try:
        urllib.request.urlopen(url, timeout=10).read()
    except Exception as e:
        log('healthcheck', f'не удалось отметиться: {e}')


def run_forever(cfg):
    metrics = exporter.Exporter(cfg)
    metrics.start()
    clients = metrics.clients
    prom = Prometheus(cfg.prometheus_url)
    state_path = os.path.join(cfg.data_dir, 'state.json')
    state = read_json(state_path, {})
    next_links = next_ping = 0
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
                links.refresh(cfg, clients)
            except Exception as e:
                log('links', f'ошибка: {e}')
            next_links = time.time() + cfg.links_interval
        if due(state, 'geocheck', cfg.geocheck_time):
            task('geocheck', lambda: geocheck.run(cfg, clients))
        if due(state, 'report', cfg.report_time):
            task('report', lambda: daily.send(prom, clients, cfg))
        if cfg.healthcheck_url and time.time() >= next_ping:
            ping(cfg.healthcheck_url)
            next_ping = time.time() + PING_EVERY
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
        step(f'хосты для проверок (пользователь «{p.monitor_user}»)', lambda: _hosts(rw, p))
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

    print('Сервер')
    step('порты проверок 21000–23999', ports_check)

    print('Prometheus')
    step('метрики панелей от reporter', reporter_metrics)
    step('проверки хостов', lambda: f'{len(prom.query("xray_proxy_status"))} результатов '
                                     '(первые появляются через 5–10 минут после запуска)')
    return 0 if ok else 1


PORT_RANGES = ((21000, 21999), (22000, 22999), (23000, 23999))   # см. render.CHECKERS


def _parse_ports(text):
    out = set()
    for part in text.replace(' ', ',').split(','):
        if '-' in part:
            a, b = part.split('-')
            out.update(range(int(a), int(b) + 1))
        elif part.strip():
            out.add(int(part))
    return out


def ports_check(proc='/proc/sys/net/ipv4'):
    """Проверкам нужны порты 21000+, 22000+, 23000+ на 127.0.0.1. Если система раздаёт
    эти же порты исходящим соединениям, проверка однажды не сможет запуститься
    («address already in use») и молча перестанет проверять новые хосты."""
    with open(f'{proc}/ip_local_port_range') as f:
        low, high = map(int, f.read().split())
    try:
        with open(f'{proc}/ip_local_reserved_ports') as f:
            reserved = _parse_ports(f.read().strip())
    except OSError:
        reserved = set()
    clash = [f'{a}–{b}' for a, b in PORT_RANGES
             if a <= high and b >= low and not set(range(a, b + 1)) <= reserved]
    if clash:
        raise RuntimeError(
            f'система раздаёт исходящим соединениям порты {low}–{high}, и среди них порты проверок '
            f'{", ".join(clash)}. Закрепите их: echo "net.ipv4.ip_local_reserved_ports = '
            '21000-21999,22000-22999,23000-23999" | sudo tee /etc/sysctl.d/90-rwmon.conf '
            '&& sudo sysctl -p /etc/sysctl.d/90-rwmon.conf')
    return 'свободны' if low > 23999 else 'закреплены за проверками'


def _hosts(rw, p):
    entries = links.panel_links(rw, p)
    lite = [e['host'] for e in entries if e['lite']]
    parts = [f'{len(entries) - len(lite)} полных']
    if lite:
        parts.append(f'{len(lite)} лёгких ({", ".join(lite)})')
    return ', '.join(parts)


# ── переход со старого .env ──────────────────────────────────

def _toml_str(v):
    return json.dumps(str(v), ensure_ascii=False)


def migrate(env=os.environ):
    g = env.get
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
# host_tag_lite = "MONITORING_LTE"
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
