"""rwmon-reporter.

  run       — работать постоянно (так запускается контейнер)
  check     — проверить доступ к панели, Prometheus и Telegram
  links     — обновить список хостов для проверок прямо сейчас
  geocheck  — прогнать GeoCheck сейчас (--send — сразу отправить сводку)
  report    — собрать ежедневную сводку сейчас (--dry-run — только показать)

Пример:  docker compose exec reporter python -m rwmon report --dry-run
"""
import os
import sys
import time

from . import config, daily, geocheck, links
from .clients import Prometheus, Remnawave, Telegram
from .util import log, now, read_json, write_json

TICK = 20            # как часто просыпается планировщик, секунд
RETRY_AFTER = 600    # если задача упала — повторить через 10 минут


def due(state, key, hm):
    """Пора ли выполнять ежедневную задачу: время наступило и сегодня её ещё не было."""
    t = now()
    if state.get(key) == t.strftime('%Y-%m-%d'):
        return False
    if time.time() < state.get(key + '_retry', 0):
        return False
    return (t.hour, t.minute) >= hm


def run_forever(cfg):
    rw, prom, tg = Remnawave(cfg), Prometheus(cfg.prometheus_url), Telegram(cfg)
    state_path = os.path.join(cfg.data_dir, 'state.json')
    state = read_json(state_path, {})
    next_links = 0
    log('main', f'запущен; GeoCheck в {cfg.geocheck_time[0]:02d}:{cfg.geocheck_time[1]:02d}, '
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
                links.refresh(rw, cfg)
            except Exception as e:
                log('links', f'ошибка: {e}')
            next_links = time.time() + cfg.links_interval

        if due(state, 'geocheck', cfg.geocheck_time):
            task('geocheck', lambda: geocheck.run(rw, cfg))
        if due(state, 'report', cfg.report_time):
            task('report', lambda: daily.send(prom, rw, tg, cfg))
        time.sleep(TICK)


def check(cfg):
    ok = True

    def step(title, fn):
        nonlocal ok
        try:
            print(f'✓ {title}: {fn()}')
        except Exception as e:
            ok = False
            print(f'✗ {title}: {e}')

    rw, prom, tg = Remnawave(cfg), Prometheus(cfg.prometheus_url), Telegram(cfg)
    step('API панели, ноды', lambda: f'{len(rw.nodes())} шт.')
    step(f'служебный пользователь «{cfg.monitor_username}» и хосты {cfg.monitor_host_tag}',
         lambda: ', '.join(links.refresh(rw, cfg)) or 'хостов с тегом нет')
    def panel_metrics():
        states = prom.targets('remnawave')
        if not states:
            raise RuntimeError('Prometheus не знает о метриках панели — проверьте prometheus.yml')
        url, health, error = states[0]
        if health == 'up':
            return f'есть ({url})'
        if health == 'unknown':
            raise RuntimeError('Prometheus ещё не успел опросить панель — повторите check через минуту')
        hint = ' — неверный RW_METRICS_USER / RW_METRICS_PASS' if '401' in error else ''
        raise RuntimeError(f'{url}: {error}{hint}')

    def checks():
        n = len(prom.query('xray_proxy_status'))
        if n:
            return f'{n} результатов'
        return 'пока нет — первые появятся через 5–10 минут после запуска'

    step('Prometheus, метрики панели', panel_metrics)
    step('Prometheus, проверки хостов', checks)
    step('Telegram-бот', lambda: '@' + tg.get_me().get('username', '?'))
    return 0 if ok else 1


def main(argv):
    cmd = argv[1] if len(argv) > 1 else 'run'
    cfg = config.load()
    if cmd == 'run':
        run_forever(cfg)
    elif cmd == 'check':
        return check(cfg)
    elif cmd == 'links':
        print('\n'.join(links.refresh(Remnawave(cfg), cfg)) or 'хостов нет')
    elif cmd == 'geocheck':
        geocheck.run(Remnawave(cfg), cfg)
        if '--send' in argv:
            daily.send(Prometheus(cfg.prometheus_url), Remnawave(cfg), Telegram(cfg), cfg)
        else:
            print('\n'.join(geocheck.telegram_section(geocheck.load_last(cfg))))
    elif cmd == 'report':
        daily.send(Prometheus(cfg.prometheus_url), Remnawave(cfg), Telegram(cfg), cfg,
                   dry_run='--dry-run' in argv)
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
