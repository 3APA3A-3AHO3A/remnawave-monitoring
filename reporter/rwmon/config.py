"""Настройки берутся из переменных окружения (.env через docker compose)."""
import os
from dataclasses import dataclass, field


def _env(name, default=''):
    return os.environ.get(name, default).strip()


def _time(value, default):
    """'15:00' -> (15, 0)."""
    try:
        h, m = (value or default).split(':')
        h, m = int(h), int(m)
        if 0 <= h < 24 and 0 <= m < 60:
            return h, m
    except ValueError:
        pass
    raise SystemExit(f'Неверное время «{value}», нужно ЧЧ:ММ (UTC)')


def _list(value):
    return [x.strip() for x in value.split(',') if x.strip()]


def _headers(value):
    """'Cookie: a=1; X-Key: 2' -> {'Cookie': 'a=1', 'X-Key': '2'}.
    Разделитель заголовков — «;» перед именем заголовка с двоеточием."""
    result = {}
    for part in value.split(';'):
        if ':' in part:
            k, v = part.split(':', 1)
            if k.strip():
                result[k.strip()] = v.strip()
        elif part.strip() and result:
            # «;» внутри значения (например, несколько cookie) — приклеиваем обратно
            last = list(result)[-1]
            result[last] += '; ' + part.strip()
    return result


@dataclass
class Config:
    rw_api_url: str
    rw_api_token: str
    rw_api_headers: dict
    tg_bot_token: str
    tg_chat_id: str
    tg_topic_id: str
    panel_name: str
    prometheus_url: str
    monitor_username: str
    monitor_host_tag: str
    links_file: str
    data_dir: str
    report_time: tuple
    geocheck_time: tuple
    geocheck_exclude: set = field(default_factory=set)
    bad_countries: set = field(default_factory=set)
    attach_images: bool = True
    outbound_tags: str = 'psiphon-out|WARP'
    links_interval: int = 600
    monitor_host_tag_lite: str = 'MONITORING_LITE'
    links_file_xray: str = '/links/monitor-xray.txt'


def load():
    cfg = Config(
        rw_api_url=_env('RW_API_URL', 'http://127.0.0.1:3000').rstrip('/'),
        rw_api_token=_env('RW_API_TOKEN'),
        rw_api_headers=_headers(_env('RW_API_HEADERS')),
        tg_bot_token=_env('TG_BOT_TOKEN'),
        tg_chat_id=_env('TG_CHAT_ID'),
        tg_topic_id=_env('TG_TOPIC_ID'),
        panel_name=_env('PANEL_NAME'),
        prometheus_url=_env('PROMETHEUS_URL', 'http://127.0.0.1:9090').rstrip('/'),
        monitor_username=_env('MONITOR_USERNAME', 'monitoring'),
        monitor_host_tag=_env('MONITOR_HOST_TAG', 'MONITORING'),
        links_file=_env('LINKS_FILE', '/links/monitor.txt'),
        data_dir=_env('DATA_DIR', '/data'),
        report_time=_time(_env('REPORT_TIME'), '15:00'),
        geocheck_time=_time(_env('GEOCHECK_TIME'), '14:30'),
        geocheck_exclude={x.lower() for x in _list(_env('GEOCHECK_EXCLUDE'))},
        bad_countries={x.upper() for x in _list(_env('GEOCHECK_BAD_COUNTRIES', 'RU,BY'))},
        attach_images=_env('GEOCHECK_ATTACH_IMAGES', 'true').lower() in ('1', 'true', 'yes'),
        outbound_tags=_env('OUTBOUND_TAGS', 'psiphon-out|WARP'),
        links_interval=int(_env('LINKS_INTERVAL', '600') or 600),
        monitor_host_tag_lite=_env('MONITOR_HOST_TAG_LITE', 'MONITORING_LITE'),
        links_file_xray=_env('LINKS_FILE_XRAY', '/links/monitor-xray.txt'),
    )
    missing = [n for n, v in (('RW_API_TOKEN', cfg.rw_api_token),
                              ('TG_BOT_TOKEN', cfg.tg_bot_token),
                              ('TG_CHAT_ID', cfg.tg_chat_id)) if not v]
    if missing:
        raise SystemExit('Не заполнено в .env: ' + ', '.join(missing))
    return cfg
