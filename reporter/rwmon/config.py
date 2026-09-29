"""Настройки: config.toml (панели, Telegram, проверки) + немного переменных окружения
от docker compose (порты, пути)."""
import os
import re
import tomllib
from dataclasses import dataclass, field

CONFIG_PATH = os.environ.get('RWMON_CONFIG', '/config/config.toml')


class ConfigError(SystemExit):
    pass


@dataclass
class Telegram:
    bot_token: str
    chat_id: str
    topic_id: str = ''

    @property
    def key(self):
        return (self.bot_token, self.chat_id, self.topic_id)


@dataclass
class Panel:
    id: str                    # латиницей: main, reserve — попадает в метки
    title: str                 # как подписывать в сообщениях и на графиках
    api_url: str
    api_token: str
    headers: dict
    monitor_user: str
    host_tag: str
    host_tag_lite: str
    host_suffix: str           # добавляется к названиям хостов этой панели
    metrics_url: str           # /metrics панели — точный трафик (необязательно)
    metrics_user: str
    metrics_password: str
    exclude_nodes: set         # имена или теги нод (в нижнем регистре)
    geocheck_exclude: set
    telegram: Telegram


@dataclass
class Config:
    panels: list
    report_time: tuple = (15, 0)
    geocheck_time: tuple = (14, 30)
    check_interval: int = 300
    check_attempts: int = 3         # попыток внутри одной проверки
    check_retry_delay: int = 5      # пауза между попытками, секунд
    check_concurrency: int = 20     # сколько хостов проверять одновременно
    url_xray: str = 'https://www.google.com/generate_204'
    url_warp: str = 'https://icanhazip.com'
    url_psiphon: str = 'http://ip-api.com/line/?fields=query'
    clients_drop_min_avg: float = 3
    clients_drop_max_now: float = 1
    outbound_tags: list = field(default_factory=lambda: ['psiphon-out', 'WARP'])
    bad_countries: set = field(default_factory=lambda: {'RU', 'BY'})
    attach_images: bool = True
    healthcheck_url: str = ''
    # из окружения
    data_dir: str = '/data'
    links_file: str = '/links/monitor.txt'
    links_file_xray: str = '/links/monitor-xray.txt'
    prometheus_url: str = 'http://127.0.0.1:9090'
    prometheus_port: int = 9090
    reporter_port: int = 9105
    poll_interval: int = 30
    links_interval: int = 600

    @property
    def multi(self):
        return len(self.panels) > 1

    def panel(self, pid):
        return next((p for p in self.panels if p.id == pid), None)

    def chats(self):
        """Все разные чаты/топики панелей — для общих сообщений."""
        seen, out = set(), []
        for p in self.panels:
            if p.telegram.key not in seen:
                seen.add(p.telegram.key)
                out.append(p.telegram)
        return out


def _time(value, name):
    m = re.fullmatch(r'(\d{1,2}):(\d{2})', str(value).strip())
    if not m or int(m[1]) > 23 or int(m[2]) > 59:
        raise ConfigError(f'config.toml: {name} = "{value}" — нужно время ЧЧ:ММ (UTC)')
    return int(m[1]), int(m[2])


def _lower_set(values):
    return {str(v).strip().lower() for v in values or [] if str(v).strip()}


def _telegram(section, where, default=None):
    """Telegram панели; чего нет в блоке панели — берётся из общего [telegram]."""
    section = section or {}
    d = default or Telegram('', '', '')
    token = str(section.get('bot_token') or d.bot_token).strip()
    chat = str(section.get('chat_id') or d.chat_id).strip()
    if 'topic_id' in section:
        topic = str(section.get('topic_id') or '').strip()
    else:
        topic = d.topic_id if chat == d.chat_id else ''
    if not token or not chat:
        raise ConfigError(f'config.toml: в {where} не заданы bot_token и chat_id Telegram')
    return Telegram(token, chat, topic)


def parse(data, env=os.environ):
    tg_default = _telegram(data['telegram'], '[telegram]') if data.get('telegram') else None
    panels_raw = data.get('panel') or []
    if not panels_raw:
        raise ConfigError('config.toml: нет ни одной панели — добавьте блок [[panel]]')

    panels, ids = [], set()
    for i, p in enumerate(panels_raw):
        where = f'[[panel]] №{i + 1}'
        pid = str(p.get('id', '')).strip()
        if not re.fullmatch(r'[a-z0-9_-]{1,20}', pid):
            raise ConfigError(f'config.toml: {where}: id должен быть латиницей, например "main"')
        if pid in ids:
            raise ConfigError(f'config.toml: id "{pid}" встречается дважды')
        ids.add(pid)
        for key in ('api_url', 'api_token'):
            if not str(p.get(key, '')).strip():
                raise ConfigError(f'config.toml: {where} ({pid}): не заполнено {key}')
        title = str(p.get('title') or pid).strip()
        default_suffix = '' if i == 0 else f' · {title}'
        panels.append(Panel(
            id=pid,
            title=title,
            api_url=str(p['api_url']).strip().rstrip('/'),
            api_token=str(p['api_token']).strip(),
            headers={str(k): str(v) for k, v in (p.get('headers') or {}).items()},
            monitor_user=str(p.get('monitor_user', 'monitoring')).strip(),
            host_tag=str(p.get('host_tag', 'MONITORING')).strip(),
            host_tag_lite=str(p.get('host_tag_lite', 'MONITORING_LITE')).strip(),
            host_suffix=str(p.get('host_suffix', default_suffix)),
            metrics_url=str(p.get('metrics_url', '')).strip(),
            metrics_user=str(p.get('metrics_user', '')).strip(),
            metrics_password=str(p.get('metrics_password', '')),
            exclude_nodes=_lower_set(p.get('exclude_nodes')),
            geocheck_exclude=_lower_set(p.get('geocheck_exclude')),
            telegram=_telegram(p.get('telegram'), f'{where} ({pid})', tg_default),
        ))
    empty = [p.id for p in panels if not p.host_suffix]
    if len(empty) > 1:
        raise ConfigError('config.toml: host_suffix пустой у нескольких панелей '
                          f'({", ".join(empty)}) — хосты разных панелей будет не различить')

    sch, chk, al, geo = (data.get(k) or {} for k in ('schedule', 'checks', 'alerts', 'geocheck'))
    return Config(
        panels=panels,
        report_time=_time(sch.get('report_time', '15:00'), 'report_time'),
        geocheck_time=_time(sch.get('geocheck_time', '14:30'), 'geocheck_time'),
        check_interval=int(chk.get('interval', 300)),
        check_attempts=max(1, int(chk.get('attempts', 3))),
        check_retry_delay=max(0, int(chk.get('retry_delay', 5))),
        check_concurrency=max(0, int(chk.get('concurrency', 20))),
        url_xray=chk.get('url_xray', Config.url_xray),
        url_warp=chk.get('url_warp', Config.url_warp),
        url_psiphon=chk.get('url_psiphon', Config.url_psiphon),
        clients_drop_min_avg=float(al.get('clients_drop_min_avg', 3)),
        clients_drop_max_now=float(al.get('clients_drop_max_now', 1)),
        outbound_tags=[str(t) for t in al.get('outbound_tags', ['psiphon-out', 'WARP'])],
        bad_countries={str(c).upper() for c in geo.get('bad_countries', ['RU', 'BY'])},
        attach_images=bool(geo.get('attach_images', True)),
        healthcheck_url=str((data.get('healthcheck') or {}).get('ping_url', '')).strip(),
        data_dir=env.get('DATA_DIR', '/data'),
        links_file=env.get('LINKS_FILE', '/links/monitor.txt'),
        links_file_xray=env.get('LINKS_FILE_XRAY', '/links/monitor-xray.txt'),
        prometheus_url=env.get('PROMETHEUS_URL', 'http://127.0.0.1:9090').rstrip('/'),
        prometheus_port=int(env.get('PROMETHEUS_PORT', 9090)),
        reporter_port=int(env.get('REPORTER_PORT', 9105)),
    )


def load(path=CONFIG_PATH):
    try:
        with open(path, 'rb') as f:
            data = tomllib.load(f)
    except FileNotFoundError:
        raise ConfigError(f'Нет файла настроек {path}. Скопируйте config.example.toml в config.toml') from None
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f'config.toml: ошибка в файле — {e}') from None
    return parse(data)
