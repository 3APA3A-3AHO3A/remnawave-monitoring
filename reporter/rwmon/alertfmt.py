"""Текст алертов для бота: rich-сообщения Telegram (таблицы, сворачиваемые блоки,
время в часовом поясе читателя) и запасной вариант обычным HTML, если клиент или
Telegram rich-разметку не приняли. Только оформление — без сети и состояния."""
import html
import re
from datetime import datetime, timezone

from .util import esc

# метки, которые не описывают «что сломалось» — по ним тишину не ставим
SERVICE_LABELS = {'alertname', 'grafana_folder', 'severity', 'scope', 'repeat'}

# группы правил для /settings: (ключ, подпись, как узнать правило по uid)
CATEGORIES = [
    ('nodes', 'Ноды и хосты', ('-down', '-bypass', '-direct', '-egress', 'clients-dropped',
                               'outbound-no-response', 'node-overload')),
    ('ru', 'Пробы из РФ', ('probe-down', 'site-down-ru')),
    ('rkn', 'Блокировки РКН', ('rkn-blocked', 'rkn-scan')),
    ('panels', 'Панели', ('panel-metrics', 'panel-slow', 'panel-restart', 'panel-memory',
                          'panel-no-hosts')),
    ('sites', 'Сайты и сертификаты', ('site-down', 'site-cert')),
    ('self', 'Сам мониторинг', ('reporter-down', 'hosts-unchecked', 'checker-down')),
]
CATEGORY_TITLE = {k: t for k, t, _ in CATEGORIES}
# порядок важен: сначала точные имена, общий хвост «-down» — последним
_EXACT = [(k, p) for k, _, ps in CATEGORIES for p in ps if not p.startswith('-')]


def category(uid):
    """Группа правила по его uid (rwmon-…). Ошибки самих правил Grafana — «Сам мониторинг»."""
    name = (uid or '').removeprefix('rwmon-')
    for key, pattern in _EXACT:
        if name == pattern:
            return key
    if any(name.endswith(s) for s in ('-down', '-bypass', '-direct', '-egress')):
        return 'nodes'
    return 'self'


def target(labels, multi):
    """Что сломалось — так же, как в шаблоне сообщений Grafana (grafana/telegram.tmpl)."""
    lb = labels
    panel = f' · {lb["panel_title"]}' if multi and lb.get('panel_title') else ''
    if lb.get('node_name'):
        out = lb['node_name'] + panel
    elif lb.get('host'):
        out = lb['host'] + panel
    else:
        out = (lb.get('name') or lb.get('site') or lb.get('panel_title')
               or (f'проба «{lb["probe"]}»' if lb.get('probe') else '')
               or (f'проверка «{lb["check"]}»' if lb.get('check') else '')
               or lb.get('rulename') or lb.get('alertname', '?'))
    if lb.get('tag'):
        out += f' · {lb["tag"]}'
    if lb.get('process'):
        out += f' · процесс «{lb["process"]}»'
    if lb.get('exit'):
        out += f' → {lb["exit"]}'
    return out


def ident(labels):
    """Метки, по которым узнаётся один и тот же сбой (для тишины)."""
    return {k: v for k, v in labels.items() if k not in SERVICE_LABELS and not k.startswith('__')}


def parse_time(s):
    """Время из Grafana (RFC 3339); «0001-01-01…» — нет времени."""
    if not s or s.startswith('0001'):
        return None
    s = re.sub(r'(\.\d{6})\d+', r'\1', s.replace('Z', '+00:00'))
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def tg_time(ts, fmt='t'):
    """Время в часовом поясе читателя; внутри — запасной текст в UTC."""
    if ts is None:
        return ''
    if isinstance(ts, (int, float)):
        ts = datetime.fromtimestamp(ts, timezone.utc)
    fallback = ts.astimezone(timezone.utc).strftime('%H:%M UTC' if fmt == 't' else '%d.%m %H:%M UTC')
    return f'<tg-time unix="{int(ts.timestamp())}" format="{fmt}">{fallback}</tg-time>'


def duration(seconds):
    m = max(0, int(seconds // 60))
    if m < 60:
        return f'{m} мин'
    h, m = divmod(m, 60)
    if h < 48:
        return f'{h} ч {m} мин' if m else f'{h} ч'
    return f'{h // 24} дн. {h % 24} ч'


# ── кнопки ──────────────────────────────────────────────────

def cb(text, data, style=''):
    return {'text': text, 'data': data, 'style': style}


def url_btn(text, url):
    return {'text': text, 'url': url}


def _button_html(b):
    text = esc(b['text'])
    style = f' style="{b["style"]}"' if b.get('style') else ''
    if b.get('url'):
        return f'<tg-button type="url" url="{html.escape(b["url"])}">{text}</tg-button>'
    return f'<tg-button type="callback_data"{style} data="{html.escape(b["data"])}">{text}</tg-button>'


def rich(body, rows=()):
    """Готовый HTML rich-сообщения: тело + ряды кнопок внутри сообщения."""
    out = [body]
    for row in rows:
        if row:
            out.append('<tg-button-row>' + ''.join(_button_html(b) for b in row) + '</tg-button-row>')
    return ''.join(out)


def keyboard(rows):
    """Те же кнопки — обычной клавиатурой под сообщением (запасной вариант)."""
    out = []
    for row in rows:
        r = []
        for b in row:
            k = {'text': b['text']}
            if b.get('url'):
                k['url'] = b['url']
            else:
                k['callback_data'] = b['data']
            r.append(k)
        if r:
            out.append(r)
    return {'inline_keyboard': out}


_KEEP = re.compile(r'</?(b|i|u|s|code|pre|a)(\s[^>]*)?>', re.I)


def plain(body):
    """rich-HTML → обычный HTML Telegram: заголовки жирным, таблицы строками, блоки раскрыты."""
    s = re.sub(r'<tg-time[^>]*>(.*?)</tg-time>', r'\1', body, flags=re.S)
    s = re.sub(r'<h[1-6][^>]*>(.*?)</h[1-6]>', r'<b>\1</b>\n', s, flags=re.S)
    s = re.sub(r'<summary[^>]*>(.*?)</summary>', r'\n<b>\1</b>\n', s, flags=re.S)
    s = re.sub(r'</t[hd]>\s*<t[hd][^>]*>', ' · ', s)
    s = re.sub(r'<li[^>]*>', '• ', s)
    s = re.sub(r'</(tr|li|p|blockquote|footer|table|details|ul|ol)>|<br\s*/?>', '\n', s)
    s = re.sub(r'<footer[^>]*>', '\n', s)
    s = re.sub(r'<(?!/?(b|i|u|s|code|pre|a)(\s|>))[^>]+>', '', s)
    s = re.sub(r'[ \t]+\n', '\n', s)
    s = re.sub(r'\n{3,}', '\n\n', s).strip()
    if len(s) > 4000:
        s = s[:3990].rsplit('\n', 1)[0] + '\n…'
    return s


# ── сообщение об алертах ────────────────────────────────────

MAX_ITEMS = 25


def _items(alerts, multi, resolved):
    lines = []
    for a in alerts[:MAX_ITEMS]:
        lb = a.get('labels', {})
        t = f'<b>{esc(target(lb, multi))}</b>'
        start, end = parse_time(a.get('startsAt')), parse_time(a.get('endsAt'))
        if resolved:
            lines.append(f'<li>{t} — {tg_time(start)} → {tg_time(end)}</li>')
        else:
            reason = (a.get('annotations') or {}).get('reason', '')
            lines.append(f'<li>{t} — с {tg_time(start)}' + (f' · {esc(reason)}' if reason else '') + '</li>')
    if len(alerts) > MAX_ITEMS:
        lines.append(f'<li>и ещё {len(alerts) - MAX_ITEMS}</li>')
    return '<ul>' + ''.join(lines) + '</ul>'


def _is_rule_error(a):
    return (a.get('labels') or {}).get('alertname') in ('DatasourceError', 'DatasourceNoData')


def alert_body(firing, resolved, multi):
    """Тело сообщения об одной группе алертов: восстановилось, потом то, что ещё не работает."""
    parts = []
    first = (firing or resolved)[0]
    if _is_rule_error(first):
        rule = esc((first.get('labels') or {}).get('rulename', '?'))
        if firing:
            return (f'<h4>⚠️ Ошибка в самом мониторинге</h4><p>Правило «{rule}» не может выполниться '
                    'и сейчас ничего не проверяет. Смотрите Grafana → Оповещение → Правила.</p>')
        return f'<h4>🟢 Правило «{rule}» снова работает</h4>'
    if resolved:
        title = (resolved[0].get('annotations') or {}).get('recovered') or 'Восстановлено'
        parts.append(f'<h4>🟢 {esc(title)}</h4>' + _items(resolved, multi, True))
    if firing:
        a = firing[0]
        title = (a.get('annotations') or {}).get('summary') or a['labels'].get('alertname', '')
        parts.append(f'<h4>🔴 {"Всё ещё: " if resolved else ""}{esc(title)}</h4>' + _items(firing, multi, False))
    return ''.join(parts)


def muted_footer(mute_until, by):
    when = 'навсегда' if not mute_until else f'до {tg_time(mute_until, "wDT")}'
    return f'<footer>🔕 Заглушено {when} — {esc(by)}</footer>'


def details_body(items):
    """items — [(заголовок, [(подпись, значение-HTML)])]."""
    out = []
    for title, rows in items:
        out.append(f'<h4>{esc(title)}</h4><table bordered compact>'
                   + ''.join(f'<tr><td>{esc(k)}</td><td>{v}</td></tr>' for k, v in rows if v)
                   + '</table>')
    return ''.join(out) or '<p>Подробностей нет.</p>'


def unescape(s):
    return html.unescape(s)
