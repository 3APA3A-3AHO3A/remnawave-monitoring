import html
import json
import re
import os
import tempfile
from datetime import datetime, timezone


def now():
    return datetime.now(timezone.utc)


def log(where, msg):
    print(f'{now():%Y-%m-%d %H:%M:%S} [{where}] {msg}', flush=True)


def esc(text):
    return html.escape(str(text), quote=False)


def read_json(path, default):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except (OSError, ValueError) as e:
        log('state', f'не удалось прочитать {path}: {e}')
        return default


def write_json(path, data):
    folder = os.path.dirname(path)
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix='.tmp-')
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False)
    os.replace(tmp, path)


def gb(n):
    """Байты → «12.3 ГБ» / «850 МБ»."""
    if n is None:
        return '—'
    if n >= 1e9:
        return f'{n / 1e9:.1f} ГБ'
    if n >= 1e6:
        return f'{n / 1e6:.0f} МБ'
    return f'{n / 1e3:.0f} КБ'


def minutes(m):
    m = int(round(m))
    if m < 60:
        return f'{m} мин'
    return f'{m // 60} ч {m % 60:02d} мин'


def promql_regex(values):
    """Список строк → регулярка для PromQL `a|b\\.c` в обратных кавычках
    (raw-строка: обратные слэши не надо удваивать, кавычки внутри не мешают)."""
    body = '|'.join(re.sub(r'([\\.^$|?*+()\[\]{}])', r'\\\1', v) for v in values)
    return '`' + body.replace('`', '') + '`'
