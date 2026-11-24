"""Страна и сеть (AS) IP выхода проверок — для egress_country / egress_asn в [[check]].

Базы — бесплатные DB-IP Lite (страна и ASN, лицензия CC BY 4.0, https://db-ip.com).
reporter скачивает их сам раз в месяц в <data>/geoip и читает своим кодом (mmdb.py).
Нужны, только если хоть у одной проверки задано egress_country или egress_asn.
"""
import gzip
import os
import time
import urllib.request
from datetime import datetime, timezone

from . import mmdb
from .util import log

URL = 'https://download.db-ip.com/free/dbip-{kind}-lite-{month}.mmdb.gz'
KINDS = ('country', 'asn')
MAX_AGE = 32 * 86400          # старше — пробуем скачать свежую (DB-IP обновляет раз в месяц)
RETRY = 6 * 3600              # не скачалось — следующая попытка через 6 часов
TIMEOUT = 120


def needed(cfg):
    return any(c.egress_country or c.egress_asn for c in cfg.route_checks)


def folder(cfg):
    return os.path.join(cfg.data_dir, 'geoip')


def path(cfg, kind):
    return os.path.join(folder(cfg), f'dbip-{kind}-lite.mmdb')


def _months(now=None):
    """Этот месяц и прошлый: в первые дни месяца новой базы ещё нет."""
    now = now or datetime.now(timezone.utc)
    prev = (now.replace(day=1).toordinal() - 1)
    prev = datetime.fromordinal(prev)
    return [f'{now:%Y-%m}', f'{prev:%Y-%m}']


def _download(kind, dest, opener=urllib.request.urlopen):
    last = None
    for month in _months():
        url = URL.format(kind=kind, month=month)
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'rwmon'})
            with opener(req, timeout=TIMEOUT) as r:
                data = gzip.decompress(r.read())
            mmdb.Reader(data)                          # проверяем, что это настоящая база
        except Exception as e:
            last = f'{url}: {e}'
            continue
        tmp = dest + '.tmp'
        with open(tmp, 'wb') as f:
            f.write(data)
        os.replace(tmp, dest)
        return month
    raise RuntimeError(last or 'нет адреса')


def update(cfg, state, opener=urllib.request.urlopen):
    """Скачать базы, если их нет или они старше месяца. Ошибка — пишем в журнал и
    пробуем позже; старая база остаётся рабочей."""
    if not needed(cfg):
        return
    os.makedirs(folder(cfg), exist_ok=True)
    for kind in KINDS:
        dest = path(cfg, kind)
        try:
            age = time.time() - os.path.getmtime(dest)
        except OSError:
            age = None
        if age is not None and age < MAX_AGE:
            continue
        if time.time() < state.get(f'geoip:{kind}:retry', 0):
            continue
        try:
            month = _download(kind, dest, opener)
            state.pop(f'geoip:{kind}:retry', None)
            log('geoip', f'база DB-IP Lite ({kind}) за {month} скачана')
        except Exception as e:
            state[f'geoip:{kind}:retry'] = time.time() + RETRY
            log('geoip', f'база DB-IP Lite ({kind}) не скачалась: {e}'
                         + (' — работаю со старой' if age is not None else ' — страну и сеть выхода пока не знаю'))


class Lookup:
    """Страна и сеть по IP. Базы перечитываются, когда файл на диске сменился."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.readers, self.mtimes, self.cache = {}, {}, {}

    def _reader(self, kind):
        p = path(self.cfg, kind)
        try:
            mtime = os.path.getmtime(p)
        except OSError:
            return None
        if self.mtimes.get(kind) != mtime:
            try:
                self.readers[kind] = mmdb.Reader(p)
            except (OSError, mmdb.MMDBError) as e:
                log('geoip', f'{p}: {e}')
                self.readers[kind] = None
            self.mtimes[kind] = mtime
            self.cache = {}
        return self.readers.get(kind)

    def get(self, ip):
        """(страна, номер AS, организация) или None, если баз ещё нет."""
        country, asn = self._reader('country'), self._reader('asn')
        if country is None and asn is None:
            return None
        if ip not in self.cache:
            c = a = None
            try:
                c = country.get(ip) if country else None
                a = asn.get(ip) if asn else None
            except (ValueError, mmdb.MMDBError):
                pass
            cc = ((c or {}).get('country') or {}).get('iso_code') or ''
            self.cache[ip] = (str(cc).upper(), (a or {}).get('autonomous_system_number') or 0,
                              str((a or {}).get('autonomous_system_organization') or ''))
        return self.cache[ip]
