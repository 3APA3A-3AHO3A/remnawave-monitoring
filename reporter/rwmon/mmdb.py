"""Чтение баз MaxMind DB (.mmdb) без внешних библиотек — для DB-IP Lite.

По IP выхода проверки reporter узнаёт страну и сеть (AS), чтобы проверить
egress_country / egress_asn из [[check]]. Формат описан на
https://maxmind.github.io/MaxMind-DB/ — здесь только чтение и поиск.
"""
import ipaddress
import struct

MARKER = b'\xab\xcd\xefMaxMind.com'
MAX_DEPTH = 32          # вложенность словарей и массивов в одной записи
MAX_VALUES = 20000      # значений в одной записи: защита от повреждённой или «раздутой» базы
MAX_BYTES = 1 << 20     # байт строк и данных в одной записи (у DB-IP — сотни байт)


class MMDBError(Exception):
    pass


class Reader:
    def __init__(self, data):
        if isinstance(data, str):
            with open(data, 'rb') as f:
                data = f.read()
        self.buf = data
        start = data.rfind(MARKER)
        if start < 0:
            raise MMDBError('это не база MaxMind DB: нет метаданных')
        self._budget, self._bytes = MAX_VALUES, MAX_BYTES
        self.meta, _ = self._decode(start + len(MARKER), start + len(MARKER))
        try:
            self.node_count = int(self.meta['node_count'])
            self.record_size = int(self.meta['record_size'])
            self.ip_version = int(self.meta['ip_version'])
        except (KeyError, TypeError, ValueError):
            raise MMDBError('в метаданных базы нет node_count / record_size / ip_version') from None
        if self.record_size not in (24, 28, 32):
            raise MMDBError(f'неизвестный размер записи {self.record_size}')
        self.node_bytes = self.record_size // 4
        self.tree_size = self.node_bytes * self.node_count
        self.data_start = self.tree_size + 16
        self._ipv4_start = None

    # ── дерево поиска ──
    def _record(self, node, bit):
        off = node * self.node_bytes
        b = self.buf
        if self.record_size == 24:
            off += bit * 3
            return int.from_bytes(b[off:off + 3], 'big')
        if self.record_size == 28:
            if bit == 0:
                return ((b[off + 3] & 0xF0) << 20) | int.from_bytes(b[off:off + 3], 'big')
            return ((b[off + 3] & 0x0F) << 24) | int.from_bytes(b[off + 4:off + 7], 'big')
        off += bit * 4
        return int.from_bytes(b[off:off + 4], 'big')

    def _start(self, bits):
        """IPv4 в базе IPv6 лежит в ::/96 — спускаемся на 96 нулевых бит один раз."""
        if self.ip_version == 4 or bits == 128:
            return 0
        if self._ipv4_start is None:
            node = 0
            for _ in range(96):
                if node >= self.node_count:
                    break
                node = self._record(node, 0)
            self._ipv4_start = node
        return self._ipv4_start

    def get(self, ip):
        """Запись для IP (dict) или None, если IP в базе нет."""
        addr = ipaddress.ip_address(ip)
        if addr.version == 6 and self.ip_version == 4:
            return None
        packed, bits = int(addr), addr.max_prefixlen
        node = self._start(bits)
        for i in range(bits):
            if node >= self.node_count:
                break
            node = self._record(node, (packed >> (bits - 1 - i)) & 1)
        if node == self.node_count:
            return None
        if node < self.node_count:
            raise MMDBError('дерево поиска базы повреждено')
        off = self.data_start + (node - self.node_count) - 16
        if off >= len(self.buf):
            raise MMDBError('ссылка за пределы базы')
        self._budget, self._bytes = MAX_VALUES, MAX_BYTES
        value, _ = self._decode(off, self.data_start)
        return value

    # ── раздел данных ──
    def _size(self, off, size):
        b = self.buf
        if size < 29:
            return size, off
        if size == 29:
            return 29 + b[off], off + 1
        if size == 30:
            return 285 + int.from_bytes(b[off:off + 2], 'big'), off + 2
        return 65821 + int.from_bytes(b[off:off + 3], 'big'), off + 3

    def _decode(self, off, base, depth=0):
        """Значение по смещению off; base — начало раздела, от которого считаются указатели."""
        b = self.buf
        self._budget -= 1
        if self._budget < 0 or depth > MAX_DEPTH:
            raise MMDBError('запись базы слишком большая или зациклена')
        if off >= len(b):
            raise MMDBError('ссылка за пределы базы')
        ctrl = b[off]
        off += 1
        kind = ctrl >> 5
        if kind == 1:                                   # указатель
            ss, vvv = (ctrl >> 3) & 3, ctrl & 7
            if ss == 0:
                p, off = (vvv << 8) | b[off], off + 1
            elif ss == 1:
                p, off = ((vvv << 16) | int.from_bytes(b[off:off + 2], 'big')) + 2048, off + 2
            elif ss == 2:
                p, off = ((vvv << 24) | int.from_bytes(b[off:off + 3], 'big')) + 526336, off + 3
            else:
                p, off = int.from_bytes(b[off:off + 4], 'big'), off + 4
            value, _ = self._decode(base + p, base, depth + 1)
            return value, off
        if kind == 0:                                   # расширенный тип
            kind = 7 + b[off]
            off += 1
        size, off = self._size(off, ctrl & 0x1F)
        if kind in (2, 4):
            self._bytes -= size
            if self._bytes < 0:
                raise MMDBError('запись базы слишком большая')
        if kind == 2:                                   # строка UTF-8
            return b[off:off + size].decode('utf-8', 'replace'), off + size
        if kind == 3:                                   # double
            return struct.unpack('>d', b[off:off + 8])[0], off + 8
        if kind == 4:                                   # байты
            return bytes(b[off:off + size]), off + size
        if kind in (5, 6, 9, 10):                       # беззнаковые целые
            return int.from_bytes(b[off:off + size], 'big'), off + size
        if kind == 7:                                   # словарь
            out = {}
            for _ in range(size):
                k, off = self._decode(off, base, depth + 1)
                v, off = self._decode(off, base, depth + 1)
                out[k] = v
            return out, off
        if kind == 8:                                   # int32
            v = int.from_bytes(b[off:off + size], 'big') if size else 0
            if size == 4 and v & 0x80000000:
                v -= 1 << 32
            return v, off + size
        if kind == 11:                                  # массив
            out = []
            for _ in range(size):
                v, off = self._decode(off, base, depth + 1)
                out.append(v)
            return out, off
        if kind == 14:                                  # логическое: значение в поле размера
            return bool(size), off
        if kind == 15:                                  # float
            return struct.unpack('>f', b[off:off + 4])[0], off + 4
        raise MMDBError(f'неизвестный тип данных {kind}')
