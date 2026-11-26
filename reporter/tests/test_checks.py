"""Проверки маршрутов из [[check]] (2.0): настройки, выбор хостов, правила, страна и сеть выхода."""
import gzip
import io
import ipaddress
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from test_rwmon import make_cfg, vless                     # noqa: E402

from rwmon import config, daily, egress, exporter, links, mmdb, render   # noqa: E402
from rwmon.__main__ import migrate_checks, port_ranges     # noqa: E402

def read(path, as_json=False):
    with open(path, encoding='utf-8') as f:
        return json.load(f) if as_json else f.read()


CHECKS = [
    {'id': 'warp', 'title': 'WARP', 'url': 'https://icanhazip.com', 'egress_asn': ['AS13335'],
     'profiles': ['Default Vless EU']},
    {'id': 'psiphon', 'title': 'Psiphon', 'url': 'http://ip-api.com/line/?fields=query', 'egress': 'other',
     'profiles': ['Default Vless EU'], 'alert': 'Gemini не работает.'},
    {'id': 'usa', 'title': 'Каскад в США', 'url': 'https://icanhazip.com', 'egress_country': ['us'],
     'hosts': ['Америка']},
]


# ── маленькая база MaxMind DB для тестов ─────────────────────

def _ctrl(kind, size):
    ext = b''
    if kind > 7:
        ext, kind = bytes([kind - 7]), 0
    if size < 29:
        return bytes([(kind << 5) | size]) + ext
    if size < 285:
        return bytes([(kind << 5) | 29]) + ext + bytes([size - 29])
    return bytes([(kind << 5) | 30]) + ext + (size - 285).to_bytes(2, 'big')


def _enc(v):
    if isinstance(v, str):
        b = v.encode()
        return _ctrl(2, len(b)) + b
    if isinstance(v, int):
        b = v.to_bytes(max(1, (v.bit_length() + 7) // 8), 'big') if v else b''
        return _ctrl(6 if v < 1 << 32 else 9, len(b)) + b
    if isinstance(v, dict):
        return _ctrl(7, len(v)) + b''.join(_enc(k) + _enc(x) for k, x in v.items())
    raise TypeError(v)


def make_mmdb(records, db_type='test'):
    """records — {"сеть": значение}; база IPv4, записи по 24 бита."""
    nodes = [[None, None]]                 # None — пусто; ('n', i) — узел; ('d', i) — данные
    data, offsets = b'', []
    for net, value in records.items():
        n = ipaddress.ip_network(net)
        offsets.append(len(data))
        data += _enc(value)
        node, bits = 0, int(n.network_address)
        for i in range(n.prefixlen):
            bit = (bits >> (31 - i)) & 1
            if i == n.prefixlen - 1:
                nodes[node][bit] = ('d', len(offsets) - 1)
            else:
                if nodes[node][bit] is None:
                    nodes.append([None, None])
                    nodes[node][bit] = ('n', len(nodes) - 1)
                node = nodes[node][bit][1]
    count = len(nodes)

    def rec(x):
        if x is None:
            return count
        return x[1] if x[0] == 'n' else count + 16 + offsets[x[1]]
    tree = b''.join(rec(a).to_bytes(3, 'big') + rec(b).to_bytes(3, 'big') for a, b in nodes)
    meta = _enc({'node_count': count, 'record_size': 24, 'ip_version': 4, 'database_type': db_type,
                 'binary_format_major_version': 2})
    return tree + b'\0' * 16 + data + mmdb.MARKER + meta


COUNTRY = {'104.28.0.0/16': {'country': {'iso_code': 'US'}}, '5.6.0.0/16': {'country': {'iso_code': 'NL'}}}
ASN = {'104.28.0.0/16': {'autonomous_system_number': 13335, 'autonomous_system_organization': 'Cloudflare, Inc.'},
       '5.6.0.0/16': {'autonomous_system_number': 60068, 'autonomous_system_organization': 'Datacamp'}}


class ConfigChecksTest(unittest.TestCase):
    def test_legacy(self):
        cfg = make_cfg()
        self.assertEqual([(c.id, c.egress, c.legacy) for c in cfg.route_checks],
                         [('warp', 'other', True), ('psiphon', 'other', True)])
        cfg = make_cfg(checks={'url_warp': 'https://x.example'})
        self.assertEqual(cfg.route_check('warp').url, 'https://x.example')

    def test_parse(self):
        cfg = make_cfg(check=CHECKS)
        warp, psi, usa = cfg.route_checks
        self.assertEqual(warp.egress_asn, {13335})
        self.assertEqual(warp.profiles, {'default vless eu'})
        self.assertEqual(warp.skip_tag, 'MONITORING_NO_WARP')
        self.assertEqual(usa.egress_country, {'US'})
        self.assertEqual(usa.hosts, {'Америка'})
        self.assertFalse(any(c.legacy for c in cfg.route_checks))
        self.assertEqual(make_cfg(check=[]).route_checks, [])        # проверок маршрутов нет вовсе

    def test_errors(self):
        base = {'id': 'x', 'url': 'https://a.b'}
        for bad in ({**base, 'id': 'Warp'}, {**base, 'id': 'xray'}, {**base, 'id': 'panel'}, {**base, 'url': 'a.b'},
                    {**base, 'egress': 'cloud'}, {**base, 'egress_asn': ['cf']}, {**base, 'profiles': 'EU'}):
            with self.assertRaises(config.ConfigError, msg=bad):
                make_cfg(check=[bad])
        with self.assertRaises(config.ConfigError):
            make_cfg(check=[base, base])
        with self.assertRaises(config.ConfigError):
            make_cfg(check=[{**base, 'id': f'c{i}'} for i in range(config.MAX_ROUTE_CHECKS + 1)])

    def test_applies(self):
        warp, psi, usa = make_cfg(check=CHECKS).route_checks
        self.assertTrue(warp.applies('Польша', ['uuid-1', 'Default Vless EU']))
        self.assertFalse(warp.applies('Москва', ['Default Vless RU']))
        self.assertTrue(usa.applies('Америка', []))
        self.assertFalse(usa.applies('Польша', ['Default Vless EU']))
        self.assertTrue(make_cfg().route_checks[0].applies('Любой', []))   # без profiles и hosts — всем

    def test_migrate_round_trip(self):
        """migrate-checks печатает блоки, которые дают те же проверки."""
        import tomllib
        for cfg in (make_cfg(), make_cfg(check=CHECKS)):
            text = migrate_checks(cfg)
            again = make_cfg(check=tomllib.loads(text)['check']).route_checks
            strip = lambda cs: [{k: v for k, v in c.__dict__.items() if k != 'legacy'} for c in cs]
            self.assertEqual(strip(again), strip(cfg.route_checks))


class SelectTest(unittest.TestCase):
    NODES = [{'panel': 'main', 'name': 'Poland 1', 'ip': '1.1.1.1', 'profiles': ['p-eu', 'Default Vless EU']},
             {'panel': 'main', 'name': 'Russia MSK 2', 'ip': '2.2.2.2', 'profiles': ['p-ru', 'Default Vless RU']},
             {'panel': 'reserve', 'name': 'USA 1', 'ip': '3.3.3.3', 'profiles': ['p-us', 'VLESS USA']}]

    def test_by_profile_and_name(self):
        cfg = make_cfg(check=CHECKS)
        main, res = cfg.panels
        main.host_exit = {'LTE 3': 'Poland 1'}
        checks, hosts = links.combine([(main, [
            {'outbound': vless('1.1.1.1'), 'host': 'Польша', 'lite': False, 'skip': []},
            {'outbound': vless('2.2.2.2'), 'host': 'Москва 2', 'lite': False, 'skip': []},
            {'outbound': vless('2.2.2.2', port=8443), 'host': 'Америка', 'lite': False, 'skip': []},
            {'outbound': vless('9.9.9.9'), 'host': 'LTE 3', 'lite': False, 'skip': ['psiphon']},
            {'outbound': vless('8.8.8.8'), 'host': 'Неизвестный', 'lite': False, 'skip': []},
            {'outbound': vless('1.1.1.1', port=9443), 'host': 'Лёгкий', 'lite': True, 'skip': []}])],
            cfg.route_checks, self.NODES)
        by = {c['name']: c['checks'] for c in checks}
        self.assertEqual(by['Польша'], {'warp', 'psiphon'})        # профиль EU
        self.assertEqual(by['Москва 2'], set())                    # профиль RU — ничего
        self.assertEqual(by['Америка'], {'usa'})                   # по названию
        self.assertEqual(by['LTE 3'], {'warp'})                    # host_exit → Poland 1, Psiphon снят тегом
        self.assertEqual(by['Неизвестный'], set())                 # нода не нашлась
        self.assertEqual(by['Лёгкий'], set())

    def test_node_map(self):
        class Rw:
            def nodes(self):
                return [{'name': 'N', 'address': '1.1.1.1', 'configProfileUuid': 'u1'}, 'мусор']

            def config_profiles(self):
                return [{'uuid': 'u1', 'name': 'EU'}]

        class NoRight(Rw):
            def config_profiles(self):
                raise RuntimeError('403')
        cfg = make_cfg()
        nodes = links.node_map(cfg, {'main': Rw(), 'reserve': NoRight()}, {})
        self.assertEqual([(n['panel'], n['profiles']) for n in nodes],
                         [('main', ['EU', 'u1']), ('reserve', ['u1'])])   # без права — только UUID

    def test_refresh_files(self):
        cfg = make_cfg(check=CHECKS)
        main, res = cfg.panels
        with tempfile.TemporaryDirectory() as d:
            cfg.links_file = os.path.join(d, 'monitor.txt')
            cfg.links_file_xray = os.path.join(d, 'monitor-xray.txt')
            orig, orig_map = links.panel_links, links.node_map
            links.panel_links = lambda rw, p, rc=(), **k: [
                {'outbound': vless('1.1.1.1'), 'host': 'Польша', 'lite': False, 'skip': []},
                {'outbound': vless('2.2.2.2'), 'host': 'Америка', 'lite': False, 'skip': []}] if p.id == 'main' else []
            links.node_map = lambda *a, **k: self.NODES
            try:
                links.refresh(cfg, {'main': None, 'reserve': None})
            finally:
                links.panel_links, links.node_map = orig, orig_map
            names = lambda f: [c['remarks'] for c in read(os.path.join(d, f), True)]
            self.assertEqual(names('monitor-warp.txt'), ['Польша'])
            self.assertEqual(names('monitor-usa.txt'), ['Америка'])
            self.assertEqual(names('monitor-xray.txt'), ['Польша', 'Америка'])


class RenderChecksTest(unittest.TestCase):
    def test_checkers_and_ports(self):
        cfg = make_cfg(check=CHECKS)
        self.assertEqual(render.checkers(cfg), [('xray', 'На ноду', 2112, 21000), ('entry', 'Через вход', 2121, 30000),
                                                 ('warp', 'WARP', 2113, 22000),
                                                 ('psiphon', 'Psiphon', 2114, 23000),
                                                 ('usa', 'Каскад в США', 2115, 24000)])
        self.assertEqual(port_ranges(cfg), [(21000, 21999), (30000, 30999), (22000, 22999), (23000, 23999),
                                            (24000, 24999)])
        targets = render.prometheus(cfg)['scrape_configs'][1]['static_configs']
        self.assertEqual([t['labels']['check'] for t in targets], ['xray', 'entry', 'warp', 'psiphon', 'usa'])

    def test_rules(self):
        cfg = make_cfg(check=CHECKS + [{'id': 'direct', 'url': 'https://a.b', 'egress': 'node'}])
        rules = {r['uid']: r for r in render.rules(cfg)['groups'][0]['rules']}
        for uid in ('rwmon-warp-down', 'rwmon-warp-egress', 'rwmon-psiphon-down', 'rwmon-psiphon-bypass',
                    'rwmon-usa-down', 'rwmon-usa-egress', 'rwmon-direct-down', 'rwmon-direct-direct'):
            self.assertIn(uid, rules)
        self.assertNotIn('rwmon-warp-bypass', rules)              # у WARP ждём сеть, а не «не с ноды»
        expr = lambda uid: rules[uid]['data'][0]['model']['expr']
        self.assertIn('rwmon_exit_info{asn!~`13335`}', expr('rwmon-warp-egress'))
        self.assertIn('rwmon_exit_info{country!~`US`}', expr('rwmon-usa-egress'))
        self.assertIn('unless on (ip) max by (ip) (rwmon_node_address)', expr('rwmon-direct-direct'))
        self.assertIn('Gemini не работает.', rules['rwmon-psiphon-down']['annotations']['description'])
        self.assertIn('rwmon_host{primary="1", usa="1"}', expr('rwmon-usa-down'))
        self.assertIn('xray_proxy_status{check="usa"}', render.unchecked(cfg))

    def test_render_files(self):
        cfg = make_cfg(check=CHECKS)
        with tempfile.TemporaryDirectory() as out:
            render.OUT = out
            render.SRC = os.path.join(os.path.dirname(__file__), '..', '..')
            render.render(cfg)
            self.assertEqual(sorted(os.listdir(os.path.join(out, 'checkers'))),
                             ['entry.env', 'psiphon.env', 'usa.env', 'warp.env', 'xray.env'])
            self.assertIn("SUBSCRIPTION_URL='file:///links/monitor-entry.txt'",
                          read(os.path.join(out, 'checkers', 'entry.env')))
            env = read(os.path.join(out, 'checkers', 'usa.env'))
            self.assertIn("XRAY_START_PORT='24000'", env)
            self.assertIn("SUBSCRIPTION_URL='file:///links/monitor-usa.txt'", env)
            dash = read(os.path.join(out, 'grafana', 'dashboards', 'files', 'remnawave-overview.json'), True)
            text = json.dumps(dash, ensure_ascii=False)
            self.assertIn('Каскад в США', text)
            self.assertIn('Каскад в США не работает', text)      # «Сейчас не работает» знает проверку
            prov = read(os.path.join(out, 'grafana', 'dashboards', 'dashboards.yml'), True)
            self.assertEqual(prov['providers'][0]['options']['path'], '/etc/rwmon/grafana/dashboards/files')

    def test_daily_names(self):
        self.assertEqual(daily.check_names(make_cfg(check=CHECKS))['usa'], 'Каскад в США')


class EgressTest(unittest.TestCase):
    def test_mmdb(self):
        r = mmdb.Reader(make_mmdb(ASN))
        self.assertEqual(r.get('104.28.1.2')['autonomous_system_number'], 13335)
        self.assertIsNone(r.get('9.9.9.9'))
        self.assertIsNone(r.get('2001:db8::1'))                   # IPv6 в базе IPv4
        with self.assertRaises(mmdb.MMDBError):
            mmdb.Reader(b'not a database')

    def test_update_and_lookup(self):
        cfg = make_cfg(check=CHECKS)
        blobs = {'country': gzip.compress(make_mmdb(COUNTRY)), 'asn': gzip.compress(make_mmdb(ASN))}
        calls = []

        def opener(req, timeout):
            calls.append(req.full_url)
            if '-asn-' in req.full_url and len([c for c in calls if '-asn-' in c]) == 1:
                raise OSError('нет базы за этот месяц')           # первая попытка — этот месяц ещё не вышел
            return io.BytesIO(blobs['asn' if '-asn-' in req.full_url else 'country'])
        with tempfile.TemporaryDirectory() as d:
            cfg.data_dir = d
            state = {}
            egress.update(cfg, state, opener)
            self.assertTrue(all(os.path.exists(egress.path(cfg, k)) for k in egress.KINDS))
            self.assertEqual(len(calls), 3)                       # asn — со второй попытки (прошлый месяц)
            egress.update(cfg, state, opener)
            self.assertEqual(len(calls), 3)                       # свежие — не качаем снова
            look = egress.Lookup(cfg)
            self.assertEqual(look.get('104.28.1.2'), ('US', 13335, 'Cloudflare, Inc.'))
            self.assertEqual(look.get('9.9.9.9'), ('', 0, ''))

            class Prom:
                def query(self, expr):
                    return [({'ip': '104.28.1.2'}, 1), ({'ip': '5.6.7.8'}, 1)]
            lines = exporter.Lines()
            exporter.exit_lines(Prom(), look, lines, {})
            text = lines.text()
            self.assertIn('rwmon_exit_info{ip="104.28.1.2",country="US",asn="13335",as_org="Cloudflare, Inc."} 1', text)
            self.assertIn('country="NL",asn="60068"', text)

    def test_update_fail_keeps_old(self):
        cfg = make_cfg(check=CHECKS)
        with tempfile.TemporaryDirectory() as d:
            cfg.data_dir = d
            state = {}
            egress.update(cfg, state, lambda req, timeout: (_ for _ in ()).throw(OSError('нет сети')))
            self.assertFalse(os.path.exists(egress.path(cfg, 'asn')))
            self.assertIn('geoip:asn:retry', state)               # следующая попытка — позже
            self.assertIsNone(egress.Lookup(cfg).get('1.1.1.1'))  # баз нет — ничего не знаем

    def test_not_needed(self):
        self.assertFalse(egress.needed(make_cfg()))
        self.assertTrue(egress.needed(make_cfg(check=CHECKS)))


if __name__ == '__main__':
    unittest.main()
