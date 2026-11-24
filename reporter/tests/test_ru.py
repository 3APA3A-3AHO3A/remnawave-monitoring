"""Проверка «Из РФ» ([ru] via): цепочка через хост в РФ и проверка сервера в обход входа."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from test_rwmon import make_cfg, vless                     # noqa: E402

from rwmon import config, daily, exporter, links, render   # noqa: E402

RU = {'via': ['Москва 1', 'Москва 2']}


def hysteria(host, port):
    return {'tag': 'proxy', 'protocol': 'hysteria',
            'settings': {'address': host, 'port': port, 'version': 2},
            'streamSettings': {'network': 'hysteria', 'security': 'tls',
                               'tlsSettings': {'serverName': 'origin.example', 'alpn': ['h3']}}}


class Rw:
    """Панель: хост LTE 3 ведёт через прокладку 9.9.9.9:20009 на CDN 1 (5.5.5.5:443, TLS),
    LTE 1 — через CDN на inbound без шифрования (за nginx), Польша — прямо на ноду."""
    class panel:
        id, title = 'main', 'Основная'

    def hosts(self):
        return [
            {'remark': 'LTE 3', 'nodes': ['n-cdn1'], 'inbound': {'configProfileInboundUuid': 'ib-hy'}},
            {'remark': 'LTE 1', 'nodes': ['n-cdn1'], 'inbound': {'configProfileInboundUuid': 'ib-xhttp'}},
            {'remark': 'Польша', 'nodes': [{'uuid': 'n-pl'}], 'inbound': {'configProfileInboundUuid': 'ib-vless'}},
        ]

    def nodes(self):
        return [{'uuid': 'n-cdn1', 'address': '5.5.5.5'}, {'uuid': 'n-pl', 'address': '1.1.1.1'}]

    def config_profiles(self):
        return [{'uuid': 'p', 'name': 'CDN', 'inbounds': [
            {'uuid': 'ib-hy', 'port': 443, 'security': 'tls'},
            {'uuid': 'ib-xhttp', 'port': 4443, 'security': 'none'},
            {'uuid': 'ib-vless', 'port': 443, 'security': 'reality'}]}]


class RuTest(unittest.TestCase):
    def test_config(self):
        self.assertEqual(make_cfg(ru=RU).ru_via, ['Москва 1', 'Москва 2'])
        self.assertEqual(make_cfg().ru_via, [])
        with self.assertRaises(config.ConfigError):
            make_cfg(ru={'via': [1]})

    def test_node_targets(self):
        t = links.node_targets(Rw(), {'LTE 3', 'LTE 1', 'Польша'}, {})
        # LTE 1 — inbound без шифрования (за nginx/CDN), напрямую не подключиться
        self.assertEqual(t, {'LTE 3': ('5.5.5.5', 443), 'Польша': ('1.1.1.1', 443)})

    def test_node_targets_no_right(self):
        class NoRight(Rw):
            def hosts(self):
                raise RuntimeError('403')
        self.assertEqual(links.node_targets(NoRight(), {'LTE 3'}, {}), {})

    def test_panel_links_bypass(self):
        class Panel(Rw):
            def user_by_username(self, name):
                return {'shortUuid': 's'}

            def raw_subscription(self, short):
                meta = lambda r, t: {'finalRemark': r, 'metadata': {'remark': r, 'tags': t}}
                return {'resolvedProxyConfigs': [meta('LTE 3', ['MONITORING_LITE']), meta('Польша', ['MONITORING'])]}

            def json_subscription(self, short):
                return [{'remarks': 'LTE 3', 'outbounds': [hysteria('9.9.9.9', 20009)]},
                        {'remarks': 'Польша', 'outbounds': [vless('1.1.1.1')]}]
        p = make_cfg().panels[0]
        entries = {e['host']: e for e in links.panel_links(Panel(), p, bypass=True, state={})}
        # LTE 3 ведёт через прокладку — напрямую на CDN 1; Польша и так ведёт на ноду
        self.assertEqual(links.server_of(entries['LTE 3']['direct']), ('5.5.5.5', 443))
        self.assertNotIn('direct', entries['Польша'])
        self.assertNotIn('direct', {e['host']: e for e in links.panel_links(Panel(), p)}['LTE 3'])

    def test_set_server(self):
        self.assertEqual(links.server_of(links.set_server(hysteria('9.9.9.9', 20009), '5.5.5.5', 443)),
                         ('5.5.5.5', 443))
        self.assertEqual(links.server_of(links.set_server(vless('9.9.9.9'), '5.5.5.5', 8443)),
                         ('5.5.5.5', 8443))

    def test_refresh(self):
        cfg = make_cfg(ru=RU)
        with tempfile.TemporaryDirectory() as d:
            cfg.links_file = os.path.join(d, 'monitor.txt')
            cfg.links_file_xray = os.path.join(d, 'monitor-xray.txt')
            entries = {'main': [
                {'outbound': vless('7.7.7.1'), 'host': 'Москва 1', 'lite': False, 'skip': []},
                {'outbound': vless('7.7.7.2'), 'host': 'Москва 2', 'lite': False, 'skip': []},
                {'outbound': hysteria('9.9.9.9', 20009), 'host': 'LTE 3', 'lite': True, 'skip': [],
                 'direct': hysteria('5.5.5.5', 443)},
            ], 'reserve': []}
            orig = links.panel_links
            links.panel_links = lambda rw, p, rc=(), **k: entries[p.id]
            try:
                links.refresh(cfg, {'main': None, 'reserve': None})
            finally:
                links.panel_links = orig
            with open(os.path.join(d, 'monitor-ruclient.txt'), encoding='utf-8') as f:
                ru = {c['remarks']: c for c in json.load(f)}
            with open(cfg.links_file_xray, encoding='utf-8') as f:
                xray = {c['remarks']: c for c in json.load(f)}
        # Москва 1 через себя не проверяется — через Москву 2
        self.assertEqual(links.server_of(ru['Москва 1']['outbounds'][1]), ('7.7.7.2', 443))
        self.assertEqual(ru['Москва 1']['outbounds'][1]['tag'], 'rwmon-via')
        # из РФ — через вход (прокладку), с сервера мониторинга — напрямую на ноду
        self.assertEqual(links.server_of(ru['LTE 3']['outbounds'][0]), ('9.9.9.9', 20009))
        self.assertEqual(links.server_of(ru['LTE 3']['outbounds'][1]), ('7.7.7.1', 443))
        self.assertEqual(links.server_of(xray['LTE 3']['outbounds'][0]), ('5.5.5.5', 443))
        via = {h['name']: h['ru_via'] for h in links.HOSTS}
        self.assertEqual(via, {'Москва 1': '7.7.7.2:443', 'Москва 2': '7.7.7.1:443', 'LTE 3': '7.7.7.1:443'})
        # метки rwmon_host: ru="1" и адрес посредника
        lines = exporter.Lines()
        exporter.host_lines(links.HOSTS, lines, cfg.panels, state={})
        text = lines.text()
        self.assertIn('ruclient="1"', text)
        self.assertIn('ru_via="7.7.7.1:443"', text)

    def test_render(self):
        cfg = make_cfg(ru=RU)
        self.assertEqual(render.checkers(cfg)[-1][:2], ('ruclient', 'Клиент из РФ'))
        text = json.dumps(render.rules(cfg), ensure_ascii=False)
        self.assertIn('rwmon-ru-down', text)
        self.assertIn('check=\\"ruclient\\"', text)
        self.assertEqual(daily.check_names(cfg)['ruclient'], 'Клиент из РФ')
        self.assertIn("PROXY_CHECK_METHOD='status'", render.checker_env(cfg, 'ruclient', 2115, 24000, cfg.url_xray))
        # без [ru] — как раньше
        plain = make_cfg()
        self.assertNotIn('ruclient', [c[0] for c in render.checkers(plain)])
        self.assertNotIn('rwmon-ru-down', json.dumps(render.rules(plain), ensure_ascii=False))


if __name__ == '__main__':
    unittest.main()
