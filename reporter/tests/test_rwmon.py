"""Тесты без сети:  cd reporter && python -m unittest discover tests"""
import base64
import json
import unittest

from rwmon import geocheck, links
from rwmon.clients import split_message
from rwmon.config import _headers

REPORT = {
    'schema': 1,
    'identity': {'ipv4': '45.154.58.229', 'asn': 203273, 'as_name': 'NetCraftersOU'},
    'reputation': {'type': 'Business', 'risk': 0, 'city': 'Madrid', 'country_code': 'ES'},
    'consensus': {'ipv4': [{'code': 'SC', 'country': 'Seychelles', 'count': 12, 'total': 30, 'percent': 40.0}]},
    'geo': {
        'services': [
            {'id': 'google', 'name': 'Google', 'kind': 'country', 'ipv4': {'value': 'sc', 'country': 'Seychelles'}},
            {'id': 'yt_premium', 'name': 'YouTube Premium', 'kind': 'availability', 'ipv4': {'value': 'blocked'}},
            {'id': 'reddit', 'name': 'Reddit', 'kind': 'country', 'ipv4': {'error': 'timeout'}},
        ],
        'geoip': [{'id': 'maxmind', 'name': 'maxmind.com', 'kind': 'country', 'ipv4': {'value': 'SC'}}],
        'cdn': [],
    },
    'stash_checks': [
        {'id': 'netflix', 'name': 'Netflix', 'state': 'available', 'region': 'de'},
        {'id': 'claude', 'name': 'Claude', 'state': 'error', 'error': 'challenge'},
    ],
}


class GeocheckTest(unittest.TestCase):
    def test_summarize(self):
        s = geocheck.summarize(REPORT)
        self.assertEqual(s['ip'], '45.154.58.229')
        self.assertEqual(s['network'], 'AS203273 NetCraftersOU')
        self.assertEqual(s['consensus'], 'SC 40%')
        self.assertEqual(s['checks']['services:google']['value'], 'SC')
        self.assertEqual(s['checks']['stash:netflix']['value'], 'available (DE)')
        self.assertNotIn('services:reddit', s['checks'])      # ошибки не сравниваем
        self.assertNotIn('stash:claude', s['checks'])

    def test_compare_and_attention(self):
        old = geocheck.summarize(REPORT)
        new_report = json.loads(json.dumps(REPORT))
        new_report['geo']['services'][0]['ipv4']['value'] = 'RU'
        new_report['geo']['geoip'][0]['ipv4']['value'] = 'NL'
        new_report['reputation']['risk'] = 45
        new = geocheck.summarize(new_report)
        main, minor = geocheck.compare(old, new)
        self.assertIn(('Google', 'SC', 'RU'), main)
        self.assertIn(('Риск IP', '0', '45'), main)
        self.assertIn(('maxmind.com', 'SC', 'NL'), minor)
        self.assertEqual(geocheck.attention(new, {'RU'}), ['Google видит RU'])
        self.assertEqual(geocheck.compare(None, new), ([], []))

    def test_pick_nodes(self):
        nodes = [
            {'uuid': '1', 'name': 'Poland 1', 'isConnected': True, 'tags': []},
            {'uuid': '2', 'name': 'Moscow 1', 'isConnected': True, 'tags': ['RU-LIMIT']},
            {'uuid': '3', 'name': 'Off', 'isConnected': False},
            {'uuid': '4', 'name': 'Disabled', 'isConnected': True, 'isDisabled': True},
        ]
        picked = geocheck.pick_nodes(nodes, {'ru-limit'})
        self.assertEqual([n['uuid'] for n in picked], ['1'])


class LinksTest(unittest.TestCase):
    def test_remark(self):
        self.assertEqual(links.link_remark('vless://id@h:443?x=1#%F0%9F%87%B5%F0%9F%87%B1%20Poland%201'), '🇵🇱 Poland 1')
        vm = 'vmess://' + base64.b64encode(json.dumps({'ps': 'VM 1'}).encode()).decode().rstrip('=')
        self.assertEqual(links.link_remark(vm), 'VM 1')

    def test_hysteria_alpn(self):
        self.assertEqual(links.fix_link('hysteria2://a@1.2.3.4:443/?sni=x.com&fm=%7B%7D#%F0%9F%8E%AE'),
                         'hysteria2://a@1.2.3.4:443/?sni=x.com&fm=%7B%7D&alpn=h3#%F0%9F%8E%AE')
        self.assertEqual(links.fix_link('hy2://a@h:443#n'), 'hy2://a@h:443?alpn=h3#n')
        self.assertEqual(links.fix_link('hysteria2://a@h:443/?alpn=h3#n'), 'hysteria2://a@h:443/?alpn=h3#n')
        self.assertEqual(links.fix_link('vless://a@h:443?x=1#n'), 'vless://a@h:443?x=1#n')

    def test_select(self):
        raw = [
            {'finalRemark': 'Poland 1', 'metadata': {'remark': 'Poland 1', 'tags': ['BALANCER', 'MONITORING']}},
            {'finalRemark': 'LTE 1', 'metadata': {'remark': 'LTE 1', 'tags': ['LTE']}},
            {'finalRemark': 'Sweden 1', 'metadata': {'remark': 'Sweden 1', 'tags': ['MONITORING']}},
            {'finalRemark': 'Old', 'metadata': {'remark': 'Old', 'tags': ['MONITORING'], 'isDisabled': True}},
        ]
        keys = {'enabledKeys': ['vless://a@1:443#Poland%201', 'vless://b@2:443#LTE%201'], 'hiddenKeys': []}
        found, names, missing = links.select_links(raw, keys, 'MONITORING')
        self.assertEqual(found, ['vless://a@1:443#Poland%201'])
        self.assertEqual(names, ['Poland 1'])
        self.assertEqual(missing, ['Sweden 1'])


class MiscTest(unittest.TestCase):
    def test_split(self):
        text = '\n'.join(f'строка {i}' for i in range(1000))
        parts = split_message(text, 4000)
        self.assertTrue(all(len(p) <= 4000 for p in parts))
        self.assertEqual('\n'.join(parts), text)

    def test_headers(self):
        self.assertEqual(_headers('Cookie: a=1; b=2; X-Key: z'), {'Cookie': 'a=1; b=2', 'X-Key': 'z'})
        self.assertEqual(_headers(''), {})


if __name__ == '__main__':
    unittest.main()
