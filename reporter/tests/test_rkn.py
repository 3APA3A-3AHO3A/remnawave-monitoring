"""Блокировки РФ ([rkn]): что проверяем, как читаем ответ cheburcheck, что попадает в алерт и сводку."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from test_rwmon import make_cfg                            # noqa: E402

from rwmon import config, daily, exporter, links, render, rkn   # noqa: E402

CLEAN = {'blocked': False, 'blocked_subnets': [], 'cdn_providers': {}}
SUBNET = {'blocked': True, 'blocked_subnets': ['1.2.3.0/24'], 'cdn_providers': {}}
RKN = {'blocked': True, 'rkn_domain': 'bad.example', 'blocked_subnets': [], 'cdn_providers': {}}


class Rw:
    def __init__(self, nodes):
        self._nodes = nodes

    def nodes(self):
        return self._nodes


class RknTest(unittest.TestCase):
    def setUp(self):
        self.sleep, rkn.time.sleep = rkn.time.sleep, lambda s: None
        self.domains = links.DOMAINS

    def tearDown(self):
        rkn.time.sleep = self.sleep
        links.DOMAINS = self.domains

    def cfg(self, **kw):
        cfg = make_cfg(rkn={'interval_hours': 6, 'extra': ['extra.example'], **kw})
        cfg.data_dir = tempfile.mkdtemp()
        return cfg

    def test_config(self):
        cfg = self.cfg()
        self.assertTrue(cfg.rkn_enabled)
        self.assertEqual(cfg.rkn_interval, 6 * 3600)
        self.assertFalse(make_cfg().rkn_enabled)
        with self.assertRaises(config.ConfigError):
            make_cfg(rkn={'interval_hours': 0})

    def test_host_of(self):
        self.assertEqual(rkn.host_of('cdn.example.com:443'), 'cdn.example.com')
        self.assertEqual(rkn.host_of('https://Panel.Example.com/sub/x'), 'panel.example.com')
        self.assertEqual(rkn.host_of('[2001:db8::1]:443'), '2001:db8::1')
        self.assertEqual(rkn.host_of('1.2.3.4'), '1.2.3.4')

    def test_verdict(self):
        cf = {'blocked': True, 'cdn_providers': {'cloudflare': ['104.16.0.0/13']}}
        self.assertEqual(rkn.verdict('node', CLEAN), (False, '', ''))
        self.assertEqual(rkn.verdict('node', SUBNET), (True, 'подсеть в списках: 1.2.3.0/24', ''))
        self.assertEqual(rkn.verdict('domain', RKN), (True, 'домен в реестре РКН', ''))
        # IP ноды в сети заблокированного CDN — тревога; домен за таким CDN — только пометка
        self.assertEqual(rkn.verdict('node', cf), (True, 'IP в сети заблокированного CDN: cloudflare', 'cloudflare'))
        self.assertEqual(rkn.verdict('domain', cf), (False, '', 'cloudflare'))
        self.assertEqual(rkn.verdict('domain', {'blocked': True}), (True, 'в списках блокировок', ''))
        self.assertEqual(rkn.verdict('domain', {'blocked': False, 'cdn_providers': {'cloudflare': ['x']}}),
                         (False, '', ''))

    def test_targets(self):
        cfg = self.cfg()
        links.DOMAINS = ['cdn.example.com', 'gateway.example.com']
        clients = {cfg.panels[0].id: Rw([
            {'name': 'Sweden 1', 'address': '5.5.5.5'},
            {'name': 'Panel', 'address': '172.18.0.1'},           # внутренний адрес — пропускаем
            {'name': 'Off', 'address': '6.6.6.6', 'isDisabled': True}]),
            cfg.panels[1].id: Rw([{'name': 'Sweden 1 R', 'address': '5.5.5.5'}])}
        got = {t['target']: t for t in rkn.targets(cfg, clients)}
        self.assertEqual(got['5.5.5.5'], {'target': '5.5.5.5', 'kind': 'node', 'name': 'Sweden 1 / Sweden 1 R'})
        self.assertNotIn('172.18.0.1', got)
        self.assertNotIn('6.6.6.6', got)
        for d in ('cdn.example.com', 'gateway.example.com', 'extra.example'):
            self.assertEqual(got[d]['kind'], 'domain')
        cfg.rkn_exclude = ['Sweden 1 R', 'gateway.example.com']   # по названию ноды и по домену
        got = {t['target'] for t in rkn.targets(cfg, clients)}
        self.assertEqual(got, {'cdn.example.com', 'extra.example'})

    def test_run_alert_and_report(self):
        cfg = self.cfg()
        links.DOMAINS = ['bad.example', 'cf.example']
        clients = {cfg.panels[0].id: Rw([{'name': 'Sweden 1', 'address': '5.5.5.5'}]),
                   cfg.panels[1].id: Rw([])}
        answers = {'5.5.5.5': SUBNET, 'bad.example': RKN,
                   'cf.example': {'blocked': True, 'cdn_providers': {'cloudflare': ['104.16.0.0/13']}}}

        def check(t):
            if t == 'extra.example':
                raise OSError('timeout')
            return answers[t]
        data = rkn.run(cfg, clients, check)
        self.assertEqual(rkn.load_last(cfg)['items'], data['items'])
        lines = exporter.Lines()
        exporter.rkn_lines(data, lines)
        text = lines.text()
        self.assertIn('name="Sweden 1 · 5.5.5.5"', text)
        self.assertIn('why="подсеть в списках: 1.2.3.0/24"', text)
        self.assertNotIn('extra.example', text)                  # не проверен — строки нет
        section = '\n'.join(rkn.telegram_section(data))
        self.assertIn('нода Sweden 1', section)
        self.assertIn('домен bad.example', section)
        self.assertIn('не проверены: 1', section)
        self.assertIn('за заблокированным CDN (cloudflare), на Reality не влияет: cf.example', section)
        self.assertIn('target="cf.example"', text)
        self.assertNotIn('домен cf.example', section)
        rules = json.dumps(render.rules(cfg), ensure_ascii=False)
        self.assertIn('rwmon-rkn-blocked', rules)
        self.assertNotIn('rwmon-rkn-blocked', json.dumps(render.rules(make_cfg()), ensure_ascii=False))
        self.assertEqual(daily.check_names(cfg)['xray'], 'На ноду')

    def test_retry_429(self):
        import urllib.error
        calls = []

        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return b'{"blocked": false}'

        def urlopen(req, timeout=None):
            calls.append(1)
            if len(calls) == 1:
                raise urllib.error.HTTPError(req.full_url, 429, 'Too Many Requests', {}, None)
            return Resp()
        orig, rkn.urllib.request.urlopen = rkn.urllib.request.urlopen, urlopen
        try:
            self.assertEqual(rkn._get('/check?target=x'), {'blocked': False})
        finally:
            rkn.urllib.request.urlopen = orig
        self.assertEqual(len(calls), 2)

    def test_run_all_failed(self):
        cfg = self.cfg()
        links.DOMAINS = []
        clients = {p.id: Rw([]) for p in cfg.panels}

        def check(t):
            raise OSError('down')
        with self.assertRaises(RuntimeError):
            rkn.run(cfg, clients, check)

    def test_clean_section(self):
        data = {'time': '2026-11-25 06:00', 'items': [dict(target='5.5.5.5', kind='node', name='S', ok=True,
                                                           blocked=False, why='')]}
        self.assertIn('ни один из 1 адресов не в списках', '\n'.join(rkn.telegram_section(data)))

    def test_client_domains(self):
        p = make_cfg().panels[0]
        ob = {'protocol': 'vless', 'settings': {'vnext': [{'address': 'cdn.example.com', 'port': 443}]},
              'streamSettings': {'realitySettings': {'serverName': 'Gateway.Example.com'}}}
        ip = {'protocol': 'vless', 'settings': {'vnext': [{'address': '1.1.1.1', 'port': 443}]}}
        got = links.client_domains([(p, [{'outbound': ob}, {'outbound': ip}])])
        self.assertEqual(got, ['cdn.example.com', 'gateway.example.com'])


if __name__ == '__main__':
    unittest.main()
