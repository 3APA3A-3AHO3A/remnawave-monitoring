"""Проверка из РФ (3.0): пробы проверяют хосты сами, сервер мониторинга — через вход и на ноду,
итог по хосту, связь с пробами по HTTPS (feed.py)."""
import base64
import json
import os
import ssl
import sys
import tempfile
import time
import unittest
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from test_rwmon import make_cfg, vless                     # noqa: E402

from rwmon import daily, exporter, feed, links, render     # noqa: E402

PROBES = [{'name': 'msk-1', 'url': 'https://7.7.7.1:9115', 'user': 'rwmon', 'password': 'p1'},
          {'name': 'msk-2', 'url': 'https://7.7.7.2:9115', 'user': 'rwmon', 'password': 'p2'}]


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
        cfg = make_cfg(probe=PROBES)
        self.assertEqual([p.host for p in cfg.probes], ['7.7.7.1', '7.7.7.2'])
        self.assertEqual(cfg.ru_port, 9116)
        self.assertFalse(cfg.ru_legacy)
        self.assertTrue(make_cfg(ru={'via': ['Москва 1']}).ru_legacy)   # старый блок не ломает запуск
        self.assertEqual(make_cfg(checks={'ru_port': 9200}).ru_port, 9200)

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

    def refresh(self, cfg, d):
        """Москва 1/2 ведут на сами пробы, LTE 3 — через прокладку на CDN 1, Польша — прямо на ноду."""
        cfg.links_file = os.path.join(d, 'monitor.txt')
        cfg.links_file_xray = os.path.join(d, 'monitor-xray.txt')
        entries = {'main': [
            {'outbound': vless('7.7.7.1'), 'host': 'Москва 1', 'lite': False, 'skip': [],
             'server_ip': '7.7.7.1', 'node_ip': '7.7.7.1'},
            {'outbound': vless('7.7.7.2'), 'host': 'Москва 2', 'lite': False, 'skip': [], 'server_ip': '7.7.7.2'},
            {'outbound': hysteria('9.9.9.9', 20009), 'host': 'LTE 3', 'lite': True, 'skip': [],
             'server_ip': '9.9.9.9', 'node_ip': '5.5.5.5', 'direct': hysteria('5.5.5.5', 443)},
            {'outbound': vless('1.1.1.1'), 'host': 'Польша', 'lite': False, 'skip': [], 'server_ip': '1.1.1.1'},
        ], 'reserve': []}
        orig = links.panel_links
        links.panel_links = lambda rw, p, rc=(), **k: entries[p.id]
        try:
            links.refresh(cfg, {'main': None, 'reserve': None})
        finally:
            links.panel_links = orig

        def load(name):
            with open(os.path.join(d, name), encoding='utf-8') as f:
                return {c['remarks']: c for c in json.load(f)}
        return load

    def test_refresh(self):
        cfg = make_cfg(probe=PROBES)
        with tempfile.TemporaryDirectory() as d:
            load = self.refresh(cfg, d)
            ru, xray, entry = load('ru-hosts.json'), load('monitor-xray.txt'), load('monitor-entry.txt')
            self.assertFalse(os.path.exists(os.path.join(d, 'monitor-ruclient.txt')))
        # из РФ — как в подписке (LTE 3 через прокладку); МСК-ноды из РФ не проверяются
        self.assertEqual(sorted(ru), ['LTE 3', 'Польша'])
        self.assertEqual(links.server_of(ru['LTE 3']['outbounds'][0]), ('9.9.9.9', 20009))
        self.assertEqual(len(ru['LTE 3']['outbounds']), 1)          # без посредников
        # с сервера мониторинга: «на ноду» — напрямую на CDN 1, «через вход» — только у LTE 3
        self.assertEqual(links.server_of(xray['LTE 3']['outbounds'][0]), ('5.5.5.5', 443))
        self.assertEqual(sorted(xray), ['LTE 3', 'Москва 1', 'Москва 2', 'Польша'])
        self.assertEqual(list(entry), ['LTE 3'])
        self.assertEqual(links.server_of(entry['LTE 3']['outbounds'][0]), ('9.9.9.9', 20009))
        flags = {h['name']: (h['entry'], h['ru']) for h in links.HOSTS}
        self.assertEqual(flags, {'Москва 1': (False, False), 'Москва 2': (False, False),
                                 'LTE 3': (True, True), 'Польша': (False, True)})
        lines = exporter.Lines()
        exporter.host_lines(links.HOSTS, lines, cfg.panels, state={})
        self.assertIn('host="LTE 3",name="LTE 3",lite="1",address="9.9.9.9:20009",owner="main",primary="1",'
                      'warp="0",psiphon="0",entry="1",ru="1"} 1', lines.text())

    def test_refresh_without_probes(self):
        cfg = make_cfg()
        with tempfile.TemporaryDirectory() as d:
            self.refresh(cfg, d)
            self.assertFalse(os.path.exists(os.path.join(d, 'ru-hosts.json')))
        self.assertFalse(any(h['ru'] for h in links.HOSTS))

    def test_host_state(self):
        relay, plain = {'entry': True}, {'entry': False}
        S = exporter
        self.assertEqual(S.host_state(relay, 1, 0, 0), S.OK)                  # из РФ работает — всё
        self.assertEqual(S.host_state(relay, 0, 1, 1), S.RU_BLOCKED)          # вход и нода живы
        self.assertEqual(S.host_state(relay, 0, 1, 0), S.ENTRY_DOWN)
        self.assertEqual(S.host_state(relay, 0, 1, 0, entry_seen=False), S.ENTRY_UNSEEN)
        self.assertEqual(S.host_state(relay, 0, 0, 0), S.NODE_DOWN)
        self.assertEqual(S.host_state(plain, 0, 1, 1), S.RU_BLOCKED)
        self.assertEqual(S.host_state(plain, None, 0, 0), S.NODE_DOWN)        # МСК-нода, проверка с сервера
        self.assertEqual(S.host_state(plain, None, 1, 1), S.OK)
        self.assertEqual(S.host_state(relay, None, 1, 0), S.ENTRY_DOWN)       # пробы молчат — по серверу
        self.assertEqual(S.host_state(relay, None, 1, 0, entry_seen=False), S.OK)
        self.assertEqual(S.host_state(relay, 0, None, None), S.RU_BLOCKED)    # с сервера данных нет

    def test_ru_and_state_lines(self):
        cfg = make_cfg(probe=PROBES)
        store = feed.Store()
        now = time.time()
        store.put('msk-1', {'LTE 3': {'status': 0, 'error_code': 2}, 'Польша': {'status': 1, 'latency_ms': 80}},
                  now=now - 30)
        store.put('msk-2', {'LTE 3': {'status': 1}}, now=now - 600)         # давно молчит — не в счёт
        lines = exporter.Lines()
        fresh = exporter.ru_lines(cfg, store, lines, now=now)
        self.assertEqual(list(fresh), ['msk-1'])
        text = lines.text()
        self.assertIn('rwmon_ru_probe_up{probe="msk-1"} 1', text)
        self.assertIn('rwmon_ru_probe_up{probe="msk-2"} 0', text)
        self.assertIn('rwmon_ru_status{probe="msk-1",name="LTE 3"} 0', text)
        self.assertIn('rwmon_ru_latency_ms{probe="msk-1",name="Польша"} 80', text)
        self.assertNotIn('probe="msk-2",name=', text)
        hosts = [{'name': 'LTE 3', 'entry': True, 'ru': True}, {'name': 'LTE 3', 'entry': True, 'ru': True},
                 {'name': 'Польша', 'entry': False, 'ru': True}, {'name': 'Москва 1', 'entry': False, 'ru': False},
                 {'name': 'Новый', 'entry': False, 'ru': True}]
        nl = {('xray', 'LTE 3'): 1, ('entry', 'LTE 3'): 0, ('xray', 'Польша'): 1, ('xray', 'Москва 1'): 0}
        lines = exporter.Lines()
        exporter.state_lines(hosts, fresh, nl, {'LTE 3'}, lines)
        text = lines.text()
        self.assertIn('rwmon_host_state{name="LTE 3"} 4', text)          # прокладку из-за границы не видно
        self.assertIn('rwmon_host_state{name="Польша"} 0', text)
        self.assertIn('rwmon_host_state{name="Москва 1"} 3', text)
        self.assertNotIn('name="Новый"', text)                           # результатов ещё нет
        self.assertEqual(text.count('name="LTE 3"'), 1)                  # одна строка на имя

    def test_parse_metrics(self):
        text = (
            '# HELP xray_proxy_status x\n'
            'xray_proxy_status{address="9.9.9.9:20009",name="🇷🇺 LTE 3",protocol="hysteria",stable_id="a"} 0\n'
            'xray_proxy_status{name="🇷🇺 LTE 3",stable_id="b"} 1\n'           # две серии — берём лучшую
            'xray_proxy_latency_ms{name="Кав\\"ычки",stable_id="c"} 120\n'
            'xray_proxy_error_code{name="🇷🇺 LTE 3"} 2\n'
            f'xray_proxy_status{{name="{links.EMPTY_NAME}"}} 0\n'
            'go_goroutines 12\n')
        out = feed.parse_metrics(text)
        self.assertEqual(out['🇷🇺 LTE 3'], {'status': 1.0, 'error_code': 2.0})
        self.assertEqual(out['Кав"ычки'], {'latency_ms': 120.0})
        self.assertNotIn(links.EMPTY_NAME, out)

    def test_who(self):
        cfg = make_cfg(probe=PROBES)
        auth = lambda u, p: 'Basic ' + base64.b64encode(f'{u}:{p}'.encode()).decode()
        self.assertEqual(feed.who(cfg, auth('rwmon', 'p2')), 'msk-2')
        self.assertIsNone(feed.who(cfg, auth('rwmon', 'nope')))
        self.assertIsNone(feed.who(cfg, auth('other', 'p1')))
        self.assertIsNone(feed.who(cfg, 'Bearer x'))
        self.assertIsNone(feed.who(cfg, None))

    def test_feed_https(self):
        """Настоящий HTTPS: проба берёт список и присылает результаты; чужой пароль — 401."""
        cfg = make_cfg(probe=PROBES)
        with tempfile.TemporaryDirectory() as d:
            cfg.data_dir = d
            cfg.links_file = os.path.join(d, 'monitor.txt')
            links.write_if_changed(links.ru_file(cfg), links.dump([links.check_config('A', vless('1.1.1.1'))]))
            cfg.ru_port = 0                                   # свободный порт
            store = feed.Store()
            server = feed.start(cfg, store)
            port = server.server_address[1]
            self.assertTrue(feed.pin(feed.cert_paths(cfg)[0]).startswith('sha256//'))
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE

            def call(path, password, data=None):
                req = urllib.request.Request(f'https://127.0.0.1:{port}{path}', data=data, headers={
                    'Authorization': 'Basic ' + base64.b64encode(f'rwmon:{password}'.encode()).decode()})
                try:
                    with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
                        return r.status, r.read()
                except urllib.error.HTTPError as e:
                    return e.code, b''
            try:
                status, body = call('/ru/hosts.json', 'p1')
                self.assertEqual(status, 200)
                self.assertEqual([c['remarks'] for c in json.loads(body)], ['A'])
                self.assertEqual(call('/ru/hosts.json', 'bad')[0], 401)
                self.assertEqual(call('/x', 'p1')[0], 404)
                status, _ = call('/ru/metrics', 'p2', b'xray_proxy_status{name="A"} 1\n')
                self.assertEqual(status, 204)
                data, seen = store.snapshot()
                self.assertEqual(data['msk-2'][1], {'A': {'status': 1.0}})
                self.assertIn('msk-1', seen)
            finally:
                server.shutdown()

    def test_render(self):
        cfg = make_cfg(probe=PROBES)
        self.assertEqual([c[0] for c in render.checkers(cfg)], ['xray', 'entry', 'warp', 'psiphon'])
        rules = {r['uid']: r for r in render.rules(cfg)['groups'][0]['rules']}
        expr = rules['rwmon-xray-down']['data'][0]['model']['expr']
        self.assertIn('rwmon_host_state', expr)
        self.assertEqual(rules['rwmon-xray-down']['title'], 'Хост не работает')
        self.assertIn('блокировка в РФ?', rules['rwmon-xray-down']['annotations']['reason'])
        self.assertIn('rwmon_ru_probe_up', rules['rwmon-probe-down']['data'][0]['model']['expr'])
        for gone in ('rwmon-ru-down', 'rwmon-probe-blocked'):
            self.assertNotIn(gone, rules)
        jobs = [j['job_name'] for j in render.prometheus(cfg)['scrape_configs']]
        self.assertIn('probe-msk-1-http', jobs)
        self.assertFalse(any(j.endswith('-tcp') for j in jobs))   # TCP-пробы убраны
        self.assertIn("PROXY_CHECK_METHOD='status'", render.checker_env(cfg, 'entry', 2121, 30000, cfg.url_xray))
        self.assertEqual(daily.check_names(cfg)['entry'], 'Через вход')
        self.assertNotIn('rwmon-probe-down', {r['uid'] for r in render.rules(make_cfg())['groups'][0]['rules']})


if __name__ == '__main__':
    unittest.main()
