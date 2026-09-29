"""Тесты без сети:  cd reporter && python -m unittest discover tests"""
import base64
import json
import unittest

import os
import tempfile

from rwmon import config, exporter, geocheck, links, render
from rwmon.clients import ApiError, split_message

TG = {'bot_token': '1:x', 'chat_id': '-100'}


def make_cfg(**over):
    data = {
        'panel': [
            {'id': 'main', 'title': 'Основная', 'api_url': 'http://127.0.0.1:3000/', 'api_token': 't1',
             'exclude_nodes': ['Panel'], 'telegram': TG},
            {'id': 'reserve', 'title': 'Резерв', 'api_url': 'https://r.example', 'api_token': 't2',
             'telegram': {'bot_token': '2:y', 'chat_id': '-200'}},
        ],
        'alerts': {'outbound_tags': ['psiphon-out', 'WARP']},
    }
    data.update(over)
    return config.parse(data, env={})

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
        pairs, missing = links.select_links(raw, keys, 'MONITORING')
        self.assertEqual(pairs, [('vless://a@1:443#Poland%201', 'Poland 1')])
        self.assertEqual(missing, ['Sweden 1'])

    def test_combine(self):
        cfg = make_cfg()
        main, res = cfg.panels
        per_panel = [
            (main, [{'link': 'vless://u@1.1.1.1:443?fp=chrome#A', 'host': 'Швеция 1', 'lite': False},
                    {'link': 'vless://u@2.2.2.2:443#B', 'host': 'LTE 1', 'lite': True}]),
            (res, [{'link': 'vless://u@1.1.1.1:443?fp=chrome#X', 'host': 'Швеция 1', 'lite': False},
                   {'link': 'vless://u@2.2.2.2:443#Y', 'host': 'LTE 1', 'lite': False},
                   {'link': 'vless://u@3.3.3.3:443#Z', 'host': 'Швеция 1', 'lite': False}]),
        ]
        checks, hosts = links.combine(per_panel)
        self.assertEqual([c['name'] for c in checks], ['Швеция 1', 'LTE 1', 'Швеция 1 · Резерв'])
        self.assertFalse(checks[1]['lite'])              # в резерве полный — проверяем полностью
        self.assertEqual(links.link_remark(checks[0]['link']), 'Швеция 1')
        # один и тот же хост, у панелей разные fp и sni — проверяется один раз
        a = 'vless://u@1.1.1.1:443?type=tcp&security=reality&pbk=K&sni=a.com&fp=edge#A'
        b = 'vless://u@1.1.1.1:443?type=tcp&security=reality&pbk=K&sni=b.com&fp=firefox&sid=1#B'
        self.assertEqual(links.connection_key(a), links.connection_key(b))
        self.assertEqual(links.connection_key(a), links.connection_key(a.replace('u@', 'v@')))
        self.assertNotEqual(links.connection_key(a), links.connection_key(a.replace(':443', ':8443')))
        self.assertNotEqual(links.connection_key(a), links.connection_key(a.replace('pbk=K', 'pbk=Q')))
        self.assertEqual([(h['panel'], h['host'], h['name']) for h in hosts], [
            ('main', 'Швеция 1', 'Швеция 1'), ('main', 'LTE 1', 'LTE 1'),
            ('reserve', 'Швеция 1', 'Швеция 1'), ('reserve', 'LTE 1', 'LTE 1'),
            ('reserve', 'Швеция 1', 'Швеция 1 · Резерв')])
        self.assertTrue(hosts[1]['lite'])
        # одинаковое название у разных хостов одной панели
        checks, _ = links.combine([(main, [{'link': 'vless://a@1:1#n', 'host': 'N', 'lite': False},
                                           {'link': 'vless://a@2:1#n', 'host': 'N', 'lite': False}])])
        self.assertEqual([c['name'] for c in checks], ['N', 'N #2'])


class MiscTest(unittest.TestCase):
    def test_split(self):
        text = '\n'.join(f'строка {i}' for i in range(1000))
        parts = split_message(text, 4000)
        self.assertTrue(all(len(p) <= 4000 for p in parts))
        self.assertEqual('\n'.join(parts), text)
        long = ['a', 'x' * 25, 'b']                     # порядок сохраняется, пустых нет
        self.assertEqual(split_message('\n'.join(long), 10), ['a', 'x' * 10, 'x' * 10, 'x' * 5 + '\nb'])
        self.assertEqual(split_message('y' * 10 + '\nz', 10), ['y' * 10, 'z'])

    def test_ports(self):
        from rwmon.__main__ import ports_check
        with tempfile.TemporaryDirectory() as d:
            def put(rng, res):
                with open(os.path.join(d, 'ip_local_port_range'), 'w') as f:
                    f.write(rng)
                with open(os.path.join(d, 'ip_local_reserved_ports'), 'w') as f:
                    f.write(res)
            put('32768\t60999\n', '\n')
            self.assertEqual(ports_check(d), 'свободны')
            put('1024\t65000\n', '\n')
            with self.assertRaises(RuntimeError):
                ports_check(d)
            put('1024\t65000\n', '21000-21999,22000-23999\n')
            self.assertEqual(ports_check(d), 'закреплены за проверками')

    def test_migrate_quotes(self):
        import contextlib
        import io
        import tomllib
        from rwmon.__main__ import migrate
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            migrate({'RW_API_TOKEN': '"tok"', 'TG_BOT_TOKEN': "'1:x'", 'TG_CHAT_ID': '-1', 'RW_METRICS_PASS': 'p"w'})
        cfg = config.parse(tomllib.loads(buf.getvalue()), env={})
        self.assertEqual(cfg.panels[0].api_token, 'tok')
        self.assertEqual(cfg.panels[0].telegram.bot_token, '1:x')
        self.assertEqual(cfg.panels[0].metrics_password, 'p"w')

    def test_link_address(self):
        self.assertEqual(links.link_address('vless://u@1.2.3.4:8443?x=1#n'), '1.2.3.4:8443')
        self.assertEqual(links.link_address('hysteria2://p@5.6.7.8:20009/?a=1#n'), '5.6.7.8:20009')
        self.assertEqual(links.link_address('vless://u@cdn.x.org?type=ws#n'), 'cdn.x.org:443')
        self.assertTrue(links.is_udp('hysteria2://p@1.2.3.4:20009#n'))
        self.assertFalse(links.is_udp('vless://u@1.2.3.4:443#n'))

    def test_sites_probes(self):
        cfg = make_cfg(site=[{'url': 'https://fixerrorvpn.com'}, {'name': 'Панель', 'url': 'https://p.x/', 'keyword': 'Remnawave'}],
                       probe=[{'name': 'ru-msk', 'url': 'https://10.0.0.1:9115/', 'user': 'u', 'password': 'p'}])
        self.assertEqual([s.name for s in cfg.sites], ['fixerrorvpn.com', 'Панель'])
        self.assertEqual(cfg.probes[0].url, 'https://10.0.0.1:9115')
        for bad in ({'site': [{'url': 'fixerrorvpn.com'}]}, {'probe': [{'name': 'RU MSK', 'url': 'https://1.1.1.1:9115'}]}):
            with self.assertRaises(config.ConfigError):
                make_cfg(**bad)
        with tempfile.TemporaryDirectory() as d:
            cfg.links_file = os.path.join(d, 'monitor.txt')
            links.write_probe_targets(cfg, [{'address': '1.2.3.4:443'}, {'address': '1.2.3.4:443'}, {'address': ''},
                                            {'address': '5.6.7.8:20009', 'udp': True}])
            with open(os.path.join(d, 'probe-tcp.json')) as f:
                self.assertEqual(json.load(f), [{'targets': ['1.2.3.4:443'], 'labels': {}}])
            with open(os.path.join(d, 'probe-http.json')) as f:
                self.assertEqual(json.load(f)[1], {'targets': ['https://p.x/'],
                                                   'labels': {'site': 'Панель', 'module': 'http_2xx'}})

    def test_rename(self):
        self.assertEqual(links.rename('vless://a@h:443?x=1#Poland%201', ' · R'),
                         'vless://a@h:443?x=1#Poland%201%20%C2%B7%20R')
        vm = 'vmess://' + base64.b64encode(json.dumps({'ps': 'VM'}).encode()).decode()
        self.assertEqual(links.link_remark(links.rename(vm, ' · R')), 'VM · R')
        self.assertEqual(links.rename('vless://a@h#n', ''), 'vless://a@h#n')


class ConfigTest(unittest.TestCase):
    def test_parse(self):
        cfg = make_cfg()
        main, res = cfg.panels
        self.assertEqual(main.api_url, 'http://127.0.0.1:3000')
        self.assertEqual(main.host_suffix, '')
        self.assertEqual(res.host_suffix, ' · Резерв')
        self.assertEqual(main.exclude_nodes, {'panel'})
        self.assertTrue(cfg.multi)
        self.assertEqual([t.chat_id for t in cfg.chats()], ['-100', '-200'])

    def test_shared_telegram(self):
        cfg = make_cfg(telegram=TG, panel=[
            {'id': 'a', 'api_url': 'x', 'api_token': 't'},
            {'id': 'b', 'api_url': 'y', 'api_token': 't'}])
        self.assertEqual(len(cfg.chats()), 1)
        self.assertEqual(cfg.panels[1].title, 'b')
        routes = render.policies(cfg)['policies'][0]['routes']
        self.assertEqual(len(routes), 3)       # 2 для хостов + 1 общий: без дублей в один чат

    def test_errors(self):
        for bad in (
            {'panel': []},
            {'panel': [{'id': 'Main', 'api_url': 'x', 'api_token': 't', 'telegram': TG}]},
            {'panel': [{'id': 'a', 'api_url': 'x', 'api_token': '', 'telegram': TG}]},
            {'panel': [{'id': 'a', 'api_url': 'x', 'api_token': 't'}]},                   # нет Telegram
            {'panel': [{'id': 'a', 'api_url': 'x', 'api_token': 't', 'telegram': TG},
                       {'id': 'a', 'api_url': 'y', 'api_token': 't', 'telegram': TG}]},
            {'panel': [{'id': 'a', 'api_url': 'x', 'api_token': 't', 'telegram': TG},
                       {'id': 'b', 'api_url': 'y', 'api_token': 't', 'telegram': TG, 'host_suffix': ''}]},
            {'panel': [{'id': 'a', 'api_url': 'x', 'api_token': 't', 'telegram': TG}],
             'schedule': {'report_time': '25:00'}},
            {'panel': [{'id': 'a', 'api_url': 'x', 'api_token': 't', 'telegram': TG}],
             'schedule': {'report_time': '15:00', 'geocheck_time': '15:30'}},
            {'panel': [{'id': 'a', 'api_url': 'x', 'api_token': 't', 'telegram': TG}],
             'checks': {'interval': 'часто'}},
        ):
            with self.assertRaises(config.ConfigError, msg=bad):
                config.parse(bad, env={})

    def test_example_file(self):
        """config.example.toml из репозитория читается (после заполнения токенов)."""
        import tomllib
        path = os.path.join(os.path.dirname(__file__), '..', '..', 'config.example.toml')
        with open(path, 'rb') as f:
            data = tomllib.load(f)
        data['panel'][0]['api_token'] = 't'
        data['panel'][0]['telegram'] = TG
        cfg = config.parse(data, env={})
        self.assertEqual(cfg.report_time, (15, 0))


class FakePanel:
    def __init__(self, fail=False):
        self.fail = fail

    def nodes(self):
        if self.fail:
            raise ApiError('нет ответа')
        return [
            {'uuid': 'u1', 'name': 'Poland 1', 'countryCode': 'pl', 'isConnected': True, 'usersOnline': 7,
             'address': '10.1.2.3', 'versions': {'xray': '25.1.30', 'node': '2.1.0'}, 'xrayUptime': 100,
             'system': {'info': {'cpus': 2, 'memoryTotal': 1000},
                        'stats': {'loadAvg': [1, 0.5, 0], 'memoryUsed': 250,
                                  'interface': {'interface': 'eth0', 'rxBytesPerSec': 1000, 'txBytesPerSec': 5000,
                                                'rxTotal': 123456789012, 'txTotal': 5}}}},
            {'uuid': 'u2', 'name': 'Panel', 'isConnected': True, 'usersOnline': 0},
            {'uuid': 'u3', 'name': 'Old', 'isDisabled': True},
            {'uuid': 'u4', 'name': 'Down', 'isConnected': False, 'usersOnline': 5},
        ]

    def nodes_metrics(self):
        return [{'nodeUuid': 'u1', 'inboundsStats': [{'tag': 'VLESS', 'upload': '1.5 GiB', 'download': '0'}],
                 'outboundsStats': [{'tag': 'WARP', 'upload': '512 KiB', 'download': '12 B'}]},
                {'nodeUuid': 'u2', 'inboundsStats': [{'tag': 'X', 'upload': '1 MiB', 'download': '1 MiB'}]}]

    def raw_metrics(self):
        return ('# TYPE remnawave_node_outbound_upload_bytes counter\n'
                'remnawave_node_outbound_upload_bytes{node_uuid="u1",node_name="Poland 1",tag="WARP"} 524301\n'
                'remnawave_node_online_users{node_uuid="u1"} 7\n')

    def stats(self):
        return {'users': {'statusCounts': {'ACTIVE': 10, 'EXPIRED': 2}, 'totalUsers': 12},
                'onlineStats': {'onlineNow': 7, 'lastDay': 20}}

    def metadata(self):
        return {'version': '2.3.0'}


class ExporterTest(unittest.TestCase):
    def collect(self, rw, **panel_over):
        p = make_cfg().panels[0]
        for k, v in panel_over.items():
            setattr(p, k, v)
        lines = exporter.Lines()
        ok = exporter.collect_panel(p, rw, lines, {})
        return ok, lines.text()

    def test_collect(self):
        ok, text = self.collect(FakePanel())
        self.assertTrue(ok)
        self.assertIn('rwmon_panel_up{panel="main",panel_title="Основная"} 1', text)
        self.assertIn('node_name="Poland 1",node="Poland 1",country="PL"} 1', text)
        self.assertIn('rwmon_node_online_users{panel="main",panel_title="Основная",node_uuid="u4"} 0', text)
        self.assertIn('rwmon_node_cpu_load5{panel="main",panel_title="Основная",node_uuid="u1"} 0.25', text)
        self.assertIn('rwmon_node_memory_used_ratio{panel="main",panel_title="Основная",node_uuid="u1"} 0.25', text)
        self.assertIn('rwmon_node_inbound_upload_bytes{panel="main",panel_title="Основная",node_uuid="u1",tag="VLESS"} 1610612736', text)
        self.assertIn('tag="WARP"} 524288', text)
        self.assertIn('rwmon_panel_traffic_exact{panel="main",panel_title="Основная"} 0', text)
        self.assertIn('rwmon_users{panel="main",panel_title="Основная",status="ACTIVE"} 10', text)
        self.assertIn('rwmon_panel_info{panel="main",panel_title="Основная",version="2.3.0"} 1', text)
        self.assertNotIn('"u2"', text)          # exclude_nodes
        self.assertNotIn('"u3"', text)          # выключена в панели
        self.assertIn('# TYPE rwmon_node_inbound_upload_bytes counter', text)
        self.assertIn('rwmon_node_network_tx_bytes_per_second{panel="main",panel_title="Основная",node_uuid="u1"} 5000', text)
        self.assertIn('rwmon_node_network_rx_bytes{panel="main",panel_title="Основная",node_uuid="u1"} 123456789012', text)

    def test_node_extras(self):
        _, text = self.collect(FakePanel())
        self.assertIn('rwmon_node_address{panel="main",panel_title="Основная",node_uuid="u1",ip="10.1.2.3"} 1', text)
        self.assertIn('xray="25.1.30",node="2.1.0"} 1', text)
        self.assertIn('rwmon_node_xray_uptime_seconds{panel="main",panel_title="Основная",node_uuid="u1"} 100', text)

    def test_geocheck_lines(self):
        cfg = make_cfg()
        run = {'finished': '2026-09-29T14:30:00+00:00', 'results': {
            'main:u1': {'summary': {'ip': '1.2.3.4', 'network': 'AS1 X', 'type': 'Hosting', 'risk': 5,
                                    'place': 'Madrid, ES', 'consensus': 'ES 90%',
                                    'checks': {'services:google': {'name': 'Google', 'group': 'services',
                                                                   'kind': 'country', 'value': 'ES'}}}},
            'reserve:u2': {'ok': False, 'error': 'timeout'},
            'u3': {'summary': {'checks': {}, 'risk': 1}}}}           # старый формат ключа
        lines = exporter.Lines()
        exporter.geocheck_lines(run, lines, cfg)
        text = lines.text()
        self.assertIn('rwmon_geocheck{panel="main",panel_title="Основная",node_uuid="u1",group="services",'
                      'service="Google",value="ES"} 1', text)
        self.assertIn('rwmon_geocheck_risk{panel="main",panel_title="Основная",node_uuid="u1"} 5', text)
        self.assertNotIn('u2', text)
        self.assertIn('rwmon_geocheck_risk{panel="main",panel_title="Основная",node_uuid="u3"} 1', text)

    def test_site(self):
        import http.server
        import threading as th

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'hello Remnawave' if self.path == '/ok' else b'nope'
                self.send_response(200 if self.path != '/500' else 500)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        srv = http.server.HTTPServer(('127.0.0.1', 0), H)
        th.Thread(target=srv.serve_forever, daemon=True).start()
        base = f'http://127.0.0.1:{srv.server_port}'
        ok = exporter.check_site(config.Site('a', base + '/ok', 'Remnawave'))
        miss = exporter.check_site(config.Site('b', base + '/x', 'Remnawave'))
        err = exporter.check_site(config.Site('c', base + '/500'))
        alive = exporter.check_site(config.Site('d', base + '/500', any_status=True))
        self.assertEqual(alive['up'], 1)
        srv.shutdown()
        self.assertEqual((ok['up'], ok['code']), (1, 200))
        self.assertEqual((miss['up'], miss['code']), (0, 200))       # нет ключевого слова
        self.assertEqual((err['up'], err['code']), (0, 500))
        lines = exporter.Lines()
        exporter.site_lines([(config.Site('a', base + '/ok'), ok)], lines)
        self.assertIn('rwmon_site_up{site="a"', lines.text())

    def test_host_lines(self):
        lines = exporter.Lines()
        exporter.host_lines([{'panel': 'main', 'panel_title': 'Основная', 'host': 'LTE 1', 'name': 'LTE 1',
                              'lite': True, 'address': '1.2.3.4:443'}], lines)
        self.assertIn('rwmon_host{panel="main",panel_title="Основная",host="LTE 1",name="LTE 1",lite="1",'
                      'address="1.2.3.4:443"} 1',
                      lines.text())

    def test_exact_traffic(self):
        ok, text = self.collect(FakePanel(), metrics_url='http://x/metrics')
        self.assertIn('rwmon_node_outbound_upload_bytes{panel="main",panel_title="Основная",node_uuid="u1",tag="WARP"} 524301', text)
        self.assertIn('rwmon_panel_traffic_exact{panel="main",panel_title="Основная"} 1', text)
        self.assertNotIn('VLESS', text)

    def test_panel_down(self):
        ok, text = self.collect(FakePanel(fail=True))
        self.assertFalse(ok)
        self.assertIn('rwmon_panel_up{panel="main",panel_title="Основная"} 0', text)
        self.assertNotIn('rwmon_node_', text)

    def test_parse_size(self):
        self.assertEqual(exporter.parse_size('0'), 0)
        self.assertEqual(exporter.parse_size('1.5 KiB'), 1536)
        self.assertEqual(exporter.parse_size('2 TiB'), 2 * 1024 ** 4)
        self.assertEqual(exporter.parse_size('100 B'), 100)
        self.assertIsNone(exporter.parse_size('много'))


class RenderTest(unittest.TestCase):
    def test_render(self):
        cfg = make_cfg()
        with tempfile.TemporaryDirectory() as out:
            render.OUT = out
            render.SRC = os.path.join(os.path.dirname(__file__), '..', '..')
            render.render(cfg)
            def load(path):
                with open(os.path.join(out, path), encoding='utf-8') as f:
                    return json.load(f) if path.endswith('.yml') else f.read()
            prom = load('prometheus/prometheus.yml')
            self.assertEqual(prom['scrape_configs'][1]['static_configs'][1]['labels'], {'check': 'warp'})
            rules = load('grafana/alerting/rules.yml')['groups'][0]['rules']
            self.assertEqual(len({r['uid'] for r in rules}), 16)
            self.assertIn('psiphon-out|WARP', json.dumps(rules))
            routes = load('grafana/alerting/policies.yml')['policies'][0]['routes']
            self.assertEqual(routes[0]['object_matchers'], [['scope', '=', 'host'], ['panel', '=', 'main']])
            self.assertTrue(all(r.get('continue') for r in routes[2:]))
            self.assertEqual([r['receiver'] for r in routes], ['telegram', 'telegram-reserve'] * 2)
            cps = load('grafana/alerting/contact-points.yml')['contactPoints']
            self.assertEqual([c['receivers'][0]['settings']['chatid'] for c in cps], ['-100', '-200'])
            tpl = load('grafana/alerting/templates.yml')['templates'][0]['template']
            self.assertTrue(tpl.startswith('{{ define'))
            self.assertNotIn('__MULTI__', tpl)
            env = load('checkers/warp.env')
            self.assertIn("PROXY_IP_CHECK_URL='https://icanhazip.com'", env)
            self.assertIn("SUBSCRIPTION_URL='file:///links/monitor.txt'", env)
            self.assertIn("PROXY_CHECK_ATTEMPTS='3'", env)
            self.assertIn("PROXY_CHECK_CONCURRENCY='20'", env)
            self.assertIn("monitor-xray.txt", load('checkers/xray.env'))
            self.assertTrue(os.path.isdir(os.path.join(out, 'grafana', 'plugins')))


if __name__ == '__main__':
    unittest.main()
