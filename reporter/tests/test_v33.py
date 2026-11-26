"""3.3.0: режим работ, тихий перезапуск панели при обновлении, число в заголовке массового сбоя,
«требует внимания» в сводке, алерт о старых geo-базах, порядок дашборда."""
import importlib.util
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from test_bot import Prom, alert, payload, BotTest      # noqa: E402
from test_rwmon import make_cfg                         # noqa: E402

from rwmon import bot, render, report                   # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def silent(p):
    return bool(p.get('disable_notification'))


class V33(unittest.TestCase):
    make = BotTest.make           # тот же бот с подменённым Telegram, без повторного прогона тестов BotTest

    def test_work_mode_marks_and_silences(self):
        b = self.make()
        body, rows = b.work_body()
        self.assertIn('выключен', body)
        b.work_start()
        self.assertTrue(b.work_until() > time.time() + 3500)
        b.on_alert(payload(alert()))
        _, p = b.fake.sent[-1]
        self.assertTrue(silent(p))
        self.assertIn('Идут работы', p['rich_message']['html'])
        until = b.work_until()
        b.work_start()                                       # «+1 час» продлевает то же окно
        self.assertAlmostEqual(b.work_until(), until + 3600, delta=2)
        self.assertEqual(len(b.state['work']), 1)
        b.work_stop()
        self.assertEqual(b.work_until(), 0)
        wins = bot.work_windows(b.cfg, time.time() - 86400)
        self.assertEqual(len(wins), 1)
        b.on_alert(payload(alert(name='LTE 4', fp='other'), key='k2'))
        self.assertFalse(silent(b.fake.sent[-1][1]))           # работы кончились — снова со звуком

    def test_panel_restart_after_update_is_quiet(self):
        class P(Prom):
            def query(self, expr, at=None):
                if 'count_over_time(rwmon_panel_info' in expr:
                    return [({'version': '3.4.11'}, 5.0), ({'version': '3.4.12'}, 3.0)]
                if 'max by (version)' in expr:
                    return [({'version': '3.4.12'}, 1.0)]
                return super().query(expr, at)
        b = self.make()
        b.prom = P()
        a = alert(name='x', rule='Процесс панели перезапустился')
        a['labels']['panel'] = 'main'
        b.on_alert(payload(a, key='r'))
        _, p = b.fake.sent[-1]
        self.assertTrue(silent(p))
        self.assertIn('обновлена до 3.4.12', p['rich_message']['html'])

    def test_panel_restart_without_update_is_loud(self):
        b = self.make()
        a = alert(name='x', rule='Процесс панели перезапустился')
        a['labels']['panel'] = 'main'
        b.on_alert(payload(a, key='r'))
        _, p = b.fake.sent[-1]
        self.assertFalse(silent(p))
        self.assertIn('Процесс панели перезапустился', p['rich_message']['html'])

    def test_mass_failure_has_count_in_title(self):
        b = self.make()
        b.on_alert(payload(*[alert(name=f'H{i}', fp=f'f{i}', rule='Psiphon не работает') for i in range(5)]))
        self.assertIn('Psiphon не работает — 5', b.fake.sent[-1][1]['rich_message']['html'])
        b.on_alert(payload(alert(name='One', fp='one', rule='WARP не работает'), key='w'))
        self.assertNotIn('— 1', b.fake.sent[-1][1]['rich_message']['html'])


def test_geodata_rule_only_with_node_exporter():
    on = json.dumps(render.rules(make_cfg(node_exporter={'port': 9100})), ensure_ascii=False)
    off = json.dumps(render.rules(make_cfg()), ensure_ascii=False)
    assert 'rwmon-geodata-stale' in on and 'rwmon-geodata-stale' not in off
    assert 'rwmon_geodata_mtime_seconds' in render.NODE_METRICS and 'node_reboot_required' in render.NODE_METRICS


def test_attention_lines():
    cfg = make_cfg()
    key = ('reserve', 'u1')
    d = {'info': {key: {'node_name': 'Sweden 2', 'panel_title': 'Резерв'}},
         'overload': {key: 45.0}, 'geo_age': {key: 4.2}, 'reboot': {key: 1.0},
         'site_up': {('a',): 1.0}, 'site_cert': {('a',): 20.0}}
    scan_data = {'items': {'1.1.1.1': {'name': 'Sweden 2 · 1.1.1.1', 'blocked': True}}}
    att = report.attention(d, None, None, scan_data, cfg)
    text = ' | '.join(att)
    for part in ('перегружалась', 'geo-базы не обновляются', 'Sweden 2', 'нужна перезагрузка',
                 'сертификат сайта истекает через 20', 'сканеры в сетях РФ видят блокировку'):
        assert part in text, part
    calm = {'info': {key: {'node_name': 'X', 'panel_title': 'P'}}, 'overload': {key: 5.0},
            'geo_age': {key: 1.0}, 'reboot': {key: 0.0}}
    assert report.attention(calm, None, None, None, cfg) == []


def test_dashboard_order_hosts_before_sites():
    spec = importlib.util.spec_from_file_location('dash', os.path.join(ROOT, 'grafana', 'dashboard.py'))
    dash = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dash)
    panels = dash.build(scanners=True)['panels']
    y = {p['title']: p['gridPos']['y'] for p in panels if p['type'] != 'stat'}
    assert y['Хосты'] < y['Ноды'] < y['Сайты'] < y['Блокировки РКН']
    rows = {p['title']: p for p in panels if p['type'] == 'row'}
    assert rows['Каждая нода отдельно: сеть сервера']['collapsed'] is True
    nodes = next(p for p in panels if p['title'] == 'Ноды' and p['type'] == 'table')
    assert any('rwmon_node_memory_used_ratio' in t['expr'] and 'sum_over_time' in t['expr'] for t in nodes['targets'])
    assert __import__('rwmon.alertfmt', fromlist=['x']).category('rwmon-geodata-stale') == 'nodes'
