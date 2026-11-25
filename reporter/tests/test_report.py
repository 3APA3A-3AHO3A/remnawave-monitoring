"""Сводка для бота и единый HTML-отчёт: трафик в обе стороны, сбои, GeoCheck, сайты, РКН."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from test_rwmon import make_cfg                            # noqa: E402

from rwmon import alertfmt as F, report                   # noqa: E402

TOKEN = '123456:' + 'A' * 35


def data():
    k1, k2 = ('main', 'n1'), ('reserve', 'n2')
    return {
        'info': {k1: {'node_name': 'Finland 1', 'panel_title': 'Основная', 'country': 'FI'},
                 k2: {'node_name': 'Sweden 1', 'panel_title': 'Резерв', 'country': 'SE'}},
        'now': {k1: 45, k2: 62}, 'peak': {k1: 71, k2: 74},
        'traffic': {k1: 214e9, k2: 175e9},
        'down': {k1: 205e9, k2: 168e9}, 'up': {k1: 8.9e9, k2: 7e9},
        'net_rx': {k1: 241e9}, 'net_tx': {k1: 236e9},
        'outbound': {k1: {'WARP': 33.6e9, 'psiphon-out': 332e6}},
        'offline': {}, 'panel_down': {}, 'probe_blocked': [], 'probe_mass': 0,
        'checks': [('main', 'LTE 3', 'lte3', 'xray', 807.0), ('main', 'Игровой', 'g', 'warp', 1.0)],
        'status': {('main', 'ACTIVE'): 238, ('main', 'EXPIRED'): 178},
        'online': {('main', 'onlineNow'): 133, ('main', 'lastDay'): 212, ('reserve', 'onlineNow'): 201},
        'total': {('main',): 576},
        'sites_down': {}, 'sites_ru_down': {},
        'site_up': {('fixerrorvpn.com',): 1, ('panel',): 1},
        'site_cert': {('fixerrorvpn.com',): 77.4, ('panel',): 76.1},
    }


RKN = {'time': '2026-11-24 10:57', 'items': [
    {'target': '184.174.96.32', 'name': 'USA 1', 'kind': 'node', 'ok': True, 'blocked': True,
     'why': 'IP в сети заблокированного CDN: ovh'},
    {'target': 'fixerrorvpn.com', 'name': 'fixerrorvpn.com', 'kind': 'domain', 'ok': True, 'blocked': False,
     'cdn': 'cloudflare'}]}

GEO = {'date': 'x', 'finished': '2026-11-24T14:32:00', 'results': {
    'main:n1': {'name': 'Finland 1', 'ok': True, 'changes': [('YouTube', 'PL', 'UA')], 'minor': [],
                'attention': ['Google видит RU'], 'attention_new': [],
                'summary': {'ip': '2.26.87.162', 'network': 'AS1 Net', 'type': 'Hosting', 'risk': 33,
                            'place': 'FI', 'consensus': 'FI 97%',
                            'checks': {'services:yt': {'name': 'YouTube', 'group': 'services', 'kind': 'country',
                                                       'value': 'UA'},
                                       'stash:nf': {'name': 'Netflix', 'group': 'stash', 'kind': 'access',
                                                    'value': 'blocked (RUS)'}}}},
    'reserve:n2': {'name': 'Sweden 1', 'ok': False, 'error': 'timeout'}}}


class Prom:
    def query_range(self, expr, start, end, step):
        if 'xray_proxy_status' in expr:
            vals = [(start + i * step, 0.0 if 100 <= i < 300 else 1.0) for i in range(720)]
            return [({'name': 'lte3', 'check': 'xray'}, vals)]
        return []


class ReportTest(unittest.TestCase):
    def setUp(self):
        self.cfg = make_cfg(rkn={'interval_hours': 6})
        self.cfg.data_dir = tempfile.mkdtemp()

    def test_summary(self):
        body = report.summary_rich(data(), {}, GEO, RKN, self.cfg)
        self.assertIn('<h3>📊 Сводка за', body)
        self.assertIn('↓205.0 ГБ', body)                     # трафик к клиентам по панели
        self.assertIn('↑8.9 ГБ', body)
        self.assertIn('Сбои: 1', body)                        # LTE 3; Игровой — короткий
        self.assertIn('дольше всего LTE 3 · Основная — 13 ч 27 мин', body)
        self.assertIn('ближайший сертификат 76 дн.', body)
        self.assertIn('РКН: в списках 1', body)
        self.assertIn('<details><summary>Ноды Основная (1)</summary>', body)
        self.assertIn('🇫🇮 Finland 1', body)
        self.assertIn('Сбои за сутки (1)', body)
        # заглушённая в боте блокировка не считается
        body = report.summary_rich(data(), {}, GEO, RKN, self.cfg, rkn_muted=lambda x: x['target'] == '184.174.96.32')
        self.assertIn('РКН: чисто (заглушено 1)', body)
        self.assertIn('🔕 USA 1', body)
        # без rich — читаемый текст без служебных тегов
        text = F.plain(body)
        self.assertNotIn('<details', text)
        self.assertNotIn('<td', text)
        self.assertIn('<b>Ноды Основная (1)</b>', text)

    def test_timeline(self):
        rows, start, end = report.timeline(Prom(), data(), self.cfg, end=1_000_000)
        self.assertEqual(len(rows), 1)                        # Игровой 1 мин — не показываем
        label, segs = rows[0]
        self.assertEqual(label, 'LTE 3 · Основная · Подключение')
        self.assertEqual(len(segs), 1)
        self.assertAlmostEqual(segs[0][1] - segs[0][0], 200 * report.STEP)

    def test_full_html(self):
        tl = report.timeline(Prom(), data(), self.cfg, end=1_000_000)
        html = report.full_html(data(), {}, GEO, RKN, self.cfg, tl,
                                rkn_muted=lambda x: x['target'] == '184.174.96.32')
        for text in ('Мониторинг ·', 'онлайн сейчас', '373.0 ГБ / 15.9 ГБ', 'LTE 3 · Основная · Подключение',
                     'class="seg"', 'Ноды · Основная', 'сеть сервера ↓ / ↑', '241.0 ГБ / 236.0 ГБ',
                     'psiphon-out', 'GeoCheck — как сервисы видят ноды', 'YouTube: PL → UA',
                     'Google видит RU', 'не выполнился', 'Все сервисы по всем нодам', 'Netflix',
                     'Сайты и сертификаты', '77 дн.', 'Блокировки РКН', 'заглушено', 'за CDN cloudflare'):
            self.assertIn(text, html)
        self.assertTrue(html.startswith('<!doctype html>'))
        self.assertTrue(html.rstrip().endswith('</html>'))

    def test_no_geocheck_and_no_bot(self):
        html = report.full_html(data(), {}, None, None, make_cfg())
        self.assertIn('Сегодня не запускался', html)
        self.assertNotIn('Блокировки РКН', html)


if __name__ == '__main__':
    unittest.main()
