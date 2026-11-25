"""Бот мониторинга: алерты с кнопками, тишина, повторы, настройки, запасной вид без rich."""
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from test_rwmon import make_cfg                            # noqa: E402

from rwmon import alertfmt as F, bot, config, render     # noqa: E402
from rwmon.clients import ApiError                        # noqa: E402

TOKEN = '123456:' + 'A' * 35


class FakeApi:
    """Запоминает отправленное; rich=False — Telegram «не принимает» rich-сообщения."""

    def __init__(self, rich=True):
        self.rich, self.sent, self.edits, self.n = rich, [], [], 0

    def call(self, method, params, timeout=30):
        if method == 'sendRichMessage' and not self.rich:
            raise ApiError('telegram/sendRichMessage → HTTP 400: can\'t parse')
        if method in ('sendRichMessage', 'sendMessage'):
            self.n += 1
            self.sent.append((method, params))
            return {'message_id': self.n}
        if method == 'editMessageText':
            self.edits.append(params)
        return True


class Prom:
    def query(self, expr, at=None):
        if 'xray_proxy_status{name=' in expr:
            return [({}, 95.0)]
        if expr == 'sum by (panel) (rwmon_node_connected)':
            return [({'panel': 'main'}, 3.0), ({'panel': 'reserve'}, 2.0)]
        if expr == 'count by (panel) (rwmon_node_connected)':
            return [({'panel': 'main'}, 3.0), ({'panel': 'reserve'}, 3.0)]
        return []


def alert(name='LTE 3', status='firing', rule='Хост не работает из РФ', fp=None, reason='таймаут'):
    return {'status': status, 'fingerprint': fp or name,
            'labels': {'alertname': rule, 'grafana_folder': 'Remnawave', 'severity': 'critical',
                       'scope': 'all', 'host': name, 'panel_title': 'Основная', 'name': name + ' · Основная'},
            'annotations': {'summary': rule, 'recovered': 'Снова работает из РФ', 'reason': reason},
            'startsAt': '2026-11-25T04:15:00.123456789Z',
            'endsAt': '0001-01-01T00:00:00Z' if status == 'firing' else '2026-11-25T05:20:00Z',
            'generatorURL': 'https://grafana.example/alerting/grafana/x/view'}


def payload(*alerts, key='{}:{alertname="x"}'):
    return {'groupKey': key, 'alerts': list(alerts)}


class BotTest(unittest.TestCase):
    def make(self, rich=True, **kw):
        cfg = make_cfg(bot={'token': TOKEN, 'admins': [1, '2'], 'timezone': 'Europe/Moscow'}, **kw)
        cfg.data_dir = tempfile.mkdtemp()
        b = bot.Bot(cfg, prom=Prom())
        b.api.call = FakeApi(rich).call
        b.fake = b.api.call.__self__
        return b

    def test_config(self):
        cfg = make_cfg(bot={'token': TOKEN, 'admins': [5]})
        self.assertEqual(cfg.bot.admins, {5})
        self.assertEqual(cfg.bot.timezone, 'UTC')
        self.assertIsNone(make_cfg().bot)
        for bad in ({'token': 'x', 'admins': [1]}, {'token': TOKEN, 'admins': []},
                    {'token': TOKEN, 'admins': [1], 'timezone': 'Mars/Base'}):
            with self.assertRaises(config.ConfigError):
                make_cfg(bot=bad)

    def test_grafana_sends_to_reporter_with_bot(self):
        cfg = make_cfg(bot={'token': TOKEN, 'admins': [1]})
        cp = render.contact_points(cfg)['contactPoints']
        self.assertEqual([c['receivers'][0]['type'] for c in cp], ['webhook'])
        self.assertIn('/alert', cp[0]['receivers'][0]['settings']['url'])
        pol = render.policies(cfg)['policies'][0]
        self.assertEqual((pol['receiver'], pol['repeat_interval']), ('rwmon-bot', '30m'))
        # без [bot] — как раньше, Telegram напрямую из Grafana
        self.assertEqual(render.contact_points(make_cfg())['contactPoints'][0]['receivers'][0]['type'], 'telegram')

    def test_categories(self):
        uids = {r['title']: r['uid'] for g in render.rules(make_cfg())['groups'] for r in g['rules']}
        self.assertEqual(F.category(uids['Xray не принимает клиентов']), 'nodes')
        self.assertEqual(F.category('rwmon-warp-down'), 'nodes')
        self.assertEqual(F.category('rwmon-site-down-ru'), 'ru')
        self.assertEqual(F.category('rwmon-site-down'), 'sites')
        self.assertEqual(F.category('rwmon-rkn-blocked'), 'rkn')
        self.assertEqual(F.category('rwmon-reporter-down'), 'self')
        self.assertEqual(F.category('rwmon-panel-slow'), 'panels')
        self.assertEqual(F.category(''), 'self')

    def test_alert_goes_to_every_chat_with_buttons(self):
        b = self.make()
        b.on_alert(payload(alert()))
        self.assertEqual(len(b.fake.sent), 2)                 # два чата панелей
        method, p = b.fake.sent[0]
        self.assertEqual(method, 'sendRichMessage')
        html = p['rich_message']['html']
        self.assertIn('LTE 3 · Основная', html)
        self.assertIn('<tg-time unix=', html)
        self.assertIn('таймаут', html)
        self.assertIn('data="m:', html)                        # кнопки тишины
        self.assertIn('Открыть в Grafana', html)

    def test_plain_fallback(self):
        b = self.make(rich=False)
        b.on_alert(payload(alert()))
        method, p = b.fake.sent[0]
        self.assertEqual(method, 'sendMessage')
        self.assertNotIn('<tg-', p['text'])
        self.assertNotIn('<li>', p['text'])
        self.assertIn('• <b>LTE 3', p['text'])
        self.assertIn('04:15 UTC', p['text'])
        self.assertTrue(p['reply_markup']['inline_keyboard'][0][0]['callback_data'].startswith('m:'))

    def test_repeat_is_throttled(self):
        b = self.make()
        b.on_alert(payload(alert()))
        b.on_alert(payload(alert()))                           # Grafana повторила через 30 мин
        self.assertEqual(len(b.fake.sent), 2)
        b.on_alert(payload(alert(), alert('LTE 4')))           # добавилось новое — сразу
        self.assertEqual(len(b.fake.sent), 4)
        b.state['last'][next(iter(b.state['last']))]['t'] -= 3600
        b.on_alert(payload(alert(), alert('LTE 4')))           # прошёл час — напоминаем
        self.assertEqual(len(b.fake.sent), 6)

    def test_mute_and_unmute(self):
        b = self.make()
        b.on_alert(payload(alert(), alert('LTE 4')))
        gid = next(iter(b.state['msgs']))
        q = {'id': 'q', 'data': f'm:{gid}:60', 'from': {'id': 1, 'first_name': 'Alex'},
             'message': {'chat': {'id': -100}, 'message_id': 1, 'rich_message': {}}}
        self.assertEqual(b.on_callback(q), 'Заглушено на 1 ч')
        self.assertEqual(len(b.state['mutes']), 2)
        self.assertEqual(len(b.fake.edits), 2)                 # обновились копии в обоих чатах
        self.assertIn('Заглушено', b.fake.edits[0]['rich_message']['html'])
        self.assertIn('Alex', b.fake.edits[0]['rich_message']['html'])
        sent = len(b.fake.sent)
        b.state['last'].clear()
        b.on_alert(payload(alert(), alert('LTE 4')))           # заглушено — в чат не идёт
        self.assertEqual(len(b.fake.sent), sent)
        b.on_alert(payload(alert('Finland 1')))               # другой хост — идёт
        self.assertEqual(len(b.fake.sent), sent + 2)
        q['data'] = f'u:{gid}'
        b.on_callback(q)
        self.assertEqual(b.state['mutes'], [])

    def test_mute_forever_survives_and_mutes_list(self):
        b = self.make()
        b.on_alert(payload(alert('USA 1', rule='Блокировка РФ: адрес в списках')))
        gid = next(iter(b.state['msgs']))
        b.mute(gid, bot.FOREVER, 'Alex')
        b2 = bot.Bot(b.cfg, prom=Prom())                       # после перезапуска reporter
        b2.api.call = FakeApi().call
        self.assertTrue(b2.muted(alert('USA 1', rule='Блокировка РФ: адрес в списках')))
        body, rows = b2.mutes_body()
        self.assertIn('навсегда', body)
        self.assertIn('USA 1', body)
        mid = b2.state['mutes'][0]['id']
        self.assertEqual(b2.unmute(mute_id=mid), 1)

    def test_only_admins(self):
        b = self.make()
        b.on_alert(payload(alert()))
        gid = next(iter(b.state['msgs']))
        q = {'id': 'q', 'data': f'm:{gid}:60', 'from': {'id': 99}, 'message': {'chat': {'id': -100}, 'message_id': 1}}
        self.assertIn('только для админов', b.on_callback(q))
        self.assertEqual(b.state['mutes'], [])
        b.on_message({'text': '/status', 'from': {'id': 99}, 'chat': {'id': 5}})
        self.assertEqual(len(b.fake.sent), 2)

    def test_settings_toggle_category_and_quiet(self):
        b = self.make()
        q = {'id': 'q', 'from': {'id': 2}, 'message': {'chat': {'id': -100}, 'message_id': 1}}
        b.on_callback({**q, 'data': 'cf:c:ru'})
        self.assertEqual(b.settings['off'], ['ru'])
        b.on_alert(payload(alert(rule='Хост не открывается из РФ')))   # группа «Проверка из РФ»
        self.assertEqual(b.fake.sent, [])
        b.on_callback({**q, 'data': 'cf:c:ru'})
        self.assertEqual(b.settings['off'], [])
        b.on_callback({**q, 'data': 'cf:r:180'})
        self.assertEqual(b.settings['repeat'], 180)
        b.on_callback({**q, 'data': 'cf:d'})
        self.assertFalse(bot.daily_enabled(b.cfg))
        b.on_callback({**q, 'data': 'cf:q:00-00'})             # чужое значение — тихих часов нет
        self.assertEqual(b.settings['quiet'], '')
        b.settings['quiet'] = '0-24'
        self.assertTrue(b.quiet_now())

    def test_status_and_details(self):
        b = self.make()
        b.on_alert(payload(alert()))
        body, rows = b.status_body()
        self.assertIn('Основная · ноды', body)
        self.assertIn('3 / 3', body)
        self.assertIn('2 / 3', body)
        self.assertIn('Горит алертов: <b>1</b>', body)
        gid = next(iter(b.state['msgs']))
        d = b.details(gid)
        self.assertIn('Не проходила за 24 ч', d)
        self.assertIn('1 ч 35 мин', d)
        self.assertIn('Что горит', b.firing_body()[0])

    def test_resolved_only_has_no_buttons_and_firing_list_updates(self):
        b = self.make()
        b.on_alert(payload(alert()))
        self.assertEqual(len(b.state['firing']), 1)
        b.on_alert(payload(alert(status='resolved')))
        self.assertEqual(b.state['firing'], {})
        html = b.fake.sent[-1][1]['rich_message']['html']
        self.assertIn('Снова работает из РФ', html)
        self.assertNotIn('tg-button', html)

    def test_commands_addressed_to_other_bot_ignored(self):
        b = self.make()
        b.username = 'rwmon_bot'
        b.on_message({'text': '/status@other_bot', 'from': {'id': 1}, 'chat': {'id': 5}})
        self.assertEqual(b.fake.sent, [])
        b.on_message({'text': '/settings@rwmon_bot', 'from': {'id': 1}, 'chat': {'id': 5}})
        self.assertIn('Уведомления', b.fake.sent[0][1]['rich_message']['html'])

    def test_plain_converter(self):
        s = F.plain('<h4>Т</h4><table bordered><tr><td>a</td><td>b</td></tr></table>'
                    '<details><summary>S</summary><p>x</p></details><footer>f</footer>')
        self.assertEqual(s, '<b>Т</b>\na · b\n\n<b>S</b>\nx\n\nf')

    def test_mute_expires(self):
        b = self.make()
        b.on_alert(payload(alert()))
        gid = next(iter(b.state['msgs']))
        b.mute(gid, 60, 'Alex')
        b.state['mutes'][0]['until'] = time.time() - 1
        self.assertIsNone(b.muted(alert()))


if __name__ == '__main__':
    unittest.main()
