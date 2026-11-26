"""Сканеры cheburcheck: разбор потока, итог, очередь адресов, пауза при 429, метрики, сводка."""
import io
import time
import urllib.error
from types import SimpleNamespace

from rwmon import exporter, scan

STREAM = b"""event:started
data:{"id":"j1","online_probes":4,"target":"1.2.3.4"}

:
event:result
data:{"probe_id":"1","provider":"MTS","region":"\xd0\x9c\xd0\xbe\xd1\x81\xd0\xba\xd0\xb2\xd0\xb0","verdicts":["tspu_block"]}

event:result
data:{"probe_id":"2","provider":"Beeline","region":"","verdicts":["tspu_block","sni_block"]}

event:result
data:{"probe_id":"3","provider":"Rostelecom","region":"","verdicts":["ok"]}

event:result
data:{"probe_id":"4","provider":"Ufanet","region":"","verdicts":["uncertain"]}

event:done
data:{"id":"j1","response_count":4,"online_probes":4}

event:result
data:{"probe_id":"5","provider":"late","verdicts":["ok"]}
"""


def raw():
    return scan.probe('1.2.3.4', 't', check=lambda t: {'id': 'abc'},
                      stream=lambda url: io.BytesIO(STREAM))


def test_probe_reads_until_done():
    r = raw()
    assert r['online'] == 4
    assert [x['provider'] for x in r['results']] == ['MTS', 'Beeline', 'Rostelecom', 'Ufanet']
    assert r['results'][0]['region'] == 'Москва'


def test_summary_counts_and_threshold():
    s = scan.summarize(raw())
    assert (s['answered'], s['ok'], s['uncertain'], s['bad']) == (4, 1, 1, 2)
    assert s['blocked'] is True                      # двое видят — блокировка
    assert s['by']['tspu_block'] == ['Beeline', 'MTS (Москва)']
    assert scan.why(s) == 'ТСПУ: Beeline, MTS (Москва); по SNI: Beeline'
    assert scan.kinds(s) == 'ТСПУ, по SNI'
    one = scan.summarize({'results': [{'provider': 'X', 'region': '', 'verdicts': ['dns_spoofing']},
                                      {'provider': 'Y', 'region': '', 'verdicts': ['ok']}]})
    assert one['bad'] == 1 and one['blocked'] is False   # одиночный вердикт — не блокировка


def test_deadline_stops_endless_stream():
    def pings():
        while True:
            yield b':\n'
    t0 = time.time()
    assert list(scan.events(pings(), deadline=time.time() + 0.2)) == []
    assert time.time() - t0 < 2


def cfg(tmp_path):
    return SimpleNamespace(data_dir=str(tmp_path), rkn_probe_interval=1800, rkn_token='t',
                           rkn_enabled=True)


def test_step_rotates_oldest_first_and_backs_off(tmp_path, monkeypatch):
    tg = [{'target': 'a', 'kind': 'node', 'name': 'A'}, {'target': 'b', 'kind': 'domain', 'name': 'b'}]
    monkeypatch.setattr(scan.rkn, 'targets', lambda c, cl: tg)
    c, data, seen = cfg(tmp_path), {}, []

    def ok(t):
        seen.append(t)
        return {'online': 1, 'results': [{'provider': 'P', 'region': '', 'verdicts': ['ok']}]}
    assert scan.step(c, None, data, ok) == 1800
    assert scan.step(c, None, data, ok) == 1800
    assert seen == ['a', 'b']
    data['items']['a']['ts'] = time.time() + 5        # «a» проверен позже «b» — следующим будет «b»
    scan.step(c, None, data, ok)
    assert seen[-1] == 'b'

    def limited(t):
        raise scan.RateLimited()
    assert scan.step(c, None, data, limited) == 1800
    assert scan.step(c, None, data, limited) == 3600   # пауза удваивается
    for _ in range(10):
        w = scan.step(c, None, data, limited)
    assert w == scan.BACKOFF_MAX
    assert scan.step(c, None, data, ok) == 1800 and data['backoff'] == 0


def test_step_drops_gone_targets_and_bad_token(tmp_path, monkeypatch):
    c = cfg(tmp_path)
    data = {'items': {'old': {'ts': time.time() - 2 * 86400, 'name': 'old'},
                      'fresh': {'ts': time.time(), 'name': 'fresh'}}}
    monkeypatch.setattr(scan.rkn, 'targets', lambda c, cl: [{'target': 'a', 'kind': 'node', 'name': 'A'}])

    def denied(t):
        raise urllib.error.HTTPError('u', 401, 'no', {}, None)
    assert scan.step(c, None, data, denied) == scan.BACKOFF_MAX
    assert 'old' not in data['items'] and 'fresh' in data['items']   # свежий держим сутки


def test_metrics_and_daily(tmp_path):
    s = scan.summarize(raw())
    data = {'items': {'1.2.3.4': dict(s, name='NL 1', kind='node', ts=time.time(), time='2026-11-26 10:00'),
                      'x.com': dict(scan.summarize({'results': [{'provider': 'P', 'region': '',
                                                                  'verdicts': ['ok']}]}),
                                    name='x.com', kind='domain', ts=time.time(), time='')}}
    lines = exporter.Lines()
    scan.lines(data, lines)
    text = lines.text()
    assert 'rwmon_rkn_scan_blocked{target="1.2.3.4",kind="node",name="NL 1 · 1.2.3.4",why="ТСПУ, по SNI"} 1' in text
    assert 'rwmon_rkn_scan_blocked{target="x.com",kind="domain",name="x.com",why=""} 0' in text
    assert 'who="ТСПУ: Beeline, MTS (Москва); по SNI: Beeline"' in text
    sec = '\n'.join(scan.telegram_section(data))
    assert 'нода NL 1: блокируют 2 из 4' in sec
    clean = scan.telegram_section({'items': {'x.com': data['items']['x.com']}})
    assert 'блокировок не видят, адресов: 1' in '\n'.join(clean)
    assert scan.telegram_section({}) == []


def test_config_token_and_interval():
    from rwmon import config
    import pytest
    assert config._rkn({'token': ' abc ', 'probe_interval_minutes': 45})['rkn_probe_interval'] == 2700
    assert config._rkn({'token': ' abc '})['rkn_token'] == 'abc'
    assert config._rkn({'interval_hours': 6})['rkn_token'] == ''
    for bad in ({'token': 5}, {'probe_interval_minutes': 1}, {'probe_interval_minutes': True}):
        with pytest.raises(config.ConfigError):
            config._rkn(bad)


def test_render_rule_and_dashboard_column():
    import importlib.util
    import os
    here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    spec = importlib.util.spec_from_file_location('dash', os.path.join(here, 'grafana', 'dashboard.py'))
    dash = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dash)
    def rkn_panel(d):
        for p in d['panels']:
            for q in p.get('panels', []) + [p]:
                if q.get('title') == 'Блокировки РКН':
                    return q
    on = rkn_panel(dash.build(scanners=True))
    off = rkn_panel(dash.build())
    assert len(on['targets']) == 7 and len(off['targets']) == 1
    assert on['gridPos']['w'] == 24 and off['gridPos']['w'] == 12
    assert on['transformations'][0]['id'] == 'merge'
    assert any('rwmon_rkn_scan_blocked' in t['expr'] for t in on['targets'])


def test_render_rule_only_with_token():
    import json, sys, os
    sys.path.insert(0, os.path.dirname(__file__))
    from test_rwmon import make_cfg
    from rwmon import render
    with_t = json.dumps(render.rules(make_cfg(rkn={'token': 'abc'})), ensure_ascii=False)
    without = json.dumps(render.rules(make_cfg(rkn={'interval_hours': 6})), ensure_ascii=False)
    assert 'rwmon-rkn-scan' in with_t and 'rwmon-rkn-scan' not in without
    assert 'rwmon-rkn-blocked' in with_t


def test_urgent_goes_first_once_per_cache(tmp_path, monkeypatch):
    tg = [{'target': 'a', 'kind': 'node', 'name': 'A'}, {'target': '9.9.9.9', 'kind': 'node', 'name': 'N'}]
    monkeypatch.setattr(scan.rkn, 'targets', lambda c, cl: tg)
    c, data, seen = cfg(tmp_path), {}, []

    def ok(t):
        seen.append(t)
        return {'online': 1, 'results': [{'provider': 'P', 'region': '', 'verdicts': ['ok']}]}
    scan.WAKE.clear()
    scan.set_urgent({'9.9.9.9': 'Хост X', '5.5.5.5': 'Хост Y'})
    assert scan.WAKE.is_set()
    scan.step(c, None, data, ok)
    scan.step(c, None, data, ok)
    assert sorted(seen) == ['5.5.5.5', '9.9.9.9']         # оба срочных — раньше очереди
    assert data['items']['9.9.9.9']['name'] == 'N'        # адрес из списка — со своей подписью
    assert data['items']['5.5.5.5']['name'] == 'Хост Y'   # IP входа вне списка — с именем хоста
    scan.step(c, None, data, ok)
    assert seen[-1] == 'a'                                # недавно проверенные — не повторяем
    scan.WAKE.clear()
    scan.set_urgent({'9.9.9.9': 'Хост X'})                # старый адрес — будить незачем
    assert not scan.WAKE.is_set()
    scan.set_urgent({})


def test_state_lines_collect_urgent():
    lines, urgent = exporter.Lines(), {}
    hosts = [{'name': 'H', 'ru': True, 'entry': False, 'ips': ['1.1.1.1']},
             {'name': 'G', 'ru': True, 'entry': False, 'ips': ['2.2.2.2']}]
    fresh = {'msk-1': {'H': {'status': 0}, 'G': {'status': 1}}}
    nl = {('xray', 'H'): 1, ('xray', 'G'): 1}
    exporter.state_lines(hosts, fresh, nl, set(), lines, urgent)
    assert urgent == {'1.1.1.1': 'H'}


def test_cdn_block_is_note_not_block():
    """«CDN Блок 16–20»: сам адрес открывается, у провайдера режутся зарубежные CDN — справка."""
    r = {'online': 5, 'results': [
        {'provider': 'Beeline', 'region': 'Ярославская область', 'verdicts': ['cdn_block']},
        {'provider': 'MTS', 'region': '', 'verdicts': ['cdn_block']},
        {'provider': 'Dom.ru', 'region': '', 'verdicts': ['cdn_block', 'ok']},
        {'provider': 'Rostelecom', 'region': '', 'verdicts': ['ok']},
        {'provider': 'Ufanet', 'region': '', 'verdicts': ['uncertain']}]}
    s = scan.summarize(r)
    assert (s['bad'], s['blocked'], s['cdn'], s['ok'], s['uncertain']) == (0, False, 3, 4, 1)
    assert scan.why(s) == '' and scan.kinds(s) == ''
    assert scan.note(s).startswith('CDN 16–20 КБ у 3 (не блокировка')
    # вместе с настоящей блокировкой — тревога только по ней
    r['results'] += [{'provider': 'A', 'region': '', 'verdicts': ['tspu_block', 'cdn_block']},
                     {'provider': 'B', 'region': '', 'verdicts': ['tspu_block']}]
    s = scan.summarize(r)
    assert (s['bad'], s['blocked'], s['cdn']) == (2, True, 4) and scan.kinds(s) == 'ТСПУ'


def test_saved_cdn_block_recounted_once(tmp_path):
    """Измерение, сохранённое, когда cdn_block был блокировкой, — после загрузки не тревога,
    и «открывают» пересчитано ровно один раз."""
    import json
    import os
    cfg = SimpleNamespace(data_dir=str(tmp_path))
    old = {'items': {'cdn.x': {'name': 'cdn.x', 'kind': 'domain', 'answered': 13, 'ok': 4, 'bad': 9,
                               'blocked': True, 'by': {'cdn_block': [f'P{i}' for i in range(9)]}}}}
    p = scan.path(cfg)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, 'w') as f:
        json.dump(old, f)
    x = scan.load(cfg)['items']['cdn.x']
    assert (x['blocked'], x['bad'], x['cdn'], x['ok']) == (False, 0, 9, 13)
    with open(p, 'w') as f:                          # loop сохранил уже пересчитанное
        json.dump({'items': {'cdn.x': x}}, f)
    assert scan.load(cfg)['items']['cdn.x']['ok'] == 13
    out = exporter.Lines()
    scan.lines({'items': {'cdn.x': x}}, out)
    text = out.text()
    assert 'rwmon_rkn_scan_blocked{target="cdn.x",kind="domain",name="cdn.x",why=""} 0' in text
    assert 'who="CDN 16–20 КБ у 9 (не блокировка' in text
