"""Графики «Серверы нод» (2.4): [node_exporter] в config.toml, список нод для Prometheus, дашборд."""
import importlib.util
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from test_rwmon import FakePanel, make_cfg                  # noqa: E402

from rwmon import config, exporter, render                   # noqa: E402


class PublicPanel(FakePanel):
    """Как FakePanel, но у Poland 1 публичный адрес, а у ноды на сервере панели — внутренний."""

    def nodes(self):
        nodes = super().nodes()
        nodes[0]['address'] = '45.154.58.229'
        nodes[1]['address'] = '172.18.0.1'
        return nodes


def load_dashboard():
    path = os.path.join(os.path.dirname(__file__), '..', '..', 'grafana', 'dashboard.py')
    spec = importlib.util.spec_from_file_location('rwmon_dashboard_test', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class NodeExporterConfigTest(unittest.TestCase):
    def test_off_by_default(self):
        self.assertEqual(make_cfg().node_exporter_port, 0)

    def test_port(self):
        self.assertEqual(make_cfg(node_exporter={'port': 9100}).node_exporter_port, 9100)
        self.assertEqual(make_cfg(node_exporter={}).node_exporter_port, 0)
        self.assertEqual(make_cfg(node_exporter={'enabled': False, 'port': 9100}).node_exporter_port, 0)

    def test_bad_port(self):
        for bad in ('9100', 0, 70000, True):
            with self.assertRaises(config.ConfigError):
                make_cfg(node_exporter={'port': bad})


class NodeTargetsTest(unittest.TestCase):
    def test_public_only(self):
        self.assertTrue(exporter.is_public_ip('45.154.58.229'))
        for ip in ('172.18.0.1', '10.1.2.3', '127.0.0.1', '', 'host.example'):
            self.assertFalse(exporter.is_public_ip(ip), ip)

    def test_collect_targets(self):
        p = make_cfg().panels[0]
        targets = {}
        exporter.collect_panel(p, PublicPanel(), exporter.Lines(), {}, node_targets=targets)
        # нода на сервере панели (внутренний адрес) и выключенная нода в список не попадают
        self.assertEqual(targets, {'45.154.58.229': {'panel': 'main', 'node_uuid': 'u1'}})

    def test_write_file_dedup(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = make_cfg(node_exporter={'port': 9100})
            cfg.links_file = os.path.join(d, 'monitor.txt')
            by_panel = {'reserve': {'1.1.1.1': {'panel': 'reserve', 'node_uuid': 'b'}},
                        'main': {'1.1.1.1': {'panel': 'main', 'node_uuid': 'a'},
                                 '8.8.8.8': {'panel': 'main', 'node_uuid': 'c'}}}
            self.assertTrue(exporter.write_node_targets(cfg, by_panel))
            with open(os.path.join(d, 'nodes.json'), encoding='utf-8') as f:
                groups = json.load(f)
            self.assertEqual(groups, [
                {'targets': ['1.1.1.1:9100'], 'labels': {'panel': 'main', 'node_uuid': 'a'}},
                {'targets': ['8.8.8.8:9100'], 'labels': {'panel': 'main', 'node_uuid': 'c'}},
            ])
            self.assertFalse(exporter.write_node_targets(cfg, by_panel))   # без изменений — не переписывает


class NodeJobTest(unittest.TestCase):
    def jobs(self, cfg):
        return {j['job_name']: j for j in render.prometheus(cfg)['scrape_configs']}

    def test_no_job_when_off(self):
        self.assertNotIn('node', self.jobs(make_cfg()))

    def test_job(self):
        job = self.jobs(make_cfg(node_exporter={'port': 9100}))['node']
        self.assertEqual(job['file_sd_configs'][0]['files'], ['/links/nodes.json'])
        keep = job['metric_relabel_configs'][0]
        self.assertEqual(keep['action'], 'keep')
        for name in ('node_cpu_seconds_total', 'node_memory_MemAvailable_bytes', 'node_filesystem_avail_bytes',
                     'node_nf_conntrack_entries_limit', 'node_boot_time_seconds'):
            self.assertRegex(name, f'^(?:{keep["regex"]})$')
        self.assertNotRegex('node_scrape_collector_duration_seconds', f'^(?:{keep["regex"]})$')


class ServersDashboardTest(unittest.TestCase):
    def rows(self, **kw):
        return {p['title']: p for p in load_dashboard().build(**kw)['panels'] if p['type'] == 'row'}

    def test_hidden_by_default(self):
        self.assertFalse(any(t.startswith('Серверы нод') for t in self.rows()))

    def test_row(self):
        row = next(p for t, p in self.rows(servers=True).items() if t.startswith('Серверы нод'))
        titles = [p['title'] for p in row['panels']]
        self.assertEqual(titles[0], 'Серверы нод')
        self.assertIn('Диск: корневой раздел', titles)
        exprs = ' '.join(t['expr'] for p in row['panels'] for t in p['targets'])
        self.assertIn('node_filesystem_avail_bytes{mountpoint="/"}', exprs)
        self.assertIn('group_left (node_name, panel_title)', exprs)   # названия нод — из rwmon_node_info

    def test_ids_unique(self):
        ids = []
        for p in load_dashboard().build(servers=True)['panels']:
            ids.append(p['id'])
            ids.extend(x['id'] for x in p.get('panels', []))
        self.assertEqual(len(ids), len(set(ids)))


if __name__ == '__main__':
    unittest.main()
