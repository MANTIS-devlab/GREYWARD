"""Migration evidence must reject incomplete comparisons and unsafe backups."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'tools/greyward-dev' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = load('desktop-performance-gate')
baseline = load('desktop-baseline')


def evidence():
    return {'schema': 'greyward.desktop-performance/v1',
            'conditions': {'hardware': 'same-machine', 'outputs': ['laptop'], 'renderer': 'same', 'workload': 'synthetic',
                           'accounting': 'complete process groups'},
            'panels': {name: {'samples': 30, 'p95_ms': 200} for name in gate.REQUIRED_PANELS},
            'idle_cpu_one_core_percent': .1, 'steady_memory_bytes': 1000,
            'continuing_growth': False, 'idle_duration_seconds': 600}


class EvidenceTests(unittest.TestCase):
    def test_no_regression_is_not_an_improvement_claim(self):
        result = gate.compare(evidence(), evidence())
        self.assertTrue(result['regression_gate_passed'])
        self.assertFalse(result['improvement_target_met'])

    def test_two_real_improvements_meet_target(self):
        candidate = evidence()
        for panel in candidate['panels'].values():
            panel['p95_ms'] *= .8
        self.assertTrue(gate.compare(evidence(), candidate)['improvement_target_met'])

    def test_each_regression_blocks_acceptance(self):
        for key, value in [('idle_cpu_one_core_percent', .7), ('steady_memory_bytes', 1101),
                           ('continuing_growth', True), ('continuing_growth', None)]:
            with self.subTest(key=key, value=value):
                candidate = evidence()
                candidate[key] = value
                self.assertFalse(gate.compare(evidence(), candidate)['regression_gate_passed'])
        candidate = evidence()
        candidate['panels']['launcher:first']['p95_ms'] = 251
        self.assertFalse(gate.compare(evidence(), candidate)['regression_gate_passed'])

    def test_missing_or_unmatched_evidence_is_refused(self):
        for mutate in [lambda x: x['conditions'].update(renderer='different'),
                       lambda x: x['panels'].pop('launcher:first'),
                       lambda x: x['panels']['launcher:first'].update(samples=29),
                       lambda x: x.update(idle_duration_seconds=599)]:
            candidate = evidence()
            mutate(candidate)
            with self.assertRaises(ValueError):
                gate.compare(evidence(), candidate)

    def test_nonfinite_negative_and_boolean_metrics_are_refused(self):
        for bad in [float('nan'), float('inf'), -1, True, '200']:
            candidate = evidence()
            candidate['panels']['launcher:first']['p95_ms'] = bad
            with self.assertRaises(ValueError):
                gate.compare(evidence(), candidate)

    def test_old_backup_cannot_be_reused_or_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            existing = Path(temporary) / 'backup'
            existing.mkdir()
            marker = existing / 'keep'
            marker.write_text('recovery data')
            with self.assertRaises(FileExistsError):
                baseline.private_directory(existing)
            self.assertEqual(marker.read_text(), 'recovery data')

    def test_recovery_selection_excludes_runtime_and_private_input_logs(self):
        self.assertTrue(all(not name.startswith('run/') for name in baseline.RECOVERY_PATHS))
        self.assertTrue(all(not name.endswith('.log') for name in baseline.RECOVERY_PATHS))


if __name__ == '__main__':
    unittest.main()
