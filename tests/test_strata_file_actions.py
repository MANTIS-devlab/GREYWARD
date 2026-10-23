"""The actual companion CLI must not turn a button/transport success into evidence."""
import importlib.util
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
gi = ModuleType('gi')
gi.require_version = lambda *_args: None
repository = ModuleType('gi.repository')
repository.Gtk = SimpleNamespace(Application=object)
repository.GLib = SimpleNamespace()
repository.Gdk = SimpleNamespace()
spec = importlib.util.spec_from_file_location('strata_file_context', ROOT / 'security-center/file-context/greyward-file-context.py')
companion = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {'gi': gi, 'gi.repository': repository}):
    spec.loader.exec_module(companion)


class FileActionTests(unittest.TestCase):
    def invoke(self, args, result=None, error=None):
        with patch.object(sys, 'argv', ['greyward-file-context', *args]), \
                patch.object(companion, 'dbus_call', return_value=result, side_effect=error) as call, \
                patch.object(companion.subprocess, 'run') as notify:
            code = companion.main()
        return code, call, notify

    def test_verified_launch_is_reported_as_started_not_workload_success(self):
        code, call, notify = self.invoke(['--safe-open', '/tmp/a; $(do-not-execute).txt'], {'ok': True, 'state': 'LAUNCHED'})
        self.assertEqual(code, 0)
        call.assert_called_once_with('SafeOpen', '/tmp/a; $(do-not-execute).txt')
        args = notify.call_args.args[0]
        self.assertEqual(args[1], 'Safe Open started')
        self.assertNotIn('shell', notify.call_args.kwargs)

    def test_refused_malformed_or_missing_evidence_never_opens_file(self):
        for result in [None, {}, {'ok': True}, {'ok': False, 'state': 'LAUNCHED'},
                       {'ok': True, 'state': 'FAILED'}, 'LAUNCHED']:
            with self.subTest(result=result):
                code, call, notify = self.invoke(['--safe-open', '/tmp/a'], result)
                self.assertEqual(code, 1)
                self.assertEqual(call.call_count, 1)
                self.assertEqual(notify.call_args.args[0][1], 'Safe Open refused')

    def test_timeout_does_not_retry_unrestricted(self):
        code, call, _ = self.invoke(['--safe-open', '/tmp/a'], error=TimeoutError())
        self.assertEqual(code, 1)
        self.assertEqual(call.call_count, 1)

    def test_nonlocal_or_invalid_selection_never_reaches_bus(self):
        for path in ['relative', 'smb://host/a', '/tmp/a\0b', '/' + 'x' * 4096]:
            with self.subTest(path=path):
                code, call, notify = self.invoke(['--safe-open', path])
                self.assertEqual(code, 2)
                call.assert_not_called()
                notify.assert_not_called()

    def test_unknown_scan_state_is_not_completed(self):
        code, call, notify = self.invoke(['--scan', '/tmp/a'], {'state': 'UNAVAILABLE'})
        self.assertEqual(code, 1)
        call.assert_called_once_with('ScanHighRiskPath', '/tmp/a')
        self.assertEqual(companion.scan_message({}), 'Scan result unavailable')

    def test_completed_clean_or_threat_scan_returns_real_outcome(self):
        for state in ['CLEAN', 'THREAT']:
            self.assertEqual(self.invoke(['--scan', '/tmp/a'], {'state': state})[0], 0)


if __name__ == '__main__':
    unittest.main()
