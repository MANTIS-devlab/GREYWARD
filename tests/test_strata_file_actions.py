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
repository.Gio = SimpleNamespace()
repository.Pango = SimpleNamespace()
spec = importlib.util.spec_from_file_location('strata_file_context', ROOT / 'security-center/file-context/greyward-file-context.py')
companion = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {'gi': gi, 'gi.repository': repository}):
    spec.loader.exec_module(companion)


class FileActionTests(unittest.TestCase):
    def invoke(self, args, result=None, error=None):
        if args and args[0] == '--scan' and isinstance(result, dict) and result.get('state') in {'CLEAN', 'THREAT'}:
            final = {'state': 'COMPLETED', 'detection_count': int(result['state'] == 'THREAT')}
            result, error = None, [{'operation_id': 'fixture'}, final]
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
        self.assertEqual(call.call_args.args[0], 'StartScan')
        self.assertEqual(__import__('json').loads(call.call_args.args[1])['paths'], ['/tmp/a'])
        self.assertEqual(companion.scan_message({}), 'Scan result unavailable')

    def test_completed_clean_or_threat_scan_returns_real_outcome(self):
        for state in ['CLEAN', 'THREAT']:
            self.assertEqual(self.invoke(['--scan', '/tmp/a'], {'state': state})[0], 0)

    def test_scan_completion_has_only_the_canonical_publisher(self):
        for state in ['CLEAN','THREAT']:
            code, _call, notify = self.invoke(['--scan','/tmp/a'],{'state':state})
            self.assertEqual(code,0);notify.assert_not_called()

    def test_folder_scan_information_does_not_require_document_provenance(self):
        from unittest.mock import Mock
        window = object.__new__(companion.FileContext)
        window.path = '/folder'
        for name in ('file_title','path_label','status','security_status','provenance_box','checks_box','safe_box','sharing_box'):
            setattr(window, name, Mock())
        window._present_receipt = Mock()
        window._clear = lambda _box: None
        window._row = lambda label, value: (label, value)
        def request(method, *_args):
            if method == 'GetSummary': return {'state':'PROTECTED'}
            if method == 'GetFileScanInfo': return {'state':'CLEAN','validity':'VALID','detail':'Current folder scan'}
            raise AssertionError('Document-only provenance must not be requested for a folder')
        with patch.object(companion, 'dbus_call', side_effect=request), patch.object(Path, 'is_dir', return_value=True):
            window._load_context()
        window.status.set_label.assert_called_with('Current folder scan')

    def test_scan_result_never_promotes_a_stale_receipt(self):
        from unittest.mock import Mock
        window = object.__new__(companion.FileContext)
        window.scanning = False
        window._last_result = None
        window._set_result = Mock()
        for current in ('CLEAN', 'THREAT'):
            window._present_receipt({'state': current, 'validity': 'STALE'})
            self.assertEqual(window._set_result.call_args.args[0], 'neutral')
        window._present_receipt({'state': 'CLEAN', 'validity': 'VALID'})
        self.assertEqual(window._set_result.call_args.args[:2], ('clean', 'No threats detected'))

    def test_scan_window_never_marks_empty_or_incomplete_counters_clean(self):
        from unittest.mock import Mock
        window = object.__new__(companion.FileContext)
        window._pulse_source = None
        for attr in ('cancel_button', 'progress', 'scan_button', 'status', '_load_context', '_set_result'):
            setattr(window, attr, Mock())
        for inspected, errors, expected in [(0, 0, 'neutral'), (None, 0, 'review'), (2, 1, 'review'), (2, 0, 'clean')]:
            window._scan_finished({'state': 'CLEAN', 'files_inspected': inspected, 'detection_count': 0, 'skipped_count': 0, 'error_count': errors}, None)
            self.assertEqual(window._set_result.call_args.args[0], expected)

    def test_cancellation_reaches_the_owning_operation(self):
        cancellation = __import__('threading').Event()
        cancellation.set()
        with patch.object(companion, 'dbus_call', side_effect=[{'operation_id':'fixture'}, {'state':'CANCELLED'}]) as call:
            self.assertEqual(companion.scan_selection('/tmp/a', cancellation=cancellation)['state'], 'CANCELLED')
        self.assertEqual(call.call_args.args, ('CancelScan', 'fixture'))


if __name__ == '__main__':
    unittest.main()
