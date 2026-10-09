import copy
import threading
import unittest
from unittest.mock import Mock, patch
try:
    from greyward_security_context.shell_runtime import ShellRuntime
    from greyward_security_context.usbguard import UsbGuardError
except ModuleNotFoundError:
    ShellRuntime = None


@unittest.skipIf(ShellRuntime is None, 'Session runtime requires Fedora D-Bus and GLib')
class OperationTests(unittest.TestCase):
    def test_signal_burst_coalesces_one_idle_callback_without_losing_dirty_state(self):
        runtime = object.__new__(ShellRuntime)
        runtime.dirty = False
        runtime.invalidate_pending = False
        runtime.tick = Mock()
        with patch('greyward_security_context.shell_runtime.GLib.idle_add') as schedule:
            for _ in range(20): runtime.invalidate()
            schedule.assert_called_once()
            self.assertTrue(runtime.dirty)
            runtime._tick_once()
            self.assertFalse(runtime.invalidate_pending)
            runtime.tick.assert_called_once()
            runtime.invalidate()
            self.assertEqual(schedule.call_count, 2)

    def test_background_reconciliation_precedes_read_projection(self):
        runtime = self.runtime
        runtime.dirty = True
        runtime.last_full = 0
        runtime.shell, runtime.files, runtime.network = {}, {}, {}
        calls = []
        runtime.service.reconcile_history.side_effect = lambda: calls.append("ingest")
        runtime.service.GetShellSummary.side_effect = lambda: calls.append("project") or '{}'
        runtime.service.GetFileSecuritySummary.return_value = '{}'
        runtime.service.GetPrivacyCapsule.return_value = '{}'
        runtime.service.usb.devices.return_value = ([], None)
        runtime.router.records = {}
        with patch('greyward_security_context.user_bus.network_summary', return_value={}), \
                patch('greyward_security_context.shell_runtime.build_experience', return_value={}), \
                patch('greyward_security_context.shell_runtime.GLib.idle_add'):
            runtime._collect()
        self.assertEqual(calls, ["ingest", "project"])

    def setUp(self):
        self.runtime = object.__new__(ShellRuntime)
        self.runtime.lock = threading.Lock()
        self.runtime.operations = {}
        self.runtime.snapshot = {'revision': 1, 'items': [{'id': 'usb:ref', 'connection_ref': 'ref', 'title': 'Test', 'actions': [{'id': 'trust_once'}]}]}
        self.runtime.invalidate = Mock()
        self.runtime.service = Mock()
        self.runtime.router = Mock()
        self.runtime.running = False

    def test_display_lease_renewal_does_not_change_revision_or_notifications(self):
        self.runtime.snapshot.update(fresh_until='expired', display_fresh_until='old')
        value = copy.deepcopy(self.runtime.snapshot)
        value.update(display_fresh_until='renewed')
        self.runtime._publish(value, False)
        self.assertEqual(self.runtime.snapshot['revision'], 1)
        self.assertEqual(self.runtime.snapshot['display_fresh_until'], 'renewed')
        self.runtime.service.ShellSummaryChanged.assert_not_called()
        self.runtime.router.reconcile.assert_not_called()

    def test_ack_is_published_before_worker_and_duplicate_coalesces(self):
        with patch('greyward_security_context.shell_runtime.threading.Thread') as worker:
            first = self.runtime.trust('ref', 'once')
            second = self.runtime.trust('ref', 'once')
        self.assertEqual(first['operation_id'], second['operation_id'])
        worker.assert_called_once()
        self.assertEqual(self.runtime.snapshot['items'][0]['actions'], [])
        self.assertEqual(self.runtime.snapshot['items'][0]['operation'], 'PENDING')
        self.runtime.router.reconcile.assert_called_once()

    def test_old_connection_and_unsupported_action_are_refused(self):
        self.assertFalse(self.runtime.trust('old-ref', 'once')['ok'])
        self.assertFalse(self.runtime.trust('ref', 'always')['ok'])
        self.assertFalse(self.runtime.trust('ref', 'arbitrary')['ok'])

    def test_late_result_cannot_complete_a_new_operation(self):
        self.runtime.operations['ref'] = {'operation_id': 'new', 'state': 'PENDING'}
        self.runtime._finish_trust('ref', 'old', {'state': 'COMPLETE'})
        self.assertEqual(self.runtime.operations['ref']['state'], 'PENDING')

    def test_removed_during_authorization_is_not_success(self):
        adapter = Mock()
        adapter.list_devices.side_effect = [[{'connection_ref': 'ref', 'device_id': '5'}], []]
        self.runtime.operations['ref'] = {'operation_id': 'op', 'state': 'PENDING'}
        with patch('greyward_security_context.shell_runtime.dbus.SystemBus'), patch('greyward_security_context.shell_runtime.UsbGuardAdapter', return_value=adapter), patch('greyward_security_context.shell_runtime.GLib.idle_add', side_effect=lambda fn, *args: fn(*args)):
            self.runtime._trust_worker('ref', 'once', 'op')
        self.assertEqual(self.runtime.operations['ref']['state'], 'REMOVED')

    def test_once_and_always_require_different_readback(self):
        for mode, trusted, expected in [('once', False, 'COMPLETE'), ('always', False, 'FAILED'), ('always', True, 'COMPLETE')]:
            with self.subTest(mode=mode, trusted=trusted):
                adapter = Mock()
                adapter.list_devices.return_value = [{'connection_ref': 'ref', 'device_id': '5', 'authorized': True, 'trusted': trusted}]
                self.runtime.operations['ref'] = {'operation_id': 'op', 'state': 'PENDING'}
                with patch('greyward_security_context.shell_runtime.dbus.SystemBus'), patch('greyward_security_context.shell_runtime.UsbGuardAdapter', return_value=adapter), patch('greyward_security_context.shell_runtime.GLib.idle_add', side_effect=lambda fn, *args: fn(*args)):
                    self.runtime._trust_worker('ref', mode, 'op')
                self.assertEqual(self.runtime.operations['ref']['state'], expected)
