import copy
import threading
import unittest
from unittest.mock import Mock, patch
try:
    from greyward_security_context.shell_runtime import ShellRuntime
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
        self.runtime.snapshot = {'revision': 1, 'items': [{'id': 'usb:ref', 'connection_ref': 'ref', 'title': 'Test', 'actions': [{'id': 'trust_once'}]}],
                                 'notification_items': [{'id': 'usb:ref', 'connection_ref': 'ref', 'title': 'Test', 'actions': [{'id': 'trust_once'}]}]}
        self.runtime.invalidate = Mock()
        self.runtime.service = Mock()
        self.runtime.router = Mock()
        self.runtime.router.eligible_items.side_effect = lambda items: items
        self.runtime.bus = Mock()
        self.runtime.update_snapshot = {}
        self.runtime.boot_id = 'test-boot'
        self.runtime._read_updates = Mock()
        self.runtime.notice_preferences = Mock()
        self.runtime.notice_preferences.read.return_value = {'sensor_start': False}
        self.runtime.sensor_starts = Mock()
        self.runtime.sensor_starts.collect.return_value = []
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

    def test_metadata_checks_are_spaced_but_ready_transaction_is_read_promptly(self):
        import json
        proxy = Mock()
        proxy.GetSnapshot.return_value = json.dumps({'snapshot_refreshing': True})
        proxy.GetTransactionStatus.return_value = json.dumps({'phase': 'READY_TO_RESTART'})
        runtime = self.runtime
        runtime.next_update_check = 0
        runtime.update_check_deadline = 0
        # Call the real method; the collection test separately mocks it.
        with patch('greyward_security_context.shell_runtime.dbus.Interface', return_value=proxy), \
                patch('greyward_security_context.shell_runtime.time.monotonic', return_value=100):
            ShellRuntime._read_updates(runtime)
        self.assertEqual(runtime.next_update_check, 1000)
        self.assertEqual(proxy.GetSnapshot.call_count, 1)
        proxy.GetSnapshot.return_value = json.dumps({'snapshot_refreshing': False})
        with patch('greyward_security_context.shell_runtime.dbus.Interface', return_value=proxy), \
                patch('greyward_security_context.shell_runtime.time.monotonic', return_value=110):
            ShellRuntime._read_updates(runtime)
        with patch('greyward_security_context.shell_runtime.dbus.Interface', return_value=proxy), \
                patch('greyward_security_context.shell_runtime.time.monotonic', return_value=120):
            ShellRuntime._read_updates(runtime)
        self.assertEqual(proxy.GetSnapshot.call_count, 2)
        proxy.GetTransactionStatus.assert_called_once()
        self.assertEqual(runtime.update_snapshot['transaction']['phase'], 'READY_TO_RESTART')

    def test_widget_and_native_notifications_receive_the_same_eligible_items(self):
        live = [
            {'id': 'usb:ref', 'severity': 'ACTION'},
            {'id': 'firewall-unavailable', 'severity': 'WARNING'},
        ]
        eligible = [live[0]]
        self.runtime.router.eligible_items.side_effect = None
        self.runtime.router.eligible_items.return_value = eligible
        value = {'revision': 1, 'items': live, 'label': 'Review needed'}

        self.runtime._publish(value, True)

        self.assertIs(self.runtime.snapshot['notification_items'], eligible)
        self.runtime.router.eligible_items.assert_called_once_with(live)
        self.runtime.router.reconcile.assert_called_once_with(eligible)
        self.runtime.service.ShellSummaryChanged.assert_called_once_with(self.runtime.snapshot['revision'])

    def test_usb_approval_requires_the_active_desktop_session(self):
        result = self.runtime.trust('0' * 32, 'always')
        self.assertFalse(result['ok'])
        self.assertEqual(result['state'], 'SESSION_REQUIRED')
        self.assertIn('background request cannot show the USB approval prompt', result['detail'])
        self.assertIn('Trust always in the GREYWARD taskbar', result['detail'])

    def test_unsupported_usb_action_is_refused(self):
        self.assertFalse(self.runtime.trust('0' * 32, 'arbitrary')['ok'])
