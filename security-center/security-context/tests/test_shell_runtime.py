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
    def setUp(self):
        self.runtime = object.__new__(ShellRuntime)
        self.runtime.lock = threading.Lock()
        self.runtime.operations = {}
        self.runtime.snapshot = {'revision': 1, 'items': [{'id': 'usb:ref', 'connection_ref': 'ref', 'title': 'Test', 'actions': [{'id': 'trust_once'}]}]}
        self.runtime.invalidate = Mock()
        self.runtime.service = Mock()
        self.runtime.router = Mock()
        self.runtime.running = False

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
