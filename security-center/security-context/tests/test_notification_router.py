import copy
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from greyward_security_context.notification_router import NotificationRouter


class Bus:
    owner = ':1.20'

    def __init__(self):
        self.sent, self.closed = [], []

    def add_signal_receiver(self, *args, **kwargs): pass
    def get_name_owner(self, name): return self.owner
    def get_object(self, *args): return self

    def Notify(self, *args, **kwargs):
        self.sent.append(args)
        return args[1] or len(self.sent)

    def CloseNotification(self, reference, **kwargs): self.closed.append(reference)


class NotificationTests(unittest.TestCase):
    def setUp(self):
        fake = SimpleNamespace(Interface=lambda value, name: value, UInt32=int, Byte=int, String=str, Boolean=bool,
                               Int32=int, Array=lambda value, **kwargs: value, Dictionary=lambda value, **kwargs: value, DBusException=RuntimeError)
        self.dbus = patch.dict(sys.modules, {'dbus': fake})
        self.dbus.start()
        self.addCleanup(self.dbus.stop)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'delivery.json'
        self.bus, self.dispatch = Bus(), Mock()
        self.router = NotificationRouter(self.bus, self.dispatch, self.path)
        self.item = {'id': 'usb:one', 'kind': 'usb', 'severity': 'ACTION', 'title': 'Device', 'detail': 'Blocked', 'actions': [{'id': 'trust_once', 'label': 'Trust once'}]}

    def test_duplicate_replace_resolve_and_stale_action(self):
        self.router.reconcile([self.item])
        self.router.reconcile([self.item])
        self.assertEqual(len(self.bus.sent), 1)
        changed = {**self.item, 'detail': 'Waiting', 'actions': []}
        self.router.reconcile([changed])
        self.assertEqual(self.bus.sent[-1][1], 1)
        self.assertTrue(self.bus.sent[-1][6]['x-greyward-quiet'])
        self.router._action(1, 'trust_once')
        self.dispatch.assert_not_called()
        self.router.reconcile([])
        self.assertEqual(self.bus.closed, [1])
        self.router._action(1, 'open')
        self.dispatch.assert_not_called()

    def test_dismiss_acknowledges_until_resolution_then_new_event(self):
        self.router.reconcile([self.item])
        self.router._closed(1, 2)
        self.router.reconcile([self.item])
        self.assertEqual(len(self.bus.sent), 1)
        self.router.reconcile([])
        self.router.reconcile([self.item])
        self.assertEqual(len(self.bus.sent), 2)

    def test_backend_restart_does_not_replay_server_restart_is_quiet(self):
        self.router.reconcile([self.item])
        self.router = NotificationRouter(self.bus, self.dispatch, self.path)
        self.router.reconcile([self.item])
        self.assertEqual(len(self.bus.sent), 1)
        self.bus.owner = ':1.30'
        self.router.reconcile([self.item])
        self.assertEqual(len(self.bus.sent), 2)
        self.assertEqual(self.bus.sent[-1][1], 0)
        self.assertTrue(self.bus.sent[-1][6]['x-greyward-quiet'])

    def test_critical_escalation_reopens_acknowledged_item(self):
        self.router.reconcile([self.item])
        self.router._closed(1, 2)
        self.router.reconcile([{**self.item, 'severity': 'CRITICAL', 'timeout_ms': 0}])
        self.assertEqual(self.bus.sent[-1][-1], 0)
        self.assertEqual(self.bus.sent[-1][6]['urgency'], 2)
        self.assertFalse(self.bus.sent[-1][6]['x-greyward-quiet'])
