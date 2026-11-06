import copy
import json
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

    def test_behavioral_notice_gauge_deduplicates_and_escalates_without_a_second_publisher(self):
        from greyward_security_context.intelligence_notices import incident_notices
        incident = {'id': 'incident-' + 'a' * 24, 'state': 'ACTIVE', 'classification': 'SUSPICIOUS',
                    'score': 45, 'confidence': 'MEDIUM', 'application': 'Validation', 'timeline': [], 'factors': []}
        snapshot = {'sensor': {'state': 'ACTIVE'}, 'incidents': [incident]}
        notice = incident_notices(snapshot)[0]
        self.router.reconcile([notice]); self.router.reconcile([notice])
        self.assertEqual(len(self.bus.sent), 1)
        self.assertNotEqual(self.bus.sent[-1][2], 'greyward-intelligence-45')
        self.assertEqual(self.bus.sent[-1][6]['image-path'], '/usr/share/icons/hicolor/scalable/apps/greyward-intelligence-45.svg')
        self.assertIn('45/100', self.bus.sent[-1][3])
        self.assertEqual(notice['route'], 'history')
        self.assertEqual(self.bus.sent[-1][6]['x-greyward-threat-score'], 45)
        self.assertIn('No behavioral block', self.bus.sent[-1][4])
        self.router._closed(1, 2)
        self.router.reconcile([notice]); self.assertEqual(len(self.bus.sent), 1)
        incident.update(classification='HIGH_THREAT', score=80)
        self.router.reconcile(incident_notices(snapshot))
        self.assertEqual(len(self.bus.sent), 2)
        self.assertEqual(self.bus.sent[-1][6]['urgency'], 2)
        self.router._action(2, 'open')
        self.assertEqual(self.dispatch.call_args.args[0]['incident_ref'], incident['id'])
        self.assertEqual(incident_notices({'sensor': {'state': 'ACTIVE'}, 'incidents': []}), [])

    def test_review_uses_existing_typed_check_route_and_rejects_unknown_routes(self):
        from greyward_security_context.notification_router import open_route
        with patch('greyward_security_context.notification_router.subprocess.Popen') as launch:
            open_route('evidence')
            self.assertEqual(launch.call_args.args[0], ['/usr/bin/greyward-security-center-route', 'evidence'])
            open_route('arbitrary-command')
            launch.assert_called_once()

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

    def test_update_reminder_survives_dismissal_provider_flap_and_service_restart(self):
        notice = {'id': 'updates-security', 'kind': 'update-notice', 'severity': 'INFO',
                  'title': 'Security updates', 'detail': 'Verified', 'reminder_seconds': 86400}
        with patch('greyward_security_context.notification_router.time.time', return_value=100000):
            self.router.reconcile([notice])
            self.router._closed(1, 2)
            self.router.reconcile([notice])
            self.router.reconcile([])
            self.router = NotificationRouter(self.bus, self.dispatch, self.path)
            self.router.reconcile([notice])
        self.assertEqual(len(self.bus.sent), 1)
        with patch('greyward_security_context.notification_router.time.time', return_value=186400):
            self.router.reconcile([notice])
        self.assertEqual(len(self.bus.sent), 2)
        self.assertFalse(self.bus.sent[-1][6]['x-greyward-quiet'])

    def test_usb_notification_never_offers_sessionless_trust_actions(self):
        item = {**self.item, 'actions': [
            {'id': 'trust_once', 'label': 'Trust once'},
            {'id': 'trust_always', 'label': 'Trust always'},
        ]}
        self.router.reconcile([item])

        # Notification review is navigation-only; trust remains in the DMS
        # widget, where its child process inherits the active session.
        self.assertEqual(self.bus.sent[-1][5], ['open', 'Review'])
        self.router._action(1, 'trust_always')
        self.dispatch.assert_not_called()
        self.router._action(1, 'open')
        self.dispatch.assert_called_once_with(item, 'open')

    def test_protected_review_handoff_is_scoped_and_never_authorizes(self):
        from greyward_security_context.notification_router import open_route
        reference = 'resource_' + 'a' * 64
        with patch('greyward_security_context.notification_router.subprocess.Popen') as launch:
            open_route('protected-data', reference)
            self.assertEqual(launch.call_args.args[0], ['/usr/bin/greyward-security-center-route', 'protected-data', reference])
            open_route('protected-data', 'resource_../../file')
            open_route('activity', reference)
            launch.assert_called_once()
    def test_application_block_dismiss_is_local_and_never_authorizes(self):
        item = {**self.item, 'kind': 'application-security', 'actions': [{'id': 'open', 'label': 'Review'}, {'id': 'dismiss', 'label': 'Dismiss'}]}
        self.router.reconcile([item])
        self.router._action(1, 'dismiss')
        self.dispatch.assert_not_called()
        self.router.reconcile([{**item, 'detail': 'More recorded attempts'}])
        self.assertEqual(len(self.bus.sent), 1)
        self.assertEqual(self.bus.closed, [1])
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

    def test_transient_posture_warnings_do_not_toast(self):
        for reference in ('secure-dns', 'firewall-unavailable', 'usb-unavailable'):
            with self.subTest(reference=reference):
                self.router._warning_since.clear()
                warning = {**self.item, 'id': reference, 'kind': 'provider', 'severity': 'WARNING', 'notification_stability_seconds': 30}
                with patch('greyward_security_context.notification_router.time.monotonic', side_effect=(10.0, 18.0)):
                    self.router.reconcile(self.router.eligible_items([warning]))
                    self.router.reconcile(self.router.eligible_items([]))
                self.assertEqual(self.bus.sent, [])

    def test_persistent_posture_warnings_toast_after_stability_window(self):
        for reference in ('secure-dns', 'firewall-unavailable', 'usb-unavailable'):
            with self.subTest(reference=reference):
                self.router._warning_since.clear()
                warning = {**self.item, 'id': reference, 'kind': 'provider', 'severity': 'WARNING', 'notification_stability_seconds': 30}
                sent_before = len(self.bus.sent)
                with patch('greyward_security_context.notification_router.time.monotonic',
                           side_effect=(30.0, 59.9, 60.0)):
                    self.router.reconcile(self.router.eligible_items([warning]))
                    self.router.reconcile(self.router.eligible_items([warning]))
                    self.assertEqual(len(self.bus.sent), sent_before)
                    self.router.reconcile(self.router.eligible_items([warning]))
                self.assertEqual(len(self.bus.sent), sent_before + 1)

    def test_recovered_notification_id_does_not_bypass_a_new_stability_window(self):
        warning = {**self.item, 'id': 'firewall-unavailable', 'kind': 'provider', 'severity': 'WARNING',
                   'notification_stability_seconds': 30}
        old = {**warning, 'detail': 'An earlier firewall warning'}
        self.path.write_text(json.dumps({'owner': self.bus.owner, 'records': {
            warning['id']: {'item': old, 'notification_id': 77, 'signature': json.dumps(old, sort_keys=True), 'acknowledged': False}
        }}))
        self.router = NotificationRouter(self.bus, self.dispatch, self.path)
        with patch('greyward_security_context.notification_router.time.monotonic', side_effect=(1.0, 30.9, 31.0)):
            self.router.reconcile(self.router.eligible_items([warning]))
            self.assertEqual(self.bus.closed, [77])
            self.router.reconcile(self.router.eligible_items([warning]))
            self.assertEqual(self.bus.sent, [])
            self.router.reconcile(self.router.eligible_items([warning]))
        self.assertEqual(len(self.bus.sent), 1)

    def test_other_and_critical_notifications_are_not_delayed(self):
        warning = {**self.item, 'id': 'network-protection', 'severity': 'WARNING'}
        critical = {**self.item, 'id': 'secure-dns', 'severity': 'CRITICAL', 'notification_stability_seconds': 30}
        with patch('greyward_security_context.notification_router.time.monotonic', return_value=0.0):
            self.router.reconcile(self.router.eligible_items([warning, critical]))
        self.assertEqual(len(self.bus.sent), 2)

    def test_alert_projection_is_shared_by_widget_and_native_publisher(self):
        warning = {**self.item, 'id': 'firewall-unavailable', 'kind': 'provider', 'severity': 'WARNING',
                   'notification_stability_seconds': 30}
        urgent = {**self.item, 'id': 'usb:urgent', 'severity': 'ACTION'}
        with patch('greyward_security_context.notification_router.time.monotonic', side_effect=(10.0, 39.9, 40.0)):
            first = self.router.eligible_items([warning, urgent])
            self.router.reconcile(first)
            self.assertEqual(first, [urgent])
            self.assertEqual(len(self.bus.sent), 1)
            self.assertEqual(self.bus.sent[0][3], 'Device')
            second = self.router.eligible_items([warning, urgent])
            self.router.reconcile(second)
            third = self.router.eligible_items([warning, urgent])
            self.router.reconcile(third)
        self.assertEqual(second, [urgent])
        self.assertEqual(third, [warning, urgent])
        self.assertEqual(len(self.bus.sent), 2)


class ScanDeliveryTests(unittest.TestCase):
    setUp = NotificationTests.setUp
    def test_completed_scan_does_not_replay_after_missing_read_restart_or_server_change(self):
        item={'id':'scan-result:fixture','kind':'scan-result','severity':'INFO','title':'Scan complete','detail':'No threats','scan_status':'CLEAN','scan_subject':'A file','route':'files'}
        self.router.reconcile([item]);self.router.reconcile([item]);self.assertEqual(len(self.bus.sent),1)
        self.router.reconcile([]);self.router.reconcile([item]);self.assertEqual(len(self.bus.sent),1)
        self.router=NotificationRouter(self.bus,self.dispatch,self.path);self.bus.owner=':1.99'
        self.router.reconcile([item]);self.assertEqual(len(self.bus.sent),1)
        self.router.reconcile([{**item,'id':'scan-result:other'}]);self.assertEqual(len(self.bus.sent),2)
        hints=self.bus.sent[0][6];self.assertTrue(self.bus.sent[0][2].endswith('greyward-scan-clean.svg?design=2'));self.assertNotIn('image-path',hints);self.assertEqual(hints['x-greyward-scan-state'],'CLEAN')
        self.assertIn('size="5"',self.bus.sent[0][4])
    def test_scan_filename_is_escaped_but_other_notification_bodies_stay_plain(self):
        item={'id':'scan-result:fixture','kind':'scan-result','severity':'INFO','title':'Scan complete','detail':'Text','scan_status':'CLEAN','scan_subject':'<font color=red>fake</font>'}
        self.router.reconcile([item]);body=self.bus.sent[-1][4]
        self.assertNotIn('<font color=red>',body)
        self.router.reconcile([{**self.item,'detail':'<b>not markup</b>'}])
        self.assertIn('&lt;b&gt;',self.bus.sent[-1][4]);self.assertNotIn('image-path',self.bus.sent[-1][6])
