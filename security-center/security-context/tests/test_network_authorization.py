"""Boundary negatives with real wrapper code; no live authority or mutation."""
import unittest
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from pathlib import Path
import threading
from unittest.mock import Mock, patch

try:
    from greyward_security_context import network_policy_service as service
except ModuleNotFoundError as error:
    if error.name not in ('dbus', 'gi'):
        raise
    service = None


class NetworkPolkitContractTests(unittest.TestCase):
    def test_session_service_callers_require_fresh_self_authentication(self):
        root = Path(__file__).parents[1] / 'polkit'
        rule = (root / '49-greyward-recovery.rules').read_text()
        branch = rule.split('if (action.id === "org.greyward.NetworkRules1.manage")', 1)[1].split('}', 1)[0]
        self.assertIn('subject.isInGroup("wheel")', branch)
        self.assertIn('polkit.Result.AUTH_SELF : polkit.Result.NO', branch)
        self.assertNotIn('AUTH_SELF_KEEP', branch)
        self.assertNotIn('polkit.Result.YES', branch)
        policy = (root / 'org.greyward.NetworkRules1.policy').read_text()
        self.assertIn('<allow_any>no</allow_any>', policy)
        self.assertIn('<allow_active>auth_self</allow_active>', policy)


@unittest.skipIf(service is None, 'Requires Fedora D-Bus/GObject bindings')
class NetworkAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.subject = object.__new__(service.OpenSnitchPolicy)
        self.subject.bus = Mock()
        self.subject.authorizations = {}
        self.subject.bus.get_unix_user.return_value = 1001

    def test_wheel_membership_does_not_authorize_non_administrator(self):
        with patch.object(service.pwd, 'getpwuid', return_value=SimpleNamespace(pw_name='ordinary', pw_gid=1001)), \
             patch.object(service.grp, 'getgrnam', return_value=SimpleNamespace(gr_gid=10, gr_mem=[])):
            with self.assertRaises(service.PolicyError):
                self.subject.peer(':1.2', True)
        with self.assertRaises(service.PolicyError):
            self.subject.peer(None)

    def test_legacy_remove_is_bounded_before_review_or_authentication(self):
        valid = 'greyward-' + 'a' * 20
        self.assertEqual(service.legacy_remove_id(valid), valid)
        for value in (None, 123, 'other-owner', 'greyward-' + 'a' * 100000):
            with self.assertRaises(service.PolicyError):
                service.legacy_remove_id(value)

    def test_firewall_state_read_is_fixed_bounded_and_never_authorizes_edits(self):
        self.subject.manager = Mock()
        self.subject.authorize = Mock(side_effect=AssertionError('Read requested authorization'))
        props = Mock()
        for value, expected in [('RUNNING', 'running'), ('FAILED', 'not-running'),
                                ('INIT', 'not-running'), ('', 'not-running')]:
            props.Get.return_value = value
            with patch.object(service.dbus, 'Interface', return_value=props):
                self.assertEqual(self.subject.GetFirewallState(':1.2'), expected)
            props.Get.assert_called_with('org.fedoraproject.FirewallD1', 'state', timeout=2)
        props.Get.side_effect = service.dbus.DBusException('Absent provider')
        with patch.object(service.dbus, 'Interface', return_value=props):
            self.assertEqual(self.subject.GetFirewallState(':1.2'), 'unavailable')
        with self.assertRaises(service.PolicyError):
            self.subject.GetFirewallState(None)
        self.subject.authorize.assert_not_called()
        self.assertEqual(self.subject.manager.mock_calls, [])

    def test_legacy_dns_port_allow_remains_an_ordinary_review(self):
        self.subject.peer = Mock(return_value=1001)
        self.subject.engine_ready = Mock()
        self.subject.slots = threading.BoundedSemaphore(2)
        self.subject.workers = Mock()
        self.subject.workers.submit.side_effect = lambda callback: callback()
        self.subject.manager = Mock()
        self.subject.manager.store.read.return_value = {'revision': 7}
        self.subject.manager.prepare.return_value = {'transaction': 'review'}
        self.subject.manager.apply.return_value = {'ok': True}
        payload = json.dumps({'application': '/usr/bin/curl', 'action': 'allow',
                              'duration': 'always', 'destination': {'port': 53}})
        with patch.object(service.GLib, 'idle_add', side_effect=lambda callback: callback()):
            self.subject.dispatch(payload, ':1.2', Mock(), Mock(), legacy='set')
        command = self.subject.manager.prepare.call_args.args[1]['commands'][0]
        self.assertEqual(command['operation'], 'upsert')
        self.assertNotIn('dns_exception', command['rule'])

    def auth(self, *, remote=False, active=True, display=True, locked=False, result=(True, False, None), changed=False):
        self.subject.peer = Mock(side_effect=[1001, 1002] if changed else [1001, 1001])
        self.subject.engine_ready = Mock()
        bus, login, user, session, authority = (Mock() for _ in range(5))
        login.GetUser.return_value = '/user'
        user.Get.side_effect = ['active', ('123', '/session') if display else ('', '/')]
        session.GetAll.return_value = {'Remote': remote, 'Active': active, 'LockedHint': locked, 'Seat': ('seat0', '/seat')}
        authority.CheckAuthorization.return_value = (result[0], result[1], result[2] or {})
        bus.get_object.side_effect = lambda name, path: {'/org/freedesktop/login1': login, '/user': user, '/session': session, '/org/freedesktop/PolicyKit1/Authority': authority}[str(path)]
        transaction = {'provider': 'application', 'before': {'revision': 7}, 'changes': [{'operation': 'create', 'rule': {'path': '/usr/bin/curl', 'uid': 1001}}]}
        with patch.object(service.dbus, 'SystemBus', return_value=bus), patch.object(service.dbus, 'Interface', side_effect=lambda obj, interface: obj):
            self.subject.authorize(':1.2', 1001, 'review-token', transaction)
        return authority

    def test_remote_inactive_and_missing_desktop_refused(self):
        for options in ({'remote': True}, {'active': False}, {'display': False}, {'locked': True}):
            with self.subTest(options=options), self.assertRaises(service.PolicyError):
                self.auth(**options)

    def test_cancel_challenge_and_cached_authority_refused(self):
        for result in ((False, False, {}), (True, True, {}), (True, False, {'polkit.temporary_authorization_id': 'cached'})):
            with self.subTest(result=result), self.assertRaises(service.PolicyError):
                self.auth(result=result)
        self.assertEqual(self.subject.authorizations, {})

    def test_fresh_authorization_rechecks_caller_and_engine(self):
        authority = self.auth()
        self.subject.engine_ready.assert_called_once()
        args = authority.CheckAuthorization.call_args.args
        self.assertEqual(args[0][1]['name'], ':1.2')
        self.assertEqual(args[1], service.ACTION)
        self.assertEqual(args[2]['greyward.policy_revision'], '7')
        with self.assertRaises(service.PolicyError):
            self.auth(changed=True)

    def test_unmatched_or_stale_engine_cannot_enable_mutations(self):
        current = {'rules_schema': 'greyward.network.rules/v2', 'opensnitch': {'state': 'OPERATING'},
                   'fresh_until': (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()}
        current['opensnitch']['last_seen'] = datetime.now(timezone.utc).isoformat()
        self.subject.engine_live_since = Mock(return_value=100)
        for changes in ({'rules_schema': 'old'}, {'opensnitch': {'state': 'UNAVAILABLE'}},
                        {'policy_error': 'Corrupt policy; retaining last-good'}):
            with self.subTest(changes=changes), patch.object(service, 'engine_projection', return_value=(dict(current, **changes), 200)):
                with self.assertRaises(service.PolicyError):
                    self.subject.engine_ready()
        with patch.object(service, 'engine_projection', return_value=(current, 200)):
            self.assertEqual(self.subject.engine_ready(), current)
        with patch.object(service, 'engine_projection', return_value=(current, 99)), self.assertRaises(service.PolicyError):
            self.subject.engine_ready()
        idle = dict(current, fresh_until='2000-01-01T00:00:00+00:00', opensnitch=dict(current['opensnitch'], state='DEGRADED'))
        with patch.object(service, 'engine_projection', return_value=(idle, 200)):
            self.assertEqual(self.subject.engine_ready(), idle)
        self.subject.engine_live_since.side_effect = service.PolicyError('Engine stopped')
        with patch.object(service, 'engine_projection', return_value=(idle, 200)), self.assertRaises(service.PolicyError):
            self.subject.engine_ready()


if __name__ == '__main__':
    unittest.main()
