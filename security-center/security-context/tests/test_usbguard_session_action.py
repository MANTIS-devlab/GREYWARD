import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

try:
    from greyward_security_context.usbguard_session import request_trust
    from greyward_security_context.usbguard import parse_rule, persistent_rule_is_narrow
except ModuleNotFoundError:
    request_trust = None


@unittest.skipIf(request_trust is None, 'USBGuard session action requires Fedora D-Bus dependencies')
class UsbGuardSessionActionTests(unittest.TestCase):
    def test_isolated_cli_returns_structured_failure_without_requesting_authorization(self):
        script = Path(__file__).resolve().parents[1] / 'greyward_security_context' / 'usbguard_session.py'
        result = subprocess.run([sys.executable, '-I', '-B', str(script), 'invalid', 'once'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)['state'], 'INVALID')
        self.assertFalse(json.loads(result.stdout)['ok'])

    def device(self, **changes):
        value = {
            'connection_ref': 'a' * 32,
            'device_id': '7',
            'state': 'BLOCK',
            'controller': False,
            'can_persist': True,
            'authorized': False,
            'trusted': False,
            'identity_metadata': {'stable_id': 'sha256-fixture', 'vendor_id': '1234', 'product_id': '5678'},
        }
        value.update(changes)
        return value

    def test_once_uses_upstream_approval_and_verifies_live_readback(self):
        adapter = Mock()
        adapter.list_devices.side_effect = [[self.device()], [self.device(state='ALLOW', authorized=True)]]

        result = request_trust('a' * 32, 'once', adapter)

        self.assertEqual(result, {'ok': True, 'state': 'COMPLETE', 'detail': 'Allowed until disconnected.'})
        adapter.allow_once.assert_called_once_with('7')
        adapter.always_allow.assert_not_called()

    def test_always_requires_stable_identity_and_confirms_persistent_rule(self):
        adapter = Mock()
        adapter.list_devices.side_effect = [[self.device()], [self.device(state='ALLOW', authorized=True, trusted=True)]]

        result = request_trust('a' * 32, 'always', adapter)

        self.assertTrue(result['ok'])
        self.assertEqual(result['state'], 'COMPLETE')
        adapter.always_allow.assert_called_once_with('7')
        adapter.allow_once.assert_not_called()

    def test_always_refuses_unstable_identity_before_mutation(self):
        adapter = Mock()
        adapter.list_devices.return_value = [self.device(can_persist=False)]

        result = request_trust('a' * 32, 'always', adapter)

        self.assertFalse(result['ok'])
        self.assertEqual(result['state'], 'REFUSED')
        adapter.always_allow.assert_not_called()

    def test_invalid_or_stale_requests_do_not_change_usbguard_policy(self):
        adapter = Mock()
        self.assertEqual(request_trust('bad-reference', 'once', adapter)['state'], 'INVALID')
        self.assertEqual(request_trust('a' * 32, 'shell', adapter)['state'], 'INVALID')
        adapter.list_devices.return_value = []
        self.assertEqual(request_trust('a' * 32, 'once', adapter)['state'], 'REMOVED')
        adapter.allow_once.assert_not_called()

    def test_controller_and_changed_device_are_not_approved(self):
        adapter = Mock()
        adapter.list_devices.return_value = [self.device(controller=True)]
        self.assertEqual(request_trust('a' * 32, 'once', adapter)['state'], 'REFUSED')
        adapter.list_devices.side_effect = [[self.device()], [self.device(state='ALLOW', authorized=True,
                                                                           identity_metadata={'stable_id': 'changed'})]]
        self.assertEqual(request_trust('a' * 32, 'once', adapter)['state'], 'REMOVED')
        adapter.allow_once.assert_called_once_with('7')

    def test_live_usbguard_host_and_external_hub_rules_are_distinguished(self):
        host = parse_rule('allow id 1d6b:0002 serial "0000:05:00.3" name "xHCI Host Controller" '
                          'hash "host-hash" via-port "usb1" with-interface 09:00:00')
        hub_rule = ('block id 05e3:0610 serial "" name "USB2.1 Hub" hash "hub-hash" '
                    'parent-hash "host-hash" via-port "3-1" with-interface 09:00:00')
        hub = parse_rule(hub_rule)

        self.assertTrue(host['controller'])
        self.assertFalse(hub['controller'])
        self.assertTrue(persistent_rule_is_narrow(hub_rule))
