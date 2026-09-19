import unittest
from unittest.mock import Mock
try:
    from greyward_security_context.usbguard import parse_rule, UsbGuardAdapter
except ModuleNotFoundError:
    parse_rule = None


@unittest.skipIf(parse_rule is None, 'USBGuard D-Bus adapter requires Fedora dependencies')
class UsbGuardTests(unittest.TestCase):
    def test_mutation_requests_upstream_interactive_authorization(self):
        try:
            import dbus.lowlevel
        except ModuleNotFoundError:
            self.skipTest('Real D-Bus message type requires Fedora')
        bus = Mock()
        bus.send_message_with_reply_and_block.return_value.get_args_list.return_value = [4]
        self.assertEqual(UsbGuardAdapter(bus).allow_once('42'), 4)
        message, timeout = bus.send_message_with_reply_and_block.call_args.args
        self.assertTrue(message.get_allow_interactive_authorization())
        self.assertEqual(message.get_member(), 'applyDevicePolicy')
        self.assertEqual(message.get_args_list(), [42, 0, False])
        self.assertEqual(timeout, 120)

    def test_unquoted_and_composite_interfaces(self):
        base = 'allow id 1234:5678 name "Device" hash "stable" via-port "1-2" '
        self.assertEqual(parse_rule(base + 'with-interface 08:06:50')['device_class'], 'EXTERNAL_STORAGE')
        self.assertEqual(parse_rule(base + 'with-interface { 03:00:00 08:06:50 }')['device_class'], 'EXTERNAL_STORAGE')
        self.assertTrue(parse_rule(base.replace('1-2', 'usb1') + 'with-interface 09:00:00')['controller'])
        self.assertFalse(parse_rule(base)['controller'])

    def test_upstream_policy_matching_and_attachment_reference(self):
        bus = Mock()
        bus.get_name_owner.return_value = ':1.4'
        adapter = UsbGuardAdapter(bus)
        listing = Mock(return_value=[(42, 'allow id 1234:5678 hash "stable" via-port "1-2" with-interface 08:06:50')])
        policy = Mock(return_value=[(7, 'allow id 1234:5678 hash "stable"')])
        adapter.method = lambda path, interface, name: listing if name == 'listDevices' else policy
        one = adapter.list_devices()[0]
        self.assertTrue(one['trusted'])
        self.assertIn('match id 1234:5678 hash "stable"', [x.args[0] for x in listing.call_args_list])
        bus.get_name_owner.return_value = ':1.5'
        self.assertNotEqual(adapter.list_devices()[0]['connection_ref'], one['connection_ref'])
        policy.return_value = []
        temporary = adapter.list_devices()[0]
        self.assertTrue(temporary['authorized'])
        self.assertFalse(temporary['trusted'])
