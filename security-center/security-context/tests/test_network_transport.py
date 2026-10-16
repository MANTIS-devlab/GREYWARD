"""Private synchronous calls must not disconnect the session service loop."""
import unittest
from unittest.mock import Mock, patch

try:
    import greyward_security_context.user_bus as user_bus
except ModuleNotFoundError as error:
    if error.name not in ('dbus', 'gi', 'grpc'):
        raise
    user_bus = None


@unittest.skipIf(user_bus is None, 'Requires Fedora runtime bindings')
class NetworkTransportTests(unittest.TestCase):
    def test_reply_and_failure_close_only_a_private_synchronous_connection(self):
        for reply in ('{"ok":true}', '{broken'):
            with self.subTest(reply=reply):
                bus = Mock()
                bus.call_blocking.return_value = reply
                with patch.object(user_bus.dbus, 'SystemBus', return_value=bus) as constructor:
                    result = user_bus._network_rules_call('GetRules', '{}')
                constructor.assert_called_once_with(private=True, mainloop=user_bus.dbus.mainloop.NULL_MAIN_LOOP)
                bus.set_exit_on_disconnect.assert_called_once_with(False)
                bus.close.assert_called_once()
                self.assertEqual(result['ok'], reply == '{"ok":true}')

    def test_unknown_methods_and_oversized_payloads_never_open_a_connection(self):
        with patch.object(user_bus.dbus, 'SystemBus') as constructor:
            with self.assertRaises(ValueError):
                user_bus._network_rules_call('ArbitraryCommand', '{}')
            self.assertFalse(user_bus._network_rules_call('Apply', 'x' * 1048577)['ok'])
            constructor.assert_not_called()


if __name__ == '__main__':
    unittest.main()
