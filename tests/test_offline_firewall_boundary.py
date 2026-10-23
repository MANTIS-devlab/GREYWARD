"""Explicit Fedora packaged-helper check on a private bus and network namespace.

The real read method forwards only to the host firewall's fixed state property.
No installed service, link, policy or graphical session is changed.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
import unittest


@unittest.skipUnless(os.name == 'posix' and os.environ.get('GREYWARD_OFFLINE_POSTURE'),
                     'explicit root Fedora packaged offline boundary check')
class OfflineFirewallBoundary(unittest.TestCase):
    def test_repeated_offline_reads_use_only_the_fixed_system_projection(self):
        import pwd
        import dbus
        import dbus.mainloop.glib
        import dbus.service
        from gi.repository import GLib
        from greyward_security_context.network_policy_service import OpenSnitchPolicy, BUS_NAME, OBJECT_PATH

        self.assertEqual(os.geteuid(), 0)
        user = pwd.getpwnam(os.environ['GREYWARD_OFFLINE_TEST_USER'])
        self.assertNotEqual(user.pw_uid, 0)
        dbus.mainloop.glib.threads_init()
        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        actual = dbus.SystemBus(private=True, mainloop=dbus.mainloop.NULL_MAIN_LOOP)
        with tempfile.TemporaryDirectory(prefix='greyward-offline-bus-') as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            config = root / 'bus.conf'
            config.write_text('''<busconfig><type>system</type><auth>EXTERNAL</auth>
<listen>unix:path=''' + str(root / 'bus') + '''</listen>
<policy context="default"><allow user="*"/>
<allow send_destination="org.freedesktop.DBus"/>
<allow send_type="method_return"/><allow send_type="error"/>
<allow receive_sender="*"/></policy>
<include>''' + str(Path(os.environ['GREYWARD_OFFLINE_POLICY']).resolve()) + '''</include></busconfig>''')
            daemon = subprocess.Popen(['dbus-daemon', '--nofork', '--print-address=1',
                                       '--config-file=' + str(config)], stdout=subprocess.PIPE, text=True)
            private = None
            loop = None
            thread = None
            try:
                address = daemon.stdout.readline().strip()
                self.assertTrue(address.startswith('unix:'))
                private = dbus.bus.BusConnection(address)
                name = dbus.service.BusName(BUS_NAME, bus=private)
                calls = []

                class RoutedReadBus:
                    def get_unix_user(self, sender):
                        uid = int(private.get_unix_user(sender))
                        calls.append(uid)
                        return uid

                    def get_object(self, destination, path, **kwargs):
                        if destination != 'org.fedoraproject.FirewallD1' or path != '/org/fedoraproject/FirewallD1':
                            raise AssertionError('Unexpected upstream request')
                        return actual.get_object(destination, path, **kwargs)

                # Export the actual packaged method without starting RuleManager
                # or exposing a writable policy store in this private test bus.
                service = object.__new__(OpenSnitchPolicy)
                dbus.service.Object.__init__(service, private, OBJECT_PATH)
                service.bus = RoutedReadBus()
                commands = root / 'commands'
                commands.mkdir()
                (commands / 'nmcli').write_text('#!/bin/sh\nexit 0\n')
                attempts = root / 'firewall-attempts'
                attempts.touch(mode=0o666)
                attempts.chmod(0o666)
                (commands / 'firewall-cmd').write_text('#!/bin/sh\necho called >> ' + str(attempts) + '\nexit 1\n')
                for path in commands.iterdir():
                    path.chmod(0o755)
                loop = GLib.MainLoop()
                thread = threading.Thread(target=loop.run, daemon=True)
                thread.start()
                environment = dict(os.environ, DBUS_SYSTEM_BUS_ADDRESS=address,
                                   PATH=str(commands) + ':' + os.environ['PATH'])
                helper = str(Path(os.environ['GREYWARD_OFFLINE_POSTURE']).resolve())
                # A private executable copy avoids unreadable build directories.
                executable = root / 'posture'
                shutil.copyfile(helper, executable)
                executable.chmod(0o755)

                def sample(program=executable):
                    result = subprocess.run(['unshare', '--net', 'runuser', '-u', user.pw_name,
                                             '--', str(program)], env=environment,
                                            capture_output=True, text=True, timeout=35, check=True)
                    data = json.loads(result.stdout)
                    return next(check for check in data['checks'] if check['check_id'] == 'network.active-connection')

                previous = os.environ.get('GREYWARD_OFFLINE_PREDECESSOR')
                if previous:
                    predecessor = root / 'predecessor'
                    shutil.copyfile(previous, predecessor)
                    predecessor.chmod(0o755)
                    self.assertNotEqual(sample(predecessor)['state'], 'SECURE')
                    self.assertEqual(attempts.read_text(), 'called\n')
                    attempts.write_text('')
                    self.assertEqual(calls, [])
                for index in range(4):
                    if index:
                        time.sleep(12)
                    self.assertEqual(sample()['state'], 'SECURE')
                self.assertEqual(calls, [user.pw_uid] * 4)
                self.assertEqual(attempts.read_text(), '')
                # Provider loss must not reuse a successful prior read or call
                # a desktop fallback that could challenge the user.
                service.remove_from_connection()
                self.assertNotEqual(sample()['state'], 'SECURE')
                self.assertEqual(attempts.read_text(), '')
                del name
            finally:
                if loop:
                    loop.quit()
                if thread:
                    thread.join(timeout=3)
                if private:
                    private.close()
                daemon.terminate()
                daemon.wait(timeout=5)
                daemon.stdout.close()
                actual.close()


if __name__ == '__main__':
    unittest.main()
