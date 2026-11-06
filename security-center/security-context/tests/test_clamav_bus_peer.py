"""Opt-in Fedora system-bus regression using isolated records and real UIDs.

Run as a root maintenance service with GREYWARD_CLAMAV_BUS_PEER_E2E=1.
No production scanner object, history, user data or bus policy is modified.
"""
import ast
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

NAME = 'systems.mantis.greyward.ClamAvRegression'
INTERFACE = 'systems.mantis.greyward.ClamAvScan1'
OBJECT = '/systems/mantis/greyward/ClamAvScan1'


def serve(directory):
    import dbus
    import dbus.service
    import dbus.mainloop.glib
    from gi.repository import GLib
    from greyward_security_context.clamav_service import ClamAvScan
    from greyward_security_context.file_security import FileSecurityManager
    from greyward_security_context.telemetry import TelemetryStore
    from greyward_security_context import file_security, clamav_service, scan_cache
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    store = TelemetryStore(Path(directory) / 'records/fixture.sqlite3')
    # This isolated provider has no systemd PrivateTmp namespace. Keep the
    # production ownership/DAC checks, using only its disposable fixture tree.
    file_security.PRIVATE_TMP_ROOTS = ()
    definitions = {'status':'CURRENT','engine_version':'fixture','database_version':'fixture'}
    file_security.clamav_status = lambda: definitions
    clamav_service.clamav_status = lambda: definitions
    for uid, name in ((1000, 'one'), (65534, 'two'), (None, 'historical')):
        store.create_file_scan({'operation_id': name, 'owner_uid': uid,
            'mode': 'FILE', 'scope': {'path': '/fixture-private/' + name},
            'state': 'COMPLETED', 'started_at': '2026-10-29T10:00:00Z'})
        store.upsert_file_detection({'detection_id': 'det-' + name, 'operation_id': name,
            'original_path': '/fixture-private/' + name, 'state': 'QUARANTINED',
            'last_error': '/private/' + name})
        store.record_file_action('det-' + name, 'RESTORE', 'FAILED', '/private/staging/' + name)
        if uid is not None:
            source = Path(directory)/('source-' + name)
            source.write_text('private fixture only')
            os.chown(source, uid, -1)
            before = scan_cache.fingerprint(source)
            scan_cache.save(store, uid, source, before, before,
                scan_cache.generation(definitions), 'CLEAN', name, '2026-10-30T12:00:00Z')
    bus = dbus.bus.BusConnection(os.environ['GREYWARD_TEST_BUS_ADDRESS'])
    name = dbus.service.BusName(NAME, bus=bus)
    service = ClamAvScan(bus, OBJECT)
    service.manager = FileSecurityManager(store)
    Path(directory, 'ready').touch()
    GLib.MainLoop().run()


@unittest.skipUnless(os.environ.get('GREYWARD_CLAMAV_BUS_PEER_E2E') == '1', 'opt-in Fedora system-bus test')
class RealPeerIsolationTests(unittest.TestCase):
    def test_real_peer_ownership_and_forged_payload(self):
        import pwd
        self.assertEqual(os.geteuid(), 0)
        with tempfile.TemporaryDirectory(prefix='greyward-scan-bus-') as directory:
            Path(directory).chmod(0o755)
            configuration = Path(directory, 'bus.conf')
            configuration.write_text(f'''<busconfig><type>system</type>
                <listen>unix:path={directory}/bus</listen><auth>EXTERNAL</auth>
                <policy context="default"><allow user="*"/><allow own="{NAME}"/>
                <allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>''')
            daemon = subprocess.run(['dbus-daemon', '--fork', '--print-address', '--print-pid',
                '--config-file=' + str(configuration)], capture_output=True, text=True, timeout=10, check=True)
            address, daemon_pid = daemon.stdout.strip().splitlines()
            environment = dict(os.environ)
            environment['GREYWARD_TEST_BUS_ADDRESS'] = address
            if environment.get('GREYWARD_CLAMAV_PROVIDER_PATH'):
                environment['PYTHONPATH'] = environment['GREYWARD_CLAMAV_PROVIDER_PATH']
            process = subprocess.Popen([sys.executable, __file__, '--serve', directory], env=environment)
            try:
                deadline = time.monotonic() + 15
                while not Path(directory, 'ready').exists() and time.monotonic() < deadline:
                    if process.poll() is not None:
                        self.fail('Fixture bus service did not start')
                    time.sleep(0.1)
                self.assertTrue(Path(directory, 'ready').exists())

                def call(uid, method, *args):
                    completed = subprocess.run(['setpriv', '--reuid', str(uid),
                        '--regid', str(pwd.getpwuid(uid).pw_gid), '--init-groups', '--',
                        'gdbus', 'call', '--address', address, '--dest', NAME, '--object-path', OBJECT,
                        '--method', INTERFACE + '.' + method, *args],
                        capture_output=True, text=True, timeout=15, check=True)
                    return json.loads(ast.literal_eval(completed.stdout.strip())[0])

                for uid, own, foreign in ((1000, 'one', 'two'), (65534, 'two', 'one')):
                    self.assertEqual(call(uid, 'GetScanStatus', own)['scope']['path'], '/fixture-private/' + own)
                    absent = call(uid, 'GetScanStatus', 'absent')
                    for selected in (foreign, 'historical'):
                        self.assertEqual(call(uid, 'GetScanStatus', selected), absent)
                        self.assertEqual(call(uid, 'CancelScan', selected)['state'], 'UNAVAILABLE')
                    detections = call(uid, 'ListFileDetections', json.dumps({'owner_uid': 0, 'limit': 1}))['detections']
                    self.assertEqual([d['detection_id'] for d in detections], ['det-' + own])
                    self.assertNotIn('/fixture-private/' + foreign, json.dumps(call(uid, 'GetFileSecuritySummary')))
                    batch = call(uid, 'GetFileScanInfoBatch', json.dumps([
                        str(Path(directory)/('source-'+own)), str(Path(directory)/('source-'+foreign))]))
                    self.assertEqual(batch['items'][0]['info']['validity'], 'VALID')
                    self.assertEqual(batch['items'][1]['info']['validity'], 'UNKNOWN')
                    self.assertNotIn('scanned_at', batch['items'][1]['info'])
                denied = call(65534, 'StartScan', json.dumps({'mode': 'SYSTEM'}))
                self.assertEqual(denied['state'], 'FAILED')
                self.assertIn('administrator', denied['detail'])
            finally:
                process.terminate()
                process.wait(timeout=10)
                os.kill(int(daemon_pid), signal.SIGTERM)


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--serve':
        serve(sys.argv[2])
    else:
        unittest.main()
