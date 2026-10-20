"""Contract tests for the explicit protected DMS shell migration."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
from types import SimpleNamespace
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'packaging/greyward-enrollment/migrate-dms-shell.py'
try:
    import pwd  # noqa: F401
except ModuleNotFoundError:  # Windows contract tests do not call account lookups.
    sys.modules['pwd'] = types.ModuleType('pwd')
SPEC = importlib.util.spec_from_file_location('greyward_dms_shell_migration', SOURCE)
migration = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(migration)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class DmsShellMigrationTests(unittest.TestCase):
    def test_quiescent_check_rejects_account_name_before_scanning_processes(self):
        replies = [SimpleNamespace(stdout='49 1000 fixture-user seat0\n'),
                   SimpleNamespace(stdout='Name=fixture-user\nClass=user\nSeat=seat0\nRemote=no\n')]
        with patch.object(migration.subprocess, 'run', side_effect=replies), patch.object(Path, 'iterdir') as scan:
            with self.assertRaisesRegex(RuntimeError, 'Log out'):
                migration.ensure_quiescent({'fixture-user'})
        scan.assert_not_called()

    def test_protected_login_input_refresh_is_detected_without_a_dms_version_change(self):
        with tempfile.TemporaryDirectory() as directory:
            shell = Path(directory) / 'shell'
            (shell / 'Services').mkdir(parents=True)
            source = shell / 'Services/Authentication.qml'
            source.write_text('one-second readiness heartbeat')
            authentication = b'{"schema":"greyward.authentication-shell/v1"}\n'
            authentication_worker = b'launch immutable early splash before DMS'
            materialize = b'auth config version 17'
            keyboard_json = b'{"schema":"greyward.keyboard-settings/v1","model":"pc105","layout":"fr","variant":"","options":""}\n'
            keyboard_config = b'validated keyboard configuration module'
            session = b'private relative Wayland socket alias'
            verifier = b'protected helper domain verifier'
            manifest = {
                'source': {'dms': 'v1.6.2-14'},
                'files': {
                    'bin/dms': sha(b'current dms binary'),
                    'shell/Services/Authentication.qml': sha(b'one-second readiness heartbeat'),
                    'authentication-input/authentication.json': sha(authentication),
                    'authentication.py': sha(authentication_worker),
                    'materialize.py': sha(materialize),
                    'keyboard.json': sha(keyboard_json),
                    'keyboard_config.py': sha(keyboard_config),
                    'session.py': sha(session),
                    'verify.py': sha(verifier),
                },
            }
            self.assertTrue(migration.payload_matches_current(
                manifest, 'v1.6.2-14', sha(b'current dms binary'), shell,
                authentication, authentication_worker, materialize, keyboard_json,
                keyboard_config, session,
                verifier))

            source.write_text('100ms startup readiness poll')
            self.assertFalse(migration.payload_matches_current(
                manifest, 'v1.6.2-14', sha(b'current dms binary'), shell,
                authentication, authentication_worker, materialize, keyboard_json,
                keyboard_config, session,
                verifier))

            source.write_text('one-second readiness heartbeat')
            self.assertFalse(migration.payload_matches_current(
                manifest, 'v1.6.2-14', sha(b'new dms binary'), shell,
                authentication, authentication_worker, materialize, keyboard_json,
                keyboard_config, session,
                verifier))
            self.assertFalse(migration.payload_matches_current(
                manifest, 'v1.6.2-14', sha(b'current dms binary'), shell,
                authentication, authentication_worker, b'auth config version 18', keyboard_json,
                keyboard_config, session,
                verifier))
            self.assertFalse(migration.payload_matches_current(
                manifest, 'v1.6.2-14', sha(b'current dms binary'), shell,
                authentication, authentication_worker, materialize, keyboard_json,
                keyboard_config, b'old absolute Wayland socket',
                verifier))
            self.assertFalse(migration.payload_matches_current(
                manifest, 'v1.6.2-14', sha(b'current dms binary'), shell,
                authentication, b'old delayed auth startup', materialize, keyboard_json,
                keyboard_config, session,
                verifier))
            self.assertFalse(migration.payload_matches_current(
                manifest, 'v1.6.2-14', sha(b'current dms binary'), shell,
                authentication, authentication_worker, materialize, keyboard_json,
                keyboard_config, session,
                b'older verifier'))

    def test_manifest_refresh_replaces_only_dms_payload_and_keeps_account_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shell = root / 'shell'
            (shell / 'Services').mkdir(parents=True)
            (shell / 'Services/WlrOutputService.qml').write_text('response readiness')
            authentication = b'{"schema":"greyward.authentication-shell/v1"}\n'
            authentication_worker = b'launch immutable early splash before DMS'
            materialize = b'auth config version 18'
            keyboard_json = b'{"schema":"greyward.keyboard-settings/v1","model":"pc105","layout":"fr","variant":"","options":""}\n'
            keyboard_config = b'validated keyboard configuration module'
            session = b'private relative Wayland socket alias'
            verifier = b'approved USB helper session verifier'
            manifest = {
                'schema': 'greyward.protected-desktop/v1',
                'source': {'labwc': 'pinned-labwc', 'dms': 'v1.6.2-12'},
                'accounts': {'1001': {'name': 'fixture-user', 'gid': 1001}},
                'files': {
                    'bin/labwc': 'a' * 64,
                    'bin/dms': 'b' * 64,
                    'shell/Services/Old.qml': 'c' * 64,
                    'authentication-input/authentication.json': 'd' * 64,
                },
            }

            updated = migration.update_desktop_manifest(
                manifest, 'v1.6.2-13', 'e' * 64, shell, authentication,
                authentication_worker, materialize, keyboard_json,
                keyboard_config, session, verifier)

            self.assertEqual(updated['source']['dms'], 'v1.6.2-13')
            self.assertEqual(updated['accounts'], manifest['accounts'])
            self.assertEqual(updated['files']['bin/labwc'], 'a' * 64)
            self.assertEqual(updated['files']['bin/dms'], 'e' * 64)
            self.assertNotIn('shell/Services/Old.qml', updated['files'])
            self.assertEqual(updated['files']['shell/Services/WlrOutputService.qml'],
                             sha(b'response readiness'))
            self.assertEqual(updated['files']['authentication-input/authentication.json'],
                             sha(authentication))
            self.assertEqual(updated['files']['authentication.py'],
                             sha(authentication_worker))
            self.assertEqual(updated['files']['materialize.py'], sha(materialize))
            self.assertEqual(updated['files']['keyboard.json'], sha(keyboard_json))
            self.assertEqual(updated['files']['keyboard_config.py'], sha(keyboard_config))
            self.assertEqual(updated['files']['session.py'], sha(session))
            self.assertEqual(updated['files']['verify.py'], sha(verifier))
            self.assertEqual(manifest['source']['dms'], 'v1.6.2-12')

    def test_administration_receipt_repairs_stale_desktop_link(self):
        new_desktop = b'{"new":"receipt"}\n'
        admin = {'schema': 'greyward.administration/v1', 'desktop': 'a' * 64,
                 'files': {'worker.py': 'a' * 64}, 'tools': {'/usr/bin/sudo': 'b' * 64}}

        updated = migration.update_admin_manifest(admin, new_desktop)

        self.assertEqual(updated['desktop'], sha(new_desktop))
        self.assertEqual(updated['files'], admin['files'])
        self.assertEqual(updated['tools'], admin['tools'])
        self.assertEqual(admin['desktop'], 'a' * 64)

    def test_verifier_only_receipt_refresh_changes_only_the_verifier_digest(self):
        desktop = {
            'schema': 'greyward.protected-desktop/v1',
            'source': {'labwc': 'pinned', 'dms': 'v1.6.2-21'},
            'accounts': {'1000': {'name': 'fixture-user'}},
            'files': {'verify.py': 'a' * 64, 'bin/labwc': 'b' * 64},
        }

        updated = migration.update_verifier_manifest(desktop, b'new verifier')

        self.assertEqual(updated['files']['verify.py'], sha(b'new verifier'))
        self.assertEqual(updated['files']['bin/labwc'], 'b' * 64)
        self.assertEqual(desktop['files']['verify.py'], 'a' * 64)

    @unittest.skipUnless(os.name != 'nt' and hasattr(os, 'geteuid')
                         and os.geteuid() == 0
                         and Path('/usr/bin/chcon').is_file(),
                         'requires root Fedora SELinux migration primitives')
    def test_verifier_only_migration_refreshes_linked_receipts_atomically(self):
        with tempfile.TemporaryDirectory(prefix='greyward-verifier-migration-',
                                          dir='/root') as directory:
            root = Path(directory)
            base, admin, source = root / 'desktop', root / 'administration', root / 'source'
            base.mkdir(mode=0o755)
            admin.mkdir(mode=0o755)
            source.mkdir(mode=0o755)
            old_verifier = b'# old verifier\nVALUE = False\n'
            new_verifier = b'# new verified helper policy\nVALUE = True\n'
            (base / 'verify.py').write_bytes(old_verifier)
            (source / 'verify.py').write_bytes(new_verifier)
            (base / 'verify.py').chmod(0o444)
            (source / 'verify.py').chmod(0o444)
            desktop = {
                'schema': 'greyward.protected-desktop/v1',
                'source': {'dms': 'v1.6.2-21'},
                'accounts': {'1000': {'name': 'synthetic-user'}},
                'files': {'verify.py': sha(old_verifier)},
            }
            desktop_bytes = (json.dumps(desktop, indent=2) + '\n').encode()
            (base / 'desktop.json').write_bytes(desktop_bytes)
            (base / 'desktop.json').chmod(0o444)
            admin_manifest = {
                'schema': 'greyward.administration/v1',
                'desktop': sha(desktop_bytes), 'files': {}, 'tools': {},
            }
            admin_bytes = (json.dumps(admin_manifest, indent=2) + '\n').encode()
            (admin / 'manifest.json').write_bytes(admin_bytes)
            (admin / 'manifest.json').chmod(0o444)

            with patch.object(migration, 'LOCK', root / 'migration.lock'), \
                    patch.object(migration, 'ensure_quiescent'):
                result = migration.migrate_verifier_only(base, admin, source)

            refreshed_desktop = json.loads((base / 'desktop.json').read_bytes())
            refreshed_admin = json.loads((admin / 'manifest.json').read_bytes())
            self.assertIn('refreshed', result)
            self.assertEqual((base / 'verify.py').read_bytes(), new_verifier)
            self.assertEqual(refreshed_desktop['files']['verify.py'], sha(new_verifier))
            self.assertEqual(refreshed_admin['desktop'], sha((base / 'desktop.json').read_bytes()))

    def test_verifier_only_migration_is_quiescent_and_updates_linked_receipts(self):
        source = SOURCE.read_text()
        self.assertIn("parser.add_argument('--refresh-verifier-only'", source)
        self.assertIn('def migrate_verifier_only(', source)
        self.assertIn('ensure_quiescent(accounts)', source)
        self.assertIn("verifier_source = desktop_source / 'verify.py'", source)
        self.assertIn("atomic_write(base / 'verify.py', verifier_bytes", source)
        self.assertIn("atomic_write(desktop_path, new_desktop_bytes", source)
        self.assertIn("atomic_write(admin_path, new_admin_bytes", source)
        self.assertIn("atomic_write(base / 'verify.py', previous_verifier", source)

    def test_administration_receipt_rejects_malformed_desktop_link(self):
        admin = {'schema': 'greyward.administration/v1', 'desktop': 'not-a-digest',
                 'files': {}, 'tools': {}}
        with self.assertRaisesRegex(RuntimeError, 'Administration receipt is invalid'):
            migration.update_admin_manifest(admin, b'new')

    def test_migration_is_explicit_and_installed_by_enrollment_package(self):
        source = SOURCE.read_text()
        spec = (ROOT / 'packaging/greyward-enrollment/greyward-enrollment.spec').read_text()
        self.assertIn('ensure_quiescent(accounts)', source)
        self.assertIn('greyward-migrate-protected-dms-shell', spec)
        self.assertIn('Log out of the protected desktop first', source)
        self.assertIn("'greyward_as_auth_runtime_t'", source)
        self.assertIn("'greyward_as_auth_exec_t'", source)
        self.assertIn("session_source = desktop_source / 'session.py'", source)
        self.assertIn("verifier_source = desktop_source / 'verify.py'", source)
        self.assertIn("authentication_source = desktop_source / 'authentication.py'", source)
        self.assertIn("'authentication.py'] = digest(authentication_worker)", source)
        self.assertIn("atomic_write(base / 'authentication.py', authentication_worker_bytes", source)
        self.assertIn("'session.py'] = digest(session)", source)
        self.assertIn("'verify.py'] = digest(verifier)", source)
        self.assertIn("atomic_write(base / 'verify.py', verifier_bytes", source)

    def test_quiescent_migration_applies_usb_policy_and_labels_both_helpers(self):
        source = SOURCE.read_text()
        self.assertIn('def activate_usbguard_approval_policy(accounts):', source)
        self.assertIn("'/usr/sbin/semodule', '-i', str(USBGUARD_POLICY)", source)
        self.assertIn("'/usr/sbin/restorecon', str(helper)", source)
        self.assertIn("'/usr/sbin/matchpathcon', '-V', str(helper)", source)
        self.assertIn("runtime / 'usbguard-approval'", source)
        self.assertIn("instance / 'instance.lock'", source)
        self.assertIn("instance / 'ipc.sock'", source)
        self.assertIn("activate_usbguard_approval_policy(accounts)", source)
        self.assertIn("greyward-usbguard-approval'", source)
        self.assertIn("greyward-usbguard-auth-approval'", source)
        self.assertLess(source.rindex('activate_usbguard_approval_policy(accounts)'),
                        source.index('if payload_matches_current(desktop'))

    @unittest.skipUnless(hasattr(socket, 'AF_UNIX'), 'requires Unix domain sockets')
    def test_migration_relabels_only_owned_existing_usbguard_runtime_endpoints(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / 'runtime'
            by_id = runtime / 'quickshell/by-id/instance-a'
            by_id.mkdir(parents=True)
            metadata = runtime / 'usbguard-approval'
            metadata.mkdir(mode=0o700)
            readiness = metadata / 'readiness.json'
            instance_lock = by_id / 'instance.lock'
            readiness.write_text('{}\n')
            instance_lock.write_text('{}\n')
            readiness.chmod(0o600)
            instance_lock.chmod(0o600)
            usb_socket = socket.socket(socket.AF_UNIX)
            try:
                usb_socket.bind(str(by_id / 'ipc.sock'))
                (by_id / 'ipc.sock').chmod(0o600)
                with patch.object(migration.subprocess, 'run') as run:
                    migration.label_existing_usbguard_runtime(runtime, os.getuid())
                relabelled = [call.args[0][-1] for call in run.call_args_list
                              if call.args[0][0] == '/usr/sbin/restorecon']
                self.assertEqual(set(relabelled), {
                    str(metadata), str(readiness),
                    str(by_id / 'instance.lock'),
                    str(by_id / 'ipc.sock'),
                })
                self.assertEqual(len(run.call_args_list), 8)
            finally:
                usb_socket.close()

    @unittest.skipUnless(os.name != 'nt', 'Windows symlink privilege is not assumed')
    def test_migration_refuses_symlinked_usbguard_runtime_endpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / 'runtime'
            runtime.mkdir()
            target = Path(directory) / 'target'
            target.write_text('{}\n')
            metadata = runtime / 'usbguard-approval'
            metadata.mkdir(mode=0o700)
            (metadata / 'readiness.json').symlink_to(target)
            with self.assertRaisesRegex(RuntimeError, 'Unsafe protected authentication runtime endpoint'):
                migration.label_existing_usbguard_runtime(runtime, os.getuid())


if __name__ == '__main__':
    unittest.main()
