"""Behavioral migration, strict assembly and user-state preservation checks."""
import importlib.util
from importlib.machinery import SourceFileLoader
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    loader = SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


assembly = load('dms_assembly', ROOT / 'packaging/greyward-dms/assemble.py')
migration = load('dms_migration', ROOT / 'environment/session/greyward-dms-state-migrate')
runtime = load('dms_runtime', ROOT / 'environment/session/greyward-dms-runtime-check')
measurement = load('dms_measurement', ROOT / 'tools/greyward-dev/dms-measure.py')
locker = load('dms_locker', ROOT / 'environment/session/greyward-session-lock')


class NativeLockTests(unittest.TestCase):
    def test_waits_for_secure_wayland_confirmation(self):
        with patch.object(locker.subprocess, 'run') as request, \
             patch.object(locker.subprocess, 'check_output', side_effect=['false', 'true']) as status, \
             patch.object(locker.time, 'sleep'):
            locker.lock()
        self.assertEqual(status.call_count, 2)
        self.assertEqual(request.call_args.args[0][-2:], ['lock', 'lock'])

    def test_unconfirmed_request_fails_instead_of_claiming_locked(self):
        with patch.object(locker.subprocess, 'run'), \
             patch.object(locker.subprocess, 'check_output', return_value='false'), \
             patch.object(locker.time, 'monotonic', side_effect=[0, 0, 0, 11]), \
             patch.object(locker.time, 'sleep'):
            with self.assertRaisesRegex(RuntimeError, 'secure Wayland lock'):
                locker.lock()

    def test_disconnected_backend_is_not_success(self):
        with patch.object(locker.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'dms')):
            with self.assertRaises(subprocess.CalledProcessError):
                locker.lock()


class MeasurementFailureTests(unittest.TestCase):
    def test_inactive_service_cannot_be_measured_as_the_whole_host(self):
        with patch.object(measurement.subprocess, 'check_output', return_value='ActiveState=inactive\nControlGroup=\nMainPID=0\n'):
            with self.assertRaisesRegex(ValueError, 'inactive or unidentified'):
                measurement.sample()


class AssemblyTests(unittest.TestCase):
    def test_exact_hunk_and_changed_preimage_refusal(self):
        patch = '--- a/quickshell/dms/a.qml\n+++ b/quickshell/dms/a.qml\n@@ -1,2 +1,2 @@\n first\n-old\n+new\n'
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); target = root / 'a.qml'
            target.write_text('first\nold\n', newline='\n')
            assembly.apply_exact(root, patch)
            self.assertEqual(target.read_text(), 'first\nnew\n')
            for bad in ['first\nchanged\n', 'offset\nfirst\nold\n']:
                target.write_text(bad, newline='\n')
                with self.assertRaisesRegex(ValueError, 'preimage'):
                    assembly.apply_exact(root, patch)
                self.assertEqual(target.read_text(), bad)

    def test_path_traversal_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            for name in ['../escape', '..\\escape']:
                with self.subTest(name=name), self.assertRaises(ValueError):
                    assembly.apply_exact(Path(temp), f'--- a/quickshell/dms/{name}\n+++ b/quickshell/dms/{name}\n@@ -1 +1 @@\n-a\n+b\n')

    def test_manifest_patch_inventory_and_hashes(self):
        manifest = json.loads((ROOT / 'environment/production/dms-release.json').read_text())
        patches = ROOT / 'environment/patches/dms'
        self.assertEqual({p.name for p in patches.glob('*.patch')}, {p['file'] for p in manifest['patches']})
        for item in manifest['patches']:
            self.assertEqual(assembly.sha(patches / item['file']), item['sha256'])
        affected = {path for item in manifest['patches'] for path in item['preimages']}
        self.assertEqual(manifest['shell']['patchedFiles'], len(affected))


@unittest.skipIf(os.name == 'nt', 'Unix socket protocol checks run on Fedora')
class RuntimeTests(unittest.TestCase):
    def exercise(self, responses, expected_error=None, ipc_error=None):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'danklinux-test.sock'
            server = socket.socket(socket.AF_UNIX); server.bind(str(path)); path.chmod(0o600)
            server.listen(); server.settimeout(.1); stopped = threading.Event()
            def serve():
                while not stopped.is_set():
                    try: connection, _ = server.accept()
                    except TimeoutError: continue
                    with connection:
                        request = json.loads(connection.makefile('rb').readline())
                        result = responses[request['method']]
                        # Unsolicited events must not be mistaken for the response.
                        connection.sendall(b'{"event":"stateChanged"}\n')
                        connection.sendall((json.dumps({'id': request['id'], 'result': result})+'\n').encode())
            worker = threading.Thread(target=serve); worker.start()
            try:
                ipc = ipc_error or (lambda args, **kwargs: json.dumps(
                    {'loginctlLocked': False, 'shouldLock': False, 'sessionLockSecure': False}
                    if args[-2:] == ['lock', 'status'] else ''))
                with patch.dict(os.environ, {'DMS_SOCKET': str(path)}), patch.object(runtime.subprocess, 'check_output', side_effect=ipc), patch('builtins.print') as output:
                    if expected_error:
                        with self.assertRaisesRegex(ValueError, expected_error): runtime.check()
                    else:
                        runtime.check()
                        self.assertEqual(json.loads(output.call_args.args[0])['state'], 'READY')
            finally:
                stopped.set(); worker.join(timeout=2); server.close()

    def test_api_34_json_ping_and_internal_sampler(self):
        self.exercise({'getServerInfo': {'apiVersion': 34, 'capabilities': ['dgop']}, 'dgop.meta': {'network': [{'name': 'eth0', 'rx': 1, 'tx': 2}]}, 'ping': {'pong': True}})

    def test_old_api_and_missing_sampler_refuse_readiness(self):
        self.exercise({'getServerInfo': {'apiVersion': 28, 'capabilities': ['dgop']}}, 'Incompatible')
        self.exercise({'getServerInfo': {'apiVersion': 34, 'capabilities': ['dgop']}, 'dgop.meta': {}}, 'sampler')

    def test_unconfirmed_ping_is_not_success(self):
        for result in ['pong', {'pong': False}, {'pong': 'true'}]:
            with self.subTest(result=result):
                self.exercise({'getServerInfo': {'apiVersion': 34, 'capabilities': ['dgop']}, 'dgop.meta': {'network': []}, 'ping': result}, 'ping failed')

    def test_stalled_shell_ipc_is_not_ready(self):
        self.exercise({'getServerInfo': {'apiVersion': 34, 'capabilities': ['dgop']}, 'dgop.meta': {'network': []}, 'ping': {'pong': True}},
                      'readiness timed out', subprocess.TimeoutExpired('shell IPC', 12))


class MigrationTests(unittest.TestCase):
    def test_fresh_wallpaper_is_seeded_before_qml_and_user_changes_survive(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); state = root/'state/DankMaterialShell'
            config = root/'config/DankMaterialShell'
            migration.migrate(config, state, root/'cache', root/'plugins', 'v1.6.2-6')
            session = state/'session.json'
            self.assertEqual(json.loads(session.read_text())['wallpaperPath'],
                             '/usr/share/backgrounds/greyward/greyward-wallpaper-black-art-4k.jpg')
            for choice in ('/home/user/Pictures/custom.jpg', ''):
                session.write_text(json.dumps({'wallpaperPath': choice, 'barPinnedApps': []}))
                migration.migrate(config, state, root/'cache', root/'plugins', 'v1.6.2-6')
                self.assertEqual(json.loads(session.read_text()), {'wallpaperPath': choice, 'barPinnedApps': []})

    def test_legacy_wallpaper_preference_is_preserved_without_split_state(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); config = root/'config'; config.mkdir()
            (config/'settings.json').write_text(json.dumps({'wallpaperPath': '/Pictures/custom.jpg'}))
            migration.migrate(config, root/'state', root/'cache', root/'plugins', 'v1.6.2-6')
            self.assertEqual(json.loads((root/'state/session.json').read_text())['wallpaperPath'], '/Pictures/custom.jpg')

    def test_missing_roots_and_owned_settings_only(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); config = root/'config/DankMaterialShell'
            config.mkdir(parents=True)
            original = {'barPinnedApps': ['user-app'], 'customTheme': 'user-theme', 'acLockTimeout': 42}
            (config/'settings.json').write_text(json.dumps(original))
            backup = migration.migrate(config, root/'state/DankMaterialShell', root/'cache/DankMaterialShell', root/'system', 'v1.6.2-1')
            result = json.loads((config/'settings.json').read_text())
            self.assertEqual(result['barPinnedApps'], original['barPinnedApps'])
            self.assertEqual(result['customTheme'], 'user-theme')
            self.assertEqual(result['acLockTimeout'], 600)
            self.assertEqual(result['acMonitorTimeout'], 900)
            self.assertEqual(result['customPowerActionLock'], '')
            self.assertTrue(result['lockBeforeSuspend'])
            self.assertTrue(result['lockPamExternallyManaged'])
            self.assertEqual(result['lockPamPath'], '/etc/pam.d/greyward-dms-lock')
            self.assertEqual(json.loads((backup/'config/settings.json').read_text()), original)
            if os.name != 'nt':
                self.assertEqual((config/'settings.json').stat().st_mode & 0o777, 0o600)
                self.assertEqual(backup.stat().st_mode & 0o777, 0o700)

    def test_malformed_settings_refuse_activation_after_backup(self):
        for contents in ['{broken', '[]']:
            with self.subTest(contents=contents), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); config = root/'config/DankMaterialShell'; config.mkdir(parents=True)
                settings = config/'settings.json'; settings.write_text(contents)
                with self.assertRaises(ValueError):
                    migration.migrate(config, root/'state/DankMaterialShell', root/'cache/DankMaterialShell', root/'system', 'v1.6.2-1')
                self.assertEqual(settings.read_text(), contents)
                backup = root/'state/greyward/dms-migration/v1.6.2-1'
                self.assertEqual((backup/'config/settings.json').read_text(), contents)
                self.assertFalse((config/'.changelog-1.6').exists())

    def test_user_plugin_symlink_is_never_removed(self):
        if os.name == 'nt': self.skipTest('Symlink permissions differ on Windows; run on Fedora')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); config = root/'config/DankMaterialShell'; system = root/'system'
            plugin = system/'greywardSecure'; plugin.mkdir(parents=True)
            (plugin/'plugin.json').write_text('{}')
            (config/'plugins').mkdir(parents=True)
            (config/'plugins/greywardSecure').symlink_to(plugin, target_is_directory=True)
            migration.migrate(config, root/'state/DankMaterialShell', root/'cache/DankMaterialShell', system, 'v1.6.2-1')
            self.assertTrue((config/'plugins/greywardSecure').is_symlink())

    def exercise(self, value):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); config = root / 'config/DankMaterialShell'; state = root / 'state/DankMaterialShell'; cache = root / 'cache/DankMaterialShell'
            for path in (config, state, cache): path.mkdir(parents=True)
            (state / 'session.json').write_text(value)
            (cache / 'private').write_text('private cache')
            system = root / 'system'; plugin = system / 'greywardSecure'; plugin.mkdir(parents=True)
            (plugin / 'plugin.json').write_text('{}')
            shutil.copytree(plugin, config / 'plugins/greywardSecure')
            custom = config / 'plugins/greywardCustom'; custom.mkdir()
            (custom / 'custom.qml').write_text('owned by user')
            backup = migration.migrate(config, state, cache, system, 'v1.6.2-1')
            self.assertEqual((state / 'session.json').read_text(), value)
            self.assertEqual((backup / 'state/session.json').read_text(), value)
            self.assertTrue((backup / 'config/plugins/greywardSecure/plugin.json').exists())
            self.assertFalse((config / 'plugins/greywardSecure').exists())
            self.assertTrue((custom / 'custom.qml').exists())
            self.assertTrue((config / '.changelog-1.6').exists())
            (state / 'session.json').write_text('later changes')
            migration.migrate(config, state, cache, system, 'v1.6.2-1')
            self.assertEqual((backup / 'state/session.json').read_text(), value)

    def test_custom_empty_and_malformed_state_survives(self):
        for value in ['{"barPinnedApps":[]}', '{"barPinnedApps":["custom"]}', '{broken']:
            with self.subTest(value=value): self.exercise(value)

    def test_modified_first_party_copy_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); config = root/'config/DankMaterialShell'; system = root/'system'
            for path in [config/'plugins/greywardSecure', system/'greywardSecure']:
                path.mkdir(parents=True)
            (system/'greywardSecure/plugin.json').write_text('{}')
            user = config/'plugins/greywardSecure/plugin.json'; user.write_text('{"custom":true}')
            migration.migrate(config, root/'state/DankMaterialShell', root/'cache/DankMaterialShell', system, 'v1.6.2-1')
            self.assertEqual(user.read_text(), '{"custom":true}')


if __name__ == '__main__': unittest.main()
