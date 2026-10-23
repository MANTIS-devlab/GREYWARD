"""Private auth profile isolation; no live policy, PAM or desktop changes."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / 'security-center/packaging/application-security/desktop/materialize.py'
SPEC = importlib.util.spec_from_file_location('authentication_clipboard_materialize', SOURCE)
materialize = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(materialize)


class AuthenticationClipboard(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.factory = root / 'factory.json'
        self.factory.write_text(json.dumps({'configVersion':18, 'clipboardMarker':'ordinary unchanged'}))
        self.state = root / 'runtime'
        patches = (
            mock.patch.object(materialize, 'STATE', self.state),
            mock.patch.object(materialize, 'Path', side_effect=lambda value:
                self.factory if str(value) == '/etc/skel/.config/DankMaterialShell/settings.json' else Path(value)),
            mock.patch.object(materialize, 'prepare_enforcement'),
            mock.patch.object(materialize, 'run'),
            mock.patch.object(materialize.os, 'getuid', return_value=0, create=True),
            mock.patch.object(materialize.os, 'geteuid', return_value=0, create=True),
            mock.patch.object(materialize.os, 'chown', create=True),
        )
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.config = self.state / 'auth-1001/config/DankMaterialShell/clsettings.json'

    def test_private_backend_starts_disabled_without_changing_factory_or_lock(self):
        before = self.factory.read_bytes()
        materialize.materialize(1001, 1001)
        self.assertEqual(json.loads(self.config.read_text()), {'disabled':True})
        if os.name == 'posix':
            self.assertEqual(self.config.stat().st_mode & 0o777, 0o444)
        settings = json.loads((self.config.parent/'settings.json').read_text())
        self.assertTrue(settings['loginctlLockIntegration'])
        self.assertEqual(settings['lockPamPath'], '/etc/pam.d/greyward-dms-lock')
        self.assertEqual(before, self.factory.read_bytes())

    @unittest.skipUnless(os.name == 'posix', 'POSIX link semantics')
    def test_linked_clipboard_configuration_is_refused(self):
        materialize.materialize(1001, 1001)
        os.link(self.config, self.config.parent/'alias')
        with self.assertRaisesRegex(RuntimeError, 'Unsafe authentication input'):
            materialize.materialize(1001, 1001)

    @unittest.skipUnless(os.name == 'posix', 'POSIX symlink semantics')
    def test_dangling_clipboard_alias_is_refused_without_creating_target(self):
        materialize.materialize(1001, 1001)
        self.config.unlink()
        target = self.config.parent/'not-created'
        self.config.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, 'Unsafe authentication input'):
            materialize.materialize(1001, 1001)
        self.assertFalse(target.exists())

    @unittest.skipUnless(os.name == 'posix', 'real Unix ownership and input modes')
    def test_2_0_profile_is_separate_and_preserves_legacy_rollback_input(self):
        materialize.materialize(1001, 1001)
        before = {p.name: p.read_bytes() for p in self.config.parent.iterdir()}
        materialize.materialize(1001, 1001, 'v2.0.0-7')
        auth = self.state / 'auth-1001'
        environment = materialize.authentication_environment(auth, 'v2.0.0-7')
        profile = Path(environment['XDG_CONFIG_HOME']) / 'dms'
        self.assertEqual(json.loads((profile / 'settings.json').read_text())['configVersion'], 42)
        self.assertEqual(json.loads((profile / 'clsettings.json').read_text()), {'disabled': True})
        self.assertEqual((profile / 'settings.json').stat().st_mode & 0o777, 0o444)
        self.assertEqual(profile.stat().st_uid, 0)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.config.parent.iterdir()})
        for key, value in environment.items():
            self.assertEqual(Path(value).name, 'dms20')
            self.assertFalse((Path(value) / 'DankMaterialShell').exists())
        self.assertIn('XDG_DATA_HOME', environment)

    def test_unknown_authentication_generation_refuses_before_writes(self):
        with mock.patch.object(materialize, 'prepare_enforcement') as prepare:
            for release in ('v2.0.1-1', 'v2.0.0-999', '../dms', None):
                with self.subTest(release=release), self.assertRaisesRegex(RuntimeError, 'Unreviewed authentication runtime'):
                    materialize.materialize(1001, 1001, release)
            prepare.assert_not_called()
        self.assertFalse(self.state.exists())

    @unittest.skipUnless(os.name == 'posix', 'POSIX aliases')
    def test_versioned_config_alias_cannot_redirect_profile_creation(self):
        auth = self.state / 'auth-1001'
        (auth / 'config').mkdir(parents=True)
        target = self.state / 'outside'; target.mkdir()
        (auth / 'config/dms20').symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, 'Unsafe versioned authentication directory'):
            materialize.materialize(1001, 1001, 'v2.0.0-7')
        self.assertEqual(list(target.iterdir()), [])



if __name__ == '__main__':
    unittest.main()
