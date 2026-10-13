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


if __name__ == '__main__':
    unittest.main()
