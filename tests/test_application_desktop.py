"""Protected display closure assets; no session or SELinux mutation."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / 'security-center/packaging/application-security/desktop/prepare.py'
SPEC = importlib.util.spec_from_file_location('greyward_desktop_assembly', SOURCE)
assembly = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(assembly)
SESSION_SPEC = importlib.util.spec_from_file_location('greyward_desktop_session', SOURCE.with_name('session.py'))
session = importlib.util.module_from_spec(SESSION_SPEC)
SESSION_SPEC.loader.exec_module(session)
KEYBOARD_SOURCE = SOURCE.with_name('greyward_keyboard.py')
KEYBOARD_SPEC = importlib.util.spec_from_file_location('greyward_keyboard_config', KEYBOARD_SOURCE)
keyboard = importlib.util.module_from_spec(KEYBOARD_SPEC)
KEYBOARD_SPEC.loader.exec_module(keyboard)


class DesktopLifetime(unittest.TestCase):
    def test_protected_labwc_receives_the_validated_per_user_keyboard_choice(self):
        source = SOURCE.with_name('session.py').read_text()
        self.assertNotIn('DISPLAY_XKB_DEFAULTS', source)
        self.assertIn('from greyward_keyboard import protected_environment', source)
        self.assertIn("env.update(protected_environment(account['home'], uid))", source)

    def test_protected_keyboard_uses_user_override_and_ignores_invalid_preference(self):
        installed = {'XKB_DEFAULT_MODEL': 'pc105', 'XKB_DEFAULT_LAYOUT': 'us',
                     'XKB_DEFAULT_VARIANT': '', 'XKB_DEFAULT_OPTIONS': ''}
        with mock.patch.object(keyboard, '_read_system_default', return_value=installed), \
             mock.patch.object(keyboard, '_read_home_file',
                               side_effect=[b'XKB_DEFAULT_LAYOUT=fr\n',
                                            b'XKB_DEFAULT_LAYOUT=$(touch /tmp/pwned)\n']):
            result = keyboard.protected_environment('/home/alice', 1001)
        self.assertEqual(result['XKB_DEFAULT_LAYOUT'], 'fr')


class KeyboardConfiguration(unittest.TestCase):
    def test_labwc_environment_dropins_override_the_main_user_environment(self):
        self.assertEqual(keyboard.DEFAULT_NAME, '50-greyward-default-keyboard.env')
        self.assertEqual(keyboard.OVERRIDE_NAME, '95-greyward-user-keyboard.env')
        self.assertIn("('environment.d', uid)", KEYBOARD_SOURCE.read_text())

    def test_anaconda_localed_selection_seeds_labwc_settings(self):
        status = """VC Keymap: fr
X11 Layout: fr,us
X11 Model: pc105
X11 Variant: ,intl
X11 Options: grp:alt_shift_toggle
"""
        self.assertEqual(keyboard.parse_localectl_status(status), {
            'XKB_DEFAULT_MODEL': 'pc105',
            'XKB_DEFAULT_LAYOUT': 'fr,us',
            'XKB_DEFAULT_VARIANT': ',intl',
            'XKB_DEFAULT_OPTIONS': 'grp:alt_shift_toggle',
        })

    def test_vconsole_layout_is_a_fallback_when_localed_has_no_x11_layout(self):
        self.assertEqual(keyboard.parse_localectl_status('VC Keymap: fr\n')['XKB_DEFAULT_LAYOUT'], 'fr')

    def test_session_launcher_adds_only_validated_per_user_keyboard_values(self):
        expected = {'XKB_DEFAULT_MODEL': 'pc105', 'XKB_DEFAULT_LAYOUT': 'fr',
                    'XKB_DEFAULT_VARIANT': 'oss', 'XKB_DEFAULT_OPTIONS': ''}
        account = SimpleNamespace(pw_dir='/home/alice', pw_name='alice')
        pwd = SimpleNamespace(getpwuid=mock.Mock(return_value=account))
        with mock.patch.dict(os.environ, {'HOME': '/home/alice'}, clear=True), \
             mock.patch.dict(sys.modules, {'pwd': pwd}), \
             mock.patch.object(keyboard.os, 'getuid', return_value=1001, create=True), \
             mock.patch.object(keyboard.os, 'geteuid', return_value=1001, create=True), \
             mock.patch.object(keyboard.Path, 'is_absolute', return_value=True), \
             mock.patch.object(keyboard.Path, 'stat', return_value=SimpleNamespace(st_uid=1001)), \
             mock.patch.object(keyboard, 'user_environment', return_value=expected), \
             mock.patch.object(keyboard.os, 'execvpe') as execvpe:
            keyboard.exec_with_keyboard_environment(['/usr/bin/uwsm', 'start', 'labwc'])
        self.assertEqual(execvpe.call_args.args[0], '/usr/bin/uwsm')
        self.assertEqual(execvpe.call_args.args[1], ['/usr/bin/uwsm', 'start', 'labwc'])
        self.assertEqual({key: execvpe.call_args.args[2][key] for key in expected}, expected)

    def test_only_valid_xkb_assignments_are_parsed(self):
        values = {'XKB_DEFAULT_MODEL': 'pc105', 'XKB_DEFAULT_LAYOUT': 'us,fr',
                  'XKB_DEFAULT_VARIANT': ',oss', 'XKB_DEFAULT_OPTIONS': 'grp:alt_shift_toggle'}
        self.assertEqual(keyboard.parse_environment(keyboard.serialize_environment(values)), values)
        with self.assertRaises(ValueError):
            keyboard.parse_environment('XKB_DEFAULT_LAYOUT=us\nPATH=/tmp\n')
        with self.assertRaises(ValueError):
            keyboard.parse_environment('XKB_DEFAULT_LAYOUT=us\nXKB_DEFAULT_LAYOUT=fr\n')
        with self.assertRaises(ValueError):
            keyboard.validate({**values, 'XKB_DEFAULT_LAYOUT': 'us;touch /tmp/pwned'})

    @unittest.skipUnless(hasattr(os, 'setxattr'), 'SELinux xattr lifecycle test requires Linux')
    def test_admitted_scope_is_retired_even_when_logind_termination_times_out(self):
        import subprocess
        state = mock.Mock()
        with mock.patch.object(session, 'process', return_value=42), \
             mock.patch.object(session.select, 'select', return_value=([42], [], [])), \
             mock.patch.object(session.os, 'setxattr'), \
             mock.patch.object(session.subprocess, 'run', side_effect=[subprocess.TimeoutExpired('loginctl', 3), mock.Mock()]) as run:
            with self.assertRaises(subprocess.TimeoutExpired):
                session.monitor(1001, 123, 456, '815', [], state, '/dev/tty1', 'original')
        state.unlink.assert_called_once_with(missing_ok=True)
        self.assertEqual(run.call_args_list[1].args[0],
                         ['/usr/bin/systemctl', 'stop', '--no-block', 'session-815.scope'])


class DesktopTheme(unittest.TestCase):
    def metadata(self, original):
        # Temporary fixtures are not root-owned packaging inputs. Model that
        # ownership only; retain actual types and data for the copy checks.
        def stat(path):
            value = original(path)
            return SimpleNamespace(st_uid=0, st_mode=value.st_mode & ~0o022, st_size=value.st_size)
        return stat

    def test_canonical_theme_and_buttons_are_in_the_actual_xdg_lookup_path(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            source = base / 'canonical'
            source.mkdir()
            (source / 'themerc').write_text('window.active.title.bg.color: #20242a\n')
            (source / 'close-active.svg').write_text('<svg/>')
            original = Path.lstat
            with mock.patch.object(Path, 'lstat', self.metadata(original)):
                assembly.copy_theme(source, base / 'display')
            installed = base / 'display/themes/Greyward/labwc'
            self.assertEqual({p.name: p.read_bytes() for p in installed.iterdir()},
                             {p.name: p.read_bytes() for p in source.iterdir()})

    def test_missing_or_unsupported_theme_inputs_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            source = base / 'canonical'
            source.mkdir()
            original = Path.lstat
            with mock.patch.object(Path, 'lstat', self.metadata(original)):
                with self.assertRaisesRegex(RuntimeError, 'configuration missing'):
                    assembly.copy_theme(source, base / 'missing')
                (source / 'themerc').write_text('theme')
                (source / 'run.sh').write_text('unexpected executable')
                with self.assertRaisesRegex(RuntimeError, 'Unsafe canonical theme asset'):
                    assembly.copy_theme(source, base / 'unsupported')

    def test_user_owned_theme_cannot_become_privileged_display_input(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder)
            value = source.lstat()
            with mock.patch.object(Path, 'lstat', return_value=SimpleNamespace(
                    st_uid=1001, st_mode=value.st_mode, st_size=value.st_size)):
                with self.assertRaisesRegex(RuntimeError, 'Root-owned canonical theme'):
                    assembly.copy_theme(source, source / 'display')


if __name__ == '__main__':
    unittest.main()
