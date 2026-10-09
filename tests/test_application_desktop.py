"""Protected display closure assets; no session or SELinux mutation."""
import importlib.util
from pathlib import Path
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


class DesktopLifetime(unittest.TestCase):
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
