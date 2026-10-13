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
    @unittest.skipUnless(__import__('os').name == 'posix', 'POSIX descriptor replacement')
    def test_readiness_reopens_an_atomically_replaced_record(self):
        import os
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'ready.json'
            path.write_bytes(b'old')
            replacement = path.with_name('next.json')
            replacement.write_bytes(b'new')
            real_fstat = os.fstat
            replaced = False

            def replace_before_stat(fd):
                nonlocal replaced
                if not replaced:
                    os.replace(replacement, path)
                    replaced = True
                return real_fstat(fd)

            with mock.patch.object(session.os, 'fstat', side_effect=replace_before_stat):
                self.assertEqual(session.private_file(path, owner=os.getuid(), retry_replaced=True), b'new')

    @unittest.skipUnless(__import__('os').name == 'posix', 'POSIX descriptor checks')
    def test_readiness_retry_does_not_accept_hardlinks_or_symlinks(self):
        import os
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'ready.json'
            path.write_bytes(b'heartbeat')
            alias = path.with_name('alias.json')
            os.link(path, alias)
            with self.assertRaisesRegex(RuntimeError, 'Unsafe fixed input'):
                session.private_file(path, owner=os.getuid(), retry_replaced=True)
            alias.unlink()
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                session.private_file(alias, owner=os.getuid(), retry_replaced=True)

    def test_invalid_readiness_fails_closed_without_escaping_the_monitor(self):
        with mock.patch.object(session, 'private_file', side_effect=RuntimeError('Unsafe fixed input')):
            failure = []
            self.assertFalse(session.authentication_ready(1001, failure))
            self.assertEqual(failure, ['readiness-input'])

    def test_malformed_readiness_reports_only_a_fixed_reason(self):
        with mock.patch.object(session, 'private_file', return_value=b'[]'):
            failure = []
            self.assertFalse(session.authentication_ready(1001, failure))
            self.assertEqual(failure, ['readiness-format'])

    def test_guardian_records_readiness_loss_before_retiring_scope(self):
        state = mock.Mock()

        def not_ready(_uid, failure):
            failure.append('heartbeat-age')
            return False

        with mock.patch.object(session, 'process', return_value=42), \
             mock.patch.object(session.select, 'select', return_value=([], [], [])), \
             mock.patch.object(session, 'authentication_ready', side_effect=not_ready), \
             mock.patch.object(session, 'record_guardian_event') as record, \
             mock.patch.object(session.os, 'setxattr', create=True), \
             mock.patch.object(session.subprocess, 'run') as run:
            session.monitor(1001, 123, 456, '815', [], state, '/dev/tty1', 'original')
        record.assert_called_once_with('815', 'heartbeat-age')
        self.assertEqual(run.call_args_list[0].args[0],
                         ['/usr/bin/loginctl', 'terminate-session', '815'])
        self.assertEqual(run.call_args_list[1].args[0],
                         ['/usr/bin/systemctl', 'stop', '--no-block', 'session-815.scope'])

    def test_admitted_scope_is_retired_even_when_logind_termination_times_out(self):
        import subprocess
        state = mock.Mock()
        with mock.patch.object(session, 'process', return_value=42), \
             mock.patch.object(session.select, 'select', return_value=([42], [], [])), \
             mock.patch.object(session, 'record_guardian_event') as record, \
             mock.patch.object(session.os, 'setxattr', create=True), \
             mock.patch.object(session.subprocess, 'run', side_effect=[subprocess.TimeoutExpired('loginctl', 3), mock.Mock()]) as run:
            with self.assertRaises(subprocess.TimeoutExpired):
                session.monitor(1001, 123, 456, '815', [], state, '/dev/tty1', 'original')
        state.unlink.assert_called_once_with(missing_ok=True)
        record.assert_called_once_with('815', 'session-owner-exited')
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


class ExistingCompositorMigration(unittest.TestCase):
    def test_uses_only_compositor_bytes_recorded_by_existing_protected_manifest(self):
        import hashlib
        import json
        with tempfile.TemporaryDirectory() as folder:
            active = Path(folder) / 'active'
            (active / 'bin').mkdir(parents=True)
            compositor = active / 'bin/labwc'
            compositor.write_bytes(b'installed protected compositor')
            digest = hashlib.sha256(compositor.read_bytes()).hexdigest()
            (active / 'desktop.json').write_text(json.dumps({
                'schema': 'greyward.protected-desktop/v1',
                'source': {'labwc': '12987307a5de32db5acbb3f59d41277373ab969e'},
                'files': {'bin/labwc': digest},
            }))
            with mock.patch.object(assembly, 'trusted_root_file'):
                self.assertEqual(assembly.compositor_digest(
                    Path(folder) / 'missing-inputs.json', active), digest)

    def test_rejects_changed_compositor_against_existing_manifest(self):
        import hashlib
        import json
        with tempfile.TemporaryDirectory() as folder:
            active = Path(folder) / 'active'
            (active / 'bin').mkdir(parents=True)
            compositor = active / 'bin/labwc'
            compositor.write_bytes(b'changed compositor')
            (active / 'desktop.json').write_text(json.dumps({
                'schema': 'greyward.protected-desktop/v1',
                'source': {'labwc': '12987307a5de32db5acbb3f59d41277373ab969e'},
                'files': {'bin/labwc': hashlib.sha256(b'previous compositor').hexdigest()},
            }))
            with mock.patch.object(assembly, 'trusted_root_file'):
                with self.assertRaisesRegex(RuntimeError, 'receipt mismatch'):
                    assembly.compositor_digest(Path(folder) / 'missing-inputs.json', active)


if __name__ == '__main__':
    unittest.main()
