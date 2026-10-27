"""Keep compositor-only migration bound to package bytes and linked receipts."""
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('screenshot_migration', ROOT / 'packaging/greyward-enrollment/migrate-screenshot.py')
MIGRATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MIGRATION)
sha = lambda data: hashlib.sha256(data).hexdigest()


class ScreenshotMigrationTests(unittest.TestCase):
    def fixture(self):
        desktop = {'schema': 'greyward.protected-desktop/v1',
                   'source': {'labwc': 'pinned'}, 'accounts': {'1000': {'name': 'fixture'}},
                   'files': {'bin/labwc': sha(b'old'), 'shell/Lock.qml': sha(b'protected lock')}}
        original = json.dumps(desktop).encode()
        admin = json.dumps({'schema': 'greyward.administration/v1', 'desktop': sha(original),
                            'files': {'worker.py': sha(b'unchanged')}, 'tools': {}}).encode()
        inputs = {'schema': 'greyward.enrollment-inputs/v1', 'labwcCommit': 'pinned',
                  'labwcSha256': sha(b'candidate'), 'screenshotPatchSha256': sha(b'patch')}
        return original, admin, inputs

    def test_only_compositor_identity_and_desktop_link_change(self):
        desktop, admin, inputs = self.fixture()
        updated, linked = MIGRATION.updated_receipts(desktop, admin, inputs, b'candidate', b'patch')
        before, after = json.loads(desktop), json.loads(updated)
        self.assertEqual(after['accounts'], before['accounts'])
        self.assertEqual(after['files']['shell/Lock.qml'], before['files']['shell/Lock.qml'])
        self.assertEqual(after['files']['bin/labwc'], sha(b'candidate'))
        self.assertEqual(json.loads(linked)['desktop'], sha(updated))
        self.assertEqual(json.loads(linked)['files'], json.loads(admin)['files'])
        self.assertEqual(before['files']['bin/labwc'], sha(b'old'))

    def test_unmatched_binary_patch_origin_or_link_is_rejected(self):
        for field in ('labwcSha256', 'screenshotPatchSha256', 'labwcCommit', 'schema'):
            desktop, admin, inputs = self.fixture()
            inputs[field] = 'wrong'
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                MIGRATION.updated_receipts(desktop, admin, inputs, b'candidate', b'patch')
        desktop, admin, inputs = self.fixture()
        changed = json.loads(admin)
        changed['desktop'] = '0' * 64
        with self.assertRaises(RuntimeError):
            MIGRATION.updated_receipts(desktop, json.dumps(changed).encode(), inputs, b'candidate', b'patch')


class QuiescentConsoleRecoveryTests(unittest.TestCase):
    def recover(self, *, active='inactive', sessions=(), workers=(),
                context='unconfined_u:unconfined_r:unconfined_t:s0',
                current='system_u:object_r:greyward_as_seat_tty_t:s0',
                expected='system_u:object_r:tty_device_t:s0',
                metadata=None, quiescence_error=None, read_error=None):
        migration = Mock()
        migration.ensure_quiescent.side_effect = quiescence_error
        results = [SimpleNamespace(stdout=active), SimpleNamespace(stdout=expected)]
        labels = [current.encode(), expected.encode()]
        metadata = metadata or SimpleNamespace(st_mode=stat.S_IFCHR | 0o620, st_uid=0, st_rdev=1025)
        with (patch.object(MIGRATION.subprocess, 'run', side_effect=results),
              patch.object(Path, 'glob', return_value=iter(sessions)),
              patch.object(Path, 'iterdir', return_value=iter(workers)),
              patch.object(Path, 'read_text', return_value=context, side_effect=read_error),
              patch.object(Path, 'lstat', return_value=metadata),
              patch.object(MIGRATION.os, 'makedev', return_value=1025, create=True),
              patch.object(MIGRATION.os, 'getxattr', side_effect=labels, create=True),
              patch.object(MIGRATION.os, 'setxattr', create=True) as write):
            try:
                result = MIGRATION.recover_quiescent_console(migration, ['fixture'])
            except Exception:
                write.assert_not_called()
                raise
            return result, write, migration

    def test_forced_logout_recovers_only_exact_stale_console(self):
        result, write, migration = self.recover(workers=[Path('/proc/42')])
        self.assertTrue(result)
        write.assert_called_once_with(Path('/dev/tty1'), 'security.selinux',
                                     b'system_u:object_r:tty_device_t:s0', follow_symlinks=False)
        self.assertEqual(migration.ensure_quiescent.call_count, 2)

    def test_normal_console_is_unchanged(self):
        result, write, _ = self.recover(current='system_u:object_r:tty_device_t:s0')
        self.assertFalse(result)
        write.assert_not_called()

    def test_active_login_sessions_workers_and_unknown_state_refuse_writes(self):
        cases = [
            {'active': 'active'}, {'sessions': [Path('seat-1000.json')]},
            {'quiescence_error': RuntimeError('User processes remain')},
            {'workers': [Path('/proc/42')], 'context': 'greyward_guard_u:greyward_guard_r:greyward_as_display_t:s0'},
            {'workers': [Path('/proc/42')], 'context': 'system_u:system_r:greyward_as_auth_t:s0'},
            {'workers': [Path('/proc/42')], 'read_error': PermissionError('unknown worker')},
            {'current': 'system_u:object_r:unexpected_t:s0'},
            {'expected': 'system_u:object_r:unexpected_t:s0'},
            {'metadata': SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0, st_rdev=1025)},
            {'metadata': SimpleNamespace(st_mode=stat.S_IFCHR, st_uid=1000, st_rdev=1025)},
            {'metadata': SimpleNamespace(st_mode=stat.S_IFCHR, st_uid=0, st_rdev=1026)},
        ]
        for case in cases:
            with self.subTest(case=case), self.assertRaises((RuntimeError, PermissionError)):
                self.recover(**case)


if __name__ == '__main__':
    unittest.main()
