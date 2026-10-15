"""Installer provenance and fail-closed lifecycle checks; no host mutation."""
import importlib.util
import json
import os
import stat
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'packaging/greyward-enrollment' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


capture = load('greyward_installer_accounts', 'installer-accounts.py')
enroll = load('greyward_installer_enrollment', 'enroll.py')


class InstallerEnrollment(unittest.TestCase):
    def static_fixture(self, base):
        program = base / 'program'
        desktop = program / 'desktop'
        admin = program / 'administration'
        previous = os.umask(0o077)
        try:
            (desktop / 'bin').mkdir(mode=0o755, parents=True)
            (desktop / 'labwc/themes/Greyward').mkdir(mode=0o755, parents=True)
            admin.mkdir(mode=0o755)
            (desktop / 'bin/labwc').write_bytes(b'fixed executable')
            (desktop / 'bin/labwc').chmod(0o555)
        finally:
            os.umask(previous)
        return program, desktop, admin

    def test_restrictive_umask_does_not_block_immutable_program_traversal(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            program, desktop, admin = self.static_fixture(base)
            private = base / 'private-policy'
            private.mkdir(mode=0o700)
            original = Path.lstat
            def metadata(path):
                value = original(path)
                return SimpleNamespace(st_uid=0, st_mode=value.st_mode & ~0o022)
            self.assertEqual(stat.S_IMODE(original(desktop / 'bin').st_mode), 0o700)
            with mock.patch.object(enroll, 'DESKTOP', desktop), mock.patch.object(enroll, 'ADMIN', admin), mock.patch.object(Path, 'lstat', metadata):
                enroll.finalize_program_directories()
            for path in [program, desktop, admin, *desktop.rglob('*')]:
                if path.is_dir():
                    self.assertEqual(stat.S_IMODE(original(path).st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(original(desktop / 'bin/labwc').st_mode), 0o555)
            self.assertEqual(stat.S_IMODE(original(private).st_mode), 0o700)

    def test_unsafe_static_input_refuses_before_any_directory_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, desktop, admin = self.static_fixture(Path(temporary))
            target = desktop / 'bin/labwc'
            original = Path.lstat
            for unsafe in [stat.S_IFLNK | 0o777, stat.S_IFREG | 0o666]:
                def metadata(path):
                    value = original(path)
                    return SimpleNamespace(st_uid=0, st_mode=unsafe if path == target else value.st_mode & ~0o022)
                with mock.patch.object(enroll, 'DESKTOP', desktop), mock.patch.object(enroll, 'ADMIN', admin), mock.patch.object(Path, 'lstat', metadata), mock.patch.object(Path, 'chmod') as chmod:
                    with self.assertRaises(RuntimeError):
                        enroll.finalize_program_directories()
                    chmod.assert_not_called()

    def test_private_origin_directory_creation_and_unsafe_existing_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'origins'
            # The temporary tree is not production root ownership; exercise
            # permission decisions with explicit metadata, without host changes.
            with mock.patch.object(Path, 'lstat') as metadata, mock.patch.object(Path, 'mkdir') as mkdir:
                metadata.return_value = SimpleNamespace(st_mode=0o40700, st_uid=0)
                enroll.private_directory(path)
                mkdir.assert_called_once_with(mode=0o700, exist_ok=True)
                metadata.return_value = SimpleNamespace(st_mode=0o40755, st_uid=0)
                with self.assertRaises(RuntimeError):
                    enroll.private_directory(path)

    def test_symlink_and_writable_parent_refuse_origin_directory(self):
        for mode in [0o120700, 0o40777]:
            with mock.patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=mode, st_uid=0)), \
                 mock.patch.object(Path, 'mkdir') as mkdir:
                with self.assertRaises(RuntimeError):
                    enroll.private_directory(Path('/private/origins'))
                mkdir.assert_not_called()

    def test_subprocess_failure_preserves_underlying_diagnostic(self):
        error = subprocess.CalledProcessError(1, ['broker'], stderr='Origin directory missing')
        with mock.patch.object(subprocess, 'run', side_effect=error):
            with self.assertRaisesRegex(RuntimeError, 'Origin directory missing'):
                enroll.run('broker')

    def test_prepared_continuation_rejects_changed_inputs_and_mapping(self):
        accounts = [{'name': 'user'}]
        receipt = {'schema': 'greyward.installer-enrollment/v1', 'phase': 'PREPARED_INPUTS',
                   'accounts': accounts, 'inputs': {'manifest': 'old'},
                   'previous': {'user': {'seuser': 'unconfined_u', 'range': 's0'}}}
        with mock.patch.object(enroll, 'prepared_inputs', return_value={'manifest': 'new'}), \
             mock.patch.object(enroll, 'run') as run:
            with self.assertRaises(RuntimeError):
                enroll.finish_preparation(accounts, receipt)
            run.assert_not_called()
        with mock.patch.object(enroll, 'prepared_inputs', return_value=receipt['inputs']), \
             mock.patch.object(enroll, 'quiescent'), \
             mock.patch.object(enroll, 'mapping', return_value={'seuser': 'greyward_guard_u', 'range': 's0'}), \
             mock.patch.object(enroll, 'run') as run:
            with self.assertRaises(RuntimeError):
                enroll.finish_preparation(accounts, receipt)
            run.assert_not_called()

    def test_preparing_continuation_requires_original_mapping_and_empty_origins(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            state = base / 'installation'
            origins = base / 'account-origins'
            state.mkdir(mode=0o700)
            origins.mkdir(mode=0o700)
            accounts = [{'name': 'user', 'uid': 1000, 'gid': 1000,
                         'home': '/home/user', 'shell': '/bin/bash'}]
            previous = {'user': {'seuser': 'unconfined_u', 'range': 's0'}}
            receipt = {'schema': 'greyward.installer-enrollment/v1', 'phase': 'PREPARING',
                       'accounts': accounts, 'previous': previous, 'inputs': {}}
            original_lstat = Path.lstat
            def root_origin_metadata(path):
                if path == origins:
                    return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0,
                                           st_nlink=1, st_size=0)
                return original_lstat(path)
            with mock.patch.object(enroll, 'STATE', state), \
                 mock.patch.object(enroll, 'ORIGINS', origins), \
                 mock.patch.object(enroll, 'quiescent'), \
                 mock.patch.object(enroll, 'mapping', return_value=previous['user']), \
                 mock.patch.object(Path, 'lstat', new=root_origin_metadata):
                enroll.validate_preparing_transaction(accounts, receipt)
                with mock.patch.object(enroll, 'mapping', return_value={'seuser': 'greyward_guard_u', 'range': 's0'}):
                    with self.assertRaisesRegex(RuntimeError, 'mapping changed'):
                        enroll.validate_preparing_transaction(accounts, receipt)
                marker = origins / 'account.json'
                marker.write_text('{}')
                with self.assertRaisesRegex(RuntimeError, 'origin state changed'):
                    enroll.validate_preparing_transaction(accounts, receipt)

    def test_preparing_continuation_rejects_malformed_receipt(self):
        accounts = [{'name': 'user'}]
        receipt = {'schema': 'greyward.installer-enrollment/v1', 'phase': 'PREPARING',
                   'accounts': accounts, 'previous': {}, 'inputs': {}}
        with self.assertRaisesRegex(RuntimeError, 'receipt is incomplete'):
            enroll.validate_preparing_transaction(accounts, receipt)

    def test_partial_tree_cleanup_is_confined_to_safe_root_owned_trees(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            partial = parent / 'partial'
            (partial / 'nested').mkdir(parents=True)
            (partial / 'nested/input.json').write_text('{}')
            original_lstat = Path.lstat
            def root_metadata(path):
                info = original_lstat(path)
                mode = stat.S_IFDIR | 0o700 if path.is_dir() else stat.S_IFREG | 0o600
                return SimpleNamespace(st_mode=mode, st_uid=0, st_nlink=info.st_nlink,
                                       st_size=info.st_size)
            with mock.patch.object(Path, 'lstat', new=root_metadata):
                enroll.discard_partial_tree(partial, parent)
            self.assertFalse(partial.exists())
            with self.assertRaisesRegex(RuntimeError, 'Invalid partial assembly path'):
                enroll.discard_partial_tree(parent / 'outside/partial', parent)

    def test_existing_selinux_users_are_reused_only_when_definition_matches(self):
        expected = {'prefix': 'user', 'level': 's0', 'range': 's0-s0:c0.c1023',
                    'roles': {'sysadm_r', 'greyward_admin_r'}}
        with mock.patch.object(enroll, 'semanage_users', return_value={'greyward_admin_u': expected}), \
             mock.patch.object(enroll, 'run') as run:
            enroll.ensure_selinux_user('greyward_admin_u', 'greyward_admin_r sysadm_r',
                                       's0-s0:c0.c1023')
            run.assert_not_called()
        with mock.patch.object(enroll, 'semanage_users', return_value={'greyward_admin_u': {**expected, 'roles': {'sysadm_r'}}}), \
             mock.patch.object(enroll, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'definition changed'):
                enroll.ensure_selinux_user('greyward_admin_u', 'greyward_admin_r sysadm_r',
                                           's0-s0:c0.c1023')
            run.assert_not_called()

    def test_rpm_builder_normalizes_its_isolated_policy_inputs_before_archiving(self):
        builder = (ROOT / 'packaging/greyward-enrollment/build.sh').read_text()
        normalize = builder.index('environment/image/stage-text.py')
        archive = builder.index("tar --sort=name")
        build = builder.index('rpmbuild -bb')
        self.assertLess(normalize, archive)
        self.assertLess(archive, build)
        self.assertIn('source_tree=', builder)

    def test_unsafe_broker_store_refuses_before_transaction_creation(self):
        with mock.patch.object(Path, 'is_file', return_value=True), \
             mock.patch.object(Path, 'exists', return_value=False), \
             mock.patch.object(enroll, 'installer_accounts', return_value=[]), \
             mock.patch.object(enroll, 'quiescent'), \
             mock.patch.object(enroll, 'run', return_value='Enforcing'), \
             mock.patch.object(enroll, 'private_directory', side_effect=RuntimeError('unsafe')) as private, \
             mock.patch.object(Path, 'mkdir') as mkdir:
            with self.assertRaises(RuntimeError):
                enroll.prepare()
            private.assert_called_once_with(enroll.STATE.parent)
            mkdir.assert_not_called()

    def test_only_supported_normal_local_accounts_are_captured(self):
        text = '\n'.join(['root:x:0:0::/root:/bin/bash',
                          'service:x:991:991::/var/lib/service:/bin/bash',
                          'external:x:1200:1200::/remote/external:/bin/bash',
                          'user:x:1000:1000::/home/user:/bin/bash',
                          'disabled:x:1001:1001::/home/disabled:/sbin/nologin'])
        result = capture.accounts(text)
        self.assertEqual([record['name'] for record in result], ['user'])

    def test_missing_and_reused_uid_inventory_is_refused(self):
        for text in ['', 'user:x:1000:1000::/home/user:/bin/bash\nother:x:1000:1000::/home/other:/bin/bash']:
            with self.assertRaises(RuntimeError):
                capture.accounts(text)

    def test_creation_identity_is_preserved_across_supported_shell_setup(self):
        value = {'schema': 'greyward.installer-accounts/v1', 'accounts': capture.accounts('user:x:1000:1000::/home/user:/bin/bash')}
        with mock.patch.object(enroll, 'trusted', return_value=json.dumps(value).encode()), \
             mock.patch.object(Path, 'read_text', return_value='user:x:1000:1000::/home/user:/usr/bin/zsh'):
            self.assertEqual(enroll.installer_accounts()[0]['shell'], '/usr/bin/zsh')

    def test_replaced_installer_account_cannot_acquire_enrollment(self):
        value = {'schema': 'greyward.installer-accounts/v1', 'accounts': capture.accounts('user:x:1000:1000::/home/user:/bin/bash')}
        for line in ['user:x:1001:1001::/home/user:/bin/bash', 'user:x:1000:1000::/other:/bin/bash', 'user:x:1000:1000::/home/user:/tmp/custom-shell']:
            with mock.patch.object(enroll, 'trusted', return_value=json.dumps(value).encode()), \
                 mock.patch.object(Path, 'read_text', return_value=line):
                with self.assertRaises(RuntimeError):
                    enroll.installer_accounts()

    def test_active_workload_refuses_mapping_change(self):
        process = SimpleNamespace(name='123', stat=lambda: SimpleNamespace(st_uid=1000))
        with mock.patch.object(Path, 'iterdir', return_value=[process]):
            with self.assertRaises(RuntimeError):
                enroll.quiescent([{'uid': 1000}])

    def test_normal_boot_cannot_invoke_offline_rollback(self):
        with mock.patch.object(Path, 'read_text', return_value='quiet'), mock.patch.object(enroll, 'run') as run:
            with self.assertRaises(RuntimeError):
                enroll.rollback()
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
