import hashlib
import os
from pathlib import Path
import tempfile
import stat
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from greyward_security_context.file_security import FileSecurityManager, _hash_descriptor, _caller_can_search, _open_readonly_nofollow


@unittest.skipUnless(os.name == 'posix', 'Linux descriptor scan contract')
class DescriptorScanTests(unittest.TestCase):
    @unittest.skipUnless(getattr(os, 'geteuid', lambda: -1)() == 0, 'isolated root DAC fixture')
    def test_leaf_ownership_does_not_bypass_another_users_private_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o755)
            private = root / 'private'
            private.mkdir(mode=0o700)
            source = private / 'owned-by-caller'
            source.write_text('private parent fixture')
            os.chown(source, 65534, 65534)
            with self.assertRaises(PermissionError):
                _open_readonly_nofollow(source, scan_uid=65534, scan_access=True)

    def test_parent_access_honors_named_acl_and_group_permissions(self):
        metadata = SimpleNamespace(st_uid=1000, st_gid=65534, st_mode=stat.S_IFDIR | 0o750)
        with patch('greyward_security_context.file_security._scan_xattr', return_value=None):
            self.assertTrue(_caller_can_search(Path('/fixture'), metadata, 65534))
        acl = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *entry) for entry in
            ((1, 7, 0xffffffff), (2, 0, 65534), (4, 7, 0xffffffff), (16, 7, 0xffffffff), (32, 7, 0xffffffff)))
        with patch('greyward_security_context.file_security._scan_xattr', return_value=acl):
            # A matching named entry does not fall through to permissive Other.
            self.assertFalse(_caller_can_search(Path('/fixture'), metadata, 65534))

    def test_protected_label_on_open_inode_is_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source'
            source.write_text('private fixture')
            context = b'user_u:object_r:greyward_as_resource_' + b'a' * 64 + b'_t:s0'
            def label(selected, name):
                return context if isinstance(selected, int) and name == 'security.selinux' else None
            with patch('greyward_security_context.file_security.PRIVATE_TMP_ROOTS', ()), \
                    patch('greyward_security_context.file_security._scan_xattr', side_effect=label):
                handles, _aliases, _before, skipped = FileSecurityManager._scan_handles([source], os.getuid(), False)
            self.assertEqual(handles, [])
            self.assertEqual(skipped, 1)

    def test_special_files_and_aliases_are_skipped_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'regular'
            source.write_text('ordinary fixture')
            os.mkfifo(root / 'pipe')
            (root / 'alias').symlink_to(source)
            with patch('greyward_security_context.file_security.PRIVATE_TMP_ROOTS', ()):
                handles, aliases, _before, skipped = FileSecurityManager._scan_handles([root], os.getuid(), True)
            try:
                self.assertEqual(len(handles), 1)
                self.assertEqual(list(aliases.values()), [str(source)])
                self.assertEqual(skipped, 2)
            finally:
                for descriptor in handles:
                    os.close(descriptor)

    def test_hash_uses_scanned_inode_after_path_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source'
            source.write_bytes(b'original')
            descriptor = os.open(source, os.O_RDONLY)
            try:
                source.unlink()
                source.write_bytes(b'replacement')
                self.assertEqual(_hash_descriptor(descriptor), (8, hashlib.sha256(b'original').hexdigest()))
            finally:
                os.close(descriptor)

    @unittest.skipUnless(getattr(os, 'geteuid', lambda: -1)() == 0, 'requires isolated root ownership fixtures')
    def test_owner_is_rechecked_on_open_inode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected, foreign = root / 'selected', root / 'foreign'
            selected.write_text('selected')
            foreign.write_text('foreign')
            os.chown(foreign, 65534, 65534)
            descriptor = os.open(foreign, os.O_RDONLY)
            with patch('greyward_security_context.file_security.PRIVATE_TMP_ROOTS', ()), \
                    patch('greyward_security_context.file_security._open_readonly_nofollow', return_value=descriptor):
                handles, aliases, _before, skipped = FileSecurityManager._scan_handles([selected], 0, False)
            self.assertEqual(handles, [])
            self.assertEqual(aliases, {})
            self.assertEqual(skipped, 1)
            with self.assertRaises(OSError):
                os.fstat(descriptor)
