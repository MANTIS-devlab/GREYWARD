"""Compile the actual ordinary-session module; never load policy into the host."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = Path('/usr/share/selinux/devel/Makefile')
COMPILER = Path('/usr/libexec/selinux/hll/pp')


@unittest.skipUnless(MAKEFILE.is_file() and COMPILER.is_file() and shutil.which('make'),
                     'Requires Fedora SELinux development tools')
class FlatpakSessionCompatibilityTests(unittest.TestCase):
    def compile_policy(self, relative='environment/production/selinux/greyward-application-session.te'):
        source = ROOT / relative
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            name = source.stem.replace('-', '_')
            (directory / (name + '.te')).write_bytes(
                source.read_bytes().replace(b'\r\n', b'\n'))
            build = subprocess.run(['make', '-f', str(MAKEFILE), name + '.pp'],
                                   cwd=directory, capture_output=True, timeout=60)
            self.assertEqual(build.returncode, 0, build.stderr.decode(errors='replace'))
            compiled = subprocess.run([str(COMPILER)],
                                      input=(directory / (name + '.pp')).read_bytes(),
                                      capture_output=True, timeout=20)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stderr.decode(errors='replace'))
        return compiled.stdout.decode()

    def test_compiled_kfd_rule_allows_metadata_without_compute_io(self):
        cil = self.compile_policy()
        permissions = re.findall(
            r'\(allow greyward_guard_t hsa_device_t \(chr_file \(([^)]+)\)\)\)', cil)
        self.assertTrue(permissions, 'The packaged module must handle the AMD KFD label')
        granted = {permission for group in permissions for permission in group.split()}
        self.assertEqual(granted, {'getattr', 'mounton'})

    def test_revokefs_descriptor_does_not_grant_helper_control(self):
        cil = self.compile_policy()
        permissions = re.findall(
            r'\(allow greyward_guard_t flatpak_helper_t \(unix_stream_socket \(([^)]+)\)\)\)', cil)
        self.assertTrue(permissions)
        granted = {permission for group in permissions for permission in group.split()}
        self.assertEqual(granted, {'read', 'write'})

    def test_revokefs_symlink_staging_has_no_regular_file_exception(self):
        cil = self.compile_policy()
        permissions = re.findall(
            r'\(allow greyward_guard_t fusefs_t \(lnk_file \(([^)]+)\)\)\)', cil)
        self.assertTrue(permissions)
        granted = {permission for group in permissions for permission in group.split()}
        self.assertEqual(granted, {'create', 'rename', 'unlink'})
        self.assertNotRegex(cil,
                            r'\(allow greyward_guard_t fusefs_t \(file \(')

    def test_screenshot_socket_does_not_add_owner_process_access(self):
        cil = self.compile_policy('environment/production/selinux/greyward-application-display.te')
        groups = re.findall(
            r'\(allow greyward_guard_t greyward_as_display_t \(unix_stream_socket \(([^)]+)\)\)\)', cil)
        self.assertEqual({p for group in groups for p in group.split()},
                         {'connectto', 'read', 'write', 'getattr', 'getopt'})
        processes = re.findall(
            r'\(allow greyward_guard_t greyward_as_display_t \(process \(([^)]+)\)\)\)', cil)
        # Existing child-to-parent SIGCHLD is needed for ordinary app startup.
        self.assertEqual({p for group in processes for p in group.split()}, {'sigchld'})


if __name__ == '__main__':
    unittest.main()
