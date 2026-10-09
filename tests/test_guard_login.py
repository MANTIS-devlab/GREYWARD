"""Real descriptor checks for enrolled graphical-session startup (Linux)."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'security-center/packaging/application-security/desktop/login.py'


@unittest.skipUnless(os.name == 'posix', 'Linux session descriptors')
class LoginDescriptors(unittest.TestCase):
    def invoke(self, runtime):
        return subprocess.run([sys.executable, '-c',
            "import os,runpy,sys;from pathlib import Path;"
            "m=runpy.run_path(sys.argv[1]);"
            "m['detach_console'](Path(sys.argv[2]),os.getuid());"
            "assert os.read(0,1)==b'';"
            "os.write(1,b'stdout-ready\\n');os.write(2,b'stderr-ready\\n')",
            str(SOURCE), str(runtime)], capture_output=True)

    def test_startup_uses_private_log_not_console(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'greyward-desktop-start.log'
            log.write_text('previous session')
            result = self.invoke(tmp)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b'')
            self.assertEqual(result.stderr, b'')
            self.assertEqual(log.read_bytes(), b'stdout-ready\nstderr-ready\n')
            self.assertEqual(log.stat().st_mode & 0o777, 0o600)

    def test_symlink_log_is_rejected_without_touching_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'target'
            target.write_text('preserve')
            (Path(tmp) / 'greyward-desktop-start.log').symlink_to(target)
            self.assertNotEqual(self.invoke(tmp).returncode, 0)
            self.assertEqual(target.read_text(), 'preserve')

    def test_hardlink_log_is_rejected_before_truncation(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'target'
            target.write_text('preserve')
            os.link(target, Path(tmp) / 'greyward-desktop-start.log')
            self.assertNotEqual(self.invoke(tmp).returncode, 0)
            self.assertEqual(target.read_text(), 'preserve')

    def test_symlink_runtime_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / 'alias'
            runtime.symlink_to(tmp, target_is_directory=True)
            self.assertNotEqual(self.invoke(runtime).returncode, 0)


if __name__ == '__main__':
    unittest.main()
