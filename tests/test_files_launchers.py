"""Execute the wrapper through the kernel, preserving its actual shebang bytes."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == 'posix', 'Linux kernel interpreter handling')
class FilesLaunchers(unittest.TestCase):
    def check_launcher(self, source):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            seed = base / 'seed'
            seed.write_bytes(b'#!/usr/bin/sh\ntest "$1" = strata\n')
            seed.chmod(0o700)
            native = base / 'native'
            native.write_bytes(b'#!/usr/bin/sh\nprintf "%s\\n" "$STRATA_PREVIEW_SANDBOX" "$@"\n')
            native.chmod(0o700)
            # Replace only the two fixed callees. Keep the kernel's interpreter
            # line byte-identical; a CRLF wrapper must fail before either stub.
            data = source.read_bytes()
            data = data.replace(b'/usr/local/libexec/greyward-files-seed', os.fsencode(seed))
            data = data.replace(b'/usr/libexec/greyward/files/strata', os.fsencode(native))
            launcher = base / 'strata'
            launcher.write_bytes(data)
            launcher.chmod(0o700)
            literal = '/synthetic/folder;$(must-not-run)'
            result = subprocess.run([str(launcher), literal], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), ['oneshot', literal])

    def test_source_launcher_starts_without_shell_fallback(self):
        self.check_launcher(ROOT / 'environment/session/desktop/strata-launcher')

    def test_crlf_negative_control_fails_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'broken'
            source.write_bytes((ROOT / 'environment/session/desktop/strata-launcher').read_bytes().replace(b'\n', b'\r\n'))
            with self.assertRaises(FileNotFoundError):
                self.check_launcher(source)

    @unittest.skipUnless(os.environ.get('GREYWARD_FILES_PACKAGE_ROOT'), 'explicit extracted RPM')
    def test_actual_packaged_wrapper_starts_without_shell_fallback(self):
        self.check_launcher(Path(os.environ['GREYWARD_FILES_PACKAGE_ROOT']) / 'usr/bin/strata')


if __name__ == '__main__':
    unittest.main()
