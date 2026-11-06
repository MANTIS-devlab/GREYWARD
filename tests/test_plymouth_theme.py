"""Run on Fedora for native-parser regression coverage; byte contract also on Windows."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'packaging/greyward-branding/SOURCES'
spec = importlib.util.spec_from_file_location('boot_theme', SOURCE / 'verify-boot-theme.py')
theme = importlib.util.module_from_spec(spec)
spec.loader.exec_module(theme)
NATIVE = any(Path(p).exists() for p in ('/usr/lib64/plymouth/script.so', '/usr/lib/plymouth/script.so'))


class ThemeTests(unittest.TestCase):
    def test_checkout_is_linux_text(self):
        for name in ('greyward.script', 'greyward.plymouth', 'greyward-plymouth-module.sh', 'verify-boot-theme.py'):
            with self.subTest(name=name):
                self.assertNotIn(b'\r', (SOURCE / name).read_bytes())

    def reject(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'theme.script'
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                theme.validate_script(path)

    def test_crlf_regression_rejected(self):
        self.reject((SOURCE / 'greyward.script').read_bytes().replace(b'\n', b'\r\n'))

    def test_nul_rejected(self):
        self.reject(b'Window.GetWidth();\x00')

    def test_empty_rejected(self):
        self.reject(b'')

    @unittest.skipUnless(NATIVE, 'requires installed Fedora Plymouth plugin')
    def test_actual_native_parser(self):
        theme.validate_script(SOURCE / 'greyward.script')

    @unittest.skipUnless(NATIVE, 'requires installed Fedora Plymouth plugin')
    def test_native_syntax_error_rejected(self):
        self.reject(b'fun broken( {\n')

    def test_build_and_kernel_refresh_are_guarded(self):
        rpm = (ROOT / 'packaging/greyward-branding/SPECS/greyward-branding.spec').read_text(encoding='utf-8')
        self.assertIn('%check\n', rpm)
        self.assertIn('python3 -I %{SOURCE15} --script %{buildroot}', rpm)
        self.assertIn('%posttrans\n', rpm)
        self.assertIn('verify-boot-theme && dracut --regenerate-all --force', rpm)
        module = (SOURCE / 'greyward-plymouth-module.sh').read_text(encoding='utf-8')
        self.assertIn('exit 1', module)  # dracut ignores install() return values


if __name__ == '__main__':
    unittest.main()
