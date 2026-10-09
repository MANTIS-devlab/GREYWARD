"""Canonical logo embedding rejects external/active SVG assets before build."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('admin_logo', ROOT / 'security-center/packaging/application-security/administration/embed-logo.py')
LOGO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LOGO)

class BrandingTests(unittest.TestCase):
    def test_canonical_symbol_bytes_are_embedded_exactly(self):
        source = ROOT / 'security-center/data/greyward-symbol.svg'
        self.assertEqual(source.read_bytes(), (ROOT / 'branding/source/greyward-symbol.svg').read_bytes())
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'logo.h'
            LOGO.embed(source, target)
            result = target.read_text()
            payload = bytes(int(b) for b in result.split('{', 1)[1].split('}', 1)[0].replace('\n', '').split(',') if b)
            self.assertEqual(payload, source.read_bytes())
            self.assertIn(hashlib.sha256(payload).hexdigest(), result)

    def test_active_or_external_assets_and_unbounded_input_are_rejected(self):
        for content in ['<script/>', '<image href="file:///etc/passwd"/>', '<path d="M0 0" onclick="x"/>']:
            with self.subTest(content=content), tempfile.TemporaryDirectory() as folder:
                source = Path(folder) / 'bad.svg'
                source.write_text('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024">' + content + '</svg>')
                with self.assertRaises(ValueError):
                    LOGO.embed(source, Path(folder) / 'logo.h')
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'large.svg'
            source.write_bytes(b' ' * 131073)
            with self.assertRaises(ValueError):
                LOGO.embed(source, Path(folder) / 'logo.h')

if __name__ == '__main__':
    unittest.main()
