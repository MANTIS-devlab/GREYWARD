"""Windows-origin source must produce executable Linux entry points."""
import os
from pathlib import Path
import tempfile
import unittest


class ExecutablePackagingTests(unittest.TestCase):
    def test_prep_normalizes_script_bytes_without_corrupting_binary_assets(self):
        specs = Path(__file__).parents[2] / 'packaging'
        for component, directory in (('center', 'data'), ('context', 'security-context')):
            with self.subTest(component=component), tempfile.TemporaryDirectory() as temporary:
                spec = (specs / f'greyward-security-{component}.spec').read_text(encoding='utf-8')
                code = spec.split("python3 - <<'PY'\n", 1)[1].split('\nPY', 1)[0]
                root = Path(temporary)
                (root / directory).mkdir()
                script = root / directory / 'launcher'
                script.write_bytes(b'#!/usr/bin/env bash\r\nprintf test\r\n')
                asset = root / directory / 'image.png'
                original = b'\x89PNG\r\n\x1a\n\x00\xff\r\n'
                asset.write_bytes(original)
                before = Path.cwd()
                try:
                    os.chdir(root)
                    exec(compile(code, '<rpm-prep>', 'exec'), {})
                finally:
                    os.chdir(before)
                self.assertEqual(script.read_bytes(), b'#!/usr/bin/env bash\nprintf test\n')
                self.assertEqual(asset.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
