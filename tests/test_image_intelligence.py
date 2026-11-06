"""Prevent missing behavioral payloads and installer-account blind spots."""
import importlib.util
import json
import os
from pathlib import Path
import runpy
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('intelligence_inputs', ROOT/'environment/image/verify-intelligence-inputs.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class ImageIntelligenceTests(unittest.TestCase):
    def test_stale_runtime_helper_is_rejected(self):
        payload = {key: (ROOT/value).read_bytes() for key, value in verifier.INPUTS.items()}
        verifier.verify_payloads(ROOT, payload.__getitem__)
        for key in payload:
            with self.subTest(key=key):
                original = payload[key]
                payload[key] = b'old source'
                with self.assertRaisesRegex(ValueError, 'Stale intelligence'):
                    verifier.verify_payloads(ROOT, payload.__getitem__)
                payload[key] = original

    @unittest.skipIf(os.name == 'nt', 'Native passwd database and private file modes')
    def test_account_refresh_preserves_administrator_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)/'policies'
            script = ROOT/'packaging/greyward-intelligence/configure-policies.py'
            def generate(users):
                with patch('sys.argv', [str(script), str(directory)]), patch('pwd.getpwall', return_value=users):
                    runpy.run_path(str(script), run_name='__main__')
            generate([])
            generate([SimpleNamespace(pw_uid=1000, pw_dir='/home/owner')])
            policy = directory/'persistence.yaml'
            self.assertIn('/home/owner/.config/autostart/', policy.read_text())
            self.assertEqual(policy.stat().st_mode & 0o777, 0o600)
            policy.write_text('administrator edit')
            generate([SimpleNamespace(pw_uid=1001, pw_dir='/home/second')])
            self.assertEqual(policy.read_text(), 'administrator edit')
            self.assertNotIn('persistence', json.loads((directory.parent/'.policies-generated.json').read_text()))
            self.assertEqual({p.name for p in directory.iterdir()}, {'persistence.yaml', 'outbound.yaml'})


if __name__ == '__main__':
    unittest.main()
