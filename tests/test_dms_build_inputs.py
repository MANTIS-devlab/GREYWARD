"""Build receipt verification must reject drift before extracting upstream inputs."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('dms_assembly', ROOT / 'packaging/greyward-dms/assemble.py')
ASSEMBLY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ASSEMBLY)


class BuildInputVerificationTests(unittest.TestCase):
    def attempt(self, changed_package=None, changed_version=None):
        release = json.loads((ROOT / 'environment/production/dms-release.json').read_text())

        def installed(command, **_kwargs):
            name = command[-1]
            return changed_version if name == changed_package else release['build']['requiredPackages'][name]

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            # Exact tools alone never authorize an unverified source archive.
            archive = base / 'unverified.tar.gz'
            archive.write_bytes(b'invalid upstream input')
            with patch.object(Path, 'exists', return_value=True), \
                    patch.object(ASSEMBLY.subprocess, 'check_output', side_effect=installed):
                ASSEMBLY.assemble(ROOT / 'environment/production/dms-release.json',
                                  archive, archive, base / 'patches', base / 'output')

    def test_stale_python_receipt_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'Unpinned Fedora build input: python3'):
            self.attempt('python3', '3.14.7-1.fc44.x86_64')

    def test_other_tool_drift_is_still_refused(self):
        with self.assertRaisesRegex(ValueError, 'Unpinned Fedora build input: golang'):
            self.attempt('golang', '0.0.0-1.fc44.x86_64')

    def test_matching_tools_still_require_verified_upstream_archive(self):
        with self.assertRaisesRegex(ValueError, 'source archive checksum mismatch'):
            self.attempt()


if __name__ == '__main__':
    unittest.main()
