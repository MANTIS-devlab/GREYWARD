"""Component cache behavior with isolated builder and RPM query fixtures."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('components', Path(__file__).resolve().parents[1] / 'environment/image/build-components.py')
components = importlib.util.module_from_spec(spec)
spec.loader.exec_module(components)


@unittest.skipIf(sys.platform == 'win32', 'Native cache locking requires Linux')
class ComponentCacheTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / 'repo'
        self.output = self.root / 'cache'
        self.inputs = self.root / 'inputs'
        directory = self.repo / 'packaging/greyward-session'
        directory.mkdir(parents=True)
        (directory / 'greyward-session.spec').write_text('Name: greyward-session\nVersion: 1\nRelease: 1%{?dist}\n')
        self.payload = directory / 'payload'
        self.payload.write_text('original')
        self.builds = 0

    def tearDown(self):
        self.temporary.cleanup()

    def run_fixture(self, *args, **kwargs):
        if str(args[0]) == 'bash':
            self.builds += 1
            build = Path(args[-1]); build.mkdir(parents=True)
            (build / 'greyward-session.rpm').write_bytes(b'fixed-rpm-fixture')
        return SimpleNamespace(stdout='greyward-session-1-1.noarch\n')

    def invoke(self):
        with patch.object(components, 'REPO', self.repo), patch.object(components, 'run', self.run_fixture), patch.object(sys, 'argv', ['components', '--output', str(self.output), '--dms-inputs', str(self.inputs), '--only', 'session']):
            components.main()

    def test_warm_run_reuses_exact_verified_bytes(self):
        self.invoke(); self.invoke()
        self.assertEqual(self.builds, 1)
        receipt = json.loads((self.output / 'selected-components.json').read_text())['session']
        self.assertTrue(receipt['reused'])
        self.assertEqual(list(receipt['packages'].values()), ['greyward-session-1-1.noarch\n'])

    def test_corrupt_cached_rpm_fails_instead_of_reusing(self):
        self.invoke()
        next(self.output.rglob('*.rpm')).write_bytes(b'tampered')
        with self.assertRaisesRegex(SystemExit, 'Corrupt cached component'):
            self.invoke()
        self.assertEqual(self.builds, 1)

    def test_changed_source_requires_new_identity(self):
        self.invoke(); self.payload.write_text('changed')
        with self.assertRaisesRegex(SystemExit, 'Increment package revision'):
            self.invoke()
        self.assertEqual(self.builds, 1)
