"""Refuse incomplete candidates before any host/tool execution."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'packaging/greyward-dms' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

VERIFY = load('verify')
TOOLCHAIN = load('toolchain')

class CandidateTests(unittest.TestCase):
    def test_incomplete_or_malformed_activation_refuses_every_entry_point(self):
        for activation in (None, False, {}, {'eligible': False, 'pending': []},
                           {'eligible': 1, 'pending': []}, {'eligible': True, 'pending': ['review']}):
            for options in ({}, {'full': False}, {'full': False, 'constraints': True}):
                with self.subTest(activation=activation, options=options), tempfile.TemporaryDirectory() as directory:
                    base = Path(directory); selector = base / 'selector'; selector.write_text('v2.0.0-7')
                    root = base / 'v2.0.0-7'; root.mkdir()
                    (root / 'release.json').write_text(json.dumps({'schema': 'greyward.dms-release/v1',
                        'releaseId': 'v2.0.0-7', 'activation': activation}))
                    with patch.object(VERIFY, 'trusted'), patch.object(VERIFY.subprocess, 'check_output') as execute:
                        with self.assertRaisesRegex(ValueError, 'not activation eligible'):
                            VERIFY.verify(selector, base, **options)
                        execute.assert_not_called()

    def test_candidate_has_no_stale_installed_evidence(self):
        candidate = json.loads((ROOT / 'environment/production/dms-2.0-candidate.json').read_text())
        self.assertIs(candidate['activation']['eligible'], True)
        self.assertEqual(candidate['activation']['pending'], [])
        self.assertEqual(candidate['activation']['scope'], 'physical-migration-test')
        self.assertIs(candidate['acceptance']['releaseAccepted'], False)
        self.assertTrue(candidate['acceptance']['pending'])
        production = json.loads((ROOT / 'environment/production/dms-release.json').read_text())
        self.assertNotEqual(candidate['releaseId'], production['releaseId'])

    def test_trial_cannot_disguise_itself_as_release_accepted(self):
        for acceptance in ({}, {'releaseAccepted': True, 'pending': []},
                           {'releaseAccepted': False, 'pending': []}):
            with self.subTest(acceptance=acceptance), tempfile.TemporaryDirectory() as directory:
                base = Path(directory); selector = base / 'selector'; selector.write_text('v2.0.0-7')
                root = base / 'v2.0.0-7'; root.mkdir()
                (root / 'release.json').write_text(json.dumps({'schema': 'greyward.dms-release/v1',
                    'releaseId': 'v2.0.0-7', 'activation': {'eligible': True, 'pending': [],
                    'scope': 'physical-migration-test'}, 'acceptance': acceptance}))
                with patch.object(VERIFY, 'trusted'), patch.object(VERIFY.subprocess, 'check_output') as execute:
                    with self.assertRaisesRegex(ValueError, 'incomplete release acceptance'):
                        VERIFY.verify(selector, base, full=False)
                    execute.assert_not_called()

    def test_candidate_has_no_inherited_installed_hashes(self):
        candidate = json.loads((ROOT / 'environment/production/dms-2.0-candidate.json').read_text())
        for field in ('shellFiles', 'binarySha256', 'firstPartyFiles', 'usbguardApprovalSha256',
                      'usbguardAuthApprovalSha256', 'usbguardApprovalSourceSha256', 'usbguardAuthApprovalSourceSha256'):
            self.assertNotIn(field, candidate)

    def test_explicit_trial_still_requires_the_installed_compatibility_tuple(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); selector = base / 'selector'; selector.write_text('v2.0.0-7')
            root = base / 'v2.0.0-7'; root.mkdir()
            receipt = json.loads((ROOT / 'environment/production/dms-2.0-candidate.json').read_text())
            (root / 'release.json').write_text(json.dumps(receipt))
            packages = {('dms-greeter' if key == 'greeter' else key): value
                        for key, value in receipt['compatibility'].items() if key != 'validation'}
            installed = '\n'.join(key + '\t' + value for key, value in packages.items())
            with patch.object(VERIFY, 'trusted'), patch.object(VERIFY.subprocess, 'check_output', return_value=installed):
                self.assertEqual(VERIFY.verify(selector, base, full=False), root)
            with patch.object(VERIFY, 'trusted'), patch.object(VERIFY.subprocess, 'check_output', return_value='quickshell\twrong'):
                with self.assertRaisesRegex(ValueError, 'compatibility tuple'):
                    VERIFY.verify(selector, base, full=False)

    def test_first_party_candidate_and_previous_copy_receipts_are_closed(self):
        candidate = json.loads((ROOT / 'environment/production/dms-2.0-candidate.json').read_text())
        plugins = ROOT / candidate['firstPartyDirectory']
        actual = {p.relative_to(plugins).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in plugins.rglob('*') if p.is_file()}
        self.assertEqual(actual, candidate['firstPartySources'])
        previous = json.loads((ROOT / 'environment/production/dms-release.json').read_text())
        self.assertEqual(candidate['previousFirstPartyFiles'], previous['firstPartyFiles'])
        for manifest in plugins.rglob('plugin.json'):
            self.assertEqual(json.loads(manifest.read_text())['requires_dms'], '=2.0.0')

    def tool_fixture(self, directory, name='go/bin/go'):
        base = Path(directory); archive = base / 'tool.tar.gz'
        with tarfile.open(archive, 'w:gz') as stream:
            content = b'fixture executable; never executed'
            member = tarfile.TarInfo(name); member.size = len(content)
            stream.addfile(member, io.BytesIO(content))
        manifest = base / 'manifest.json'
        manifest.write_text(json.dumps({'build': {'toolchain': {'input': 'go', 'version': 'go1.27.3',
            'goVersion': 'go version go1.27.3 linux/amd64'}}, 'inputs': {'go': {
                'sha256': hashlib.sha256(archive.read_bytes()).hexdigest(), 'root': 'go'}}}))
        return manifest, archive, base / 'output'

    def test_unverified_toolchain_never_executes(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, archive, output = self.tool_fixture(directory)
            archive.write_bytes(b'changed')
            with patch.object(TOOLCHAIN.subprocess, 'check_output') as execute:
                with self.assertRaisesRegex(ValueError, 'checksum'):
                    TOOLCHAIN.prepare(manifest, archive, output)
                execute.assert_not_called()
            self.assertFalse(output.exists())

    def test_version_mismatch_and_existing_destination_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, archive, output = self.tool_fixture(directory)
            with patch.object(TOOLCHAIN.subprocess, 'check_output', return_value='go version go1.26.9 linux/amd64') as execute:
                with self.assertRaisesRegex(ValueError, 'version differs'):
                    TOOLCHAIN.prepare(manifest, archive, output)
                self.assertEqual(execute.call_args.kwargs['env']['GOTOOLCHAIN'], 'local')
                self.assertEqual(execute.call_args.kwargs['env']['GOPROXY'], 'off')
                with self.assertRaisesRegex(ValueError, 'must be new'):
                    TOOLCHAIN.prepare(manifest, archive, output)
                self.assertEqual(execute.call_count, 1)

    def test_archive_cannot_escape_build_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, archive, output = self.tool_fixture(directory, '../escaped')
            with patch.object(TOOLCHAIN.subprocess, 'check_output') as execute:
                with self.assertRaises(tarfile.FilterError):
                    TOOLCHAIN.prepare(manifest, archive, output)
                execute.assert_not_called()
            self.assertFalse((Path(directory) / 'escaped').exists())

if __name__ == '__main__':
    unittest.main()
