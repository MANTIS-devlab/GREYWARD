"""Root-owned fixture tests for installed runtime selection and integrity refusal."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('dms_verify', ROOT/'packaging/greyward-dms/verify.py')
verifier = importlib.util.module_from_spec(spec); spec.loader.exec_module(verifier)


@unittest.skipUnless(os.name != 'nt' and os.geteuid() == 0, 'Run root-owned fixtures with sudo on Fedora')
class PackageVerificationTests(unittest.TestCase):
    def setUp(self):
        parent = Path('/usr/lib/greyward')
        if not parent.is_dir(): self.skipTest('GREYWARD candidate must be installed first')
        self.temporary = tempfile.TemporaryDirectory(prefix='verify-fixture-', dir=parent)
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)/'runtimes'; self.root = self.base/'v1.6.2-99'
        (self.root/'shell').mkdir(parents=True); (self.root/'bin').mkdir()
        (self.root/'shell/sample.qml').write_text('fixture')
        (self.root/'bin/dms').write_text('fixture binary; never executed')
        self.selector = Path(self.temporary.name)/'selector'; self.selector.write_text('v1.6.2-99\n')
        self.receipt = {'schema': 'greyward.dms-release/v1', 'releaseId': 'v1.6.2-99',
                        'compatibility': {'quickshell': 'test-1'},
                        'binarySha256': hashlib.sha256((self.root/'bin/dms').read_bytes()).hexdigest(),
                        'shellFiles': {'sample.qml': hashlib.sha256(b'fixture').hexdigest()}, 'firstPartyFiles': {}}
        self.save()
        self.packages = patch.object(verifier.subprocess, 'check_output', return_value='quickshell\ttest-1\n')
        self.packages.start(); self.addCleanup(self.packages.stop)

    def save(self):
        (self.root/'release.json').write_text(json.dumps(self.receipt))

    def verify(self, full=True):
        return verifier.verify(self.selector, self.base, full=full)

    def test_valid_pair_and_changed_shell_refusal_at_startup(self):
        self.assertEqual(self.verify(), self.root)
        (self.root/'shell/sample.qml').write_text('changed')
        with self.assertRaisesRegex(ValueError, 'digest mismatch'): self.verify()
        # IPC selection reaches an already running, startup-verified shell.
        self.assertEqual(self.verify(full=False), self.root)

    def test_unlisted_file_and_binary_digest_refuse_startup(self):
        extra = self.root/'shell/extra.qml'; extra.write_text('extra')
        with self.assertRaisesRegex(ValueError, 'inventory'): self.verify()
        extra.unlink(); (self.root/'bin/dms').write_text('changed')
        with self.assertRaisesRegex(ValueError, 'digest'): self.verify()

    def test_writable_binary_refuses_even_ipc_selection(self):
        (self.root/'bin/dms').chmod(0o666)
        with self.assertRaisesRegex(ValueError, 'Untrusted'): self.verify(full=False)
        (self.root/'bin/dms').chmod(0o644)
        (self.root/'bin').chmod(0o777)
        with self.assertRaisesRegex(ValueError, 'Untrusted'): self.verify()
        (self.root/'bin').chmod(0o755)
        self.assertEqual(self.verify(), self.root)

    def test_selector_traversal_and_symlink_are_refused(self):
        self.selector.write_text('../outside')
        with self.assertRaisesRegex(ValueError, 'Invalid'): self.verify()
        self.selector.unlink(); self.selector.symlink_to(self.root/'release.json')
        with self.assertRaisesRegex(ValueError, 'Untrusted'): self.verify()

    def test_pairing_and_tuple_refuse_selection(self):
        self.receipt['releaseId'] = 'wrong'; self.save()
        with self.assertRaisesRegex(ValueError, 'pairing'): self.verify(full=False)
        self.receipt['releaseId'] = 'v1.6.2-99'; self.receipt['compatibility']['quickshell'] = 'unvalidated'; self.save()
        with self.assertRaisesRegex(ValueError, 'tuple'): self.verify(full=False)


if __name__ == '__main__': unittest.main()
