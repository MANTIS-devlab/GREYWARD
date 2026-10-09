"""Exact-input authentication assembly; no VM, policy or PAM mutation."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / 'security-center/packaging/application-security/authentication/assemble.py'
SPEC = importlib.util.spec_from_file_location('greyward_authentication_assembly', SOURCE)
assembly = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(assembly)


class AuthenticationAssembly(unittest.TestCase):
    def fixture(self, base):
        # Synthetic structure exercises transformation/refusal without pretending
        # to be the pinned upstream files. Real QML/PAM is a separate Fedora gate.
        root = base / 'source'
        (root / 'Modules/Lock').mkdir(parents=True)
        (root / 'shell.qml').write_text('original shell\n')
        lock = '''import qs.Services
    property bool shouldLock: false
        locked: shouldLock && !lockRetryPending
    function lock() {
        return;
    }
    function unlock() {
        return;
    }
        lockSecured: root.shouldLock
            LockSurface {
                anchors.fill: parent
                visible: lockSurface.isActiveScreen
                lock: sessionLock
                pam: sharedPam
                sharedPasswordBuffer: root.sharedPasswordBuffer
                screenName: lockSurface.currentScreenName
                isLocked: shouldLock
                onUnlockRequested: root.unlock()
                onPasswordChanged: newPassword => {
                    root.sharedPasswordBuffer = newPassword;
                }
            }
'''
        lock += '\n'.join('function ' + name + ' { return true; }' for name in
                         ['spawnCustomLocker()', 'handleLoginctlCustomLock(): bool', 'onSessionUnlocked()'])
        for name in ['unlock', 'forceReset', 'demo']:
            body = 'demoWindow.showDemo();' if name == 'demo' else f'root.{name}();'
            lock += f'\n        function {name}() {{\n            {body}\n        }}'
        (root / 'Modules/Lock/Lock.qml').write_text(lock)
        pam = '''function ensureUserPamConfig(): void { return; }
        id: passwd

        config: { return "login"; }
        configDirectory: { return "user"; }
readonly property bool customPamActive: SettingsData.lockPamPath !== "" && customPamWatcher.loaded
readonly property bool customU2fPamActive: SettingsData.lockU2fPamPath !== "" && customU2fPamWatcher.loaded
readonly property bool fprintSuppressedByPrimaryPam: SettingsData.lockPamExternallyManaged || (customPamActive && SettingsData.lockPamInlineFprint)
readonly property bool u2fSuppressedByPrimaryPam: SettingsData.lockPamExternallyManaged || (customPamActive && SettingsData.lockPamInlineU2f)
'''
        (root / 'Modules/Lock/Pam.qml').write_text(pam)
        receipt = base / 'release.json'
        self.write_receipt(root, receipt)
        pins = {name: assembly.receipt(root)[0][name] for name in assembly.PREIMAGES}
        return root, receipt, pins

    def write_receipt(self, root, path):
        files, digest = assembly.receipt(root)
        path.write_text(json.dumps({'schema': 'greyward.dms-release/v1', 'releaseId': 'v1.6.2-6',
                                   'shellFiles': files, 'shell': {'sha256': digest}}))

    def test_reproducible_independent_output_preserves_source(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            root, receipt, pins = self.fixture(base)
            before = assembly.receipt(root)
            with mock.patch.object(assembly, 'PREIMAGES', pins):
                first = assembly.assemble(root, receipt, base / 'first')
                second = assembly.assemble(root, receipt, base / 'second')
            self.assertEqual(first, second)
            self.assertEqual(first['coverage'], 'UNKNOWN')
            self.assertEqual(assembly.receipt(root), before)
            self.assertEqual(assembly.receipt(base / 'first/shell')[1], first['shellDigest'])
            lock = (base / 'first/shell/Modules/Lock/Lock.qml').read_text()
            self.assertIn('active: !root.authorizationActive', lock)
            self.assertIn('sourceComponent: LockSurface {', lock)
            self.assertNotIn('\n            LockSurface {', lock)

    def test_changed_source_and_reissued_receipt_cannot_bypass_pin(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            root, receipt, pins = self.fixture(base)
            (root / 'Modules/Lock/Lock.qml').write_text('changed')
            with mock.patch.object(assembly, 'PREIMAGES', pins):
                with self.assertRaises(ValueError):
                    assembly.assemble(root, receipt, base / 'out')
                self.write_receipt(root, receipt)
                with self.assertRaises(ValueError):
                    assembly.assemble(root, receipt, base / 'out')
            self.assertFalse((base / 'out').exists())

    def test_existing_or_nested_outputs_refuse_without_mutation(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            root, receipt, pins = self.fixture(base)
            (base / 'existing').mkdir()
            marker = base / 'existing/keep'
            marker.write_text('preserve')
            with mock.patch.object(assembly, 'PREIMAGES', pins):
                for output in [base / 'existing', root / 'nested']:
                    with self.assertRaises(ValueError):
                        assembly.assemble(root, receipt, output)
            self.assertEqual(marker.read_text(), 'preserve')
            self.assertFalse((root / 'nested').exists())


if __name__ == '__main__':
    unittest.main()
