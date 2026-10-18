"""Exact-input authentication assembly; no VM, policy or PAM mutation."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / 'security-center/packaging/application-security/authentication/assemble.py'
SPEC = importlib.util.spec_from_file_location('greyward_authentication_assembly', SOURCE)
assembly = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(assembly)
MATERIALIZE_SOURCE = Path(__file__).resolve().parents[1] / 'security-center/packaging/application-security/desktop/materialize.py'
MATERIALIZE_SPEC = importlib.util.spec_from_file_location('greyward_authentication_materialize', MATERIALIZE_SOURCE)
materialize = importlib.util.module_from_spec(MATERIALIZE_SPEC)
MATERIALIZE_SPEC.loader.exec_module(materialize)


class AuthenticationAssembly(unittest.TestCase):
    def test_wayland_protocol_integrity_pin_uses_canonical_git_bytes(self):
        root = Path(__file__).resolve().parents[1]
        protocol = root / 'security-center/packaging/application-security/wayland/security-context-v1.xml'
        canonical = protocol.read_bytes().replace(b'\r\n', b'\n')
        digest = hashlib.sha256(canonical).hexdigest()
        spec = (root / 'security-center/packaging/application-security/greyward-application-security-experimental.spec').read_text()

        self.assertIn(f"expected = '{digest}'", spec)

    def test_private_auth_profile_marks_pinned_dms_defaults_current(self):
        template = {'configVersion': 0, 'loginctlLockIntegration': False,
                    'lockPamPath': '/unsafe/user/value', 'customDefault': 'preserved'}
        settings = materialize.authentication_settings(template)

        self.assertEqual(settings['configVersion'], 18)
        self.assertEqual(settings['loginctlLockIntegration'], True)
        self.assertEqual(settings['lockPamPath'], '/etc/pam.d/greyward-dms-lock')
        self.assertEqual(settings['customDefault'], 'preserved')
        self.assertEqual(template['configVersion'], 0)
        self.assertEqual(template['lockPamPath'], '/unsafe/user/value')

    def test_login_readiness_polls_fast_then_keeps_a_low_rate_heartbeat(self):
        self.assertIn('id: readinessTimer', assembly.SHELL)
        self.assertIn('interval: 100', assembly.SHELL)
        self.assertIn('const registered = PolkitService.agent?.isRegistered === true;', assembly.SHELL)
        self.assertIn('if (registered)\n                readinessTimer.interval = 1000;', assembly.SHELL)
        self.assertIn('polkitRegistered: registered', assembly.SHELL)

    def test_atomic_readiness_has_a_dedicated_metadata_parent(self):
        start = assembly.SHELL.index('id: usbReadiness\n')
        end = assembly.SHELL.index('    Timer {', start)
        writer = assembly.SHELL[start:end]
        self.assertIn('/usbguard-approval/readiness.json', writer)
        self.assertNotIn('atomicWrites: false', assembly.SHELL)
        # The permission is for metadata only, not arbitrary auth runtime files.
        policy = (SOURCE.parents[4] / 'environment/production/selinux/greyward-application-usbguard-approval.te').read_text()
        self.assertIn('greyward_usbguard_auth_readiness_dir_t "usbguard-approval";', policy)
        self.assertIn('greyward_as_auth_t greyward_usbguard_auth_readiness_dir_t:file', policy)
        self.assertNotIn('greyward_usbguard_approval_t greyward_as_auth_runtime_t:file', policy)
        self.assertNotIn('cgroup', policy)

    def test_usb_cli_buffers_are_private_without_general_tmpfs_or_auth_reads(self):
        policy = (SOURCE.parents[4] / 'environment/production/selinux/greyward-application-usbguard-approval.te').read_text()
        self.assertIn('fs_tmpfs_filetrans(greyward_usbguard_approval_t, greyward_usbguard_client_tmpfs_t, file)', policy)
        self.assertNotIn('greyward_usbguard_approval_t tmpfs_t:file', policy)
        self.assertNotIn('greyward_usbguard_approval_t greyward_as_auth_runtime_t:file', policy)
        self.assertIn('greyward_as_auth_runtime_t:dir { search getattr }', policy)

    @unittest.skipUnless(os.name == 'posix', 'Unix ownership and modes')
    def test_usb_metadata_directory_is_private_and_rejects_aliases(self):
        with tempfile.TemporaryDirectory() as folder:
            auth = Path(folder)
            (auth / 'runtime').mkdir()
            with mock.patch.object(materialize.os, 'chown') as chown, mock.patch.object(materialize, 'run') as run:
                materialize.prepare_usb_metadata(auth, os.getuid(), os.getgid())
                directory = auth / 'runtime/usbguard-approval'
                chown.assert_called_once()
                run.assert_called_once_with('/usr/bin/chcon', '-t', 'greyward_usbguard_auth_readiness_dir_t', str(directory))
            directory.rmdir()
            directory.symlink_to(auth / 'runtime', target_is_directory=True)
            with self.assertRaises(RuntimeError), mock.patch.object(materialize, 'run') as run:
                materialize.prepare_usb_metadata(auth, 1000, 1000)
            run.assert_not_called()

    def test_usbguard_request_is_executed_by_the_active_protected_session(self):
        root = Path(__file__).resolve().parents[1]
        widget = (root / 'environment/session/dankmaterialshell/plugins/greywardSecure/SecureWidget.qml').read_text()
        helper = (root / 'packaging/greyward-dms/usbguard-approval.go').read_text()
        auth_helper = (root / 'packaging/greyward-dms/usbguard-approval-execute.go').read_text()
        self.assertIn('function requestUsbTrust(reference: string, mode: string, requestId: string)', assembly.SHELL)
        self.assertIn('function usbTrustStatus(requestId: string)', assembly.SHELL)
        self.assertIn('PolkitService.agent?.isRegistered !== true', assembly.SHELL)
        self.assertIn('/usr/libexec/greyward-usbguard-auth-approval', assembly.SHELL)
        self.assertIn('"usbguard-approval", "readiness.json"', helper)
        self.assertIn('"/usr/bin/qs"', helper)
        self.assertIn('"--pid"', helper)
        self.assertNotIn('"--any-display"', helper)
        self.assertIn('"requestUsbTrust"', helper)
        self.assertIn('"usbTrustStatus"', helper)
        self.assertIn('syscall.Exec("/usr/bin/python3", argv, os.Environ())', auth_helper)
        self.assertIn('greyward-usbguard-approval', widget)
        self.assertNotIn('greyward-usbguard-auth-approval', widget)

    def test_startup_backdrop_is_branded_noninteractive_and_behind_the_desktop(self):
        self.assertIn('import Quickshell.Wayland', assembly.SHELL)
        self.assertIn('model: Quickshell.screens', assembly.SHELL)
        self.assertIn('WlrLayershell.layer: WlrLayer.Background', assembly.SHELL)
        self.assertIn('WlrLayershell.keyboardFocus: WlrKeyboardFocus.None', assembly.SHELL)
        self.assertIn('mask: Region { item: Item {} }', assembly.SHELL)
        self.assertIn('Starting your secure desktop', assembly.SHELL)

    def test_early_startup_surface_is_minimal_noninteractive_and_in_auth_shell_receipt(self):
        splash = assembly.STARTUP_SHELL
        self.assertIn('import QtQuick', splash)
        self.assertIn('import Quickshell.Wayland', splash)
        self.assertIn('WlrLayershell.layer: WlrLayer.Background', splash)
        self.assertIn('WlrLayershell.keyboardFocus: WlrKeyboardFocus.None', splash)
        self.assertIn('mask: Region { item: Item {} }', splash)
        self.assertNotIn('PolkitService', splash)
        self.assertNotIn('onClicked', splash)

    def test_authentication_worker_starts_optional_splash_before_full_dms(self):
        source = (Path(__file__).resolve().parents[1] /
                  'security-center/packaging/application-security/desktop/authentication.py').read_text()
        splash_start = source.index("BASE / 'shell/startup'")
        backend_start = source.index("BASE / 'bin/dms'")
        self.assertLess(splash_start, backend_start)
        self.assertIn('except OSError as error:', source)
        self.assertIn("runtime / 'authentication-ready.json'", source)
        self.assertIn('process.terminate()', source)

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
            self.assertIn('startup/shell.qml', first['shellFiles'])
            self.assertEqual((base / 'first/shell/startup/shell.qml').read_text(encoding='utf-8'),
                             assembly.STARTUP_SHELL)
            auth_shell = (base / 'first/shell/shell.qml').read_text(encoding='utf-8')
            self.assertIn('split(String.fromCharCode(10))', auth_shell)
            self.assertNotIn('split(/\n', auth_shell)
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

    def test_candidate_revision_preserves_pins_and_rejects_unknown_releases(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            root, receipt, pins = self.fixture(base)
            release = json.loads(receipt.read_text())
            with mock.patch.object(assembly, 'PREIMAGES', pins):
                for supported in ['v1.6.2-8', 'v1.6.2-10', 'v1.6.2-11', 'v1.6.2-12', 'v1.6.2-13', 'v1.6.2-14', 'v1.6.2-15', 'v1.6.2-17', 'v1.6.2-18', 'v1.6.2-19', 'v1.6.2-20', 'v1.6.2-21', 'v1.6.2-22', 'v1.6.2-23']:
                    release['releaseId'] = supported
                    receipt.write_text(json.dumps(release))
                    result = assembly.assemble(root, receipt,
                                               base / ('candidate-' + supported.rsplit('-', 1)[1]))
                    self.assertEqual(result['sourceRelease'], supported)
                release['releaseId'] = 'v1.6.2-9'
                receipt.write_text(json.dumps(release))
                with self.assertRaises(ValueError):
                    assembly.assemble(root, receipt, base / 'unknown')
            self.assertFalse((base / 'unknown').exists())

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
