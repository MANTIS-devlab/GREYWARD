#!/usr/bin/python3
"""Offline exact-input auth-only DMS derivative; never changes the desktop shell.

This is a packaging input, not an enrollment/activation command. The generated
tree must be root-owned and selected only by the root authentication launcher.
Its receipt is integrity metadata, never live authentication/session coverage.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

PREIMAGES = {
    "Modules/Lock/Lock.qml": "e9a7ef6fef68684e1f9b1a8385f3d958b4f3b8f68d5d32ddf837e91e008ac985",
    "Modules/Lock/Pam.qml": "d4a9f0a2b775d3117a0c405cef09173b38bb96bb1dc497cde67d0b664e2b0a1c",
}

SHELL = '''//@ pragma UseQApplication
//@ pragma AppId com.danklinux.dms
import QtQuick
import Quickshell
import Quickshell.Io
import qs.Common
import qs.DankCommon.Common as DC
import qs.Modules.Lock
import qs.Services

ShellRoot {
    Component.onCompleted: {
        Quickshell.watchFiles = false;
        DC.Style.theme = Theme;
        DC.Style.settings = SettingsData;
        DC.I18n.backend = I18n;
        DC.Paths.backend = Paths;
        DC.Log.backend = Log;
        DC.Host.session = SessionService;
        DC.Host.cache = CacheData;
        void PolkitService.agent;
    }
    property double administrationClock: Date.now()
    Lock { id: nativeLock; administrationActive: administrationState.adapter.active && administrationState.adapter.validUntilMs > administrationClock }
    FileView {
        id: administrationState
        path: Quickshell.env("XDG_RUNTIME_DIR") + "/administration-state.json"
        watchChanges: true
        adapter: JsonAdapter { property bool active: false; property double validUntilMs: 0 }
    }
    Timer { interval: 100; running: true; repeat: true; onTriggered: administrationClock = Date.now() }
    FileView {
        id: readiness
        path: Quickshell.env("XDG_RUNTIME_DIR") + "/authentication-ready.json"
    }
    Timer {
        interval: 1000
        running: true
        repeat: true
        onTriggered: readiness.setText(JSON.stringify({
            schema: "greyward.authentication-readiness/v1",
            pid: Quickshell.processId, observedAtMs: Date.now(),
            polkitRegistered: PolkitService.agent?.isRegistered === true,
            polkitActive: PolkitService.agent?.isActive === true,
            exclusiveInput: nativeLock.authenticationInputSecure,
            lockRequested: nativeLock.shouldLock
        }))
    }
    IpcHandler {
        target: "settings"
        function get(key: string): string {
            if (!["loginctlLockIntegration", "customPowerActionLock", "lockPamExternallyManaged", "lockPamPath"].includes(key))
                throw new Error("Authentication setting unavailable");
            return JSON.stringify(SettingsData[key]);
        }
    }
    IpcHandler {
        target: "authentication"
        function status(): string {
            return JSON.stringify({ polkitRegistered: PolkitService.agent?.isRegistered === true,
                polkitActive: PolkitService.agent?.isActive === true,
                responseRequired: PolkitService.agent?.flow?.isResponseRequired === true });
        }
    }
}
'''


def receipt(root):
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError("Special/alias input is not supported")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    digest = hashlib.sha256("".join(f"{name}\0{value}\n" for name, value in sorted(result.items())).encode()).hexdigest()
    return result, digest


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError("Authentication preimage/structure changed")
    return text.replace(before, after, 1)


def block(text, signature, replacement):
    """Only used after an exact whole-file hash; refuses unmatched boundaries."""
    if text.count(signature) != 1:
        raise ValueError("Authentication block changed")
    start = text.index(signature)
    opening = text.index("{", start)
    depth = 1
    end = opening + 1
    while end < len(text) and depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    if depth:
        raise ValueError("Unclosed authentication block")
    return text[:start] + replacement + text[end:]


def restricted_lock(text):
    text = block(text, "function spawnCustomLocker() {", "function spawnCustomLocker() { throw new Error('External locker unavailable'); }")
    text = block(text, "function handleLoginctlCustomLock(): bool {", "function handleLoginctlCustomLock(): bool { return false; }")
    text = block(text, "function onSessionUnlocked() {", "function onSessionUnlocked() { /* Only successful local PAM can release the lock. */ }")
    # Remove only IPC methods, retaining the internal PAM completion handlers.
    for method in ["unlock", "forceReset", "demo"]:
        text = replace_once(text, f"        function {method}() {{\n            " + ("demoWindow.showDemo();" if method == "demo" else f"root.{method}();") + "\n        }", "")
    return text


def protected_authorization(text):
    """Use the native session-lock surface for both password-bearing flows.

    Ordinary clients may keep layer-shell chrome, so a floating Polkit window
    cannot establish exclusive input. Completion releases only a lock acquired
    for this challenge; it never releases a pre-existing native session lock.
    """
    text = replace_once(text, "import qs.Services\n", "import qs.Services\nimport qs.Modals\n")
    text = replace_once(text, '    property bool shouldLock: false\n', '''    property bool shouldLock: false
    readonly property bool authenticationInputSecure: sessionLock.secure
    readonly property bool authorizationActive: PolkitService.agent?.isActive ?? false
    property bool authorizationPending: false
    property bool authorizationWasLocked: false
    property bool administrationActive: false

    onAuthorizationActiveChanged: {
        if (authorizationActive) {
            authorizationWasLocked = shouldLock;
            authorizationPending = true;
            sharedPasswordBuffer = "";
            shouldLock = true;
        } else if (authorizationPending) {
            authorizationPending = false;
            if (!authorizationWasLocked)
                shouldLock = false;
        }
    }
''')
    # Root coordinates exclusive ownership: native DMS retains lock/PAM authority,
    # while Administration temporarily owns a private terminal surface. It never
    # unlocks DMS, receives passwords, or substitutes a different locker.
    text = replace_once(text, '        locked: shouldLock && !lockRetryPending\n',
                        '        locked: shouldLock && !lockRetryPending && !root.administrationActive\n')
    text = replace_once(text, '    function unlock() {\n', '    function unlock() {\n        if (authorizationActive)\n            return;\n')
    text = replace_once(text, '\n    function lock() {\n', '''\n    function lock() {
        if (authorizationActive) {
            authorizationWasLocked = true;
            return;
        }
''')
    text = replace_once(text, '        lockSecured: root.shouldLock\n', '        lockSecured: root.shouldLock && !root.authorizationActive\n')
    text = replace_once(text, '                visible: lockSurface.isActiveScreen\n', '                visible: lockSurface.isActiveScreen && !root.authorizationActive\n')
    text = replace_once(text, '            LockSurface {\n', '''            Rectangle {
                anchors.fill: parent
                color: Theme.background
                visible: root.authorizationActive
            }

            Loader {
                id: authorizationContent
                anchors.centerIn: parent
                width: Math.min(720, parent.width - 32)
                height: Math.min(420, parent.height - 32)
                active: root.authorizationActive
                visible: sessionLock.secure && root.authorizationActive
                sourceComponent: PolkitAuthContent {
                    onCloseRequested: PolkitService.agent?.flow?.cancelAuthenticationRequest()
                }
                onLoaded: {
                    if (sessionLock.secure)
                        Qt.callLater(() => item?.focusPasswordField());
                }
            }

            Connections {
                target: sessionLock
                function onSecureChanged() {
                    if (sessionLock.secure && root.authorizationActive)
                        Qt.callLater(() => authorizationContent.item?.focusPasswordField());
                }
            }

            LockSurface {
''')
    # An invisible FocusScope can still request focus when its lock state
    # changes. Destroy the ordinary lock form throughout a Polkit challenge;
    # only the protected authorization form may handle the response.
    text = replace_once(text, '''            LockSurface {
                anchors.fill: parent
                visible: lockSurface.isActiveScreen && !root.authorizationActive
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
''', '''            Loader {
                anchors.fill: parent
                active: !root.authorizationActive
                visible: lockSurface.isActiveScreen && !root.authorizationActive
                sourceComponent: LockSurface {
                    lock: sessionLock
                    pam: sharedPam
                    sharedPasswordBuffer: root.sharedPasswordBuffer
                    screenName: lockSurface.currentScreenName
                    isLocked: root.shouldLock
                    onUnlockRequested: root.unlock()
                    onPasswordChanged: newPassword => {
                        root.sharedPasswordBuffer = newPassword;
                    }
                }
            }
''')
    return text


def restricted_pam(text):
    text = block(text, "function ensureUserPamConfig(): void {", "function ensureUserPamConfig(): void { /* Fedora's installed PAM stack only. */ }")
    # The primary PAM service is package-owned, never selected from user JSON.
    text = block(text, "        id: passwd\n\n        config: {", '        id: passwd\n\n        config: "greyward-dms-lock"')
    text = block(text, '        config: "greyward-dms-lock"\n        configDirectory: {', '        config: "greyward-dms-lock"\n        configDirectory: "/etc/pam.d"')
    text = replace_once(text, 'readonly property bool customPamActive: SettingsData.lockPamPath !== "" && customPamWatcher.loaded', 'readonly property bool customPamActive: false')
    text = replace_once(text, 'readonly property bool customU2fPamActive: SettingsData.lockU2fPamPath !== "" && customU2fPamWatcher.loaded', 'readonly property bool customU2fPamActive: false')
    text = replace_once(text, 'readonly property bool fprintSuppressedByPrimaryPam: SettingsData.lockPamExternallyManaged || (customPamActive && SettingsData.lockPamInlineFprint)', 'readonly property bool fprintSuppressedByPrimaryPam: true')
    text = replace_once(text, 'readonly property bool u2fSuppressedByPrimaryPam: SettingsData.lockPamExternallyManaged || (customPamActive && SettingsData.lockPamInlineU2f)', 'readonly property bool u2fSuppressedByPrimaryPam: true')
    return text


def assemble(source, release_receipt, output):
    source, output = Path(source), Path(output)
    if source.is_symlink() or Path(release_receipt).is_symlink():
        raise ValueError("Alias source/receipt is not supported")
    release = json.loads(Path(release_receipt).read_text(encoding="utf-8"))
    files, digest = receipt(source)
    if release.get("schema") != "greyward.dms-release/v1" or release.get("releaseId") != "v1.6.2-6" or release.get("shellFiles") != files or release.get("shell", {}).get("sha256") != digest:
        raise ValueError("Matched DMS package shell/receipt required")
    if any(files.get(name) != digest for name, digest in PREIMAGES.items()):
        raise ValueError("Authentication source changed; review and tests required")
    if output.exists() or source.resolve() in output.resolve().parents:
        raise ValueError("New independent output required")
    # Perform all structure checks before creating output.
    lock = protected_authorization(restricted_lock((source / "Modules/Lock/Lock.qml").read_text(encoding="utf-8")))
    pam = restricted_pam((source / "Modules/Lock/Pam.qml").read_text(encoding="utf-8"))
    shutil.copytree(source, output / "shell")
    for name, text in {"shell.qml": SHELL, "Modules/Lock/Lock.qml": lock, "Modules/Lock/Pam.qml": pam}.items():
        (output / "shell" / name).write_bytes(text.encode())
    generated, digest = receipt(output / "shell")
    result = {"schema": "greyward.authentication-shell/v1", "sourceRelease": release["releaseId"],
              "sourceDigest": release["shell"]["sha256"], "shellDigest": digest,
              "shellFiles": generated, "status": "experimental-unactivated", "coverage": "UNKNOWN"}
    (output / "authentication.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ["source", "receipt", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    options = parser.parse_args()
    assemble(options.source, options.receipt, options.output)
