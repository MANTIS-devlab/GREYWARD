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
    "Modals/PolkitAuthContent.qml": "4f185cdfc1cba27e6e6f1a85444d40f90f172349b82afc7f09e33c7b34652cd8",
}

# Revision 8 changes build receipts/desktop plugins; the authentication inputs
# remain exact-pinned below. A new release still requires explicit review.
SUPPORTED_RELEASES = frozenset({"v1.6.2-6", "v1.6.2-8", "v1.6.2-10", "v1.6.2-11", "v1.6.2-12", "v1.6.2-13", "v1.6.2-14", "v1.6.2-15", "v1.6.2-17", "v1.6.2-18", "v1.6.2-19", "v1.6.2-20", "v1.6.2-21", "v1.6.2-22", "v1.6.2-23", "v1.6.2-24", "v1.6.2-25", "v1.6.2-26"})

SHELL = '''//@ pragma UseQApplication
//@ pragma AppId com.danklinux.dms
import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import qs.Common
import qs.DankCommon.Common as DC
import qs.Modules.Lock
import qs.Services

ShellRoot {
    id: shellRoot
    property string usbApprovalRequestId: ""
    property bool usbApprovalActive: false
    property double usbApprovalUpdatedAtMs: 0
    property var usbApprovalResult: ({ok: false, state: "IDLE", detail: "No USB approval request."})

    Variants {
        model: Quickshell.screens

        PanelWindow {
            required property var modelData
            screen: modelData

            WlrLayershell.layer: WlrLayer.Background
            WlrLayershell.exclusionMode: ExclusionMode.Ignore
            WlrLayershell.keyboardFocus: WlrKeyboardFocus.None
            anchors.top: true
            anchors.bottom: true
            anchors.left: true
            anchors.right: true
            color: "#151a20"

            // Show a trusted background during protected-login startup. The
            // normal desktop wallpaper replaces it at the same layer.
            mask: Region { item: Item {} }

            Rectangle {
                anchors.fill: parent
                gradient: Gradient {
                    GradientStop { position: 0.0; color: "#202830" }
                    GradientStop { position: 1.0; color: "#11161b" }
                }
            }

            Column {
                anchors.centerIn: parent
                spacing: 12

                Text {
                    anchors.horizontalCenter: parent.horizontalCenter
                    text: "GREYWARD"
                    color: "#d9e1e7"
                    font.pixelSize: 28
                    font.weight: Font.DemiBold
                    font.letterSpacing: 4
                }

                Text {
                    anchors.horizontalCenter: parent.horizontalCenter
                    text: "Starting your secure desktop…"
                    color: "#aab7c2"
                    font.pixelSize: 15
                }
            }
        }
    }

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
    FileView {
        id: usbReadiness
        // Its dedicated parent labels atomic temporary inodes as metadata.
        // Never export the general authentication heartbeat or private runtime.
        path: Quickshell.env("XDG_RUNTIME_DIR") + "/usbguard-approval/readiness.json"
    }
    Timer {
        id: readinessTimer
        interval: 100
        running: true
        repeat: true
        onTriggered: {
            const registered = PolkitService.agent?.isRegistered === true;
            readiness.setText(JSON.stringify({
                schema: "greyward.authentication-readiness/v1",
                pid: Quickshell.processId, observedAtMs: Date.now(),
                polkitRegistered: registered,
                polkitActive: PolkitService.agent?.isActive === true,
                exclusiveInput: nativeLock.authenticationInputSecure,
                lockRequested: nativeLock.shouldLock
            }));
            usbReadiness.setText(JSON.stringify({
                schema: "greyward.authentication-readiness/v1",
                pid: Quickshell.processId, observedAtMs: Date.now(),
                polkitRegistered: registered,
                polkitActive: PolkitService.agent?.isActive === true
            }));
            // Poll quickly only during startup so login does not wait for the
            // first one-second heartbeat after Polkit registers.
            if (registered)
                readinessTimer.interval = 1000;
        }
    }
    Process {
        id: usbApprovalProcess
        command: []
        stdout: StdioCollector { id: usbApprovalOutput }
        onExited: (exitCode, exitStatus) => {
            const lines = String(usbApprovalOutput.text || "").split(String.fromCharCode(10)).filter(line => line.trim().length > 0);
            let result = null;
            try { result = lines.length ? JSON.parse(lines[lines.length - 1]) : null; } catch (error) {}
            const confirmed = exitCode === 0 && result?.ok === true && result?.state === "COMPLETE";
            if (!confirmed) {
                result = result && result.ok === false && typeof result.state === "string" ? result :
                    {ok: false, state: "FAILED", detail: "USBGuard did not return verified approval evidence. The device remains blocked."};
            }
            shellRoot.usbApprovalResult = result;
            shellRoot.usbApprovalActive = false;
            shellRoot.usbApprovalUpdatedAtMs = Date.now();
        }
    }
    function requestUsbTrust(reference: string, mode: string, requestId: string): string {
        if (!/^[0-9a-f]{32}$/.test(reference) || !["once", "always"].includes(mode) || !/^[0-9a-f]{32}$/.test(requestId))
            return JSON.stringify({ok: false, state: "INVALID", detail: "Choose a current USB device and a supported trust action."});
        if (requestId === usbApprovalRequestId && (usbApprovalActive || Date.now() - usbApprovalUpdatedAtMs < 180000))
            return JSON.stringify(usbApprovalResult);
        if (usbApprovalActive || usbApprovalProcess.running || PolkitService.agent?.isActive === true)
            return JSON.stringify({ok: false, state: "BUSY", detail: "Another protected authorization is active. Try again when it finishes."});
        if (PolkitService.agent?.isRegistered !== true)
            return JSON.stringify({ok: false, state: "UNAVAILABLE", detail: "The protected authorization agent is unavailable. The device remains blocked."});
        usbApprovalRequestId = requestId;
        usbApprovalResult = {ok: true, state: "PENDING", detail: "Waiting for administrator approval…"};
        usbApprovalUpdatedAtMs = Date.now();
        usbApprovalActive = true;
        usbApprovalProcess.exec({command: ["/usr/libexec/greyward-usbguard-auth-approval", reference, mode], workingDirectory: "/"});
        return JSON.stringify(usbApprovalResult);
    }
    function usbTrustStatus(requestId: string): string {
        if (!/^[0-9a-f]{32}$/.test(requestId) || requestId !== usbApprovalRequestId)
            return JSON.stringify({ok: false, state: "UNKNOWN", detail: "This USB approval request is no longer available."});
        if (usbApprovalActive)
            return JSON.stringify(usbApprovalResult);
        if (Date.now() - usbApprovalUpdatedAtMs > 180000)
            return JSON.stringify({ok: false, state: "EXPIRED", detail: "The approval result expired. Check the current device state before retrying."});
        return JSON.stringify(usbApprovalResult);
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
        function requestUsbTrust(reference: string, mode: string, requestId: string): string {
            return shellRoot.requestUsbTrust(reference, mode, requestId);
        }
        function usbTrustStatus(requestId: string): string {
            return shellRoot.usbTrustStatus(requestId);
        }
    }
}
'''

# Start a tiny compositor surface before the full DMS authentication shell
# initializes. It carries no input and gives the protected session a visible
# transition while the existing readiness gate completes.
STARTUP_SHELL = '''//@ pragma UseQApplication
//@ pragma AppId systems.mantis.greyward.startup
import QtQuick
import Quickshell
import Quickshell.Wayland

ShellRoot {
    Variants {
        model: Quickshell.screens

        PanelWindow {
            required property var modelData
            screen: modelData

            WlrLayershell.layer: WlrLayer.Background
            WlrLayershell.exclusionMode: ExclusionMode.Ignore
            WlrLayershell.keyboardFocus: WlrKeyboardFocus.None
            anchors.top: true
            anchors.bottom: true
            anchors.left: true
            anchors.right: true
            color: "#151a20"
            mask: Region { item: Item {} }

            Rectangle {
                anchors.fill: parent
                gradient: Gradient {
                    GradientStop { position: 0.0; color: "#202830" }
                    GradientStop { position: 1.0; color: "#11161b" }
                }
            }

            Column {
                anchors.centerIn: parent
                spacing: 12

                Text {
                    anchors.horizontalCenter: parent.horizontalCenter
                    text: "GREYWARD"
                    color: "#d9e1e7"
                    font.pixelSize: 28
                    font.weight: Font.DemiBold
                    font.letterSpacing: 4
                }

                Text {
                    anchors.horizontalCenter: parent.horizontalCenter
                    text: "Starting your secure desktop…"
                    color: "#aab7c2"
                    font.pixelSize: 15
                }
            }
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


def replace_region_once(text, start_marker, end_marker, replacement):
    if text.count(start_marker) != 1 or text.count(end_marker) != 1:
        raise ValueError("Authentication region changed")
    start = text.index(start_marker)
    end = text.index(end_marker, start)
    if end <= start:
        raise ValueError("Authentication region boundaries changed")
    return text[:start] + replacement + text[end:]


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


def branded_authorization_content(text):
    """Use the same bounded GREYWARD card on the input and mirror displays."""
    text = replace_once(text, '    property string passwordInput: ""\n',
                        '    property string passwordInput: ""\n'
                        '    readonly property int passwordCharacterCount: passwordInput.length\n')
    text = block(text, "    Item {\n        id: headerSection", "")
    card = '''    Rectangle {
        id: authorizationCard
        anchors.centerIn: parent
        width: Math.max(1, Math.min(720, parent.width))
        height: Math.max(1, Math.min(440, parent.height))
        radius: 24
        color: "#141b22"
        border.color: "#40545f"
        border.width: 1
        clip: true

        Rectangle {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: parent.top
            height: 3
            gradient: Gradient {
                GradientStop { position: 0; color: "#34525e" }
                GradientStop { position: 0.48; color: "#78d7df" }
                GradientStop { position: 1; color: "#34525e" }
            }
        }

        Column {
            anchors.fill: parent
            anchors.margins: 28
            spacing: 13

            Row {
                width: parent.width
                spacing: 12

                Rectangle {
                    width: 42
                    height: 42
                    radius: 14
                    color: "#20343e"
                    border.color: "#3f6472"
                    border.width: 1

                    DankIcon {
                        anchors.centerIn: parent
                        name: "shield_lock"
                        size: 23
                        color: "#8bd5df"
                        filled: true
                    }
                }

                Column {
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: 3

                    StyledText {
                        text: "GREYWARD"
                        font.pixelSize: Theme.fontSizeSmall
                        font.weight: Font.DemiBold
                        font.letterSpacing: 1.7
                        color: "#e7eef1"
                    }

                    StyledText {
                        text: "SECURE AUTHORIZATION"
                        font.pixelSize: Theme.fontSizeSmall - 2
                        font.weight: Font.Medium
                        font.letterSpacing: 1
                        color: "#8bd5df"
                    }
                }
            }

            StyledText {
                width: parent.width
                text: I18n.tr("Authentication Required")
                font.pixelSize: Theme.fontSizeLarge
                font.weight: Font.DemiBold
                color: "#f1f5f7"
            }

            Rectangle {
                width: parent.width
                height: 76
                radius: 15
                color: "#1b252d"
                border.color: "#344853"
                border.width: 1
                clip: true

                Column {
                    anchors.fill: parent
                    anchors.margins: 13
                    spacing: 4

                    StyledText {
                        text: "AUTHORIZATION REQUEST"
                        font.pixelSize: Theme.fontSizeSmall - 2
                        font.weight: Font.DemiBold
                        font.letterSpacing: 1
                        color: "#94aab5"
                    }

                    StyledText {
                        width: parent.width
                        text: root.currentFlow?.message ?? ""
                        font.pixelSize: Theme.fontSizeMedium
                        color: "#e0e8ec"
                        wrapMode: Text.Wrap
                        maximumLineCount: 2
                        elide: Text.ElideRight
                    }
                }
            }

            DankTextField {
                id: passwordField
                width: parent.width
                height: 68
                radius: 15
                cornerRadius: 15
                backgroundColor: "#10171d"
                focusedBorderColor: "#70cbd5"
                normalBorderColor: passwordCharacterCount > 0 ? "#70cbd5" : "#42535d"
                borderWidth: 1
                focusedBorderWidth: 2
                labelText: root.currentFlow?.inputPrompt ?? I18n.tr("Password")
                placeholderText: I18n.tr("Enter your password")
                hidePlaceholderOnFocus: false
                leftIconName: "lock"
                leftIconSize: 19
                leftIconColor: "#8bd5df"
                leftIconFocusedColor: "#8bd5df"
                font.pixelSize: Theme.fontSizeMedium
                textColor: "#edf3f5"
                text: root.passwordInput
                showPasswordToggle: false
                echoMode: (root.currentFlow?.responseVisible ?? false) || passwordVisible ? TextInput.Normal : TextInput.Password
                enabled: !root.isLoading
                opacity: enabled ? 1 : 0.5
                onTextEdited: root.passwordInput = text
                onAccepted: root.submitAuth()
            }

            StyledText {
                width: parent.width
                text: I18n.tr("Authentication failed - try again")
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.error
                visible: PolkitService.authFailed
            }

            Item {
                width: parent.width
                height: 40

                Row {
                    anchors.right: parent.right
                    spacing: 10

                    Rectangle {
                        width: 88
                        height: 38
                        radius: 12
                        color: cancelButton.containsMouse ? "#27343d" : "#202a31"
                        border.color: "#43555f"
                        border.width: 1
                        enabled: !root.isLoading
                        opacity: enabled ? 1 : 0.5

                        StyledText {
                            anchors.centerIn: parent
                            text: I18n.tr("Cancel")
                            font.pixelSize: Theme.fontSizeSmall
                            font.weight: Font.Medium
                            color: "#d9e2e6"
                        }

                        MouseArea {
                            id: cancelButton
                            anchors.fill: parent
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            enabled: parent.enabled
                            onClicked: root.cancelAuth()
                        }
                    }

                    Rectangle {
                        width: 126
                        height: 38
                        radius: 12
                        color: authenticateButton.containsMouse ? "#9ae0e5" : "#78d2db"
                        enabled: !root.isLoading
                        opacity: enabled ? 1 : 0.5

                        StyledText {
                            anchors.centerIn: parent
                            text: I18n.tr("Authenticate")
                            font.pixelSize: Theme.fontSizeSmall
                            font.weight: Font.DemiBold
                            color: "#112027"
                        }

                        MouseArea {
                            id: authenticateButton
                            anchors.fill: parent
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            enabled: parent.enabled
                            onClicked: root.submitAuth()
                        }
                    }
                }
            }
        }
    }
'''
    return block(text, "    Column {\n        id: bottomSection", card)

def protected_authorization(text):
    """Use the native session-lock surface for both password-bearing flows.

    Ordinary clients may keep layer-shell chrome, so a floating Polkit window
    cannot establish exclusive input. Completion releases only a lock acquired
    for this challenge; it never releases a pre-existing native session lock.
    """
    text = replace_once(text, "import qs.Services\n", "import qs.Services\nimport QtQuick.Window\nimport qs.Modals\nimport qs.Widgets\n")
    text = replace_once(text, '    property bool shouldLock: false\n', '''    property bool shouldLock: false
    readonly property bool authenticationInputSecure: sessionLock.secure
    readonly property bool authorizationActive: PolkitService.agent?.isActive ?? false
    property bool authorizationPending: false
    property bool authorizationWasLocked: false
    property bool administrationActive: false
    property string authorizationScreenName: ""
    property int authorizationPasswordLength: 0
    property var authorizationController: null

    function reconcileAuthorizationScreen() {
        const screens = Quickshell.screens ?? [];
        for (const screen of screens) {
            if (screen?.name === authorizationScreenName)
                return;
        }
        authorizationScreenName = screens[0]?.name ?? "";
    }

    onAuthorizationActiveChanged: {
        if (authorizationActive) {
            // Keep one protected password-entry control for the Polkit
            // challenge; every output mirrors only its masked character count.
            authorizationScreenName = Quickshell.screens?.[0]?.name ?? "";
            authorizationWasLocked = shouldLock;
            authorizationPending = true;
            sharedPasswordBuffer = "";
            authorizationPasswordLength = 0;
            authorizationController = null;
            shouldLock = true;
        } else if (authorizationPending) {
            authorizationPending = false;
            authorizationScreenName = "";
            authorizationPasswordLength = 0;
            authorizationController = null;
            if (!authorizationWasLocked)
                shouldLock = false;
        }
    }

    Connections {
        target: Quickshell
        function onScreensChanged() {
            root.reconcileAuthorizationScreen();
        }
    }
''')
    # Root coordinates exclusive ownership: native DMS retains lock/PAM authority,
    # while Administration temporarily owns a private terminal surface. It never
    # unlocks DMS, receives passwords, or substitutes a different locker.
    text = replace_once(text, '        locked: shouldLock && !lockRetryPending\n',
                        '        locked: root.authorizationActive || (shouldLock && !lockRetryPending && !root.administrationActive)\n')
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
                color: "#10161b"
                visible: root.authorizationActive

                Column {
                    anchors.centerIn: parent
                    width: Math.min(520, parent.width - 40)
                    spacing: 10
                    visible: root.authorizationActive && !sessionLock.secure

                    Text {
                        width: parent.width
                        text: "GREYWARD  ·  SECURE AUTHORIZATION"
                        color: "#a8d7c7"
                        font.pixelSize: 13
                        font.weight: Font.DemiBold
                        horizontalAlignment: Text.AlignHCenter
                    }

                    Text {
                        width: parent.width
                        text: "Securing the authorization screen…"
                        color: "#e1e8ed"
                        font.pixelSize: 18
                        font.weight: Font.Medium
                        horizontalAlignment: Text.AlignHCenter
                        wrapMode: Text.Wrap
                    }

                    Text {
                        width: parent.width
                        text: "Password entry will appear after this screen is protected."
                        color: "#adbac3"
                        font.pixelSize: 14
                        horizontalAlignment: Text.AlignHCenter
                        wrapMode: Text.Wrap
                    }
                }
            }

            Loader {
                id: authorizationContent
                anchors.centerIn: parent
                width: Math.max(1, Math.min(720, parent.width - 48))
                height: Math.max(1, Math.min(440, parent.height - 48))
                active: root.authorizationActive && lockSurface.screen?.name === root.authorizationScreenName
                visible: sessionLock.secure && root.authorizationActive && lockSurface.screen?.name === root.authorizationScreenName
                focus: visible
                sourceComponent: PolkitAuthContent {
                    onCloseRequested: PolkitService.agent?.flow?.cancelAuthenticationRequest()
                }
                function focusAuthorization(reason) {
                    if (!visible || !sessionLock.secure || !item || lockSurface.screen?.name !== root.authorizationScreenName)
                        return;
                    Qt.callLater(() => {
                        if (!visible || !sessionLock.secure || !item || lockSurface.screen?.name !== root.authorizationScreenName)
                            return;
                        item.focusPasswordField();
                        // State only: never log keys, text or password length.
                        console.info("GREYWARD protected-input", reason,
                            "scopeFocused=" + item.activeFocus,
                            "windowFocused=" + (authorizationContent.Window.window?.active ?? false));
                    });
                }
                onLoaded: {
                    root.authorizationController = item;
                    root.authorizationPasswordLength = item.passwordCharacterCount;
                    focusAuthorization("loaded");
                }
                onVisibleChanged: focusAuthorization("visible")
            }

            Connections {
                target: authorizationContent.item
                function onPasswordCharacterCountChanged() {
                    root.authorizationPasswordLength = authorizationContent.item?.passwordCharacterCount ?? 0;
                }
            }

            Rectangle {
                id: remoteAuthorizationCard
                anchors.centerIn: parent
                width: Math.min(480, parent.width - 48)
                height: 274
                radius: 22
                color: "#131b22"
                border.color: "#526875"
                border.width: 1
                visible: sessionLock.secure && root.authorizationActive && lockSurface.screen?.name !== root.authorizationScreenName

                Rectangle {
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: parent.top
                    anchors.leftMargin: 24
                    anchors.rightMargin: 24
                    height: 2
                    radius: 1
                    gradient: Gradient {
                        GradientStop { position: 0; color: "#24404b" }
                        GradientStop { position: 0.5; color: "#70c7d5" }
                        GradientStop { position: 1; color: "#24404b" }
                    }
                }

                Column {
                    anchors.fill: parent
                    anchors.margins: 26
                    spacing: 13

                    Row {
                        spacing: 10

                        Rectangle {
                            width: 38
                            height: 38
                            radius: 12
                            color: "#20333c"
                            border.color: "#426574"
                            border.width: 1

                            DankIcon {
                                anchors.centerIn: parent
                                name: "shield_lock"
                                size: 21
                                color: "#8bd5df"
                                filled: true
                            }
                        }

                        Column {
                            anchors.verticalCenter: parent.verticalCenter
                            spacing: 2

                            StyledText {
                                text: "GREYWARD"
                                font.pixelSize: Theme.fontSizeSmall
                                font.weight: Font.DemiBold
                                font.letterSpacing: 1.5
                                color: "#e4ebef"
                            }

                            StyledText {
                                text: "SECURE AUTHORIZATION"
                                font.pixelSize: Theme.fontSizeSmall - 2
                                font.weight: Font.Medium
                                font.letterSpacing: 1
                                color: "#8bd5df"
                            }
                        }
                    }

                    StyledText {
                        width: parent.width
                        text: I18n.tr("Authentication Required")
                        font.pixelSize: Theme.fontSizeLarge
                        font.weight: Font.DemiBold
                        color: "#f1f5f7"
                    }

                    Rectangle {
                        width: parent.width
                        height: 66
                        radius: 13
                        color: "#1a2730"
                        border.color: "#344d59"
                        border.width: 1

                        Row {
                            anchors.fill: parent
                            anchors.leftMargin: 14
                            anchors.rightMargin: 14
                            spacing: 11

                            DankIcon {
                                anchors.verticalCenter: parent.verticalCenter
                                name: "keyboard"
                                size: 22
                                color: "#8bd5df"
                            }

                            Column {
                                anchors.verticalCenter: parent.verticalCenter
                                spacing: 3

                                StyledText {
                                    text: "KEYBOARD INPUT ON"
                                    font.pixelSize: Theme.fontSizeSmall - 2
                                    font.weight: Font.DemiBold
                                    font.letterSpacing: 1
                                    color: "#a6b7c1"
                                }

                                StyledText {
                                    text: root.authorizationScreenName || "Primary display"
                                    font.pixelSize: Theme.fontSizeMedium
                                    font.weight: Font.DemiBold
                                    color: "#f1f5f7"
                                }
                            }
                        }
                    }

                    Row {
                        spacing: 8

                        Rectangle {
                            radius: 9
                            width: layoutIndicatorContent.implicitWidth + 16
                            implicitWidth: width
                            height: 30
                            color: "#202c34"
                            border.color: "#3b505b"
                            border.width: 1

                            Row {
                                id: layoutIndicatorContent
                                anchors.centerIn: parent
                                spacing: 6

                                DankIcon {
                                    anchors.verticalCenter: parent.verticalCenter
                                    name: "keyboard"
                                    size: 14
                                    color: "#b4c5ce"
                                }

                                StyledText {
                                    anchors.verticalCenter: parent.verticalCenter
                                    text: root.keyboardLayoutLabel
                                    font.pixelSize: Theme.fontSizeSmall - 1
                                    font.weight: Font.DemiBold
                                    color: "#d6e0e5"
                                }
                            }
                        }

                        StyledText {
                            anchors.verticalCenter: parent.verticalCenter
                            text: "VIEW ONLY"
                            font.pixelSize: Theme.fontSizeSmall - 2
                            font.weight: Font.DemiBold
                            font.letterSpacing: 1
                            color: "#8e9ca5"
                        }
                    }
                }
            }

            Connections {
                target: sessionLock
                function onSecureChanged() {
                    if (sessionLock.secure && root.authorizationActive && authorizationContent.active)
                        authorizationContent.focusAuthorization("secured");
                }
            }

            Connections {
                target: authorizationContent.Window.window
                function onActiveChanged() {
                    // Wayland keyboard-enter can arrive after locked/loaded.
                    // Focus only on window entry; retain normal button/Tab use.
                    if (authorizationContent.active && authorizationContent.Window.window?.active === true)
                        authorizationContent.focusAuthorization("keyboard-enter");
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
    remote_card = '''            Rectangle {
                id: remoteAuthorizationCard
                anchors.centerIn: parent
                width: Math.max(1, Math.min(720, parent.width - 48))
                height: Math.max(1, Math.min(440, parent.height - 48))
                radius: 24
                color: "#141b22"
                border.color: "#40545f"
                border.width: 1
                clip: true
                visible: sessionLock.secure && root.authorizationActive && lockSurface.screen?.name !== root.authorizationScreenName

                Rectangle {
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: parent.top
                    height: 3
                    gradient: Gradient {
                        GradientStop { position: 0; color: "#34525e" }
                        GradientStop { position: 0.48; color: "#78d7df" }
                        GradientStop { position: 1; color: "#34525e" }
                    }
                }

                Column {
                    anchors.fill: parent
                    anchors.margins: 28
                    spacing: 13

                    Row {
                        width: parent.width
                        spacing: 12

                        Rectangle {
                            width: 42
                            height: 42
                            radius: 14
                            color: "#20343e"
                            border.color: "#3f6472"
                            border.width: 1

                            DankIcon {
                                anchors.centerIn: parent
                                name: "shield_lock"
                                size: 23
                                color: "#8bd5df"
                                filled: true
                            }
                        }

                        Column {
                            anchors.verticalCenter: parent.verticalCenter
                            spacing: 3

                            StyledText {
                                text: "GREYWARD"
                                font.pixelSize: Theme.fontSizeSmall
                                font.weight: Font.DemiBold
                                font.letterSpacing: 1.7
                                color: "#e7eef1"
                            }

                            StyledText {
                                text: "SECURE AUTHORIZATION"
                                font.pixelSize: Theme.fontSizeSmall - 2
                                font.weight: Font.Medium
                                font.letterSpacing: 1
                                color: "#8bd5df"
                            }
                        }
                    }

                    StyledText {
                        width: parent.width
                        text: I18n.tr("Authentication Required")
                        font.pixelSize: Theme.fontSizeLarge
                        font.weight: Font.DemiBold
                        color: "#f1f5f7"
                    }

                    Rectangle {
                        width: parent.width
                        height: 76
                        radius: 15
                        color: "#1b252d"
                        border.color: "#344853"
                        border.width: 1
                        clip: true

                        Column {
                            anchors.fill: parent
                            anchors.margins: 13
                            spacing: 4

                            StyledText {
                                text: "AUTHORIZATION REQUEST"
                                font.pixelSize: Theme.fontSizeSmall - 2
                                font.weight: Font.DemiBold
                                font.letterSpacing: 1
                                color: "#94aab5"
                            }

                            StyledText {
                                width: parent.width
                                text: PolkitService.agent?.flow?.message ?? ""
                                font.pixelSize: Theme.fontSizeMedium
                                color: "#e0e8ec"
                                wrapMode: Text.Wrap
                                maximumLineCount: 2
                                elide: Text.ElideRight
                            }
                        }
                    }

                    Rectangle {
                        id: mirroredPasswordField
                        width: parent.width
                        height: 68
                        radius: 15
                        color: "#10171d"
                        border.color: root.authorizationPasswordLength > 0 ? "#70cbd5" : "#42535d"
                        border.width: root.authorizationPasswordLength > 0 ? 2 : 1

                        Row {
                            anchors.fill: parent
                            anchors.leftMargin: 15
                            anchors.rightMargin: 15
                            spacing: 12

                            DankIcon {
                                anchors.verticalCenter: parent.verticalCenter
                                name: "lock"
                                size: 19
                                color: "#8bd5df"
                            }

                            Column {
                                anchors.verticalCenter: parent.verticalCenter
                                spacing: 3

                                StyledText {
                                text: root.authorizationController?.currentFlow?.inputPrompt ?? I18n.tr("Password")
                                    font.pixelSize: Theme.fontSizeSmall - 2
                                    font.weight: Font.DemiBold
                                    font.letterSpacing: 1
                                    color: "#93a4ad"
                                }

                                StyledText {
                                    width: mirroredPasswordField.width - 90
                                    text: root.authorizationPasswordLength > 0
                                        ? "\\u2022".repeat(root.authorizationPasswordLength)
                                        : I18n.tr("Enter your password")
                                    font.pixelSize: Theme.fontSizeMedium
                                    font.weight: Font.Medium
                                    color: "#edf3f5"
                                    maximumLineCount: 1
                                    elide: Text.ElideRight
                                }
                            }
                        }

                        MouseArea {
                            anchors.fill: parent
                            cursorShape: Qt.IBeamCursor
                            onClicked: root.authorizationController?.focusPasswordField()
                        }
                    }

                    StyledText {
                        width: parent.width
                        text: I18n.tr("Authentication failed - try again")
                        font.pixelSize: Theme.fontSizeSmall
                        color: Theme.error
                        visible: PolkitService.authFailed
                    }

                    Item {
                        width: parent.width
                        height: 40

                        Row {
                            anchors.right: parent.right
                            spacing: 10

                            Rectangle {
                                width: 88
                                height: 38
                                radius: 12
                                color: cancelRemote.containsMouse ? "#27343d" : "#202a31"
                                border.color: "#43555f"
                                border.width: 1

                                StyledText {
                                    anchors.centerIn: parent
                                    text: I18n.tr("Cancel")
                                    font.pixelSize: Theme.fontSizeSmall
                                    font.weight: Font.Medium
                                    color: "#d9e2e6"
                                }

                                MouseArea {
                                    id: cancelRemote
                                    anchors.fill: parent
                                    hoverEnabled: true
                                    cursorShape: Qt.PointingHandCursor
                                    enabled: !(root.authorizationController?.isLoading ?? false)
                                    onClicked: root.authorizationController?.cancelAuth()
                                }
                            }

                            Rectangle {
                                width: 126
                                height: 38
                                radius: 12
                                color: authenticateRemote.containsMouse ? "#9ae0e5" : "#78d2db"
                                enabled: !(root.authorizationController?.isLoading ?? false)
                                opacity: enabled ? 1 : 0.5

                                StyledText {
                                    anchors.centerIn: parent
                                    text: I18n.tr("Authenticate")
                                    font.pixelSize: Theme.fontSizeSmall
                                    font.weight: Font.DemiBold
                                    color: "#112027"
                                }

                                MouseArea {
                                    id: authenticateRemote
                                    anchors.fill: parent
                                    hoverEnabled: true
                                    cursorShape: Qt.PointingHandCursor
                                    enabled: parent.enabled
                                    onClicked: root.authorizationController?.submitAuth()
                                }
                            }
                        }
                    }
                }
            }
'''
    text = replace_region_once(
        text,
        '            Rectangle {\n                id: remoteAuthorizationCard\n',
        '\n            Connections {\n                target: sessionLock',
        remote_card + '\n')
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
    if release.get("schema") != "greyward.dms-release/v1" or release.get("releaseId") not in SUPPORTED_RELEASES or release.get("shellFiles") != files or release.get("shell", {}).get("sha256") != digest:
        raise ValueError("Matched DMS package shell/receipt required")
    if any(files.get(name) != digest for name, digest in PREIMAGES.items()):
        raise ValueError("Authentication source changed; review and tests required")
    if output.exists() or source.resolve() in output.resolve().parents:
        raise ValueError("New independent output required")
    # Perform all structure checks before creating output.
    lock = protected_authorization(restricted_lock((source / "Modules/Lock/Lock.qml").read_text(encoding="utf-8")))
    pam = restricted_pam((source / "Modules/Lock/Pam.qml").read_text(encoding="utf-8"))
    shutil.copytree(source, output / "shell")
    authorization_content = branded_authorization_content(
        (source / "Modals/PolkitAuthContent.qml").read_text(encoding="utf-8"))
    for name, text in {"shell.qml": SHELL, "Modules/Lock/Lock.qml": lock,
                       "Modules/Lock/Pam.qml": pam,
                       "Modals/PolkitAuthContent.qml": authorization_content}.items():
        (output / "shell" / name).write_bytes(text.encode())
    startup = output / "shell/startup"
    startup.mkdir()
    (startup / "shell.qml").write_bytes(STARTUP_SHELL.encode())
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
