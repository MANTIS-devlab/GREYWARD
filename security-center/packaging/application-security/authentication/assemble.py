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
import textwrap
import re
import xml.etree.ElementTree as ET

PREIMAGES = {
    "Modules/Lock/Lock.qml": "e9a7ef6fef68684e1f9b1a8385f3d958b4f3b8f68d5d32ddf837e91e008ac985",
    "Modules/Lock/Pam.qml": "d4a9f0a2b775d3117a0c405cef09173b38bb96bb1dc497cde67d0b664e2b0a1c",
    "Modals/PolkitAuthContent.qml": "4f185cdfc1cba27e6e6f1a85444d40f90f172349b82afc7f09e33c7b34652cd8",
}

# Revision 8 changes build receipts/desktop plugins; the authentication inputs
# remain exact-pinned below. A new release still requires explicit review.
CANDIDATE_PREIMAGES = {'Modules/Lock/Lock.qml': '02e0da725e0a22716def9d46106a7e7d1af7ba4d3d60f782ccb1d2c4ba8651b4', 'Modules/Lock/Pam.qml': '036f107b404e0a0967f8da13b54f9e2c24a00f6b1c51d8664da0bb6695c94642', 'Modals/PolkitAuthContent.qml': '1afdb4a82d45f3c0fd02e865fe39ddd7c4d45a40f1fc22a9ae5f0d45aa7e3764'}
CANDIDATE_PREIMAGES["Services/PluginService.qml"] = "61a3ffe25dbc5445eab1aaf76affed47cd53c8e609f98b6d88a7e99fe6074d8b"
CANDIDATE_PREIMAGES["Common/SettingsData.qml"] = "8bd76e548070c8cb3565d7215fe3f5126331d8949d0ad04e04b574fe59ab3d99"
CANDIDATE_PREIMAGES["Common/Theme.qml"] = "bbec1714abc78e5f077d5a489d4f404593dcd1be6389b25883af8a401e05f15d"
CANDIDATE_PREIMAGES["Modules/Lock/LockScreenBackground.qml"] = "5ea87d5d72d2ee4a42bef09ab00106624ed9c431b020dc50c9cf488f5e4a9049"
CANDIDATE_RELEASES = frozenset({"v2.0.0-7"})

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
            color: "#0B0D10"

            // Show a trusted background during protected-login startup. The
            // normal desktop wallpaper replaces it at the same layer.
            mask: Region { item: Item {} }

            GreywardStartup { anchors.fill: parent }
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
        function appearance(): string {
            return JSON.stringify({settingsLoaded: SettingsData._hasLoaded === true,
                wallpaperPath: SettingsData.lockScreenWallpaperPath,
                wallpaperFillMode: SettingsData.lockScreenWallpaperFillMode,
                theme: Theme.currentTheme, surface: String(Theme.surface),
                fontFamily: SettingsData.lockScreenFontFamily});
        }
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
            color: "#0B0D10"
            mask: Region { item: Item {} }

            GreywardStartup { anchors.fill: parent }
        }
    }
}
'''


# One visual source for the early backdrop and the full protected shell.
# The animation is deliberately finite: the long-lived auth background must
# return to idle after login rather than animate invisibly behind the desktop.
STARTUP_CONTENT = '''import QtQuick
import QtQuick.Shapes

Item {
    id: startupVisual
    objectName: "greywardStartupVisual"
    enabled: false

    Rectangle {
        anchors.fill: parent
        gradient: Gradient {
            GradientStop { position: 0.0; color: "#12181E" }
            GradientStop { position: 0.55; color: "#0D1116" }
            GradientStop { position: 1.0; color: "#080B0E" }
        }
    }

    Column {
        anchors.centerIn: parent
        width: 460
        spacing: 0
        scale: Math.max(0.35, Math.min(1, (startupVisual.width - 48) / width,
                                     (startupVisual.height - 48) / implicitHeight))

        Item {
            anchors.horizontalCenter: parent.horizontalCenter
            width: 112; height: 140
@STARTUP_EMBLEM@
        }
        Item { width: 1; height: 22 }
        Text {
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            text: "GREYWARD"
            color: "#E1E7EC"
            font.family: "Inter"
            font.pixelSize: 30
            font.weight: Font.Medium
            font.letterSpacing: 5.5
        }
        Item { width: 1; height: 14 }
        Text {
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            text: "Preparing your desktop"
            color: "#A3B0BC"
            font.family: "Inter"
            font.pixelSize: 14
        }
        Item { width: 1; height: 30 }
        Rectangle {
            anchors.horizontalCenter: parent.horizontalCenter
            width: 120; height: 2; radius: 1
            color: "#26313B"
            clip: true
            Rectangle {
                width: 34; height: parent.height; radius: 1
                color: "#BBCBD7"
                NumberAnimation on x {
                    id: waitSweep
                    from: -34; to: 120
                    duration: 1600
                    loops: 4
                    running: startupVisual.visible
                    easing.type: Easing.InOutSine
                }
            }
        }
    }

    Text {
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.bottom: parent.bottom
        anchors.bottomMargin: 24
        text: "MANTIS SYSTEMS"
        color: "#65717D"
        font.family: "Inter"
        font.pixelSize: 10
        font.letterSpacing: 2
    }
}
'''


# A protected owner must never discover or execute ordinary QML plugins, even
# if a future transitive dependency first-touches PluginService. This closed
# read-only stub replaces the pinned 2.0 plugin loader, not the ordinary shell.
NO_PLUGINS = '''pragma Singleton
import QtQuick
import Quickshell
Singleton {
    readonly property var availablePlugins: ({})
    readonly property var loadedPlugins: ({})
    readonly property var availablePluginsList: []
    readonly property var pluginWidgetComponents: ({})
    readonly property var pluginDaemonComponents: ({})
    readonly property var pluginDaemonInstances: ({})
    readonly property var pluginLauncherComponents: ({})
    readonly property var pluginDashComponents: ({})
    readonly property var pluginDashCardComponents: ({})
    readonly property var pluginDesktopComponents: ({})
    readonly property var pluginInstances: ({})
    readonly property var globalVars: ({})
    readonly property string pluginDirectory: ""
    readonly property string systemPluginDirectory: ""
    readonly property bool pluginDirectoryExists: false
    signal pluginListUpdated()
    signal pluginDataChanged(string pluginId)
    signal pluginStateChanged(string pluginId)
    signal globalVarChanged(string pluginId, string name)
    function isPluginLoaded(pluginId) { return false; }
    function checkPluginCompatibility(requirement) { return false; }
    function getPluginVariants(pluginId) { return []; }
    function loadPluginData(pluginId, key, fallback) { return fallback; }
    function loadPluginState(pluginId, key, fallback) { return fallback; }
    function getGlobalVar(pluginId, key, fallback) { return fallback; }
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
    text = replace_once(text, 'import QtQuick\n', 'import QtQuick\nimport QtQuick.Shapes\n')
    text = block(text, "    Item {\n        id: headerSection", "")
    return block(text, "    Column {\n        id: bottomSection", authorization_card())


def startup_content():
    """Compile only canonical OS logo paths; no image worker or file at runtime."""
    source = Path(__file__).with_name('greyward-symbol.svg')
    if not source.exists():
        source = Path(__file__).resolve().parents[3] / 'data/greyward-symbol.svg'
    if source.is_symlink() or source.stat().st_size > 65536:
        raise ValueError('Invalid startup emblem')
    svg = ET.fromstring(source.read_bytes())
    ns = '{http://www.w3.org/2000/svg}'
    if svg.tag != ns + 'svg' or svg.get('viewBox') != '0 0 1024 1024':
        raise ValueError('Unsupported startup emblem geometry')
    def color(value, opacity=1):
        value = '#FFFFFF' if value == 'white' else value
        if not re.fullmatch(r'#[0-9a-fA-F]{6}', value) or not 0 <= opacity <= 1:
            raise ValueError('Unsupported startup emblem paint')
        rgb = [int(value[i:i + 2], 16) / 255 for i in (1, 3, 5)]
        return 'Qt.rgba(' + ', '.join(map(str, [*rgb, opacity])) + ')'
    gradients = {}
    for defs in svg.findall(ns + 'defs'):
        for gradient in defs:
            if (gradient.tag != ns + 'linearGradient'
                    or gradient.get('id') != 'gradient_0' or gradients
                    or gradient.get('gradientUnits') != 'userSpaceOnUse'
                    or set(gradient.attrib) != {'id', 'gradientUnits', 'x1', 'y1', 'x2', 'y2'}):
                raise ValueError('Unsupported startup emblem gradient')
            coordinates = {key: float(gradient.get(key)) for key in ('x1', 'y1', 'x2', 'y2')}
            if not all(abs(value) <= 4096 for value in coordinates.values()) or not 2 <= len(gradient) <= 16:
                raise ValueError('Invalid startup emblem gradient')
            stops = []
            for stop in gradient:
                if stop.tag != ns + 'stop' or set(stop.attrib) != {'offset', 'stop-color', 'stop-opacity'}:
                    raise ValueError('Unsupported startup emblem gradient stop')
                position = float(stop.get('offset'))
                if not 0 <= position <= 1:
                    raise ValueError('Invalid startup emblem gradient stop')
                stops.append('GradientStop { position: ' + str(position) + '; color: '
                             + color(stop.get('stop-color'), float(stop.get('stop-opacity'))) + ' }')
            gradients['url(#gradient_0)'] = 'fillGradient: LinearGradient { ' + '; '.join(
                key + ': ' + str(value) for key, value in coordinates.items()) + '; ' + ' '.join(stops) + ' }'
    paths = []
    for child in svg:
        # Nonrendered metadata is omitted; local definitions are compiled above.
        if child.tag in {ns + 'metadata', ns + 'defs', ns + 'title', ns + 'desc'}:
            continue
        if (child.tag != ns + 'path' or not {'d', 'fill'}.issubset(child.attrib)
                or set(child.attrib) - {'d', 'fill', 'fill-opacity'}):
            raise ValueError('Unsupported startup emblem paint')
        opacity = float(child.get('fill-opacity', '1'))
        if not 0 <= opacity <= 1:
            raise ValueError('Invalid startup emblem opacity')
        fill = child.get('fill')
        paint = gradients.get(fill) or 'fillColor: ' + color(fill, opacity)
        if fill in gradients and opacity != 1:
            raise ValueError('Unsupported startup gradient opacity')
        paths.append('                ShapePath { strokeColor: "transparent"; ' + paint
                     + '\n                    PathSvg { path: ' + json.dumps(child.attrib['d']) + ' } }')
    if not paths:
        raise ValueError('Empty startup emblem')
    emblem = '''            Shape {
                objectName: "greywardStartupEmblem"
                width: 1024; height: 1024
                scale: parent.width / 512
                x: -256 * scale; y: -192 * scale
                transformOrigin: Item.TopLeft
                asynchronous: false
                preferredRendererType: Shape.GeometryRenderer
@PATHS@
            }'''.replace('@PATHS@', '\n'.join(paths))
    return STARTUP_CONTENT.replace('@STARTUP_EMBLEM@', emblem)


def authorization_emblem():
    """Compile the package-owned SVG into synchronous Qt Quick geometry.

    Image/data-URL loading can require a worker unavailable in the protected
    runtime. Retain the exact canonical paths without an image loader or an
    ordinary icon theme. Refuse new SVG features until explicitly reviewed.
    """
    source = Path(__file__).with_name('greyward-security-status.svg')
    if not source.exists():
        source = Path(__file__).resolve().parents[3] / 'data/greyward-security-status.svg'
    if source.is_symlink() or source.stat().st_size > 65536:
        raise ValueError('Invalid protected authorization emblem')
    svg = ET.fromstring(source.read_bytes())
    ns = '{http://www.w3.org/2000/svg}'
    if svg.tag != ns + 'svg' or svg.get('viewBox') != '0 0 1024 1024':
        raise ValueError('Unsupported authorization emblem geometry')
    paths = []
    for child in svg:
        if child.tag in {ns + 'title', ns + 'desc'}:
            continue
        if (child.tag != ns + 'path' or set(child.attrib) != {'d', 'fill'}
                or not re.fullmatch(r'#[0-9a-fA-F]{6}', child.get('fill', ''))):
            raise ValueError('Unsupported authorization emblem paint')
        paths.append('            ShapePath { strokeColor: "transparent"; fillColor: '
            + json.dumps(child.attrib['fill']) + '; PathSvg { path: '
            + json.dumps(child.attrib['d']) + ' } }')
    if not paths:
        raise ValueError('Empty authorization emblem')
    return '''Item {
    width: 48; height: 48
    Shape {
        objectName: "greywardAuthorizationEmblem"
        width: 1024; height: 1024
        scale: parent.width / width
        transformOrigin: Item.TopLeft
        asynchronous: false
        preferredRendererType: Shape.GeometryRenderer
@PATHS@
    }
}'''.replace('@PATHS@', '\n'.join(paths))


def authorization_card(native=False, mirror=False):
    """One Obsidian/Platinum layout for the protected input and mirror outputs.

    The mirror receives only a masked length and routes actions to the owner.
    Colors follow branding/source/greyward-desktop-palette.json. No writable
    ordinary-shell theme or plugin is imported into the authentication surface.
    """
    field = '''
DankTextField {
    id: passwordField
    width: parent.width
    height: 64
    radius: 12
    cornerRadius: 12
    backgroundColor: "#101214"
    focusedBorderColor: "#E1E7EC"
    normalBorderColor: passwordCharacterCount > 0 ? "#E1E7EC" : "#485560"
    borderWidth: 1
    focusedBorderWidth: 2
    labelText: root.currentFlow?.inputPrompt ?? I18n.tr("Password")
    placeholderText: I18n.tr("Enter your password")
    hidePlaceholderOnFocus: false
    leftIconName: "lock"
    leftIconSize: 19
    leftIconColor: "#C5DBE8"
    leftIconFocusedColor: "#C5DBE8"
    font.pixelSize: Theme.fontSizeMedium
    textColor: "#F2F5F7"
    text: root.passwordInput
    showPasswordToggle: false
    echoMode: (root.currentFlow?.responseVisible ?? false) || passwordVisible ? TextInput.Normal : TextInput.Password
    enabled: !root.isLoading
    opacity: enabled ? 1 : 0.5
    onActiveFocusChanged: if (activeFocus) authorizationViewport.contentY = Math.max(0, y - 8)
    onTextEdited: root.passwordInput = text
    onAccepted: root.submitAuth()
}

'''
    if mirror:
        field = '''
Rectangle {
    id: mirroredPasswordField
    width: parent.width
    height: 64
    radius: 12
    color: "#101214"
    border.color: root.authorizationPasswordLength > 0 ? "#E1E7EC" : "#485560"
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
            color: "#C5DBE8"
        }

        Column {
            width: parent.width - 40
            anchors.verticalCenter: parent.verticalCenter
            spacing: 3

            StyledText {
                width: parent.width
                text: root.authorizationController?.currentFlow?.inputPrompt ?? I18n.tr("Password")
                elide: Text.ElideRight
                font.pixelSize: Theme.fontSizeSmall - 2
                font.weight: Font.DemiBold
                font.letterSpacing: 1
                color: "#9EACB7"
            }

            StyledText {
                width: mirroredPasswordField.width - 90
                text: root.authorizationPasswordLength > 0
                    ? "\\u2022".repeat(root.authorizationPasswordLength)
                    : I18n.tr("Enter your password")
                font.pixelSize: Theme.fontSizeMedium
                font.weight: Font.Medium
                color: "#F2F5F7"
                maximumLineCount: 1
                elide: Text.ElideRight
            }
        }
    }

    MouseArea {
        anchors.fill: parent
        cursorShape: Qt.IBeamCursor
        enabled: !(root.authorizationController?.isLoading ?? false)
        onClicked: root.authorizationController?.focusPasswordField()
    }
}

'''
    flow = 'PolkitService.agent?.flow' if mirror else 'root.currentFlow'
    controller = 'root.authorizationController?' if mirror else 'root'
    # Cancellation belongs to the shared Polkit flow. A mirror must not depend
    # on the password field's Loader/controller being available to cancel it.
    cancel = 'PolkitService.agent?.flow?.cancelAuthenticationRequest()' if mirror else 'root.cancelAuth()'
    loading = '(root.authorizationController?.isLoading ?? false)' if mirror else 'root.isLoading'
    card = '''    Rectangle {
        id: authorizationCard
        objectName: "greywardAuthorizationCard"
        anchors.centerIn: parent
        width: Math.max(1, Math.min(640, parent.width))
        height: Math.max(1, Math.min(authorizationLayout.implicitHeight + 64, parent.height))
        radius: 20
        color: "#050607"
        border.color: "#34383B"
        border.width: 1
        clip: true

        // Short viewports scroll the whole form; long requests scroll inside
        // their own region. Actions remain reachable without truncating text.
        Flickable {
            id: authorizationViewport
            objectName: "greywardAuthorizationViewport"
            anchors.fill: parent
            anchors.margins: Math.min(32, Math.max(12, parent.width * 0.05))
            contentWidth: width
            contentHeight: authorizationLayout.implicitHeight
            boundsBehavior: Flickable.StopAtBounds
            clip: true

            Column {
                id: authorizationLayout
                width: parent.width
                spacing: 20

                Row {
                    width: parent.width
                    spacing: 14
@EMBLEM@
                    Column {
                        anchors.verticalCenter: parent.verticalCenter
                        spacing: 5
                        StyledText {
                            text: "GREYWARD"
                            font.pixelSize: Theme.fontSizeSmall
                            font.weight: Font.DemiBold
                            font.letterSpacing: 2
                            color: "#F2F5F7"
                        }
                        StyledText {
                            text: I18n.tr("Secure authorization")
                            font.pixelSize: Theme.fontSizeSmall
                            color: "#9EACB7"
                        }
                    }
                }
                Rectangle { width: parent.width; height: 1; color: "#292D30" }
                Column {
                    width: parent.width
                    spacing: 10
                    StyledText {
                        width: parent.width
                        text: I18n.tr("Authentication Required")
                        font.pixelSize: Theme.fontSizeLarge + 4
                        font.weight: Font.Medium
                        color: "#F2F5F7"
                        wrapMode: Text.Wrap
                    }
                    StyledText {
                        width: parent.width
                        text: I18n.tr("Confirm this request to continue.")
                        font.pixelSize: Theme.fontSizeSmall
                        color: "#BEC8D0"
                        wrapMode: Text.Wrap
                    }
                }
                Rectangle {
                    width: parent.width
                    height: Math.min(144, requestMessage.implicitHeight + 32)
                    radius: 12
                    color: "#16191C"
                    Flickable {
                        anchors.fill: parent
                        anchors.margins: 16
                        contentWidth: width
                        contentHeight: requestMessage.implicitHeight
                        boundsBehavior: Flickable.StopAtBounds
                        clip: true
                        StyledText {
                            id: requestMessage
                            objectName: "greywardAuthorizationMessage"
                            width: parent.width
                            text: @FLOW@?.message ?? ""
                            textFormat: Text.PlainText
                            font.pixelSize: Theme.fontSizeMedium
                            color: "#F2F5F7"
                            wrapMode: Text.Wrap
                        }
                    }
                }
@FIELD@
                StyledText {
                    width: parent.width
                    text: @FLOW@?.supplementaryMessage ?? ""
                    textFormat: Text.PlainText
                    font.pixelSize: Theme.fontSizeSmall
                    color: (@FLOW@?.supplementaryIsError ?? false) ? "#F4A59B" : "#BEC8D0"
                    wrapMode: Text.Wrap
                    visible: text.length > 0
                }
                StyledText {
                    width: parent.width
                    text: I18n.tr("Authentication failed - try again")
                    font.pixelSize: Theme.fontSizeSmall
                    color: "#F4A59B"
                    wrapMode: Text.Wrap
                    visible: PolkitService.authFailed
                    Accessible.role: Accessible.AlertMessage
                }
                Row {
                    width: parent.width
                    spacing: 12
                    Rectangle {
                        objectName: "greywardAuthorizationCancel"
                        width: Math.max(1, (parent.width - 12) * 0.4)
                        height: 46; radius: 12
                        color: cancelButton.containsMouse ? "#292D30" : "#16191C"
                        border.color: activeFocus ? "#E1E7EC" : "#485560"
                        border.width: activeFocus ? 2 : 1
                        enabled: !@LOADING@
                        opacity: enabled ? 1 : 0.5
                        activeFocusOnTab: true
                        onActiveFocusChanged: if (activeFocus) authorizationViewport.contentY = Math.max(0, authorizationLayout.height - authorizationViewport.height)
                        Accessible.role: Accessible.Button
                        Accessible.name: I18n.tr("Cancel")
                        Keys.onReturnPressed: @CANCEL@
                        Keys.onSpacePressed: @CANCEL@
                        StyledText {
                            anchors.centerIn: parent
                            text: I18n.tr("Cancel")
                            font.pixelSize: Theme.fontSizeSmall
                            font.weight: Font.Medium
                            color: "#F2F5F7"
                        }
                        MouseArea {
                            id: cancelButton
                            anchors.fill: parent
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            enabled: parent.enabled
                            onClicked: @CANCEL@
                        }
                    }
                    Rectangle {
                        objectName: "greywardAuthorizationSubmit"
                        width: Math.max(1, (parent.width - 12) * 0.6)
                        height: 46; radius: 12
                        color: authenticateButton.containsMouse ? "#F2F5F7" : "#DDE5EB"
                        border.color: "#83939F"
                        border.width: activeFocus ? 3 : 0
                        enabled: !@LOADING@
                        opacity: enabled ? 1 : 0.6
                        activeFocusOnTab: true
                        onActiveFocusChanged: if (activeFocus) authorizationViewport.contentY = Math.max(0, authorizationLayout.height - authorizationViewport.height)
                        Accessible.role: Accessible.Button
                        Accessible.name: I18n.tr("Authenticate")
                        Keys.onReturnPressed: @CONTROLLER@.submitAuth()
                        Keys.onSpacePressed: @CONTROLLER@.submitAuth()
                        StyledText {
                            anchors.centerIn: parent
                            text: @LOADING@ ? I18n.tr("Authenticating…") : I18n.tr("Authenticate")
                            font.pixelSize: Theme.fontSizeSmall
                            font.weight: Font.DemiBold
                            color: "#08090A"
                        }
                        MouseArea {
                            id: authenticateButton
                            anchors.fill: parent
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            enabled: parent.enabled
                            onClicked: @CONTROLLER@.submitAuth()
                        }
                    }
                }
            }
        }
    }
'''
    card = card.replace('@FIELD@', textwrap.indent(field, '                '))
    card = card.replace('@EMBLEM@', textwrap.indent(authorization_emblem(), '                    '))
    card = card.replace('@FLOW@', flow).replace('@CONTROLLER@', controller).replace('@LOADING@', loading)
    card = card.replace('@CANCEL@', cancel)
    if mirror:
        card = card.replace('id: authorizationCard', 'id: remoteAuthorizationCard', 1)
        card = card.replace('Math.min(640, parent.width)', 'Math.min(640, parent.width - 48)', 1)
        card = card.replace('authorizationLayout.implicitHeight + 64, parent.height)',
                            'authorizationLayout.implicitHeight + 64, parent.height - 48)', 1)
        card = card.replace('        clip: true', '        clip: true\n'
            '        visible: sessionLock.secure && root.authorizationActive && lockSurface.screen?.name !== root.authorizationScreenName', 1)
    if native:
        card = card.replace('DankTextField {', 'DTextField {').replace('DankIcon {', 'DIcon {')
    return card


def branded_authorization_content_v2(text):
    # 2.0's DDialog owns window-style actions. The protected shell owns the
    # native session-lock surface instead, retaining upstream flow/PAM handling.
    text = replace_once(text, 'import QtQuick\n', 'import QtQuick\nimport QtQuick.Shapes\n')
    text = replace_once(text, 'DDialog {', 'FocusScope {')
    text = replace_once(text, '    focus: true\n', '    focus: true\n'
                        '    Keys.onEscapePressed: if (!root.isLoading) root.cancelAuth()\n')
    text = replace_once(text, 'import qs.DCommon.Widgets\n',
                        'import qs.DCommon.Widgets\nimport qs.DCommon.Common\n')
    text = replace_once(text, '    property string passwordInput: ""\n',
                        '    property string passwordInput: ""\n'
                        '    readonly property int passwordCharacterCount: passwordInput.length\n')
    text = replace_region_once(text, '    title: I18n.tr("Authentication Required")\n',
                              '    function focusPasswordField()',
                              '    onCancelRequested: root.currentFlow?.cancelAuthenticationRequest()\n\n')
    text = replace_once(text, '            passwordField.forceActiveFocus();\n',
                        '            if (!root.isLoading) passwordField.forceActiveFocus();\n')
    # The exact whole-file hash gates this presentation-only replacement.
    marker = '    StyledText {\n        text: root.currentFlow?.supplementaryMessage'
    if text.count(marker) != 1:
        raise ValueError('Authentication 2.0 presentation changed')
    return text[:text.index(marker)] + authorization_card(native=True) + '}\n'

def protected_authorization(text, native=False):
    """Use the native session-lock surface for both password-bearing flows.

    Ordinary clients may keep layer-shell chrome, so a floating Polkit window
    cannot establish exclusive input. Completion releases only a lock acquired
    for this challenge; it never releases a pre-existing native session lock.
    """
    text = replace_once(text, "import qs.Services\n", "import qs.Services\nimport QtQuick.Window\nimport QtQuick.Shapes\nimport qs.Modals\nimport qs.Widgets\n")
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
            // Clear the previous owner before screen bindings can synchronously
            // construct the new Loader and publish its controller in onLoaded.
            authorizationController = null;
            // Keep one protected password-entry control for the Polkit
            // challenge; every output mirrors only its masked character count.
            authorizationScreenName = Quickshell.screens?.[0]?.name ?? "";
            authorizationWasLocked = shouldLock;
            authorizationPending = true;
            sharedPasswordBuffer = "";
            authorizationPasswordLength = 0;
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
                width: Math.max(1, Math.min(640, parent.width - 48))
                height: Math.max(1, parent.height - 48)
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
    old_surface = '''            LockSurface {
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
'''
    new_surface = '''            Loader {
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
'''
    if native:
        old_surface = replace_once(old_surface, '                screenName:', '                inputRevealed: root.inputRevealed\n                onInputRevealRequested: revealed => root.inputRevealed = revealed\n                screenName:')
        new_surface = replace_once(new_surface, '                    screenName:', '                    inputRevealed: root.inputRevealed\n                    onInputRevealRequested: revealed => root.inputRevealed = revealed\n                    screenName:')
    text = replace_once(text, old_surface, new_surface)
    remote_card = textwrap.indent(authorization_card(native=native, mirror=True), '        ')
    text = replace_region_once(
        text,
        '            Rectangle {\n                id: remoteAuthorizationCard\n',
        '\n            Connections {\n                target: sessionLock',
        remote_card + '\n')
    if native:
        text = text.replace('import qs.Widgets\n', 'import qs.DCommon.Widgets\n').replace('DankIcon {', 'DIcon {')
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


def protected_native_settings(text):
    """Read the single immutable profile without threaded config.d discovery.

    The ordinary shell keeps upstream's extensible loader. Authentication has
    one root-prepared settings file; a folder worker must not leave its settings
    stage Discovering forever or silently retain upstream wallpaper/PAM defaults.
    """
    text = replace_once(text, '            blockLoading: false\n            blockWrites: true',
                        '            blockLoading: true\n            blockWrites: true')
    text = replace_once(text, '            watchChanges: !isGreeterMode\n',
                        '            watchChanges: false\n')
    text = replace_once(text, '    property bool _settingsFolderChecked: isGreeterMode\n',
                        '    property bool _settingsFolderChecked: true\n')
    return replace_once(text, '        id: settingsFolderLoader\n        active: !isGreeterMode\n',
                        '        id: settingsFolderLoader\n        active: false\n')


def protected_native_theme(text):
    return replace_once(text, '        id: customThemeFileView\n        blockLoading: false\n'
                        '        watchChanges: currentTheme === "custom"\n',
                        '        id: customThemeFileView\n        blockLoading: true\n'
                        '        watchChanges: false\n')


def protected_native_background(text):
    # The protected session uses Qt's software renderer. A GPU MultiEffect layer
    # can be black even when its Image reports Ready; retain the native image
    # and scrim directly on software, with upstream effects on capable renderers.
    text = replace_once(text, 'import QtQuick\n', 'import QtQuick\nimport QtQuick.Window\n')
    return replace_once(text, '        layer.enabled: true\n',
                        '        layer.enabled: GraphicsInfo.api !== GraphicsInfo.Software\n')


def assemble(source, release_receipt, output):
    source, output = Path(source), Path(output)
    if source.is_symlink() or Path(release_receipt).is_symlink():
        raise ValueError("Alias source/receipt is not supported")
    release = json.loads(Path(release_receipt).read_text(encoding="utf-8"))
    files, digest = receipt(source)
    if release.get("schema") != "greyward.dms-release/v1" or release.get("releaseId") not in (SUPPORTED_RELEASES | CANDIDATE_RELEASES) or release.get("shellFiles") != files or release.get("shell", {}).get("sha256") != digest:
        raise ValueError("Matched DMS package shell/receipt required")
    native = release.get("releaseId") in CANDIDATE_RELEASES
    pins = CANDIDATE_PREIMAGES if native else PREIMAGES
    if any(files.get(name) != digest for name, digest in pins.items()):
        raise ValueError("Authentication source changed; review and tests required")
    if output.exists() or source.resolve() in output.resolve().parents:
        raise ValueError("New independent output required")
    # Perform all structure checks before creating output.
    lock = protected_authorization(restricted_lock((source / "Modules/Lock/Lock.qml").read_text(encoding="utf-8")), native=native)
    pam = restricted_pam((source / "Modules/Lock/Pam.qml").read_text(encoding="utf-8"))
    native_inputs = {}
    if native:
        native_inputs = {name: transform((source / name).read_text(encoding='utf-8'))
            for name, transform in [('Common/SettingsData.qml', protected_native_settings),
                                    ('Common/Theme.qml', protected_native_theme),
                                    ('Modules/Lock/LockScreenBackground.qml', protected_native_background)]}
    shutil.copytree(source, output / "shell")
    content_adapter = branded_authorization_content_v2 if native else branded_authorization_content
    authorization_content = content_adapter(
        (source / "Modals/PolkitAuthContent.qml").read_text(encoding="utf-8"))
    shell = SHELL.replace("qs.DankCommon.Common", "qs.DCommon.Common").replace("AppId com.danklinux.dms", "AppId systems.mantis.greyward.authentication") if native else SHELL
    for name, text in {"shell.qml": shell, "Modules/Lock/Lock.qml": lock,
                       "Modules/Lock/Pam.qml": pam,
                       "Modals/PolkitAuthContent.qml": authorization_content}.items():
        (output / "shell" / name).write_bytes(text.encode())
    if native:
        (output / "shell/Services/PluginService.qml").write_bytes(NO_PLUGINS.encode())
        for name, content in native_inputs.items():
            (output / 'shell' / name).write_bytes(content.encode())
    startup = output / "shell/startup"
    startup.mkdir()
    (startup / "shell.qml").write_bytes(STARTUP_SHELL.encode())
    visual = startup_content().encode()
    (output / "shell/GreywardStartup.qml").write_bytes(visual)
    (startup / "GreywardStartup.qml").write_bytes(visual)
    generated, digest = receipt(output / "shell")
    result = {"schema": "greyward.authentication-shell/v1", "sourceRelease": release["releaseId"],
              "sourceDigest": release["shell"]["sha256"], "shellDigest": digest,
              "shellFiles": generated, "status": "experimental-unactivated", "coverage": "UNKNOWN"}
    if native:
        # Assembly is not acceptance. Retain the explicit trial classification
        # and incomplete physical gates from the matched ordinary receipt.
        result["activation"] = dict(release.get("activation", {"eligible": False,
            "pending": ["protected-input-and-session-acceptance"]}))
        if "acceptance" in release:
            result["acceptance"] = dict(release["acceptance"])
        result["restrictions"] = {"ordinaryPlugins": False, "customPam": False, "externalLocker": False, "clipboardCollector": False}
    (output / "authentication.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ["source", "receipt", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    options = parser.parse_args()
    assemble(options.source, options.receipt, options.output)
