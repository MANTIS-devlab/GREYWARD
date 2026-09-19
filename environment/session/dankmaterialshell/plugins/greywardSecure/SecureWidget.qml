import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Wayland
import qs.Common
import qs.Services
import qs.Widgets
import qs.Modules.Plugins

PluginComponent {
    id: root
    layerNamespacePlugin: "greyward-secure"
    readonly property string busName: "systems.mantis.greyward.SecurityContext1"
    readonly property string objectPath: "/systems/mantis/greyward/SecurityContext1"
    // The shell projection itself has a 30-second bounded freshness lease.
    // Do not place recovery on the same edge: a missed D-Bus signal previously
    // made the pill discard its live content before the fallback read returned.
    readonly property int capsuleWatchdogIntervalMs: 15000
    readonly property int flyoutWidth: Math.min(400, Math.max(280, Number(parentScreen?.width || 432) - 32))
    readonly property int flyoutHeightLimit: Math.max(180, Math.min(660, Number(parentScreen?.height || 756) - 96))
    property var presentation: ({items: [], activity: [], details: []})
    property bool requestPending: false
    property int requestGeneration: 0
    property string subscriptionId: ""
    property bool initialized: false
    property var previousIds: []
    property string attentionId: ""
    property bool detailsOpen: false
    property bool activityOpen: false
    property bool otherItemsOpen: false
    property bool profileMenuOpen: false
    property bool actionPending: false
    property string actionMessage: ""
    property double clockNow: Date.now()
    readonly property bool reducedMotion: SettingsData.animationSpeed === SettingsData.AnimationSpeed.None
    readonly property bool freshnessLeaseValid: initialized && Date.parse(presentation.fresh_until || "") > clockNow
    // Keep an already-confirmed snapshot visible during its replacement
    // request. This closes the expiry/readback gap without treating stale
    // evidence as actionable: `fresh` remains the control authority.
    readonly property bool fresh: freshnessLeaseValid
    readonly property bool showingSnapshot: fresh || requestPending
    readonly property var items: showingSnapshot ? presentation.items || [] : []
    readonly property var activities: showingSnapshot ? presentation.activity || [] : []
    readonly property var primaryItem: items.length ? items[0] : null
    readonly property string statusLabel: fresh ? presentation.label || qsTr("Status unavailable") : initialized ? qsTr("Status unavailable") : qsTr("Connecting")
    readonly property string statusReason: fresh ? presentation.reason || "" : initialized ? qsTr("Current security status cannot be confirmed") : qsTr("Reading security status")
    readonly property color accent: !fresh ? "#aebbc4" : presentation.severity === "CRITICAL" ? "#eeaaa7" : ["ACTION", "WARNING"].includes(presentation.severity) ? "#e5c084" : "#c5d4de"
    readonly property var liveIcons: {
        const result = []; const seen = {};
        for (const item of activities) {
            if (seen[item.kind]) continue;
            seen[item.kind] = true;
            result.push({kind: item.kind, icon: item.icon, title: item.title});
        }
        return result;
    }
    readonly property bool hasAttention: fresh && attentionId !== "" && items.some(item => item.id === attentionId)
    readonly property string attentionLabel: primaryItem?.kind === "usb" ? qsTr("Device approval") : primaryItem?.severity === "CRITICAL" ? qsTr("Threat detected") : qsTr("Review needed")
    readonly property string accessibleSummary: qsTr("Security Center: %1").arg(statusLabel) + (activities.length ? ". " + activities.map(item => item.title).join(", ") : "")

    function decodeGdbusJson(stdout) {
        const match = String(stdout || "").trim().match(/^\(\s*'([\s\S]*)'\s*,\s*\)$/);
        if (!match) return null;
        try { return JSON.parse(match[1].replace(/\\'/g, "'").replace(/\\\\/g, "\\")); } catch (error) { return null; }
    }
    function variantString(value) { return '"' + String(value).replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"'; }
    function call(method, args, callback) {
        Proc.runCommand("greywardSecure." + method, ["/usr/bin/gdbus", "call", "--session", "--timeout", "6", "--dest", busName, "--object-path", objectPath, "--method", busName + "." + method].concat(args || []), function(stdout, code) {
            callback(code === 0 ? decodeGdbusJson(stdout) : null);
        });
    }
    function refreshSummary() {
        if (requestPending) return;
        requestPending = true;
        const generation = ++requestGeneration;
        requestTimeout.restart();
        call("GetShellPresentation", [], function(next) {
            if (generation !== requestGeneration) return;
            requestTimeout.stop(); requestPending = false; clockNow = Date.now();
            if (!next || next.schema !== "greyward.security.experience/v1") return;
            const nextFreshUntil = Date.parse(next.fresh_until || "");
            const ids = (next.items || []).filter(item => item.severity !== "INFO").map(item => item.id);
            const newItem = ids.find(id => previousIds.indexOf(id) < 0);
            if (initialized && newItem && (!primaryItem || next.items[0]?.id === newItem)) {
                attentionId = newItem; attentionTimer.restart();
            }
            previousIds = ids;
            presentation = next; initialized = Number.isFinite(nextFreshUntil);
            const result = (next.operations || []).find(op => op.state === "COMPLETE");
            if (result) { actionMessage = result.detail; messageTimer.restart(); }
        });
    }
    function subscribe() {
        if (subscriptionId || !DMSService.isConnected || typeof DMSService.dbusSubscribe !== "function") return;
        DMSService.dbusSubscribe("session", busName, objectPath, busName, "ShellSummaryChanged", function(response) {
            if (response?.result?.subscriptionId) subscriptionId = String(response.result.subscriptionId);
        });
    }
    function activateSecurityCenterWindow() {
        for (const window of (ToplevelManager?.toplevels?.values || [])) {
            if (String(window?.appId || "").toLowerCase().includes("greyward.securitycenter") && typeof window.activate === "function") { window.activate(); return; }
        }
    }
    function openRoute(route) {
        activateSecurityCenterWindow();
        Quickshell.execDetached(["/usr/bin/greyward-security-center-route", route || "overview"]);
    }
    function openSecurityCenter() { activateSecurityCenterWindow(); Quickshell.execDetached(["/usr/bin/greyward-security-center-launch"]); }
    function runAction(item, action) {
        if (!freshnessLeaseValid || actionPending) return;
        actionPending = true;
        actionTimeout.restart();
        const finish = function(result) {
            actionTimeout.stop();
            actionPending = false;
            actionMessage = result?.ok ? result.state === "PENDING" ? qsTr("Waiting for authorization…") : qsTr("Done") : result?.detail || qsTr("The action could not be completed. Check Security Center.");
            messageTimer.restart(); refreshSummary();
        };
        if (action.id === "trust_once" || action.id === "trust_always")
            call("RequestUsbTrust", [variantString(item.connection_ref), variantString(action.id === "trust_once" ? "once" : "always")], finish);
        else if (action.id === "clear_clipboard") call("ClearClipboard", [variantString(item.id)], finish);
        else { actionPending = false; actionTimeout.stop(); }
    }
    function setPrivacyProfile(profile) {
        if (!freshnessLeaseValid || actionPending || !presentation.capabilities?.privacy_profile_change) return;
        actionPending = true;
        actionTimeout.restart();
        call("SetPrivacyProfile", [variantString(profile)], function(result) {
            actionTimeout.stop();
            actionPending = false; profileMenuOpen = false;
            actionMessage = result?.ok && result.profile === profile ? qsTr("Privacy profile applied") : qsTr("Privacy profile could not be applied");
            messageTimer.restart(); refreshSummary();
        });
    }
    Timer { id: requestTimeout; interval: 7000; onTriggered: { ++root.requestGeneration; root.requestPending = false; root.clockNow = Date.now(); } }
    Timer { id: actionTimeout; interval: 7000; onTriggered: { root.actionPending = false; root.actionMessage = qsTr("The result is not confirmed. Check Security Center before retrying."); messageTimer.restart(); root.refreshSummary(); } }
    Timer { id: attentionTimer; interval: 10000; onTriggered: root.attentionId = "" }
    Timer { id: messageTimer; interval: 5000; onTriggered: root.actionMessage = "" }
    Timer { interval: 1000; running: true; repeat: true; onTriggered: root.clockNow = Date.now() }
    Timer { interval: root.capsuleWatchdogIntervalMs; running: true; repeat: true; onTriggered: { root.subscribe(); root.refreshSummary(); } }
    Connections {
        target: DMSService
        function onDbusSignalReceived(id, data) { if (String(id) === root.subscriptionId) root.refreshSummary(); }
        function onConnectionStateChanged() {
            if (!DMSService.isConnected) root.subscriptionId = "";
            else { root.subscribe(); root.refreshSummary(); }
        }
    }
    Component.onCompleted: { subscribe(); refreshSummary(); }
    Component.onDestruction: { if (subscriptionId && DMSService.isConnected) DMSService.dbusUnsubscribe(subscriptionId); }
    pillRightClickAction: root.openSecurityCenter

    component SecurityButton: Button {
    id: control
    property bool primary: false
    implicitHeight: 34
    height: 34
    Layout.minimumHeight: 34
    topInset: 0
    bottomInset: 0
    leftInset: 0
    rightInset: 0
    implicitWidth: label.implicitWidth + 24
    padding: 8
    hoverEnabled: true
    focusPolicy: Qt.StrongFocus
    Accessible.name: text
    contentItem: Text {
        id: label
        text: control.text
        font.family: "Inter"
        font.pixelSize: 13
        font.weight: control.primary ? Font.DemiBold : Font.Medium
        color: !control.enabled ? "#707d87" : control.primary ? "#182027" : "#e0e6eb"
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
    }
    background: Rectangle {
        radius: 8
        color: control.down ? "#788893" : control.primary ? (control.hovered ? "#f0f3f5" : "#cad5dd") : control.hovered ? "#35424c" : "#27323b"
        border.width: control.visualFocus ? 2 : 1
        border.color: control.visualFocus ? "#f3f6f8" : control.primary ? "#d8e1e7" : "#485560"
        opacity: control.enabled ? 1 : 0.55
        Behavior on color { ColorAnimation { duration: root.reducedMotion ? 0 : 120 } }
    }
}

    component CompactStatus: Rectangle {
        property bool vertical: false
        implicitWidth: vertical ? 36 : 36 + Math.min(root.liveIcons.length, 2) * 22 + (root.liveIcons.length > 2 ? 23 : 0) + (root.hasAttention ? 112 : 0)
        implicitHeight: 32
        width: implicitWidth; height: implicitHeight; radius: 10
        color: compactHover.hovered ? "#303b45" : "#20282f"
        border.width: activeFocus ? 2 : 1; border.color: activeFocus ? "#f3f6f8" : compactHover.hovered ? "#91a0ab" : "#52606b"
        activeFocusOnTab: true
        Keys.onReturnPressed: root.triggerPopout()
        Keys.onSpacePressed: root.triggerPopout()
        Accessible.role: Accessible.Button
        Accessible.name: root.accessibleSummary
        Accessible.onPressAction: root.triggerPopout()
        HoverHandler { id: compactHover }
        Behavior on implicitWidth { NumberAnimation { duration: root.reducedMotion ? 0 : 200; easing.type: Easing.OutCubic } }
        Row {
            anchors.centerIn: parent; spacing: 4
            Image { source: Quickshell.iconPath("greyward-security-status"); width: 22; height: 22; sourceSize: Qt.size(44,44); anchors.verticalCenter: parent.verticalCenter }
            Repeater { model: vertical ? [] : root.liveIcons.slice(0,2); delegate: DankIcon { required property var modelData; name: modelData.icon; size: 17; color: modelData.kind === "camera" || modelData.kind === "microphone" ? "#acd8c4" : "#bcc9d2"; anchors.verticalCenter: parent.verticalCenter } }
            Text { visible: !vertical && root.liveIcons.length > 2; text: "+" + (root.liveIcons.length - 2); color: "#c8d2d9"; font.pixelSize: 11; anchors.verticalCenter: parent.verticalCenter }
            Text { visible: !vertical && root.hasAttention; width: visible ? 108 : 0; text: root.attentionLabel; color: root.accent; font.family: "Inter"; font.pixelSize: 12; elide: Text.ElideRight; anchors.verticalCenter: parent.verticalCenter }
        }
        Rectangle {
            visible: root.fresh && ["CRITICAL", "ACTION", "WARNING"].includes(root.presentation.severity)
            anchors.right: parent.right; anchors.top: parent.top; anchors.margins: -2
            width: 12; height: 12; radius: 6; color: root.accent
            Text { anchors.centerIn: parent; text: "!"; color: "#1c252c"; font.pixelSize: 10; font.bold: true }
        }
    }
    horizontalBarPill: Component { CompactStatus {} }
    verticalBarPill: Component { CompactStatus { vertical: true } }
    popoutWidth: root.flyoutWidth
    popoutHeight: 0
    popoutContent: Component {
        Rectangle {
            width: root.flyoutWidth - Theme.spacingXL * 2
            implicitHeight: Math.min(content.implicitHeight + 32, root.flyoutHeightLimit)
            height: implicitHeight
            color: "#1b232a"; radius: 14; border.width: 1; border.color: "#586571"
            ScrollView {
                anchors.fill: parent; anchors.margins: 16; clip: true
                contentWidth: availableWidth
                ColumnLayout {
                    id: content
                    width: parent.width; spacing: 12
                    RowLayout {
                        Layout.fillWidth: true; spacing: 12
                        Image { source: Quickshell.iconPath("greyward-security-status"); sourceSize: Qt.size(72,72); Layout.preferredWidth: 36; Layout.preferredHeight: 36 }
                        ColumnLayout {
                            Layout.fillWidth: true; spacing: 3
                            Text { text: qsTr("Security Center"); color: "#aebbc5"; font.family: "Inter"; font.pixelSize: 12 }
                            Text { text: root.statusLabel; color: root.accent; font.family: "Inter"; font.pixelSize: 16; font.weight: Font.DemiBold; Layout.fillWidth: true; wrapMode: Text.Wrap }
                        }
                    }
                    Text { text: root.statusReason; color: "#b6c2cb"; font.family: "Inter"; font.pixelSize: 13; Layout.fillWidth: true; wrapMode: Text.Wrap }
                    Repeater {
                        model: root.otherItemsOpen ? root.items : root.items.slice(0,1)
                        delegate: Rectangle {
                            id: eventCard
                            required property var modelData
                            Layout.fillWidth: true
                            implicitHeight: eventBody.implicitHeight + 24
                            radius: 10; color: modelData.severity === "CRITICAL" ? "#35282b" : "#28323a"
                            border.width: 1; border.color: modelData.severity === "CRITICAL" ? "#986968" : "#657078"
                            ColumnLayout {
                                id: eventBody
                                anchors.fill: parent; anchors.margins: 12; spacing: 8
                                Text { text: eventCard.modelData.title; color: "#edf1f4"; font.family: "Inter"; font.pixelSize: 14; font.weight: Font.DemiBold; Layout.fillWidth: true; wrapMode: Text.Wrap }
                                Text { text: eventCard.modelData.detail; color: "#c2cbd2"; font.family: "Inter"; font.pixelSize: 13; Layout.fillWidth: true; wrapMode: Text.Wrap }
                                Flow {
                                    Layout.fillWidth: true; Layout.preferredHeight: childrenRect.height; spacing: 8
                                    Repeater {
                                        model: eventCard.modelData.actions || []
                                        delegate: SecurityButton {
                                            required property var modelData
                                            text: modelData.label; primary: modelData.id === "trust_once" || modelData.id === "clear_clipboard"
                                            enabled: root.fresh && !root.actionPending
                                            onClicked: root.runAction(eventCard.modelData, modelData)
                                        }
                                    }
                                    SecurityButton { text: qsTr("Review"); visible: !(eventCard.modelData.actions || []).length && !["PENDING","VERIFYING","INDETERMINATE"].includes(eventCard.modelData.operation); onClicked: root.openRoute(eventCard.modelData.route) }
                                }
                            }
                        }
                    }
                    SecurityButton { visible: root.items.length > 1; text: root.otherItemsOpen ? qsTr("Show less") : qsTr("%1 more items").arg(root.items.length - 1); onClicked: root.otherItemsOpen = !root.otherItemsOpen }
                    Rectangle { visible: root.activities.length > 0; Layout.fillWidth: true; height: 1; color: "#3c4852" }
                    Text { visible: root.activities.length > 0; text: qsTr("Live activity"); color: "#aebdc7"; font.family: "Inter"; font.pixelSize: 12; font.weight: Font.Medium }
                    Repeater {
                        model: root.activityOpen ? root.activities : root.activities.slice(0,3)
                        delegate: Item {
                            required property var modelData
                            Layout.fillWidth: true; implicitHeight: Math.max(40, activityText.implicitHeight + 8)
                            RowLayout {
                                anchors.fill: parent; spacing: 10
                                DankIcon { name: modelData.icon; size: 18; color: modelData.kind === "microphone" || modelData.kind === "camera" ? "#acd8c4" : "#b7c5d0" }
                                ColumnLayout {
                                    id: activityText; Layout.fillWidth: true; spacing: 2
                                    Text { text: modelData.title; color: "#dfe6eb"; font.pixelSize: 13; font.family: "Inter"; elide: Text.ElideRight; Layout.fillWidth: true }
                                    Text { text: modelData.detail; color: "#a7b5c0"; font.pixelSize: 12; font.family: "Inter"; wrapMode: Text.Wrap; Layout.fillWidth: true }
                                }
                                SecurityButton { text: qsTr("View"); onClicked: root.openRoute(modelData.route) }
                            }
                        }
                    }
                    SecurityButton { visible: root.activities.length > 3; text: root.activityOpen ? qsTr("Show less activity") : qsTr("All activity (%1)").arg(root.activities.length); onClicked: root.activityOpen = !root.activityOpen }
                    SecurityButton { text: root.detailsOpen ? qsTr("Hide details") : qsTr("Protection details"); onClicked: root.detailsOpen = !root.detailsOpen }
                    ColumnLayout {
                        visible: root.detailsOpen; Layout.fillWidth: true; spacing: 8
                        Repeater { model: root.presentation.details || []; delegate: RowLayout {
                            required property var modelData
                            Layout.fillWidth: true
                            Text { text: modelData.label; color: "#aebbc5"; font.family: "Inter"; font.pixelSize: 12; Layout.fillWidth: true }
                            Text { text: root.fresh ? modelData.value : qsTr("Unavailable"); color: "#e0e6eb"; font.family: "Inter"; font.pixelSize: 12 }
                        } }
                        SecurityButton { visible: root.fresh && root.presentation.capabilities?.privacy_profile_change === true; text: qsTr("Change privacy profile"); onClicked: root.profileMenuOpen = !root.profileMenuOpen }
                        Flow { visible: root.profileMenuOpen && root.fresh; Layout.fillWidth: true; Layout.preferredHeight: childrenRect.height; spacing: 8
                            Repeater { model: ["STANDARD", "PRIVATE", "TRAVEL"]; delegate: SecurityButton { required property string modelData; text: modelData.charAt(0) + modelData.slice(1).toLowerCase(); enabled: !root.actionPending; onClicked: root.setPrivacyProfile(modelData) } }
                        }
                        SecurityButton { text: qsTr("Refresh status"); enabled: !root.requestPending; onClicked: root.refreshSummary() }
                    }
                    Text { visible: root.actionMessage !== ""; text: root.actionMessage; color: "#cad9d2"; font.family: "Inter"; font.pixelSize: 13; wrapMode: Text.Wrap; Layout.fillWidth: true; Accessible.role: Accessible.StaticText; Accessible.name: text }
                    SecurityButton { text: qsTr("Open Security Center"); primary: true; Layout.fillWidth: true; onClicked: root.openSecurityCenter() }
                }
            }
        }
    }
}
