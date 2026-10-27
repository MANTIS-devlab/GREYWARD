import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Wayland
import qs.Common
import qs.Services
import qs.DCommon.Widgets
import qs.Modules.Plugins
import "StatusModel.js" as Status
import "StatePalette.js" as Palette

PluginComponent {
    id: root
    layerNamespacePlugin: "greyward-secure"
    readonly property var provider: pluginService?.pluginDaemonInstances?.[pluginId] ?? null
    readonly property int securityIconSize: root.iconSizeLarge + 4
    readonly property int flyoutWidth: Math.min(440, Math.max(280, Number(parentScreen?.width || 472) - 32))
    readonly property int flyoutHeightLimit: Math.max(180, Math.min(660, Number(parentScreen?.height || 756) - 96))
    property bool detailsOpen: false
    property bool activityOpen: false
    property bool otherItemsOpen: false
    property bool profileMenuOpen: false
    readonly property bool reducedMotion: SettingsData.reduceMotion || Theme.currentAnimationSpeed === SettingsData.AnimationSpeed.None
    readonly property var presentation: provider?.presentation ?? ({items: [], activity: [], details: []})
    readonly property bool requestPending: provider?.requestPending ?? false
    readonly property bool initialized: provider?.initialized ?? false
    readonly property string attentionId: provider?.attentionId ?? ""
    readonly property bool actionPending: provider?.actionPending ?? false
    readonly property string actionMessage: provider?.actionMessage ?? ""
    readonly property bool launchPending: provider?.launchPending ?? false
    readonly property string launchState: provider?.launchState ?? ""
    readonly property string launchMessage: provider?.launchMessage ?? ""
    readonly property double clockNow: provider?.clockNow ?? 0
    readonly property bool freshnessLeaseValid: initialized && Date.parse(presentation.fresh_until || "") > clockNow
    // Keep an already-confirmed snapshot visible during its replacement
    // request. This closes the expiry/readback gap without treating stale
    // evidence as actionable: `fresh` remains the control authority.
    readonly property bool fresh: freshnessLeaseValid
    // Confirmed unavailability has a display lease, never an action lease.
    readonly property bool displayFresh: initialized && Date.parse(presentation.display_fresh_until || presentation.fresh_until || "") > clockNow
    readonly property bool showingSnapshot: displayFresh || requestPending
    // Cards, badge and attention use the exact alert list that the server
    // passes to native desktop notifications. The main status remains live.
    readonly property var items: showingSnapshot ? presentation.notification_items || [] : []
    readonly property var activities: showingSnapshot ? presentation.activity || [] : []
    readonly property var primaryItem: items.length ? items[0] : null
    readonly property string statusLabel: !displayFresh ? initialized ? qsTr("Status unavailable") : qsTr("Connecting") : !fresh ? qsTr("Refreshing security status") : presentation.label || qsTr("Status unavailable")
    readonly property string statusReason: !displayFresh ? initialized ? qsTr("Current security status cannot be confirmed") : qsTr("Reading security status") : !fresh ? qsTr("The last confirmed status is shown. Actions are paused while GREYWARD refreshes it.") : presentation.reason || ""
    readonly property color accent: Palette.color(Status.protectionTone(presentation, fresh), Theme.isLightMode)
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

    function refreshSummary() { provider?.refreshSummary(); }
    function openRoute(route, resourceRef) { provider?.openRoute(route, resourceRef); }
    function openSecurityCenter() { provider?.openSecurityCenter(); }
    function runAction(item, action) { provider?.runAction(item, action); }
    function setPrivacyProfile(profile) { profileMenuOpen = false; provider?.setPrivacyProfile(profile); }

    pillRightClickAction: root.openSecurityCenter

    component SecurityButton: DButton {
        property bool primary: false
        textColor: primary ? Theme.onPrimary : Theme.surfaceText
        backgroundColor: primary ? Theme.primary : Theme.surfaceContainerHigh
        Accessible.name: text
    }
    component CompactStatus: Item {
        property bool vertical: false
        implicitWidth: statusRow.implicitWidth
        implicitHeight: root.securityIconSize
        width: implicitWidth; height: implicitHeight
        activeFocusOnTab: true
        Keys.onReturnPressed: root.triggerPopout()
        Keys.onSpacePressed: root.triggerPopout()
        Accessible.role: Accessible.Button
        Accessible.name: root.accessibleSummary
        Accessible.onPressAction: root.triggerPopout()
        Rectangle { anchors.fill: parent; radius: 8; color: "transparent"; border.width: parent.activeFocus ? 2 : 0; border.color: Theme.primary }
        Behavior on implicitWidth { NumberAnimation { duration: root.reducedMotion ? 0 : 200; easing.type: Easing.OutCubic } }
        Row {
            id: statusRow
            anchors.centerIn: parent; spacing: 4
            Item {
                width: root.securityIconSize; height: root.securityIconSize; anchors.verticalCenter: parent.verticalCenter
                Image { source: Quickshell.iconPath("greyward-security-status"); anchors.fill: parent; sourceSize: Qt.size(root.securityIconSize * 2, root.securityIconSize * 2) }
                Rectangle {
                    anchors.right: parent.right; anchors.bottom: parent.bottom
                    width: 6; height: 6; radius: 3; color: root.accent
                    border.width: 1; border.color: Theme.surfaceContainerHigh
                    Accessible.ignored: true
                }
            }
            Repeater { model: vertical ? [] : root.liveIcons.slice(0,2); delegate: DIcon { required property var modelData; name: modelData.icon; size: root.iconSize; color: modelData.kind === "camera" || modelData.kind === "microphone" ? Theme.primary : Theme.surfaceText; anchors.verticalCenter: parent.verticalCenter } }
            Text { visible: !vertical && root.liveIcons.length > 2; text: "+" + (root.liveIcons.length - 2); color: Theme.surfaceText; font.pixelSize: 11; anchors.verticalCenter: parent.verticalCenter }
            Text { visible: !vertical && root.hasAttention; width: visible ? 108 : 0; text: root.attentionLabel; color: root.accent; font.family: Theme.fontFamily; font.pixelSize: 12; elide: Text.ElideRight; anchors.verticalCenter: parent.verticalCenter }
        }
        Rectangle {
            visible: root.fresh && root.items.some(item => ["CRITICAL", "ACTION", "WARNING"].includes(item.severity))
            anchors.right: parent.right; anchors.top: parent.top; anchors.margins: -2
            width: 12; height: 12; radius: 6; color: root.accent
            Text { anchors.centerIn: parent; text: "!"; color: Theme.onPrimary; font.pixelSize: 10; font.bold: true }
        }
    }
    horizontalBarPill: Component { CompactStatus {} }
    verticalBarPill: Component { CompactStatus { vertical: true } }
    popoutWidth: root.flyoutWidth
    popoutHeight: 0
    popoutContent: Component {
        Rectangle {
            width: root.flyoutWidth - Theme.spacingXL * 2
            implicitHeight: Math.min(content.implicitHeight + 40, root.flyoutHeightLimit)
            height: implicitHeight
            color: Theme.surfaceContainer; radius: 14; border.width: 1; border.color: Theme.outlineVariant
            ScrollView {
                anchors.fill: parent; anchors.margins: 20; clip: true
                contentWidth: availableWidth
                ColumnLayout {
                    id: content
                    width: parent.width; spacing: 14
                    RowLayout {
                        Layout.fillWidth: true; spacing: 12
                        Image { source: Quickshell.iconPath("greyward-security-status"); sourceSize: Qt.size(88,88); Layout.preferredWidth: 44; Layout.preferredHeight: 44 }
                        ColumnLayout {
                            Layout.fillWidth: true; spacing: 3
                            Text { text: qsTr("Security Center"); color: Theme.surfaceVariantText; font.family: Theme.fontFamily; font.pixelSize: 12 }
                            Text { text: root.statusLabel; color: root.accent; font.family: Theme.fontFamily; font.pixelSize: 20; font.weight: Font.DemiBold; Layout.fillWidth: true; wrapMode: Text.Wrap }
                        }
                    }
                    Text { text: root.statusReason; color: Theme.surfaceVariantText; font.family: Theme.fontFamily; font.pixelSize: 13; Layout.fillWidth: true; wrapMode: Text.Wrap }
                    Repeater {
                        model: root.otherItemsOpen ? root.items : root.items.slice(0,1)
                        delegate: Rectangle {
                            id: eventCard
                            required property var modelData
                            Layout.fillWidth: true
                            implicitHeight: eventBody.implicitHeight + 24
                            radius: 12; color: modelData.severity === "CRITICAL" ? Theme.errorContainer : Theme.surfaceContainerHigh
                            border.width: 1; border.color: modelData.severity === "CRITICAL" ? Theme.error : Qt.alpha(root.accent, 0.30)
                            ColumnLayout {
                                id: eventBody
                                anchors.fill: parent; anchors.margins: 12; spacing: 8
                                Text { text: eventCard.modelData.title; color: Theme.surfaceText; font.family: Theme.fontFamily; font.pixelSize: 14; font.weight: Font.DemiBold; Layout.fillWidth: true; wrapMode: Text.Wrap }
                                Text { text: eventCard.modelData.detail; color: Theme.surfaceVariantText; font.family: Theme.fontFamily; font.pixelSize: 13; Layout.fillWidth: true; wrapMode: Text.Wrap }
                                Flow {
                                    Layout.fillWidth: true; Layout.preferredHeight: childrenRect.height; spacing: 8
                                    Repeater {
                                        // Dismiss is owned by the notification publisher; this widget
                                        // exposes only actions its typed handler can actually perform.
                                        model: (eventCard.modelData.actions || []).filter(action => action.id !== "dismiss")
                                        delegate: SecurityButton {
                                            required property var modelData
                                            text: modelData.label; primary: modelData.id === "trust_once" || modelData.id === "clear_clipboard"
                                            busy: root.actionPending && ["trust_once", "trust_always"].includes(modelData.id)
                                            enabled: root.fresh && !root.actionPending
                                            onClicked: root.runAction(eventCard.modelData, modelData)
                                        }
                                    }
                                    SecurityButton { text: qsTr("Review"); visible: !(eventCard.modelData.actions || []).length && !["PENDING","VERIFYING","INDETERMINATE"].includes(eventCard.modelData.operation); onClicked: root.openRoute(eventCard.modelData.route, eventCard.modelData.resource_ref) }
                                }
                            }
                        }
                    }
                    SecurityButton { visible: root.items.length > 1; text: root.otherItemsOpen ? qsTr("Show less") : qsTr("%1 more items").arg(root.items.length - 1); onClicked: root.otherItemsOpen = !root.otherItemsOpen }
                    Rectangle { visible: root.activities.length > 0; Layout.fillWidth: true; height: 1; color: Theme.outlineVariant }
                    Text { visible: root.activities.length > 0; text: qsTr("Live activity"); color: Theme.surfaceVariantText; font.family: Theme.fontFamily; font.pixelSize: 12; font.weight: Font.Medium }
                    Repeater {
                        model: root.activityOpen ? root.activities : root.activities.slice(0,3)
                        delegate: Item {
                            required property var modelData
                            Layout.fillWidth: true; implicitHeight: Math.max(40, activityText.implicitHeight + 8)
                            RowLayout {
                                anchors.fill: parent; spacing: 10
                                DIcon { name: modelData.icon; size: 18; color: modelData.kind === "microphone" || modelData.kind === "camera" ? Theme.primary : Theme.surfaceText }
                                ColumnLayout {
                                    id: activityText; Layout.fillWidth: true; spacing: 2
                                    Text { text: modelData.title; color: Theme.surfaceText; font.pixelSize: 13; font.family: Theme.fontFamily; elide: Text.ElideRight; Layout.fillWidth: true }
                                    Text { text: modelData.detail; color: Theme.surfaceVariantText; font.pixelSize: 12; font.family: Theme.fontFamily; wrapMode: Text.Wrap; Layout.fillWidth: true }
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
                            Text { text: modelData.label; color: Theme.surfaceVariantText; font.family: Theme.fontFamily; font.pixelSize: 12; Layout.fillWidth: true }
                            Text { text: root.fresh ? modelData.value : qsTr("Unavailable"); color: Theme.surfaceText; font.family: Theme.fontFamily; font.pixelSize: 12 }
                        } }
                        SecurityButton { visible: root.fresh && root.presentation.capabilities?.privacy_profile_change === true; text: qsTr("Change privacy profile"); onClicked: root.profileMenuOpen = !root.profileMenuOpen }
                        Flow { visible: root.profileMenuOpen && root.fresh; Layout.fillWidth: true; Layout.preferredHeight: childrenRect.height; spacing: 8
                            Repeater { model: ["STANDARD", "PRIVATE", "TRAVEL"]; delegate: SecurityButton { required property string modelData; text: modelData.charAt(0) + modelData.slice(1).toLowerCase(); enabled: !root.actionPending; onClicked: root.setPrivacyProfile(modelData) } }
                        }
                        SecurityButton { text: qsTr("Refresh status"); enabled: !root.requestPending; onClicked: root.refreshSummary() }
                    }
                    Text { visible: root.actionMessage !== ""; text: root.actionMessage; color: Theme.surfaceVariantText; font.family: Theme.fontFamily; font.pixelSize: 13; wrapMode: Text.Wrap; Layout.fillWidth: true; Accessible.role: Accessible.StaticText; Accessible.name: text }
                    SecurityButton { text: root.launchPending ? qsTr("Opening Security Center…") : qsTr("Open Security Center"); primary: true; busy: root.launchPending; Layout.fillWidth: true; onClicked: root.openSecurityCenter() }
                    Text {
                        visible: root.launchMessage !== ""
                        text: root.launchMessage
                        color: root.launchState === "error" ? Theme.error : root.launchState === "opening" ? Theme.primary : Theme.primary
                        font.family: Theme.fontFamily; font.pixelSize: 13
                        Layout.fillWidth: true; wrapMode: Text.Wrap
                        Accessible.role: Accessible.StaticText
                    }
                }
            }
        }
    }
}
