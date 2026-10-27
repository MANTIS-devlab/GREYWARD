import QtQuick
import QtQuick.Layouts
import Quickshell
import qs.Common
import qs.DCommon.Widgets
import qs.Modules.Plugins
import "StatusModel.js" as Status
import "StatePalette.js" as Palette

DashCardComponent {
    id: root
    property string section: "protection"
    readonly property var provider: pluginService?.pluginDaemonInstances?.greywardSecure ?? null
    readonly property bool fresh: provider?.freshnessLeaseValid ?? false
    readonly property var presentation: provider?.presentation ?? ({})
    readonly property var assessment: Status.card(section, presentation, fresh, provider !== null)
    readonly property string stateTone: assessment.tone
    readonly property color stateColor: Palette.color(stateTone, Theme.isLightMode)
    readonly property string value: assessment.value
    readonly property string detail: assessment.detail
    readonly property var rows: assessment.rows
    readonly property bool compact: height < 200
    readonly property string route: section === "protection" ? "overview" : section
    readonly property string heading: section === "protection" ? qsTr("Protection") : section === "network" ? qsTr("Network security") : qsTr("Updates")
    readonly property string emblem: section === "protection" ? "shield_lock" : section === "network" ? "hub" : "system_update"

    pad: root.height < 220 ? 14 : Theme.spacingL
    clipContent: true
    clickable: true
    color: Theme.surfaceContainer
    border.color: Qt.alpha(Theme.surfaceText, Theme.isLightMode ? 0.10 : 0.08)
    onClicked: Quickshell.execDetached(["/usr/bin/greyward-security-center-route", root.route])
    Accessible.role: Accessible.Button
    Accessible.name: heading + ": " + value
    Accessible.description: detail + ". " + rows.map(row => row.label + ": " + row.value).join(". ")

    // State accents belong to the functional header, assessment and footer.
    // Keep the reading surface clear at every size and in both color schemes.
    ColumnLayout {
        objectName: "greywardStatusContent"
        anchors.fill: parent
        spacing: root.height < 220 ? 5 : 8
        RowLayout {
            Layout.fillWidth: true; spacing: 10
            Rectangle {
                Layout.preferredWidth: 32; Layout.preferredHeight: 32
                radius: 9; color: Qt.alpha(root.stateColor, Theme.isLightMode ? 0.10 : 0.13)
                DIcon { anchors.centerIn: parent; name: root.emblem; size: 22; color: root.stateColor }
            }
            StyledText {
                text: root.heading; Layout.fillWidth: true; Layout.minimumWidth: 0
                font.pixelSize: Theme.fontSizeSmall; font.weight: Font.DemiBold; color: Theme.surfaceText
                elide: Text.ElideRight; maximumLineCount: 1
            }
            DIcon { name: root.stateTone === "positive" ? "check_circle" : root.stateTone === "critical" ? "error" : "info"; size: 16; color: root.stateColor }
        }
        StyledText {
            Layout.fillWidth: true; Layout.minimumWidth: 0
            text: root.value; color: root.stateColor
            font.pixelSize: Theme.fontSizeXLarge; font.weight: Font.DemiBold
            maximumLineCount: 2; wrapMode: Text.Wrap; elide: Text.ElideRight
        }
        StyledText {
            Layout.fillWidth: true; Layout.minimumWidth: 0; visible: root.height >= 170
            text: root.detail; color: Theme.surfaceVariantText; font.pixelSize: Theme.fontSizeSmall
            maximumLineCount: root.section === "updates" ? (root.height < 220 ? 3 : 4) : root.height < 240 ? 1 : 2; wrapMode: Text.Wrap; elide: Text.ElideRight
        }
        ColumnLayout {
            Layout.fillWidth: true; spacing: 4; visible: root.height >= 195 && root.section !== "updates"
            Repeater {
                model: root.rows.slice(0, root.height >= 240 ? 3 : 2)
                RowLayout {
                    required property var modelData
                    Layout.fillWidth: true; spacing: 8
                    StyledText {
                        text: modelData.label; Layout.fillWidth: true; Layout.minimumWidth: 0
                        font.pixelSize: Theme.fontSizeSmall; color: Theme.surfaceVariantText
                        maximumLineCount: 1; elide: Text.ElideRight
                    }
                    StyledText {
                        text: modelData.value
                        Layout.preferredWidth: (root.width - root.pad * 2) * 0.50
                        Layout.maximumWidth: (root.width - root.pad * 2) * 0.50
                        Layout.minimumWidth: 0
                        font.pixelSize: Theme.fontSizeSmall
                        color: modelData.tone === "info" ? Theme.surfaceVariantText : Palette.color(modelData.tone, Theme.isLightMode)
                        horizontalAlignment: Text.AlignRight; maximumLineCount: 1; elide: Text.ElideRight
                    }
                }
            }
        }
        Item { Layout.fillHeight: true; Layout.minimumHeight: 0 }
        Rectangle { Layout.fillWidth: true; height: 1; color: Qt.alpha(root.stateColor, 0.18) }
        RowLayout {
            Layout.fillWidth: true; spacing: 6
            Rectangle { width: 5; height: 5; radius: 2.5; color: root.stateColor }
            StyledText {
                Layout.fillWidth: true; Layout.minimumWidth: 0
                text: !root.fresh ? qsTr("Evidence unavailable") : root.section === "updates" ? qsTr("Open Update Center") : qsTr("Protection details")
                font.pixelSize: Theme.fontSizeSmall - 1; color: Theme.surfaceVariantText
                elide: Text.ElideRight; maximumLineCount: 1
            }
            DIcon { name: "arrow_forward"; size: 15; color: root.stateColor }
        }
    }
}
