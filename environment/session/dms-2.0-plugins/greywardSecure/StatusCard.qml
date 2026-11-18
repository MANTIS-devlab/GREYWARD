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
    readonly property string signalState: assessment.signal
    readonly property bool confirmedSignal: signalState !== "unknown"
    readonly property color stateColor: signalState === "unknown" ? Theme.surfaceVariantText
        : signalState === "busy" ? (Theme.isLightMode ? "#315F85" : "#95C9F6")
        : Palette.color(signalState, Theme.isLightMode)
    readonly property string signalIcon: ({
        positive: "check",
        warning: "warning",
        critical: "error",
        busy: "hourglass_top",
        unknown: "help_outline"
    })[signalState]
    readonly property string value: assessment.value
    readonly property string detail: assessment.detail
    readonly property var rows: assessment.rows
    readonly property string route: section === "protection" ? "overview" : section
    readonly property string heading: section === "protection" ? qsTr("Protection") : section === "network" ? qsTr("Network security") : qsTr("Updates")
    readonly property string emblem: section === "protection" ? "shield_lock" : section === "network" ? "hub" : "system_update"
    readonly property string destinationLabel: section === "updates" ? qsTr("Open Update Center") : section === "network" ? qsTr("Network details") : qsTr("Protection details")
    readonly property int rowHeight: Math.ceil(dataFont.height)
    readonly property int medallionSize: width >= 230 && height >= 180 ? 53 : height >= 140 ? 42 : 32
    readonly property int visibleRowCount: section === "updates" ? 0 : Math.max(0, Math.min(rows.length, height >= 225 ? 3 : 2, Math.floor(
        (height - 2 * pad - hero.implicitHeight - (supportingText.visible ? supportingText.implicitHeight : 0)
        - footer.implicitHeight - divider.implicitHeight - content.spacing * 5 + metadata.spacing)
        / (rowHeight + metadata.spacing))))

    pad: height < 188 ? 11 : 14
    clipContent: true
    clickable: true
    showFocusRing: true
    color: Theme.surfaceContainer
    border.color: Qt.alpha(root.stateColor, root.confirmedSignal ? (hover.hovered ? 0.65 : 0.38) : 0.22)
    onClicked: Quickshell.execDetached(["/usr/bin/greyward-security-center-route", root.route])
    Accessible.role: Accessible.Button
    Accessible.name: heading + ": " + value
    Accessible.description: detail + ". " + rows.map(row => row.label + ": " + row.value).join(". ")

    HoverHandler { id: hover }
    FontMetrics { id: dataFont; font: supportingText.font }

    // The light is strongest in the status area and falls into the evidence area.
    Rectangle {
        anchors.fill: parent
        anchors.margins: root.border.width - root.pad
        radius: Math.max(0, root.bodyRadius - root.border.width)
        gradient: Gradient {
            GradientStop {
                position: 0
                color: Qt.tint(root.color, Qt.alpha(root.stateColor, root.confirmedSignal
                    ? (Theme.isLightMode ? 0.13 : 0.24) : (Theme.isLightMode ? 0.045 : 0.065)))
            }
            GradientStop {
                position: 0.55
                color: Qt.tint(root.color, Qt.alpha(root.stateColor, root.confirmedSignal ? 0.05 : 0.012))
            }
            GradientStop { position: 1; color: root.color }
        }
    }

    ColumnLayout {
        id: content
        objectName: "greywardStatusContent"
        anchors.fill: parent
        spacing: root.height >= 186 ? 6 : 5

        RowLayout {
            id: hero
            Layout.fillWidth: true
            spacing: root.width >= 230 ? 12 : 8

            ColumnLayout {
                Layout.fillWidth: true
                Layout.minimumWidth: 0
                spacing: 5

                RowLayout {
                    Layout.fillWidth: true
                    spacing: 6
                    DIcon { name: root.emblem; size: 15; color: Theme.surfaceVariantText }
                    StyledText {
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0
                        text: root.heading
                        font.pixelSize: Theme.fontSizeSmall
                        font.weight: Font.DemiBold
                        color: Theme.surfaceText
                        wrapMode: Text.NoWrap
                        elide: Text.ElideRight
                    }
                }

                StyledText {
                    Layout.fillWidth: true
                    Layout.minimumWidth: 0
                    text: root.value
                    color: root.confirmedSignal ? root.stateColor : Theme.surfaceText
                    font.pixelSize: Theme.fontSizeXLarge + (root.width >= 244 ? 2 : 0)
                    font.weight: Font.DemiBold
                    maximumLineCount: root.height >= 140 ? 2 : 1
                    wrapMode: Text.Wrap
                    elide: Text.ElideRight
                }
            }

            Rectangle {
                Layout.preferredWidth: root.medallionSize
                Layout.preferredHeight: root.medallionSize
                Layout.alignment: Qt.AlignVCenter
                radius: width / 2
                color: Qt.alpha(root.stateColor, root.confirmedSignal ? (Theme.isLightMode ? 0.13 : 0.19) : 0.08)
                border.width: 1
                border.color: Qt.alpha(root.stateColor, root.confirmedSignal ? 0.68 : 0.30)

                Rectangle {
                    anchors.fill: parent
                    anchors.margins: 4
                    radius: width / 2
                    color: Qt.tint(root.color, Qt.alpha(root.stateColor, root.confirmedSignal ? 0.12 : 0.035))

                    DIcon {
                        anchors.centerIn: parent
                        name: root.signalIcon
                        size: Math.round(root.medallionSize * 0.56)
                        color: root.stateColor
                    }
                }
            }
        }

        StyledText {
            id: supportingText
            Layout.fillWidth: true
            Layout.minimumWidth: 0
            visible: root.height >= 146 && text.length > 0
            text: root.detail
            color: Theme.surfaceVariantText
            font.pixelSize: Theme.fontSizeSmall
            maximumLineCount: root.section === "updates" && root.height >= 185 ? 3 : root.height >= 198 ? 2 : 1
            wrapMode: Text.Wrap
            elide: Text.ElideRight
        }

        ColumnLayout {
            id: metadata
            Layout.fillWidth: true
            visible: root.visibleRowCount > 0
            spacing: 3
            Repeater {
                model: root.rows.slice(0, root.visibleRowCount)
                RowLayout {
                    required property var modelData
                    Layout.fillWidth: true
                    Layout.preferredHeight: root.rowHeight
                    spacing: 8

                    StyledText {
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0
                        text: modelData.label
                        font.pixelSize: supportingText.font.pixelSize
                        color: Theme.surfaceVariantText
                        wrapMode: Text.NoWrap
                        elide: Text.ElideRight
                    }
                    StyledText {
                        Layout.maximumWidth: (root.width - 2 * root.pad) * 0.53
                        Layout.minimumWidth: 0
                        text: modelData.value
                        font.pixelSize: supportingText.font.pixelSize
                        font.weight: Font.Medium
                        color: modelData.tone === "info" ? Theme.surfaceText : Palette.color(modelData.tone, Theme.isLightMode)
                        horizontalAlignment: Text.AlignRight
                        wrapMode: Text.NoWrap
                        elide: Text.ElideRight
                    }
                }
            }
        }

        Item { Layout.fillHeight: true; Layout.minimumHeight: 0 }

        Rectangle {
            id: divider
            Layout.fillWidth: true
            implicitHeight: 1
            color: Qt.alpha(root.stateColor, root.confirmedSignal ? 0.26 : 0.18)
        }

        RowLayout {
            id: footer
            Layout.fillWidth: true
            spacing: 8

            StyledText {
                Layout.fillWidth: true
                Layout.minimumWidth: 0
                text: root.destinationLabel
                color: hover.hovered ? Theme.surfaceText : Theme.surfaceVariantText
                font.pixelSize: Theme.fontSizeSmall
                font.weight: Font.Medium
                wrapMode: Text.NoWrap
                elide: Text.ElideRight
            }
            DIcon { name: "arrow_forward"; size: 16; color: root.stateColor }
        }
    }
}
