import QtQuick
import QtQuick.Layouts
import qs.Common
import qs.DCommon.Widgets
import qs.Modules.Plugins

DashTabComponent {
    id: root
    readonly property var provider: pluginService?.pluginDaemonInstances?.greywardSecure ?? null
    readonly property bool fresh: provider?.freshnessLeaseValid ?? false
    onLiveChanged: { if (live) provider?.refreshSummary(); }

    DFlickable {
        anchors.fill: parent
        contentHeight: content.implicitHeight + Theme.spacingL
        clip: true
        ColumnLayout {
            id: content
            width: parent.width
            spacing: Theme.spacingL
            StyledText { text: qsTr("Security"); font.pixelSize: Theme.fontSizeLarge; font.weight: Font.DemiBold }
            GridLayout {
                Layout.fillWidth: true
                columns: width > 720 ? 3 : 1
                columnSpacing: Theme.spacingM
                rowSpacing: Theme.spacingM
                Repeater {
                    model: ["protection", "network", "updates"]
                    StatusCard {
                        required property string modelData
                        section: modelData
                        pluginService: root.pluginService
                        live: root.live
                        Layout.fillWidth: true
                        Layout.preferredHeight: 200
                    }
                }
            }
            StyledText { text: qsTr("Needs your attention"); font.pixelSize: Theme.fontSizeMedium; font.weight: Font.DemiBold }
            StyledText {
                Layout.fillWidth: true
                visible: !root.fresh || !(root.provider?.presentation?.notification_items?.length)
                text: !root.fresh ? qsTr("Current evidence is unavailable. Open Security Center to inspect protection.") : qsTr("No pending items in the current notification projection.")
                color: Theme.surfaceVariantText
                wrapMode: Text.Wrap
            }
            Repeater {
                model: root.fresh ? root.provider?.presentation?.notification_items ?? [] : []
                DCard {
                    id: notice
                    required property var modelData
                    Layout.fillWidth: true
                    implicitHeight: row.implicitHeight + notice.pad * 2
                    ColumnLayout {
                        id: row
                        anchors.fill: parent
                        spacing: Theme.spacingS
                        StyledText { text: notice.modelData.title; Layout.fillWidth: true; font.weight: Font.DemiBold; wrapMode: Text.Wrap }
                        StyledText { text: notice.modelData.detail; Layout.fillWidth: true; color: Theme.surfaceVariantText; wrapMode: Text.Wrap }
                        Flow {
                            Layout.fillWidth: true
                            Layout.preferredHeight: childrenRect.height
                            spacing: Theme.spacingS
                            Repeater {
                                model: (notice.modelData.actions ?? []).filter(action => action.id !== "dismiss")
                                DButton {
                                    required property var modelData
                                    text: modelData.label
                                    enabled: root.fresh && !(root.provider?.actionPending ?? true)
                                    onClicked: root.provider?.runAction(notice.modelData, modelData)
                                }
                            }
                        }
                    }
                }
            }
            StyledText {
                Layout.fillWidth: true
                visible: (root.provider?.actionMessage ?? "") !== ""
                text: root.provider?.actionMessage ?? ""
                wrapMode: Text.Wrap
            }
            DButton { text: qsTr("Open Security Center"); onClicked: root.provider?.openSecurityCenter() }
        }
    }
}
