import QtQuick
import Quickshell
import qs.Common
import qs.Widgets
import qs.Modules.Plugins

PluginComponent {
    id: root

    layerNamespacePlugin: "greyward-network-traffic"

    NetworkTrafficModel {
        id: trafficModel
    }

    readonly property int textSize: Theme.barTextSize(
        root.barThickness,
        root.barConfig?.fontScale,
        root.barConfig?.maximizeWidgetText
    )

    function openNetworkActivity() {
        Quickshell.execDetached(["/usr/bin/greyward-security-center-route", "activity"])
    }

    pillClickAction: root.openNetworkActivity

    horizontalBarPill: Component {
        Row {
            spacing: Theme.spacingS
            height: 28

            Item {
                width: rxValueMetrics.width + rxArrow.width + Theme.spacingXXS
                height: parent.height

                StyledText {
                    id: rxArrow
                    text: "↓"
                    color: Theme.info
                    font.pixelSize: root.textSize
                    isMonospace: true
                    anchors.left: parent.left
                    anchors.verticalCenter: parent.verticalCenter
                }

                StyledText {
                    id: rxValue
                    text: trafficModel.downloadText
                    color: Theme.widgetTextColor
                    font.pixelSize: root.textSize
                    isMonospace: true
                    width: rxValueMetrics.width
                    anchors.left: rxArrow.right
                    anchors.leftMargin: Theme.spacingXXS
                    anchors.verticalCenter: parent.verticalCenter
                    horizontalAlignment: Text.AlignLeft
                    elide: Text.ElideNone
                    wrapMode: Text.NoWrap
                }

                StyledTextMetrics {
                    id: rxValueMetrics
                    text: "999.9 GB/s"
                    font.pixelSize: root.textSize
                    isMonospace: true
                }
            }

            Item {
                width: txValueMetrics.width + txArrow.width + Theme.spacingXXS
                height: parent.height

                StyledText {
                    id: txArrow
                    text: "↑"
                    color: Theme.secondary
                    font.pixelSize: root.textSize
                    isMonospace: true
                    anchors.left: parent.left
                    anchors.verticalCenter: parent.verticalCenter
                }

                StyledText {
                    id: txValue
                    text: trafficModel.uploadText
                    color: Theme.widgetTextColor
                    font.pixelSize: root.textSize
                    isMonospace: true
                    width: txValueMetrics.width
                    anchors.left: txArrow.right
                    anchors.leftMargin: Theme.spacingXXS
                    anchors.verticalCenter: parent.verticalCenter
                    horizontalAlignment: Text.AlignLeft
                    elide: Text.ElideNone
                    wrapMode: Text.NoWrap
                }

                StyledTextMetrics {
                    id: txValueMetrics
                    text: "999.9 GB/s"
                    font.pixelSize: root.textSize
                    isMonospace: true
                }
            }
        }
    }

    verticalBarPill: Component {
        Column {
            spacing: Theme.spacingXXS
            anchors.centerIn: parent

            StyledText {
                text: "↓ " + trafficModel.downloadText.replace(" ", "\u00a0")
                color: Theme.info
                font.pixelSize: root.textSize
                isMonospace: true
                horizontalAlignment: Text.AlignHCenter
            }

            StyledText {
                text: "↑ " + trafficModel.uploadText.replace(" ", "\u00a0")
                color: Theme.secondary
                font.pixelSize: root.textSize
                isMonospace: true
                horizontalAlignment: Text.AlignHCenter
            }
        }
    }
}
