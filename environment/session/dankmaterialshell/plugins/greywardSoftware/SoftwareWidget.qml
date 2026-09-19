import QtQuick
import Quickshell
import qs.Common
import qs.Widgets
import qs.Modules.Plugins

PluginComponent {
    id: root
    layerNamespacePlugin: "greyward-software"

    readonly property string selectionLauncher: "/usr/local/libexec/greyward-software-selection"

    function openSelection() {
        Quickshell.execDetached([root.selectionLauncher])
    }

    // This is intentionally a single-action shell affordance. Software
    // discovery, installs, updates and errors remain inside Software.
    pillClickAction: root.openSelection

    horizontalBarPill: Component {
        Row {
            spacing: Theme.spacingXS
            height: 28

            DankIcon {
                name: "storefront"
                size: 19
                color: Theme.primary
                anchors.verticalCenter: parent.verticalCenter
            }
        }
    }

    verticalBarPill: Component {
        Item {
            width: 22
            height: 22

            DankIcon {
                anchors.centerIn: parent
                name: "storefront"
                size: 17
                color: Theme.primary
            }
        }
    }
}
