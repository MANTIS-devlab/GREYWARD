import QtQuick
import Quickshell

Item {
    id: root
    property var pluginService: null
    property string trigger: "security"
    signal itemsChanged()
    readonly property var routes: [
        {name: qsTr("Security Center"), icon: "material:shield_lock", comment: qsTr("Review protection"), action: "overview"},
        {name: qsTr("Network security"), icon: "material:policy", comment: qsTr("Application and IP filtering"), action: "network"},
        {name: qsTr("Update Center"), icon: "material:system_update", comment: qsTr("Review system updates"), action: "updates"},
        {name: qsTr("Device protection"), icon: "material:usb", comment: qsTr("Review device access"), action: "devices"},
        {name: qsTr("Security evidence"), icon: "material:fact_check", comment: qsTr("Inspect observed evidence"), action: "evidence"}
    ]
    function getItems(query) {
        const value = String(query || "").toLocaleLowerCase().trim();
        return routes.filter(item => !value || (item.name + " " + item.comment).toLocaleLowerCase().includes(value));
    }
    function executeItem(item) {
        const match = routes.find(route => route.action === item?.action);
        if (match) Quickshell.execDetached(["/usr/bin/greyward-security-center-route", match.action]);
    }
}
