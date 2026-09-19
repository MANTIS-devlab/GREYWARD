import QtQuick
import qs.Services
import "./NetworkTrafficMath.js" as NetworkTrafficMath

Item {
    id: root

    visible: false
    width: 0
    height: 0

    property real downloadBytesPerSecond: 0
    property real uploadBytesPerSecond: 0
    property string downloadText: NetworkTrafficMath.formatRate(downloadBytesPerSecond)
    property string uploadText: NetworkTrafficMath.formatRate(uploadBytesPerSecond)
    property var activeInterfaces: []
    property var previousCounters: ({})
    property double previousSampleAt: 0

    readonly property bool backendAvailable: DgopService.dgopAvailable
    readonly property string activeInterfaceLabel: activeInterfaces.length > 0
        ? activeInterfaces.join(", ") : "No active link"

    function physicalInterfaceNames() {
        const names = []
        const services = [DMSNetworkService, NetworkService]
        for (const service of services) {
            for (const name of [service.ethernetInterface, service.wifiInterface]) {
                const value = String(name || "").trim()
                if (value && !names.includes(value))
                    names.push(value)
            }
            for (const devices of [service.ethernetDevices, service.wifiDevices]) {
                for (const device of devices || []) {
                    const value = String(device?.name || "").trim()
                    if (value && !names.includes(value))
                        names.push(value)
                }
            }
        }
        return names
    }

    function reset() {
        previousCounters = {}
        previousSampleAt = 0
        activeInterfaces = []
        downloadBytesPerSecond = 0
        uploadBytesPerSecond = 0
    }

    function ingest(snapshot) {
        const now = Date.now()
        const elapsed = root.previousSampleAt > 0 ? now - root.previousSampleAt : 0
        const result = NetworkTrafficMath.calculateRates(
            snapshot,
            root.previousCounters,
            elapsed,
            root.physicalInterfaceNames()
        )

        root.activeInterfaces = result.interfaces
        root.previousCounters = result.counters
        root.previousSampleAt = now
        if (elapsed > 0) {
            root.downloadBytesPerSecond = Math.max(0, result.rxRate)
            root.uploadBytesPerSecond = Math.max(0, result.txRate)
        } else {
            root.downloadBytesPerSecond = 0
            root.uploadBytesPerSecond = 0
        }
    }

    Component.onCompleted: {
        DgopService.addRef(["network"])
        if (DgopService.networkInterfaces && DgopService.networkInterfaces.length > 0)
            root.ingest(DgopService.networkInterfaces)
    }

    Component.onDestruction: DgopService.removeRef(["network"])

    Connections {
        target: DgopService
        function onNetworkInterfacesChanged() {
            root.ingest(DgopService.networkInterfaces)
        }
        function onDgopAvailableChanged() {
            if (DgopService.dgopAvailable)
                DgopService.updateAllStats()
            else
                root.reset()
        }
    }

    Connections {
        target: DMSNetworkService
        function onConnectionChanged() { root.reset() }
    }

    Connections {
        target: NetworkService
        function onConnectionChanged() { root.reset() }
    }
}
