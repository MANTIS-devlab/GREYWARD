import QtQuick
import Quickshell
import qs.Common
import qs.Services
import qs.Widgets
import qs.Modules.Plugins

PluginComponent {
    id: root

    layerNamespacePlugin: "greyward-public-ip"

    readonly property string primaryEndpoint: "https://ipapi.co/json/"
    readonly property string fallbackEndpoint: "https://ipwho.is/"
    readonly property int refreshIntervalMs: 1200000
    readonly property int primaryBackoffMs: 3600000
    readonly property int fallbackBackoffMs: 1800000

    // Fail closed until the persistent preference has been loaded. This avoids
    // a startup request racing ahead of a saved opt-out.
    property bool stateInitialized: false
    property bool publicLookupEnabled: false
    property string publicIp: ""
    property string localAddress: ""
    property string countryCode: ""
    property string publicState: "OFF"
    property double primaryBackoffUntil: 0
    property double fallbackBackoffUntil: 0
    property bool requestInFlight: false
    property int requestGeneration: 0

    readonly property string publicDisplay: !stateInitialized ? qsTr("Starting")
        : !publicLookupEnabled ? qsTr("Off")
        : publicState === "AVAILABLE" ? publicIp
        : publicState === "CHECKING" ? qsTr("Checking…") : qsTr("Unavailable")
    readonly property string localDisplay: localAddress !== "" ? localAddress : qsTr("Unavailable")
    readonly property bool hasCountryCode: /^[A-Z]{2}$/.test(countryCode)
    readonly property int textSize: Theme.barTextSize(
        root.barThickness,
        root.barConfig?.fontScale,
        root.barConfig?.maximizeWidgetText
    )

    function isPublicAddress(value) {
        const ip = String(value || "").trim()
        if (ip.indexOf(":") >= 0) {
            const lower = ip.toLowerCase()
            return lower !== "::1" && !lower.startsWith("fe80:")
                && !lower.startsWith("fc") && !lower.startsWith("fd")
        }
        const parts = ip.split(".")
        if (parts.length !== 4 || parts.some(part => !/^\d{1,3}$/.test(part)))
            return false
        const octets = parts.map(part => Number(part))
        if (octets.some(part => part < 0 || part > 255))
            return false
        return octets[0] !== 0 && octets[0] !== 10 && octets[0] !== 127
            && !(octets[0] === 169 && octets[1] === 254)
            && !(octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31)
            && !(octets[0] === 192 && octets[1] === 168)
    }

    function initializeState() {
        if (root.stateInitialized || !root.pluginService || !root.pluginId)
            return
        const stored = root.pluginService.loadPluginState(
            root.pluginId, "publicLookupEnabled", true)
        root.publicLookupEnabled = stored === true
            || String(stored).toLowerCase() === "true"
        root.publicState = root.publicLookupEnabled ? "CHECKING" : "OFF"
        root.stateInitialized = true

        // Remove legacy address cache fields. A network identity is sensitive
        // and must not survive the shell process or be presented as current.
        root.pluginService.removePluginStateKey(root.pluginId, "publicIp")
        root.pluginService.removePluginStateKey(root.pluginId, "countryCode")
        root.pluginService.removePluginStateKey(root.pluginId, "cachedAt")

        root.refreshLocalAddress()
        if (root.publicLookupEnabled)
            initialFetchTimer.restart()
    }

    function setPublicLookupEnabled(enabled) {
        if (!root.stateInitialized)
            return
        root.publicLookupEnabled = enabled
        root.pluginService.savePluginState(root.pluginId, "publicLookupEnabled", enabled)
        root.requestGeneration += 1
        root.requestInFlight = false
        initialFetchTimer.stop()
        networkRefreshTimer.stop()
        root.publicIp = ""
        root.countryCode = ""
        root.publicState = enabled ? "CHECKING" : "OFF"
        if (enabled)
            Qt.callLater(root.fetchPublicIdentity)
    }

    function applyIdentity(identity, generation) {
        if (generation !== root.requestGeneration || !root.publicLookupEnabled)
            return false
        if (!identity || !root.isPublicAddress(identity.ip)
                || !/^[A-Z]{2}$/.test(identity.countryCode))
            return false
        root.publicIp = identity.ip
        root.countryCode = identity.countryCode
        root.publicState = "AVAILABLE"
        return true
    }

    function requestProvider(provider, endpoint, callback) {
        // Start immediately so switching off cannot leave a provider launch
        // queued in Proc's debounce timer.
        Proc.runCommand("greywardPublicIp." + provider, [
            "curl", "--silent", "--show-error",
            "--proto", "=https", "--tlsv1.2",
            "--header", "Accept: application/json",
            "--user-agent", "curl",
            "--connect-timeout", "4", "--max-time", "8",
            "--write-out", "\n__GREYWARD_HTTP_STATUS__:%{http_code}", endpoint
        ], function (stdout, exitCode) {
            const marker = "__GREYWARD_HTTP_STATUS__:"
            const markerIndex = String(stdout || "").lastIndexOf(marker)
            const body = markerIndex >= 0 ? String(stdout).slice(0, markerIndex) : ""
            const status = markerIndex >= 0
                ? Number(String(stdout).slice(markerIndex + marker.length).trim()) : 0
            let identity = null
            if (exitCode === 0 && status >= 200 && status < 300) {
                try {
                    const payload = JSON.parse(body)
                    const nextIp = String(payload.ip || "").trim()
                    const nextCountry = String(payload.country_code || "")
                        .trim().toUpperCase()
                    if (payload.success !== false && root.isPublicAddress(nextIp)
                            && /^[A-Z]{2}$/.test(nextCountry))
                        identity = { ip: nextIp, countryCode: nextCountry }
                } catch (error) {
                    // Invalid provider data is handled as a provider failure.
                }
            }
            callback({ status: status, identity: identity })
        }, 0)
    }

    function finishFailure(generation, primaryStatus, fallbackStatus) {
        if (generation !== root.requestGeneration || !root.publicLookupEnabled)
            return
        root.publicIp = ""
        root.countryCode = ""
        root.publicState = "UNAVAILABLE"
        root.requestInFlight = false
        console.info("[GREYWARD public IP] providers unavailable",
                     "primary=" + primaryStatus, "fallback=" + fallbackStatus)
    }

    function fetchFallback(generation, primaryStatus) {
        if (generation !== root.requestGeneration || !root.publicLookupEnabled)
            return
        if (Date.now() < root.fallbackBackoffUntil) {
            root.finishFailure(generation, primaryStatus, "backoff")
            return
        }
        root.requestProvider("fallback", root.fallbackEndpoint, function (result) {
            if (generation !== root.requestGeneration || !root.publicLookupEnabled)
                return
            if (result.identity && root.applyIdentity(result.identity, generation)) {
                root.requestInFlight = false
                return
            }
            root.fallbackBackoffUntil = Date.now() + root.fallbackBackoffMs
            root.finishFailure(generation, primaryStatus, result.status || "request-failed")
        })
    }

    function fetchPublicIdentity() {
        if (!root.stateInitialized || !root.publicLookupEnabled || root.requestInFlight)
            return

        root.requestGeneration += 1
        const generation = root.requestGeneration
        root.requestInFlight = true
        root.publicIp = ""
        root.countryCode = ""
        root.publicState = "CHECKING"
        if (Date.now() < root.primaryBackoffUntil) {
            root.fetchFallback(generation, "backoff")
            return
        }
        root.requestProvider("primary", root.primaryEndpoint, function (result) {
            if (generation !== root.requestGeneration || !root.publicLookupEnabled)
                return
            if (result.identity && root.applyIdentity(result.identity, generation)) {
                root.requestInFlight = false
                return
            }
            if (result.status === 429) {
                root.primaryBackoffUntil = Date.now() + root.primaryBackoffMs
                console.info("[GREYWARD public IP] ipapi.co returned HTTP 429; using ipwho.is fallback")
            }
            root.fetchFallback(generation, result.status || "request-failed")
        })
    }

    function chooseLocalAddress(values) {
        const candidates = values || []
        return candidates.find(value => {
            const ip = String(value || "").trim().toLowerCase()
            return ip !== "" && ip !== "127.0.0.1" && ip !== "::1"
                && !ip.startsWith("fe80:")
        }) || ""
    }

    function refreshLocalAddress() {
        // `ip route get` consults the local routing table; it does not send a
        // packet to the reserved TEST-NET destination used for route selection.
        Proc.runCommand("greywardPublicIp.localRoute", [
            "ip", "-json", "route", "get", "192.0.2.1"
        ], function (stdout, exitCode) {
            let nextLocal = ""
            if (exitCode === 0) {
                try {
                    const routes = JSON.parse(String(stdout || "[]"))
                    if (routes.length > 0)
                        nextLocal = root.chooseLocalAddress([
                            routes[0].prefsrc || routes[0].src || ""
                        ])
                } catch (error) {
                    // Fall through to the local hostname lookup.
                }
            }
            if (nextLocal !== "") {
                root.localAddress = nextLocal
                return
            }
            Proc.runCommand("greywardPublicIp.localAddresses", ["hostname", "-I"], function (fallbackOutput, fallbackExitCode) {
                root.localAddress = fallbackExitCode === 0
                    ? root.chooseLocalAddress(String(fallbackOutput || "").trim().split(/\s+/)) : ""
            }, 250)
        }, 250)
    }

    function scheduleNetworkRefresh() {
        root.refreshLocalAddress()
        if (!root.stateInitialized || !root.publicLookupEnabled)
            return
        root.requestGeneration += 1
        root.requestInFlight = false
        root.publicIp = ""
        root.countryCode = ""
        root.publicState = "CHECKING"
        networkRefreshTimer.restart()
    }

    Timer {
        id: initialFetchTimer
        interval: 2000
        repeat: false
        onTriggered: root.fetchPublicIdentity()
    }

    Timer {
        id: periodicRefreshTimer
        interval: root.refreshIntervalMs
        running: root.stateInitialized && root.publicLookupEnabled
        repeat: true
        onTriggered: root.fetchPublicIdentity()
    }

    Timer {
        id: networkRefreshTimer
        interval: 5000
        repeat: false
        onTriggered: root.fetchPublicIdentity()
    }

    Timer {
        id: stateInitializationTimer
        interval: 100
        running: !root.stateInitialized
        repeat: true
        onTriggered: root.initializeState()
    }

    Connections {
        target: DMSNetworkService
        function onConnectionChanged() {
            root.scheduleNetworkRefresh()
        }
    }

    Component.onCompleted: Qt.callLater(root.initializeState)

    horizontalBarPill: Component {
        Row {
            spacing: Theme.spacingXS
            height: 28

            Rectangle {
                width: 24
                height: 24
                radius: 12
                color: root.publicLookupEnabled
                    ? Qt.rgba(Theme.info.r, Theme.info.g, Theme.info.b, 0.14)
                    : Qt.rgba(Theme.surfaceVariantText.r, Theme.surfaceVariantText.g,
                              Theme.surfaceVariantText.b, 0.10)
                anchors.verticalCenter: parent.verticalCenter

                DankIcon {
                    anchors.centerIn: parent
                    name: "public"
                    size: 15
                    color: root.publicLookupEnabled ? Theme.info : Theme.surfaceVariantText
                }
            }

            Rectangle {
                visible: root.hasCountryCode
                width: 20
                height: 14
                radius: 3
                color: "transparent"
                border.width: 1
                border.color: Qt.rgba(Theme.surfaceText.r, Theme.surfaceText.g,
                                      Theme.surfaceText.b, 0.24)
                anchors.verticalCenter: parent.verticalCenter
                Canvas {
                    id: flagCanvas
                    anchors.centerIn: parent
                    width: 18
                    height: 12
                    property string code: root.countryCode
                    onCodeChanged: requestPaint()
                    Component.onCompleted: requestPaint()
                    onPaint: {
                        const ctx = getContext("2d")
                        const w = width
                        const h = height
                        ctx.clearRect(0, 0, w, h)
                        ctx.fillStyle = "#6B7280"
                        ctx.fillRect(0, 0, w, h)
                        function rect(color, x, y, rw, rh) {
                            ctx.fillStyle = color
                            ctx.fillRect(x, y, rw, rh)
                        }
                        function circle(color, x, y, r) {
                            ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2)
                            ctx.fillStyle = color; ctx.fill()
                        }
                        switch (code) {
                        case "FR": rect("#0055A4", 0, 0, w / 3, h); rect("#FFF", w / 3, 0, w / 3, h); rect("#EF4135", 2 * w / 3, 0, w / 3, h); break
                        case "IT": rect("#009246", 0, 0, w / 3, h); rect("#FFF", w / 3, 0, w / 3, h); rect("#CE2B37", 2 * w / 3, 0, w / 3, h); break
                        case "BE": rect("#000", 0, 0, w / 3, h); rect("#FFD90C", w / 3, 0, w / 3, h); rect("#EF3340", 2 * w / 3, 0, w / 3, h); break
                        case "NL": rect("#AE1C28", 0, 0, w, h / 3); rect("#FFF", 0, h / 3, w, h / 3); rect("#21468B", 0, 2 * h / 3, w, h / 3); break
                        case "DE": rect("#000", 0, 0, w, h / 3); rect("#DD0000", 0, h / 3, w, h / 3); rect("#FFCE00", 0, 2 * h / 3, w, h / 3); break
                        case "RU": rect("#FFF", 0, 0, w, h / 3); rect("#0039A6", 0, h / 3, w, h / 3); rect("#D52B1E", 0, 2 * h / 3, w, h / 3); break
                        case "ES": rect("#AA151B", 0, 0, w, h / 4); rect("#F1BF00", 0, h / 4, w, h / 2); rect("#AA151B", 0, 3 * h / 4, w, h / 4); break
                        case "JP": rect("#FFF", 0, 0, w, h); circle("#BC002D", w / 2, h / 2, h * 0.3); break
                        case "CH": rect("#D52B1E", 0, 0, w, h); rect("#FFF", w * 0.42, h * 0.2, w * 0.16, h * 0.6); rect("#FFF", w * 0.25, h * 0.4, w * 0.5, h * 0.2); break
                        case "CN": rect("#DE2910", 0, 0, w, h); circle("#FFDE00", w * 0.25, h * 0.3, h * 0.16); break
                        case "IN": rect("#FF9933", 0, 0, w, h / 3); rect("#FFF", 0, h / 3, w, h / 3); rect("#138808", 0, 2 * h / 3, w, h / 3); circle("#000080", w / 2, h / 2, h * 0.11); break
                        case "US":
                            for (let i = 0; i < 7; ++i) rect(i % 2 === 0 ? "#B22234" : "#FFF", 0, i * h / 7, w, h / 7)
                            rect("#3C3B6E", 0, 0, w * 0.42, h * 0.54); break
                        default:
                            rect("#374151", 0, 0, w, h)
                            ctx.fillStyle = "#FFF"; ctx.font = "bold 6px sans-serif"; ctx.textAlign = "center"; ctx.textBaseline = "middle"; ctx.fillText(code, w / 2, h / 2)
                        }
                    }
                }
            }

            StyledText {
                text: root.publicDisplay
                color: root.publicLookupEnabled ? Theme.widgetTextColor : Theme.surfaceVariantText
                font.pixelSize: root.textSize
                isMonospace: true
                verticalAlignment: Text.AlignVCenter
                anchors.verticalCenter: parent.verticalCenter
            }

            Rectangle {
                width: 1
                height: 16
                color: Qt.rgba(Theme.surfaceVariantText.r, Theme.surfaceVariantText.g,
                               Theme.surfaceVariantText.b, 0.38)
                anchors.verticalCenter: parent.verticalCenter
            }

            Rectangle {
                width: 24
                height: 24
                radius: 12
                color: Qt.rgba(Theme.secondary.r, Theme.secondary.g, Theme.secondary.b, 0.14)
                anchors.verticalCenter: parent.verticalCenter

                DankIcon {
                    anchors.centerIn: parent
                    name: "lan"
                    size: 15
                    color: Theme.secondary
                }
            }

            StyledText {
                text: root.localDisplay
                color: Theme.widgetTextColor
                font.pixelSize: root.textSize
                isMonospace: true
                verticalAlignment: Text.AlignVCenter
                anchors.verticalCenter: parent.verticalCenter
            }
        }
    }

    verticalBarPill: Component {
        Column {
            spacing: Theme.spacingXXS
            anchors.centerIn: parent

            DankIcon {
                name: "public"
                size: 16
                color: root.publicLookupEnabled ? Theme.info : Theme.surfaceVariantText
            }

            DankIcon {
                name: "lan"
                size: 16
                color: Theme.secondary
            }
        }
    }

    popoutWidth: 420
    popoutHeight: root.publicLookupEnabled ? 240 : 290
    popoutContent: Component {
        PopoutComponent {
            headerText: qsTr("Network identity")
            detailsText: qsTr("Current public and local IP addresses")
            showCloseButton: true

            Item {
                width: parent.width
                implicitHeight: identityControls.implicitHeight

                Column {
                    id: identityControls
                    width: parent.width
                    spacing: Theme.spacingM

                    DankToggle {
                        width: parent.width
                        checked: root.publicLookupEnabled
                        text: qsTr("Public IP check")
                        description: qsTr("Uses HTTPS providers. Turn off to stop all public-IP network requests.")
                        onToggled: isEnabled => root.setPublicLookupEnabled(isEnabled)
                    }

                    Row {
                        width: parent.width
                        height: 30
                        spacing: Theme.spacingS

                        Rectangle {
                            width: 28
                            height: 28
                            radius: 14
                            color: Qt.rgba(Theme.info.r, Theme.info.g, Theme.info.b, 0.14)

                            DankIcon {
                                anchors.centerIn: parent
                                name: "public"
                                size: 17
                                color: root.publicLookupEnabled ? Theme.info : Theme.surfaceVariantText
                            }
                        }

                        StyledText {
                            width: parent.width - 28 - Theme.spacingS
                            text: root.publicDisplay
                            color: root.publicLookupEnabled ? Theme.surfaceText : Theme.surfaceVariantText
                            font.pixelSize: Theme.fontSizeMedium
                            isMonospace: true
                            elide: Text.ElideRight
                            anchors.verticalCenter: parent.verticalCenter
                        }
                    }

                    Row {
                        width: parent.width
                        height: 30
                        spacing: Theme.spacingS

                        Rectangle {
                            width: 28
                            height: 28
                            radius: 14
                            color: Qt.rgba(Theme.secondary.r, Theme.secondary.g,
                                           Theme.secondary.b, 0.14)

                            DankIcon {
                                anchors.centerIn: parent
                                name: "lan"
                                size: 17
                                color: Theme.secondary
                            }
                        }

                        StyledText {
                            width: parent.width - 28 - Theme.spacingS
                            text: root.localDisplay
                            color: Theme.surfaceText
                            font.pixelSize: Theme.fontSizeMedium
                            isMonospace: true
                            elide: Text.ElideRight
                            anchors.verticalCenter: parent.verticalCenter
                        }
                    }

                    StyledText {
                        visible: !root.publicLookupEnabled
                        width: parent.width
                        text: qsTr("Public-IP checking stays off after restart until you turn it on here.")
                        color: Theme.surfaceVariantText
                        font.pixelSize: Theme.fontSizeSmall
                        wrapMode: Text.Wrap
                    }
                }
            }
        }
    }
}
