import QtQuick
import Quickshell
import Quickshell.Wayland
import qs.Common
import qs.Services

Scope {
    id: root
    property string pluginId: "greywardSecure"
    property var pluginService: null
    readonly property string busName: "systems.mantis.greyward.SecurityContext1"
    readonly property string objectPath: "/systems/mantis/greyward/SecurityContext1"
    readonly property string systemBusName: "systems.mantis.greyward.ApplicationSecurity1"
    readonly property string systemObjectPath: "/systems/mantis/greyward/ApplicationSecurity1"
    readonly property string usbguardApproval: "/usr/libexec/greyward-usbguard-approval"
    readonly property string instanceToken: Math.random().toString(36).slice(2)
    // One owner survives output/widget changes. A new enable/reload receives
    // a different nonce so late callbacks cannot replace its operations.
    readonly property string processCommandPrefix: "greywardSecure.daemon." + instanceToken + "."
    // The shell projection itself has a 30-second bounded freshness lease.
    // Do not place recovery on the same edge: a missed D-Bus signal previously
    // made the pill discard its live content before the fallback read returned.
    readonly property int capsuleWatchdogIntervalMs: 5000
    property var presentation: ({items: [], activity: [], details: []})
    property bool subscriptionPending: false
    property bool requestPending: false
    property int requestGeneration: 0
    property string subscriptionId: ""
    property bool initialized: false
    property var previousIds: []
    property string attentionId: ""
    property bool actionPending: false
    property string actionMessage: ""
    property int usbActionGeneration: 0
    property bool launchPending: false
    property int launchChecks: 0
    property string launchState: ""
    property string launchMessage: ""
    property double clockNow: Date.now()
    readonly property bool freshnessLeaseValid: initialized && Date.parse(presentation.fresh_until || "") > clockNow
    readonly property var primaryItem: presentation.notification_items?.[0] ?? null
    function decodeGdbusJson(stdout) {
        const match = String(stdout || "").trim().match(/^\(\s*'([\s\S]*)'\s*,\s*\)$/);
        if (!match) return null;
        try { return JSON.parse(match[1].replace(/\\'/g, "'").replace(/\\\\/g, "\\")); } catch (error) { return null; }
    }
    function variantString(value) { return '"' + String(value).replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"'; }
    function processCommandId(operation) { return root.processCommandPrefix + operation; }
    function call(method, args, callback) {
        Proc.runCommand(root.processCommandId(method), ["/usr/bin/gdbus", "call", "--session", "--timeout", "6", "--dest", busName, "--object-path", objectPath, "--method", busName + "." + method].concat(args || []), function(stdout, code) {
            callback(code === 0 ? root.decodeGdbusJson(stdout) : null);
        }, 0, 10000, root);
    }
    function readProtectedDesktopPosture(generation, callback) {
        Proc.runCommand(root.processCommandId("system-posture." + generation), ["/usr/bin/gdbus", "call", "--system", "--timeout", "6", "--dest", systemBusName, "--object-path", systemObjectPath, "--method", "systems.mantis.greyward.ApplicationSecurity1.GetSystemPosture"], function(stdout, code) {
            const posture = code === 0 ? root.decodeGdbusJson(stdout) : null;
            callback(posture?.schema === "greyward.security.system-posture/v1" ? posture : null);
        }, 0, 10000, root);
    }
    function applyProtectedDesktopPosture(posture) {
        const now = Date.now();
        const loading = posture.loading === true;
        const state = String(posture.state || "UNAVAILABLE").toUpperCase();
        // The aggregate fallback has no per-provider evidence and cannot
        // resolve pending actions. A positive reply must not replace a rich
        // snapshot that is still within its original authority lease. Never
        // renew that lease, and never retain it over a new negative finding.
        const previous = root.presentation || {};
        if (!loading && ["SECURE", "PROTECTED"].includes(state)
                && Number(posture.fresh_for_ms || 0) > 0
                && root.initialized && Date.parse(previous.fresh_until || "") > now
                && (previous.details || []).length > 0) {
            root.clockNow = now;
            return;
        }
        const label = loading ? qsTr("Connecting") : ["SECURE", "PROTECTED"].includes(state) ? qsTr("Protected") : state === "REVIEW NEEDED" ? qsTr("Review needed") : qsTr("Status unavailable");
        const reason = loading ? qsTr("Reading system security status") : state === "REVIEW NEEDED" ? qsTr("Review the system findings in Security Center") : ["SECURE", "PROTECTED"].includes(state) ? qsTr("System security status is confirmed") : qsTr("Current system security status cannot be confirmed");
        const freshMs = Math.max(0, Number(posture.fresh_for_ms || 0));
        const displayMs = Math.max(freshMs, Number(posture.display_for_ms || 0));
        root.presentation = {
            schema: "greyward.security.experience/v1",
            posture: state,
            loading,
            label,
            reason,
            severity: state === "REVIEW NEEDED" ? "WARNING" : "INFO",
            items: [], notification_items: [], activity: [], details: [], operations: [],
            fresh_until: new Date(now + (loading ? Math.max(freshMs, 1000) : freshMs)).toISOString(),
            display_fresh_until: new Date(now + (loading ? Math.max(displayMs, 6000) : displayMs)).toISOString(),
        };
        root.initialized = true;
        root.clockNow = now;
        root.attentionId = "";
        root.previousIds = [];
    }
    function markPostureUnavailable() {
        const now = Date.now();
        const previous = root.presentation || {};
        const previousPosture = String(previous.posture || "").toUpperCase();
        const previousDisplayUntil = Date.parse(previous.display_fresh_until || previous.fresh_until || "");
        if (root.initialized && ["SECURE", "PROTECTED", "REVIEW NEEDED"].includes(previousPosture)
                && Number.isFinite(previousDisplayUntil) && previousDisplayUntil > now) {
            root.presentation = {
                schema: "greyward.security.experience/v1",
                posture: previousPosture,
                label: previous.label || qsTr("Status unavailable"),
                reason: qsTr("The last confirmed status is shown. Actions are paused while GREYWARD refreshes it."),
                severity: previous.severity || "INFO",
                items: [], notification_items: [], activity: [], details: [], operations: [],
                fresh_until: new Date(now).toISOString(),
                display_fresh_until: new Date(Math.min(previousDisplayUntil, now + 12000)).toISOString(),
            };
            root.clockNow = now;
            root.attentionId = "";
            root.previousIds = [];
            return;
        }
        root.presentation = {
            schema: "greyward.security.experience/v1",
            posture: "UNAVAILABLE",
            label: qsTr("Status unavailable"),
            reason: qsTr("Current system security status cannot be confirmed"),
            severity: "INFO",
            items: [], notification_items: [], activity: [], details: [], operations: [],
            fresh_until: new Date(now).toISOString(),
            display_fresh_until: new Date(now).toISOString(),
        };
        root.initialized = true;
        root.clockNow = now;
        root.attentionId = "";
        root.previousIds = [];
    }
    function refreshSummary() {
        if (requestPending) return;
        requestPending = true;
        const generation = ++requestGeneration;
        requestTimeout.restart();
        call("GetShellPresentation", [], function(next) {
            if (generation !== root.requestGeneration) return;
            if (!next || next.schema !== "greyward.security.experience/v1") {
                readProtectedDesktopPosture(generation, function(posture) {
                    if (generation !== root.requestGeneration) return;
                    requestTimeout.stop(); root.requestPending = false;
                    if (posture) root.applyProtectedDesktopPosture(posture);
                    else root.markPostureUnavailable();
                });
                return;
            }
            requestTimeout.stop(); root.requestPending = false; root.clockNow = Date.now();
            const nextFreshUntil = Date.parse(next.fresh_until || "");
            const eligibleItems = next.notification_items || [];
            const ids = eligibleItems.filter(item => item.severity !== "INFO").map(item => item.id);
            const newItem = ids.find(id => root.previousIds.indexOf(id) < 0);
            if (root.initialized && newItem && (!root.primaryItem || eligibleItems[0]?.id === newItem)) {
                root.attentionId = newItem; attentionTimer.restart();
            }
            root.previousIds = ids;
            root.presentation = next; root.initialized = Number.isFinite(nextFreshUntil);
            const result = (next.operations || []).find(op => op.state === "COMPLETE");
            if (result) { root.actionMessage = result.detail; messageTimer.restart(); }
        });
    }
    function subscribe() {
        if (subscriptionId || subscriptionPending || !DMSService.isConnected || typeof DMSService.dbusSubscribe !== "function") return;
        subscriptionPending = true;
        DMSService.dbusSubscribe("session", busName, objectPath, busName, "ShellSummaryChanged", function(response) {
            root.subscriptionPending = false;
            if (response?.result?.subscriptionId) root.subscriptionId = String(response.result.subscriptionId);
        });
    }
    function activateSecurityCenterWindow() {
        for (const window of (ToplevelManager?.toplevels?.values || [])) {
            if (["greyward-security-center", "systems.mantis.greyward.securitycenter"].includes(String(window?.appId || "").toLowerCase()) && typeof window.activate === "function") { window.activate(); return; }
        }
    }
    function findSecurityCenterWindow() {
        const windows = Array.from(ToplevelManager?.toplevels?.values || []);
        return windows.find(window => ["greyward-security-center", "systems.mantis.greyward.securitycenter"].includes(String(window?.appId || "").toLowerCase())) || null;
    }
    function finishSecurityCenterLaunch(state, message) {
        launchPending = false;
        launchState = state;
        launchMessage = message;
        launchWindowTimer.stop();
        launchMessageTimer.restart();
    }
    function checkSecurityCenterLaunch() {
        if (!launchPending) { launchWindowTimer.stop(); return; }
        launchChecks += 1;
        const window = findSecurityCenterWindow();
        if (window) {
            try { if (typeof window.activate === "function") window.activate(); } catch (error) {}
            finishSecurityCenterLaunch("success", qsTr("Security Center opened"));
        } else if (launchChecks >= 48) {
            finishSecurityCenterLaunch("error", qsTr("Security Center did not open. Check that it is installed, then try again."));
        }
    }
    function openRoute(route, resourceRef) {
        activateSecurityCenterWindow();
        const command = ["/usr/bin/greyward-security-center-route", route || "overview"];
        if (route === "protected-data" && /^resource_[0-9a-f]{64}$/.test(String(resourceRef || ""))) command.push(resourceRef);
        Quickshell.execDetached(command);
    }
    function openSecurityCenter() {
        if (launchPending) {
            launchMessage = qsTr("Opening Security Center…");
            launchMessageTimer.restart();
            return;
        }
        const existingWindow = findSecurityCenterWindow();
        if (existingWindow) {
            try {
                if (typeof existingWindow.activate === "function") existingWindow.activate();
                launchState = "success";
                launchMessage = qsTr("Security Center brought to front");
            } catch (error) {
                launchState = "error";
                launchMessage = qsTr("Security Center is open, but could not be focused");
            }
            launchMessageTimer.restart();
            return;
        }
        launchChecks = 0;
        launchPending = true;
        launchState = "opening";
        launchMessage = qsTr("Opening Security Center…");
        launchMessageTimer.stop();
        launchWindowTimer.start();
        try {
            const desktopEntry = DesktopEntries.heuristicLookup("systems.mantis.greyward.securitycenter");
            if (!desktopEntry || !desktopEntry.command) {
                finishSecurityCenterLaunch("error", qsTr("Security Center is missing from the application menu."));
                return;
            }
            // Use DMS's normal desktop-entry path so protected-session launch handling applies.
            SessionService.launchDesktopEntry(desktopEntry);
        } catch (error) {
            finishSecurityCenterLaunch("error", qsTr("Could not start Security Center. Try again."));
        }
    }
    function runAction(item, action) {
        if (!freshnessLeaseValid || actionPending) return;
        if (action.id === "open") { openRoute(item.route, item.resource_ref); return; }
        actionPending = true;
        actionTimeout.restart();
        const finish = function(result) {
            actionTimeout.stop();
            root.actionPending = false;
            root.actionMessage = result?.ok ? result.state === "PENDING" ? qsTr("Waiting for authorization…") : qsTr("Done") : result?.detail || qsTr("The action could not be completed. Check Security Center.");
            messageTimer.restart(); root.refreshSummary();
        };
        if (action.id === "trust_once" || action.id === "trust_always") {
            const mode = action.id === "trust_once" ? "once" : "always";
            actionTimeout.stop();
            root.actionMessage = qsTr("Waiting for administrator approval…");
            usbActionTimeout.restart();
            // USBGuard's Polkit request may wait 120 seconds. DMS Proc's
            // default timeout is 10 seconds, so give each reviewed request a
            // unique ID and a bounded timeout that covers lookup, approval,
            // and readback without allowing one device's callback to replace
            // another's.
            Proc.runCommand(root.processCommandId("usb." + mode + "." + String(item.connection_ref) + "." + (++usbActionGeneration)),
                [usbguardApproval, String(item.connection_ref), mode],
                function(stdout, code) {
                    usbActionTimeout.stop();
                    root.actionPending = false;
                    let result = null;
                    try { result = JSON.parse(String(stdout || "").trim()); } catch (error) {}
                    const confirmed = code === 0 && result?.ok === true && result?.state === "COMPLETE";
                    root.actionMessage = confirmed ? result.detail || qsTr("USB permission confirmed") : result?.detail || qsTr("USB approval could not be confirmed. The device remains blocked.");
                    messageTimer.restart(); root.refreshSummary();
                }, 0, 150000, root);
        }
        else if (action.id === "clear_clipboard") call("ClearClipboard", [variantString(item.id)], finish);
        else { actionPending = false; actionTimeout.stop(); }
    }
    function setPrivacyProfile(profile) {
        if (!freshnessLeaseValid || actionPending || !presentation.capabilities?.privacy_profile_change) return;
        actionPending = true;
        actionTimeout.restart();
        call("SetPrivacyProfile", [variantString(profile)], function(result) {
            actionTimeout.stop();
            root.actionPending = false;
            root.actionMessage = result?.ok && result.profile === profile ? qsTr("Privacy profile applied") : qsTr("Privacy profile could not be applied");
            messageTimer.restart(); root.refreshSummary();
        });
    }
    Timer { id: summaryChange; interval: 60; onTriggered: root.refreshSummary() }
    Timer { id: requestTimeout; interval: 15000; onTriggered: { ++root.requestGeneration; root.requestPending = false; root.markPostureUnavailable(); } }
    Timer { id: actionTimeout; interval: 7000; onTriggered: { root.actionPending = false; root.actionMessage = qsTr("The result is not confirmed. Check Security Center before retrying."); messageTimer.restart(); root.refreshSummary(); } }
    Timer { id: usbActionTimeout; interval: 160000; onTriggered: { root.actionPending = false; root.actionMessage = qsTr("Authorization timed out. The device remains blocked."); messageTimer.restart(); root.refreshSummary(); } }
    Timer { id: launchWindowTimer; interval: 250; repeat: true; onTriggered: root.checkSecurityCenterLaunch() }
    Timer { id: launchMessageTimer; interval: 7000; onTriggered: { root.launchState = ""; root.launchMessage = "" } }
    Timer { id: attentionTimer; interval: 10000; onTriggered: root.attentionId = "" }
    Timer { id: messageTimer; interval: 5000; onTriggered: root.actionMessage = "" }
    Timer { interval: 1000; running: true; repeat: true; onTriggered: root.clockNow = Date.now() }
    Timer { interval: root.capsuleWatchdogIntervalMs; running: true; repeat: true; onTriggered: { root.subscribe(); root.refreshSummary(); } }
    Connections {
        target: DMSService
        function onDbusSignalReceived(id, data) { if (String(id) === root.subscriptionId) summaryChange.restart(); }
        function onConnectionStateChanged() {
            if (!DMSService.isConnected) { root.subscriptionId = ""; root.subscriptionPending = false; }
            else { root.subscribe(); root.refreshSummary(); }
        }
    }
    Component.onCompleted: { subscribe(); refreshSummary(); }
    Component.onDestruction: { if (subscriptionId && DMSService.isConnected) DMSService.dbusUnsubscribe(subscriptionId); }
}
