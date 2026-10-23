.pragma library

// Read-only presentation of the existing bounded summary. No new collection,
// timers or policy decisions. Unknown/stale evidence can never become green.
function token(value) { return String(value || "").trim().toUpperCase().replace(/[ -]+/g, "_"); }
function detail(presentation, label) {
    return (presentation.details || []).find(function(row) { return row.label === label; }) || null;
}
function detailTone(row) {
    // v1 details expose a closed English display vocabulary, not raw states.
    // Prefer a future explicit state if provided; never match substrings or
    // interpret arbitrary/localized display text as positive evidence.
    const state = token(row && Object.prototype.hasOwnProperty.call(row, "state") ? row.state : row?.value);
    if (["SECURE", "PROTECTED", "HEALTHY", "ACTIVE", "OPERATING", "ENCRYPTED"].includes(state)) return "positive";
    if (["FAILED", "ERROR", "INSECURE", "COMPROMISED", "DISABLED", "STOPPED", "INACTIVE"].includes(state)) return "critical";
    return "warning";
}
function notices(presentation, section) {
    return (presentation.notification_items || []).filter(function(item) {
        return section === "protection" || item.route === section || (section === "updates" && item.kind === "update");
    });
}
function protectionTone(presentation, fresh) {
    if (!fresh || presentation.loading === true) return "warning";
    const state = token(presentation.posture), severity = token(presentation.severity);
    if (severity === "CRITICAL" || ["INSECURE", "COMPROMISED"].includes(state)
            || notices(presentation, "protection").some(function(item) { return item.severity === "CRITICAL"; })) return "critical";
    if (severity !== "INFO" || (presentation.activity || []).some(function(item) { return item.id === "definitions-initializing"; })) return "warning";
    return ["SECURE", "PROTECTED"].includes(state) ? "positive" : "warning";
}
function card(section, presentation, fresh, available) {
    const result = {tone:"warning", value:"Status unavailable", detail:"Current evidence cannot be confirmed. Open Security Center for details.", rows:[]};
    if (!available) {
        result.value = "Integration unavailable";
        result.detail = "Enable the Security Center integration in Plugins.";
        return result;
    }
    if (!fresh) return result;
    const pending = notices(presentation, section);
    if (section === "protection") {
        result.tone = protectionTone(presentation, fresh);
        result.value = presentation.label || "Status unavailable";
        result.detail = presentation.reason || "Review the observed system checks in Security Center.";
        const devices = detail(presentation, "Device protection");
        if (devices) result.rows.push({label:"USB protection", value:devices.value, tone:detailTone(devices)});
        result.rows.push({label:"Attention", value:pending.length ? String(pending.length) + " to review" : "No pending items", tone:pending.length ? "warning" : "info"});
        const activity = (presentation.activity || []).filter(function(item) { return ["camera", "microphone", "screen"].includes(item.kind); });
        result.rows.push({label:"Privacy activity", value:activity.length ? String(activity.length) + " active indicators" : "No active indicators", tone:"info"});
    } else if (section === "network") {
        const firewall = detail(presentation, "Firewall"), apps = detail(presentation, "Network protection"), dns = detail(presentation, "Secure DNS");
        const dnsState = token(dns && Object.prototype.hasOwnProperty.call(dns, "state") ? dns.state : dns?.value);
        const vpn = detail(presentation, "VPN");
        const vpnState = token(vpn?.state);
        // Explicit observed absence is required for Off. DNS ownership alone
        // cannot establish the absence of a split-tunnel VPN.
        const vpnActive = vpn ? vpnState === "ACTIVE" : ["VPNOWNED", "VPN_OWNED"].includes(dnsState);
        const vpnValue = vpnActive ? "VPN active" : vpnState === "OFF" ? "VPN off" : "VPN status unavailable";
        const attention = pending.filter(function(item) { return ["WARNING", "ACTION", "CRITICAL"].includes(item.severity); });
        result.rows = [{label:"Firewall", value:firewall?.value || "Unavailable", tone:detailTone(firewall)},
                       {label:"Application traffic", value:apps?.value || "Unavailable", tone:detailTone(apps)}];
        result.rows.push({label:"VPN", value:vpnActive ? "Active" : vpnState === "OFF" ? "Off" : "Unavailable", tone:"info"});
        const critical = attention.some(function(item) { return item.severity === "CRITICAL"; }) || result.rows.some(function(row) { return row.tone === "critical"; });
        result.tone = critical ? "critical" : attention.length || result.rows.slice(0,2).some(function(row) { return row.tone !== "positive"; }) ? "warning" : "positive";
        const inactive = [firewall, apps].some(function(row) { return ["DISABLED", "STOPPED", "INACTIVE"].includes(token(row?.state ?? row?.value)); });
        const complete = firewall !== null && apps !== null;
        result.value = result.tone === "positive" ? "Protection active" : inactive ? "Protection inactive" : critical ? "Needs attention" : attention.length || complete ? "Review needed" : "Status unavailable";
        result.detail = vpnValue + (attention[0]?.detail ? " · " + attention[0].detail : !complete ? " · Waiting for filtering evidence." : result.tone !== "positive" ? " · Review filtering evidence." : "");
    } else {
        const operation = (presentation.activity || []).find(function(item) { return item.kind === "update"; });
        const failed = pending.some(function(item) { return item.id === "update-failed" || item.severity === "CRITICAL"; });
        result.tone = failed ? "critical" : "warning";
        result.value = operation?.title || pending[0]?.title || "Check updates";
        result.detail = operation?.detail || pending[0]?.detail || "Open Update Center for available updates and the last check.";
        result.rows = [{label:"Update status", value:operation ? operation.title : failed ? "Could not finish" : "Review in Update Center", tone:failed ? "critical" : "info"}];
        // The summary has no idle update count/last-check result. Do not invent
        // a number, progress bar or an Up to date state from overall posture.
    }
    return result;
}
