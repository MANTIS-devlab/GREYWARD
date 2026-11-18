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
// Keep dashboard findings visible independently of notification eligibility.
function cardFindings(presentation, section) {
    const seen = new Set();
    return [...(presentation.items || []), ...(presentation.notices || []), ...(presentation.notification_items || [])].filter(function(item) {
        if (item.stale || (item.id && seen.has(item.id))) return false;
        const relevant = section === "protection" ? ["WARNING", "ACTION", "CRITICAL"].includes(item.severity)
            : section === "network" ? item.route === section || item.id === "threat-feed"
            : item.route === section || item.kind === "update";
        if (relevant && item.id) seen.add(item.id);
        return relevant;
    });
}

function card(section, presentation, fresh, available) {
    const result = {tone:"warning", signal:"unknown", value:"Status unavailable", detail:"Current evidence cannot be confirmed. Open Security Center for details.", rows:[]};
    if (!available) {
        result.value = "Integration unavailable";
        result.detail = "Enable the Security Center integration in Plugins.";
        return result;
    }
    if (!fresh || presentation.loading === true) return result;
    const pending = cardFindings(presentation, section);
    if (section === "protection") {
        result.tone = protectionTone(presentation, fresh);
        const severity = token(presentation.severity);
        const critical = result.tone === "critical" || pending.some(item => item.severity === "CRITICAL");
        const review = pending.length > 0 || ["WARNING", "ACTION"].includes(severity) || token(presentation.posture) === "REVIEW_NEEDED";
        result.signal = critical ? "critical" : review ? "warning" : result.tone === "positive" ? "positive" : "unknown";
        result.value = presentation.label || "Status unavailable";
        const newFinding = result.tone === "positive" && result.signal !== "positive";
        if (newFinding) result.value = critical ? "Threat needs attention" : "Review needed";
        result.detail = newFinding
            ? pending.find(item => item.severity === (critical ? "CRITICAL" : "ACTION"))?.detail
                || pending[0]?.detail || "Review security findings."
            : presentation.reason || "Review the observed system checks in Security Center.";
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
        result.signal = !complete && !attention.length && !critical ? "unknown" : result.tone;
        result.value = result.tone === "positive" ? "Protection active" : inactive ? "Protection inactive" : critical ? "Needs attention" : attention.length || complete ? "Review needed" : "Status unavailable";
        result.detail = vpnValue + (attention[0]?.detail ? " · " + attention[0].detail : !complete ? " · Waiting for filtering evidence." : result.tone !== "positive" ? " · Review filtering evidence." : "");
    } else {
        const operation = (presentation.activity || []).find(function(item) { return item.kind === "update"; });
        const failure = pending.find(item => item.id === "update-failed" || item.severity === "CRITICAL");
        const restart = pending.find(item => item.id === "updates-restart");
        const available = pending.find(item => item.id === "updates-security" || ["WARNING", "ACTION"].includes(item.severity));
        const current = failure || restart || operation || available;
        result.tone = failure ? "critical" : "warning";
        result.signal = failure ? "critical" : restart ? "warning" : operation ? "busy" : available ? "warning" : "unknown";
        result.value = current?.id === "updates-security" ? "Updates available" : current?.title || "Check updates";
        result.detail = current?.detail || "Open Update Center for available updates and the last check.";
        result.rows = [{label:"Update status", value:operation ? operation.title : failure ? "Could not finish" : "Review in Update Center", tone:failure ? "critical" : "info"}];
        // The summary has no idle update count/last-check result. Do not invent
        // a number, progress bar or an Up to date state from overall posture.
    }
    return result;
}
