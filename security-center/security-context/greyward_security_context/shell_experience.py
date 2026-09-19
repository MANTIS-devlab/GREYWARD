"""One bounded presentation of posture, activity and actionable conditions.

This is a projection, not a second security evaluator or evidence store.
"""
import datetime as dt
import hashlib
from pathlib import Path

RANK = {"CRITICAL": 0, "ACTION": 1, "WARNING": 2, "INFO": 3}


def item(key, kind, severity, title, detail, route, actions=(), **extra):
    return {"id": key, "kind": kind, "severity": severity, "title": title,
            "detail": detail, "route": route, "actions": list(actions),
            "timeout_ms": 0 if severity == "CRITICAL" else 10000,
            **extra}


def action(key, label):
    return {"id": key, "label": label}


def build_experience(shell, capsule, devices, usb_error, files, network, operations=None, previous_items=()):
    operations = operations or {}
    pending, activity, details = [], [], []
    for signal in capsule.get("signals", []):
        category, state = signal.get("category"), signal.get("state")
        if category == "ACTIVE_SENSOR" and state == "ACTIVE":
            camera = str(signal.get("signal_id", "")).startswith("camera")
            activity.append({"id": signal["signal_id"], "kind": "camera" if camera else "microphone",
                             "icon": "videocam" if camera else "mic", "title": "Camera in use" if camera else "Microphone in use",
                             "detail": signal.get("application") or "Application could not be identified", "route": "privacy"})
        elif category == "ACTIVE_SENSOR" and state in {"UNAVAILABLE", "STALE"}:
            if not any(x["id"] == "sensor-unavailable" for x in pending):
                pending.append(item("sensor-unavailable", "provider", "WARNING", "Privacy activity unavailable", "Live microphone and camera use cannot be confirmed.", "privacy"))
        elif category == "DEGRADED_PROTECTION" and state == "DEGRADED":
            pending.append(item("secure-dns", "provider", "WARNING", "Secure DNS needs attention", signal.get("detail", "Encrypted DNS is unavailable."), "network"))
        elif category == "SENSITIVE_DATA" and state == "ACTIVE":
            pending.append(item(signal.get("event_id", "clipboard"), "clipboard", "ACTION", "Sensitive text on clipboard", "Clear it when you have finished pasting.", "privacy",
                                [action("clear_clipboard", "Clear clipboard")] if "clear_clipboard" in signal.get("actions", []) else []))

    if usb_error:
        pending.append(item("usb-unavailable", "provider", "WARNING", "Device protection unavailable", "Connected device permissions cannot be confirmed.", "devices"))
        for ref, op in operations.items():
            if op.get('state') in {'PENDING', 'VERIFYING', 'INDETERMINATE'}:
                pending.append(item('usb:' + ref, 'usb', 'ACTION', 'Device approval', op.get('detail') or 'Waiting for authorization…', 'devices',
                                    connection_ref=ref, operation=op['state']))
    else:
        for device in devices[:64]:
            if device.get("controller"):
                continue
            ref = device.get("connection_ref", "")
            op = operations.get(ref, {})
            if device.get("state") in {"BLOCK", "REJECT"}:
                actions = [action("trust_once", "Trust once")]
                if device.get("can_persist"):
                    actions.append(action("trust_always", "Trust always"))
                busy = op.get("state") in {"PENDING", "VERIFYING", "INDETERMINATE"}
                pending.append(item("usb:" + ref, "usb", "ACTION", device.get("name") or "USB device",
                                    op.get("detail") or "Blocked until you approve this device.", "devices",
                                    [] if busy else actions, connection_ref=ref, operation=op.get("state", "IDLE"),
                                    notification_title="USB device needs approval", notification_detail=(device.get('name') or 'USB device') + ': ' + (op.get('detail') or 'Blocked until you approve it.')))
            elif device.get("authorized"):
                activity.append({"id": "usb:" + ref, "kind": "usb", "icon": "usb", "title": device.get("name") or "USB device",
                                 "detail": "Trusted device connected" if device.get("trusted") else "Allowed for this connection", "route": "devices"})

    opensnitch = network.get("opensnitch", {})
    if shell.get('firewall', {}).get('state') in {'UNAVAILABLE', 'DISABLED', 'INACTIVE'}:
        pending.append(item('firewall-unavailable', 'provider', 'WARNING', 'Firewall needs attention', 'Firewall protection cannot be confirmed.', 'network'))
    if opensnitch.get("state") in {"DEGRADED", "UNAVAILABLE"}:
        pending.append(item("network-protection", "provider", "WARNING", "Network protection needs attention", opensnitch.get("detail") or "Application protection cannot be confirmed.", "network"))
    threat = network.get("threat_intel") or {}
    if threat.get("enabled") and threat.get("state") in {"ERROR", "STALE", "UNAVAILABLE"}:
        pending.append(item("threat-feed", "provider", "WARNING", "Threat blocking needs attention", "The threat feed is unavailable or outdated.", "threats"))
    for event in network.get("activity", []):
        if event.get("decision") != "BLOCKED" or not event.get("threat"):
            continue
        try:
            timestamp = dt.datetime.fromisoformat(str(event.get("occurred_at") or event.get("timestamp")).replace("Z", "+00:00"))
            if (dt.datetime.now(dt.timezone.utc) - timestamp).total_seconds() > 300: continue
        except (TypeError, ValueError):
            continue
        app = str(event.get("application") or "An application")[:80]
        key = hashlib.sha256((app + str(event["threat"].get("ip"))).encode()).hexdigest()[:24]
        if not any(x["id"] == "network:" + key for x in pending):
            pending.append(item("network:" + key, "network", "INFO", "Malicious connection blocked", app + " was prevented from reaching a known threat.", "threats", timeout_ms=8000))

    for detection in files.get("detections", [])[:64]:
        if detection.get("state") not in {"DETECTED", "QUARANTINE_FAILED", "QUARANTINE_PENDING"}: continue
        reference = str(detection.get("detection_id") or detection.get("id") or "")
        name = Path(str(detection.get("original_path") or detection.get("path") or "A file")).name[:100]
        pending.append(item("detection:" + reference, "malware", "CRITICAL", "Threat detected", name + " needs review in File Security.", "files"))
    scan = files.get("active_scan") or {}
    if scan:
        activity.append({"id": "scan:" + str(scan.get("operation_id", "active")), "kind": "scan", "icon": "search", "title": "Scanning files", "detail": "View scan progress in Security Center", "route": "files"})
    elif files.get("state") == "UNAVAILABLE":
        pending.append(item("scanner-unavailable", "provider", "WARNING", "File protection unavailable", "Scan status cannot be confirmed.", "files"))
    latest = files.get("latest_scan") or {}
    if not scan and latest.get("ended_at") and not latest.get("detection_count"):
        try:
            ended = dt.datetime.fromisoformat(str(latest['ended_at']).replace('Z', '+00:00'))
            recent = 0 <= (dt.datetime.now(dt.timezone.utc) - ended).total_seconds() < 30
        except (TypeError, ValueError):
            recent = False
        if recent:
            state = latest.get('state')
            title = 'Scan finished' if state == 'COMPLETED' else 'Scan cancelled' if state == 'CANCELLED' else 'Scan could not finish'
            pending.append(item('scan-result:' + str(latest.get('operation_id')), 'operation', 'INFO' if state in {'COMPLETED', 'CANCELLED'} else 'WARNING', title,
                                'No known threats found.' if state == 'COMPLETED' else latest.get('detail') or 'Review the result in File Security.', 'files', timeout_ms=4000))
    if shell.get("malware", {}).get("state") in {"OUTDATED", "UNAVAILABLE"}:
        pending.append(item("definitions", "provider", "WARNING", "Malware protection needs attention", "Check the scanning engine and threat definitions.", "files"))
    for event in shell.get("notification_events", []):
        if str(event.get("event_id", "")).startswith("usbguard-"): continue
        observed_change = str(event.get("event_id", "")).startswith("persistence-")
        pending.append(item(str(event["event_id"]), "security", "INFO" if observed_change else "WARNING", event.get("title") or "Security change detected", event.get("detail") or "Review the recorded change.", "overview"))
    update = shell.get("update", {})
    if update.get("active") or update.get("phase") == "READY_TO_RESTART":
        progress = update.get('progress')
        detail = str(progress) + '% completed' if isinstance(progress, (int, float)) else 'Review updates in Security Center'
        activity.append({"id": "updates", "kind": "update", "icon": "system_update", "title": "Restart required" if update.get("phase") == "READY_TO_RESTART" else "Updating your system", "detail": detail, "route": "updates"})
    elif update.get("phase") == "FAILED":
        pending.append(item("update-failed", "operation", "WARNING", "Update could not finish", update.get("error") or "Review the update result before retrying.", "updates"))
    for label, value in (("Network protection", opensnitch.get("state")), ("Firewall", shell.get("firewall", {}).get("state")), ("Secure DNS", shell.get("secure_dns", {}).get("state")), ("Privacy profile", shell.get("privacy", {}).get("profile"))):
        copy = {'SECUREPROVIDER': 'Encrypted', 'SECURE_PROVIDER': 'Encrypted', 'SYSTEM': 'System default'}
        details.append({"label": label, "value": copy.get(str(value).upper(), str(value or "UNAVAILABLE").replace("_", " ").capitalize())})
    # Delivery's last confirmed presentation is evidence of an earlier warning,
    # never evidence of current permission or resolution. Provider loss cannot
    # erase it or leave mutation actions enabled.
    present = {entry['id'] for entry in pending}
    for previous in previous_items:
        unavailable = (previous.get('kind') == 'usb' and usb_error) or (previous.get('kind') == 'malware' and files.get('state') == 'UNAVAILABLE')
        if unavailable and previous.get('id') not in present:
            detail = 'Current state cannot be confirmed. Review when protection is available.'
            pending.append({**previous, 'actions': [], 'stale': True, 'detail': detail, 'notification_detail': detail})
    pending = sorted({x["id"]: x for x in pending}.values(), key=lambda x: (RANK[x["severity"]], x["id"]))[:64]
    grouped = []
    for entry in activity:
        existing = next((x for x in grouped if x['kind'] == entry['kind']), None)
        if existing and entry['kind'] in {'microphone', 'camera'}:
            existing['members'].append(entry['detail'])
            existing['detail'] = ', '.join(dict.fromkeys(existing['members']))
        else:
            grouped.append({**entry, 'members': [entry['detail']]})
    activity = grouped
    posture = shell.get("posture", {}).get("state", "UNAVAILABLE")
    severity = pending[0]["severity"] if pending else ("WARNING" if posture == "REVIEW NEEDED" else "INFO")
    label = "Threat needs attention" if severity == "CRITICAL" else "Action needed" if severity == "ACTION" else "Review needed" if severity == "WARNING" else "Protected" if posture in {"SECURE", "PROTECTED"} else "Status unavailable"
    reason = ("Review the detected threat" if severity == "CRITICAL" else "A decision is required" if severity == "ACTION" else "Some protection needs attention") if pending and severity != 'INFO' else "Review system checks" if posture == "REVIEW NEEDED" else "Protection is operating" if posture in {"SECURE", "PROTECTED"} else "Security providers cannot confirm current status"
    return {"schema": "greyward.security.experience/v1", "fresh_until": shell.get("fresh_until"),
            "posture": posture, "label": label, "reason": reason, "severity": severity,
            "items": pending, "activity": activity[:32], "details": details,
            "capabilities": shell.get("capabilities", {}), "privacy": shell.get("privacy", {})}
