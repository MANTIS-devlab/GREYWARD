"""Small, redacted shell projection built from the Security Context summary."""
import datetime as dt
import re

SCHEMA = "greyward.security.shell/v1"
POSTURES = {"SECURE", "PROTECTED", "REVIEW NEEDED", "UNAVAILABLE"}
ACTIVE_UPDATE_PHASES = {
    "RESOLVING",
    "AUTHENTICATING",
    "DOWNLOADING",
    "INSTALLING",
    "VERIFYING",
    "PREPARING_RESTART",
    "RESTARTING",
}
UPDATE_PHASES = ACTIVE_UPDATE_PHASES | {"READY_TO_RESTART", "FAILED", "CANCELLED", "COMPLETE", "IDLE"}
SENSOR_KINDS = {"MICROPHONE", "CAMERA"}
SHELL_CACHE_SECONDS = 30


def _now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def _stamp(value):
    return value.isoformat().replace("+00:00", "Z")


def _text(value, limit=240):
    """Return a bounded user-facing string without leaking absolute paths."""
    text = str(value or "").replace("\x00", " ").strip()
    text = re.sub(r"(?<![\w:])/(?:[\w.-]+/)+([\w.-]+)", r"\1", text)
    return text[:limit]


def _int(value, default=0, maximum=999):
    try:
        return max(0, min(int(value), maximum))
    except (TypeError, ValueError):
        return default


def _parse_time(value):
    try:
        return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError, OverflowError):
        return dt.datetime.min.replace(tzinfo=dt.timezone.utc)


def _event_priority(event):
    kind = str(event.get("kind") or "").upper()
    notification = str(event.get("notification") or "").upper()
    state = str(event.get("state") or "").upper()
    severity = {
        "THREAT_DETECTED": 100,
        "MALWARE_DETECTED": 100,
        "PERSISTENCE_CHANGE_DETECTED": 90,
        "USB_DEVICE_BLOCKED": 88,
        "APP_CONNECTION_BLOCKED": 75,
        "MICROPHONE_STARTED": 60,
        "CAMERA_STARTED": 60,
    }.get(kind, 30)
    if state == "THREAT" or "THREAT" in kind or "MALWARE" in kind:
        severity = max(severity, 100)
    if notification == "ACTION_REQUIRED":
        severity += 20
    return severity


def _priority_event(events):
    candidates = [item for item in events if isinstance(item, dict) and item.get("event_id")]
    if not candidates:
        return None
    event = max(candidates, key=lambda item: (_event_priority(item), _parse_time(item.get("occurred_at"))))
    kind = str(event.get("kind") or "SECURITY_EVENT").upper()
    severity = "CRITICAL" if _event_priority(event) >= 100 else ("WARNING" if _event_priority(event) >= 70 else "INFO")
    return {
        "kind": kind,
        "severity": severity,
        "event_id": _text(event.get("event_id"), 96),
        "title": _text(event.get("title") or "Security event", 120),
        "detail": _text(event.get("detail") or "Review this item in Security Center."),
        "source": _text(event.get("source") or "GREYWARD Security Context", 80),
        "action_target": {
            "USB_DEVICE_BLOCKED": "devices",
            "APP_CONNECTION_BLOCKED": "network",
            "THREAT_DETECTED": "threats",
            "MALWARE_DETECTED": "threats",
            "PERSISTENCE_CHANGE_DETECTED": "overview",
        }.get(kind, "overview"),
    }


def _sensor(live_states):
    active = [
        item for item in live_states
        if isinstance(item, dict)
        and str(item.get("kind") or "").upper() in SENSOR_KINDS
        and str(item.get("state") or "").upper() in {"ACTIVE", "REVIEW NEEDED", "PROTECTED"}
    ]
    if not active:
        return {"state": "IDLE", "kind": None, "detail": None, "attribution": None}
    item = active[0]
    kind = str(item.get("kind") or "").upper()
    detail = _text(item.get("detail") or ("Microphone in use" if kind == "MICROPHONE" else "Camera in use"))
    attribution = "AMBIGUOUS" if "attribution=AMBIGUOUS" in detail.lower() else "RELIABLE"
    return {"state": kind, "kind": kind, "detail": detail, "attribution": attribution}


def _network(network):
    opensnitch = network.get("opensnitch") if isinstance(network, dict) else None
    opensnitch = opensnitch if isinstance(opensnitch, dict) else {}
    state = str(opensnitch.get("state") or "UNAVAILABLE").upper()
    if state not in {"OPERATING", "DEGRADED", "UNAVAILABLE"}:
        state = "UNAVAILABLE"
    activity = network.get("activity") if isinstance(network, dict) else []
    activity = activity if isinstance(activity, list) else []
    blocked = [
        item for item in activity
        if isinstance(item, dict) and str(item.get("decision") or "").upper() in {"BLOCKED", "DENIED", "REJECTED", "DROP"}
    ]
    application = None
    if blocked and isinstance(blocked[0], dict):
        application = _text(blocked[0].get("application"), 80) or None
    return {
        "state": state,
        "detail": _text(opensnitch.get("detail") or "Application network protection is unavailable."),
        "blocked_recent": len(blocked[:64]),
        "last_blocked_application": application,
    }


def _malware(summary, clamav):
    events = summary.get("recent_events") if isinstance(summary, dict) else []
    events = events if isinstance(events, list) else []
    threat = any(
        isinstance(item, dict)
        and (str(item.get("state") or "").upper() == "THREAT" or "THREAT" in str(item.get("kind") or "").upper())
        for item in events
    )
    value = clamav if isinstance(clamav, dict) else {}
    status = "THREAT" if threat else str(value.get("status") or "UNAVAILABLE").upper()
    if status not in {"CURRENT", "OUTDATED", "THREAT", "UNAVAILABLE"}:
        status = "UNAVAILABLE"
    return {"state": status, "database_age_seconds": _int(value.get("database_age_seconds"), 0, 31536000)}


def _usb(summary):
    value = summary.get("usb") if isinstance(summary, dict) else None
    if not isinstance(value, dict):
        return {"state": "UNAVAILABLE", "blocked_count": 0}
    state = str(value.get("state") or "UNAVAILABLE").upper()
    if state not in {"CLEAR", "BLOCKED", "UNAVAILABLE"}:
        state = "UNAVAILABLE"
    return {"state": state, "blocked_count": _int(value.get("blocked_count"), 0, 128)}


def _update(transaction):
    value = transaction if isinstance(transaction, dict) else {}
    phase = str(value.get("phase") or "IDLE").upper()
    if phase not in UPDATE_PHASES:
        phase = "UNAVAILABLE"
    progress = value.get("progress")
    try:
        progress = max(0, min(int(progress), 100)) if progress is not None else None
    except (TypeError, ValueError):
        progress = None
    return {
        "phase": phase,
        "active": phase in ACTIVE_UPDATE_PHASES,
        "progress": progress,
        "current_item": _text(value.get("current_item"), 120) or None,
        "restart_required": str(value.get("restart_required") or "UNKNOWN").upper(),
        "error": _text(value.get("error"), 160) or None,
    }


def _profile(profile, provider_fresh):
    value = profile if isinstance(profile, dict) else {}
    name = str(value.get("profile") or "UNAVAILABLE").upper()
    if name not in {"STANDARD", "PRIVATE", "TRAVEL"}:
        name = "UNAVAILABLE"
    zone = _text(value.get("firewall_zone"), 32).upper() or "UNAVAILABLE"
    available = bool(value.get("available", False)) and provider_fresh and name != "UNAVAILABLE"
    return {
        "state": name if available else "UNAVAILABLE",
        "available": available,
        "firewall": {"state": zone if provider_fresh and value.get("available", False) else "UNAVAILABLE"},
    }


def _secure_dns(value, provider_fresh):
    value = value if isinstance(value, dict) else {}
    effective = str(value.get("effective_policy") or "UNAVAILABLE")
    transport = str(value.get("effective_transport") or "UNAVAILABLE")
    provider = _text(value.get("provider"), 48) or None
    available = provider_fresh and effective not in {"", "Unavailable", "UNAVAILABLE"}
    return {
        "state": effective.upper() if available else "UNAVAILABLE",
        "transport": transport.upper() if available else "UNAVAILABLE",
        "provider": provider if available else None,
        "available": available,
    }


def build_shell_summary(summary, network=None, clamav=None, profile=None, transaction=None, now_value=None, security_digest=None, secure_dns=None):
    """Build the bounded shell contract without reading providers."""
    current = now_value or _now()
    value = summary if isinstance(summary, dict) else {}
    state = str(value.get("state") or "UNAVAILABLE").upper()
    if state not in POSTURES:
        state = "UNAVAILABLE"
    events = value.get("recent_events") if isinstance(value.get("recent_events"), list) else []
    live_states = value.get("live_states") if isinstance(value.get("live_states"), list) else []
    fresh_until = value.get("fresh_until")
    provider_fresh = state != "UNAVAILABLE" and _parse_time(fresh_until) >= current
    freshness = "UNAVAILABLE" if state == "UNAVAILABLE" else ("FRESH" if provider_fresh else ("STALE" if fresh_until else "UNAVAILABLE"))
    cached_posture = {"state": state, "review_count": _int(value.get("review_count"), 0, 999)}
    cached_security = dict((security_digest or {}).get("devices", {})) if isinstance(security_digest, dict) else {}
    if not provider_fresh:
        state = "UNAVAILABLE"
        fresh_until = _stamp(current)
    else:
        # The shell projection may collect several already-authoritative
        # providers before it is serialized. Give the resulting immutable
        # cache a short bounded lifetime independent of the posture evaluator's
        # five-second sampling window; the next Security Context poll replaces
        # it sooner in normal operation.
        fresh_until = _stamp(current + dt.timedelta(seconds=SHELL_CACHE_SECONDS))
    profile_data = _profile(profile, provider_fresh)
    review_count = max(0, _int(value.get("review_count"), 0, 999))
    unavailable_count = max(0, _int(value.get("unavailable_count"), 0, 999))
    attention_count = max(review_count + unavailable_count, _int(value.get("attention_count"), 0, 999))
    return {
        "schema": SCHEMA,
        "generated_at": _text(value.get("generated_at") or _stamp(current), 40),
        "fresh_until": _text(fresh_until or _stamp(current), 40),
        "freshness": freshness,
        "cached": {"posture": cached_posture, "security": cached_security},
        "posture": {
            "state": state,
            "review_count": attention_count if provider_fresh else None,
        },
        "priority": _priority_event(events) if provider_fresh else None,
        "notification_events": [
            {
                "event_id": _text(item.get("event_id"), 96),
                "title": _text(item.get("title") or "Security action required", 120),
                "detail": _text(item.get("detail") or "Review this item in Security Center."),
                "notification": str(item.get("notification") or "").upper(),
            }
            for item in sorted(
                [item for item in events if isinstance(item, dict) and str(item.get("notification") or "").upper() == "ACTION_REQUIRED"],
                key=lambda item: _parse_time(item.get("occurred_at")),
                reverse=True,
            )[:8]
        ] if provider_fresh else [],
        "sensor": _sensor(live_states) if provider_fresh else {"state": "IDLE", "kind": None, "detail": None, "attribution": None},
        "network": _network(network or {}) if provider_fresh else {"state": "UNAVAILABLE", "detail": "Security Context data is stale."},
        "network_profile": {"state": profile_data["state"], "available": profile_data["available"]},
        "firewall": profile_data["firewall"],
        "secure_dns": _secure_dns(secure_dns, provider_fresh),
        "malware": _malware(value, clamav or {}) if provider_fresh else {"state": "UNAVAILABLE", "database_age_seconds": 0},
        "usb": _usb(value) if provider_fresh else {"state": "UNAVAILABLE", "blocked_count": 0},
        "update": _update(transaction or {}) if provider_fresh else _update({}),
        "privacy": {
            "profile": profile_data["state"] if provider_fresh else "UNAVAILABLE",
            "available": profile_data["available"],
        },
        "capabilities": {
            "refresh": True,
            "open_security_center": True,
            "privacy_profile_change": profile_data["available"],
        },
        "security": {
            "unresolved_count": attention_count if provider_fresh else None,
            "important_activity_count": max(0, min(len((security_digest or {}).get("recent_activity", [])), 999)) if provider_fresh else None,
            "external_devices": (security_digest or {}).get("devices", {}).get("connected_external") if provider_fresh and isinstance((security_digest or {}).get("devices"), dict) else None,
            "new_unknown_count": (security_digest or {}).get("devices", {}).get("new_unknown_count") if provider_fresh and isinstance((security_digest or {}).get("devices"), dict) else None,
            "source_state": (security_digest or {}).get("source_state", {"state": "UNAVAILABLE"}) if provider_fresh else {"state": "UNAVAILABLE", "reason": "Security Context data is stale."},
        },
    }
