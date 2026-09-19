"""Shared bounded projections for Security Center and the DMS plugin."""
from __future__ import annotations

import datetime as dt
from typing import Any, Mapping

from greyward_security_context.telemetry import TelemetryError, TelemetryStore, stamp


IMPORTANT_TYPES = {
    "CONTROL_STATE_CHANGE", "CONFIGURATION_CHANGE", "UPDATE_PHASE",
    "RECOVERY_POINT_CREATED", "RECOVERY_POINT_ASSOCIATED", "BACKUP_COMPLETED",
    "BACKUP_VERIFICATION", "SERVICE_FAILURE", "SERVICE_RESTART", "DEVICE_CONNECTED",
    "DEVICE_DISCONNECTED", "DEVICE_UNKNOWN", "USB_DEVICE_BLOCKED",
}


def _time(value: Any) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        # Native/runtime projections can omit an offset. Treat those bounded
        # local timestamps as UTC so one malformed source cannot make the
        # shared digest (and therefore the shell plugin) unavailable.
        return parsed.replace(tzinfo=dt.timezone.utc) if parsed.tzinfo is None else parsed
    except (TypeError, ValueError, OverflowError):
        return dt.datetime.min.replace(tzinfo=dt.timezone.utc)


def _text(value: Any, limit: int = 240) -> str:
    return "".join(character for character in str(value or "") if character.isprintable())[:limit]


def _event_summary(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "event_id": _text(item.get("event_id"), 96),
        "occurred_at": _text(item.get("occurred_at"), 64),
        "component": _text(item.get("component"), 96),
        "category": _text(item.get("category"), 48),
        "event_type": _text(item.get("event_type") or item.get("kind"), 96),
        "outcome": _text(item.get("outcome") or item.get("state"), 32).upper(),
        "severity": _text(item.get("severity") or "INFO", 24).upper(),
        "assessment": _text(item.get("assessment") or "NOTEWORTHY", 32).upper(),
        "title": _text(item.get("title") or item.get("event_type") or item.get("kind") or "Security activity", 140),
        "summary": _text(item.get("summary") or item.get("detail") or "Recorded by GREYWARD.", 280),
    }


def _finding_from_event(store: TelemetryStore, item: Mapping[str, Any]) -> None:
    outcome = _text(item.get("outcome") or item.get("state"), 32).upper()
    category = _text(item.get("category"), 48).upper()
    event_type = _text(item.get("event_type") or item.get("kind"), 96).upper()
    if outcome not in {"FAILURE", "FAILED", "ERROR"}:
        return
    if category == "NETWORK":
        # A blocked connection is noteworthy evidence, not an automatic finding.
        return
    if category not in {"SERVICE", "UPDATE", "RECOVERY", "CAPABILITY", "CONFIGURATION"}:
        return
    correlation = item.get("correlation") if isinstance(item.get("correlation"), Mapping) else {}
    subject = _text(correlation.get("unit") or correlation.get("operation_id") or correlation.get("transaction_id") or item.get("component"), 160) or "unknown"
    kind = "UPDATE_FAILURE" if category == "UPDATE" else "RECOVERY_FAILURE" if category == "RECOVERY" else "SERVICE_FAILURE" if category == "SERVICE" else "CAPABILITY_FAILURE"
    store.upsert_finding({
        "finding_id": f"{kind.lower()}:{subject}", "kind": kind, "subject_key": subject,
        "state": "UNRESOLVED", "severity": "ERROR", "title": event_type.replace("_", " ").title(),
        "summary": _text(item.get("details", {}).get("error") if isinstance(item.get("details"), Mapping) else None) or "A security operation failed.",
        "destination": "updates" if category == "UPDATE" else "devices" if category == "RECOVERY" else "overview",
        "last_seen": _text(item.get("occurred_at"), 64), "evidence": [_text(item.get("event_id"), 96)],
    })


def _devices(device_state: Mapping[str, Any] | None, current: dt.datetime) -> dict[str, Any]:
    value = device_state if isinstance(device_state, Mapping) else {}
    source_state = _text(value.get("source_state"), 32).upper() or "UNAVAILABLE"
    records = [item for item in value.get("devices", []) if isinstance(item, Mapping)]
    if source_state != "AVAILABLE":
        return {"source_state": source_state, "connected_external": None, "new_unknown": [], "new_unknown_count": None}
    cutoff = current - dt.timedelta(days=7)
    external = [item for item in records if _text(item.get("device_class"), 48).upper().startswith("EXTERNAL_")]
    unknown = [item for item in external if not item.get("trusted") and not item.get("reviewed") and _time(item.get("first_seen")) >= cutoff]
    return {
        "source_state": "AVAILABLE", "connected_external": sum(1 for item in external if item.get("connected")),
        "new_unknown": [{key: item.get(key) for key in ("identity_id", "name", "device_class", "first_seen", "last_seen", "connected", "identity_confidence", "state") } for item in unknown[:32]],
        "new_unknown_count": len(unknown),
    }


def _sync_device_findings(telemetry: TelemetryStore, device_state: Mapping[str, Any] | None) -> None:
    if not isinstance(device_state, Mapping) or _text(device_state.get("source_state"), 32).upper() != "AVAILABLE":
        return
    for item in device_state.get("devices", []):
        if not isinstance(item, Mapping) or not _text(item.get("device_class"), 48).upper().startswith("EXTERNAL_"):
            continue
        identity = _text(item.get("identity_id"), 96)
        if not identity:
            continue
        trusted = bool(item.get("trusted") or item.get("reviewed"))
        connected = bool(item.get("connected"))
        state = "RESOLVED" if trusted else "UNRESOLVED" if connected else "HISTORY_ONLY"
        telemetry.upsert_finding({
            "finding_id": "device-unknown:" + identity, "kind": "UNKNOWN_EXTERNAL_DEVICE", "subject_key": identity,
            "state": state, "severity": "WARNING", "title": "Unknown external device",
            "summary": "Review this connected external device." if connected and not trusted else "The device is retained as recent history.",
            "destination": "devices", "first_seen": _text(item.get("first_seen"), 64), "last_seen": _text(item.get("last_seen"), 64),
            "resolved_at": _text(item.get("last_seen"), 64) if trusted else None, "evidence": [_text(item.get("last_event_id"), 96)] if item.get("last_event_id") else [],
        })


def build_security_digest(summary: Mapping[str, Any] | None = None, *, network: Mapping[str, Any] | None = None,
                          device_state: Mapping[str, Any] | None = None, store: TelemetryStore | None = None,
                          now_value: dt.datetime | None = None) -> dict[str, Any]:
    """Build the single semantic aggregation used by both user-bus projections."""
    current = now_value or dt.datetime.now(dt.timezone.utc)
    telemetry = store or TelemetryStore()
    source_state = {"state": "AVAILABLE", "reason": None}
    events: list[dict[str, Any]] = []
    try:
        result = telemetry.query({"from": stamp(current - dt.timedelta(hours=24)), "limit": 512})
        events.extend(result.get("events", []))
        for item in events:
            _finding_from_event(telemetry, item)
    except (TelemetryError, OSError):
        source_state = {"state": "UNAVAILABLE", "reason": "Telemetry history is unavailable."}
    for item in (summary or {}).get("recent_events", []) if isinstance(summary, Mapping) else []:
        if isinstance(item, Mapping) and item.get("event_id") and not any(event.get("event_id") == item.get("event_id") for event in events):
            events.append(item)
    important = [
        _event_summary(item) for item in sorted(events, key=lambda item: (_time(item.get("occurred_at")), str(item.get("event_id"))), reverse=True)
        if _text(item.get("event_type") or item.get("kind"), 96).upper() in IMPORTANT_TYPES
        or _text(item.get("assessment"), 32).upper() in {"DEGRADED", "FAILED", "POTENTIALLY_SUSPICIOUS"}
        or _text(item.get("outcome") or item.get("state"), 32).upper() in {"FAILURE", "FAILED", "ERROR"}
    ][:16]
    findings = telemetry.list_findings(unresolved_only=True) if source_state["state"] == "AVAILABLE" else []
    device = _devices(device_state, current)
    try:
        _sync_device_findings(telemetry, device_state)
        findings = telemetry.list_findings(unresolved_only=True) if source_state["state"] == "AVAILABLE" else []
    except (TelemetryError, OSError):
        source_state = {"state": "UNAVAILABLE", "reason": "Telemetry history is unavailable."}
        findings = []
    network_value = network if isinstance(network, Mapping) else {}
    opensnitch = network_value.get("opensnitch") if isinstance(network_value.get("opensnitch"), Mapping) else {}
    return {
        "schema": "greyward.security.digest/v1", "generated_at": stamp(current), "source_state": source_state,
        "unresolved_findings": findings[:16], "unresolved_count": len(findings),
        "recent_activity": important, "capabilities": important[:16],
        "devices": device,
        "network": {"state": _text(opensnitch.get("state"), 24).upper() or "UNAVAILABLE", "blocked_recent": sum(1 for item in events if _text(item.get("category"), 32).upper() == "NETWORK" and _text(item.get("decision"), 24).upper() == "BLOCKED")},
    }
