"""Pure bounded finding rules; ingestion/reconciliation owns persistence."""
from __future__ import annotations

from typing import Any, Mapping


def _text(value: Any, limit: int = 240) -> str:
    return "".join(character for character in str(value or "") if character.isprintable())[:limit]


def event_finding(item: Mapping[str, Any]) -> dict[str, Any] | None:
    outcome = _text(item.get("outcome") or item.get("state"), 32).upper()
    category = _text(item.get("category"), 48).upper()
    event_type = _text(item.get("event_type") or item.get("kind"), 96).upper()
    if outcome not in {"FAILURE", "FAILED", "ERROR"} or category not in {
        "SERVICE", "UPDATE", "RECOVERY", "CAPABILITY", "CONFIGURATION",
    }:
        # Ordinary network/access blocks are evidence, not automatic findings.
        return None
    correlation = item.get("correlation") if isinstance(item.get("correlation"), Mapping) else {}
    subject = _text(correlation.get("unit") or correlation.get("operation_id") or correlation.get("transaction_id") or item.get("component"), 160) or "unknown"
    kind = "UPDATE_FAILURE" if category == "UPDATE" else "RECOVERY_FAILURE" if category == "RECOVERY" else "SERVICE_FAILURE" if category == "SERVICE" else "CAPABILITY_FAILURE"
    details = item.get("details") if isinstance(item.get("details"), Mapping) else {}
    return {
        "finding_id": f"{kind.lower()}:{subject}", "kind": kind, "subject_key": subject,
        "state": "UNRESOLVED", "severity": "ERROR", "title": event_type.replace("_", " ").title(),
        "summary": _text(details.get("error")) or "A security operation failed.",
        "destination": "updates" if category == "UPDATE" else "devices" if category == "RECOVERY" else "overview",
        "last_seen": _text(item.get("occurred_at"), 64), "evidence": [_text(item.get("event_id"), 96)],
    }


def device_finding(item: Mapping[str, Any]) -> dict[str, Any] | None:
    if not _text(item.get("device_class"), 48).upper().startswith("EXTERNAL_"):
        return None
    identity = _text(item.get("identity_id"), 96)
    if not identity:
        return None
    trusted = bool(item.get("trusted") or item.get("reviewed"))
    connected = bool(item.get("connected"))
    state = "RESOLVED" if trusted else "UNRESOLVED" if connected else "HISTORY_ONLY"
    return {
        "finding_id": "device-unknown:" + identity, "kind": "UNKNOWN_EXTERNAL_DEVICE", "subject_key": identity,
        "state": state, "severity": "WARNING", "title": "Unknown external device",
        "summary": "Review this connected external device." if connected and not trusted else "The device is retained as recent history.",
        "destination": "devices", "first_seen": _text(item.get("first_seen"), 64), "last_seen": _text(item.get("last_seen"), 64),
        "resolved_at": _text(item.get("last_seen"), 64) if trusted else None,
        "evidence": [_text(item.get("last_event_id"), 96)] if item.get("last_event_id") else [],
    }
