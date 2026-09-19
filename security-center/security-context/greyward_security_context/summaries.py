"""Deterministic, privacy-preserving aggregation for Security Context events."""
from __future__ import annotations

import datetime as dt
from collections import Counter
from typing import Iterable, Mapping

SCHEMA = "greyward.security.summary/v1"
MAX_EVENTS = 64
MAX_LINES = 12


def _parse_time(value: object) -> dt.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def _bounded_events(events: Iterable[Mapping], end: dt.datetime) -> list[Mapping]:
    start = end - dt.timedelta(days=7)
    result, seen = [], set()
    for event in events:
        if not isinstance(event, Mapping):
            continue
        event_id, occurred = event.get("event_id"), _parse_time(event.get("occurred_at"))
        if not isinstance(event_id, str) or event_id in seen or occurred is None:
            continue
        if start <= occurred <= end:
            seen.add(event_id)
            result.append(event)
    return result[:MAX_EVENTS]


def weekly_summary(events: Iterable[Mapping], *, window_end: dt.datetime | None = None) -> dict:
    """Aggregate normalized events; no raw detail or host/path is copied."""
    end = window_end or dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    if end.tzinfo is None:
        end = end.replace(tzinfo=dt.timezone.utc)
    selected = _bounded_events(events, end)
    counts = Counter(str(event.get("kind")) for event in selected)
    lines = ["Weekly security summary"]
    inbound = counts.get("INBOUND_ATTACK_ACTIVITY", 0)
    connections = counts.get("APP_CONNECTION_BLOCKED", 0)
    scans = counts.get("USB_SCAN_RESULT", 0)
    if inbound:
        lines.append(f"{inbound} inbound security attempts blocked")
    if connections:
        lines.append(f"{connections} application connections blocked")
    if scans:
        lines.append(f"{scans} removable-media scans")
    threats = sum(1 for event in selected if event.get("kind") == "USB_SCAN_RESULT" and event.get("state") == "THREAT")
    unavailable = sum(1 for event in selected if event.get("kind") == "USB_SCAN_RESULT" and event.get("state") in {"UNAVAILABLE", "TIMEOUT", "ERROR"})
    if threats:
        lines.append(f"{threats} known malware detection(s) reported by available scans")
    elif scans and not unavailable:
        lines.append("No known malware detected in available scan results")
    elif scans:
        lines.append("Malware status unavailable for some scan results")
    else:
        lines.append("No malware conclusion available; no removable-media scan evidence")
    persistence = counts.get("PERSISTENCE_CHANGE_DETECTED", 0)
    if persistence:
        lines.append(f"{persistence} persistence configuration change(s) detected")
    allowed = {"APP_CONNECTION_BLOCKED", "INBOUND_ATTACK_ACTIVITY", "USB_SCAN_RESULT", "PERSISTENCE_CHANGE_DETECTED"}
    return {"schema": SCHEMA, "window_start": (end - dt.timedelta(days=7)).isoformat().replace("+00:00", "Z"), "window_end": end.isoformat().replace("+00:00", "Z"), "lines": lines[:MAX_LINES], "counts": {key: counts[key] for key in sorted(counts) if key in allowed}, "evidence_event_count": len(selected)}
