"""Volatile live privacy activity projection for the GREYWARD taskbar.

This module deliberately contains no persistence or telemetry integration.  The
projection is a bounded, session-local view of current activity.  It is safe to
import in unit tests without D-Bus or desktop dependencies.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import time
import uuid
from copy import deepcopy


SCHEMA = "greyward.security.capsule/v1"
MAX_RECENT_EVENTS = 4
RECENT_EVENT_TTL_SECONDS = 60
SESSION_EPOCH = uuid.uuid4().hex[:12]

PRIORITY = {
    "DEGRADED_PROTECTION": 0,
    "SENSITIVE_DATA": 1,
    "SCREEN_SHARE": 1,
    "ACTIVE_SENSOR": 2,
    "USB_DEVICE": 3,
    "UNUSUAL_ACTIVITY": 4,
}


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _stamp(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_stamp(value: object) -> dt.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(dt.timezone.utc)
    except ValueError:
        return None


def _subject_key(signal: dict) -> str:
    """Return a bounded opaque subject key for stable per-session generations."""

    raw = "|".join(
        str(signal.get(field) or "")[:120]
        for field in ("signal_id", "application", "device", "category")
    )
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:24]


def _safe_signal(signal: dict) -> dict:
    allowed = (
        "signal_id",
        "category",
        "capability",
        "state",
        "title",
        "detail",
        "application",
        "device",
        "started_at",
        "observed_at",
        "fresh_until",
        "duration_seconds",
        "metric",
        "actions",
        "reason",
    )
    result = {key: signal[key] for key in allowed if key in signal}
    result["signal_id"] = str(result.get("signal_id") or "unknown")[:96]
    result["category"] = str(result.get("category") or "UNUSUAL_ACTIVITY")[:40]
    result["capability"] = str(result.get("capability") or "UNAVAILABLE")[:20]
    result["state"] = str(result.get("state") or "UNAVAILABLE")[:20]
    if isinstance(result.get("actions"), list):
        result["actions"] = [str(item)[:48] for item in result["actions"][:2]]
    return result


class PrivacyCapsule:
    """Build a session-local capsule and emit revisions on meaningful changes."""

    def __init__(self, session_epoch: str | None = None):
        self.session_epoch = (session_epoch or SESSION_EPOCH)[:32]
        self.revision = 0
        self.initialized = False
        self._active: dict[str, dict] = {}
        self._signals: dict[str, dict] = {}
        self._generations: dict[str, int] = {}
        self._recent_events: list[dict] = []
        self._last_shape: str | None = None

    @staticmethod
    def _is_live(signal: dict) -> bool:
        return signal.get("state") in {"ACTIVE", "DEGRADED", "INFO", "NEW"}

    @staticmethod
    def _event_state(signal: dict) -> str:
        return "DEGRADED" if signal.get("state") == "DEGRADED" else "ACTIVE"

    def _event_id(self, signal_id: str, generation: int) -> str:
        bounded = str(signal_id).replace("/", "_")[:96]
        return f"capsule:{self.session_epoch}:{bounded}:{generation}"

    def _add_event(self, signal: dict, generation: int, transition: str, observed_at: dt.datetime) -> None:
        event = {
            "event_id": self._event_id(str(signal.get("signal_id") or "unknown"), generation),
            "generation": generation,
            "signal_id": str(signal.get("signal_id") or "unknown")[:96],
            "category": str(signal.get("category") or "UNUSUAL_ACTIVITY")[:40],
            "state": self._event_state(signal) if transition == "ACTIVE" else transition,
            "title": str(signal.get("title") or "Privacy activity")[:120],
            "occurred_at": _stamp(observed_at),
            "transition": transition,
        }
        self._recent_events = [
            item for item in self._recent_events
            if not (item["event_id"] == event["event_id"] and item.get("transition") == transition)
        ]
        self._recent_events.append(event)
        self._recent_events = self._recent_events[-MAX_RECENT_EVENTS:]

    def _prune_events(self, observed_at: dt.datetime) -> None:
        kept = []
        for event in self._recent_events:
            occurred = _parse_stamp(event.get("occurred_at"))
            if occurred and (observed_at - occurred).total_seconds() <= RECENT_EVENT_TTL_SECONDS:
                kept.append(event)
        self._recent_events = kept[-MAX_RECENT_EVENTS:]

    def update(self, signals: list[dict], observed_at: dt.datetime | None = None) -> bool:
        observed_at = observed_at or _utc_now()
        normalized = {}
        for signal in signals:
            safe = _safe_signal(signal)
            freshness = _parse_stamp(safe.get("fresh_until"))
            if (
                freshness is not None
                and self._is_live(safe)
                and freshness <= observed_at
                and safe.get("capability") == "SUPPORTED"
            ):
                safe["state"] = "STALE"
            normalized[safe["signal_id"]] = safe
        previous = self._active
        next_active: dict[str, dict] = {}

        for signal_id, signal in normalized.items():
            if not self._is_live(signal):
                continue
            subject = _subject_key(signal)
            old = previous.get(signal_id)
            if old is None:
                generation = self._generations.get(subject, 0) + 1
                self._generations[subject] = generation
                signal["generation"] = generation
                signal["event_id"] = self._event_id(signal_id, generation)
                signal["started_at"] = signal.get("started_at") or _stamp(observed_at)
                if self.initialized:
                    self._add_event(signal, generation, "ACTIVE", observed_at)
            else:
                generation = int(old.get("generation") or self._generations.get(subject, 1))
                signal["generation"] = generation
                signal["event_id"] = old.get("event_id") or self._event_id(signal_id, generation)
                signal["started_at"] = old.get("started_at") or signal.get("started_at") or _stamp(observed_at)
            started = _parse_stamp(signal.get("started_at")) or observed_at
            signal["duration_seconds"] = max(0, int((observed_at - started).total_seconds()))
            next_active[signal_id] = signal

        for signal_id, old in previous.items():
            if signal_id not in next_active and self.initialized:
                self._add_event(old, int(old.get("generation") or 0), "CLEARED", observed_at)

        self._active = next_active
        self._signals = normalized
        self._prune_events(observed_at)
        shape = json.dumps(
            {
                "signals": [
                    {
                        **{
                            key: value
                            for key, value in item.items()
                            if key not in {"observed_at", "fresh_until", "duration_seconds", "started_at"}
                        },
                        "freshness_state": (
                            "STALE"
                            if _parse_stamp(item.get("fresh_until")) is not None
                            and _parse_stamp(item.get("fresh_until")) <= observed_at
                            else "FRESH"
                        ),
                    }
                    for item in sorted(normalized.values(), key=lambda item: item["signal_id"])
                ],
                "recent": self._recent_events,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        changed = self._last_shape is not None and shape != self._last_shape
        self._last_shape = shape
        if self.revision == 0:
            self.revision = 1
        elif changed:
            self.revision += 1
        self.initialized = True
        return changed

    def snapshot(self, observed_at: dt.datetime | None = None) -> dict:
        observed_at = observed_at or _utc_now()
        self._prune_events(observed_at)
        signals = []
        for item in self._signals.values():
            value = deepcopy(item)
            if self._is_live(value):
                started = _parse_stamp(value.get("started_at")) or observed_at
                value["observed_at"] = _stamp(observed_at)
                value["duration_seconds"] = max(0, int((observed_at - started).total_seconds()))
            signals.append(value)

        signals.sort(key=lambda item: (PRIORITY.get(item.get("category"), 99), item.get("signal_id", "")))
        active = [item for item in signals if self._is_live(item)]
        strongest = active[0] if active else None
        fresh_until = [
            _parse_stamp(item.get("fresh_until"))
            for item in signals
            if _parse_stamp(item.get("fresh_until")) is not None
        ]
        return {
            "schema": SCHEMA,
            "revision": self.revision,
            "generated_at": _stamp(observed_at),
            "fresh_until": _stamp(min(fresh_until) if fresh_until else observed_at + dt.timedelta(seconds=10)),
            "availability": "AVAILABLE",
            "active_count": len(active),
            "strongest_signal": strongest.get("signal_id") if strongest else None,
            "has_new_event": any(item.get("transition") == "ACTIVE" for item in self._recent_events),
            "signals": signals,
            "recent_events": deepcopy(self._recent_events),
            "capabilities": {
                item["signal_id"]: {
                    "capability": item.get("capability", "UNAVAILABLE"),
                    "state": item.get("state", "UNAVAILABLE"),
                    "reason": item.get("reason"),
                }
                for item in signals
            },
        }


def clipboard_classification(text: str) -> str | None:
    """Classify bounded text without retaining or returning the text itself."""

    if not isinstance(text, str) or not text or len(text.encode("utf-8", "ignore")) > 256 * 1024:
        return None
    import re

    if re.search(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", text) and re.search(r"-----END [A-Z0-9 ]*PRIVATE KEY-----", text):
        return "PRIVATE_KEY"
    if re.search(r"(?im)^\s*(password|passwd|api_key|secret|token)\s*=\s*\S+\s*$", text):
        return "STRUCTURED_CREDENTIAL"
    if re.search(r"\b(?:gh[pousr]_|github_pat_|glpat-|xox[baprs]-)[A-Za-z0-9_-]{16,}\b", text):
        return "API_TOKEN"
    compact = re.sub(r"[ -]", "", text.strip())
    if re.fullmatch(r"\d{13,19}", compact) and _luhn(compact):
        return "PAYMENT_CARD"
    return None


def _luhn(value: str) -> bool:
    total = 0
    parity = len(value) % 2
    for index, char in enumerate(value):
        digit = int(char)
        if index % 2 == parity:
            digit = digit * 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0
