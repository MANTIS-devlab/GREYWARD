"""Compatibility projection over the existing event store, never security truth.

Legacy presentation JSON is imported once, transactionally, and retained only
as a rollback input. New presentation events have a fixed source/category and
unverified quality; callers cannot publish kernel evidence or policy outcomes.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat

from greyward_security_context.telemetry import TelemetryError, _SECRET_VALUE, event, stamp, user_store

SCHEMA = "greyward.local-activity/v1"
CATEGORY = "LOCAL_ACTIVITY"
COMPONENT = "greyward-security-center"
SOURCE = "security-center/presentation"
MARKER = "local-activity-migration/v1"
MAX_ITEMS = 64
MAX_INPUT_BYTES = 256 * 1024
_FIELDS = {"event_id", "category", "severity", "occurred_at", "title", "detail", "related_check_id"}
_PRIVATE_PATH = re.compile(r"/(?:home|root|media|mnt|run/user)(?:/[^\s\"'<>;,]*)?")


def legacy_path():
    base = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
    return base / "greyward/security-center/activity.json"


def _text(value, maximum):
    if not isinstance(value, str) or len(value) > maximum or any(not character.isprintable() for character in value):
        raise TelemetryError("Invalid local presentation metadata")
    return _PRIVATE_PATH.sub("[PRIVATE_PATH]", _SECRET_VALUE.sub(r"\1=[REDACTED]", value))


def normalize(value, *, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    if not isinstance(value, dict) or set(value) != _FIELDS:
        raise TelemetryError("Invalid local activity shape")
    if (not isinstance(value["category"], str) or value["category"] not in {"Posture", "Action", "Evidence"}
            or not isinstance(value["severity"], str) or value["severity"] not in {"Information", "Review", "Important"}):
        raise TelemetryError("Invalid local activity classification")
    try:
        if not isinstance(value["occurred_at"], str) or len(value["occurred_at"]) > 64:
            raise ValueError("Invalid activity timestamp")
        occurred = dt.datetime.fromisoformat(value["occurred_at"].replace("Z", "+00:00"))
        if occurred.tzinfo is None or occurred > now + dt.timedelta(minutes=1):
            raise ValueError("Invalid activity timestamp")
    except (AttributeError, TypeError, ValueError) as error:
        raise TelemetryError("Invalid local activity timestamp") from error
    related = value["related_check_id"]
    if related is not None and (not isinstance(related, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,96}", related)):
        raise TelemetryError("Invalid related check reference")
    # Redact before persistence. Keep two bounded detail chunks so telemetry's
    # per-string cap does not silently discard the legacy 320-character field.
    identity = value["event_id"]
    if not isinstance(identity, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", identity):
        raise TelemetryError("Invalid local event reference")
    title = _text(value["title"], 160)
    raw_detail = value["detail"]
    if not isinstance(raw_detail, str) or len(raw_detail) > 320 or any(not c.isprintable() for c in raw_detail):
        raise TelemetryError("Invalid local activity detail")
    detail = _text(raw_detail, 320)[:320]
    normalized = {"event_id": identity, "category": value["category"], "severity": value["severity"],
                  "occurred_at": occurred.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
                  "title": title[:160], "detail": detail, "related_check_id": related}
    key = hashlib.sha256(json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    normalized_event = event(event_id="local-activity-" + key, occurred_at=normalized["occurred_at"],
        component=COMPONENT, source=SOURCE, category=CATEGORY, event_type="LOCAL_" + value["category"].upper(),
        action="REPORT", outcome="OBSERVED", severity="INFO", assessment="NORMAL",
        details={"local": {**{k: v for k, v in normalized.items() if k != "detail"},
                           "detail_parts": [detail[:160], detail[160:320]]}},
        quality={"source_state": "AVAILABLE", "attribution": "UNVERIFIED", "confidence": "LOW",
                 "origin": "USER_PRESENTATION", "authoritative": False},
        retention_class="semantic")
    # Preserve the original subsecond ordering instead of collapsing distinct
    # legacy actions to the second; the common store supports ISO timestamps.
    normalized_event["occurred_at"] = occurred.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    return normalized_event


def _trim(connection):
    connection.execute("""DELETE FROM events WHERE component=? AND source=? AND category=?
        AND event_id NOT IN (SELECT event_id FROM events WHERE component=? AND source=? AND category=?
                            ORDER BY occurred_at DESC,event_id DESC LIMIT ?)""",
        (COMPONENT, SOURCE, CATEGORY, COMPONENT, SOURCE, CATEGORY, MAX_ITEMS))


def migrate(store=None, path=None, *, now=None):
    store = store or user_store()
    path = Path(path) if path is not None else legacy_path()
    connection = store._connect()
    try:
        with connection:
            saved = connection.execute("SELECT value FROM metadata WHERE key=?", (MARKER,)).fetchone()
            if saved:
                if saved[0] != '{"complete":true}':
                    raise TelemetryError("Invalid local activity migration receipt")
                return {"complete": True, "processed": 0}
            try:
                descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
            except FileNotFoundError:
                values = []
            else:
                with os.fdopen(descriptor, "rb") as source:
                    info = os.fstat(source.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_size > MAX_INPUT_BYTES:
                        raise TelemetryError("Unsafe or oversized legacy activity input")
                    raw = source.read(MAX_INPUT_BYTES + 1)
                    if len(raw) > MAX_INPUT_BYTES:
                        raise TelemetryError("Oversized legacy activity input")
                    values = json.loads(raw)
            if not isinstance(values, list) or len(values) > MAX_ITEMS:
                raise TelemetryError("Invalid legacy activity collection")
            prepared = [normalize(value, now=now) for value in values]
            cutoff = stamp((now or dt.datetime.now(dt.timezone.utc)) - dt.timedelta(days=30))
            for value in prepared:
                if value["occurred_at"] >= cutoff:
                    store._record_value(connection, value)
            _trim(connection)
            # Events and the one-time marker commit together. An interruption
            # before commit permits exact replay; the original file is retained.
            connection.execute("INSERT INTO metadata(key,value) VALUES(?,?)", (MARKER, '{"complete":true}'))
        store.prune()
        return {"complete": True, "processed": len(prepared)}
    except (OSError, ValueError, sqlite3.Error) as error:
        raise TelemetryError("Local activity migration unavailable") from error
    finally:
        connection.close()


def read(store=None):
    store = store or user_store()
    values = store.query({"component": COMPONENT, "source": SOURCE, "category": CATEGORY, "limit": MAX_ITEMS}, read_only=True)
    items = []
    for value in reversed(values["events"]):
        local = (value.get("details") or {}).get("local")
        if not isinstance(local, dict) or set(local) != (_FIELDS - {"detail"}) | {"detail_parts"}:
            raise TelemetryError("Invalid local activity projection")
        parts = local["detail_parts"]
        if not isinstance(parts, list) or len(parts) != 2 or any(not isinstance(part, str) or len(part) > 160 for part in parts):
            raise TelemetryError("Invalid local activity projection")
        items.append({**{key: value for key, value in local.items() if key != "detail_parts"}, "detail": "".join(parts)})
    return {"schema": SCHEMA, "state": "AVAILABLE", "items": items}


def record(payload, store=None):
    if not isinstance(payload, str) or len(payload.encode()) > 4096:
        raise TelemetryError("Oversized local activity request")
    store = store or user_store()
    prepared = normalize(json.loads(payload))
    migrate(store)
    connection = store._connect()
    try:
        with connection:
            store._record_value(connection, prepared)
            _trim(connection)
        store.prune()
    finally:
        connection.close()
    return {"schema": SCHEMA, "state": "AVAILABLE", "items": []}


def clear(store=None):
    store = store or user_store()
    migrate(store)
    connection = store._connect()
    try:
        with connection:
            connection.execute("DELETE FROM events WHERE component=? AND source=? AND category=?", (COMPONENT, SOURCE, CATEGORY))
            remaining = connection.execute("SELECT count(*) FROM events WHERE component=? AND source=? AND category=?", (COMPONENT, SOURCE, CATEGORY)).fetchone()[0]
            if remaining:
                raise TelemetryError("Local activity clear readback failed")
    finally:
        connection.close()
    return {"schema": SCHEMA, "state": "AVAILABLE", "items": []}
