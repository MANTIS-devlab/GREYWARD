"""Bounded, redacted GREYWARD telemetry history.

The live OpenSnitch projection remains in memory.  This module stores only
approved normalized events for historical investigation; native journal and
backend evidence remain the authoritative sources.
"""
from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Mapping

try:
    import grp
except ImportError:  # pragma: no cover - Windows source/test host
    grp = None

try:
    from systemd import journal as _journal
except ImportError:
    _journal = None


SCHEMA = "greyward.telemetry.event/v1"
QUERY_SCHEMA = "greyward.telemetry.query/v1"
DEFAULT_DB_PATH = Path("/var/lib/greyward/telemetry/events.sqlite3")
DEFAULT_USER_DB_ROOT = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "greyward" / "telemetry"
DEFAULT_USER_DB_PATH = DEFAULT_USER_DB_ROOT / "events.sqlite3"
DEFAULT_ROOT_SPOOL_PATH = Path("/run/greyward-security-context/telemetry-events.jsonl")


def _wheel_gid():
    if grp is None:
        return None
    try:
        return grp.getgrnam("wheel").gr_gid
    except (KeyError, OSError):
        return None


def _chown_wheel(path):
    wheel_gid = _wheel_gid()
    chown = getattr(os, "chown", None)
    if wheel_gid is not None and callable(chown):
        try:
            chown(path, 0, wheel_gid)
        except OSError:
            pass
INVESTIGATION_DAYS = 7
SEMANTIC_DAYS = 30
MAX_DB_BYTES = 128 * 1024 * 1024
MAX_ROOT_SPOOL_BYTES = 2 * 1024 * 1024
MAX_ROOT_SPOOL_EVENTS = 4096
MAX_QUERY_EVENTS = 512
MAX_QUERY_BYTES = 2 * 1024 * 1024
MAX_DETAILS_BYTES = 32 * 1024
MAX_RELATIONS = 16
MAX_TEXT = 240
MAX_FILE_OPERATIONS = 256
MAX_FILE_DETECTIONS = 512
_SECRET_KEY = re.compile(r"(?:password|passphrase|token|api[_-]?key|secret|private[_-]?key|authorization|cookie|credential)", re.I)
_SECRET_VALUE = re.compile(r"(?i)\b(password|passphrase|token|api[_-]?key|secret|authorization|bearer|cookie)\s*[:=]\s*[^\s,;]+")


class TelemetryError(RuntimeError):
    pass


def stamp(value: dt.datetime | None = None) -> str:
    value = value or dt.datetime.now(dt.timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _text(value: Any, maximum: int = MAX_TEXT) -> str:
    return "".join(character for character in str(value or "") if character.isprintable())[:maximum]


def _safe_value(value: Any, depth: int = 0) -> Any:
    if depth > 4:
        return "[TRUNCATED]"
    if isinstance(value, Mapping):
        result = {}
        for key, item in list(value.items())[:64]:
            name = _text(key, 80)
            result[name] = "[REDACTED]" if _SECRET_KEY.search(name) else _safe_value(item, depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        return [_safe_value(item, depth + 1) for item in list(value)[:64]]
    if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
        return value
    return _SECRET_VALUE.sub(r"\1=[REDACTED]", _text(value, MAX_TEXT))


def boot_id() -> str | None:
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return value[:64] or None


def _retention(retention_class: str, occurred_at: str) -> str:
    try:
        value = dt.datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
    except ValueError:
        value = dt.datetime.now(dt.timezone.utc)
    days = SEMANTIC_DAYS if retention_class == "semantic" else INVESTIGATION_DAYS
    return stamp(value + dt.timedelta(days=days))


def event(
    *,
    event_id: str | None = None,
    occurred_at: str | None = None,
    observed_at: str | None = None,
    component: str,
    source: str,
    category: str,
    event_type: str,
    action: str,
    outcome: str,
    severity: str = "INFO",
    assessment: str = "NORMAL",
    session_id: str | None = None,
    application: str | None = None,
    destination: Mapping[str, Any] | None = None,
    protocol: str | None = None,
    port: int | None = None,
    decision: str | None = None,
    correlation: Mapping[str, Any] | None = None,
    details: Mapping[str, Any] | None = None,
    quality: Mapping[str, Any] | None = None,
    native_evidence: Mapping[str, Any] | None = None,
    relations: list[Mapping[str, Any]] | None = None,
    retention_class: str = "investigation",
) -> dict[str, Any]:
    occurred = _text(occurred_at or stamp(), 64)
    if retention_class not in {"investigation", "semantic"}:
        raise TelemetryError("Invalid telemetry retention class")
    destination_value = _safe_value(destination or {})
    if category.upper() == "NETWORK" and isinstance(destination_value, dict):
        destination_value = {key: destination_value.get(key) for key in ("host", "ip", "port") if key in destination_value}
    correlation_value = _safe_value(correlation or {})
    detail_value = _safe_value(details or {})
    if category.upper() == "NETWORK" and isinstance(detail_value, dict):
        detail_value = {key: detail_value.get(key) for key in ("rule_name", "control", "network_event_type") if key in detail_value}
    result = {
        "schema": SCHEMA,
        "event_id": _text(event_id or "gw-" + uuid.uuid4().hex, 96),
        "occurred_at": occurred,
        "observed_at": _text(observed_at or stamp(), 64),
        "monotonic_ns": time.monotonic_ns(),
        "boot_id": boot_id(),
        "session_id": _text(session_id, 96) or None,
        "component": _text(component, 96),
        "source": _text(source, 128),
        "category": _text(category, 64).upper(),
        "event_type": _text(event_type, 96).upper(),
        "action": _text(action, 64).upper(),
        "outcome": _text(outcome, 64).upper(),
        "severity": _text(severity, 32).upper(),
        "assessment": _text(assessment, 48).upper(),
        "application": _text(application, 240) or None,
        "destination": destination_value or None,
        "protocol": _text(protocol, 24).lower() or None,
        "port": int(port) if port is not None and str(port).isdigit() else None,
        "decision": _text(decision, 24).upper() or None,
        "correlation": correlation_value,
        "details": detail_value,
        "quality": _safe_value(quality or {"source_state": "AVAILABLE", "attribution": "EXACT", "confidence": "EXACT"}),
        "native_evidence": _safe_value(native_evidence or {}),
        "relations": [_safe_value(item) for item in (relations or [])[:MAX_RELATIONS]],
        "retention_class": retention_class,
    }
    result["expires_at"] = _retention(retention_class, occurred)
    return result


def _database_path(path: Path | str | None = None) -> Path:
    configured = path or os.environ.get("GREYWARD_TELEMETRY_DB")
    return Path(configured).expanduser() if configured else DEFAULT_DB_PATH


def user_database_path(path: Path | str | None = None) -> Path:
    """Return the per-user history path used by the unprivileged session service."""
    configured = path or os.environ.get("GREYWARD_TELEMETRY_USER_DB")
    return Path(configured).expanduser() if configured else DEFAULT_USER_DB_PATH


def user_store(path: Path | str | None = None, *, max_bytes: int = MAX_DB_BYTES) -> "TelemetryStore":
    return TelemetryStore(user_database_path(path), max_bytes=max_bytes)


def root_spool_path(path: Path | str | None = None) -> Path:
    configured = path or os.environ.get("GREYWARD_TELEMETRY_SPOOL")
    return Path(configured).expanduser() if configured else DEFAULT_ROOT_SPOOL_PATH


def spool_event(value: Mapping[str, Any], path: Path | str | None = None) -> bool:
    """Append one approved event to the bounded root-to-user handoff spool.

    The root collector owns this file. It is intentionally ephemeral: journald
    remains the native source of truth, while this spool lets an unprivileged
    session service import recent normalized events into its own SQLite store.
    """
    if value.get("schema") != SCHEMA or not value.get("event_id"):
        return False
    target = root_spool_path(path)
    lock_path = target.with_name(target.name + ".lock")
    payload = json.dumps(_safe_value(dict(value)), sort_keys=True, separators=(",", ":"))
    if len(payload.encode("utf-8")) > MAX_DETAILS_BYTES * 2:
        return False
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        lock_path.touch(mode=0o600, exist_ok=True)
        with lock_path.open("a+", encoding="utf-8") as lock:
            try:
                import fcntl
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            except (ImportError, OSError):
                pass
            try:
                existing = target.read_bytes()[-MAX_ROOT_SPOOL_BYTES:] if target.exists() else b""
                lines = [line for line in existing.decode("utf-8", "replace").splitlines() if line]
                lines.append(payload)
                retained: list[str] = []
                size = 0
                for line in reversed(lines[-MAX_ROOT_SPOOL_EVENTS:]):
                    line_size = len(line.encode("utf-8")) + 1
                    if retained and size + line_size > MAX_ROOT_SPOOL_BYTES:
                        break
                    retained.append(line)
                    size += line_size
                temporary = target.with_name(target.name + ".new")
                temporary.write_text("\n".join(reversed(retained)) + "\n", encoding="utf-8")
                os.chmod(temporary, 0o640)
                _chown_wheel(temporary)
                os.replace(temporary, target)
                os.chmod(target, 0o640)
                _chown_wheel(target)
            finally:
                try:
                    import fcntl
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
                except (ImportError, OSError):
                    pass
        try:
            os.chmod(target.parent, 0o750)
            _chown_wheel(target.parent)
            os.chmod(lock_path, 0o600)
        except OSError:
            pass
        return True
    except (OSError, UnicodeError):
        return False


def import_root_spool(store: "TelemetryStore" | None = None, path: Path | str | None = None) -> dict[str, int | str]:
    """Import valid, deduplicated root events into a user-owned history store."""
    target = root_spool_path(path)
    telemetry = store or user_store()
    try:
        raw = target.read_bytes()[-MAX_ROOT_SPOOL_BYTES:] if target.exists() else b""
    except OSError:
        return {"state": "UNAVAILABLE", "imported": 0, "invalid": 0}
    imported = 0
    invalid = 0
    values = []
    for line in raw.decode("utf-8", "replace").splitlines()[-MAX_ROOT_SPOOL_EVENTS:]:
        try:
            value = json.loads(line)
            if not isinstance(value, Mapping) or value.get("schema") != SCHEMA or not value.get("event_id"):
                invalid += 1
                continue
            details = json.dumps(_safe_value(value.get("details", {})), sort_keys=True, separators=(",", ":"))
            if len(details.encode("utf-8")) > MAX_DETAILS_BYTES:
                raise TelemetryError("Telemetry event details are too large")
            values.append(value)
        except (TypeError, ValueError, json.JSONDecodeError, TelemetryError, OSError, sqlite3.Error):
            invalid += 1
    try:
        imported = telemetry.record_many(values)
    except (TypeError, ValueError, TelemetryError, OSError, sqlite3.Error):
        invalid += len(values)
    return {"state": "AVAILABLE", "imported": imported, "invalid": invalid}


class TelemetryStore:
    """SQLite history with bounded writes and deterministic reads."""

    def __init__(self, path: Path | str | None = None, *, max_bytes: int = MAX_DB_BYTES):
        self.path = _database_path(path)
        self.max_bytes = max(1024, int(max_bytes))

    def _connect(self) -> sqlite3.Connection:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            new_database = not self.path.exists()
            connection = sqlite3.connect(self.path, timeout=2)
            connection.row_factory = sqlite3.Row
            if new_database:
                # Keep the fixed schema overhead small enough for tests and
                # constrained installations to honor a reduced explicit
                # history budget. This must happen before the first table is
                # created; existing databases keep their established page
                # size.
                connection.execute("PRAGMA page_size=1024")
                connection.execute("PRAGMA auto_vacuum=INCREMENTAL")
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=NORMAL")
            connection.execute("PRAGMA busy_timeout=2000")
            self._schema(connection)
            try:
                os.chmod(self.path.parent, 0o750)
                os.chmod(self.path, 0o640)
            except OSError:
                pass
            return connection
        except (OSError, sqlite3.Error) as error:
            raise TelemetryError(f"Telemetry storage is unavailable: {type(error).__name__}") from error

    @staticmethod
    def _schema(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                schema TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                monotonic_ns INTEGER,
                boot_id TEXT,
                session_id TEXT,
                component TEXT NOT NULL,
                source TEXT NOT NULL,
                category TEXT NOT NULL,
                event_type TEXT NOT NULL,
                action TEXT NOT NULL,
                outcome TEXT NOT NULL,
                severity TEXT NOT NULL,
                assessment TEXT NOT NULL,
                application TEXT,
                operation_id TEXT,
                transaction_id TEXT,
                unit TEXT,
                rule_id TEXT,
                destination_json TEXT,
                protocol TEXT,
                port INTEGER,
                decision TEXT,
                correlation_json TEXT NOT NULL,
                details_json TEXT NOT NULL,
                quality_json TEXT NOT NULL,
                native_evidence_json TEXT NOT NULL,
                retention_class TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                inserted_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS event_relations (
                event_id TEXT NOT NULL,
                related_event_id TEXT NOT NULL,
                relation TEXT NOT NULL,
                confidence TEXT NOT NULL,
                basis TEXT,
                PRIMARY KEY(event_id, related_event_id, relation),
                FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS devices (
                identity_id TEXT PRIMARY KEY,
                identity_confidence TEXT NOT NULL,
                name TEXT NOT NULL,
                device_class TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                connected INTEGER NOT NULL,
                trusted INTEGER NOT NULL,
                state TEXT NOT NULL,
                source_quality TEXT NOT NULL,
                last_event_id TEXT,
                reviewed INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                subject_key TEXT NOT NULL,
                state TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                summary TEXT NOT NULL,
                destination TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                resolved_at TEXT,
                evidence_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS file_scan_operations (
                operation_id TEXT PRIMARY KEY,
                mode TEXT NOT NULL,
                scope_json TEXT NOT NULL,
                state TEXT NOT NULL,
                phase TEXT NOT NULL,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                files_inspected INTEGER NOT NULL DEFAULT 0,
                detection_count INTEGER NOT NULL DEFAULT 0,
                error_count INTEGER NOT NULL DEFAULT 0,
                skipped_count INTEGER NOT NULL DEFAULT 0,
                total_files INTEGER,
                total_known INTEGER NOT NULL DEFAULT 0,
                detail TEXT,
                scanner_version TEXT,
                database_version TEXT
            );
            CREATE TABLE IF NOT EXISTS file_detections (
                detection_id TEXT PRIMARY KEY,
                operation_id TEXT NOT NULL,
                original_path TEXT NOT NULL,
                file_ref TEXT NOT NULL,
                detection_name TEXT NOT NULL,
                detected_at TEXT NOT NULL,
                scanner_version TEXT,
                database_version TEXT,
                file_size INTEGER,
                file_hash TEXT,
                state TEXT NOT NULL,
                quarantine_id TEXT,
                restore_staging_path TEXT,
                last_error TEXT,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS file_detection_actions (
                action_id INTEGER PRIMARY KEY AUTOINCREMENT,
                detection_id TEXT NOT NULL,
                action TEXT NOT NULL,
                outcome TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                detail TEXT
            );
            CREATE INDEX IF NOT EXISTS events_time ON events(occurred_at DESC, event_id DESC);
            CREATE INDEX IF NOT EXISTS events_category_time ON events(category, occurred_at DESC, event_id DESC);
            CREATE INDEX IF NOT EXISTS events_category_decision_time ON events(category, decision, occurred_at DESC, event_id DESC);
            CREATE INDEX IF NOT EXISTS events_category_protocol_time ON events(category, protocol, occurred_at DESC, event_id DESC);
            CREATE INDEX IF NOT EXISTS events_boot_time ON events(boot_id, occurred_at DESC);
            CREATE INDEX IF NOT EXISTS events_component_time ON events(component, category, occurred_at DESC);
            CREATE INDEX IF NOT EXISTS events_severity_time ON events(severity, assessment, occurred_at DESC);
            CREATE INDEX IF NOT EXISTS events_application_time ON events(application, occurred_at DESC);
            CREATE INDEX IF NOT EXISTS events_expiry ON events(retention_class, expires_at);
            CREATE INDEX IF NOT EXISTS relations_related ON event_relations(related_event_id, event_id);
            CREATE INDEX IF NOT EXISTS devices_connected ON devices(connected, last_seen DESC);
            CREATE INDEX IF NOT EXISTS devices_first_seen ON devices(first_seen DESC);
            CREATE INDEX IF NOT EXISTS devices_class ON devices(device_class, last_seen DESC);
            CREATE INDEX IF NOT EXISTS findings_state ON findings(state, last_seen DESC);
            CREATE INDEX IF NOT EXISTS findings_kind ON findings(kind, subject_key);
            CREATE INDEX IF NOT EXISTS file_scan_operations_time ON file_scan_operations(started_at DESC);
            CREATE INDEX IF NOT EXISTS file_scan_operations_state ON file_scan_operations(state, started_at DESC);
            CREATE INDEX IF NOT EXISTS file_detections_state ON file_detections(state, updated_at DESC);
            CREATE INDEX IF NOT EXISTS file_detections_time ON file_detections(detected_at DESC);
            CREATE INDEX IF NOT EXISTS file_detections_operation ON file_detections(operation_id, detected_at DESC);
            CREATE INDEX IF NOT EXISTS file_detection_actions_detection ON file_detection_actions(detection_id, occurred_at DESC);
            """
        )
        columns = {row[1] for row in connection.execute("PRAGMA table_info(events)").fetchall()}
        for name in ("session_id", "operation_id", "transaction_id", "unit", "rule_id"):
            if name not in columns:
                connection.execute(f"ALTER TABLE events ADD COLUMN {name} TEXT")
        detection_columns = {row[1] for row in connection.execute("PRAGMA table_info(file_detections)").fetchall()}
        if "restore_staging_path" not in detection_columns:
            connection.execute("ALTER TABLE file_detections ADD COLUMN restore_staging_path TEXT")
        connection.execute("CREATE INDEX IF NOT EXISTS events_session_time ON events(session_id, occurred_at DESC)")
        connection.execute("CREATE INDEX IF NOT EXISTS events_operation ON events(operation_id, occurred_at DESC)")
        connection.execute("CREATE INDEX IF NOT EXISTS events_transaction ON events(transaction_id, occurred_at DESC)")
        connection.execute("CREATE INDEX IF NOT EXISTS events_unit ON events(unit, occurred_at DESC)")
        connection.execute("CREATE INDEX IF NOT EXISTS events_rule ON events(rule_id, occurred_at DESC)")
        connection.execute("CREATE INDEX IF NOT EXISTS events_decision ON events(decision, occurred_at DESC)")
        connection.execute("CREATE INDEX IF NOT EXISTS events_protocol_port ON events(protocol, port, occurred_at DESC)")

    @staticmethod
    def _record_value(connection: sqlite3.Connection, value: Mapping[str, Any]) -> None:
        details = json.dumps(_safe_value(value.get("details", {})), sort_keys=True, separators=(",", ":"))
        connection.execute(
                    """INSERT OR IGNORE INTO events
                    (event_id,schema,occurred_at,observed_at,monotonic_ns,boot_id,session_id,component,source,category,event_type,
                     action,outcome,severity,assessment,application,operation_id,transaction_id,unit,rule_id,destination_json,protocol,port,decision,correlation_json,
                     details_json,quality_json,native_evidence_json,retention_class,expires_at,inserted_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        _text(value["event_id"], 96), value["schema"], _text(value["occurred_at"], 64),
                        _text(value["observed_at"], 64), value.get("monotonic_ns"), _text(value.get("boot_id"), 64) or None,
                        _text(value.get("session_id"), 96) or None,
                        _text(value["component"], 96), _text(value["source"], 128), _text(value["category"], 64),
                        _text(value["event_type"], 96), _text(value["action"], 64), _text(value["outcome"], 64),
                        _text(value["severity"], 32), _text(value["assessment"], 48), _text(value.get("application"), 240) or None,
                        _text((value.get("correlation") or {}).get("operation_id"), 160) or None,
                        _text((value.get("correlation") or {}).get("transaction_id"), 160) or None,
                        _text((value.get("correlation") or {}).get("unit"), 160) or None,
                        _text((value.get("correlation") or {}).get("rule_id"), 160) or None,
                        json.dumps(_safe_value(value.get("destination") or {}), sort_keys=True, separators=(",", ":")),
                        _text(value.get("protocol"), 24) or None, value.get("port"), _text(value.get("decision"), 24).upper() or None,
                        json.dumps(_safe_value(value.get("correlation") or {}), sort_keys=True, separators=(",", ":")),
                        details, json.dumps(_safe_value(value.get("quality") or {}), sort_keys=True, separators=(",", ":")),
                        json.dumps(_safe_value(value.get("native_evidence") or {}), sort_keys=True, separators=(",", ":")),
                        _text(value["retention_class"], 24), _text(value["expires_at"], 64), stamp(),
                    ),
                )
        for relation in value.get("relations", [])[:MAX_RELATIONS]:
            if not isinstance(relation, Mapping) or not relation.get("event_id"):
                continue
            connection.execute(
                        "INSERT OR IGNORE INTO event_relations(event_id,related_event_id,relation,confidence,basis) VALUES(?,?,?,?,?)",
                        (_text(value["event_id"], 96), _text(relation.get("event_id"), 96), _text(relation.get("relation"), 48), _text(relation.get("confidence"), 24), _text(relation.get("basis"), 160)),
            )

    def record(self, value: Mapping[str, Any]) -> bool:
        return bool(self.record_many([value]))

    def record_many(self, values: list[Mapping[str, Any]]) -> int:
        """Persist several normalized events with one connection and prune."""
        prepared = []
        for value in values:
            if value.get("schema") != SCHEMA or not value.get("event_id"):
                raise TelemetryError("Invalid telemetry event")
            details = json.dumps(_safe_value(value.get("details", {})), sort_keys=True, separators=(",", ":"))
            if len(details.encode("utf-8")) > MAX_DETAILS_BYTES:
                raise TelemetryError("Telemetry event details are too large")
            prepared.append(value)
        if not prepared:
            return 0
        connection = self._connect()
        try:
            with connection:
                for value in prepared:
                    self._record_value(connection, value)
        finally:
            connection.close()
        self.prune()
        return len(prepared)

    def prune(self, connection: sqlite3.Connection | None = None, now: str | None = None) -> dict[str, int]:
        owned = connection is None
        connection = connection or self._connect()
        removed_expired = 0
        removed_for_size = 0
        try:
            with connection:
                cursor = connection.execute("DELETE FROM events WHERE expires_at < ?", (now or stamp(),))
                removed_expired = cursor.rowcount
                # File-security records are evidence, but must remain bounded
                # independently of the normalized event table. Keep active
                # quarantine records until the object is explicitly handled;
                # old completed history is safe to age out.
                cutoff = connection.execute("SELECT datetime(?, '-30 days')", (now or stamp(),)).fetchone()[0]
                connection.execute("DELETE FROM file_detection_actions WHERE datetime(occurred_at) < datetime(?)", (cutoff,))
                connection.execute("DELETE FROM file_detections WHERE state IN ('RESTORED','DELETED') AND datetime(updated_at) < datetime(?)", (cutoff,))
                connection.execute("DELETE FROM file_scan_operations WHERE ended_at IS NOT NULL AND datetime(ended_at) < datetime(?)", (cutoff,))
                connection.execute(
                    """DELETE FROM file_detection_actions WHERE action_id NOT IN
                    (SELECT action_id FROM file_detection_actions ORDER BY occurred_at DESC, action_id DESC LIMIT 2048)"""
                )
                connection.execute(
                    """DELETE FROM file_scan_operations WHERE operation_id NOT IN
                    (SELECT operation_id FROM file_scan_operations ORDER BY started_at DESC LIMIT ?) AND state NOT IN ('QUEUED','SCANNING','FINALIZING')""",
                    (MAX_FILE_OPERATIONS,),
                )
                connection.execute(
                    """DELETE FROM file_detections WHERE detection_id NOT IN
                    (SELECT detection_id FROM file_detections ORDER BY updated_at DESC LIMIT ?) AND state NOT IN ('QUARANTINED','QUARANTINE_FAILED')""",
                    (MAX_FILE_DETECTIONS,),
                )
            while self._size_bytes() > self.max_bytes:
                row = connection.execute(
                    "SELECT event_id FROM events ORDER BY CASE retention_class WHEN 'investigation' THEN 0 ELSE 1 END, occurred_at ASC, event_id ASC LIMIT 64"
                ).fetchall()
                if not row:
                    file_rows = connection.execute(
                        "SELECT detection_id FROM file_detections WHERE state NOT IN ('QUARANTINED','QUARANTINE_FAILED') ORDER BY updated_at ASC, detection_id ASC LIMIT 64"
                    ).fetchall()
                    if file_rows:
                        with connection:
                            connection.executemany("DELETE FROM file_detections WHERE detection_id = ?", [(item["detection_id"],) for item in file_rows])
                        removed_for_size += len(file_rows)
                        continue
                    operation_rows = connection.execute(
                        "SELECT operation_id FROM file_scan_operations WHERE state NOT IN ('QUEUED','SCANNING','FINALIZING') ORDER BY started_at ASC, operation_id ASC LIMIT 64"
                    ).fetchall()
                    if operation_rows:
                        with connection:
                            connection.executemany("DELETE FROM file_scan_operations WHERE operation_id = ?", [(item["operation_id"],) for item in operation_rows])
                        removed_for_size += len(operation_rows)
                        continue
                    break
                with connection:
                    connection.executemany("DELETE FROM events WHERE event_id = ?", [(item["event_id"],) for item in row])
                removed_for_size += len(row)
                connection.execute("PRAGMA wal_checkpoint(PASSIVE)")
            with connection:
                for key, value in {
                    "last_prune_at": now or stamp(),
                    "last_expired_deletions": str(removed_expired),
                    "last_size_evictions": str(removed_for_size),
                }.items():
                    connection.execute("INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
            if removed_expired or removed_for_size:
                # Keep deleted pages and the WAL inside the same disk budget.
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                connection.execute("VACUUM")
            return {"expired": removed_expired, "size": removed_for_size}
        finally:
            if owned:
                connection.close()

    def _size_bytes(self) -> int:
        total = 0
        for candidate in (self.path, Path(str(self.path) + "-wal"), Path(str(self.path) + "-shm")):
            try:
                total += candidate.stat().st_size
            except OSError:
                pass
        return total

    @staticmethod
    def _cursor(value: str | None) -> tuple[str, str] | None:
        if not value:
            return None
        try:
            padding = "=" * (-len(value) % 4)
            decoded = json.loads(base64.urlsafe_b64decode((value + padding).encode("ascii")).decode("utf-8"))
            if isinstance(decoded, list) and len(decoded) == 2:
                return _text(decoded[0], 64), _text(decoded[1], 96)
        except (ValueError, TypeError, binascii.Error, json.JSONDecodeError):
            pass
        raise TelemetryError("Invalid telemetry cursor")

    @staticmethod
    def _make_cursor(row: sqlite3.Row) -> str:
        value = json.dumps([row["occurred_at"], row["event_id"]], separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

    @staticmethod
    def _row_value(row: sqlite3.Row) -> dict[str, Any]:
        value = dict(row)
        for key in ("destination_json", "correlation_json", "details_json", "quality_json", "native_evidence_json"):
            target = key.removesuffix("_json")
            try:
                value[target] = json.loads(value.pop(key))
            except (TypeError, json.JSONDecodeError):
                value[target] = {}
        return value

    @staticmethod
    def _attach_relations(connection: sqlite3.Connection, values: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not values:
            return values
        ids = [value["event_id"] for value in values]
        placeholders = ",".join("?" for _ in ids)
        rows = connection.execute(
            f"SELECT event_id,related_event_id,relation,confidence,basis FROM event_relations WHERE event_id IN ({placeholders}) OR related_event_id IN ({placeholders})",
            (*ids, *ids),
        ).fetchall()
        by_id = {value["event_id"]: value for value in values}
        for row in rows:
            if row["event_id"] in by_id:
                by_id[row["event_id"]].setdefault("relations", []).append({"event_id": row["related_event_id"], "relation": row["relation"], "confidence": row["confidence"], "basis": row["basis"]})
            if row["related_event_id"] in by_id:
                by_id[row["related_event_id"]].setdefault("relations", []).append({"event_id": row["event_id"], "relation": row["relation"], "confidence": row["confidence"], "basis": row["basis"]})
        return values

    def query(self, filters: Mapping[str, Any] | None = None) -> dict[str, Any]:
        filters = filters or {}
        limit = max(1, min(MAX_QUERY_EVENTS, int(filters.get("limit", 128))))
        clauses, params = [], []
        for key in ("component", "source", "category", "event_type", "severity", "assessment", "application", "boot_id"):
            value = filters.get(key)
            if value:
                clauses.append(f"{key} = ?")
                params.append(_text(value, 160))
        if filters.get("session_id"):
            clauses.append("session_id = ?")
            params.append(_text(filters["session_id"], 96))
        for key in ("operation_id", "transaction_id", "unit", "rule_id"):
            value = filters.get(key)
            if value:
                clauses.append(f"{key} = ?")
                params.append(_text(value, 160))
        for key in ("decision", "protocol"):
            value = filters.get(key)
            if value:
                clauses.append(f"{key} = ?")
                params.append(_text(value, 32).upper() if key == "decision" else _text(value, 24).lower())
        if filters.get("port") not in (None, ""):
            try:
                clauses.append("port = ?")
                params.append(int(filters["port"]))
            except (TypeError, ValueError) as error:
                raise TelemetryError("Invalid telemetry port") from error
        if filters.get("destination"):
            host = _text(filters["destination"], 240).lower().replace("%", "")
            clauses.append("lower(destination_json) LIKE ?")
            params.append("%\"host\":\"" + host + "%")
        if filters.get("search"):
            search = _text(filters["search"], 160).lower().replace("%", "")
            clauses.append("(lower(COALESCE(application, '')) LIKE ? OR lower(destination_json) LIKE ?)")
            params.extend(["%" + search + "%", "%" + search + "%"])
        for key, operator in (("from", ">="), ("to", "<=")):
            value = filters.get(key)
            if value:
                clauses.append(f"occurred_at {operator} ?")
                params.append(_text(value, 64))
        cursor = self._cursor(filters.get("cursor"))
        if cursor:
            clauses.append("(occurred_at < ? OR (occurred_at = ? AND event_id < ?))")
            params.extend([cursor[0], cursor[0], cursor[1]])
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        connection = self._connect()
        try:
            rows = connection.execute(f"SELECT * FROM events{where} ORDER BY occurred_at DESC, event_id DESC LIMIT ?", (*params, limit + 1)).fetchall()
            truncated = len(rows) > limit
            rows = rows[:limit]
            events = self._attach_relations(connection, [self._row_value(row) for row in rows])
            result = {
                "schema": QUERY_SCHEMA,
                "generated_at": stamp(),
                "events": events,
                "truncated": truncated,
                "next_cursor": self._make_cursor(rows[-1]) if truncated and rows else None,
                "source_state": self.status(connection),
            }
            encoded = json.dumps(result, sort_keys=True, separators=(",", ":"))
            if len(encoded.encode("utf-8")) > MAX_QUERY_BYTES:
                result["events"] = events[: max(1, len(events) // 2)]
                result["truncated"] = True
                result["size_limited"] = True
            return result
        finally:
            connection.close()

    def related(self, event_id: str, limit: int = 128) -> dict[str, Any]:
        connection = self._connect()
        try:
            root = connection.execute("SELECT * FROM events WHERE event_id = ?", (_text(event_id, 96),)).fetchone()
            if root is None:
                return {"schema": QUERY_SCHEMA, "generated_at": stamp(), "events": [], "source_state": self.status(connection)}
            related = connection.execute(
                """SELECT e.* FROM events e JOIN event_relations r
                   ON (r.related_event_id=e.event_id AND r.event_id=?)
                   OR (r.event_id=e.event_id AND r.related_event_id=?)
                   ORDER BY e.occurred_at DESC LIMIT ?""",
                (_text(event_id, 96), _text(event_id, 96), max(1, min(MAX_QUERY_EVENTS, int(limit)))),
            ).fetchall()
            values = [self._row_value(root)] + [self._row_value(row) for row in related if row["event_id"] != root["event_id"]]
            values = self._attach_relations(connection, values)
            return {"schema": QUERY_SCHEMA, "generated_at": stamp(), "seed_event_id": event_id, "events": values[:MAX_QUERY_EVENTS], "source_state": self.status(connection)}
        finally:
            connection.close()

    def status(self, connection: sqlite3.Connection | None = None) -> dict[str, Any]:
        owned = connection is None
        connection = connection or self._connect()
        result = None
        try:
            count, oldest, newest = connection.execute("SELECT COUNT(*), MIN(occurred_at), MAX(occurred_at) FROM events").fetchone()
            metadata = {row["key"]: row["value"] for row in connection.execute("SELECT key,value FROM metadata").fetchall()}
            result = {"source": "greyward-sqlite-history", "state": "AVAILABLE", "count": count, "oldest": oldest, "newest": newest, "max_bytes": self.max_bytes, "retention_days": {"investigation": INVESTIGATION_DAYS, "semantic": SEMANTIC_DAYS}, "last_prune_at": metadata.get("last_prune_at"), "last_size_evictions": int(metadata.get("last_size_evictions", "0") or 0)}
        finally:
            if owned:
                connection.close()
        result["size_bytes"] = self._size_bytes()
        return result

    def create_file_scan(self, value: Mapping[str, Any]) -> dict[str, Any]:
        connection = self._connect()
        try:
            with connection:
                connection.execute(
                    """INSERT INTO file_scan_operations
                    (operation_id,mode,scope_json,state,phase,started_at,files_inspected,detection_count,
                     error_count,skipped_count,total_files,total_known,detail,scanner_version,database_version)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (_text(value.get("operation_id"), 96), _text(value.get("mode"), 24),
                     json.dumps(_safe_value(value.get("scope") or {}), sort_keys=True, separators=(",", ":")),
                     _text(value.get("state"), 24) or "QUEUED", _text(value.get("phase"), 48) or "QUEUED",
                     _text(value.get("started_at"), 64) or stamp(), int(value.get("files_inspected", 0) or 0),
                     int(value.get("detection_count", 0) or 0), int(value.get("error_count", 0) or 0),
                     int(value.get("skipped_count", 0) or 0), value.get("total_files"),
                     int(bool(value.get("total_known"))), _text(value.get("detail"), 320) or None,
                     _text(value.get("scanner_version"), 48) or None, _text(value.get("database_version"), 96) or None),
                )
            return self.get_file_scan(_text(value.get("operation_id"), 96)) or {}
        finally:
            connection.close()

    def update_file_scan(self, operation_id: str, **changes: Any) -> dict[str, Any] | None:
        allowed = {"state", "phase", "ended_at", "files_inspected", "detection_count", "error_count",
                   "skipped_count", "total_files", "total_known", "detail", "scanner_version", "database_version"}
        changes = {key: value for key, value in changes.items() if key in allowed}
        if not changes:
            return self.get_file_scan(operation_id)
        assignments = ",".join(f"{key} = ?" for key in changes)
        values = [int(bool(value)) if key == "total_known" else value for key, value in changes.items()]
        connection = self._connect()
        try:
            with connection:
                connection.execute(f"UPDATE file_scan_operations SET {assignments} WHERE operation_id = ?", (*values, _text(operation_id, 96)))
            return self.get_file_scan(operation_id)
        finally:
            connection.close()

    def get_file_scan(self, operation_id: str) -> dict[str, Any] | None:
        connection = self._connect()
        try:
            row = connection.execute("SELECT * FROM file_scan_operations WHERE operation_id = ?", (_text(operation_id, 96),)).fetchone()
            if not row:
                return None
            value = dict(row)
            try: value["scope"] = json.loads(value.pop("scope_json"))
            except (TypeError, json.JSONDecodeError): value["scope"] = {}
            value["total_known"] = bool(value.get("total_known"))
            return value
        finally:
            connection.close()

    def list_file_scans(self, limit: int = 32) -> list[dict[str, Any]]:
        connection = self._connect()
        try:
            rows = connection.execute("SELECT operation_id FROM file_scan_operations ORDER BY started_at DESC LIMIT ?", (max(1, min(128, int(limit))),)).fetchall()
            return [value for row in rows if (value := self.get_file_scan(row["operation_id"]))]
        finally:
            connection.close()

    def upsert_file_detection(self, value: Mapping[str, Any]) -> dict[str, Any]:
        detection_id = _text(value.get("detection_id"), 128)
        if not detection_id:
            raise TelemetryError("Detection ID is required")
        connection = self._connect()
        try:
            with connection:
                connection.execute(
                    """INSERT INTO file_detections
                    (detection_id,operation_id,original_path,file_ref,detection_name,detected_at,scanner_version,
                     database_version,file_size,file_hash,state,quarantine_id,restore_staging_path,last_error,updated_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(detection_id) DO UPDATE SET state=excluded.state,quarantine_id=excluded.quarantine_id,
                    restore_staging_path=excluded.restore_staging_path,last_error=excluded.last_error,updated_at=excluded.updated_at""",
                    (detection_id, _text(value.get("operation_id"), 96), _text(value.get("original_path"), 4096),
                     _text(value.get("file_ref"), 96), _text(value.get("detection_name"), 160) or "Known threat",
                     _text(value.get("detected_at"), 64) or stamp(), _text(value.get("scanner_version"), 48) or None,
                     _text(value.get("database_version"), 96) or None, value.get("file_size"), _text(value.get("file_hash"), 128) or None,
                     _text(value.get("state"), 32) or "DETECTED", _text(value.get("quarantine_id"), 128) or None,
                     _text(value.get("restore_staging_path"), 4096) or None, _text(value.get("last_error"), 320) or None,
                     _text(value.get("updated_at"), 64) or stamp()),
                )
            return self.get_file_detection(detection_id) or {}
        finally:
            connection.close()

    def get_file_detection(self, detection_id: str) -> dict[str, Any] | None:
        connection = self._connect()
        try:
            row = connection.execute("SELECT * FROM file_detections WHERE detection_id = ?", (_text(detection_id, 128),)).fetchone()
            if not row: return None
            value = dict(row)
            actions = connection.execute("SELECT action,outcome,occurred_at,detail FROM file_detection_actions WHERE detection_id = ? ORDER BY occurred_at DESC", (_text(detection_id, 128),)).fetchall()
            value["actions"] = [dict(action) for action in actions]
            return value
        finally:
            connection.close()

    def list_file_detections(self, *, state: str | None = None, operation_id: str | None = None, limit: int = 128) -> list[dict[str, Any]]:
        connection = self._connect()
        try:
            if state and operation_id:
                rows = connection.execute("SELECT detection_id FROM file_detections WHERE state = ? AND operation_id = ? ORDER BY updated_at DESC LIMIT ?", (_text(state, 32), _text(operation_id, 96), max(1, min(256, int(limit))))).fetchall()
            elif state:
                rows = connection.execute("SELECT detection_id FROM file_detections WHERE state = ? ORDER BY updated_at DESC LIMIT ?", (_text(state, 32), max(1, min(256, int(limit))))).fetchall()
            elif operation_id:
                rows = connection.execute("SELECT detection_id FROM file_detections WHERE operation_id = ? ORDER BY updated_at DESC LIMIT ?", (_text(operation_id, 96), max(1, min(256, int(limit))))).fetchall()
            else:
                rows = connection.execute("SELECT detection_id FROM file_detections ORDER BY updated_at DESC LIMIT ?", (max(1, min(256, int(limit))),)).fetchall()
            return [value for row in rows if (value := self.get_file_detection(row["detection_id"]))]
        finally:
            connection.close()

    def record_file_action(self, detection_id: str, action: str, outcome: str, detail: str = "") -> bool:
        connection = self._connect()
        try:
            with connection:
                connection.execute("INSERT INTO file_detection_actions(detection_id,action,outcome,occurred_at,detail) VALUES(?,?,?,?,?)", (_text(detection_id, 128), _text(action, 48), _text(outcome, 32), stamp(), _text(detail, 320) or None))
            return True
        finally:
            connection.close()

    @staticmethod
    def _device_row(row: sqlite3.Row) -> dict[str, Any]:
        value = dict(row)
        value["connected"] = bool(value.get("connected"))
        value["trusted"] = bool(value.get("trusted"))
        value["reviewed"] = bool(value.get("reviewed"))
        return value

    def sync_devices(self, observations: list[Mapping[str, Any]], *, source_quality: str = "AVAILABLE") -> dict[str, Any]:
        """Synchronize only an available scan; unavailable scans never imply removal."""
        connection = self._connect()
        try:
            if source_quality != "AVAILABLE":
                return {"source_state": source_quality, "devices": [], "changed": False}
            current = stamp()
            with connection:
                connection.execute("UPDATE devices SET connected = 0 WHERE connected = 1")
                for item in observations[:128]:
                    identity = _text(item.get("identity_id"), 96)
                    if not identity:
                        continue
                    existing = connection.execute("SELECT * FROM devices WHERE identity_id = ?", (identity,)).fetchone()
                    first_seen = existing["first_seen"] if existing else _text(item.get("observed_at"), 64) or current
                    reviewed = int(existing["reviewed"]) if existing else 0
                    connection.execute(
                        """INSERT INTO devices(identity_id,identity_confidence,name,device_class,first_seen,last_seen,connected,trusted,state,source_quality,last_event_id,reviewed)
                           VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                           ON CONFLICT(identity_id) DO UPDATE SET identity_confidence=excluded.identity_confidence,
                           name=excluded.name,device_class=excluded.device_class,last_seen=excluded.last_seen,
                           connected=excluded.connected,trusted=excluded.trusted,state=excluded.state,
                           source_quality=excluded.source_quality,last_event_id=excluded.last_event_id,reviewed=devices.reviewed""",
                        (identity, _text(item.get("identity_confidence"), 24) or "LOW", _text(item.get("name"), 120) or "External device",
                         _text(item.get("device_class"), 48) or "UNKNOWN", first_seen, _text(item.get("observed_at"), 64) or current,
                         1, int(bool(item.get("trusted"))), _text(item.get("state"), 24) or "UNKNOWN", _text(source_quality, 32),
                         _text(item.get("event_id"), 96) or None, reviewed),
                    )
            rows = connection.execute("SELECT * FROM devices ORDER BY last_seen DESC, identity_id DESC LIMIT 128").fetchall()
            return {"source_state": "AVAILABLE", "devices": [self._device_row(row) for row in rows], "changed": True}
        finally:
            connection.close()

    def list_devices(self, *, since: str | None = None, unknown_only: bool = False, limit: int = 128) -> dict[str, Any]:
        connection = self._connect()
        try:
            clauses, params = [], []
            if since:
                clauses.append("first_seen >= ?"); params.append(_text(since, 64))
            if unknown_only:
                clauses.append("trusted = 0 AND reviewed = 0")
            where = " WHERE " + " AND ".join(clauses) if clauses else ""
            rows = connection.execute(f"SELECT * FROM devices{where} ORDER BY first_seen DESC, identity_id DESC LIMIT ?", (*params, max(1, min(128, int(limit))))).fetchall()
            return {"source_state": "AVAILABLE", "devices": [self._device_row(row) for row in rows]}
        finally:
            connection.close()

    def set_device_reviewed(self, identity_id: str) -> bool:
        connection = self._connect()
        try:
            with connection:
                cursor = connection.execute("UPDATE devices SET reviewed = 1 WHERE identity_id = ?", (_text(identity_id, 96),))
            return cursor.rowcount == 1
        finally:
            connection.close()

    def upsert_finding(self, value: Mapping[str, Any]) -> dict[str, Any]:
        finding_id = _text(value.get("finding_id"), 128)
        if not finding_id:
            raise TelemetryError("Finding ID is required")
        connection = self._connect()
        try:
            now = _text(value.get("last_seen"), 64) or stamp()
            existing = connection.execute("SELECT * FROM findings WHERE finding_id = ?", (finding_id,)).fetchone()
            with connection:
                connection.execute(
                    """INSERT INTO findings(finding_id,kind,subject_key,state,severity,title,summary,destination,first_seen,last_seen,resolved_at,evidence_json)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(finding_id) DO UPDATE SET state=excluded.state,severity=excluded.severity,title=excluded.title,
                       summary=excluded.summary,destination=excluded.destination,last_seen=excluded.last_seen,
                       resolved_at=excluded.resolved_at,evidence_json=excluded.evidence_json""",
                    (finding_id, _text(value.get("kind"), 64), _text(value.get("subject_key"), 160), _text(value.get("state"), 24),
                     _text(value.get("severity"), 24), _text(value.get("title"), 160), _text(value.get("summary"), 320),
                     _text(value.get("destination"), 64) or "overview", _text(value.get("first_seen"), 64) or (existing["first_seen"] if existing else now),
                     now, _text(value.get("resolved_at"), 64) or None, json.dumps(_safe_value(value.get("evidence", [])), separators=(",", ":"))))
            return dict(connection.execute("SELECT * FROM findings WHERE finding_id = ?", (finding_id,)).fetchone())
        finally:
            connection.close()

    def list_findings(self, *, unresolved_only: bool = False, limit: int = 64) -> list[dict[str, Any]]:
        connection = self._connect()
        try:
            where = " WHERE state = 'UNRESOLVED'" if unresolved_only else ""
            rows = connection.execute(f"SELECT * FROM findings{where} ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'WARNING' THEN 1 ELSE 2 END, last_seen DESC LIMIT ?", (max(1, min(64, int(limit))),)).fetchall()
            values = []
            for row in rows:
                value = dict(row)
                try: value["evidence"] = json.loads(value.pop("evidence_json"))
                except (TypeError, json.JSONDecodeError): value["evidence"] = []
                values.append(value)
            return values
        finally:
            connection.close()


def derive_device_identity(metadata: Mapping[str, Any], key_path: Path | str | None = None) -> tuple[str | None, str]:
    """Return an opaque identity; raw approved metadata never leaves this function."""
    # A physical port is useful context, but it is not a device identity:
    # identical devices can occupy the same port over time. Without a
    # stronger stable identifier, do not claim reconnect deduplication.
    if not any(metadata.get(key) for key in ("stable_id", "serial", "hash")):
        return None, "LOW"
    material = "|".join(_text(metadata.get(key), 160) for key in ("stable_id", "serial", "hash", "via_port", "vendor_id", "product_id", "interface", "device_class") if metadata.get(key))
    if not material:
        return None, "LOW"
    path = Path(key_path or Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "greyward/device-identity.key")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            key = path.read_bytes()
        else:
            key = os.urandom(32)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
            try:
                descriptor = os.open(path, flags, 0o600)
            except FileExistsError:
                key = path.read_bytes()
            else:
                try:
                    offset = 0
                    while offset < len(key):
                        offset += os.write(descriptor, key[offset:])
                    os.fsync(descriptor)
                finally: os.close(descriptor)
        if len(key) < 16:
            return None, "LOW"
        digest = hmac.new(key, material.encode("utf-8"), hashlib.sha256).hexdigest()
        confidence = "HIGH"
        return "usb-hmac-" + digest[:48], confidence
    except (OSError, ValueError):
        return None, "LOW"


def record_event(value: Mapping[str, Any], store: TelemetryStore | None = None) -> bool:
    """Best-effort telemetry recording; telemetry failure must not break control."""
    if os.name != "posix" and store is None and not os.environ.get("GREYWARD_TELEMETRY_DB"):
        return False
    try:
        # Root-owned collectors must not write a database that the user-bus
        # service cannot safely read. Keep the approved event in the bounded
        # runtime handoff spool; the user service imports it into its own DB.
        root_collector = (
            store is None
            and os.name == "posix"
            and hasattr(os, "geteuid")
            and os.geteuid() == 0
            and not os.environ.get("GREYWARD_TELEMETRY_DB")
        )
        recorded = spool_event(value) if root_collector else (store or TelemetryStore()).record(value)
    except (TelemetryError, OSError, sqlite3.Error):
        return False
    if recorded and _journal is not None:
        try:
            payload = json.dumps(_safe_value(dict(value)), sort_keys=True, separators=(",", ":"))
            _journal.send(
                MESSAGE=payload,
                SYSLOG_IDENTIFIER="greyward-telemetry",
                GREYWARD_EVENT="1",
                GREYWARD_SCHEMA=SCHEMA,
                GREYWARD_EVENT_ID=_text(value.get("event_id"), 96),
                GREYWARD_CATEGORY=_text(value.get("category"), 64),
                GREYWARD_EVENT_TYPE=_text(value.get("event_type"), 96),
            )
        except Exception:
            # SQLite history remains valid when journald is unavailable.
            pass
    return recorded
