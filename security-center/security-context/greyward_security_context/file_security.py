"""Bounded ClamAV operations and file-security state.

The module deliberately owns no policy beyond the approved scan scopes.  The
Security Context services expose this manager through narrow typed methods;
the UI never receives a scanner command line or uses a path as an action key.
"""
from __future__ import annotations

import hashlib
import json
import os
try:
    import pwd
except ImportError:  # Windows-only syntax/unit-test environments
    pwd = None
import re
import signal
import stat
import subprocess
import tempfile
import threading
import uuid
from pathlib import Path
from typing import Any, Mapping

from .clamav import DATABASE_DIRS, _version, status as clamav_status
from .telemetry import TelemetryError, TelemetryStore, event, record_event, stamp

SCAN_STATES = {"QUEUED", "SCANNING", "FINALIZING", "COMPLETED", "PARTIAL", "CANCELLED", "INTERRUPTED", "FAILED"}
MODES = {"FILE", "FOLDER", "SYSTEM"}
SYSTEM_EXCLUDES = {
    "/proc", "/sys", "/dev", "/run", "/media", "/mnt", "/var/lib/greyward/quarantine",
}
FOUND_RE = re.compile(r"^(.*?):\s*(.+?)\s+FOUND\s*$")
ERROR_RE = re.compile(r"\b(error|warning|access denied|permission denied|cannot open)\b", re.I)
PRIVATE_TMP_ROOTS = (Path("/tmp"), Path("/var/tmp"))
QUARANTINE_ID_RE = re.compile(r"^q-[a-f0-9]{32}$")
SCAN_TIMEOUT_SECONDS = 2 * 60 * 60

FILE_ACTIVITY_TITLES = {
    "FILE_SCAN_STARTED": ("Scan started", "GREYWARD started inspecting the selected scope."),
    "FILE_SCAN_COMPLETED": ("Scan completed", "The selected scope was inspected without a scan error."),
    "FILE_SCAN_CANCELLED": ("Scan cancelled", "The scan was cancelled before completion; this is not a clean result."),
    "FILE_SCAN_PARTIAL": ("Scan incomplete", "The scan completed with errors; some files may not have been inspected."),
    "FILE_SCAN_FAILED": ("Scan failed", "The scanner could not complete the selected operation."),
    "FILE_DETECTION": ("Threat detected", "ClamAV identified a known threat in an inspected file."),
    "FILE_QUARANTINED": ("File quarantined", "The detected file was moved to protected GREYWARD quarantine."),
    "FILE_QUARANTINE_FAILED": ("Quarantine failed", "The detected file was not removed from its original location."),
    "FILE_RESTORED": ("File restored for review", "The quarantined content was restored to a collision-safe review location."),
    "FILE_RESTORE_FAILED": ("Restore failed", "The quarantined content was not restored."),
    "FILE_DELETED": ("Quarantined file deleted", "The quarantined object was permanently deleted."),
    "FILE_DELETE_FAILED": ("Permanent deletion failed", "The quarantined object could not be permanently deleted."),
    "SAFE_OPEN_RESULT": ("Safe Open", "The selected file was handled by the restricted no-network context."),
    "SANITIZATION_RESULT": ("Sanitized copy", "A separate metadata-sanitized copy operation was recorded."),
}


def _file_ref(path: str) -> str:
    return "file-" + hashlib.sha256(path.encode("utf-8", "replace")).hexdigest()[:24]


def _hash_file(path: Path) -> tuple[int | None, str | None]:
    descriptor = -1
    try:
        digest = hashlib.sha256()
        size = 0
        descriptor = _open_readonly_nofollow(path)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            return None, None
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
        return size, digest.hexdigest()
    except (OSError, ValueError):
        return None, None
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _safe_path(raw: str, *, owner_uid: int | None = None, directory: bool = False) -> Path:
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("Symlinks and empty paths are not valid scan sources.")
    candidate = Path(raw)
    if not candidate.is_absolute():
        raise ValueError("The selected source must be an absolute path.")
    # The system scanner runs with PrivateTmp, so a path in the caller's
    # /tmp namespace cannot be resolved from this service. Reject the
    # namespace before filesystem resolution so the caller gets the real
    # boundary reason instead of a misleading "does not exist" result.
    try:
        candidate_absolute = candidate.absolute()
    except (OSError, RuntimeError) as error:
        raise ValueError("The selected source is not visible to the scanning service.") from error
    if any(candidate_absolute == root or root in candidate_absolute.parents for root in PRIVATE_TMP_ROOTS):
        raise ValueError("The selected source is not visible to the scanning service; /tmp and /var/tmp are private to it.")
    # Reject symlinks anywhere in the selected path, not only when the final
    # directory entry is a link. The scanner contract never follows a path
    # through a user-controlled alias.
    current = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        current /= part
        if current.is_symlink():
            raise ValueError("Symlinks and empty paths are not valid scan sources.")
    try:
        resolved = candidate.resolve(strict=True)
    except (FileNotFoundError, OSError, RuntimeError) as error:
        raise ValueError("The selected source does not exist or is unavailable.") from error
    if any(resolved == root or root in resolved.parents for root in PRIVATE_TMP_ROOTS):
        raise ValueError("The selected source is not visible to the scanning service; /tmp and /var/tmp are private to it.")
    if directory and not resolved.is_dir():
        raise ValueError("The selected source is not a directory.")
    if not directory and not resolved.exists():
        raise ValueError("The selected source does not exist.")
    if owner_uid is not None:
        metadata = resolved.stat()
        if metadata.st_uid != owner_uid:
            raise PermissionError("The selected source is not owned by the requesting user.")
        required = stat.S_IRUSR | (stat.S_IXUSR if directory else 0)
        if metadata.st_mode & required != required:
            raise PermissionError("The selected source is not readable by the requesting user.")
    return resolved


def _safe_detected_file(raw: str) -> Path:
    """Resolve a scanner-reported file without following path aliases.

    Detection paths cross into the root-owned remediation service. They must
    be checked again at that boundary instead of trusting a path emitted by a
    scanner or a persisted record.
    """
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("The detected source is unavailable.")
    candidate = Path(raw)
    if not candidate.is_absolute():
        raise ValueError("The detected source must be an absolute path.")
    try:
        current = Path(candidate.anchor)
        for part in candidate.parts[1:]:
            current /= part
            if current.is_symlink():
                raise ValueError("The detected source path contains a symlink.")
        resolved = candidate.resolve(strict=True)
    except (FileNotFoundError, OSError, RuntimeError) as error:
        raise ValueError("The detected source is unavailable.") from error
    if not resolved.is_file() or resolved.is_symlink():
        raise ValueError("The detected source is no longer a regular file.")
    return resolved


def _open_readonly_nofollow(path: Path) -> int:
    """Open a regular-file source without allowing a raced path alias."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    if os.open in getattr(os, "supports_dir_fd", set()):
        directory_fd = os.open(path.anchor, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            parts = path.parts[1:]
            for part in parts[:-1]:
                next_fd = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = next_fd
            return os.open(parts[-1], flags, dir_fd=directory_fd)
        finally:
            try:
                os.close(directory_fd)
            except OSError:
                pass
    return os.open(path, flags)


def _unlink_verified_source(source: Path, expected_hash: str | None = None, owner_uid: int | None = None) -> None:
    """Remove exactly the regular file that was opened and hash-verified."""
    descriptor = -1
    try:
        descriptor = _open_readonly_nofollow(source)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("The source is no longer a regular file.")
        if owner_uid is not None and metadata.st_uid != owner_uid:
            raise PermissionError("The source is not owned by the requesting user.")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        actual_hash = digest.hexdigest()
        if expected_hash and actual_hash != expected_hash:
            raise ValueError("The source changed before it could be removed.")
        current = os.lstat(source)
        if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise ValueError("The source changed before it could be removed.")
        os.close(descriptor)
        descriptor = -1
        source.unlink()
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _system_exclude_args() -> list[str]:
    return ["--exclude-dir=" + re.escape(path) + r"(?:/|$)" for path in sorted(SYSTEM_EXCLUDES)]


def _parse_found(line: str) -> tuple[str, str] | None:
    match = FOUND_RE.match(line.strip())
    if not match:
        return None
    return match.group(1)[:4096], match.group(2)[:160]


def file_activity_items(values: list[Mapping[str, Any]] | None, limit: int = 64) -> list[dict[str, Any]]:
    """Project normalized File Security events into concise user activity."""
    projected = []
    for item in values or []:
        event_type = str(item.get("event_type") or "").upper()
        title, default_detail = FILE_ACTIVITY_TITLES.get(event_type, (None, None))
        if not title:
            continue
        details = item.get("details") if isinstance(item.get("details"), Mapping) else {}
        outcome = str(item.get("outcome") or "").upper()
        detail = default_detail
        if event_type == "FILE_DETECTION":
            name = str(details.get("message") or "").strip()
            detail = f"ClamAV identified {name[:160]}." if name else default_detail
        elif event_type in {"SAFE_OPEN_RESULT", "SANITIZATION_RESULT"}:
            detail = str(details.get("message") or default_detail)[:320]
        elif outcome in {"FAILURE", "FAILED", "PARTIAL"}:
            detail = str(details.get("message") or default_detail)[:320]
        occurred_at = str(item.get("occurred_at") or item.get("observed_at") or "")
        projected.append({
            "event_id": str(item.get("event_id") or "")[:96],
            "title": title,
            "detail": detail[:320],
            "category": "FILE_SECURITY",
            "severity": "IMPORTANT" if outcome in {"FAILURE", "FAILED"} else "REVIEW" if outcome in {"DETECTED", "PARTIAL"} else "INFORMATION",
            "occurred_at": occurred_at,
        })
    projected.sort(key=lambda value: (value.get("occurred_at", ""), value.get("event_id", "")), reverse=True)
    return projected[:max(1, min(128, int(limit)))]


class FileSecurityManager:
    """Own one bounded scan worker and durable operation/detection state."""

    def __init__(self, store: TelemetryStore | None = None):
        self.store = store or TelemetryStore()
        self.on_change = None
        self._lock = threading.RLock()
        self._cancel: dict[str, threading.Event] = {}
        self._process: dict[str, subprocess.Popen[str]] = {}
        self._pending_quarantines: dict[str, dict[str, Any]] = {}
        self._pending_restores: dict[str, dict[str, Any]] = {}

    def record_legacy_result(self, path: str, result: dict) -> None:
        """Put the synchronous scan entry point in the existing scan/detection store."""
        operation_id = "scan-" + uuid.uuid4().hex
        state = result.get("state")
        current = stamp()
        self.store.create_file_scan({
            "operation_id": operation_id, "mode": "FILE", "scope": {"label": Path(path).name},
            "state": "COMPLETED" if state in {"CLEAN", "THREAT"} else "FAILED",
            "phase": "COMPLETED" if state in {"CLEAN", "THREAT"} else "FAILED",
            "started_at": current, "ended_at": current, "files_inspected": int(state in {"CLEAN", "THREAT"}),
            "detection_count": int(state == "THREAT"), "detail": result.get("detail", "Scan finished."),
        })
        self.store.update_file_scan(operation_id, ended_at=current)
        if self.on_change:
            self.on_change()
        if state != "THREAT":
            return
        original = str(Path(path).absolute())
        size, file_hash = _hash_file(Path(original))
        # Repeated entry-point requests must not create duplicate unresolved alerts.
        if any(x.get("file_ref") == _file_ref(original) and x.get("file_hash") == file_hash
               and x.get("state") in {"DETECTED", "QUARANTINE_FAILED"} for x in self.detections()):
            return
        self.store.upsert_file_detection({
            "detection_id": "det-" + uuid.uuid4().hex, "operation_id": operation_id,
            "original_path": original, "file_ref": _file_ref(original),
            "detection_name": result.get("detection_name") or "Known threat", "detected_at": current,
            "file_size": size, "file_hash": file_hash, "state": "DETECTED",
        })
        if self.on_change:
            self.on_change()

    def _active(self) -> str | None:
        for item in self.store.list_file_scans(64):
            if item.get("state") in {"QUEUED", "SCANNING", "FINALIZING"}:
                operation_id = str(item.get("operation_id"))
                if self._mark_interrupted_if_orphaned(operation_id):
                    continue
                return operation_id
        return None

    def _mark_interrupted_if_orphaned(self, operation_id: str) -> bool:
        """Persist an orphaned active record as interrupted after worker loss.

        The running-worker maps are deliberately process-local.  If a fresh
        manager sees an active database record without a local worker token,
        no component remains able to finish or cancel that operation.  Keep
        the measured counters, but make the terminal result durable so every
        summary agrees that it is not a clean or actively running scan.
        """
        with self._lock:
            if operation_id in self._cancel:
                return False
        value = self.store.get_file_scan(operation_id)
        if not value or value.get("state") not in {"QUEUED", "SCANNING", "FINALIZING"}:
            return False
        self.store.update_file_scan(
            operation_id,
            state="INTERRUPTED",
            phase="INTERRUPTED",
            ended_at=stamp(),
            detail="The scan stopped before Security Context could finish it.",
        )
        return True

    def reconcile_interrupted_scans(self, limit: int = 64) -> list[dict[str, Any]]:
        """Return recent scans after durably reconciling orphaned workers."""
        for item in self.store.list_file_scans(limit):
            if item.get("state") in {"QUEUED", "SCANNING", "FINALIZING"}:
                self._mark_interrupted_if_orphaned(str(item.get("operation_id")))
        return self.store.list_file_scans(limit)

    def start(self, mode: str, paths: list[str] | None = None, *, owner_uid: int | None = None, authorized_system: bool = False) -> dict[str, Any]:
        mode = str(mode or "").upper()
        paths = paths or []
        if mode not in MODES:
            raise ValueError("Unsupported scan mode.")
        if self._active():
            raise RuntimeError("A file security scan is already running.")
        if mode == "SYSTEM":
            if not authorized_system:
                raise PermissionError("System scanning requires authorization.")
            scope = {"label": "Local system files", "roots": ["/"]}
        else:
            if len(paths) != 1:
                raise ValueError("Select exactly one file or folder.")
            selected = _safe_path(paths[0], owner_uid=owner_uid, directory=mode == "FOLDER")
            if mode == "FILE" and not selected.is_file():
                raise ValueError("The selected source is not a regular file.")
            scope = {"label": selected.name or str(selected), "path": str(selected), "kind": mode.lower()}
        info = clamav_status()
        if info.get("status") != "CURRENT" or not info.get("engine_version"):
            raise RuntimeError("ClamAV scanning is unavailable until its engine and current security database are available.")
        operation_id = "scan-" + uuid.uuid4().hex
        current = stamp()
        self.store.create_file_scan({
            "operation_id": operation_id, "mode": mode, "scope": scope, "state": "QUEUED", "phase": "QUEUED",
            "started_at": current, "scanner_version": info.get("engine_version"), "database_version": info.get("database_version"),
            "detail": "Waiting for the scanner.",
        })
        cancel = threading.Event()
        with self._lock:
            self._cancel[operation_id] = cancel
        threading.Thread(target=self._run, args=(operation_id, mode, scope, cancel), name="greyward-file-scan", daemon=True).start()
        return self.store.get_file_scan(operation_id) or {"operation_id": operation_id, "state": "QUEUED"}

    def cancel(self, operation_id: str) -> dict[str, Any] | None:
        with self._lock:
            token = self._cancel.get(operation_id)
            process = self._process.get(operation_id)
            if token is None:
                return self.store.get_file_scan(operation_id)
            token.set()
            if process is not None:
                try:
                    process.send_signal(signal.SIGTERM)
                except OSError:
                    pass
        return self.store.get_file_scan(operation_id)

    def status(self, operation_id: str) -> dict[str, Any] | None:
        self._mark_interrupted_if_orphaned(operation_id)
        value = self.store.get_file_scan(operation_id)
        if value:
            value["detections"] = self.store.list_file_detections(operation_id=operation_id) if hasattr(self.store, "list_file_detections") else []
        return value

    def detections(self, *, state: str | None = None, limit: int = 128) -> list[dict[str, Any]]:
        return self.store.list_file_detections(state=state, limit=limit)

    def activity(self, limit: int = 64) -> list[dict[str, Any]]:
        try:
            values = self.store.query({"category": "FILE_SECURITY", "limit": max(1, min(128, int(limit)))})
            return file_activity_items(values.get("events", []), limit)
        except (OSError, TelemetryError, TypeError, ValueError):
            return []

    @staticmethod
    def _quarantine_root(owner_uid: int) -> Path:
        return Path("/var/lib/greyward/quarantine") / str(int(owner_uid))

    @staticmethod
    def _copy_verified(source: Path, destination: Path, expected_hash: str | None = None, owner_uid: int | None = None) -> tuple[int, str]:
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".pending-", dir=destination.parent)
        digest = hashlib.sha256()
        size = 0
        source_descriptor = -1
        try:
            source_descriptor = _open_readonly_nofollow(source)
            source_metadata = os.fstat(source_descriptor)
            if not stat.S_ISREG(source_metadata.st_mode):
                raise ValueError("The source is no longer a regular file.")
            if owner_uid is not None and source_metadata.st_uid != owner_uid:
                raise PermissionError("The source is no longer owned by the requesting user.")
            with os.fdopen(source_descriptor, "rb") as source_handle, os.fdopen(descriptor, "wb") as destination_handle:
                source_descriptor = -1
                descriptor = -1
                for chunk in iter(lambda: source_handle.read(1024 * 1024), b""):
                    destination_handle.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)
                destination_handle.flush()
                os.fsync(destination_handle.fileno())
            actual_hash = digest.hexdigest()
            if expected_hash and actual_hash != expected_hash:
                raise ValueError("The source changed while it was being quarantined.")
            os.chmod(temporary, 0o600)
            os.replace(temporary, destination)
            return size, actual_hash
        finally:
            if source_descriptor >= 0:
                try:
                    os.close(source_descriptor)
                except OSError:
                    pass
            if descriptor >= 0:
                try: os.close(descriptor)
                except OSError: pass
            try: os.unlink(temporary)
            except FileNotFoundError: pass

    def _find_quarantine_object(self, quarantine_id: str, owner_uid: int | None = None) -> Path | None:
        if not QUARANTINE_ID_RE.fullmatch(quarantine_id):
            raise ValueError("The quarantine reference is invalid.")
        roots = [self._quarantine_root(int(owner_uid))] if owner_uid is not None else [self._quarantine_root(0)]
        roots.append(Path("/var/lib/greyward/quarantine"))
        for root in roots:
            candidate = root / (quarantine_id + ".object")
            if candidate.is_file() and not candidate.is_symlink():
                return candidate
        if owner_uid is None:
            for candidate in Path("/var/lib/greyward/quarantine").glob(f"*/{quarantine_id}.object"):
                if candidate.is_file() and not candidate.is_symlink():
                    return candidate
        return None

    def _write_manifest(self, path: Path, manifest: Mapping[str, Any]) -> None:
        descriptor, temporary = tempfile.mkstemp(prefix=".manifest-", dir=path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                descriptor = -1
                json.dump(dict(manifest), handle, sort_keys=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        finally:
            if descriptor >= 0:
                try: os.close(descriptor)
                except OSError: pass
            try: os.unlink(temporary)
            except FileNotFoundError: pass

    def prepare_quarantine(self, detection_id: str, *, actor_uid: int = 0) -> dict[str, Any]:
        """Copy and publish a quarantine object, leaving home mutation to the user bus."""
        detection = self.store.get_file_detection(detection_id)
        if not detection:
            raise ValueError("The detection is no longer available.")
        if detection.get("state") == "QUARANTINED":
            return detection
        source = _safe_detected_file(str(detection.get("original_path") or ""))
        if actor_uid and actor_uid != 0 and source.stat().st_uid not in {actor_uid, 0}:
            raise PermissionError("The detection is not owned by the requesting user.")
        owner_uid = int(source.stat().st_uid)
        root = self._quarantine_root(owner_uid)
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        quarantine_id = "q-" + uuid.uuid4().hex
        destination = root / (quarantine_id + ".object")
        manifest_path = root / (quarantine_id + ".json")
        try:
            size, digest = self._copy_verified(source, destination, detection.get("file_hash"), owner_uid=owner_uid)
            self._write_manifest(manifest_path, {
                "quarantine_id": quarantine_id, "detection_id": detection_id,
                "owner_uid": owner_uid, "original_path": str(source),
                "file_hash": digest, "file_size": size, "created_at": stamp(),
            })
            pending = {"state": "QUARANTINE_PENDING", "detection_id": detection_id,
                    "quarantine_id": quarantine_id, "source_path": str(source),
                    "owner_uid": owner_uid, "file_hash": digest, "file_size": size}
            with self._lock:
                self._pending_quarantines[detection_id] = pending
            return pending
        except (OSError, ValueError):
            if not manifest_path.exists():
                try: destination.unlink()
                except FileNotFoundError: pass
            raise

    def complete_quarantine(self, detection_id: str, *, actor_uid: int = 0) -> dict[str, Any]:
        detection = self.store.get_file_detection(detection_id)
        if not detection:
            raise ValueError("The detection is no longer available.")
        if detection.get("state") == "QUARANTINED":
            return detection
        source = Path(str(detection.get("original_path") or ""))
        if source.exists() or source.is_symlink():
            raise ValueError("The original file is still present; quarantine was not completed.")
        quarantine_id = str(detection.get("quarantine_id") or "")
        pending = self._find_pending_quarantine(detection_id)
        if pending:
            quarantine_id = pending.get("quarantine_id", quarantine_id)
        owner_value = (pending or {}).get("owner_uid") if pending else None
        object_path = self._find_quarantine_object(quarantine_id, int(owner_value) if owner_value is not None else None)
        if object_path is None:
            raise FileNotFoundError("The verified quarantine object is unavailable.")
        size, digest = _hash_file(object_path)
        if not digest:
            raise OSError("The verified quarantine object cannot be read.")
        expected = str((pending or {}).get("file_hash") or detection.get("file_hash") or digest)
        if digest != expected:
            raise ValueError("The quarantine object failed integrity verification.")
        result = self.store.upsert_file_detection({**detection, "state": "QUARANTINED", "quarantine_id": quarantine_id,
            "file_hash": digest, "file_size": size, "last_error": None})
        self.store.record_file_action(detection_id, "QUARANTINE", "SUCCESS", "Threat moved to GREYWARD quarantine.")
        self._emit(detection.get("operation_id", "file-security"), "FILE_QUARANTINED", "SUCCESS", "Threat moved to quarantine.", "WARNING", details={"detection_id": detection_id, "file_ref": detection.get("file_ref")})
        with self._lock:
            self._pending_quarantines.pop(detection_id, None)
        return result

    def _find_pending_quarantine(self, detection_id: str) -> dict[str, Any] | None:
        with self._lock:
            if detection_id in self._pending_quarantines:
                return dict(self._pending_quarantines[detection_id])
        detection = self.store.get_file_detection(detection_id) or {}
        quarantine_id = str(detection.get("quarantine_id") or "")
        if quarantine_id and QUARANTINE_ID_RE.fullmatch(quarantine_id):
            return {"quarantine_id": quarantine_id, "file_hash": detection.get("file_hash")}
        for root in (Path("/var/lib/greyward/quarantine"),):
            for manifest_path in root.glob("*/*.json"):
                try:
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                except (OSError, ValueError, json.JSONDecodeError):
                    continue
                if manifest.get("detection_id") == detection_id:
                    return manifest
        return None

    def fail_quarantine(self, detection_id: str, detail: str, *, actor_uid: int = 0) -> dict[str, Any]:
        detection = self.store.get_file_detection(detection_id)
        if not detection:
            raise ValueError("The detection is no longer available.")
        pending = self._find_pending_quarantine(detection_id) or {}
        value = {**detection, "state": "QUARANTINE_FAILED", "quarantine_id": pending.get("quarantine_id") or detection.get("quarantine_id"),
                 "file_hash": pending.get("file_hash") or detection.get("file_hash"), "file_size": pending.get("file_size") or detection.get("file_size"),
                 "last_error": str(detail)[:320]}
        result = self.store.upsert_file_detection(value)
        self.store.record_file_action(detection_id, "QUARANTINE", "FAILED", str(detail)[:320])
        self._emit(detection.get("operation_id", "file-security"), "FILE_QUARANTINE_FAILED", "FAILURE", str(detail)[:320], "ERROR", details={"detection_id": detection_id, "file_ref": detection.get("file_ref")})
        return result

    def _restore_target(self, detection: Mapping[str, Any], destination: str | None, actor_uid: int) -> Path:
        if destination:
            target = Path(destination)
        elif actor_uid:
            if pwd is None:
                raise PermissionError("User-home restore is unavailable on this platform.")
            try:
                home = Path(pwd.getpwuid(actor_uid).pw_dir).resolve()
            except (KeyError, OSError) as error:
                raise PermissionError("The requesting user's home is unavailable.") from error
            target = home / ".local" / "share" / "greyward" / "restore-staging" / (Path(str(detection.get("original_path") or "")).name or str(detection.get("detection_id")))
        else:
            target = Path("/var/lib/greyward/restore-staging") / str(detection.get("detection_id"))
        if not target.is_absolute():
            raise PermissionError("Restore destinations must be absolute paths.")
        if actor_uid:
            if pwd is None:
                raise PermissionError("User-home restore is unavailable on this platform.")
            try:
                home = Path(pwd.getpwuid(actor_uid).pw_dir).resolve()
                target.resolve(strict=False).relative_to(home)
            except (KeyError, ValueError, OSError) as error:
                raise PermissionError("Restore destinations must be inside the requesting user's home.") from error
        if target.exists() or target.is_symlink():
            raise FileExistsError("The restore destination already exists.")
        return target

    def prepare_restore(self, detection_id: str, destination: str | None = None, *, actor_uid: int = 0) -> dict[str, Any]:
        """Stage a verified object in /run; the user session creates the home file."""
        detection = self.store.get_file_detection(detection_id)
        if not detection or detection.get("state") not in {"QUARANTINED", "QUARANTINE_FAILED"}:
            raise ValueError("Only a quarantined detection can be restored.")
        quarantine_id = str(detection.get("quarantine_id") or "")
        source = self._find_quarantine_object(quarantine_id, actor_uid or None)
        if source is None:
            raise FileNotFoundError("The quarantined object is unavailable.")
        target = self._restore_target(detection, destination, actor_uid)
        transfer_root = Path("/run/greyward-file-security") / str(int(actor_uid))
        transfer_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(transfer_root, 0o700)
        if actor_uid:
            os.chown(transfer_root, actor_uid, -1)
        transfer = transfer_root / (detection_id + ".transfer")
        if transfer.exists() or transfer.is_symlink():
            raise FileExistsError("A restore operation is already staged for this detection.")
        try:
            size, digest = self._copy_verified(source, transfer, detection.get("file_hash"))
            if actor_uid:
                os.chown(transfer, actor_uid, -1)
            pending = {"state": "RESTORE_PENDING", "detection_id": detection_id,
                       "transfer_path": str(transfer), "destination": str(target),
                       "file_hash": digest, "file_size": size, "actor_uid": actor_uid}
            with self._lock:
                self._pending_restores[detection_id] = pending
            return pending
        except (OSError, ValueError):
            try: transfer.unlink()
            except FileNotFoundError: pass
            raise

    def complete_restore(self, detection_id: str, destination: str, *, actor_uid: int = 0) -> dict[str, Any]:
        detection = self.store.get_file_detection(detection_id)
        with self._lock:
            pending = dict(self._pending_restores.get(detection_id) or {})
        if not detection or not pending:
            raise ValueError("The restore operation is no longer pending.")
        target = Path(destination)
        if str(target) != str(pending.get("destination")):
            raise ValueError("The restore destination does not match the prepared operation.")
        if target.is_symlink() or not target.is_file():
            raise FileNotFoundError("The restored file was not created in the requested location.")
        if actor_uid and target.stat().st_uid != actor_uid:
            raise PermissionError("The restored file is not owned by the requesting user.")
        size, digest = _hash_file(target)
        if digest != pending.get("file_hash"):
            raise ValueError("The restored file failed integrity verification.")
        transfer = Path(str(pending.get("transfer_path") or ""))
        try: transfer.unlink()
        except FileNotFoundError: pass
        result = self.store.upsert_file_detection({**detection, "state": "RESTORED", "last_error": None,
            "file_size": size, "file_hash": digest, "restore_staging_path": str(target)})
        self.store.record_file_action(detection_id, "RESTORE", "SUCCESS", "Restored to review location.")
        self._emit(detection.get("operation_id", "file-security"), "FILE_RESTORED", "SUCCESS", "Quarantined file restored to a review location.", "WARNING", details={"detection_id": detection_id, "file_ref": detection.get("file_ref")})
        with self._lock:
            self._pending_restores.pop(detection_id, None)
        result["staging_path"] = str(target)
        return result

    def fail_restore(self, detection_id: str, detail: str, *, actor_uid: int = 0) -> dict[str, Any]:
        detection = self.store.get_file_detection(detection_id)
        if not detection:
            raise ValueError("The detection is no longer available.")
        result = self.store.upsert_file_detection({**detection, "state": "RESTORE_FAILED", "last_error": str(detail)[:320]})
        self.store.record_file_action(detection_id, "RESTORE", "FAILED", str(detail)[:320])
        self._emit(detection.get("operation_id", "file-security"), "FILE_RESTORE_FAILED", "FAILURE", str(detail)[:320], "ERROR", details={"detection_id": detection_id, "file_ref": detection.get("file_ref")})
        return result

    def quarantine_detection(self, detection_id: str, *, actor_uid: int = 0) -> dict[str, Any]:
        try:
            pending = self.prepare_quarantine(detection_id, actor_uid=actor_uid)
            _unlink_verified_source(
                Path(pending["source_path"]),
                pending.get("file_hash"),
                actor_uid or None,
            )
            return self.complete_quarantine(detection_id, actor_uid=actor_uid)
        except (OSError, ValueError, PermissionError) as error:
            try: self.fail_quarantine(detection_id, str(error), actor_uid=actor_uid)
            except (OSError, ValueError, TelemetryError): pass
            raise

    def restore_detection(self, detection_id: str, destination: str | None = None, *, actor_uid: int = 0) -> dict[str, Any]:
        detection = self.store.get_file_detection(detection_id)
        if not detection or detection.get("state") not in {"QUARANTINED", "QUARANTINE_FAILED"}:
            raise ValueError("Only a quarantined detection can be restored.")
        quarantine_id = detection.get("quarantine_id")
        source = self._quarantine_root(int(actor_uid or 0)) / (str(quarantine_id) + ".object")
        if not source.is_file():
            for candidate in Path("/var/lib/greyward/quarantine").glob(f"*/{quarantine_id}.object"):
                source = candidate
                break
        if not source.is_file():
            raise FileNotFoundError("The quarantined object is unavailable.")
        if destination:
            target = Path(destination).resolve()
            if actor_uid:
                if pwd is None:
                    raise PermissionError("User-home restore is unavailable on this platform.")
                try:
                    home = Path(pwd.getpwuid(actor_uid).pw_dir).resolve()
                    target.relative_to(home)
                except (KeyError, ValueError, OSError) as error:
                    raise PermissionError("Restore destinations must be inside the requesting user's home.") from error
        else:
            original = Path(str(detection.get("original_path") or ""))
            if actor_uid:
                if pwd is None:
                    raise PermissionError("User-home restore is unavailable on this platform.")
                try:
                    home = Path(pwd.getpwuid(actor_uid).pw_dir).resolve()
                except (KeyError, OSError) as error:
                    raise PermissionError("The requesting user's home is unavailable.") from error
                base = home / ".local" / "share" / "greyward" / "restore-staging"
            else:
                base = Path("/var/lib/greyward/restore-staging") / str(source.parent.name)
            target = base / (original.name or detection_id)
        if target.exists() or target.is_symlink():
            raise FileExistsError("The restore destination already exists.")
        try:
            size, digest = self._copy_verified(source, target, detection.get("file_hash"))
            if actor_uid:
                try:
                    os.chown(target, actor_uid, -1)
                except OSError as error:
                    target.unlink(missing_ok=True)
                    raise PermissionError("The restored file could not be assigned to the requesting user.") from error
            result = self.store.upsert_file_detection({**detection, "state": "RESTORED", "last_error": None, "file_size": size, "file_hash": digest, "restore_staging_path": str(target)})
            self.store.record_file_action(detection_id, "RESTORE", "SUCCESS", f"Restored to review location: {target}")
            self._emit(detection.get("operation_id", "file-security"), "FILE_RESTORED", "SUCCESS", "Quarantined file restored to a review location.", "WARNING", details={"detection_id": detection_id, "file_ref": detection.get("file_ref")})
            result["staging_path"] = str(target)
            return result
        except (OSError, ValueError) as error:
            self.store.upsert_file_detection({**detection, "state": "RESTORE_FAILED", "last_error": str(error)[:320]})
            self.store.record_file_action(detection_id, "RESTORE", "FAILED", str(error)[:320])
            raise

    def delete_detection(self, detection_id: str, *, actor_uid: int = 0) -> dict[str, Any]:
        detection = self.store.get_file_detection(detection_id)
        if not detection or not detection.get("quarantine_id"):
            raise ValueError("Move the detection to quarantine before deleting it.")
        quarantine_id = str(detection["quarantine_id"])
        object_path = self._find_quarantine_object(quarantine_id, actor_uid or None)
        if object_path is None:
            error = FileNotFoundError("The quarantined object is unavailable; it was not marked deleted.")
            self.store.upsert_file_detection({**detection, "state": "DELETE_FAILED", "last_error": str(error)})
            self.store.record_file_action(detection_id, "DELETE", "FAILED", str(error))
            self._emit(detection.get("operation_id", "file-security"), "FILE_DELETE_FAILED", "FAILURE", str(error), "ERROR", details={"detection_id": detection_id, "file_ref": detection.get("file_ref")})
            raise error
        candidates = [object_path, object_path.with_suffix(".json")]
        try:
            for candidate in candidates:
                candidate.unlink(missing_ok=True)
            result = self.store.upsert_file_detection({**detection, "state": "DELETED", "last_error": None})
            self.store.record_file_action(detection_id, "DELETE", "SUCCESS", "Quarantined object permanently deleted.")
            self._emit(detection.get("operation_id", "file-security"), "FILE_DELETED", "SUCCESS", "Quarantined object permanently deleted.", "WARNING", details={"detection_id": detection_id, "file_ref": detection.get("file_ref")})
            return result
        except OSError as error:
            self.store.upsert_file_detection({**detection, "state": "DELETE_FAILED", "last_error": str(error)[:320]})
            self.store.record_file_action(detection_id, "DELETE", "FAILED", str(error)[:320])
            self._emit(detection.get("operation_id", "file-security"), "FILE_DELETE_FAILED", "FAILURE", str(error)[:320], "ERROR", details={"detection_id": detection_id, "file_ref": detection.get("file_ref")})
            raise

    def _run(self, operation_id: str, mode: str, scope: Mapping[str, Any], cancel: threading.Event) -> None:
        info = clamav_status()
        if info.get("status") in {"UNAVAILABLE", "OUTDATED", "INITIALIZING", "UPDATING"}:
            self.store.update_file_scan(operation_id, state="FAILED", phase="FAILED", ended_at=stamp(), detail="Threat definitions are unavailable or outdated.", scanner_version=info.get("engine_version"), database_version=info.get("database_version"))
            self._emit(operation_id, "FILE_SCAN_FAILED", "FAILURE", "Definitions are unavailable or outdated.", "ERROR")
            self._finish(operation_id)
            return
        path = scope.get("path", "/")
        # Keep OK lines so the inspected-file counter reflects real scanner
        # progress. The frontend still receives only bounded counters and
        # detections, never the raw stream.
        command = ["clamscan", "--no-summary", "--verbose"]
        if mode in {"FOLDER", "SYSTEM"}:
            command.extend(["--recursive"])
        if mode == "SYSTEM":
            # Stay on the root filesystem. This prevents a deliberate system
            # scan from walking into network, removable, container, or other
            # separately mounted filesystems.
            command.extend(["--cross-fs=no", *_system_exclude_args()])
        command.extend(["--", str(path)])
        self.store.update_file_scan(operation_id, state="SCANNING", phase="SCANNING", detail="Scanning selected files.", scanner_version=info.get("engine_version"), database_version=info.get("database_version"))
        self._emit(operation_id, "FILE_SCAN_STARTED", "IN_PROGRESS", "File scan started.", "INFO")
        inspected = errors = skipped = detections = 0
        inspected_paths: set[str] = set()
        detection_paths: set[str] = set()
        error_paths: set[str] = set()
        process = None
        watchdog_stop = threading.Event()
        timeout_expired = threading.Event()
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace", bufsize=1, start_new_session=True, env={**os.environ, "LC_ALL": "C", "LANG": "C"})
            with self._lock:
                self._process[operation_id] = process

            def stop_stalled_scan():
                if watchdog_stop.wait(SCAN_TIMEOUT_SECONDS):
                    return
                if process is not None and process.poll() is None:
                    timeout_expired.set()
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except OSError:
                        try:
                            process.kill()
                        except OSError:
                            pass

            threading.Thread(target=stop_stalled_scan, name="greyward-file-scan-watchdog", daemon=True).start()
            assert process.stdout is not None
            for line in process.stdout:
                if cancel.is_set():
                    try: os.killpg(process.pid, signal.SIGTERM)
                    except OSError: pass
                    break
                if timeout_expired.is_set():
                    break
                found = _parse_found(line)
                if found:
                    original, detection_name = found
                    if original not in inspected_paths:
                        inspected_paths.add(original)
                        inspected += 1
                    if original in detection_paths:
                        continue
                    detection_paths.add(original)
                    size, file_hash = _hash_file(Path(original))
                    detection_id = "det-" + uuid.uuid4().hex
                    self.store.upsert_file_detection({
                        "detection_id": detection_id, "operation_id": operation_id, "original_path": original,
                        "file_ref": _file_ref(original), "detection_name": detection_name, "detected_at": stamp(),
                        "scanner_version": info.get("engine_version"), "database_version": info.get("database_version"),
                        "file_size": size, "file_hash": file_hash, "state": "DETECTED",
                    })
                    detections += 1
                    self._emit(operation_id, "FILE_DETECTION", "DETECTED", detection_name, "WARNING", details={"detection_id": detection_id, "file_ref": _file_ref(original)})
                elif line.strip().endswith(": OK"):
                    original = line.strip()[:-3].rstrip()
                    if original and original not in inspected_paths:
                        inspected_paths.add(original)
                        inspected += 1
                elif ERROR_RE.search(line):
                    errors += 1
                    original = line.strip().split(":", 1)[0]
                    if original and original not in error_paths:
                        error_paths.add(original)
                        skipped += 1
                if inspected and inspected % 32 == 0:
                    self.store.update_file_scan(operation_id, files_inspected=inspected, detection_count=detections, error_count=errors, skipped_count=skipped, detail="Scanning selected files.")
            return_code = process.wait(timeout=10)
            if cancel.is_set():
                state, phase, detail = "CANCELLED", "CANCELLED", "The scan was cancelled before completion."
            elif timeout_expired.is_set():
                state = "PARTIAL" if inspected or detections else "FAILED"
                phase, detail = state, "ClamAV did not complete the scan within the allowed time."
            elif return_code == 0:
                state, phase, detail = "COMPLETED", "COMPLETED", "No known threats were found." if not detections else "Scan completed with detections."
            elif return_code == 1:
                state = "PARTIAL" if errors or not detections else "COMPLETED"
                phase = state
                detail = "Scan completed with detections." if detections and not errors else "ClamAV reported a detection, but no actionable detection record could be created." if not errors else "Scan completed with errors."
            else:
                state, phase, detail = "PARTIAL" if inspected or detections else "FAILED", "FAILED", "ClamAV could not complete the scan."
            self.store.update_file_scan(operation_id, state=state, phase=phase, ended_at=stamp(), files_inspected=inspected, detection_count=detections, error_count=errors, skipped_count=skipped, detail=detail)
            event_type = {"COMPLETED": "FILE_SCAN_COMPLETED", "CANCELLED": "FILE_SCAN_CANCELLED", "PARTIAL": "FILE_SCAN_PARTIAL"}.get(state, "FILE_SCAN_FAILED")
            outcome = "SUCCESS" if state == "COMPLETED" else state
            self._emit(operation_id, event_type, outcome, detail, "INFO" if state == "COMPLETED" else "WARNING")
        except (OSError, subprocess.SubprocessError) as error:
            if process is not None and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass
            self.store.update_file_scan(operation_id, state="FAILED", phase="FAILED", ended_at=stamp(), files_inspected=inspected, detection_count=detections, error_count=errors + 1, skipped_count=skipped, detail="ClamAV is unavailable or stopped.")
            self._emit(operation_id, "FILE_SCAN_FAILED", "FAILURE", type(error).__name__, "ERROR")
        finally:
            watchdog_stop.set()
            self._finish(operation_id)

    def _finish(self, operation_id: str) -> None:
        with self._lock:
            self._cancel.pop(operation_id, None)
            self._process.pop(operation_id, None)
        # Operation and detection tables share the bounded telemetry store;
        # prune after each completed worker so a scan cannot grow those tables
        # without the normal retention/size policy being applied.
        try:
            self.store.prune()
        except (OSError, TelemetryError):
            pass

    def _emit(self, operation_id: str, event_type: str, outcome: str, detail: str, severity: str, *, details: Mapping[str, Any] | None = None) -> None:
        payload = {"message": detail, **(details or {})}
        # A detection can legitimately produce several durable events over
        # time (failed quarantine, successful retry, restore, delete). Do not
        # derive the event ID only from the detection ID or later outcomes
        # would collide with the first telemetry row.
        suffix = f"{event_type.lower()}-{uuid.uuid4().hex[:12]}"
        action = "SCAN" if event_type.startswith("FILE_SCAN") else "DETECT" if event_type == "FILE_DETECTION" else "REMEDIATE"
        record_event(event(event_id=f"{operation_id}-{suffix}", component="greyward-file-security", source="clamav", category="FILE_SECURITY", event_type=event_type, action=action, outcome=outcome, severity=severity, assessment="FAILED" if severity == "ERROR" else "NOTEWORTHY" if severity == "WARNING" else "NORMAL", correlation={"operation_id": operation_id}, details=payload, retention_class="semantic"), self.store)
        if self.on_change:
            self.on_change()
