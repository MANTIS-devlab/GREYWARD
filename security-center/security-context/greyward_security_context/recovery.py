"""Small, defensive local Btrfs recovery-point manager.

This module is intentionally a one-shot command implementation.  It only
creates read-only snapshots and metadata; it does not attempt boot rollback
or restore the installed system.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from greyward_security_context.telemetry import event as telemetry_event
from greyward_security_context.telemetry import record_event

DEFAULT_STATE_DIR = Path("/var/lib/greyward/recovery")
DEFAULT_POINT_DIR = DEFAULT_STATE_DIR / "points"
KEEP_POINTS = 3
SYSTEM_SUBVOLUMES = (("/var/lib/portables", "var-lib-portables"),)
MAX_TEXT = 240


class RecoveryError(RuntimeError):
    pass


def stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def state_dir() -> Path:
    # This helper is root-owned.  Never let inherited environment state
    # redirect snapshot creation or cleanup outside the fixed product area.
    return DEFAULT_STATE_DIR


def point_dir() -> Path:
    return state_dir() / "points"


def run(argv: list[str], *, timeout: int = 120, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False, env={**os.environ, "LC_ALL": "C", "LANG": "C"})
    except (OSError, subprocess.SubprocessError) as error:
        raise RecoveryError(f"{argv[0]} is unavailable: {type(error).__name__}") from error
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "command failed").strip()[:MAX_TEXT]
        raise RecoveryError(detail)
    return result


def is_subvolume(path: Path) -> bool:
    result = run(["btrfs", "subvolume", "show", str(path)], check=False)
    return result.returncode == 0


def ensure_btrfs_root() -> None:
    if shutil.which("btrfs") is None:
        raise RecoveryError("btrfs-progs is unavailable")
    if not is_subvolume(Path("/")):
        raise RecoveryError("The installed root is not a Btrfs subvolume")


def atomic_write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if path.name == "metadata.json":
            os.chmod(path, 0o644)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def read_metadata(path: Path) -> dict | None:
    try:
        value = json.loads((path / "metadata.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def list_points() -> list[dict]:
    result = []
    root = point_dir()
    if not root.is_dir():
        return result
    for child in root.iterdir():
        if not child.is_dir() or child.is_symlink():
            continue
        metadata = read_metadata(child)
        if metadata and metadata.get("id") == child.name:
            result.append(metadata)
    result.sort(key=lambda item: str(item.get("created_at", "")), reverse=True)
    return result


def _safe_point_path(point: dict) -> Path:
    identifier = point.get("id")
    if not isinstance(identifier, str) or not identifier or Path(identifier).name != identifier:
        raise RecoveryError("Recovery metadata has an invalid point ID")
    candidate = (point_dir() / identifier).resolve()
    root = point_dir().resolve()
    if candidate.parent != root:
        raise RecoveryError("Recovery point is outside the managed directory")
    return candidate


def _delete_snapshot(path: Path) -> None:
    if not path.exists() or path.is_symlink():
        return
    if not is_subvolume(path):
        raise RecoveryError(f"Refusing to delete a non-subvolume: {path}")
    run(["btrfs", "subvolume", "delete", str(path)], timeout=120)


def create(reason: str, operation_id: str | None = None) -> dict:
    if reason not in {"manual", "pre-update"}:
        raise RecoveryError("Recovery point reason must be manual or pre-update")
    if operation_id and len(operation_id) > 160:
        raise RecoveryError("Update operation ID is too long")
    ensure_btrfs_root()
    identifier = f"{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
    destination = point_dir() / identifier
    point_dir().mkdir(parents=True, exist_ok=True)
    os.chmod(state_dir(), 0o755)
    os.chmod(point_dir(), 0o755)
    destination.mkdir(parents=True, exist_ok=False)
    os.chmod(destination, 0o755)
    snapshots: list[dict] = []
    metadata = {
        "schema": "greyward.recovery-point/v1",
        "id": identifier,
        "created_at": stamp(),
        "reason": reason,
        "operation_id": operation_id,
        "dnf_transaction_id": None,
        "status": "creating",
        "cleanup": "retained",
        "excluded": ["/home", "/boot", "/boot/efi"],
        "snapshots": snapshots,
    }
    try:
        root_destination = destination / "root"
        run(["btrfs", "subvolume", "snapshot", "-r", "/", str(root_destination)], timeout=600)
        snapshots.append({"source": "/", "path": "root", "read_only": True})
        for source_text, label in SYSTEM_SUBVOLUMES:
            source = Path(source_text)
            if not is_subvolume(source):
                continue
            target = destination / label
            run(["btrfs", "subvolume", "snapshot", "-r", str(source), str(target)], timeout=600)
            snapshots.append({"source": source_text, "path": label, "read_only": True})
        metadata["status"] = "valid"
        atomic_write(destination / "metadata.json", metadata)
        record_event(telemetry_event(
            event_id=f"recovery-{identifier}-valid",
            occurred_at=metadata["created_at"],
            component="greyward-recovery",
            source="greyward-recovery-point",
            category="RECOVERY",
            event_type="RECOVERY_POINT_CREATED",
            action="CREATE",
            outcome="SUCCESS",
            severity="NOTICE",
            assessment="NOTEWORTHY",
            correlation={"operation_id": operation_id} if operation_id else {},
            details={"recovery_point_id": identifier, "reason": reason, "included_subvolumes": [item["source"] for item in snapshots], "excluded": metadata["excluded"]},
            quality={"source_state": "AVAILABLE", "attribution": "EXACT", "confidence": "EXACT"},
            retention_class="semantic",
        ))
        cleanup()
        return metadata
    except Exception as error:
        metadata["status"] = "failed"
        metadata["cleanup"] = "pending"
        metadata["error"] = str(error)[:MAX_TEXT]
        try:
            atomic_write(destination / "metadata.json", metadata)
        except OSError:
            pass
        record_event(telemetry_event(
            event_id=f"recovery-{identifier}-failed",
            occurred_at=metadata["created_at"],
            component="greyward-recovery",
            source="greyward-recovery-point",
            category="RECOVERY",
            event_type="RECOVERY_POINT_CREATED",
            action="CREATE",
            outcome="FAILURE",
            severity="ERROR",
            assessment="FAILED",
            correlation={"operation_id": operation_id} if operation_id else {},
            details={"recovery_point_id": identifier, "reason": reason, "error": "Recovery point creation failed"},
            quality={"source_state": "AVAILABLE", "attribution": "EXACT", "confidence": "EXACT"},
            retention_class="semantic",
        ))
        raise


def cleanup() -> dict:
    points = list_points()
    valid = [item for item in points if item.get("status") == "valid"]
    failed = [item for item in points if item.get("status") != "valid"]
    removed = []
    for point in failed + valid[KEEP_POINTS:]:
        base = _safe_point_path(point)
        for snapshot in reversed(point.get("snapshots", [])):
            relative = snapshot.get("path") if isinstance(snapshot, dict) else None
            if not isinstance(relative, str) or Path(relative).name != relative:
                raise RecoveryError("Recovery metadata has an invalid snapshot path")
            _delete_snapshot(base / relative)
        metadata = base / "metadata.json"
        if metadata.exists():
            metadata.unlink()
        try:
            base.rmdir()
        except OSError as error:
            raise RecoveryError(f"Recovery point cleanup could not remove {base.name}: {error}") from error
        removed.append(point["id"])
    return {"ok": True, "kept": [item["id"] for item in valid[:KEEP_POINTS]], "removed": removed}


def associate(operation_id: str, dnf_transaction_id: str) -> dict:
    if not operation_id or len(operation_id) > 160 or not dnf_transaction_id or len(dnf_transaction_id) > 160:
        raise RecoveryError("Invalid transaction association")
    for point in list_points():
        if point.get("operation_id") != operation_id:
            continue
        point["dnf_transaction_id"] = dnf_transaction_id
        atomic_write(_safe_point_path(point) / "metadata.json", point)
        record_event(telemetry_event(
            event_id=f"recovery-{point['id']}-associated",
            component="greyward-recovery",
            source="greyward-recovery-point",
            category="RECOVERY",
            event_type="RECOVERY_POINT_ASSOCIATED",
            action="ASSOCIATE",
            outcome="SUCCESS",
            severity="INFO",
            assessment="NOTEWORTHY",
            correlation={"operation_id": operation_id, "transaction_id": dnf_transaction_id},
            details={"recovery_point_id": point["id"]},
            quality={"source_state": "AVAILABLE", "attribution": "EXACT", "confidence": "EXACT"},
            retention_class="semantic",
        ))
        return point
    raise RecoveryError("No recovery point matches that update operation")


def command_line(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="GREYWARD local Btrfs recovery points")
    sub = parser.add_subparsers(dest="command", required=True)
    create_parser = sub.add_parser("create")
    create_parser.add_argument("--reason", required=True, choices=("manual", "pre-update"))
    create_parser.add_argument("--operation-id")
    sub.add_parser("list")
    sub.add_parser("cleanup")
    associate_parser = sub.add_parser("associate")
    associate_parser.add_argument("--operation-id", required=True)
    associate_parser.add_argument("--dnf-transaction-id", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            value = create(args.reason, args.operation_id)
        elif args.command == "list":
            value = {"ok": True, "points": list_points()}
        elif args.command == "cleanup":
            value = cleanup()
        else:
            value = associate(args.operation_id, args.dnf_transaction_id)
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))
        return 0
    except RecoveryError as error:
        print(json.dumps({"ok": False, "error": str(error)[:MAX_TEXT]}, separators=(",", ":")))
        return 1
