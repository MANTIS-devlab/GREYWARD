"""User-scoped Restic backup operations for personal data only."""
from __future__ import annotations

import argparse
import datetime as dt
import errno
import getpass
import json
import os
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

try:
    import fcntl
except ImportError:  # pragma: no cover - the packaged target is Fedora/Linux.
    fcntl = None

from greyward_security_context.telemetry import event as telemetry_event
from greyward_security_context.telemetry import record_event

CONFIG_PATH = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "greyward" / "recovery-backup.json"
STATE_PATH = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "greyward-recovery" / "backup.json"
KEEP_DAILY = 7
KEEP_WEEKLY = 4
MAX_TEXT = 240
MAX_RESTORE_SELECTION = 100
MAX_RESTORE_CANDIDATES = 500
SETTING_DIRS = (".config/DankMaterialShell", ".config/labwc", ".config/greyward")
PERSONAL_DIRS = ("Desktop", "Documents", "Downloads", "Music", "Pictures", "Videos")
TERMINAL_OPERATION_STATES = {"COMPLETED", "FAILED", "CANCELLED"}
MOUNT_PROBE_TIMEOUT = 8


class BackupError(RuntimeError):
    pass


def problem_for(error: BaseException | str) -> str:
    """Return a stable, user-safe outcome instead of provider diagnostics."""
    text = str(error).lower()
    if any(token in text for token in ("wrong password", "incorrect password", "invalid password", "no key found")):
        return "CHECK_PASSPHRASE"
    if any(token in text for token in ("destination", "mounted", "writable")):
        return "CHECK_DESTINATION"
    if "already running" in text or "lock" in text:
        return "TRY_LATER"
    if "unavailable" in text or "failed to start" in text:
        return "SERVICE_UNAVAILABLE"
    return "TRY_AGAIN"


def operation_record(kind: str, state: str, problem: str | None = None, *, started_at: str | None = None) -> dict:
    value = {
        "kind": kind,
        "state": state,
        "started_at": started_at or stamp(),
        "completed_at": stamp() if state in TERMINAL_OPERATION_STATES else None,
        "problem": problem,
    }
    return value


def stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def atomic_write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
        temporary = Path(handle.name)
        json.dump(value, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def atomic_write_text(path: Path, value: str) -> None:
    """Restore an existing JSON file without losing its original contents."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def load_json(path: Path, default: object) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def load_config() -> dict:
    value = load_json(CONFIG_PATH, {})
    return value if isinstance(value, dict) else {}


def load_state() -> dict:
    value = load_json(STATE_PATH, {})
    return value if isinstance(value, dict) else {}


def _repository_id_from_config_output(output: str) -> str | None:
    try:
        value = json.loads(str(output or ""))
    except json.JSONDecodeError:
        value = None
    if isinstance(value, dict):
        identifier = value.get("id")
        if isinstance(identifier, str) and 1 <= len(identifier) <= 128:
            return f"restic:{identifier}"
    return None


def repository_identity(password: str) -> str:
    """Read the Restic repository identity without storing credentials."""
    result = restic(["cat", "config"], password)
    identifier = _repository_id_from_config_output(result.stdout)
    if not identifier:
        raise BackupError("The Restic repository identity could not be verified")
    return identifier


def ensure_repository_identity(password: str) -> str:
    config = load_config()
    identifier = repository_identity(password)
    if config.get("repository_id") != identifier:
        config["repository_id"] = identifier
        atomic_write(CONFIG_PATH, config)
    return identifier


def _repository_record(state: dict, identifier: str, *, create: bool = False) -> dict:
    records = state.get("repositories")
    if not isinstance(records, dict):
        if not create:
            return {}
        records = {}
        state["repositories"] = records
    record = records.get(identifier)
    if isinstance(record, dict):
        return record
    if not create:
        return {}
    record = {}
    records[identifier] = record
    return record


def _save_repository_record(state: dict, identifier: str, record: dict) -> None:
    records = state.setdefault("repositories", {})
    if not isinstance(records, dict):
        records = {}
        state["repositories"] = records
    records[identifier] = record
    state["active_repository_id"] = identifier
    atomic_write(STATE_PATH, state)


@contextmanager
def operation_lock():
    """Serialize helper invocations and release the lock if a process dies."""
    lock_path = STATE_PATH.with_name("backup-operation.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("w", encoding="utf-8")
    try:
        if fcntl is not None:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                if error.errno in {errno.EACCES, errno.EAGAIN}:
                    raise BackupError("Another backup operation is already running") from error
                raise BackupError("The backup operation could not be locked") from error
        yield
    finally:
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def destination(path_text: str) -> Path:
    path = Path(path_text).expanduser().resolve()
    if not path.is_dir() or path.is_symlink():
        raise BackupError("The backup destination is not an available directory")
    if not os.access(path, os.W_OK | os.X_OK):
        raise BackupError("The backup destination is not writable")
    home = Path.home().resolve()
    if path == home or home in path.parents:
        raise BackupError("Choose a mounted destination outside the home directory")
    if shutil.which("findmnt") is None:
        raise BackupError("findmnt is unavailable; the destination cannot be validated")
    try:
        probe = subprocess.run(["findmnt", "-T", str(path), "-no", "TARGET"], capture_output=True, text=True, check=False, timeout=MOUNT_PROBE_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as error:
        raise BackupError("The destination mount could not be validated") from error
    if probe.returncode != 0 or not probe.stdout.strip():
        raise BackupError("The destination is not mounted")
    return path


def repository(path: Path) -> Path:
    return path / ".greyward-restic"


def sources() -> list[Path]:
    home = Path.home()
    values = [home / relative for relative in PERSONAL_DIRS + SETTING_DIRS]
    return [path for path in values if path.exists()]


def password_file(password: str):
    runtime = Path(os.environ.get("XDG_RUNTIME_DIR", tempfile.gettempdir()))
    runtime.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=runtime, prefix="greyward-restic-", delete=False)
    path = Path(handle.name)
    try:
        os.chmod(path, 0o600)
        handle.write(password)
        handle.write("\n")
        handle.flush()
        handle.close()
        return path
    except Exception:
        handle.close()
        path.unlink(missing_ok=True)
        raise


def restic(argv: list[str], password: str, timeout: int = 7200) -> subprocess.CompletedProcess[str]:
    config = load_config()
    repo = config.get("repository")
    if not isinstance(repo, str) or not repo:
        raise BackupError("No backup destination has been configured")
    if shutil.which("restic") is None:
        raise BackupError("Restic is unavailable")
    temporary = password_file(password)
    try:
        env = {**os.environ, "RESTIC_REPOSITORY": repo, "RESTIC_PASSWORD_FILE": str(temporary), "LC_ALL": "C", "LANG": "C"}
        try:
            result = subprocess.run(["restic", *argv], capture_output=True, text=True, timeout=timeout, check=False, env=env)
        except (OSError, subprocess.SubprocessError) as error:
            raise BackupError(f"Restic failed to start: {type(error).__name__}") from error
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "Restic reported a failure").strip().replace(password, "[redacted]")[:MAX_TEXT]
            raise BackupError(detail)
        return result
    finally:
        temporary.unlink(missing_ok=True)


def configure(path_text: str, password: str, confirm: str) -> dict:
    if not password or password != confirm:
        raise BackupError("The repository passphrases do not match")
    requested = str(path_text or "").strip()
    if not requested:
        raise BackupError("Choose a mounted backup destination before configuring Restic")
    path = Path(requested).expanduser().resolve()
    path = destination(str(path))
    repo = repository(path)
    try:
        previous_config = CONFIG_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        previous_config = None
    except OSError as error:
        raise BackupError("The existing backup configuration could not be read safely") from error
    atomic_write(CONFIG_PATH, {"schema": "greyward.restic-backup/v1", "destination": str(path), "repository": str(repo), "configured_at": stamp()})
    try:
        try:
            restic(["init"], password)
        except BackupError as error:
            if "already exists" not in str(error).lower() and "already initialized" not in str(error).lower():
                raise
        restic(["snapshots", "--latest", "1"], password)
        identifier = repository_identity(password)
        atomic_write(CONFIG_PATH, {"schema": "greyward.restic-backup/v1", "destination": str(path), "repository": str(repo), "repository_id": identifier, "configured_at": stamp()})
    except BackupError:
        try:
            if previous_config is None:
                CONFIG_PATH.unlink(missing_ok=True)
            else:
                atomic_write_text(CONFIG_PATH, previous_config)
        except OSError as restore_error:
            raise BackupError("The previous backup configuration could not be restored") from restore_error
        raise
    state = load_state()
    _repository_record(state, identifier, create=True)
    _save_repository_record(state, identifier, _repository_record(state, identifier))
    return status()


def status() -> dict:
    config = load_config()
    state = load_state()
    configured = isinstance(config.get("repository"), str) and bool(config.get("repository"))
    identifier = config.get("repository_id") if isinstance(config.get("repository_id"), str) else None
    record = _repository_record(state, identifier) if identifier else {}
    path = config.get("destination")
    available = False
    if isinstance(path, str):
        try:
            destination(path)
            available = True
        except BackupError:
            available = False
    operation = record.get("operation") if configured and identifier else None
    return {
        "ok": True,
        "configured": configured,
        "destination": path,
        "destination_available": available,
        "repository_id": identifier,
        "last_backup_at": record.get("last_backup_at") if configured and identifier else None,
        "last_backup_status": record.get("last_backup_status") if configured and identifier else None,
        "last_backup_problem": record.get("last_backup_problem") if configured and identifier else None,
        "last_snapshot_id": record.get("last_snapshot_id") if configured and identifier else None,
        "last_retention_status": record.get("last_retention_status") if configured and identifier else None,
        "last_retention_problem": record.get("last_retention_problem") if configured and identifier else None,
        "last_check_at": record.get("last_check_at") if configured and identifier else None,
        "last_check_status": record.get("last_check_status") if configured and identifier else None,
        "last_check_problem": record.get("last_check_problem") if configured and identifier else None,
        "operation": operation if isinstance(operation, dict) else None,
        "retention": {"daily": KEEP_DAILY, "weekly": KEEP_WEEKLY},
        "sources": [str(path) for path in sources()],
        "restore_selection_limit": MAX_RESTORE_SELECTION,
    }


def backup(password: str) -> dict:
    if not sources():
        raise BackupError("No personal files or approved settings are available to back up")
    config = load_config()
    if not isinstance(config.get("repository"), str) or not config.get("repository"):
        raise BackupError("No backup destination has been configured")
    identifier = ensure_repository_identity(password)
    state = load_state()
    record = _repository_record(state, identifier, create=True)
    started_at = stamp()
    record["operation"] = operation_record("BACKUP", "RUNNING", started_at=started_at)
    _save_repository_record(state, identifier, record)
    try:
        result = restic(["backup", "--json", *[str(path) for path in sources()]], password)
    except BackupError as error:
        problem = problem_for(error)
        record.update({
            "last_backup_status": "FAILED",
            "last_backup_problem": problem,
            "operation": operation_record("BACKUP", "FAILED", problem, started_at=started_at),
        })
        _save_repository_record(state, identifier, record)
        record_event(telemetry_event(
            component="greyward-restic-backup",
            source="greyward-backup",
            category="RECOVERY",
            event_type="BACKUP_COMPLETED",
            action="BACKUP",
            outcome="FAILURE",
            severity="ERROR",
            assessment="FAILED",
            details={"retention": {"daily": KEEP_DAILY, "weekly": KEEP_WEEKLY}, "error": "Backup operation failed"},
            quality={"source_state": "AVAILABLE", "attribution": "EXACT", "confidence": "EXACT"},
            retention_class="semantic",
        ))
        raise
    snapshot_id = None
    for line in reversed(result.stdout.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("snapshot_id"):
            snapshot_id = value["snapshot_id"]
            break
    backup_at = stamp()
    record.update({"last_backup_at": backup_at, "last_backup_status": "SUCCESSFUL", "last_snapshot_id": snapshot_id})
    record.pop("last_backup_problem", None)

    # Retention is maintenance after the encrypted snapshot has been safely
    # written. A prune failure must not turn a completed backup into a failed
    # backup or make the user repeat the data transfer unnecessarily.
    retention_status = "SUCCESSFUL"
    retention_error = None
    try:
        restic(["forget", "--keep-daily", str(KEEP_DAILY), "--keep-weekly", str(KEEP_WEEKLY), "--prune", "--json"], password)
    except BackupError as error:
        retention_status = "FAILED"
        retention_error = problem_for(error)
    record["last_retention_status"] = retention_status
    if retention_error:
        record["last_retention_problem"] = retention_error
    else:
        record.pop("last_retention_problem", None)
    record["operation"] = operation_record("BACKUP", "COMPLETED", started_at=started_at)
    _save_repository_record(state, identifier, record)
    record_event(telemetry_event(
        event_id=f"backup-{snapshot_id or stamp()}",
        component="greyward-restic-backup",
        source="greyward-backup",
        category="RECOVERY",
        event_type="BACKUP_COMPLETED",
        action="BACKUP",
        outcome="SUCCESS",
        severity="NOTICE",
        assessment="NOTEWORTHY",
        details={"snapshot_id": snapshot_id, "retention": {"daily": KEEP_DAILY, "weekly": KEEP_WEEKLY}, "retention_status": retention_status},
        quality={"source_state": "AVAILABLE", "attribution": "EXACT", "confidence": "EXACT"},
        retention_class="semantic",
    ))
    result = {"ok": True, "status": "SUCCESSFUL", "snapshot_id": snapshot_id, "last_backup_at": backup_at, "retention_status": retention_status, "verified": record.get("last_check_status") == "VERIFIED", "last_check_at": record.get("last_check_at")}
    if retention_error:
        result["message"] = "Backup completed. Retention cleanup will retry after the next backup."
    return result


def verify(password: str) -> dict:
    identifier = ensure_repository_identity(password)
    state = load_state()
    record = _repository_record(state, identifier, create=True)
    started_at = stamp()
    record["operation"] = operation_record("VERIFY", "RUNNING", started_at=started_at)
    _save_repository_record(state, identifier, record)
    try:
        restic(["check"], password, timeout=14400)
    except BackupError as error:
        problem = problem_for(error)
        record.update({
            "last_check_at": stamp(),
            "last_check_status": "FAILED",
            "last_check_problem": problem,
            "operation": operation_record("VERIFY", "FAILED", problem, started_at=started_at),
        })
        _save_repository_record(state, identifier, record)
        record_event(telemetry_event(
            component="greyward-restic-backup",
            source="greyward-backup",
            category="RECOVERY",
            event_type="BACKUP_VERIFICATION",
            action="VERIFY",
            outcome="FAILURE",
            severity="ERROR",
            assessment="FAILED",
            details={"error": "Repository verification failed"},
            quality={"source_state": "AVAILABLE", "attribution": "EXACT", "confidence": "EXACT"},
            retention_class="semantic",
        ))
        raise
    record.update({"last_check_at": stamp(), "last_check_status": "VERIFIED", "operation": operation_record("VERIFY", "COMPLETED", started_at=started_at)})
    record.pop("last_check_problem", None)
    _save_repository_record(state, identifier, record)
    record_event(telemetry_event(
        event_id=f"backup-verify-{record['last_check_at']}",
        component="greyward-restic-backup",
        source="greyward-backup",
        category="RECOVERY",
        event_type="BACKUP_VERIFICATION",
        action="VERIFY",
        outcome="SUCCESS",
        severity="NOTICE",
        assessment="NOTEWORTHY",
        details={"verification": "restic check completed successfully"},
        quality={"source_state": "AVAILABLE", "attribution": "EXACT", "confidence": "EXACT"},
        retention_class="semantic",
    ))
    return {"ok": True, "status": "VERIFIED", "last_check_at": record["last_check_at"]}


def _restore_candidate_kind(value: dict) -> str:
    raw = str(value.get("type") or value.get("node_type") or value.get("kind") or "").strip().lower()
    if raw in {"dir", "directory"}:
        return "DIRECTORY"
    if raw in {"file", "regular"}:
        return "FILE"
    return "UNKNOWN"


def list_files(password: str) -> dict:
    result = restic(["ls", "latest", "--json"], password)
    candidates_by_path = {}
    home = str(Path.home().resolve()).replace("\\", "/")
    for line in result.stdout.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        path = value.get("path") if isinstance(value, dict) else None
        if isinstance(path, str):
            path = path.replace("\\", "/")
        if isinstance(path, str) and (path == home or path.startswith(home + "/")):
            candidates_by_path[path] = {"path": path, "kind": _restore_candidate_kind(value)}
    available = [candidates_by_path[path] for path in sorted(candidates_by_path)]
    shown = available[:MAX_RESTORE_CANDIDATES]
    return {
        "ok": True,
        "files": [candidate["path"] for candidate in shown],
        "candidates": shown,
        "available_count": len(available),
        "shown_count": len(shown),
        "selection_limit": MAX_RESTORE_SELECTION,
    }


def restore(password: str, selected: list[str]) -> dict:
    home = Path.home().resolve()
    safe = []
    for value in selected:
        path = Path(value).expanduser().resolve()
        if path != home and home not in path.parents:
            raise BackupError("Restore is limited to files in the user home")
        safe.append(str(path))
    if not safe:
        raise BackupError("Select at least one file to restore")
    if len(safe) > MAX_RESTORE_SELECTION:
        raise BackupError("Select fewer files for one restore operation")
    identifier = ensure_repository_identity(password)
    state = load_state()
    record = _repository_record(state, identifier, create=True)
    started_at = stamp()
    record["operation"] = operation_record("RESTORE", "PREPARING", started_at=started_at)
    _save_repository_record(state, identifier, record)
    staging = home / ".local/share/greyward/recovery-restore" / dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    try:
        staging.mkdir(parents=True, exist_ok=False)
    except OSError as error:
        record["operation"] = operation_record("RESTORE", "FAILED", "TRY_AGAIN", started_at=started_at)
        _save_repository_record(state, identifier, record)
        raise BackupError(f"The restore staging directory could not be created: {error}") from error
    try:
        record["operation"] = operation_record("RESTORE", "RUNNING", started_at=started_at)
        _save_repository_record(state, identifier, record)
        restic(["restore", "latest", "--target", str(staging), *sum((["--include", path] for path in safe), [])], password)
    except BackupError as error:
        shutil.rmtree(staging, ignore_errors=True)
        record["operation"] = operation_record("RESTORE", "FAILED", problem_for(error), started_at=started_at)
        _save_repository_record(state, identifier, record)
        raise
    record["operation"] = operation_record("RESTORE", "COMPLETED", started_at=started_at)
    _save_repository_record(state, identifier, record)
    return {"ok": True, "status": "STAGED", "staging_path": str(staging), "files": safe}


def command_line(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="GREYWARD personal Restic backup")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    config = sub.add_parser("configure"); config.add_argument("--destination", default=""); config.add_argument("--password-stdin", action="store_true")
    for name in ("backup", "verify", "list-files"):
        operation = sub.add_parser(name); operation.add_argument("--password-stdin", action="store_true")
    restore_parser = sub.add_parser("restore"); restore_parser.add_argument("paths", nargs="+"); restore_parser.add_argument("--password-stdin", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "status":
            value = status()
        elif args.command == "configure":
            if args.password_stdin:
                values = sys.stdin.read().splitlines()
                if len(values) < 2:
                    raise BackupError("Two passphrase lines are required")
                password, confirm = values[0], values[1]
            else:
                password = getpass.getpass("Restic passphrase: "); confirm = getpass.getpass("Confirm Restic passphrase: ")
            value = configure(args.destination, password, confirm)
        else:
            with operation_lock():
                password = sys.stdin.readline().rstrip("\n") if args.password_stdin else getpass.getpass("Restic passphrase: ")
                value = {"backup": backup, "verify": verify, "list-files": list_files}.get(args.command, lambda secret: restore(secret, args.paths))(password)
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))
        return 0
    except BackupError as error:
        print(json.dumps({"ok": False, "error": str(error)[:MAX_TEXT]}, separators=(",", ":")))
        return 1
