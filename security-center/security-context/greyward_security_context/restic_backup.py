"""User-scoped Restic backup operations for personal data only."""
from __future__ import annotations

import argparse
import datetime as dt
import errno
import getpass
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

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
SNAPSHOT_TAG = "greyward-personal"
SNAPSHOT_ID = re.compile(r"[0-9a-f]{64}")
MAX_SNAPSHOT_VERSIONS = 20


class BackupError(RuntimeError):
    pass


def problem_for(error: BaseException | str) -> str:
    """Return a stable, user-safe outcome instead of provider diagnostics."""
    text = str(error).lower()
    if isinstance(error, BackupError) and getattr(error, "problem", None):
        return error.problem
    if any(token in text for token in ("wrong password", "incorrect password", "invalid password", "no key found")):
        return "CHECK_PASSPHRASE"
    if "outside the home" in text:
        return "DESTINATION_IN_HOME"
    if "not an available directory" in text:
        return "DESTINATION_INVALID"
    if "not writable" in text:
        return "DESTINATION_NOT_WRITABLE"
    if "not mounted" in text:
        return "DESTINATION_NOT_MOUNTED"
    if "mount could not be validated" in text:
        return "DESTINATION_MOUNT_VALIDATION"
    if "findmnt is unavailable" in text:
        return "DESTINATION_MOUNT_PROVIDER"
    if "mount identity is not recorded" in text:
        return "DESTINATION_IDENTITY_MISSING"
    if "mount identity" in text or "mount has changed" in text:
        return "DESTINATION_CHANGED"
    if "configured restic repository" in text:
        return "REPOSITORY_MISMATCH"
    if any(token in text for token in ("destination", "mounted", "writable")):
        return "CHECK_DESTINATION"
    if "already running" in text or "lock" in text:
        return "TRY_LATER"
    if "repository" in text or "restic" in text:
        return "REPOSITORY_INACCESSIBLE"
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


def repository_identity(password: str, *, config: dict | None = None) -> str:
    """Read the Restic repository identity without storing credentials."""
    result = restic(["cat", "config"], password, **({"config": config} if config is not None else {}))
    identifier = _repository_id_from_config_output(result.stdout)
    if not identifier:
        raise BackupError("The Restic repository identity could not be verified")
    return identifier


def ensure_repository_identity(password: str) -> str:
    config = load_config()
    identifier = repository_identity(password)
    if config.get("repository_id") and config["repository_id"] != identifier:
        raise BackupError("The configured Restic repository identity has changed; choose it again")
    if not config.get("repository_id"):
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
    handle = lock_path.open("a", encoding="utf-8")
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


def operation_active() -> bool:
    if fcntl is None:
        return True
    try:
        with STATE_PATH.with_name("backup-operation.lock").open("r", encoding="utf-8") as handle:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            return False
    except FileNotFoundError:
        return False
    except OSError:
        return True  # An unreadable lock is not proof that work has stopped.


def _mount_identity(path: Path) -> dict[str, str]:
    if shutil.which("findmnt") is None:
        raise BackupError("findmnt is unavailable; the destination cannot be validated")
    try:
        probe = subprocess.run(
            ["findmnt", "--json", "--list", "-T", str(path), "-o", "TARGET,SOURCE,FSTYPE,UUID"],
            capture_output=True,
            text=True,
            check=False,
            timeout=MOUNT_PROBE_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise BackupError("The destination mount could not be validated") from error
    if probe.returncode != 0:
        raise BackupError("The destination mount could not be validated")
    try:
        entries = json.loads(probe.stdout)["filesystems"]
        if len(entries) != 1:
            raise ValueError
        entry = entries[0]
        target, source, filesystem = (entry[key] for key in ("target", "source", "fstype"))
        uuid = entry.get("uuid")
        if not all(isinstance(value, str) and value for value in (target, source, filesystem)):
            raise ValueError
    except (ValueError, KeyError, IndexError, TypeError, AttributeError) as error:
        raise BackupError("The destination mount could not be validated") from error
    if target == "/":
        raise BackupError("The destination is not mounted")
    if not isinstance(uuid, str) or not uuid:
        raise BackupError("The destination mount could not be validated: no filesystem UUID")
    return {"target": target, "source": source, "filesystem": filesystem, "uuid": uuid}


def _validated_destination(path_text: str) -> tuple[Path, dict[str, str]]:
    requested = Path(path_text).expanduser()
    try:
        if requested.is_symlink():
            raise BackupError("The backup destination is not an available directory")
        path = requested.resolve(strict=True)
    except BackupError:
        raise
    except (OSError, RuntimeError) as error:
        raise BackupError("The backup destination is not an available directory") from error
    if not path.is_dir():
        raise BackupError("The backup destination is not an available directory")
    home = Path.home().resolve()
    if path == home or home in path.parents:
        raise BackupError("Choose a mounted destination outside the home directory")
    mount = _mount_identity(path)
    if not os.access(path, os.W_OK | os.X_OK):
        raise BackupError("The backup destination is not writable")
    return path, mount


def destination(path_text: str) -> Path:
    return _validated_destination(path_text)[0]


def _validated_configuration(config: dict) -> tuple[Path, dict[str, str]]:
    destination_text = config.get("destination")
    repo = config.get("repository")
    if not isinstance(destination_text, str) or not destination_text:
        raise BackupError("No backup destination has been configured")
    if not isinstance(repo, str) or not repo:
        raise BackupError("No backup destination has been configured")
    path, mount = _validated_destination(destination_text)
    try:
        configured_repo = Path(repo).expanduser().resolve()
        expected_repo = repository(path)
    except (OSError, RuntimeError) as error:
        raise BackupError("The configured Restic repository could not be resolved") from error
    if expected_repo.is_symlink() or configured_repo != expected_repo:
        raise BackupError("The configured Restic repository does not match the destination")
    recorded_mount = config.get("mount")
    if not isinstance(recorded_mount, dict):
        raise BackupError("The configured backup destination mount identity is not recorded; choose it again")
    # Linux device names (e.g. /dev/sdb1) can change when a drive is replugged.
    # A filesystem UUID and type still have to match at the configured mount.
    if any(recorded_mount.get(key) != mount[key] for key in ("target", "filesystem", "uuid")):
        raise BackupError("The configured backup destination mount identity has changed; choose it again")
    return path, mount


def repository(path: Path) -> Path:
    return path / ".greyward-restic"


def sources() -> list[Path]:
    home = Path.home()
    values = [home / relative for relative in PERSONAL_DIRS + SETTING_DIRS]
    return [path for path in values if path.exists()]


def restic(argv: list[str], password: str, timeout: int = 7200, *, config: dict | None = None) -> subprocess.CompletedProcess[str]:
    if config is None:
        config = load_config()
    _validated_configuration(config)
    repo = config["repository"]
    if shutil.which("restic") is None:
        raise BackupError("Restic is unavailable")
    env = {**os.environ, "RESTIC_REPOSITORY": repo, "LC_ALL": "C", "LANG": "C"}
    for key in ("RESTIC_PASSWORD", "RESTIC_PASSWORD_FILE", "RESTIC_PASSWORD_COMMAND", "RESTIC_REPOSITORY_FILE"):
        env.pop(key, None)
    # Use a pipe so an interrupted or killed helper cannot leave a credential
    # file behind. None of these fixed Restic commands uses stdin for data.
    try:
        result = subprocess.run(
            ["restic", "--password-file", "/dev/stdin", *argv],
            input=password + "\n", capture_output=True, text=True, timeout=timeout, check=False, env=env,
        )
    except subprocess.TimeoutExpired as error:
        raise BackupError("The Restic operation timed out") from error
    except (OSError, subprocess.SubprocessError) as error:
        raise BackupError(f"Restic failed to start: {type(error).__name__}") from error
    if result.returncode != 0 and not (argv[0] == "backup" and result.returncode == 3):
        detail = (result.stderr or result.stdout or "Restic reported a failure").strip()
        raise BackupError((detail.replace(password, "[redacted]") if password else detail)[:MAX_TEXT])
    return result


def configure(path_text: str, password: str, confirm: str) -> dict:
    if not password or password != confirm:
        raise BackupError("The repository passphrases do not match")
    requested = str(path_text or "").strip()
    if not requested:
        raise BackupError("Choose a mounted backup destination before configuring Restic")
    path, mount = _validated_destination(requested)
    repo = repository(path)
    candidate = {"schema": "greyward.restic-backup/v1", "destination": str(path), "repository": str(repo), "mount": mount, "configured_at": stamp()}
    if repo.is_symlink():
        raise BackupError("The configured Restic repository does not match the destination")
    if not (repo / "config").exists():
        restic(["init"], password, config=candidate)
    identifier = repository_identity(password, config=candidate)
    atomic_write(CONFIG_PATH, {**candidate, "repository_id": identifier})
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
    repository_available = False
    destination_problem = None
    if configured:
        try:
            destination_path, _ = _validated_configuration(config)
            available = True
            repository_config = repository(destination_path) / "config"
            repository_available = (not repository_config.is_symlink()
                                    and repository_config.is_file()
                                    and os.access(repository_config, os.R_OK))
        except BackupError as error:
            destination_problem = problem_for(error)
    operation = record.get("operation") if configured and identifier else None
    if isinstance(operation, dict) and operation.get("state") not in TERMINAL_OPERATION_STATES:
        if not operation_active():
            operation = {**operation, "state": "FAILED", "problem": "INTERRUPTED"}
    return {
        "ok": True,
        "configured": configured,
        "destination": path,
        "destination_available": available,
        "destination_problem": destination_problem,
        "repository_available": repository_available,
        "last_check_scope": "FULL_DATA" if record.get("last_check_at") else None,
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
    selected_sources = sources()
    if not selected_sources:
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
        result = restic(["backup", "--json", "--host", socket.gethostname(), "--tag", SNAPSHOT_TAG, *[str(path) for path in selected_sources]], password)
        snapshot_id = None
        for line in reversed(result.stdout.splitlines()):
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict) and value.get("message_type") == "summary" and value.get("snapshot_id"):
                snapshot_id = value["snapshot_id"]
                break
        if not snapshot_id:
            raise BackupError("Restic did not confirm a saved snapshot")
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
    if result.returncode == 3:
        record.update({
            "last_backup_status": "PARTIAL",
            "last_backup_problem": "SOURCE_UNREADABLE",
            "operation": operation_record("BACKUP", "FAILED", "SOURCE_UNREADABLE", started_at=started_at),
        })
        _save_repository_record(state, identifier, record)
        return {"ok": False, "status": "PARTIAL", "problem": "SOURCE_UNREADABLE", "snapshot_id": snapshot_id}
    backup_at = stamp()
    record.update({"last_backup_at": backup_at, "last_backup_status": "SUCCESSFUL", "last_snapshot_id": snapshot_id})
    record.pop("last_backup_problem", None)
    record["last_retention_status"] = "PENDING"
    _save_repository_record(state, identifier, record)

    # Retention is maintenance after the encrypted snapshot has been safely
    # written. A prune failure must not turn a completed backup into a failed
    # backup or make the user repeat the data transfer unnecessarily.
    retention_status = "SUCCESSFUL"
    retention_error = None
    try:
        restic(["forget", "--host", socket.gethostname(), "--tag", SNAPSHOT_TAG, "--keep-daily", str(KEEP_DAILY), "--keep-weekly", str(KEEP_WEEKLY), "--prune", "--json"], password)
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
        restic(["check", "--read-data"], password, timeout=14400)
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


def _home_path(value: str, home: PurePosixPath) -> bool:
    path = PurePosixPath(value)
    return path != home and ".." not in path.parts and home in path.parents


def list_files(password: str, snapshot: str | None = None, *, search: str = "", folder: str = "", offset: int = 0) -> dict:
    ensure_repository_identity(password)
    home = PurePosixPath(Path.home().resolve().as_posix())
    try:
        records = json.loads(restic(["snapshots", "--json"], password).stdout)
    except (ValueError, TypeError) as error:
        raise BackupError("Restic did not return the saved backup versions") from error
    if not isinstance(records, list):
        raise BackupError("Restic did not return the saved backup versions")
    versions = [
        {"id": item["id"], "time": item["time"]}
        for item in records
        if isinstance(item, dict) and isinstance(item.get("id"), str) and SNAPSHOT_ID.fullmatch(item["id"])
        and isinstance(item.get("time"), str) and isinstance(item.get("paths"), list)
        and any(isinstance(path, str) and _home_path(path, home) for path in item["paths"])
    ]
    versions.sort(key=lambda item: item["time"], reverse=True)
    versions = versions[:MAX_SNAPSHOT_VERSIONS]
    if snapshot is None and versions:
        snapshot = versions[0]["id"]
    if snapshot is not None and not any(item["id"] == snapshot for item in versions):
        raise BackupError("The selected backup version is no longer available")
    search = search.strip().casefold()
    if len(search) > 160 or not 0 <= offset <= 1_000_000_000:
        raise BackupError("Invalid backup browser query")
    if folder and (len(folder) > 4096 or not _home_path(folder, home) or ".." in PurePosixPath(folder).parts):
        raise BackupError("Choose a backed-up folder in the user home")
    directory = PurePosixPath(folder) if folder else None
    command = ["ls", snapshot, "--json"]
    if directory is not None:
        if search:
            command.append("--recursive")
        command.extend(["--", str(directory)])
    result = restic(command, password, timeout=120) if snapshot else None
    candidates_by_path = {}
    scope = {str(home / relative) for relative in PERSONAL_DIRS + SETTING_DIRS}
    scope_candidates = {}
    ordinary_count = 0
    for line in result.stdout.splitlines() if result else ():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        path = value.get("path") if isinstance(value, dict) else None
        if not isinstance(path, str) or not _home_path(path, home):
            continue
        if search and search not in path.casefold():
            continue
        if directory is not None and (path == str(directory) or not PurePosixPath(path).is_relative_to(directory)):
            continue
        kind = _restore_candidate_kind(value)
        if kind == "UNKNOWN":
            continue
        if directory is None and not search and path in scope:
            scope_candidates[path] = {"path": path, "kind": kind}
        else:
            # Scope rows occupy at most len(scope) slots at the start. Keep a
            # bounded overlap so later pages preserve the same traversal order.
            first = max(0, offset - len(scope))
            if first <= ordinary_count < offset + MAX_RESTORE_CANDIDATES:
                candidates_by_path[path] = {"path": path, "kind": kind}
            ordinary_count += 1
    # Keep every backed top-level folder selectable even when an earlier
    # directory alone contains more than the display limit.
    roots = [scope_candidates[path] for path in sorted(scope_candidates)]
    first = max(0, offset - len(scope))
    start = max(0, offset - len(roots)) - first
    shown = roots[offset:offset + MAX_RESTORE_CANDIDATES]
    shown.extend(list(candidates_by_path.values())[start:start + MAX_RESTORE_CANDIDATES - len(shown)])
    available_count = len(roots) + ordinary_count
    return {
        "ok": True,
        "files": [candidate["path"] for candidate in shown],
        "candidates": shown,
        "available_count": available_count,
        "shown_count": len(shown),
        "offset": offset,
        "next_offset": offset + len(shown) if shown and offset + len(shown) < available_count else None,
        "previous_offset": max(0, offset - MAX_RESTORE_CANDIDATES) if offset else None,
        "folder": str(directory) if directory is not None else "",
        "home": str(home),
        "selection_limit": MAX_RESTORE_SELECTION,
        "snapshot": snapshot,
        "versions": versions,
    }


def restore(password: str, snapshot: str, selected: list[str]) -> dict:
    if not selected:
        raise BackupError("Select at least one file to restore")
    if len(selected) > MAX_RESTORE_SELECTION:
        raise BackupError("Select fewer files for one restore operation")
    if not SNAPSHOT_ID.fullmatch(snapshot):
        raise BackupError("Choose an exact backup version to restore")
    home = PurePosixPath(Path.home().resolve().as_posix())
    safe = list(dict.fromkeys(selected))
    if any(not _home_path(path, home) or not PurePosixPath(path).is_absolute() for path in safe):
        raise BackupError("Restore is limited to files in the user home")
    identifier = ensure_repository_identity(password)
    state = load_state()
    record = _repository_record(state, identifier, create=True)
    started_at = stamp()
    record["operation"] = operation_record("RESTORE", "PREPARING", started_at=started_at)
    _save_repository_record(state, identifier, record)
    restore_root = Path(home) / ".local/share/greyward/recovery-restore"
    try:
        restore_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        staging = Path(tempfile.mkdtemp(dir=restore_root, prefix=dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-")))
    except OSError as error:
        record["operation"] = operation_record("RESTORE", "FAILED", "TRY_AGAIN", started_at=started_at)
        _save_repository_record(state, identifier, record)
        raise BackupError(f"The restore staging directory could not be created: {error}") from error
    try:
        record["operation"] = operation_record("RESTORE", "RUNNING", started_at=started_at)
        _save_repository_record(state, identifier, record)
        # Restic's include arguments are glob patterns, even for paths selected
        # in the UI. Escape filename metacharacters and pin the browsed version.
        patterns = [part for path in safe for part in ("--include", re.sub(r"([\\*?\[\]])", r"\\\1", path))]
        restic(["restore", snapshot, "--target", str(staging), "--verify", *patterns], password)
        if any(not (staging / path.lstrip("/")).exists() for path in safe):
            raise BackupError("The backup version does not contain every selected file")
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
    for name in ("backup", "verify", "list-files", "restore"):
        operation = sub.add_parser(name)
        operation.add_argument("--password-stdin", action="store_true")
        if name in {"list-files", "restore"}:
            operation.add_argument("--snapshot", required=name == "restore")
        if name == "list-files":
            operation.add_argument("--search", default="")
            operation.add_argument("--folder", default="")
            operation.add_argument("--offset", type=int, default=0)
        if name == "restore":
            operation.add_argument("paths", nargs="+")
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
            with operation_lock():
                value = configure(args.destination, password, confirm)
        else:
            with operation_lock():
                password = sys.stdin.readline().rstrip("\n") if args.password_stdin else getpass.getpass("Restic passphrase: ")
                if args.command == "list-files":
                    value = list_files(password, args.snapshot, search=args.search, folder=args.folder, offset=args.offset)
                elif args.command == "restore":
                    value = restore(password, args.snapshot, args.paths)
                else:
                    value = {"backup": backup, "verify": verify}[args.command](password)
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))
        return 0
    except BackupError as error:
        print(json.dumps({"ok": False, "error": str(error)[:MAX_TEXT], "problem": problem_for(error)}, separators=(",", ":")))
        return 1
