#!/usr/bin/python3
"""GREYWARD Update Center native DNF5 daemon facade."""
import json
import os
import threading
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

from greyward_security_context.update_center import BUS_NAME, OBJECT_PATH, SCHEMA, essential_driver_package_names, load_history, selected_system_provider, snapshot
from greyward_security_context.telemetry import event as telemetry_event
from greyward_security_context.telemetry import record_event

STATE_DIR = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "greyward-update-center"
TRANSACTION_PATH = STATE_DIR / "transaction.json"
DNF_BUS = "org.rpm.dnf.v0"
DNF_ROOT = "/org/rpm/dnf/v0"
UPDATE_HELPER = "/usr/libexec/greyward-update-action"
POLKIT_EXEC = "/usr/bin/pkexec"
DNF_DBUS_TIMEOUT = 60
DBUS_CANCEL_TIMEOUT = 10
LOGIN1_DBUS_TIMEOUT = 30
DNF_CLI = "/usr/bin/dnf5"


def stamp():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def new_operation_id():
    return f"dnf5-{int(time.time() * 1000)}"


def default_transaction():
    return {
        "id": None,
        "provider": "DNF5",
        "backend": "dnf5daemon",
        "operation": None,
        "phase": "IDLE",
        "progress": None,
        "current_item": None,
        "downloaded": 0,
        "download_total": 0,
        "processed": 0,
        "total": 0,
        "summary": None,
        "error": None,
        "details": None,
        "restart_required": "UNKNOWN",
        "started_at": None,
        "updated_at": stamp(),
        "finished_at": None,
        "provider_results": [],
        "recovery_point_id": None,
        "recovery_point_status": None,
        "boot_id": None,
        "cancellable": False,
    }


def current_boot_id():
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def dnf_offline_history_result(started_at):
    """Return the matching post-reboot DNF5 history record, if one exists."""
    try:
        threshold = int(datetime.fromisoformat(str(started_at or "").replace("Z", "+00:00")).timestamp()) - 300
    except (TypeError, ValueError, OverflowError):
        threshold = 0
    try:
        completed = subprocess.run(
            [DNF_CLI, "history", "list", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
        )
        records = json.loads(completed.stdout) if completed.returncode == 0 else []
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None
    if not isinstance(records, list):
        return None
    for record in sorted(
        (item for item in records if isinstance(item, dict)),
        key=lambda item: int(item.get("start_time") or 0),
        reverse=True,
    ):
        command = str(record.get("command_line") or "").lower()
        if int(record.get("start_time") or 0) < threshold:
            continue
        if "--offline" in command and (" upgrade" in f" {command}" or " do " in f" {command} "):
            return record
    return None


def reconcile_completed_restart(value):
    """Finish a changed-boot transaction only with the expected provider evidence."""
    dnf_expected = any(
        str(item.get("provider") or "").upper() == "DNF5"
        and str(item.get("state") or "").upper() == "SUCCESS"
        for item in value.get("provider_results") or []
        if isinstance(item, dict)
    )
    history = dnf_offline_history_result(value.get("started_at")) if dnf_expected else None
    if dnf_expected and (history is None or str(history.get("status") or "").lower() != "ok"):
        status = str((history or {}).get("status") or "missing").lower()
        value.update({"phase":"FAILED", "current_item":"The prepared system update could not be verified after restart.", "restart_required":"UNKNOWN", "error":"The offline system update did not produce a successful DNF5 history result.", "details":f"DNF5 post-restart history status: {status}.", "finished_at":stamp(), "updated_at":stamp(), "cancellable":False, "boot_id":current_boot_id()})
        return value
    history_id = history.get("id") if history else None
    detail = f"GREYWARD observed a new boot and matched successful DNF5 history transaction {history_id}." if history_id is not None else "GREYWARD observed a new boot after the prepared provider update."
    value.update({"phase":"COMPLETE", "current_item":"The prepared update restart completed.", "restart_required":"UNKNOWN", "error":None, "details":detail, "finished_at":stamp(), "updated_at":stamp(), "boot_id":current_boot_id()})
    return value


def reconcile_transaction(value):
    """Close transactions left behind by a reboot without deleting history."""
    phase = value.get("phase")
    if phase not in {
        "AUTHENTICATING",
        "RESOLVING",
        "DOWNLOADING",
        "INSTALLING",
        "VERIFYING",
        "CHECKPOINTING",
        "PREPARING_RESTART",
        "RESTARTING",
        "READY_TO_RESTART",
    }:
        return value
    stored_boot = value.get("boot_id")
    boot_changed = bool(stored_boot and current_boot_id() and stored_boot != current_boot_id())
    try:
        age = time.time() - datetime.fromisoformat(str(value.get("updated_at", "")).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError, OverflowError):
        age = 0
    if phase in {"RESTARTING", "READY_TO_RESTART"} and boot_changed:
        value = reconcile_completed_restart(value)
    elif phase == "RESTARTING" and age > 900:
        value.update({"phase":"FAILED", "current_item":"The requested restart did not occur.", "restart_required":"REQUIRED", "error":"The system did not restart to install the prepared update.", "details":"GREYWARD kept the prepared update available so the restart can be retried.", "finished_at":stamp(), "updated_at":stamp(), "cancellable":False, "boot_id":current_boot_id()})
    elif boot_changed:
        value.update({"phase":"FAILED", "current_item":"The interrupted update was reset after restart.", "restart_required":"UNKNOWN", "error":"The update was interrupted before it completed.", "details":"GREYWARD found no active update worker after the system restarted and closed the stale transaction.", "finished_at":stamp(), "updated_at":stamp(), "cancellable":False, "boot_id":current_boot_id()})
    return value


def load_transaction():
    try:
        value = json.loads(TRANSACTION_PATH.read_text(encoding="utf-8"))
        result = default_transaction()
        if isinstance(value, dict):
            result.update(value)
        before_reconcile = (result.get("phase"), result.get("finished_at"), result.get("current_item"))
        result = reconcile_transaction(result)
        after_reconcile = (result.get("phase"), result.get("finished_at"), result.get("current_item"))
        if after_reconcile != before_reconcile:
            try:
                TRANSACTION_PATH.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")), encoding="utf-8")
            except OSError:
                pass
        if result.get("error") and result.get("finished_at") and result.get("phase") not in {"FAILED", "CANCELLED", "COMPLETE", "READY_TO_RESTART"}:
            result["phase"] = "FAILED"
            result["progress"] = None
        return result
    except (OSError, json.JSONDecodeError):
        return default_transaction()


_transaction = load_transaction()
_transaction_lock = threading.Lock()
_native_bus = None
_native_session = None
_native_session_path = None
_native_root = None
_native_lock = threading.Lock()
_cli_process = None
_cli_process_lock = threading.Lock()
_last_snapshot = None
_snapshot_lock = threading.Lock()
_snapshot_refreshing = False
_snapshot_refreshed_at = 0.0
SNAPSHOT_TTL = 30.0
TERMINAL_PHASES = {"COMPLETE", "CANCELLED", "FAILED", "READY_TO_RESTART"}
ACTIVE_PHASES = {
    "RESOLVING", "AUTHENTICATING", "DOWNLOADING", "INSTALLING", "VERIFYING",
    "CHECKPOINTING", "PREPARING_RESTART", "UPDATING_APPLICATIONS",
    "UPDATING_FIRMWARE", "UPDATING_SECURITY", "RESTARTING",
}


def save_transaction():
    try:
        TRANSACTION_PATH.parent.mkdir(parents=True, exist_ok=True)
        TRANSACTION_PATH.write_text(json.dumps(_transaction, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    except OSError:
        pass


def transaction_copy():
    with _transaction_lock:
        return dict(_transaction)


def set_transaction(**values):
    with _transaction_lock:
        previous_phase = _transaction.get("phase")
        _transaction.update(values)
        phase = str(_transaction.get("phase") or "IDLE").upper()
        if phase in TERMINAL_PHASES:
            _transaction["progress"] = None
            _transaction["cancellable"] = False
            if "current_item" not in values:
                _transaction["current_item"] = None
        _transaction["boot_id"] = current_boot_id()
        _transaction["updated_at"] = stamp()
        value = dict(_transaction)
        save_transaction()
    if value.get("phase") != previous_phase and value.get("id"):
        phase = str(value.get("phase") or "UNKNOWN").upper()
        outcome = "FAILURE" if phase == "FAILED" else ("SUCCESS" if phase == "COMPLETE" else ("CANCELLED" if phase == "CANCELLED" else "IN_PROGRESS"))
        record_event(telemetry_event(
            event_id=f"update-{value['id']}-{phase}-{value['updated_at']}",
            occurred_at=value["updated_at"],
            component="greyward-update-center",
            source="greyward-update-center",
            category="UPDATE",
            event_type="UPDATE_PHASE",
            action="UPDATE",
            outcome=outcome,
            severity="ERROR" if outcome == "FAILURE" else "INFO",
            assessment="FAILED" if outcome == "FAILURE" else ("NOTEWORTHY" if outcome in {"SUCCESS", "CANCELLED"} else "NORMAL"),
            correlation={"operation_id": value.get("id"), "transaction_id": value.get("id"), "boot_id": value.get("boot_id")},
            details={"phase": phase, "recovery_point_id": value.get("recovery_point_id"), "recovery_point_status": value.get("recovery_point_status"), "restart_required": value.get("restart_required")},
            quality={"source_state": "AVAILABLE", "attribution": "EXACT", "confidence": "EXACT"},
            retention_class="semantic",
        ))
    return value


def dnf_options(**values):
    return dbus.Dictionary(values, signature="sv")


def native_session():
    global _native_bus, _native_root, _native_session, _native_session_path
    with _native_lock:
        if _native_session is not None:
            return _native_session
        _native_bus = dbus.SystemBus()
        _native_root = _native_bus.get_object(DNF_BUS, DNF_ROOT)
        _native_session_path = _native_root.open_session(dnf_options(), dbus_interface=f"{DNF_BUS}.SessionManager", timeout=DNF_DBUS_TIMEOUT)
        _native_session = _native_bus.get_object(DNF_BUS, _native_session_path)
        register_progress_signals(_native_session_path)
        return _native_session


def close_native_session():
    global _native_session, _native_session_path
    with _native_lock:
        if _native_root is not None and _native_session_path:
            try:
                _native_root.close_session(_native_session_path, dbus_interface=f"{DNF_BUS}.SessionManager", timeout=DNF_DBUS_TIMEOUT)
            except dbus.DBusException:
                pass
        _native_session = None
        _native_session_path = None


def native_daemon_error(error):
    """Return whether a DNF5 daemon failure means the provider is absent."""
    detail = str(error)
    return "ServiceUnknown" in detail or "not activatable" in detail


def run_privileged_update(operation_id, *, system=False, system_flatpak=False, firmware=False, driver_packages=None, timeout=3600):
    """Run the bounded privileged provider plan through one Polkit decision."""
    global _cli_process
    if not Path(UPDATE_HELPER).exists():
        raise RuntimeError("The GREYWARD update transaction helper is unavailable.")
    command = [POLKIT_EXEC, UPDATE_HELPER, "apply", "--operation-id", str(operation_id)]
    if system:
        command.append("--system")
    if system_flatpak:
        command.append("--system-flatpak")
    if firmware:
        command.append("--firmware")
    for package in driver_packages or []:
        command.extend(("--driver-package", package))
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env, bufsize=1)
    except OSError as error:
        raise RuntimeError(f"The privileged update action could not start: {type(error).__name__}.") from error
    with _cli_process_lock:
        _cli_process = process
    diagnostics = []
    completion = None
    try:
        deadline = time.monotonic() + timeout
        for line in process.stdout:
            if time.monotonic() > deadline:
                process.kill()
                raise RuntimeError("The privileged update action timed out.")
            value = None
            try:
                candidate = json.loads(line)
                if isinstance(candidate, dict) and candidate.get("greyward_update_event"):
                    value = candidate
            except json.JSONDecodeError:
                pass
            if value is None:
                diagnostics.append(line.strip())
                diagnostics = diagnostics[-40:]
                continue
            event = value.get("greyward_update_event")
            if event == "phase" and value.get("phase") in {"CHECKPOINTING", "PREPARING_RESTART", "UPDATING_APPLICATIONS", "UPDATING_FIRMWARE"}:
                set_transaction(phase=value["phase"], current_item=str(value.get("message") or "The update is in progress."), progress=None)
            elif event == "recovery":
                point = value.get("recovery_point") or {}
                if point.get("id") and point.get("status") == "valid":
                    set_transaction(recovery_point_id=point["id"], recovery_point_status="VALID")
            elif event == "provider":
                results = list(transaction_copy().get("provider_results") or [])
                results.append({key: value.get(key) for key in ("provider", "state", "reason")})
                set_transaction(provider_results=results)
            elif event == "complete":
                completion = value
        process.wait(timeout=max(1, int(deadline - time.monotonic())))
    finally:
        with _cli_process_lock:
            if _cli_process is process:
                _cli_process = None
    if process.returncode != 0:
        if process.returncode in (126, 127):
            raise RuntimeError("Authorization was cancelled or unavailable. No privileged update was started.")
        detail = " ".join(item for item in diagnostics[-8:] if item)[-1000:]
        raise RuntimeError(detail or f"The native update provider exited with status {process.returncode}.")
    if completion is None:
        raise RuntimeError("The update helper finished without a verified completion event.")
    return completion


def register_progress_signals(path):
    if _native_bus is None:
        return
    common = {"bus_name": DNF_BUS, "path": path}
    for name, callback in (
        ("download_add_new", on_download_add),
        ("download_progress", on_download_progress),
        ("transaction_before_begin", on_transaction_begin),
        ("transaction_elem_progress", on_element_progress),
        ("transaction_action_start", on_action_start),
        ("transaction_action_progress", on_action_progress),
        ("transaction_verify_start", on_verify_start),
        ("transaction_verify_progress", on_verify_progress),
        ("transaction_transaction_start", on_transaction_start),
        ("transaction_transaction_progress", on_transaction_progress),
        ("transaction_after_complete", on_transaction_complete),
    ):
        _native_bus.add_signal_receiver(callback, dbus_interface=f"{DNF_BUS}.Base" if name.startswith("download") else f"{DNF_BUS}.rpm.Rpm", signal_name=name, **common)


def same_session(path):
    return _native_session_path is None or str(path) == str(_native_session_path)


def signal_live(path):
    return same_session(path) and transaction_copy().get("phase") not in {"FAILED", "CANCELLED", "COMPLETE", "READY_TO_RESTART"}

def percent(done, total):
    if not total:
        return None
    return max(0, min(100, int((int(done) * 100) / int(total))))


def on_download_add(path, download_id, description, total):
    if signal_live(path):
        set_transaction(phase="DOWNLOADING", current_item=str(description), downloaded=0, download_total=int(total), progress=0, cancellable=_native_session is not None)


def on_download_progress(path, download_id, total, downloaded):
    if signal_live(path):
        set_transaction(phase="DOWNLOADING", downloaded=int(downloaded), download_total=int(total), progress=percent(downloaded, total))


def on_transaction_begin(path, total):
    if signal_live(path):
        set_transaction(phase="INSTALLING", processed=0, total=int(total), progress=0, cancellable=False)


def package_progress_label(nevra):
    """Keep an implementation-specific NEVRA in diagnostics, not the primary UI line."""
    value = str(nevra or "package")
    parts = value.rsplit("-", 3)
    name = parts[0] if len(parts) == 4 and parts[0] else value
    return f"Updating {name}.", f"Package: {value[:240]}"


def on_element_progress(path, nevra, processed, total):
    if signal_live(path):
        label, details = package_progress_label(nevra)
        set_transaction(phase="INSTALLING", current_item=label, details=details, processed=int(processed), total=int(total), progress=percent(processed, total), cancellable=False)


def on_action_start(path, nevra, action, total):
    if signal_live(path):
        label, details = package_progress_label(nevra)
        set_transaction(phase="INSTALLING", current_item=label, details=details, processed=0, total=int(total), progress=0, cancellable=False)


def on_action_progress(path, nevra, processed, total):
    if signal_live(path):
        label, details = package_progress_label(nevra)
        set_transaction(phase="INSTALLING", current_item=label, details=details, processed=int(processed), total=int(total), progress=percent(processed, total), cancellable=False)


def on_verify_start(path, total):
    if signal_live(path):
        set_transaction(phase="VERIFYING", processed=0, total=int(total), progress=0, cancellable=False)


def on_verify_progress(path, processed, total):
    if signal_live(path):
        set_transaction(phase="VERIFYING", processed=int(processed), total=int(total), progress=percent(processed, total), cancellable=False)


def on_transaction_start(path, total):
    if signal_live(path):
        set_transaction(phase="INSTALLING", processed=0, total=int(total), progress=0, cancellable=False)


def on_transaction_progress(path, processed, total):
    if signal_live(path):
        set_transaction(phase="INSTALLING", processed=int(processed), total=int(total), progress=percent(processed, total), cancellable=False)


def on_transaction_complete(path, success):
    if same_session(path) and not bool(success):
        set_transaction(phase="FAILED", error="DNF5 could not complete the transaction.", details="The native DNF5 transaction reported failure.", finished_at=stamp())


def item_dict(item):
    if isinstance(item, dict):
        value = {str(key): item_value for key, item_value in item.items()}
        value.setdefault("action", "upgrade")
        value.setdefault("reason", "available")
        return value
    metadata = dict(item[4]) if len(item) > 4 else {}
    return {"type": str(item[0]), "action": str(item[1]), "reason": str(item[2]), **{str(k): v for k, v in metadata.items()}}


def make_summary(items):
    summary = {"packages": len(items), "upgrades": 0, "installs": 0, "removals": 0, "downgrades": 0, "download_size": 0, "install_size": 0, "security_updates": 0, "restart_required": "REQUIRED", "preview": []}
    for index, item in enumerate(items):
        info = item_dict(item)
        action = info["action"].lower()
        if "remove" in action:
            summary["removals"] += 1
        elif "downgrade" in action:
            summary["downgrades"] += 1
        elif "install" in action:
            summary["installs"] += 1
        else:
            summary["upgrades"] += 1
        summary["download_size"] += int(info.get("download_size") or 0)
        summary["install_size"] += int(info.get("install_size") or 0)
        if index < 30:
            summary["preview"].append({key: info.get(key) for key in ("name", "full_nevra", "action", "reason", "download_size", "install_size", "repo_id")})
    try:
        records = snapshot().get("records", [])
        summary["security_updates"] = len({item.get("name") for item in records if item.get("security_relevance") == "SECURITY_FIX"})
    except Exception:
        pass
    return summary


def cli_upgrade_items():
    """Resolve updates through dnf5 itself when dnf5daemon is not installed."""
    if shutil.which("dnf5") is None:
        raise RuntimeError("dnf5 command is unavailable")
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    try:
        completed = subprocess.run(
            ["dnf5", "check-upgrade", "--json"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            env=env,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RuntimeError(f"dnf5 update check failed to start: {type(error).__name__}") from error
    if completed.returncode not in (0, 100):
        detail = (completed.stderr or completed.stdout or "dnf5 update check failed.").strip()[:240]
        raise RuntimeError(detail)
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("dnf5 returned malformed update data") from error
    upgrades = value.get("upgrades") if isinstance(value, dict) else None
    if not isinstance(upgrades, list):
        raise RuntimeError("dnf5 returned no upgrade list")
    items = [item for item in upgrades if isinstance(item, dict)]
    items.extend({
        "name": package,
        "action": "install",
        "reason": "essential-driver",
    } for package in essential_driver_package_names())
    return items


def resolve_cli_worker():
    try:
        set_transaction(backend="dnf5-cli", current_item="Reading DNF5 update metadata.", progress=None)
        items = cli_upgrade_items()
        summary = make_summary(items)
        if not items:
            set_transaction(phase="COMPLETE", summary=summary, current_item=None, progress=None, error=None, details=None, finished_at=stamp())
        else:
            set_transaction(phase="RESOLVED", summary=summary, current_item=None, progress=None, error=None, details="Resolved through the dnf5 command-line backend.")
        request_snapshot_refresh(force=True)
    except Exception as error:
        set_transaction(phase="FAILED", error="DNF5 could not resolve the update.", details=str(error), finished_at=stamp())


def resolve_native_goal(session):
    """Resolve a fresh DNF5 goal in the session that will execute it."""
    driver_packages = essential_driver_package_names()
    if driver_packages:
        session.install(driver_packages, dnf_options(interactive=dbus.Boolean(False)), dbus_interface=f"{DNF_BUS}.rpm.Rpm", timeout=DNF_DBUS_TIMEOUT)
    session.upgrade(["*"], dnf_options(interactive=dbus.Boolean(False)), dbus_interface=f"{DNF_BUS}.rpm.Rpm", timeout=DNF_DBUS_TIMEOUT)
    items, result = session.resolve(dnf_options(allow_erasing=dbus.Boolean(False), interactive=dbus.Boolean(False)), dbus_interface=f"{DNF_BUS}.Goal", timeout=DNF_DBUS_TIMEOUT)
    if int(result) == 0:
        return items, None
    problems = session.get_transaction_problems_string(dbus_interface=f"{DNF_BUS}.Goal", timeout=DNF_DBUS_TIMEOUT)
    detail = problems if isinstance(problems, str) else "; ".join(str(item) for item in problems)
    return None, detail


def resolve_worker():
    try:
        session = native_session()
        set_transaction(backend="dnf5daemon")
        items, detail = resolve_native_goal(session)
        if detail is not None:
            set_transaction(phase="FAILED", error="DNF5 could not resolve the update.", details=detail, finished_at=stamp())
            return
        summary = make_summary(items)
        if not items:
            set_transaction(phase="COMPLETE", summary=summary, current_item=None, progress=None, error=None, details=None, finished_at=stamp())
        else:
            set_transaction(phase="RESOLVED", summary=summary, current_item=None, progress=None, error=None, details=None)
    except dbus.DBusException as error:
        if native_daemon_error(error):
            resolve_cli_worker()
            return
        set_transaction(phase="FAILED", error="DNF5 could not resolve the update.", details=str(error), finished_at=stamp())
    except Exception as error:
        set_transaction(phase="FAILED", error="DNF5 could not resolve the update.", details=str(error), finished_at=stamp())


def run_optional_provider_updates(data, initial_results=None, privileged_plan=None):
    """Finish unprivileged providers and verify every completed provider."""
    records = data.get("records", [])
    results = list(initial_results or [])
    privileged_plan = privileged_plan or {}
    optional = [
        ("Flatpak (user)", ["flatpak", "update", "--user", "--noninteractive"], "application", "UPDATING_APPLICATIONS", "user"),
    ]
    for provider, argv, category, phase, scope in optional:
        actionable = provider_has_actionable_update(records, category, scope)
        if not actionable:
            results.append({"provider": provider, "state": "SKIPPED", "reason": "No actionable update was reported by the provider."})
            continue
        if shutil.which(argv[0]) is None:
            results.append({"provider": provider, "state": "UNAVAILABLE", "reason": f"{argv[0]} is unavailable."})
            continue
        set_transaction(phase=phase, current_item=f"Updating {provider} through its native provider.", progress=None, error=None)
        try:
            completed = subprocess.run(argv, capture_output=True, text=True, timeout=1800, check=False)
        except (OSError, subprocess.SubprocessError):
            results.append({"provider": provider, "state": "DEGRADED", "reason": f"{provider} did not complete."})
            continue
        output_lines = (completed.stdout + "\n" + completed.stderr).strip().splitlines()
        detail = output_lines[-1][:240] if output_lines else None
        if completed.returncode == 0:
            results.append({"provider": provider, "state": "SUCCESS", "reason": f"{provider} completed through its native provider.", "detail": detail})
        else:
            results.append({"provider": provider, "state": "DEGRADED", "reason": f"{provider} reported a failure.", "detail": detail})
    for provider, key, category, scope in (
        ("Flatpak (system)", "system_flatpak", "application", "system"),
        ("fwupd", "firmware", "firmware", None),
    ):
        if not provider_has_actionable_update(records, category, scope):
            results.append({"provider": provider, "state": "SKIPPED", "reason": "No actionable update was reported by the provider."})
        elif not privileged_plan.get(key) and not any(item.get("provider") == provider for item in results):
            results.append({"provider": provider, "state": "UNAVAILABLE", "reason": "The privileged provider plan was not available."})
    results.append({"provider": "freshclam/ClamAV", "state": "SKIPPED", "reason": "No actionable database update was reported."})
    try:
        readback = snapshot()
    except Exception:
        readback = None
    if readback is None:
        for result in results:
            if result.get("state") == "SUCCESS":
                result.update({"state": "DEGRADED", "reason": "Provider completion could not be verified."})
    else:
        cache_snapshot(readback)
        for result in results:
            if result.get("state") != "SUCCESS":
                continue
            if result["provider"] == "Flatpak (user)":
                still_available = provider_has_actionable_update(readback.get("records", []), "application", "user")
            elif result["provider"] == "Flatpak (system)":
                still_available = provider_has_actionable_update(readback.get("records", []), "application", "system")
            elif result["provider"] == "fwupd":
                still_available = provider_has_actionable_update(readback.get("records", []), "firmware", None)
            else:
                still_available = False
            if still_available:
                result.update({"state": "DEGRADED", "reason": "The provider still reports an available update after the operation."})
    current = transaction_copy()
    readback_requires_restart = bool(readback and any(item.get("reboot_required") == "REQUIRED" for item in readback.get("records", [])))
    restart_required = "REQUIRED" if current.get("restart_required") == "REQUIRED" or readback_requires_restart else current.get("restart_required", "UNKNOWN")
    final_phase = "READY_TO_RESTART" if restart_required == "REQUIRED" else "COMPLETE"
    value = set_transaction(provider_results=results, phase=final_phase, current_item=None, progress=None, restart_required=restart_required, finished_at=stamp())
    request_snapshot_refresh(force=True)
    return value


def provider_has_actionable_update(records, category, scope=None):
    return any(
        item.get("category") == category
        and item.get("update_available") is True
        and (scope is None or item.get("metadata", {}).get("scope") == scope)
        for item in records
    )


def cache_snapshot(value):
    global _last_snapshot, _snapshot_refreshed_at, _snapshot_refreshing
    with _snapshot_lock:
        _last_snapshot = value
        _snapshot_refreshed_at = time.monotonic()
        _snapshot_refreshing = False


def apply_all_worker():
    """Apply one reviewed provider plan with at most one Polkit prompt."""
    try:
        set_transaction(backend="native-provider-helper", phase="RESOLVING", current_item="Confirming the reviewed provider plan.", error=None, details=None, provider_results=[])
        data = snapshot()
        cache_snapshot(data)
        records = data.get("records", [])
        system_name, _collector = selected_system_provider()
        system = system_name == "DNF5" and provider_has_actionable_update(records, "system")
        if system_name == "rpm-ostree" and provider_has_actionable_update(records, "system"):
            set_transaction(phase="FAILED", error="The Atomic system update could not be applied.", details="The rpm-ostree mutation path is unavailable in this build.", finished_at=stamp())
            return
        plan = {
            "system": system,
            "system_flatpak": provider_has_actionable_update(records, "application", "system"),
            "firmware": provider_has_actionable_update(records, "firmware"),
        }
        results = []
        if any(plan.values()):
            set_transaction(phase="AUTHENTICATING", current_item="Enter your account password once to authorize the reviewed system changes.")
            completion = run_privileged_update(
                transaction_copy().get("id"),
                system=plan["system"],
                system_flatpak=plan["system_flatpak"],
                firmware=plan["firmware"],
                driver_packages=essential_driver_package_names() if plan["system"] else [],
            )
            results = list(completion.get("provider_results") or [])
            point = completion.get("recovery_point") or {}
            details = "The reviewed privileged providers completed through one authenticated transaction."
            if completion.get("optional_repo_skipped"):
                details += " The optional OpenH264 repository was unavailable; its codec packages were deferred."
            set_transaction(
                provider_results=results,
                recovery_point_id=point.get("id") or transaction_copy().get("recovery_point_id"),
                recovery_point_status="VALID" if point.get("status") == "valid" else transaction_copy().get("recovery_point_status"),
                restart_required="REQUIRED" if plan["system"] else transaction_copy().get("restart_required", "UNKNOWN"),
                details=details,
            )
        return run_optional_provider_updates(data, initial_results=results, privileged_plan=plan)
    except Exception as error:
        set_transaction(phase="FAILED", error="The update was not completed.", details=str(error), finished_at=stamp())


def apply_worker():
    """Compatibility entry point for the provider-agnostic apply workflow."""
    return apply_all_worker()


def restart_worker():
    try:
        set_transaction(phase="RESTARTING", current_item="Restarting through the desktop system service.", restart_required="REQUIRED")
        system_bus = dbus.SystemBus()
        login1 = system_bus.get_object("org.freedesktop.login1", "/org/freedesktop/login1")
        login1.Reboot(True, dbus_interface="org.freedesktop.login1.Manager", timeout=LOGIN1_DBUS_TIMEOUT)
    except Exception as error:
        set_transaction(phase="FAILED", error="The system could not be restarted.", details=str(error), finished_at=stamp())


def start_operation(operation):
    current = transaction_copy()
    if operation == "cancel" and current.get("phase") in ACTIVE_PHASES:
        if current.get("cancellable") is not True:
            return current
        try:
            if _native_session is not None:
                _native_session.cancel(dbus_interface=f"{DNF_BUS}.Goal", timeout=DBUS_CANCEL_TIMEOUT)
            else:
                return current
        except Exception:
            return current
        return set_transaction(phase="CANCELLED", error=None, details=None, finished_at=stamp(), cancellable=False)
    if current.get("phase") in ACTIVE_PHASES:
        return current
    if operation == "resolve":
        value = set_transaction(id=new_operation_id(), operation=operation, phase="RESOLVING", summary=None, progress=None, current_item="Resolving Fedora updates.", error=None, details=None, recovery_point_id=None, recovery_point_status=None, provider_results=[], downloaded=0, download_total=0, processed=0, total=0, restart_required="UNKNOWN", started_at=stamp(), finished_at=None, cancellable=False)
        threading.Thread(target=resolve_worker, daemon=True).start()
        return value
    if operation in ("apply", "apply_all"):
        value = set_transaction(id=new_operation_id(), operation=operation, phase="RESOLVING", progress=None, current_item="Confirming the reviewed provider plan.", error=None, details=None, recovery_point_id=None, recovery_point_status=None, provider_results=[], downloaded=0, download_total=0, processed=0, total=0, restart_required="UNKNOWN", started_at=stamp(), finished_at=None, cancellable=False)
        worker = apply_all_worker if operation == "apply_all" else apply_worker
        threading.Thread(target=worker, daemon=True).start()
        return value
    if operation == "reboot":
        value = set_transaction(operation="reboot", phase="RESTARTING", current_item="Restarting through the desktop system service.", started_at=stamp(), finished_at=None, cancellable=False)
        threading.Thread(target=restart_worker, daemon=True).start()
        return value
    return current


class UpdateCenter(dbus.service.Object):
    def __init__(self, bus):
        super().__init__(bus, OBJECT_PATH)

    @dbus.service.method(BUS_NAME, in_signature="", out_signature="s")
    def GetSnapshot(self):
        value = read_snapshot()
        value["transaction"] = transaction_copy()
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    @dbus.service.method(BUS_NAME, in_signature="", out_signature="s")
    def GetProviderStatus(self):
        return json.dumps(read_snapshot()["providers"], sort_keys=True, separators=(",", ":"))

    @dbus.service.method(BUS_NAME, in_signature="", out_signature="s")
    def GetHistory(self):
        return json.dumps(read_snapshot()["history"], sort_keys=True, separators=(",", ":"))

    @dbus.service.method(BUS_NAME, in_signature="", out_signature="s")
    def CheckForUpdates(self):
        request_snapshot_refresh(force=True)
        value = read_snapshot()
        value["transaction"] = transaction_copy()
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    @dbus.service.method(BUS_NAME, in_signature="", out_signature="s")
    def GetTransactionStatus(self):
        return json.dumps(transaction_copy(), sort_keys=True, separators=(",", ":"))

    @dbus.service.method(BUS_NAME, in_signature="", out_signature="s")
    def UpdateAll(self):
        # This is the provider-agnostic resolve/check operation.  Provider
        # mutations belong to ApplySystemUpdate and must never occur during a
        # read or resolve request.
        return json.dumps(start_operation("resolve"), sort_keys=True, separators=(",", ":"))

    @dbus.service.method(BUS_NAME, in_signature="", out_signature="s")
    def ResolveSystemUpdate(self):
        return json.dumps(start_operation("resolve"), sort_keys=True, separators=(",", ":"))

    @dbus.service.method(BUS_NAME, in_signature="", out_signature="s")
    def ApplySystemUpdate(self):
        return json.dumps(start_operation("apply_all"), sort_keys=True, separators=(",", ":"))

    @dbus.service.method(BUS_NAME, in_signature="", out_signature="s")
    def PrepareSystemUpdate(self):
        return json.dumps(start_operation("apply_all"), sort_keys=True, separators=(",", ":"))

    @dbus.service.method(BUS_NAME, in_signature="", out_signature="s")
    def CancelUpdate(self):
        return json.dumps(start_operation("cancel"), sort_keys=True, separators=(",", ":"))

    @dbus.service.method(BUS_NAME, in_signature="", out_signature="s")
    def RestartAndApply(self):
        return json.dumps(start_operation("reboot"), sort_keys=True, separators=(",", ":"))


def pending_snapshot():
    observed = stamp()
    system_name, _ = selected_system_provider()
    provider_names = (system_name, "Flatpak", "fwupd", "freshclam/ClamAV")
    return {
        "schema": SCHEMA,
        "generated_at": observed,
        "providers": {
            name: {
                "state": "CHECKING",
                "observed_at": observed,
                "last_successful_at": None,
                "reason": "Update source is being checked.",
            }
            for name in provider_names
        },
        "records": [],
        "history": load_history(),
    }


def refresh_snapshot_worker():
    global _last_snapshot, _snapshot_refreshing, _snapshot_refreshed_at
    if transaction_copy().get("phase") in ACTIVE_PHASES:
        with _snapshot_lock:
            _snapshot_refreshing = False
        return
    try:
        value = snapshot()
    except Exception as error:
        with _snapshot_lock:
            value = _last_snapshot or pending_snapshot()
            value = dict(value)
            value["snapshot_error"] = str(error)[:240]
            _last_snapshot = value
            _snapshot_refreshed_at = time.monotonic()
            _snapshot_refreshing = False
        return
    with _snapshot_lock:
        _last_snapshot = value
        _snapshot_refreshed_at = time.monotonic()
        _snapshot_refreshing = False


def request_snapshot_refresh(force=False):
    global _snapshot_refreshing
    with _snapshot_lock:
        stale = _last_snapshot is None or time.monotonic() - _snapshot_refreshed_at >= SNAPSHOT_TTL
        if _snapshot_refreshing or (not force and not stale):
            return
        _snapshot_refreshing = True
    threading.Thread(target=refresh_snapshot_worker, daemon=True).start()


def read_snapshot():
    """Return cached provider data immediately and refresh it outside the D-Bus loop."""
    if transaction_copy().get("phase") not in ACTIVE_PHASES:
        request_snapshot_refresh()
    with _snapshot_lock:
        value = dict(_last_snapshot) if _last_snapshot is not None else pending_snapshot()
        refreshing = _snapshot_refreshing
    value["snapshot_refreshing"] = refreshing
    return value

def main():
    global _native_bus
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus()
    _native_bus = bus
    name = dbus.service.BusName(BUS_NAME, bus=bus)
    UpdateCenter(bus)
    request_snapshot_refresh(force=True)
    GLib.MainLoop().run()


if __name__ == "__main__":
    main()
