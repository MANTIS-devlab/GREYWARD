"""Read-only provider aggregation for the GREYWARD Update Center.

This module deliberately owns no update transaction.  Every provider query is
read-only and provider metadata is preserved without inventing trust or risk.
"""
import datetime as dt
import json
import os
import shutil
import subprocess
from pathlib import Path

try:
    import dbus
except ImportError:
    dbus = None

from .clamav import status as clamav_status

BUS_NAME = "org.greyward.Update1"
OBJECT_PATH = "/org/greyward/Update1"
SCHEMA = "org.greyward.update/v1"
MAX_HISTORY = 200
COMMAND_TIMEOUT = 8
PCI_DEVICES_ROOT = Path("/sys/bus/pci/devices")
ESSENTIAL_PCI_CLASSES = {"01", "02", "03"}
DRIVER_QUERY_FORMAT = "%{name}|%{evr}|%{arch}|%{repoid}|%{full_nevra}\n"
DRIVER_PACKAGE_LIMIT = 32


def now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def stamp(value):
    return value.isoformat().replace("+00:00", "Z")


def provider_state(state, reason, observed, last_successful=None):
    return {
        "state": state,
        "observed_at": stamp(observed),
        "last_successful_at": stamp(last_successful) if last_successful else None,
        "reason": reason,
    }


def run_json(argv, accepted_returncodes=(0,)):
    if shutil.which(argv[0]) is None:
        return None, "provider command is unavailable"
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT,
            check=False,
            env=env,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return None, type(error).__name__
    if result.returncode not in accepted_returncodes:
        return None, (result.stderr.strip() or result.stdout.strip() or f"provider exited with status {result.returncode}")[:240]
    if not result.stdout.strip():
        return None, (result.stderr.strip() or "provider returned no data")[:240]
    try:
        return json.loads(result.stdout), None
    except json.JSONDecodeError:
        return None, "provider returned malformed JSON"


def record(record_id, category, name, provider, source=None, current=None,
           available=None, update_available=None, reboot="UNKNOWN",
           rollback="UNKNOWN", signature="UNKNOWN", security="UNKNOWN",
           provider_health=None, metadata=None):
    observed = now()
    metadata = metadata or {}
    return {
        "id": record_id,
        "identity": metadata.get("identity") or name,
        "category": category,
        "name": name,
        "provider": provider,
        "source": source,
        "current_version": current,
        "available_version": available,
        "update_available": update_available,
        "reboot_required": reboot,
        "rollback_available": rollback,
        "signature_state": signature,
        "security_relevance": security,
        "observed_at": stamp(observed),
        "provider_health": provider_health,
        "metadata": metadata or {},
    }


def dnf5_daemon_upgrades():
    if dbus is None:
        raise RuntimeError("python-dbus is unavailable")
    bus = dbus.SystemBus()
    root = bus.get_object("org.rpm.dnf.v0", "/org/rpm/dnf/v0")
    session_path = root.open_session({}, dbus_interface="org.rpm.dnf.v0.SessionManager", timeout=COMMAND_TIMEOUT)
    try:
        session = bus.get_object("org.rpm.dnf.v0", session_path)
        attrs = dbus.Array(
            [dbus.String(name) for name in ("name", "evr", "arch", "repo_id", "download_size", "is_installed", "full_nevra")],
            signature="s",
        )
        options = dbus.Dictionary({"scope": dbus.String("upgrades"), "package_attrs": attrs}, signature="sv")
        packages = session.list(options, dbus_interface="org.rpm.dnf.v0.rpm.Rpm", timeout=COMMAND_TIMEOUT)
        return [{str(key): value for key, value in item.items()} for item in packages]
    finally:
        try:
            root.close_session(session_path, dbus_interface="org.rpm.dnf.v0.SessionManager", timeout=COMMAND_TIMEOUT)
        except dbus.DBusException:
            pass


def installed_rpm_versions():
    """Read installed package versions in one bounded rpm query."""
    text, error = run_text([
        "rpm", "-qa", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n",
    ])
    if error:
        return {}
    versions = {}
    for line in text.splitlines():
        name, separator, version_arch = line.partition("\t")
        if not separator or not name or "." not in version_arch:
            continue
        version, arch = version_arch.rsplit(".", 1)
        versions[(name, arch)] = version
    return versions


def _read_sysfs(path):
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def essential_pci_devices(root=PCI_DEVICES_ROOT):
    """Return essential PCI devices whose kernel driver is not bound.

    PCI class codes are stable kernel ABI data: 01 is mass storage, 02 is
    network, and 03 is display.  A bound driver is deliberately treated as
    handled without trying to judge whether another driver would be better.
    """
    try:
        devices = sorted(path for path in root.iterdir() if path.is_dir())
    except OSError:
        return []
    missing = []
    for device in devices:
        class_code = _read_sysfs(device / "class")
        if not class_code or len(class_code) < 4 or class_code[2:4].lower() not in ESSENTIAL_PCI_CLASSES:
            continue
        if (device / "driver").is_symlink():
            continue
        modalias = _read_sysfs(device / "modalias")
        missing.append({
            "sysfs_name": device.name,
            "class_code": class_code,
            "modalias": modalias,
            "vendor": _read_sysfs(device / "vendor"),
            "device": _read_sysfs(device / "device"),
            "label": _read_sysfs(device / "label"),
        })
    return missing


def driver_device_name(device):
    label = device.get("label")
    if label:
        return label
    vendor = device.get("vendor") or "unknown-vendor"
    product = device.get("device") or "unknown-device"
    return f"PCI device {vendor}:{product}"


def dnf5_driver_candidates(modalias):
    """Find available RPMs advertising a kernel modalias capability."""
    if not modalias:
        return [], None
    if shutil.which("dnf5") is None:
        return [], "DNF5 modalias lookup is unavailable"
    text, error = run_text([
        "dnf5", "repoquery", "--available",
        "--whatprovides", f"modalias({modalias})",
        "--latest-limit=1", "--qf", DRIVER_QUERY_FORMAT,
    ])
    if error:
        return [], error
    candidates = []
    for line in text.splitlines():
        fields = line.split("|", 4)
        if len(fields) != 5 or not fields[0].strip() or not fields[2].strip():
            continue
        name, evr, arch, repo_id, full_nevra = (field.strip() for field in fields)
        # Debug module packages are not a usable runtime driver payload.
        if any(token in name.lower() for token in ("debug", "debuginfo", "debugsource")):
            continue
        candidates.append({
            "name": name,
            "evr": evr or None,
            "arch": arch,
            "repo_id": repo_id or None,
            "full_nevra": full_nevra or None,
        })
    return candidates, None


def essential_driver_records(installed=None):
    """Normalize missing essential PCI driver support into DNF5 records."""
    installed_names = {name for name, _arch in (installed or {}).keys()}
    records = []
    lookup_errors = []
    for device in essential_pci_devices():
        modalias = device.get("modalias")
        candidates, error = dnf5_driver_candidates(modalias)
        if error:
            lookup_errors.append(error)
        candidate = next((item for item in candidates
                          if item.get("name") not in installed_names
                          and not any(token in item.get("name", "").lower()
                                      for token in ("debug", "debuginfo", "debugsource"))), None)
        package = candidate["name"] if candidate else None
        resolution = "AVAILABLE" if package else "UNRESOLVED"
        reason = "A configured repository provides a matching driver package." if package else (
            "No suitable driver package was found in configured repositories."
            if not candidates else
            "A matching package is already installed; the unbound device may need review."
        )
        metadata = {
            "driver_support": True,
            "device": driver_device_name(device),
            "sysfs_name": device.get("sysfs_name"),
            "class_code": device.get("class_code"),
            "modalias": modalias,
            "resolution": resolution,
            "reason": reason,
            "package_name": package,
            "package_version": candidate.get("evr") if candidate else None,
            "package_arch": candidate.get("arch") if candidate else None,
            "package_repo": candidate.get("repo_id") if candidate else None,
        }
        records.append(record(
            f"system.driver.{device.get('sysfs_name') or 'unknown'}",
            "system",
            driver_device_name(device),
            "DNF5",
            candidate.get("repo_id") if candidate else None,
            None,
            candidate.get("evr") if candidate else None,
            package is not None,
            "REQUIRED" if package else "UNKNOWN",
            "UNKNOWN",
            "UNKNOWN",
            "UNKNOWN",
            None,
            metadata,
        ))
    return records, lookup_errors


def essential_driver_package_names():
    records, _errors = essential_driver_records(installed_rpm_versions())
    return [
        item["metadata"]["package_name"]
        for item in records
        if item.get("update_available") is True and item.get("metadata", {}).get("package_name")
    ][:DRIVER_PACKAGE_LIMIT]

def dnf5():
    """Collect normal Fedora system updates through DNF5, read-only."""
    observed = now()
    if shutil.which("dnf5") is None:
        return provider_state("UNAVAILABLE", "dnf5 command is unavailable", observed), []
    try:
        upgrades = dnf5_daemon_upgrades()
    except Exception:
        payload, error = run_json(["dnf5", "check-upgrade", "--json"], accepted_returncodes=(0, 100))
        if error:
            return provider_state("DEGRADED", error, observed), []
        upgrades = payload.get("upgrades") if isinstance(payload, dict) else None
    if not isinstance(upgrades, list):
        return provider_state("DEGRADED", "DNF5 returned no upgrade list", observed), []
    advisories_payload, advisories_error = run_json(["dnf5", "updateinfo", "list", "--json"])
    advisories = advisories_payload if isinstance(advisories_payload, list) else []
    history_payload, history_error = run_json(["dnf5", "history", "list", "--json"])
    transactions = history_payload if isinstance(history_payload, list) else []
    installed = installed_rpm_versions()
    driver_records, driver_lookup_errors = essential_driver_records(installed)
    health = provider_state("AVAILABLE", "DNF5 update metadata collected", observed, observed)
    records = []
    for item in upgrades[:512]:
        name = item.get("name") or "System package"
        arch = item.get("arch") or "unknown"
        available = item.get("evr") or item.get("available_version")
        package_advisories = [
            advisory for advisory in advisories
            if advisory.get("nevra", "").endswith(f"-{available}.{arch}")
        ]
        security = "SECURITY_FIX" if any(a.get("type") == "security" for a in package_advisories) else "UNKNOWN"
        current = installed.get((name, arch))
        records.append(record(
            f"system.dnf5.{name}.{arch}",
            "system",
            name,
            "DNF5",
            item.get("repository") or item.get("repo_id"),
            current,
            available,
            True,
            "UNKNOWN",
            "UNKNOWN",
            "UNKNOWN",
            security,
            health,
            {
                "arch": arch,
                "download_size": int(item.get("download_size") or 0),
                "install_size": int(item.get("install_size") or 0),
                "advisories": package_advisories,
                "history_count": len(transactions),
                "last_transaction": transactions[0] if transactions else None,
            },
        ))
    if not records:
        current = installed.get(("fedora-release", "x86_64"))
        records.append(record(
            "system.dnf5", "system", "Fedora system", "DNF5", None,
            current,
            None, False, "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN", health,
            {"history_count": len(transactions)},
        ))
    records.extend(driver_records)
    if driver_lookup_errors and health["state"] == "AVAILABLE":
        health = provider_state("DEGRADED", "; ".join(sorted(set(driver_lookup_errors)))[:240], observed, observed)
    for item in records + driver_records:
        item["provider_health"] = health
    return health, records

def rpm_ostree():
    observed = now()
    payload, error = run_json(["rpm-ostree", "status", "--json"])
    if error:
        return provider_state("UNAVAILABLE", error, observed), []
    deployments = payload.get("deployments") or []
    booted = next((item for item in deployments if item.get("booted")), None)
    pending = next((item for item in deployments if not item.get("booted") and item.get("staged")), None)
    if pending is None and len(deployments) > 1:
        pending = next((item for item in deployments if not item.get("booted")), None)
    current = (booted or {}).get("version") or (booted or {}).get("checksum")
    available = (pending or {}).get("version") or (pending or {}).get("checksum")
    source = (booted or {}).get("origin") or (pending or {}).get("origin")
    health = provider_state("AVAILABLE", "rpm-ostree status collected", observed, observed)
    item = record(
        "system.rpm-ostree",
        "system",
        "GREYWARD OS",
        "rpm-ostree",
        source,
        current,
        available,
        pending is not None,
        "REQUIRED" if pending is not None else "NOT_REQUIRED",
        "AVAILABLE" if len(deployments) > 1 else "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        health,
        {
            "deployment_count": len(deployments),
            "pending_deployment": pending is not None,
            "deployments": [
                {"checksum": item.get("checksum"), "version": item.get("version"), "booted": bool(item.get("booted"))}
                for item in deployments[:8]
            ],
        },
    )
    return health, [item]


def is_ostree_host():
    """Return whether the running system is an ostree deployment.

    Fedora can have DNF5 and rpm-ostree tooling available in the same package
    universe, but only the booted deployment owns the system-update boundary.
    The boot marker is the authoritative host distinction; a missing
    rpm-ostree command on a normal Fedora installation is therefore not a
    provider failure.
    """
    return Path("/run/ostree-booted").exists()


def selected_system_provider():
    """Select the one authoritative system update provider for this host."""
    if is_ostree_host():
        return "rpm-ostree", rpm_ostree
    return "DNF5", dnf5


def flatpak():
    """Collect user and system Flatpak application state through fixed native queries."""
    observed = now()
    if shutil.which("flatpak") is None:
        return provider_state("UNAVAILABLE", "flatpak command is unavailable", observed), []
    apps = []
    updates = {}
    errors = []
    columns = "application,name,version,origin,arch,branch,runtime"
    for scope in ("user", "system"):
        scope_flag = f"--{scope}"
        listing_text, listing_error = run_text(["flatpak", "list", "--app", scope_flag, f"--columns={columns}"])
        if listing_error:
            errors.append(f"{scope}: {listing_error}")
        else:
            apps.extend(parse_flatpak_lines(listing_text, scope))
        update_text, update_error = run_text(["flatpak", "remote-ls", "--updates", "--app", scope_flag, f"--columns={columns}"], accepted_returncodes=(0,))
        if update_error:
            errors.append(f"{scope} updates: {update_error}")
        else:
            for item in parse_flatpak_lines(update_text, scope):
                updates[(scope, item["app_id"])] = item
    if not apps and errors:
        return provider_state("DEGRADED", "; ".join(errors)[:240], observed), []
    records = []
    health = provider_state("DEGRADED" if errors else "AVAILABLE", "; ".join(errors)[:240] if errors else "Flatpak application state collected", observed, observed)
    for item in apps[:512]:
        update = updates.get((item["scope"], item["app_id"]))
        records.append(record(
            f"application.flatpak.{item['scope']}.{item['app_id']}",
            "application",
            item["name"],
            "Flatpak",
            item.get("origin"),
            item.get("version"),
            update.get("version") if update else None,
            update is not None,
            "UNKNOWN",
            "UNKNOWN",
            "UNKNOWN",
            "UNKNOWN",
            health,
            {
                "app_id": item["app_id"],
                "scope": item["scope"],
                "arch": item.get("arch"),
                "branch": item.get("branch"),
                "runtime": item.get("runtime"),
                "remote": item.get("origin"),
                "publisher_verification": "UNKNOWN",
            },
        ))
    return health, records

def run_text(argv, accepted_returncodes=(0, 1)):
    if shutil.which(argv[0]) is None:
        return "", "provider command is unavailable"
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=COMMAND_TIMEOUT, check=False, env=env)
    except (OSError, subprocess.SubprocessError) as error:
        return "", type(error).__name__
    if result.returncode not in accepted_returncodes:
        return "", (result.stderr.strip() or "provider failed")[:240]
    return result.stdout, None


def parse_flatpak_lines(text, scope):
    values = []
    for line in text.splitlines()[:512]:
        fields = line.split("\t")
        if len(fields) < 3 or not fields[0].strip():
            continue
        values.append({
            "app_id": fields[0].strip(),
            "name": fields[1].strip() or fields[0].strip(),
            "version": fields[2].strip() or None,
            "origin": fields[3].strip() if len(fields) > 3 and fields[3].strip() else None,
            "arch": fields[4].strip() if len(fields) > 4 and fields[4].strip() else None,
            "branch": fields[5].strip() if len(fields) > 5 and fields[5].strip() else None,
            "runtime": fields[6].strip() if len(fields) > 6 and fields[6].strip() else None,
            "scope": scope,
        })
    return values


def fwupd():
    observed = now()
    payload, error = run_json(["fwupdmgr", "get-updates", "--json"])
    if error:
        if shutil.which("fwupdmgr") is None:
            return provider_state("UNAVAILABLE", error, observed), []
        return provider_state("DEGRADED", error, observed), []
    devices = payload.get("Devices") or payload.get("devices") or []
    records = []
    for device in devices[:128]:
        releases = device.get("Releases") or device.get("releases") or []
        for release in releases[:16]:
            metadata = {}
            for key in ("CVE", "Cves", "Issues", "Description", "TrustFlags"):
                if key in release:
                    metadata[key] = release[key]
            reboot = explicit_reboot_requirement(release, device)
            records.append(record(
                f"firmware.fwupd.{device.get('DeviceId') or device.get('device_id') or device.get('Name', 'device')}",
                "firmware",
                device.get("Name") or device.get("name") or "Firmware device",
                "fwupd",
                release.get("Vendor") or release.get("vendor"),
                device.get("Version") or device.get("version"),
                release.get("Version") or release.get("version"),
                True,
                reboot,
                "UNKNOWN",
                "VERIFIED" if release.get("TrustFlags") == "verified" else "UNKNOWN",
                "SECURITY_FIX" if metadata.get("CVE") or metadata.get("Cves") or metadata.get("Issues") else "UNKNOWN",
                provider_state("AVAILABLE", "fwupd update metadata collected", observed, observed),
                {**metadata, "urgent": release.get("IsUrgent", release.get("is_urgent"))},
            ))
    if not records:
        devices_payload, devices_error = run_json(["fwupdmgr", "get-devices", "--json"])
        devices = (devices_payload or {}).get("Devices") or (devices_payload or {}).get("devices") or []
        for device in devices[:128]:
            device_id = device.get("DeviceId") or device.get("device_id") or device.get("Name") or "device"
            records.append(record(
                f"firmware.fwupd.device.{device_id}",
                "firmware",
                device.get("Name") or device.get("name") or "Firmware device",
                "fwupd",
                device.get("Vendor") or device.get("vendor"),
                device.get("Version") or device.get("version"),
                None,
                False,
                "UNKNOWN",
                "UNKNOWN",
                "UNKNOWN",
                "UNKNOWN",
                provider_state("AVAILABLE", "fwupd device metadata collected", observed, observed),
                {"device_id": device_id, "plugin": device.get("Plugin") or device.get("plugin"), "flags": device.get("Flags") or device.get("flags") or []},
            ))
        if not records and devices_error:
            return provider_state("DEGRADED", devices_error, observed), []
        if not records:
            records.append(record(
                "firmware.fwupd", "firmware", "Firmware", "fwupd", None, None, None, False,
                "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN",
                provider_state("AVAILABLE", "fwupd reports no devices or available updates", observed, observed),
            ))
    return provider_state("AVAILABLE", "fwupd update metadata collected", observed, observed), records


def explicit_reboot_requirement(release, device=None):
    """Use only an explicit provider reboot field; urgency is not reboot state."""
    device = device or {}
    for source in (release, device):
        for key in ("NeedsReboot", "needs_reboot", "RequiresReboot", "requires_reboot"):
            if key not in source:
                continue
            value = source[key]
            if isinstance(value, bool):
                return "REQUIRED" if value else "NOT_REQUIRED"
            if isinstance(value, (int, float)) and value in (0, 1):
                return "REQUIRED" if value else "NOT_REQUIRED"
            normalized = str(value).strip().lower()
            if normalized in {"true", "yes", "required", "1"}:
                return "REQUIRED"
            if normalized in {"false", "no", "not_required", "none", "0"}:
                return "NOT_REQUIRED"
    return "UNKNOWN"


def freshclam():
    observed = now()
    try:
        value = clamav_status()
    except Exception as error:  # provider failures become data, never empty success
        return provider_state("DEGRADED", f"ClamAV status failed: {type(error).__name__}", observed), []
    if value.get("status") == "UNAVAILABLE":
        health = provider_state("UNAVAILABLE", value.get("detail") or value.get("update_failure_state") or "ClamAV database unavailable", observed)
    elif value.get("status") in {"INITIALIZING", "UPDATING", "OUTDATED"}:
        health = provider_state("DEGRADED", value.get("detail") or "ClamAV definitions are not ready", observed)
    elif value.get("update_failure_state"):
        health = provider_state("DEGRADED", value["update_failure_state"][:240], observed)
    else:
        health = provider_state("AVAILABLE", "ClamAV database status collected", observed, observed)
    item = record(
        "security.clamav-database", "security", "ClamAV signature database", "freshclam/ClamAV",
        None, value.get("database_version"), None, None, "NOT_REQUIRED", "UNKNOWN",
        "UNKNOWN", "UNKNOWN", health,
        {"database_age_seconds": value.get("database_age_seconds"), "last_successful_update": value.get("last_successful_update"), "engine_version": value.get("engine_version"), "status": value.get("status"), "update_service_state": value.get("update_service_state")},
    )
    return health, [item]


def history_path():
    root = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
    return root / "greyward-update-center" / "history.json"


def normalize_history_version(value, architecture=None):
    """Keep version transitions separate from optional NEVRA architecture text."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    suffix = f".{architecture}" if architecture else ""
    return text[:-len(suffix)] if suffix and text.endswith(suffix) else text


def load_history():
    try:
        value = json.loads(history_path().read_text(encoding="utf-8"))
        return value if isinstance(value, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def previous_records_path():
    return history_path().with_name("previous-records.json")

def load_previous_records():
    try:
        value = json.loads(previous_records_path().read_text(encoding="utf-8"))
        return value if isinstance(value, list) else []
    except (OSError, json.JSONDecodeError):
        return []

def update_history(previous, records):
    history = load_history()
    old = {item.get("id"): item for item in previous}
    for item in records:
        before = old.get(item["id"])
        architecture = (item.get("metadata") or {}).get("arch") or (item.get("metadata") or {}).get("architecture")
        previous_version = normalize_history_version(before.get("current_version"), architecture) if before else None
        new_version = normalize_history_version(item.get("current_version"), architecture)
        if not before or not previous_version or not new_version or previous_version == new_version:
            continue
        metadata = item.get("metadata") or {}
        result = str(metadata.get("history_result") or "UNKNOWN").upper()
        if result not in {"SUCCESS", "FAILURE", "UNKNOWN"}:
            result = "UNKNOWN"
        history.append({
            "record_id": item["id"],
            "identity": item.get("identity") or item.get("name") or item["id"],
            "category": item.get("category"),
            "name": item.get("name"),
            "provider": item["provider"],
            "previous_version": previous_version,
            "new_version": new_version,
            "timestamp": item["observed_at"],
            "source": item.get("source"),
            "result": result,
            "provider_transaction_id": metadata.get("transaction_id") or metadata.get("history_id"),
        })
    history = history[-MAX_HISTORY:]
    try:
        path = history_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(history, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    except OSError:
        pass
    return history


def snapshot():
    previous = load_previous_records()
    health = {}
    records = []
    system_name, system_collector = selected_system_provider()
    for name, collector in ((system_name, system_collector), ("Flatpak", flatpak), ("fwupd", fwupd), ("freshclam/ClamAV", freshclam)):
        state, items = collector()
        health[name] = state
        records.extend(items)
    history = update_history(previous, records)
    try:
        previous_records_path().parent.mkdir(parents=True, exist_ok=True)
        previous_records_path().write_text(json.dumps(records, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    except OSError:
        pass
    generated = now()
    return {"schema": SCHEMA, "generated_at": stamp(generated), "providers": health, "records": records, "history": history}
