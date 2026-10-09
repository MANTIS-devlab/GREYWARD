"""Typed, read-only projection of the root Application Security broker.

This adapter grants no authority to user-owned history or session-bus callers.
Missing inventory is unavailable, not an empty protected application list.
"""
import datetime as dt
import json
import os
import re
import stat
import time
from pathlib import Path

SCHEMA = "greyward.application-security/v1"
BROKER = "systems.mantis.greyward.ApplicationSecurity1"
OBJECT = "/systems/mantis/greyward/ApplicationSecurity1"
BUS_OBJECT = "/org/freedesktop/DBus"
BUS_INTERFACE = "org.freedesktop.DBus"
MAX_REPLY = 256 * 1024
DEADLINE_SECONDS = 6
U64_MAX = (1 << 64) - 1
HEALTH = {"AVAILABLE", "UNAVAILABLE", "DEGRADED", "UNKNOWN"}
PROFILES = {"PROTECTED", "ISOLATED", "TRUSTED"}
COVERAGE = {"graphical_session", "user_manager", "direct_exec",
            "services_and_scheduled_jobs", "enrolled_remote_sessions",
            "protected_resource_labels", "deputies_and_portals"}
ISOLATION = {"private_home", "filesystem_scope", "namespaces", "landlock",
             "seccomp", "network_denied", "display_required", "private_display"}


class ApplicationReadError(Exception):
    """A bounded failure code; never disclose transport errors or private paths."""


def unavailable_read(reason="INVALID_REQUEST"):
    observed = dt.datetime.now(dt.timezone.utc).isoformat()
    return {"schema": SCHEMA, "source_state": {"state": "UNAVAILABLE", "reason": reason},
            "observed_at": observed, "fresh_until": observed, "projection": None}


def _integer(value, maximum=U64_MAX):
    return type(value) is int and 0 <= value <= maximum


def _reference(value, namespace):
    return isinstance(value, str) and re.fullmatch(namespace + r"_[0-9a-f]{64}", value) is not None


def _fields(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ApplicationReadError("INVALID_PROJECTION")


def _booleans(value, fields):
    _fields(value, fields)
    if any(type(item) is not bool for item in value.values()):
        raise ApplicationReadError("INVALID_PROJECTION")


def _protection(value, elapsed_ms):
    _fields(value, {"requested_profile", "effective_profile", "health", "coverage",
                    "isolation", "reviewed_exception", "policy_revision", "evidence_age_ms"})
    _booleans(value["coverage"], COVERAGE)
    _booleans(value["isolation"], ISOLATION)
    if (value["requested_profile"] not in PROFILES or value["health"] not in HEALTH
            or type(value["reviewed_exception"]) is not bool
            or not _integer(value["policy_revision"])
            or (value["evidence_age_ms"] is not None and not _integer(value["evidence_age_ms"]))):
        raise ApplicationReadError("INVALID_PROJECTION")
    available = value["health"] == "AVAILABLE"
    if available != (value["effective_profile"] is not None):
        raise ApplicationReadError("INVALID_PROTECTION")
    if available:
        isolation = value["isolation"]
        isolated = all(isolation[item] for item in ISOLATION - {"display_required", "private_display"})
        isolated = isolated and (not isolation["display_required"] or isolation["private_display"])
        if (value["effective_profile"] != value["requested_profile"]
                or not all(value["coverage"][key] for key in COVERAGE - {"deputies_and_portals"}) or value["policy_revision"] == 0
                or value["evidence_age_ms"] is None
                or value["evidence_age_ms"] + elapsed_ms > 30_000
                or (value["requested_profile"] == "ISOLATED" and not isolated)
                or (value["requested_profile"] == "TRUSTED" and not value["reviewed_exception"])):
            raise ApplicationReadError("INVALID_PROTECTION")
        # Preserve transport time in the age carried to presentation.
        value["evidence_age_ms"] += elapsed_ms


def _detail(value, uid, elapsed_ms):
    _fields(value, {"record", "protection"})
    record = value["record"]
    _fields(record, {"identity", "first_seen", "last_seen"})
    identity = record["identity"]
    _fields(identity, {"application_ref", "installation_ref", "generation", "provider", "owner_uid", "provenance"} | ({"display_name"} if "display_name" in identity else set()))
    if "display_name" in identity:
        name=identity["display_name"]
        if not isinstance(name,str) or not name or len(name.encode('utf-8'))>256 or any(ord(c)<32 or 127<=ord(c)<=159 for c in name):
            raise ApplicationReadError("INVALID_IDENTITY")
    if (not _reference(identity["application_ref"], "application")
            or not _reference(identity["installation_ref"], "installation")
            or not isinstance(identity["generation"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", identity["generation"])
            or identity["provider"] not in {"RPM", "FLATPAK", "APP_IMAGE", "MANUAL", "SCRIPT", "UNKNOWN"}
            or not _integer(identity["owner_uid"], (1 << 32) - 1) or identity["owner_uid"] != uid
            or not _integer(record["first_seen"]) or not _integer(record["last_seen"])
            or record["first_seen"] > record["last_seen"]):
        raise ApplicationReadError("INVALID_IDENTITY")
    provenance = identity["provenance"]
    _fields(provenance, {"state", "source_receipt"})
    receipt = provenance["source_receipt"]
    if (provenance["state"] not in {"VERIFIED", "UNVERIFIED", "UNAVAILABLE", "UNKNOWN"}
            or (receipt is not None and (not isinstance(receipt, str) or not re.fullmatch(r"[0-9a-f]{64}", receipt)))
            or (provenance["state"] == "VERIFIED" and receipt is None)):
        raise ApplicationReadError("INVALID_IDENTITY")
    _protection(value["protection"], elapsed_ms)


def _resource(value, uid, revision):
    _fields(value, {"resource_ref", "owner_uid", "category", "label", "coverage", "policy_revision"})
    if (not _reference(value["resource_ref"], "resource")
            or not _integer(value["owner_uid"], (1 << 32) - 1) or value["owner_uid"] != uid
            or value["category"] not in {"CREDENTIALS", "CLOUD", "DEVELOPMENT", "BROWSER_SESSION", "CUSTOM"}
            or not isinstance(value["label"], str) or not value["label"]
            or len(value["label"].encode('utf-8')) > 256
            or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value["label"])
            or value["coverage"] not in {"UNKNOWN", "PROTECTED", "UNAVAILABLE"}
            or not _integer(value["policy_revision"]) or not 1 <= value["policy_revision"] <= revision):
        # Positive state is a leased projection from the pinned root broker's
        # fresh object/kernel/session readback, never stored policy intent.
        raise ApplicationReadError("INVALID_PROJECTION")


def _unique_object(pairs):
    value = {}
    for name, item in pairs:
        if name in value:
            raise ApplicationReadError("INVALID_PROJECTION")
        value[name] = item
    return value


def _reject_constant(_):
    raise ApplicationReadError("INVALID_PROJECTION")


def validate_projection(raw, method, uid, *, limit=100, revision=None, reference=None, after="", elapsed_ms=0):
    """Validate complete typed responses, including cross-user and stale pages."""
    if not isinstance(raw, str):
        raise ApplicationReadError("RESPONSE_LIMIT")
    try:
        if len(raw.encode("utf-8")) > MAX_REPLY:
            raise ApplicationReadError("RESPONSE_LIMIT")
        value = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
        if method == "GetCoverage":
            _fields(value, {"schema", "inventory_health", "protection"})
            if value["inventory_health"] not in HEALTH:
                raise ApplicationReadError("INVALID_PROJECTION")
            _protection(value["protection"], elapsed_ms)
        elif method == "GetApplication":
            _fields(value, {"schema", "application"})
            if value["application"] is not None:
                _detail(value["application"], uid, elapsed_ms)
                if value["application"]["record"]["identity"]["installation_ref"] != reference:
                    raise ApplicationReadError("INVALID_IDENTITY")
        elif method == "ListApplications":
            _fields(value, {"schema", "inventory_revision", "inventory_health", "applications", "next_cursor"})
            if (not _integer(value["inventory_revision"]) or value["inventory_health"] not in HEALTH
                    or (revision is not None and value["inventory_revision"] != revision)
                    or not isinstance(value["applications"], list) or len(value["applications"]) > limit):
                raise ApplicationReadError("INVALID_PROJECTION")
            references = []
            for item in value["applications"]:
                _detail(item, uid, elapsed_ms)
                references.append(item["record"]["identity"]["installation_ref"])
            if len(set(references)) != len(references):
                raise ApplicationReadError("INVALID_IDENTITY")
            if references != sorted(references) or (after and any(item <= after for item in references)):
                raise ApplicationReadError("INVALID_PROJECTION")
            expected_cursor = references[-1] if len(references) == limit else None
            if value["next_cursor"] != expected_cursor:
                raise ApplicationReadError("INVALID_PROJECTION")
        elif method in {"ListProtectedResources", "GetProtectedResource"}:
            if method == "ListProtectedResources":
                _fields(value, {"schema", "policy_revision", "inventory_health", "resources", "next_cursor"})
                if (value["inventory_health"] != "UNKNOWN" or not isinstance(value["resources"], list)
                        or len(value["resources"]) > limit):
                    raise ApplicationReadError("INVALID_PROJECTION")
                resources = value["resources"]
            else:
                _fields(value, {"schema", "policy_revision", "resource"})
                resources = [] if value["resource"] is None else [value["resource"]]
            policy_revision = value["policy_revision"]
            if (not _integer(policy_revision) or policy_revision == 0
                    or (revision is not None and revision != policy_revision)):
                raise ApplicationReadError("INVALID_PROJECTION")
            references = []
            for resource in resources:
                _resource(resource, uid, policy_revision)
                references.append(resource["resource_ref"])
            if method == "GetProtectedResource":
                if references and references != [reference]:
                    raise ApplicationReadError("INVALID_PROJECTION")
            elif (references != sorted(set(references)) or (after and any(r <= after for r in references))
                    or value["next_cursor"] != (references[-1] if len(references) == limit else None)):
                raise ApplicationReadError("INVALID_PROJECTION")
        else:
            raise ApplicationReadError("INVALID_REQUEST")
        if value["schema"] != SCHEMA:
            raise ApplicationReadError("INVALID_SCHEMA")
        return value
    except (ValueError, TypeError, RecursionError, UnicodeError) as error:
        raise ApplicationReadError("INVALID_PROJECTION") from error


class RootBrokerTransport:
    """Fixed system socket, root-owned unique destination and total deadline."""

    def read(self, method, signature, arguments):
        from .application_workflows import selected_broker
        destination = selected_broker()
        try:
            import dbus
        except ImportError as error:
            raise ApplicationReadError("BROKER_UNAVAILABLE") from error
        deadline = time.monotonic() + DEADLINE_SECONDS
        bus = None
        try:
            socket = Path("/run/dbus/system_bus_socket")
            for directory in (Path("/run"), socket.parent):
                metadata = directory.lstat()
                if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
                    raise ApplicationReadError("BROKER_UNAVAILABLE")
            metadata = socket.lstat()
            if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != 0:
                raise ApplicationReadError("BROKER_UNAVAILABLE")
            # Do not honor a user-selected DBUS_SYSTEM_BUS_ADDRESS.
            bus = dbus.bus.BusConnection("unix:path=/run/dbus/system_bus_socket")

            def call(destination, path, interface, member, sig, args, maximum=2):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ApplicationReadError("BROKER_DEADLINE")
                return bus.call_blocking(destination, path, interface, member, sig, args,
                                         timeout=min(maximum, remaining))

            owner = str(call(BUS_INTERFACE, BUS_OBJECT, BUS_INTERFACE, "GetNameOwner", "s", (destination,)))
            if not re.fullmatch(r":[0-9]+\.[0-9]+", owner):
                raise ApplicationReadError("BROKER_UNAVAILABLE")
            credentials = call(BUS_INTERFACE, BUS_OBJECT, BUS_INTERFACE, "GetConnectionCredentials", "s", (owner,))
            if ("UnixUserID" not in credentials or int(credentials["UnixUserID"]) != 0
                    or "ProcessID" not in credentials or int(credentials["ProcessID"]) <= 0):
                raise ApplicationReadError("BROKER_AUTHORITY_UNAVAILABLE")
            result = call(owner, OBJECT, BROKER, method, signature, arguments, DEADLINE_SECONDS)
            current = str(call(BUS_INTERFACE, BUS_OBJECT, BUS_INTERFACE, "GetNameOwner", "s", (destination,)))
            if current != owner:
                raise ApplicationReadError("BROKER_CHANGED")
            if time.monotonic() >= deadline:
                raise ApplicationReadError("BROKER_DEADLINE")
            return result
        except (OSError, dbus.DBusException, TypeError, ValueError) as error:
            raise ApplicationReadError("BROKER_UNAVAILABLE") from error
        finally:
            if bus is not None:
                try:
                    bus.close()
                except (OSError, dbus.DBusException) as error:
                    raise ApplicationReadError("BROKER_UNAVAILABLE") from error


class ApplicationSecurityReads:
    """No generic operation, claimed UID, executable path or policy writes."""

    def __init__(self, transport=None):
        self.transport = transport or RootBrokerTransport()

    def _read(self, method, signature, arguments, **validation):
        started = time.monotonic()
        try:
            raw = self.transport.read(method, signature, arguments)
            elapsed_ms = int((time.monotonic() - started) * 1000)
            if elapsed_ms >= DEADLINE_SECONDS * 1000:
                raise ApplicationReadError("BROKER_DEADLINE")
            projection = validate_projection(raw, method, os.getuid(), elapsed_ms=elapsed_ms, **validation)
            protections = ([item["protection"] for item in projection["applications"]] if method == "ListApplications"
                           else [projection["application"]["protection"]] if method == "GetApplication" and projection["application"]
                           else [projection["protection"]] if method == "GetCoverage" else [])
            lease_ms = min([5000] + [30_000 - value["evidence_age_ms"] for value in protections if value["health"] == "AVAILABLE"])
            observed = dt.datetime.now(dt.timezone.utc)
            return {"schema": SCHEMA, "source_state": {"state": "AVAILABLE", "reason": None},
                    "observed_at": observed.isoformat(), "fresh_until": (observed + dt.timedelta(milliseconds=lease_ms)).isoformat(),
                    "projection": projection}
        except ApplicationReadError as error:
            return unavailable_read(str(error))

    def coverage(self):
        return self._read("GetCoverage", "", ())

    def application(self, reference):
        if not _reference(reference, "installation"):
            raise ApplicationReadError("INVALID_REQUEST")
        return self._read("GetApplication", "s", (reference,), reference=reference)

    def applications(self, limit=100, has_revision=False, revision=0, after=""):
        if (not _integer(limit, 100) or limit == 0 or type(has_revision) is not bool
                or not _integer(revision) or not isinstance(after, str)
                or (after and not _reference(after, "installation"))
                or (not has_revision and (revision != 0 or after))):
            raise ApplicationReadError("INVALID_REQUEST")
        return self._read("ListApplications", "ubts", (limit, has_revision, revision, after),
                          limit=limit, revision=revision if has_revision else None, after=after)

    def resource(self, reference):
        if not _reference(reference, "resource"):
            raise ApplicationReadError("INVALID_REQUEST")
        return self._read("GetProtectedResource", "s", (reference,), reference=reference)

    def resources(self, limit=100, has_revision=False, revision=0, after=""):
        if (not _integer(limit, 100) or limit == 0 or type(has_revision) is not bool
                or not _integer(revision) or not isinstance(after, str)
                or (after and not _reference(after, "resource"))
                or (not has_revision and (revision != 0 or after))):
            raise ApplicationReadError("INVALID_REQUEST")
        return self._read("ListProtectedResources", "ubts", (limit, has_revision, revision, after),
                          limit=limit, revision=revision if has_revision else None, after=after)
