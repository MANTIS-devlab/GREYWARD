"""Typed reviewed changes; the root broker retains descriptors and authority.

The session adapter binds opaque reviews to the real session-bus peer process.
It never accepts a claimed UID, SELinux context, policy text or root command.
"""
import json
import os
import re
import stat
import threading
import time
from pathlib import Path

from .application_security import (
    ApplicationReadError, BROKER, BUS_INTERFACE, BUS_OBJECT, DEADLINE_SECONDS,
    MAX_REPLY, OBJECT, SCHEMA, _fields, _integer, _reference, _unique_object,
    _reject_constant,
)

DEVELOPMENT_BROKER = "systems.mantis.greyward.ApplicationSecurityDevelopment1"
SELECTION = Path("/etc/greyward/application-security-development.json")
RISKS = {"RAW_CREDENTIAL_ACCESS", "IN_PROCESS_EXTENSIONS_SHARE_ACCESS",
         "RESTART_REQUIRED_FOR_REVOCATION", "BROADER_ORDINARY_FILE_ACCESS",
         "BROADER_NETWORK_ACCESS"}
OUTCOMES = {"PENDING", "RUNNING", "CANCEL_REQUESTED", "VERIFYING", "COMPLETED",
            "FAILED", "CANCELLED", "EXPIRED"}
FAILURES = {"AUTHORIZATION_REQUIRED", "STALE_REVISION", "IDENTITY_CHANGED",
            "PROVIDER_UNAVAILABLE", "ENFORCEMENT_UNAVAILABLE", "READBACK_FAILED",
            "DEADLINE_EXCEEDED", "WORKER_FAILED"}


def selected_broker():
    """Only a root-owned opt-in selects the already validated UID-1002 provider."""
    if os.getuid() != 1002:
        return BROKER
    try:
        for directory in (SELECTION.parent.parent, SELECTION.parent):
            m = directory.lstat()
            if not stat.S_ISDIR(m.st_mode) or m.st_uid != 0 or m.st_mode & 0o022:
                return BROKER
        fd = os.open(SELECTION, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as source:
            m = os.fstat(source.fileno())
            if not stat.S_ISREG(m.st_mode) or m.st_uid != 0 or m.st_mode & 0o022 or m.st_size > 1024:
                return BROKER
            value = json.loads(source.read(1025))
        if value == {"schema": SCHEMA, "development_uid": 1002}:
            return DEVELOPMENT_BROKER
    except (OSError, ValueError, AttributeError):
        pass
    return BROKER


def decode(raw):
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_REPLY:
        raise ApplicationReadError("INVALID_WORKFLOW")
    try:
        return json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (ValueError, TypeError, RecursionError) as error:
        raise ApplicationReadError("INVALID_WORKFLOW") from error


def validate_preview(value, uid):
    _fields(value, {"kind", "preview"})
    kind, review = value["kind"], value["preview"]
    if kind == "GRANT":
        _fields(review, {"grant_ref", "tool_profile", "review"})
        if (not _reference(review["grant_ref"], "grant")
                or review["tool_profile"] != "openssh-key-inspection/v1"):
            raise ApplicationReadError("INVALID_WORKFLOW")
        review = review["review"]
    if kind == "REGISTRATION":
        _fields(review, {"operation_ref", "resource", "expected_revision", "expires_after_ms"})
        from .application_security import _resource
        _resource(review["resource"], uid, review["expected_revision"] + 1)
        if (review["resource"]["policy_revision"] != review["expected_revision"] + 1
                or review["resource"]["coverage"] != "UNKNOWN"):
            raise ApplicationReadError("INVALID_WORKFLOW")
    elif kind in {"GRANT", "REVOCATION"}:
        _fields(review, {"operation_ref", "installation_ref", "generation", "resource_refs",
                         "risks", "expected_revision", "expires_after_ms"})
        if (not _reference(review["installation_ref"], "installation")
                or not isinstance(review["generation"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", review["generation"])
                or not isinstance(review["resource_refs"], list)
                or not 1 <= len(review["resource_refs"]) <= 64
                or len(set(review["resource_refs"])) != len(review["resource_refs"])
                or any(not _reference(r, "resource") for r in review["resource_refs"])
                or not isinstance(review["risks"], list) or len(review["risks"]) > 5
                or any(r not in RISKS for r in review["risks"])
                or (kind == "GRANT" and not {"RAW_CREDENTIAL_ACCESS", "IN_PROCESS_EXTENSIONS_SHARE_ACCESS"}.issubset(review["risks"]))):
            raise ApplicationReadError("INVALID_WORKFLOW")
    else:
        raise ApplicationReadError("INVALID_WORKFLOW")
    if (not _reference(review["operation_ref"], "operation")
            or not _integer(review["expected_revision"]) or review["expected_revision"] == 0
            or not _integer(review["expires_after_ms"], 120000) or review["expires_after_ms"] == 0):
        raise ApplicationReadError("INVALID_WORKFLOW")
    return review


def validate_operation(value, reference):
    _fields(value, {"operation_ref", "outcome", "committed_revision", "verified_readback", "failure"})
    completed = value["outcome"] == "COMPLETED"
    revision = value["committed_revision"]
    if (value["operation_ref"] != reference or value["outcome"] not in OUTCOMES
            or type(value["verified_readback"]) is not bool
            or (revision is not None and (not _integer(revision) or revision == 0))
            or (value["failure"] is not None and value["failure"] not in FAILURES)
            or (completed and (not value["verified_readback"] or revision is None or value["failure"] is not None))
            or (value["verified_readback"] and not completed)
            or (value["outcome"] in {"FAILED", "EXPIRED"} and value["failure"] is None)):
        raise ApplicationReadError("INVALID_WORKFLOW")
    return value


class WorkflowTransport:
    def reset_owner(self):
        if self.bus is not None:
            self.bus.close()
        self.bus = None
        self.owner = None

    """One fixed root connection retains broker execution ownership of reviews."""
    def __init__(self):
        self.bus = None
        self.owner = None
        self.destination = selected_broker()

    def call(self, member, signature, arguments):
        import dbus
        try:
            if self.bus is None:
                socket = Path("/run/dbus/system_bus_socket")
                for directory in (Path("/run"), socket.parent):
                    m = directory.lstat()
                    if not stat.S_ISDIR(m.st_mode) or m.st_uid != 0 or m.st_mode & 0o022:
                        raise ApplicationReadError("BROKER_UNAVAILABLE")
                m = socket.lstat()
                if not stat.S_ISSOCK(m.st_mode) or m.st_uid != 0:
                    raise ApplicationReadError("BROKER_UNAVAILABLE")
                self.bus = dbus.bus.BusConnection("unix:path=/run/dbus/system_bus_socket")
            def owner():
                return str(self.bus.call_blocking(BUS_INTERFACE, BUS_OBJECT, BUS_INTERFACE,
                    "GetNameOwner", "s", (self.destination,), timeout=2))
            current = owner()
            if self.owner is None:
                credentials = self.bus.call_blocking(BUS_INTERFACE, BUS_OBJECT, BUS_INTERFACE,
                    "GetConnectionCredentials", "s", (current,), timeout=2)
                if not re.fullmatch(r":[0-9]+\.[0-9]+", current) or int(credentials.get("UnixUserID", -1)) != 0:
                    raise ApplicationReadError("BROKER_UNAVAILABLE")
                self.owner = current
            if current != self.owner:
                raise ApplicationReadError("BROKER_CHANGED")
            result = self.bus.call_blocking(self.owner, OBJECT, BROKER, member, signature,
                                           arguments, timeout=DEADLINE_SECONDS)
            if owner() != self.owner:
                raise ApplicationReadError("BROKER_CHANGED")
            return result
        except (OSError, dbus.DBusException, TypeError, ValueError) as error:
            raise ApplicationReadError("BROKER_UNAVAILABLE") from error


class ApplicationSecurityWorkflows:
    def administration_state(self):
        value = decode(str(self._call('GetAdministrationState', '', ())))
        _fields(value, {'schema','available','active','authentication_window_seconds'})
        if value['schema'] != 'greyward.administration/v1' or type(value['available']) is not bool or type(value['active']) is not bool or value['authentication_window_seconds'] != 120:
            raise ApplicationReadError('INVALID_WORKFLOW')
        return value

    def open_administration(self):
        if not bool(self._call('RequestAdministration', 'as', (['-i'],))):
            raise ApplicationReadError('ADMINISTRATION_UNAVAILABLE')
        return {'opened':True}

    def __init__(self, transport=None, clock=time.monotonic, record=None):
        self.transport = transport or WorkflowTransport()
        self.clock = clock
        self.owners = {}
        self.lock = threading.Lock()
        self.record = record or self._record
        self.published = set()
        self.launches = {}
        self.event_cursor = 0
        self.access_blocks = {}
        self.event_source = "UNKNOWN"

    def _call(self, member, signature, arguments):
        try:
            return self.transport.call(member, signature, arguments)
        except ApplicationReadError as error:
            if str(error) == "BROKER_CHANGED":
                # Never replay a mutation or carry leases across root owners.
                # A subsequent call must authenticate the new root owner.
                self.owners.clear()
                self.published.clear()
                self.launches.clear()
                self.event_cursor = 0
                self.access_blocks.clear()
                self.event_source = "UNAVAILABLE"
                self.transport.reset_owner()
            raise

    def reconcile_access_events(self):
        """Ingestion only. Projections never mutate history or grant authority."""
        from .telemetry import event, record_event, user_store, stamp
        with self.lock:
            try:
                value = decode(str(self._call("ReadSecurityEvents", "tu", (self.event_cursor, 100))))
                _fields(value, {"schema", "source_state", "cursor", "truncated", "events"})
                if (value["schema"] != SCHEMA or value["source_state"] not in {"AVAILABLE", "UNAVAILABLE"}
                        or not _integer(value["cursor"]) or type(value["truncated"]) is not bool
                        or not isinstance(value["events"], list) or len(value["events"]) > 100
                        or (value["source_state"] != "AVAILABLE" and value["events"])):
                    raise ApplicationReadError("INVALID_WORKFLOW")
                sequence = self.event_cursor
                if value["cursor"] < sequence and value["truncated"]:
                    sequence = 0  # Root owner restarted; stable event IDs deduplicate history.
                for item in value["events"]:
                    base = {"sequence", "event_id", "resource_ref", "action", "decision", "attribution"}
                    optional = {"process", "occurred_at_ms", "policy_revision"}
                    if not isinstance(item, dict) or not base <= set(item) or set(item) - base - optional:
                        raise ApplicationReadError("INVALID_WORKFLOW")
                    if (not _integer(item["sequence"]) or item["sequence"] <= sequence
                            or not re.fullmatch(r"appsec-denial-[0-9a-f]{64}", str(item["event_id"]))
                            or not _reference(item["resource_ref"], "resource")
                            or item["action"] not in {"READ", "WRITE", "OPEN"}
                            or item["decision"] != "DENIED" or item["attribution"] != "UNKNOWN"):
                        raise ApplicationReadError("INVALID_WORKFLOW")
                    process = item.get("process")
                    if process is not None:
                        _fields(process, {"pid", "executable_name", "source"})
                        if (not _integer(process["pid"], (1 << 32) - 1) or process["pid"] == 0
                                or process["source"] != "KERNEL_AUDIT"
                                or not isinstance(process["executable_name"], str)
                                or not re.fullmatch(r"[A-Za-z0-9._+\-]{1,128}", process["executable_name"])):
                            raise ApplicationReadError("INVALID_WORKFLOW")
                    if (item.get("policy_revision") is not None and
                            (not _integer(item["policy_revision"]) or item["policy_revision"] == 0)):
                        raise ApplicationReadError("INVALID_WORKFLOW")
                    if item.get("occurred_at_ms") is not None and not _integer(item["occurred_at_ms"], 253402300799999):
                        raise ApplicationReadError("INVALID_WORKFLOW")
                    sequence = item["sequence"]
                if value["events"] and sequence != value["cursor"]:
                    raise ApplicationReadError("INVALID_WORKFLOW")
                for item in value["events"]:
                    details = {"resource_refs": [item["resource_ref"]], "audit_truncated": value["truncated"]}
                    if item.get("process") is not None:
                        details["observed_process"] = item["process"]
                    if item.get("policy_revision") is not None:
                        details["policy_revision"] = item["policy_revision"]
                    occurred = None
                    if item.get("occurred_at_ms") is not None:
                        import datetime as dt
                        occurred = stamp(dt.datetime.fromtimestamp(item["occurred_at_ms"] / 1000, dt.timezone.utc))
                    recorded = record_event(event(event_id=item["event_id"],
                        component="greyward-application-security", source="root-kernel-selinux-audit",
                        category="APPLICATION_SECURITY", event_type="SENSITIVE_ACCESS_BLOCKED",
                        action=item["action"], outcome="DENIED", decision="DENIED",
                        occurred_at=occurred, details=details,
                        quality={"source_state": "PARTIAL" if value["truncated"] else "AVAILABLE",
                                 "attribution": "UNKNOWN", "confidence": "KERNEL_DECISION"}), user_store())
                    if recorded:
                        previous = self.access_blocks.get(item["resource_ref"], {})
                        self.access_blocks[item["resource_ref"]] = {"resource_ref": item["resource_ref"],
                            "count": min(1000000, previous.get("count", 0) + 1), "expires": self.clock() + 300}
                self.event_cursor = value["cursor"]
                self.event_source = value["source_state"]
            except (ApplicationReadError, OSError, ValueError, RuntimeError):
                self.event_source = "UNAVAILABLE"
            self.access_blocks = {key: entry for key, entry in self.access_blocks.items()
                                  if entry["expires"] > self.clock()}
            if len(self.access_blocks) > 256:
                self.access_blocks = dict(list(self.access_blocks.items())[-256:])

    def recent_access_blocks(self):
        with self.lock:
            return [{"resource_ref": item["resource_ref"], "count": item["count"]}
                    for item in self.access_blocks.values() if item["expires"] > self.clock()]

    @staticmethod
    def _record(reference, kind, result, summary):
        from .telemetry import event, record_event, user_store
        record_event(event(event_id="appsec-" + reference,
            component="greyward-application-security", source="root-broker-operation-readback",
            category="APPLICATION_SECURITY", event_type="POLICY_" + kind,
            action=kind, outcome=result["outcome"], retention_class="semantic",
            application=summary.get("installation_ref"),
            correlation={"operation_ref": reference},
            details={"policy_revision": result["committed_revision"], "verified_readback": result["verified_readback"],
                     "resource_refs": summary.get("resource_refs", []), "failure": result["failure"]},
            quality={"source_state": "AVAILABLE", "attribution": "EXACT", "confidence": "EXACT"}), user_store())

    def grants(self):
        with self.lock:
            value = decode(str(self._call("ListAccessGrants", "", ())))
            if "capabilities" not in value:
                value["capabilities"] = {"isolation": False, "policy_changes": False}
            _fields(value, {"schema", "policy_revision", "enforcement_health", "grants", "capabilities"})
            _fields(value["capabilities"], {"isolation", "policy_changes"})
            if any(type(flag) is not bool for flag in value["capabilities"].values()):
                raise ApplicationReadError("INVALID_WORKFLOW")
            if (value["schema"] != SCHEMA or value["enforcement_health"] != "UNKNOWN"
                    or not _integer(value["policy_revision"]) or value["policy_revision"] == 0
                    or not isinstance(value["grants"], list) or len(value["grants"]) > 256):
                raise ApplicationReadError("INVALID_WORKFLOW")
            seen = set()
            for grant in value["grants"]:
                _fields(grant, {"grant_ref", "owner_uid", "installation_ref", "generation", "resources",
                                "access", "lifetime", "policy_revision"})
                if (not _reference(grant["grant_ref"], "grant") or grant["grant_ref"] in seen
                        or grant["owner_uid"] != os.getuid()
                        or not _reference(grant["installation_ref"], "installation")
                        or not isinstance(grant["generation"], str) or not re.fullmatch(r"[0-9a-f]{64}", grant["generation"])
                        or not isinstance(grant["resources"], list) or not 1 <= len(grant["resources"]) <= 64
                        or any(not _reference(r, "resource") for r in grant["resources"])
                        or grant["access"] != ["READ"] or grant["lifetime"] != {"kind": "PERSISTENT"}
                        or not _integer(grant["policy_revision"]) or not 1 <= grant["policy_revision"] <= value["policy_revision"]):
                    raise ApplicationReadError("INVALID_WORKFLOW")
                seen.add(grant["grant_ref"])
            return value

    def prepare_launch(self, actor, descriptor, graphical=True, handler=None, arguments=()):
        with self.lock:
            self.launches = {r: entry for r, entry in self.launches.items() if entry[1] > self.clock()}
            if len(self.launches) >= 32:
                raise ApplicationReadError("WORKFLOW_CAPACITY")
            member = "PrepareSelectedDocumentLaunch" if handler else "PrepareGraphicalLaunch" if graphical else "PrepareIsolatedLaunch"
            signature = "hsasb" if handler else "has"
            args = (descriptor, handler, list(arguments), graphical) if handler else (descriptor, list(arguments))
            reference = str(self._call(member, signature, args))
            if not _reference(reference, "launch"):
                raise ApplicationReadError("INVALID_WORKFLOW")
            self.launches[reference] = (actor, self.clock() + 90, graphical)
            return {"schema": SCHEMA, "launch_ref": reference, "requested_profile": "ISOLATED",
                    "enforcement_health": "UNKNOWN", "private_display_requested": graphical,
                    "expires_after_ms": 90000}

    def start_launch(self, actor, reference):
        with self.lock:
            entry = self.launches.get(reference)
            if not entry or entry[0] != actor or entry[1] <= self.clock():
                raise ApplicationReadError("REVIEW_OWNER_CHANGED")
            del self.launches[reference]
            streams = self._call("StartPreparedLaunch", "s", (reference,))
            if not isinstance(streams, (tuple, list)) or len(streams) != 3:
                raise ApplicationReadError("INVALID_WORKFLOW")
            descriptors = []
            try:
                descriptors = [stream.take() for stream in streams]
                os.close(descriptors[0])
                for fd in descriptors[1:]:
                    threading.Thread(target=_discard_stream, args=(fd,), daemon=True).start()
            except (OSError, AttributeError, TypeError) as error:
                for fd in descriptors:
                    try: os.close(fd)
                    except OSError: pass
                raise ApplicationReadError("INVALID_WORKFLOW") from error
            process = BrokerLaunchProcess(self, reference)
            return process, {"schema": SCHEMA, "launch_ref": reference, "state": "LAUNCHED",
                             "isolation_established": True, "enforcement_health": "UNKNOWN",
                             "private_display": entry[2]}

    def launch_exit(self, reference):
        with self.lock:
            result = self._call("GetLaunch", "s", (reference,))
            if not isinstance(result, (tuple, list)) or len(result) != 2 or not 0 <= int(result[1]) <= 255:
                raise ApplicationReadError("INVALID_WORKFLOW")
            return int(result[1]) if bool(result[0]) else None

    def preview(self, actor, member, signature, arguments):
        if member not in {"PreviewResourceRegistration", "PreviewPolicyChange", "PreviewGrantRevocation"}:
            raise ApplicationReadError("INVALID_REQUEST")
        with self.lock:
            self.owners = {r: entry for r, entry in self.owners.items() if entry[1] > self.clock()}
            self.published.intersection_update(self.owners)
            if len(self.owners) >= 32:
                raise ApplicationReadError("WORKFLOW_CAPACITY")
            started = self.clock()
            value = decode(str(self._call(member, signature, arguments)))
            review = validate_preview(value, os.getuid())
            expires = started + review["expires_after_ms"] / 1000
            if self.clock() >= expires:
                raise ApplicationReadError("REVIEW_EXPIRED")
            self.owners[review["operation_ref"]] = (actor, expires + 300, expires, value["kind"], dict(review))
            # UI receives the reduced lease, never an extended local review.
            review["expires_after_ms"] = max(1, int((expires - self.clock()) * 1000))
            return value

    def operation(self, actor, reference, action="GetOperation"):
        if not _reference(reference, "operation") or action not in {"GetOperation", "ApplyPolicyChange", "CancelOperation"}:
            raise ApplicationReadError("INVALID_REQUEST")
        with self.lock:
            entry = self.owners.get(reference)
            if not entry or entry[0] != actor or entry[1] <= self.clock():
                raise ApplicationReadError("REVIEW_OWNER_CHANGED")
            if action == "ApplyPolicyChange" and entry[2] <= self.clock():
                raise ApplicationReadError("REVIEW_EXPIRED")
            args = (reference, True) if action == "ApplyPolicyChange" else (reference,)
            value = decode(str(self._call(action, "sb" if action == "ApplyPolicyChange" else "s", args)))
            result = validate_operation(value, reference)
            if result["outcome"] in {"COMPLETED", "FAILED", "CANCELLED", "EXPIRED"} and reference not in self.published:
                try:
                    self.record(reference, entry[3], result, entry[4])
                    self.published.add(reference)
                except (OSError, ValueError, RuntimeError, ImportError):
                    # A history failure never changes the enforcement result.
                    pass
            return result


def _discard_stream(fd):
    try:
        with os.fdopen(fd, "rb") as stream:
            while stream.read(8192):
                pass
    except OSError:
        pass


class BrokerLaunchProcess:
    """Popen-compatible lifetime handle; only the owning root workload is polled."""
    def __init__(self, workflows, reference):
        self.workflows = workflows
        self.reference = reference
        self.returncode = None
        self.deadline = time.monotonic() + 3660

    def poll(self):
        if self.returncode is None:
            self.returncode = self.workflows.launch_exit(self.reference)
        return self.returncode

    def wait(self, timeout=None):
        limit = self.deadline if timeout is None else min(self.deadline, time.monotonic() + max(0, timeout))
        while self.poll() is None:
            if time.monotonic() >= limit:
                raise ApplicationReadError("LAUNCH_OUTCOME_UNCONFIRMED")
            time.sleep(0.3)
        return self.returncode
