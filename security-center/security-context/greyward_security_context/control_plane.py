#!/usr/bin/python3
"""Root-only OpenSnitch v1.8.0 control plane.

The service deliberately owns only the daemon gRPC boundary and a bounded,
redacted Security Context handoff. It never imports OpenSnitch UI code.
"""
import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
import stat
import subprocess
import tempfile
import uuid
from concurrent import futures
from pathlib import Path

import grpc

from greyward_security_context.proto.v1_8_0 import ui_pb2
from greyward_security_context.proto.v1_8_0 import ui_pb2_grpc
from greyward_security_context.telemetry import event as telemetry_event
from greyward_security_context.telemetry import record_event
from greyward_security_context.network_location import country_resolution_for_destination
from greyward_security_context.feodo import matching_indicator, threat_status

try:
    import grp
except ImportError:  # pragma: no cover - Windows source/test host
    grp = None

PROTOCOL_VERSION = "1.8.0"
SCHEMA = "greyward.security.context/v1"
MAX_EVENTS = 64
MAX_NETWORK_ACTIVITY = 4096
NETWORK_ACTIVITY_RETENTION_SECONDS = 30 * 60
MAX_NETWORK_RULES = 128
NETWORK_STALE_SECONDS = 30
DNS_POLICY_PORTS = (53, 853)
DNS_PROVIDER_ADDRESSES = {
    "9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9",
    "76.76.2.2", "76.76.10.2", "2606:1a40::2", "2606:1a40:1::2",
    "94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",
}
VPN_DEVICE_TYPES = frozenset({"openvpn", "tun", "tap", "vpn", "wireguard"})
LOCAL_RESOLVER_ADDRESSES = frozenset({"127.0.0.53", "127.0.0.54", "::1"})
SOCKET_PATH = Path("/run/greyward-opensnitch/control-plane.sock")
STATE_PATH = Path("/run/greyward-security-context/opensnitch-summary.json")
NETWORK_STATE_PATH = Path("/run/greyward-security-context/network-protection.json")
POLICY_PATH = Path("/etc/greyward/opensnitch-policy.json")
SECURITY_CONTEXT_RUNTIME_DIR = Path("/run/greyward-security-context")


def _wheel_gid():
    if grp is None:
        return None
    try:
        return grp.getgrnam("wheel").gr_gid
    except (KeyError, OSError):
        return None


def _secure_projection(path):
    return path.parent == SECURITY_CONTEXT_RUNTIME_DIR and path.name in {
        "network-protection.json",
        "opensnitch-summary.json",
    }


def _chown_wheel(path):
    wheel_gid = _wheel_gid()
    chown = getattr(os, "chown", None)
    if wheel_gid is not None and callable(chown):
        try:
            chown(path, 0, wheel_gid)
        except OSError:
            pass


def now():
    return dt.datetime.now(dt.timezone.utc)


def iso(value):
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def bounded(value, maximum):
    return "".join(character for character in str(value) if character.isprintable())[:maximum]


def atomic_json(path, value, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    projection = _secure_projection(path)
    os.chmod(path.parent, 0o750 if path.parent in {SOCKET_PATH.parent, SECURITY_CONTEXT_RUNTIME_DIR} else 0o755)
    if projection:
        _chown_wheel(path.parent)
    descriptor, temporary = tempfile.mkstemp(prefix=".new-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o640 if projection else mode)
        if projection:
            _chown_wheel(temporary)
        os.replace(temporary, path)
        if projection:
            os.chmod(path, 0o640)
            _chown_wheel(path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

def default_policy():
    return {
        "default_action": "allow",
        "default_duration": "once",
        "interactive_prompts": False,
        "dns_policy": {"enforce": True, "ports": list(DNS_POLICY_PORTS)},
        "threat_intel": {"enabled": True, "provider": "feodo-recommended"},
        "rules": [],
    }


def load_policy():
    try:
        candidate = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default_policy()
    except (OSError, json.JSONDecodeError):
        return default_policy()
    if not isinstance(candidate, dict):
        return default_policy()
    action = candidate.get("default_action", "allow")
    duration = candidate.get("default_duration", "once")
    interactive_prompts = candidate.get("interactive_prompts", False)
    dns_policy = candidate.get("dns_policy", {"enforce": True, "ports": list(DNS_POLICY_PORTS)})
    threat_intel = candidate.get("threat_intel", {"enabled": True, "provider": "feodo-recommended"})
    rules = candidate.get("rules", [])
    if action not in ("allow", "deny", "reject") or duration not in ("once", "until restart", "always") or not isinstance(interactive_prompts, bool):
        return default_policy()
    if not isinstance(rules, list) or not isinstance(dns_policy, dict) or not isinstance(threat_intel, dict):
        return default_policy()
    if dns_policy.get("enforce", True) is not True or dns_policy.get("ports", list(DNS_POLICY_PORTS)) != list(DNS_POLICY_PORTS):
        return default_policy()
    if threat_intel.get("enabled", True) not in (True, False) or threat_intel.get("provider", "feodo-recommended") != "feodo-recommended":
        return default_policy()
    return {
        "default_action": action,
        "default_duration": duration,
        "interactive_prompts": interactive_prompts,
        "dns_policy": {"enforce": True, "ports": list(DNS_POLICY_PORTS)},
        "threat_intel": {"enabled": bool(threat_intel.get("enabled", True)), "provider": "feodo-recommended"},
        "rules": rules[:128],
    }


def _clean(value, maximum=160):
    return "".join(character for character in str(value or "") if character.isprintable())[:maximum]


def _application_name(path):
    value = _clean(path, 240)
    if not value:
        return "Unknown application"
    return Path(value).name or value


def _active_vpn_dns_addresses():
    """Return only DNS servers currently supplied by an active VPN device.

    This intentionally queries NetworkManager's observed device state instead
    of trusting a static provider list. A port-53 exception is therefore
    unavailable when no VPN is connected, and it cannot authorize arbitrary
    DNS destinations while a VPN is active.
    """
    def nmcli(arguments):
        return subprocess.run(
            ["nmcli", *arguments],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )

    try:
        devices = nmcli(["-t", "-f", "DEVICE,TYPE,STATE", "device", "status"])
    except (OSError, subprocess.SubprocessError):
        return set()
    if devices.returncode != 0:
        return set()

    addresses = set()
    for line in devices.stdout.splitlines():
        fields = line.split(":")
        if len(fields) < 3:
            continue
        device, device_type, state = fields[:3]
        # NetworkManager marks tunnel devices it did not create itself as
        # "connected (externally)".  They are still active VPN links and
        # their observed DNS must receive the same narrowly-scoped exception.
        if device_type.lower() not in VPN_DEVICE_TYPES or not state.lower().startswith("connected"):
            continue
        try:
            dns = nmcli(["-t", "-f", "IP4.DNS,IP6.DNS", "device", "show", device])
        except (OSError, subprocess.SubprocessError):
            continue
        if dns.returncode != 0:
            continue
        for dns_line in dns.stdout.splitlines():
            _field, separator, value = dns_line.partition(":")
            if not separator:
                continue
            for candidate in value.replace("\\:", ":").split(","):
                candidate = candidate.strip()
                try:
                    addresses.add(str(ipaddress.ip_address(candidate)))
                except ValueError:
                    continue
    return addresses


def _destination(connection):
    host = _clean(getattr(connection, "dst_host", ""), 160)
    address = _clean(getattr(connection, "dst_ip", ""), 64)
    country = country_resolution_for_destination(address, host)
    return {
        "host": host or None,
        "ip": address or None,
        "port": int(getattr(connection, "dst_port", 0) or 0),
        "country_code": country["country_code"] or None,
        "country_confidence": country["confidence"],
        "country_converged": country["converged"],
        "country_source_count": country["source_count"],
        "country_source": country["source"],
    }


def _decision(action):
    action = str(action or "").lower()
    if action == "allow":
        return "ALLOWED"
    if action in ("deny", "reject"):
        return "BLOCKED"
    return "UNKNOWN"


class NetworkState:
    """Bounded, redacted OpenSnitch state for the unprivileged user boundary."""

    def __init__(self):
        self.connected = False
        self.version = ""
        self.last_seen = None
        self.stats = {}
        self.rules = []
        self.activity = []
        self.activity_session_id = "network-" + uuid.uuid4().hex[:16]
        self.next_activity_sequence = 0
        self.activity_retained_at = {}

    @staticmethod
    def _same_connection(left, right):
        return (
            left.get("executable") == right.get("executable")
            and (left.get("destination") or {}).get("host") == (right.get("destination") or {}).get("host")
            and (left.get("destination") or {}).get("ip") == (right.get("destination") or {}).get("ip")
            and (left.get("destination") or {}).get("port") == (right.get("destination") or {}).get("port")
            and left.get("decision") == right.get("decision")
        )

    @staticmethod
    def _within_coalesce_window(left, right, seconds=15):
        try:
            left_time = dt.datetime.fromisoformat(str(left).replace("Z", "+00:00"))
            right_time = dt.datetime.fromisoformat(str(right).replace("Z", "+00:00"))
            return abs((left_time - right_time).total_seconds()) <= seconds
        except (TypeError, ValueError):
            return False

    def _record(self, connection, action="", source="opensnitch", occurred_at=None, rule_name="", threat=None):
        process_path = _clean(getattr(connection, "process_path", ""), 240)
        destination = _destination(connection)
        decision = _decision(action)
        timestamp = occurred_at or iso(now())
        identity = "|".join((process_path, destination["host"] or "", destination["ip"] or "", str(destination["port"]), decision, timestamp))
        event_id = "network-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
        inherited_threat = next((existing.get("threat") for existing in self.activity if self._same_connection(existing, {
            "executable": process_path,
            "destination": destination,
            "decision": decision,
        }) and existing.get("threat")), None)
        threat = threat or inherited_threat
        event = {
            "event_id": event_id,
            "occurred_at": timestamp,
            "application": _application_name(process_path),
            "executable": process_path or None,
            "destination": destination,
            "protocol": _clean(getattr(connection, "protocol", ""), 24).lower() or None,
            "decision": decision,
            "rule_name": _clean(rule_name, 160) or None,
            "source": source,
        }
        if isinstance(threat, dict):
            event["threat"] = {
                "provider": "feodo-recommended",
                "ip": destination["ip"],
                "port": destination["port"],
                "malware": _clean(threat.get("malware"), 96) or None,
                "indicator_id": _clean(threat.get("indicator_id"), 96) or None,
            }
        # AskRule gives immediate feedback while Ping statistics provide the
        # authoritative record. Replace the provisional record when the
        # daemon report arrives, and never show both for one connection.
        matching = [existing for existing in self.activity if self._same_connection(existing, event)]
        if matching:
            if source == "greyward-policy" and any(
                existing.get("source") == "opensnitch-statistics"
                and self._within_coalesce_window(timestamp, existing.get("occurred_at"))
                for existing in matching
            ):
                return
            if source == "opensnitch-statistics":
                self.activity = [existing for existing in self.activity if not (self._same_connection(existing, event) and existing.get("source") == "greyward-policy")]
        for existing in reversed(self.activity):
            if existing["event_id"] == event_id:
                return
        self._prune_activity()
        self.next_activity_sequence += 1
        event["sequence"] = self.next_activity_sequence
        self.activity.append(event)
        self.activity_retained_at[event_id] = now()
        self.activity = self.activity[-MAX_NETWORK_ACTIVITY:]
        self.activity_retained_at = {
            item["event_id"]: self.activity_retained_at[item["event_id"]]
            for item in self.activity
            if item["event_id"] in self.activity_retained_at
        }
        # The live buffer remains the fast UI working set.  Persist only the
        # approved redacted projection for historical investigation.
        telemetry_destination = {key: destination[key] for key in ("host", "ip", "port")}
        record_event(telemetry_event(
            event_id=event_id,
            occurred_at=timestamp,
            component="opensnitch-control-plane",
            source=source,
            category="NETWORK",
            event_type="CONNECTION_ATTEMPT",
            action="CONNECT",
            outcome=decision,
            severity="NOTICE" if decision == "BLOCKED" else "INFO",
            assessment="NOTEWORTHY" if decision == "BLOCKED" else "NORMAL",
            session_id=self.activity_session_id,
            application=event["application"],
            destination=telemetry_destination,
            protocol=event["protocol"],
            port=destination["port"],
            decision=decision,
            correlation={"session_id": self.activity_session_id},
            details={"rule_name": event["rule_name"], "network_event_type": "CONNECTION_ATTEMPT"},
            quality={"source_state": "AVAILABLE", "attribution": "EXACT" if process_path else "UNKNOWN", "confidence": "EXACT" if process_path else "UNKNOWN"},
            relations=[],
            retention_class="investigation",
        ))

    def _prune_activity(self):
        cutoff = now() - dt.timedelta(seconds=NETWORK_ACTIVITY_RETENTION_SECONDS)
        self.activity = [
            event for event in self.activity
            if self.activity_retained_at.get(event.get("event_id"), now()) >= cutoff
        ][-MAX_NETWORK_ACTIVITY:]
        self.activity_retained_at = {
            event["event_id"]: self.activity_retained_at[event["event_id"]]
            for event in self.activity
            if event.get("event_id") in self.activity_retained_at
        }

    def pinged(self, stats):
        self.connected = True
        self.version = _clean(getattr(stats, "daemon_version", ""), 32)
        self.last_seen = now()
        self.stats = {
            "connections": int(getattr(stats, "connections", 0) or 0),
            "accepted": int(getattr(stats, "accepted", 0) or 0),
            "dropped": int(getattr(stats, "dropped", 0) or 0),
            "rule_hits": int(getattr(stats, "rule_hits", 0) or 0),
            "rule_misses": int(getattr(stats, "rule_misses", 0) or 0),
            "rules": int(getattr(stats, "rules", 0) or 0),
        }
        for event in getattr(stats, "events", []):
            connection = getattr(event, "connection", None)
            if connection is None or not getattr(connection, "process_path", ""):
                continue
            rule = getattr(event, "rule", None)
            action = getattr(rule, "action", "") if rule is not None else ""
            occurred_at = _clean(getattr(event, "time", ""), 64) or iso(now())
            self._record(connection, action, "opensnitch-statistics", occurred_at, getattr(rule, "name", "") if rule else "")

    def subscribed(self, config):
        self.connected = True
        self.version = _clean(getattr(config, "version", ""), 32)
        self.last_seen = now()
        self.rules = [
            self._rule(rule, "GREYWARD_DAEMON" if str(getattr(rule, "name", "")).startswith("greyward-") else "OPENSNITCH")
            for rule in getattr(config, "rules", [])
        ]
        self.rules = [rule for rule in self.rules if rule is not None][-MAX_NETWORK_RULES:]

    def _rule(self, rule, source):
        name = _clean(getattr(rule, "name", ""), 160)
        action = str(getattr(rule, "action", "") or "").lower()
        if action not in ("allow", "deny", "reject"):
            return None
        operator = getattr(rule, "operator", None)
        operand = _clean(getattr(operator, "operand", "") if operator else "", 40)
        data = _clean(getattr(operator, "data", "") if operator else "", 240)
        scope = {"application": data if operand == "process.path" else None, "destination": None}
        if operand == "list" and operator is not None:
            destination = {"host": None, "ip": None, "port": None}
            for child in getattr(operator, "list", []):
                child_operand = _clean(getattr(child, "operand", ""), 40)
                child_data = _clean(getattr(child, "data", ""), 240)
                if child_operand == "process.path":
                    scope["application"] = child_data
                elif child_operand == "dest.host":
                    destination["host"] = child_data
                elif child_operand == "dest.ip":
                    destination["ip"] = child_data
                elif child_operand == "dest.port":
                    destination["port"] = int(child_data) if child_data.isdigit() else None
            scope["destination"] = destination if any(destination.values()) else None
        return {
            "id": "rule-" + hashlib.sha256((name or data or action).encode("utf-8")).hexdigest()[:20],
            "name": name or "Unnamed rule",
            "source": source,
            "action": "ALLOW" if action == "allow" else "BLOCK",
            "duration": _clean(getattr(rule, "duration", ""), 32).upper().replace(" ", "_"),
            "enabled": bool(getattr(rule, "enabled", True)),
            "scope": scope,
            "mutable": source == "GREYWARD",
        }

    def snapshot(self):
        self._prune_activity()
        current = now()
        if not self.connected or self.last_seen is None:
            state = "UNAVAILABLE"
            detail = "OpenSnitch application protection is unavailable."
        elif (current - self.last_seen).total_seconds() > NETWORK_STALE_SECONDS:
            state = "DEGRADED"
            detail = "OpenSnitch has not reported a fresh heartbeat. Recent activity may be stale."
        else:
            state = "OPERATING"
            detail = "OpenSnitch application interception is operating."
        apps = {}
        for event in self.activity:
            key = event["executable"] or event["application"]
            app = apps.setdefault(key, {"application": event["application"], "executable": event["executable"], "allowed": 0, "blocked": 0, "unknown": 0, "last_seen": event["occurred_at"], "destinations": []})
            decision_key = {"ALLOWED": "allowed", "BLOCKED": "blocked"}.get(event["decision"], "unknown")
            app[decision_key] += 1
            app["last_seen"] = max(app["last_seen"], event["occurred_at"])
            destination = event["destination"].get("host") or event["destination"].get("ip")
            if destination and destination not in app["destinations"]:
                app["destinations"].append(destination)
                app["destinations"] = app["destinations"][-8:]
        policy = load_policy()
        policy_rules = []
        for item in policy["rules"]:
            if not isinstance(item, dict) or not item.get("path"):
                continue
            action = item.get("action")
            if action not in ("allow", "deny", "reject"):
                continue
            policy_rules.append({
                "id": "greyward-" + hashlib.sha256(json.dumps(item, sort_keys=True).encode("utf-8")).hexdigest()[:20],
                "name": _clean(item.get("name") or f"GREYWARD {_application_name(item['path'])}", 160),
                "source": "GREYWARD",
                "action": "ALLOW" if action == "allow" else "BLOCK",
                "duration": _clean(item.get("duration", "always"), 32).upper().replace(" ", "_"),
                "enabled": True,
                "scope": {"application": _clean(item["path"], 240), "destination": {"host": _clean(item.get("host"), 160) or None, "ip": _clean(item.get("ip"), 64) or None, "port": int(item.get("port", 0) or 0)} if item.get("host") or item.get("ip") or item.get("port") else None},
                "mutable": True,
                "tier": item.get("tier", "GREYWARD"),
            })
        activity_summary = self.activity_summary()
        threat = threat_status(policy, self.activity)
        threat["exceptions"] = [
            item for item in policy_rules if item.get("tier") == "THREAT_EXCEPTION"
        ]
        capability_available = state == "OPERATING"
        return {
            "schema": "greyward.security.network/v1",
            "generated_at": iso(current),
            "fresh_until": iso(current + dt.timedelta(seconds=NETWORK_STALE_SECONDS)),
            "opensnitch": {
                "state": state,
                "detail": detail,
                "version": self.version or None,
                "last_seen": iso(self.last_seen) if self.last_seen else None,
                "stats": self.stats,
                "health": {
                    "state": "IDLE" if state == "OPERATING" and not self.activity else ("ACTIVE" if state == "OPERATING" else state),
                    "daemon": "ACTIVE" if self.connected else "INACTIVE",
                    "control_plane": "ACTIVE",
                    "event_stream": "EMPTY" if not self.activity else "OBSERVED",
                    "freshness": "FRESH" if state == "OPERATING" else "STALE",
                    "healthy": state == "OPERATING",
                    "detail": "Link ready; no application traffic has been observed yet." if state == "OPERATING" and not self.activity else detail,
                },
                "capabilities": {
                    "installed": True,
                    "activity": capability_available,
                    "rules": capability_available,
                    "rule_mutation": "TYPED_POLICY" if capability_available else "UNAVAILABLE",
                    "interactive_prompts": "DEFERRED",
                },
            },
            "applications": list(apps.values()),
            "activity": list(reversed(self.activity)),
            "activity_session_id": self.activity_session_id,
            "activity_next_sequence": self.next_activity_sequence,
            "activity_summary": activity_summary,
            "threat_intel": threat,
            "rules": (policy_rules + self.rules)[-MAX_NETWORK_RULES:],
        }

    def activity_summary(self):
        self._prune_activity()
        current = now().replace(second=0, microsecond=0)
        first_bucket = current - dt.timedelta(minutes=29)
        buckets = []
        for index in range(30):
            buckets.append({
                "started_at": iso(first_bucket + dt.timedelta(minutes=index)),
                "total": 0,
                "allowed": 0,
                "blocked": 0,
                "unknown": 0,
            })
        counts = {"total": 0, "allowed": 0, "blocked": 0, "unknown": 0}
        for event in self.activity:
            decision = event.get("decision", "UNKNOWN")
            key = {"ALLOWED": "allowed", "BLOCKED": "blocked"}.get(decision, "unknown")
            counts["total"] += 1
            counts[key] += 1
            retained_at = self.activity_retained_at.get(event.get("event_id"))
            if retained_at is None:
                continue
            bucket_index = int((retained_at.replace(second=0, microsecond=0) - first_bucket).total_seconds() // 60)
            if 0 <= bucket_index < len(buckets):
                buckets[bucket_index]["total"] += 1
                buckets[bucket_index][key] += 1
        counts["window_seconds"] = NETWORK_ACTIVITY_RETENTION_SECONDS
        counts["buckets"] = buckets
        return counts

    def activity_response(self, since_sequence=0, limit=256):
        self._prune_activity()
        snapshot = self.snapshot()
        try:
            since = max(0, int(since_sequence))
        except (TypeError, ValueError):
            since = 0
        try:
            limit = max(1, min(256, int(limit)))
        except (TypeError, ValueError):
            limit = 256
        ordered = list(self.activity)
        oldest = int(ordered[0].get("sequence", 0)) if ordered else 0
        reset = since == 0 or (oldest and since < oldest - 1)
        if reset:
            selected = list(reversed(ordered))[:limit]
        else:
            selected = [event for event in reversed(ordered) if int(event.get("sequence", 0)) > since][:limit]
        return {
            "schema": "greyward.security.network.activity/v1",
            "state": snapshot["opensnitch"]["state"],
            "detail": snapshot["opensnitch"]["detail"],
            "session_id": self.activity_session_id,
            "generated_at": snapshot["generated_at"],
            "fresh_until": snapshot["fresh_until"],
            "next_sequence": self.next_activity_sequence,
            "reset": reset,
            "summary": snapshot["activity_summary"],
            "rule_mutation": snapshot["opensnitch"]["capabilities"].get("rule_mutation", "UNAVAILABLE"),
            "events": selected,
        }

    def write(self):
        atomic_json(NETWORK_STATE_PATH, self.snapshot(), 0o640)


def select_policy_rule(connection):
    policy = load_policy()
    process_path = connection.process_path
    destination = _destination(connection)

    def matches(rule, exact_application=False):
        if not isinstance(rule, dict):
            return False
        if exact_application:
            return (
                rule.get("path") == process_path
                and rule.get("action") == "allow"
                and rule.get("ip") == destination["ip"]
                and int(rule.get("port", 0) or 0) == destination["port"]
                and bool(destination["ip"])
                and bool(destination["port"])
            )
        if rule.get("path") not in {process_path, "*"}:
            return False
        if rule.get("host") and rule.get("host") != destination["host"]:
            return False
        if rule.get("ip") and rule.get("ip") != destination["ip"]:
            return False
        if rule.get("port") and int(rule.get("port")) != destination["port"]:
            return False
        return True

    # Tier 1: only the dedicated Security Center false-positive action can
    # bypass a Feodo indicator. Ordinary application allow rules remain below
    # the threat tier and cannot silently weaken it.
    for rule in policy["rules"]:
        if isinstance(rule, dict) and rule.get("tier") == "THREAT_EXCEPTION" and matches(rule, exact_application=True):
            return "allow", "always", rule

    # Tier 2: exact Feodo IP+port match. The snapshot is GREYWARD-owned and
    # is read by the existing AskRule path; OpenSnitch still enforces it.
    threat_config = policy.get("threat_intel", {})
    indicator = matching_indicator(connection) if threat_config.get("enabled", True) is True else None
    if indicator:
        indicator["tier"] = "THREAT"
        indicator["path"] = "*"
        indicator["action"] = "deny"
        indicator["duration"] = "always"
        indicator["name"] = "GREYWARD Feodo known malicious C2"
        indicator["indicator_id"] = f"{indicator.get('ip')}:{indicator.get('port')}"
        return "deny", "always", indicator

    # Tier 3: existing GREYWARD rules, retaining their current matching
    # semantics and specificity without allowing them to outrank threats.
    candidates = sorted(
        (item for item in policy["rules"] if isinstance(item, dict) and item.get("tier") != "THREAT_EXCEPTION"),
        key=lambda item: (
            item.get("path") == process_path,
            bool(item.get("host") or item.get("ip") or item.get("port")),
            bool(item.get("path")),
        ),
        reverse=True,
    )
    for rule in candidates:
        if not matches(rule):
            continue
        action = rule.get("action")
        duration = rule.get("duration", "always")
        if action in ("allow", "deny", "reject") and duration in ("once", "until restart", "always"):
            return action, duration, rule
    dns_policy = policy.get("dns_policy", {})
    port = int(getattr(connection, "dst_port", 0) or 0)
    if dns_policy.get("enforce") is True and port in DNS_POLICY_PORTS:
        destination_ip = str(getattr(connection, "dst_ip", "") or "")
        if port == 53 and destination_ip in LOCAL_RESOLVER_ADDRESSES:
            # Applications talk to the local resolved stub; only
            # systemd-resolved is allowed to leave the machine for DNS.
            return "allow", "always", {"path": "*", "ip": destination_ip, "port": port, "name": "GREYWARD local resolver stub"}
        # systemd-resolved is the only built-in upstream client allowed to
        # reach the managed provider set. Applications must use the local
        # stub; their direct UDP/TCP DNS is denied unless an app rule above
        # explicitly grants a DNS bypass.
        if (
            process_path.endswith("/systemd-resolved")
            and port == 853
            and str(getattr(connection, "dst_ip", "")) in DNS_PROVIDER_ADDRESSES
        ):
            return "allow", "always", {"path": process_path, "port": port, "name": "GREYWARD managed resolver upstream"}
        if (
            process_path.endswith("/systemd-resolved")
            and port == 53
            and destination_ip in _active_vpn_dns_addresses()
        ):
            return "allow", "always", {"path": process_path, "ip": destination_ip, "port": port, "name": "GREYWARD active VPN resolver upstream"}
        return "deny", "always", {"path": "*", "port": port, "name": "GREYWARD deny direct DNS outside managed resolver"}
    return policy["default_action"], policy["default_duration"], None


class SecurityContextStore:
    def __init__(self):
        self.events = []
        self.network = NetworkState()
        self.daemon_connected = False
        self.daemon_version = ""
        self.last_seen = now()
        self.write()

    def write(self):
        timestamp = now()
        review_count = len(self.events)
        if review_count:
            live_states = [{
                "kind": "REVIEW NEEDED",
                "state": "REVIEW NEEDED",
                "detail": "OpenSnitch blocked one or more application connections.",
                "observed_at": iso(timestamp),
            }]
            state = "REVIEW NEEDED"
        else:
            live_states = [{
                "kind": "PROTECTED",
                "state": "SECURE" if self.daemon_connected else "UNAVAILABLE",
                "detail": "OpenSnitch control plane is connected." if self.daemon_connected else "OpenSnitch control plane has not connected.",
                "observed_at": iso(timestamp),
            }]
            state = "SECURE" if self.daemon_connected else "UNAVAILABLE"
        summary = {
            "schema": SCHEMA,
            "state": state,
            "generated_at": iso(timestamp),
            "fresh_until": iso(timestamp + dt.timedelta(minutes=2)),
            "review_count": review_count,
            "live_states": live_states,
            "recent_events": self.events[-MAX_EVENTS:],
        }
        atomic_json(STATE_PATH, summary, 0o640)
        self.network.write()

    def subscribed(self, config):
        self.daemon_connected = True
        self.daemon_version = bounded(config.version, 32)
        self.last_seen = now()
        self.network.subscribed(config)
        self.write()

    def pinged(self, stats):
        self.daemon_connected = True
        self.daemon_version = bounded(stats.daemon_version, 32)
        self.last_seen = now()
        self.network.pinged(stats)
        self.write()

    def blocked(self, connection, selected=None):
        destination = bounded(connection.dst_host or connection.dst_ip or "unknown destination", 160)
        process_path = bounded(connection.process_path or "unknown application", 160)
        event_key = "|".join((process_path, destination, str(connection.dst_port)))
        event_id = "opensnitch-" + hashlib.sha256(event_key.encode("utf-8")).hexdigest()[:24]
        occurred_at = iso(now())
        for event in reversed(self.events):
            if event["event_id"] == event_id:
                event["occurred_at"] = occurred_at
                break
        else:
            threat = selected if isinstance(selected, dict) and selected.get("tier") == "THREAT" else None
            event = {
                "event_id": event_id,
                "kind": "NETWORK_THREAT_BLOCKED" if threat else "APP_CONNECTION_BLOCKED",
                "notification": "AGGREGATABLE",
                "occurred_at": occurred_at,
                "title": "Application connection blocked",
                "detail": bounded(f"{process_path} was blocked from connecting to {destination}:{connection.dst_port}.", 320),
                "source": "opensnitch/v1.8.0",
            }
            if threat:
                event["threat"] = {"provider": "feodo-recommended", "ip": connection.dst_ip, "port": int(connection.dst_port), "malware": threat.get("malware"), "indicator_id": threat.get("indicator_id")}
            self.events.append(event)
            self.events = self.events[-MAX_EVENTS:]
        threat = selected if isinstance(selected, dict) and selected.get("tier") == "THREAT" else None
        self.network._record(connection, "deny", "greyward-policy", rule_name=threat.get("name", "") if threat else "", threat=threat)
        self.write()


class ControlPlane(ui_pb2_grpc.UIServicer):
    def __init__(self, store):
        self.store = store

    def Ping(self, request, context):
        self.store.pinged(request.stats)
        return ui_pb2.PingReply(id=request.id)

    def Subscribe(self, request, context):
        self.store.subscribed(request)
        return request

    def AskRule(self, request, context):
        action, duration, selected = select_policy_rule(request)
        if action in ("deny", "reject"):
            self.store.blocked(request, selected)
        else:
            self.store.network._record(request, action, "greyward-policy", rule_name=selected.get("name", "") if selected else "", threat=selected if selected and selected.get("tier") == "THREAT" else None)
            self.store.network.write()
        operators = []
        if selected and selected.get("path"):
            operators.append(ui_pb2.Operator(type="simple", operand="process.path", data=selected["path"]))
        if selected and selected.get("host"):
            operators.append(ui_pb2.Operator(type="simple", operand="dest.host", data=selected["host"]))
        if selected and selected.get("ip"):
            operators.append(ui_pb2.Operator(type="simple", operand="dest.ip", data=selected["ip"]))
        if selected and selected.get("port"):
            operators.append(ui_pb2.Operator(type="simple", operand="dest.port", data=str(selected["port"])))
        if len(operators) > 1:
            operator = ui_pb2.Operator(type="list", operand="list", list=operators)
        elif operators:
            operator = operators[0]
        else:
            operator = ui_pb2.Operator(type="simple", operand="true", data="")
        name_seed = json.dumps(selected or {"action": action}, sort_keys=True)
        digest = hashlib.sha256(name_seed.encode("utf-8")).hexdigest()[:12]
        # GREYWARD persistence lives in the validated policy file. Return a
        # one-shot daemon decision so removing that policy cannot leave an
        # independently persisted OpenSnitch rule behind.
        effective_duration = "once" if selected else duration
        return ui_pb2.Rule(
            name=f"greyward-{action}-{digest}",
            description="GREYWARD typed application-network decision",
            enabled=True,
            precedence=True,
            action=action,
            duration=effective_duration,
            operator=operator,
        )

    def Notifications(self, request_iterator, context):
        for _reply in request_iterator:
            self.store.write()
        return

    def PostAlert(self, request, context):
        return ui_pb2.MsgResponse(id=request.id)


def serve():
    if os.geteuid() != 0:
        raise SystemExit("greyward-opensnitch-control-plane must run as root")
    os.umask(0o077)
    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(SOCKET_PATH.parent, 0o750)
    try:
        mode = os.lstat(SOCKET_PATH).st_mode
        if stat.S_ISSOCK(mode):
            SOCKET_PATH.unlink()
        else:
            raise RuntimeError(f"refusing non-socket path: {SOCKET_PATH}")
    except FileNotFoundError:
        pass
    store = SecurityContextStore()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    ui_pb2_grpc.add_UIServicer_to_server(ControlPlane(store), server)
    if server.add_insecure_port("unix:" + str(SOCKET_PATH)) != 1:
        raise RuntimeError("unable to bind OpenSnitch control socket")
    server.start()
    os.chmod(SOCKET_PATH, 0o600)
    server.wait_for_termination()


def set_rule(arguments):
    if os.geteuid() != 0:
        raise SystemExit("root is required to change OpenSnitch policy")
    if not arguments.path.startswith("/") or "\x00" in arguments.path:
        raise SystemExit("an absolute application path is required")
    if arguments.port is not None and not 1 <= arguments.port <= 65535:
        raise SystemExit("destination port must be between 1 and 65535")
    policy = load_policy()
    def same_scope(rule):
        return (
            isinstance(rule, dict)
            and rule.get("path") == arguments.path
            and rule.get("host") == arguments.host
            and rule.get("ip") == arguments.ip
            and int(rule.get("port", 0) or 0) == int(arguments.port or 0)
            and rule.get("tier") != "THREAT_EXCEPTION"
        )
    rules = [rule for rule in policy["rules"] if not same_scope(rule)]
    rules.append({
        "path": arguments.path,
        "host": arguments.host,
        "ip": arguments.ip,
        "port": arguments.port,
        "action": arguments.action,
        "duration": arguments.duration,
        "name": arguments.name or f"GREYWARD {_application_name(arguments.path)}",
    })
    policy["rules"] = rules
    POLICY_PATH.parent.mkdir(parents=True, exist_ok=True)
    atomic_json(POLICY_PATH, policy, 0o600)


def remove_rule(arguments):
    if os.geteuid() != 0:
        raise SystemExit("root is required to change OpenSnitch policy")
    policy = load_policy()
    before = len(policy["rules"])
    policy["rules"] = [
        rule for rule in policy["rules"]
        if not isinstance(rule, dict)
        or not rule.get("path")
        or "greyward-" + hashlib.sha256(json.dumps(rule, sort_keys=True).encode("utf-8")).hexdigest()[:20] != arguments.rule_id
    ]
    if len(policy["rules"]) == before:
        raise SystemExit("GREYWARD rule was not found")
    atomic_json(POLICY_PATH, policy, 0o600)


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("serve")
    rule = commands.add_parser("set-rule")
    rule.add_argument("--path", required=True)
    rule.add_argument("--action", choices=("allow", "deny", "reject"), required=True)
    rule.add_argument("--duration", choices=("once", "until restart", "always"), default="always")
    rule.add_argument("--host")
    rule.add_argument("--ip")
    rule.add_argument("--port", type=int)
    rule.add_argument("--name")
    remove = commands.add_parser("remove-rule")
    remove.add_argument("--rule-id", required=True)
    arguments = parser.parse_args()
    if arguments.command == "serve":
        serve()
    elif arguments.command == "remove-rule":
        remove_rule(arguments)
    else:
        set_rule(arguments)


if __name__ == "__main__":
    main()
