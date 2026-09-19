#!/usr/bin/python3
"""Root-owned, typed OpenSnitch policy boundary for Security Context."""
import hashlib
import ipaddress
import json
import os
import re

import dbus
import dbus.mainloop.glib
import dbus.service

from greyward_security_context.control_plane import POLICY_PATH, atomic_json, load_policy, _application_name

BUS_NAME = "systems.mantis.greyward.OpenSnitchPolicy1"
OBJECT_PATH = "/systems/mantis/greyward/OpenSnitchPolicy1"


def _rule_id(rule):
    return "greyward-" + hashlib.sha256(json.dumps(rule, sort_keys=True).encode("utf-8")).hexdigest()[:20]


def validate(value):
    if not isinstance(value, dict):
        raise ValueError("A typed network rule is required.")
    path = str(value.get("application") or "")
    action = str(value.get("action") or "").lower()
    duration = str(value.get("duration") or "always").lower()
    if not path.startswith("/") or "\x00" in path or len(path) > 240:
        raise ValueError("A valid absolute application path is required.")
    if action not in {"allow", "block", "deny", "reject"}:
        raise ValueError("Unsupported network action.")
    if duration not in {"once", "until_restart", "until restart", "always"}:
        raise ValueError("Unsupported network duration.")
    destination = value.get("destination") or {}
    if not isinstance(destination, dict):
        raise ValueError("Destination scope is invalid.")
    host = str(destination.get("host") or "").strip().lower()
    address = str(destination.get("ip") or "").strip()
    port = destination.get("port")
    if host and (len(host) > 160 or not re.fullmatch(r"[a-z0-9._-]+", host)):
        raise ValueError("Destination domain is invalid.")
    if address:
        try:
            ipaddress.ip_address(address)
        except ValueError as error:
            raise ValueError("Destination IP is invalid.") from error
    if port not in (None, "", 0):
        try:
            port = int(port)
        except (TypeError, ValueError) as error:
            raise ValueError("Destination port is invalid.") from error
        if not 1 <= port <= 65535:
            raise ValueError("Destination port must be between 1 and 65535.")
    else:
        port = None
    return {
        "path": path,
        "host": host or None,
        "ip": address or None,
        "port": port,
        "action": "allow" if action == "allow" else "deny",
        "duration": "until restart" if duration in {"until_restart", "until restart"} else duration,
        "name": str(value.get("name") or f"GREYWARD {_application_name(path)}")[:160],
    }


def validate_threat_exception(value):
    item = validate(value)
    destination = value.get("destination") or {}
    if item["action"] != "allow" or item["duration"] != "always":
        raise ValueError("A Feodo exception must permanently allow the selected application scope.")
    if item["host"] or not item["ip"] or not item["port"]:
        raise ValueError("A Feodo exception requires only an exact IP and port.")
    item["tier"] = "THREAT_EXCEPTION"
    item["name"] = "GREYWARD Feodo false-positive exception"
    return item


def set_rule(value):
    item = validate(value)
    policy = load_policy()
    rules = [
        rule for rule in policy["rules"]
        if not (
            isinstance(rule, dict)
            and rule.get("path") == item["path"]
            and rule.get("host") == item["host"]
            and rule.get("ip") == item["ip"]
            and int(rule.get("port", 0) or 0) == int(item["port"] or 0)
            and rule.get("tier") != "THREAT_EXCEPTION"
        )
    ]
    rules.append(item)
    policy["rules"] = rules[-128:]
    POLICY_PATH.parent.mkdir(parents=True, exist_ok=True)
    atomic_json(POLICY_PATH, policy, 0o600)
    result = {"ok": True, "state": "SAVED", "rule_id": _rule_id(item), "detail": "The typed GREYWARD rule was saved for future matching connections."}
    return result


def set_threat_exception(value):
    item = validate_threat_exception(value)
    policy = load_policy()
    rules = [
        rule for rule in policy["rules"]
        if not (
            isinstance(rule, dict)
            and rule.get("tier") == "THREAT_EXCEPTION"
            and rule.get("path") == item["path"]
            and rule.get("ip") == item["ip"]
            and int(rule.get("port", 0) or 0) == int(item["port"] or 0)
        )
    ]
    rules.append(item)
    policy["rules"] = rules[-128:]
    POLICY_PATH.parent.mkdir(parents=True, exist_ok=True)
    atomic_json(POLICY_PATH, policy, 0o600)
    result = {"ok": True, "state": "SAVED", "rule_id": _rule_id(item), "detail": "The narrow GREYWARD Feodo exception was saved."}
    return result


def set_threat_intel_enabled(value):
    if not isinstance(value, bool):
        raise ValueError("Threat protection enablement must be boolean.")
    policy = load_policy()
    policy["threat_intel"] = {"enabled": value, "provider": "feodo-recommended"}
    POLICY_PATH.parent.mkdir(parents=True, exist_ok=True)
    atomic_json(POLICY_PATH, policy, 0o600)
    return {"ok": True, "state": "ENABLED" if value else "DISABLED", "enabled": value, "detail": "Feodo threat blocking setting updated."}


def remove_rule(rule_id):
    if not isinstance(rule_id, str) or not re.fullmatch(r"greyward-[a-f0-9]{20}", rule_id):
        raise ValueError("Only a GREYWARD-owned rule can be removed.")
    policy = load_policy()
    rules = [rule for rule in policy["rules"] if not (isinstance(rule, dict) and _rule_id(rule) == rule_id)]
    if len(rules) == len(policy["rules"]):
        raise ValueError("GREYWARD rule was not found.")
    policy["rules"] = rules
    atomic_json(POLICY_PATH, policy, 0o600)
    return {"ok": True, "state": "REMOVED", "rule_id": rule_id, "detail": "The GREYWARD rule was removed for future matching connections."}


def list_rules():
    rules = []
    for item in load_policy()["rules"]:
        if not isinstance(item, dict) or not item.get("path"):
            continue
        rules.append({
            "id": _rule_id(item), "name": item.get("name") or f"GREYWARD {_application_name(item['path'])}",
            "action": "ALLOW" if item.get("action") == "allow" else "DENY",
            "duration": str(item.get("duration") or "always").upper().replace(" ", "_"),
            "scope": {"application": item["path"], "destination": {"host": item.get("host"), "ip": item.get("ip"), "port": item.get("port")} if any(item.get(key) for key in ("host", "ip", "port")) else None},
            "source": "GREYWARD", "mutable": True, "enabled": True,
            "tier": item.get("tier", "GREYWARD"),
        })
    return {"ok": True, "rules": rules}


class OpenSnitchPolicy(dbus.service.Object):
    def __init__(self, bus):
        super().__init__(bus, OBJECT_PATH)

    @dbus.service.method(BUS_NAME, in_signature="s", out_signature="s")
    def SetRule(self, payload):
        try:
            return json.dumps(set_rule(json.loads(payload)), separators=(",", ":"))
        except (ValueError, json.JSONDecodeError, OSError) as error:
            return json.dumps({"ok": False, "state": "REFUSED", "detail": str(error)[:240]}, separators=(",", ":"))

    @dbus.service.method(BUS_NAME, in_signature="s", out_signature="s")
    def SetThreatException(self, payload):
        try:
            return json.dumps(set_threat_exception(json.loads(payload)), separators=(",", ":"))
        except (ValueError, json.JSONDecodeError, OSError) as error:
            return json.dumps({"ok": False, "state": "REFUSED", "detail": str(error)[:240]}, separators=(",", ":"))

    @dbus.service.method(BUS_NAME, in_signature="s", out_signature="s")
    def SetThreatIntelEnabled(self, payload):
        try:
            value = json.loads(payload)
            return json.dumps(set_threat_intel_enabled(value), separators=(",", ":"))
        except (ValueError, json.JSONDecodeError, OSError) as error:
            return json.dumps({"ok": False, "state": "REFUSED", "detail": str(error)[:240]}, separators=(",", ":"))

    @dbus.service.method(BUS_NAME, in_signature="s", out_signature="s")
    def RemoveRule(self, rule_id):
        try:
            return json.dumps(remove_rule(rule_id), separators=(",", ":"))
        except (ValueError, OSError) as error:
            return json.dumps({"ok": False, "state": "REFUSED", "detail": str(error)[:240]}, separators=(",", ":"))

    @dbus.service.method(BUS_NAME, in_signature="", out_signature="s")
    def ListRules(self):
        try:
            return json.dumps(list_rules(), separators=(",", ":"))
        except OSError as error:
            return json.dumps({"ok": False, "rules": [], "detail": str(error)[:240]}, separators=(",", ":"))


def main():
    if os.geteuid() != 0:
        raise SystemExit("greyward-opensnitch-policy must run as root")
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    name = dbus.service.BusName(BUS_NAME, bus=bus)
    OpenSnitchPolicy(bus)
    from gi.repository import GLib
    GLib.MainLoop().run()


if __name__ == "__main__":
    main()
