#!/usr/bin/python3
"""Transactional per-link Secure DNS state reconciler.

NetworkManager remains the source of connection/VPN/split-DNS metadata. The
reconciler never writes a global resolver or edits NetworkManager profiles.
It mutates only one unambiguous non-VPN default link and restores a verified
snapshot before compatibility fallback.
"""
import datetime as dt
import ipaddress
import json
import os
import socket
import sys
from pathlib import Path

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

BUS_NAME = "systems.mantis.greyward.SecureDns1"
OBJECT_PATH = "/systems/mantis/greyward/SecureDns1"
POLICY_PATH = Path("/var/lib/greyward/secure-dns/policy.json")
STATE_PATH = Path("/run/greyward-secure-dns/state.json")
SNAPSHOT_PATH = Path("/run/greyward-secure-dns/managed-link.json")
READ_ONLY_MARKER = Path("/etc/greyward/secure-dns-read-only")
MODES = {"Automatic", "Privacy", "NetworkDefault"}
PROVIDER_ORDER = ("quad9", "controld", "adguard")
PROVIDERS = {
    "quad9": {
        "label": "Quad9",
        "sni": "dns.quad9.net",
        "addresses": ("9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"),
    },
    # Control D's public p2 endpoint is its Ads & Tracking profile. It is a
    # stable free endpoint and, unlike account profiles, needs no secret.
    "controld": {
        "label": "Control D",
        "sni": "p2.freedns.controld.com",
        "addresses": ("76.76.2.2", "76.76.10.2", "2606:1a40::2", "2606:1a40:1::2"),
    },
    "adguard": {
        "label": "AdGuard Public",
        "sni": "dns.adguard-dns.com",
        "addresses": ("94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"),
    },
}
DBUS_CALL_TIMEOUT = 8


def _stamp():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read(path, fallback):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else fallback
    except (OSError, json.JSONDecodeError):
        return fallback


def _write(path, value, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    os.chmod(temporary, mode)
    os.replace(temporary, path)


def _policy():
    value = _read(POLICY_PATH, {"desired_policy": "Automatic", "provider": "quad9", "provider_order": list(PROVIDER_ORDER), "custom": None})
    value["desired_policy"] = value.get("desired_policy") if value.get("desired_policy") in MODES else "Automatic"
    order = value.get("provider_order")
    if not isinstance(order, list):
        order = list(PROVIDER_ORDER)
    value["provider_order"] = [item for item in order if item in PROVIDERS]
    for item in PROVIDER_ORDER:
        if item not in value["provider_order"]:
            value["provider_order"].append(item)
    value["provider"] = value.get("provider") if value.get("provider") in PROVIDERS else value["provider_order"][0]
    return value


def _props(bus, service, path, interface):
    return dbus.Interface(bus.get_object(service, path), "org.freedesktop.DBus.Properties").GetAll(interface, timeout=DBUS_CALL_TIMEOUT)


def _active_devices(bus):
    manager = bus.get_object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager")
    devices = []
    for path in dbus.Interface(manager, "org.freedesktop.NetworkManager").GetDevices(timeout=DBUS_CALL_TIMEOUT):
        props = _props(bus, "org.freedesktop.NetworkManager", str(path), "org.freedesktop.NetworkManager.Device")
        if int(props.get("State", 0)) != 100:
            continue
        interface = str(props.get("Interface", ""))
        if not interface or interface == "lo":
            continue
        device_type = int(props.get("DeviceType", 0))
        devices.append({"interface": interface, "ifindex": socket.if_nametoindex(interface), "vpn": device_type == 53 or interface.startswith(("tun", "tap", "wg", "ppp"))})
    return devices


def _link(bus, ifindex):
    manager = bus.get_object("org.freedesktop.resolve1", "/org/freedesktop/resolve1")
    path = str(dbus.Interface(manager, "org.freedesktop.resolve1.Manager").GetLink(ifindex, timeout=DBUS_CALL_TIMEOUT))
    return _props(bus, "org.freedesktop.resolve1", path, "org.freedesktop.resolve1.Link")


def _domains(props):
    result = []
    for item in props.get("Domains", []):
        try:
            if len(item) == 2:
                result.append(str(item[0]))
        except (TypeError, ValueError):
            pass
    return result


def _server(props):
    current = props.get("CurrentDNSServerEx")
    try:
        family, address, port, name = current
        text = str(ipaddress.ip_address(bytes(address)))
        return {"address": text, "port": int(port), "name": str(name), "family": int(family)}
    except (TypeError, ValueError, OSError):
        return None


def _transport(props, vpn):
    if vpn:
        return "VPNProtected"
    value = str(props.get("DNSOverTLS", "")).lower()
    return "DoT" if value in {"yes", "true"} else "Plain"


def _mutation_enabled():
    return not READ_ONLY_MARKER.is_file()


def _resolved_link(bus, ifindex):
    manager = bus.get_object("org.freedesktop.resolve1", "/org/freedesktop/resolve1")
    path = str(dbus.Interface(manager, "org.freedesktop.resolve1.Manager").GetLink(ifindex))
    return path, _props(bus, "org.freedesktop.resolve1", path, "org.freedesktop.resolve1.Link")


def _dns_ex(props):
    result = []
    for item in props.get("DNSEx", []):
        try:
            if len(item) == 4:
                result.append([int(item[0]), [int(byte) for byte in item[1]], int(item[2]), str(item[3])])
        except (TypeError, ValueError):
            pass
    return result


def _provider_dns(provider):
    entries = []
    for text in provider["addresses"]:
        address = ipaddress.ip_address(text)
        entries.append((dbus.Int32(2 if address.version == 4 else 10), dbus.Array([dbus.Byte(byte) for byte in address.packed], signature="y"), dbus.UInt16(853), dbus.String(provider["sni"])))
    return dbus.Array(entries, signature="(iayqs)")


def _snapshot(ifindex, props):
    return {"ifindex": int(ifindex), "dns_ex": _dns_ex(props), "dns_over_tls": str(props.get("DNSOverTLS", "")), "dnssec": str(props.get("DNSSEC", "")), "default_route": bool(props.get("DefaultRoute", True)), "domains": []}


def _managed(props, provider):
    expected = {(2 if ipaddress.ip_address(address).version == 4 else 10, tuple(ipaddress.ip_address(address).packed), provider["sni"]) for address in provider["addresses"]}
    # resolve1 currently reports the DoT port as zero in DNSEx while the
    # DNSOverTLS property carries the transport policy, so the port is not a
    # stable ownership discriminator here.
    actual = {(int(item[0]), tuple(int(byte) for byte in item[1]), str(item[3])) for item in props.get("DNSEx", [])}
    return actual == expected and str(props.get("DNSOverTLS", "")).lower() in {"yes", "true"} and str(props.get("DNSSEC", "")).lower() in {"yes", "true"}


def _apply_link(bus, ifindex, provider):
    manager = dbus.Interface(bus.get_object("org.freedesktop.resolve1", "/org/freedesktop/resolve1"), "org.freedesktop.resolve1.Manager")
    manager.SetLinkDNSEx(ifindex, _provider_dns(provider), timeout=DBUS_CALL_TIMEOUT)
    manager.SetLinkDNSOverTLS(ifindex, "yes", timeout=DBUS_CALL_TIMEOUT)
    manager.SetLinkDNSSEC(ifindex, "yes", timeout=DBUS_CALL_TIMEOUT)


def _managed_provider(props):
    for key, provider in PROVIDERS.items():
        if _managed(props, provider):
            return key
    return None


def _restore_link(bus, snapshot, provider=None):
    if not snapshot or "ifindex" not in snapshot:
        return False
    path, current = _resolved_link(bus, int(snapshot["ifindex"]))
    if provider is not None and not _managed(current, provider):
        return False
    if provider is None and _managed_provider(current) is None:
        return False
    link = dbus.Interface(bus.get_object("org.freedesktop.resolve1", path), "org.freedesktop.resolve1.Link")
    dns = [(dbus.Int32(item[0]), dbus.Array([dbus.Byte(byte) for byte in item[1]], signature="y"), dbus.UInt16(item[2]), dbus.String(item[3])) for item in snapshot.get("dns_ex", [])]
    link.SetDNSEx(dbus.Array(dns, signature="(iayqs)"), timeout=DBUS_CALL_TIMEOUT)
    link.SetDNSOverTLS(str(snapshot.get("dns_over_tls", "")), timeout=DBUS_CALL_TIMEOUT)
    link.SetDNSSEC(str(snapshot.get("dnssec", "")), timeout=DBUS_CALL_TIMEOUT)
    link.SetDefaultRoute(bool(snapshot.get("default_route", True)), timeout=DBUS_CALL_TIMEOUT)
    return True


def _revert_managed_link(bus, ifindex, provider=None):
    path, current = _resolved_link(bus, int(ifindex))
    if provider is not None and not _managed(current, provider):
        return False
    if provider is None and _managed_provider(current) is None:
        return False
    dbus.Interface(bus.get_object("org.freedesktop.resolve1", path), "org.freedesktop.resolve1.Link").Revert(timeout=DBUS_CALL_TIMEOUT)
    return True


def _matches_provider(props, provider):
    server = _server(props)
    if not server:
        return False
    return server["name"] == provider["sni"] or server["address"] in provider["addresses"]


def _probe(bus, ifindex):
    _, props = _resolved_link(bus, ifindex)
    encrypted = str(props.get("DNSOverTLS", "")).lower() in {"yes", "true"}
    validated = str(props.get("DNSSEC", "")).lower() in {"yes", "true"}
    manager = dbus.Interface(bus.get_object("org.freedesktop.resolve1", "/org/freedesktop/resolve1"), "org.freedesktop.resolve1.Manager")
    try:
        manager.ResolveHostname(ifindex, "example.com", socket.AF_UNSPEC, dbus.UInt64(0), timeout=DBUS_CALL_TIMEOUT)
        return encrypted, validated, None
    except dbus.DBusException as error:
        return encrypted, validated, str(error.get_dbus_name() or error)[:160]


def _state():
    policy = _policy()
    desired = policy["desired_policy"]
    base = {"schema": "greyward.secure-dns/v1", "generated_at": _stamp(), "desired_policy": desired, "effective_policy": "Disconnected", "effective_owner": "None", "effective_transport": "None", "provider": policy["provider"], "provider_order": policy["provider_order"], "dns_enforcement": "MANAGED_DNS_PORTS", "encryption": "Unknown", "validation": "Unknown", "degradation_reason": "NoActiveLink", "link": None, "vpn_links": [], "route_domains": [], "resolver": None, "last_successful_reconciliation": None, "runtime_mutation": "ENABLED" if _mutation_enabled() else "DISABLED_READ_ONLY"}
    bus = dbus.SystemBus()
    devices = _active_devices(bus)
    if not devices:
        return base
    vpn = [item for item in devices if item["vpn"]]
    base["vpn_links"] = [item["interface"] for item in vpn]
    primary = vpn[0] if vpn else devices[0]
    base["link"] = primary["interface"]
    props = _link(bus, primary["ifindex"])
    base["route_domains"] = _domains(props)
    base["resolver"] = _server(props)
    if vpn:
        base.update({"effective_policy": "VPNOwned", "effective_owner": "VPN", "effective_transport": "VPNProtected", "encryption": "Enabled", "validation": "Measured by VPN/provider", "degradation_reason": None, "last_successful_reconciliation": _stamp()})
        return base
    provider_order = policy["provider_order"]
    provider = PROVIDERS[policy["provider"]]
    selected_provider = None
    snapshot = _read(SNAPSHOT_PATH, {})
    if _mutation_enabled() and desired == "NetworkDefault" and snapshot and int(snapshot.get("ifindex", -1)) == int(primary["ifindex"]):
        if _restore_link(bus, snapshot):
            try: SNAPSHOT_PATH.unlink()
            except FileNotFoundError: pass
            props = _link(bus, primary["ifindex"])
    if _mutation_enabled() and desired == "NetworkDefault" and _managed_provider(props):
        if _revert_managed_link(bus, primary["ifindex"]):
            try: SNAPSHOT_PATH.unlink()
            except FileNotFoundError: pass
            props = _link(bus, primary["ifindex"])
    mutation_error = None
    if _mutation_enabled() and desired in {"Automatic", "Privacy"} and not base["route_domains"] and len(devices) == 1:
        if not _managed_provider(props) and not snapshot:
            _write(SNAPSHOT_PATH, _snapshot(primary["ifindex"], props), 0o600)
        for provider_key in provider_order:
            candidate = PROVIDERS[provider_key]
            try:
                if not _managed(props, candidate):
                    _apply_link(bus, primary["ifindex"], candidate)
                    props = _link(bus, primary["ifindex"])
                encrypted, validated, probe_error = _probe(bus, primary["ifindex"])
                props = _link(bus, primary["ifindex"])
                if not probe_error and encrypted and validated and _matches_provider(props, candidate):
                    selected_provider = provider_key
                    provider = candidate
                    mutation_error = None
                    break
                mutation_error = probe_error or "ResolverValidationFailed"
            except (dbus.DBusException, OSError, ValueError, KeyError) as error:
                mutation_error = str(error)[:160]
        if selected_provider:
            base["provider"] = selected_provider
    encrypted = str(props.get("DNSOverTLS", "")).lower() in {"yes", "true"}
    validated = str(props.get("DNSSEC", "")).lower() in {"yes", "true"}
    base["resolver"] = _server(props)
    base["route_domains"] = _domains(props)
    if mutation_error and desired == "Automatic":
        restored = False
        try:
            snapshot_value = _read(SNAPSHOT_PATH, {})
            restored = _restore_link(bus, snapshot_value)
            if not restored:
                current_props = _link(bus, primary["ifindex"])
                if _managed_provider(current_props):
                    restored = _revert_managed_link(bus, primary["ifindex"])
        except (dbus.DBusException, OSError, ValueError, KeyError):
            restored = False
        if restored:
            try: SNAPSHOT_PATH.unlink()
            except FileNotFoundError: pass
        # The managed profile is fail-closed. Restoring the old link snapshot
        # prevents a stale GREYWARD override from surviving, while OpenSnitch's
        # DNS policy blocks direct plaintext/alternate DNS until a provider is
        # healthy again. We must not report this as a usable network fallback.
        base.update({"effective_policy": "Unavailable", "effective_owner": "None", "effective_transport": "None", "encryption": "Unavailable", "validation": "Unavailable", "degradation_reason": "AllProvidersUnavailable"})
    elif mutation_error:
        base.update({"effective_policy": "Unavailable", "effective_owner": "None", "effective_transport": "None", "encryption": "Unavailable", "validation": "Unavailable", "degradation_reason": "ResolverUnreachable"})
    elif desired == "NetworkDefault":
        base.update({"effective_policy": "NetworkDefault", "effective_owner": "Network", "effective_transport": _transport(props, False), "encryption": "Enabled" if encrypted else "Not guaranteed", "validation": "Enabled" if validated else "Not guaranteed", "degradation_reason": None if encrypted or validated else "NetworkDnsOnly", "last_successful_reconciliation": _stamp()})
    elif desired in {"Automatic", "Privacy"} and len(devices) > 1 and not base["route_domains"]:
        base.update({"effective_policy": "Unavailable", "effective_owner": "None", "effective_transport": "None", "encryption": "Unavailable", "validation": "Unavailable", "degradation_reason": "SplitDnsAmbiguous"})
    elif encrypted and validated and selected_provider and _matches_provider(props, provider):
        base.update({"effective_policy": "SecureProvider", "effective_owner": "Greyward", "effective_transport": "DoT", "encryption": "Enabled", "validation": "Enabled", "degradation_reason": None, "last_successful_reconciliation": _stamp()})
    elif desired == "Automatic":
        base.update({"effective_policy": "Unavailable", "effective_owner": "None", "effective_transport": "None", "encryption": "Unavailable", "validation": "Unavailable", "degradation_reason": "DoTUnavailable"})
    else:
        base.update({"effective_policy": "Unavailable", "effective_owner": "None", "effective_transport": "None", "encryption": "Unavailable", "validation": "Unavailable", "degradation_reason": "ResolverUnreachable"})
    return base


class SecureDnsService(dbus.service.Object):
    def __init__(self, bus):
        super().__init__(bus, OBJECT_PATH)
        self._refresh_source = None
        bus.add_signal_receiver(self._schedule_refresh, signal_name="StateChanged", dbus_interface="org.freedesktop.NetworkManager")
        bus.add_signal_receiver(self._schedule_refresh, signal_name="PropertiesChanged", dbus_interface="org.freedesktop.DBus.Properties")
        self.refresh()
        GLib.timeout_add_seconds(30, self.refresh)

    def _schedule_refresh(self, *args, **kwargs):
        if self._refresh_source is None:
            self._refresh_source = GLib.timeout_add(250, self._scheduled_refresh)

    def _scheduled_refresh(self):
        self._refresh_source = None
        self.refresh()
        return False

    def refresh(self):
        try:
            value = _state()
        except (dbus.DBusException, OSError, ValueError):
            value = {"schema": "greyward.secure-dns/v1", "generated_at": _stamp(), "desired_policy": _policy()["desired_policy"], "effective_policy": "Unavailable", "effective_owner": "None", "effective_transport": "None", "provider": _policy()["provider"], "encryption": "Unknown", "validation": "Unknown", "degradation_reason": "ResolverUnreachable", "runtime_mutation": "ENABLED" if _mutation_enabled() else "DISABLED_READ_ONLY"}
        _write(STATE_PATH, value, 0o644)
        self.state = value
        return True

    @dbus.service.method(BUS_NAME, in_signature="", out_signature="s")
    def GetState(self):
        self.refresh()
        return json.dumps(self.state, sort_keys=True, separators=(",", ":"))

    @dbus.service.method(BUS_NAME, in_signature="s", out_signature="s")
    def SetMode(self, mode):
        mode = str(mode)
        if mode not in MODES:
            return json.dumps({"ok": False, "state": "INVALID", "detail": "Unsupported Secure DNS mode."}, separators=(",", ":"))
        if not _mutation_enabled():
            self.refresh()
            return json.dumps({"ok": False, "state": "READ_ONLY", "detail": "Secure DNS configuration is read-only in this runtime; no change was saved.", "result": self.state}, sort_keys=True, separators=(",", ":"))
        value = _policy()
        value["desired_policy"] = mode
        _write(POLICY_PATH, value, 0o640)
        self.refresh()
        return json.dumps({"ok": True, "state": "SAVED", "result": self.state}, sort_keys=True, separators=(",", ":"))

    @dbus.service.method(BUS_NAME, in_signature="s", out_signature="s")
    def SetProvider(self, provider):
        provider = str(provider).lower()
        if provider not in PROVIDERS:
            return json.dumps({"ok": False, "state": "INVALID", "detail": "Unsupported Secure DNS provider."}, separators=(",", ":"))
        if not _mutation_enabled():
            self.refresh()
            return json.dumps({"ok": False, "state": "READ_ONLY", "detail": "Secure DNS configuration is read-only in this runtime; no change was saved.", "result": self.state}, sort_keys=True, separators=(",", ":"))
        value = _policy()
        value["provider"] = provider
        _write(POLICY_PATH, value, 0o640)
        self.refresh()
        return json.dumps({"ok": True, "state": "SAVED", "result": self.state}, sort_keys=True, separators=(",", ":"))

    @dbus.service.method(BUS_NAME, in_signature="", out_signature="s")
    def RetrySecureDns(self):
        self.refresh()
        return json.dumps({"ok": True, "state": "RETRIED", "result": self.state}, sort_keys=True, separators=(",", ":"))


def restore_runtime():
    snapshot = _read(SNAPSHOT_PATH, {})
    if not snapshot:
        return
    bus = dbus.SystemBus()
    restored = False
    try:
        restored = _restore_link(bus, snapshot)
        if not restored:
            restored = _revert_managed_link(bus, int(snapshot.get("ifindex", -1)))
    except (dbus.DBusException, OSError, ValueError, KeyError):
        restored = False
    if restored:
        try:
            SNAPSHOT_PATH.unlink()
        except FileNotFoundError:
            pass


def main():
    if os.geteuid() != 0:
        raise SystemExit("greyward-secure-dns must run as root")
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    if len(sys.argv) > 1 and sys.argv[1] == "--restore":
        restore_runtime()
        return
    bus = dbus.SystemBus()
    name = dbus.service.BusName(BUS_NAME, bus=bus)
    service = SecureDnsService(bus)
    GLib.MainLoop().run()


if __name__ == "__main__":
    main()
