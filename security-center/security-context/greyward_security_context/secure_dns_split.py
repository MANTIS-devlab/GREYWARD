"""Separate public and site-private DNS scopes inside the existing resolver.

Only one non-VPN link with explicit, non-root domains is eligible. DHCP DNS
and domains stay on that link. A reversible /run drop-in supplies the public
root scope; persistent administrator configuration is never edited.
"""
import os
import time
from pathlib import Path

import dbus

from greyward_security_context import secure_dns_reconciler as dns

CONFIG_PATH = Path("/run/systemd/resolved.conf.d/60-greyward-secure-dns.conf")
SNAPSHOT_PATH = Path("/run/greyward-secure-dns/private-link.json")
RESET_CONFIGURATION = "# Managed by greyward-secure-dns; scope removal in progress.\n[Resolve]\nDNS=\nDomains=\n"


def _configuration(provider):
    servers = []
    for address in provider["addresses"]:
        host = f"[{address}]" if ":" in address else address
        servers.append(f"{host}:853#{provider['sni']}")
    return ("# Managed by greyward-secure-dns; runtime public scope only.\n"
            "[Resolve]\nDNS=\nDNS=" + " ".join(servers) +
            "\nDomains=\nDomains=~.\nFallbackDNS=\nDNSOverTLS=yes\nDNSSEC=yes\n")


def _owned_configuration():
    if CONFIG_PATH.is_symlink():
        raise ValueError("Secure DNS runtime configuration is a symlink")
    if not CONFIG_PATH.exists():
        return None
    text = CONFIG_PATH.read_text(encoding="utf-8")
    if text == RESET_CONFIGURATION:
        return 'reset'
    for key, provider in dns.PROVIDERS.items():
        if text == _configuration(provider):
            return key
    raise ValueError("Secure DNS runtime configuration has a foreign owner")


def _global(bus):
    props = dns._props(bus, "org.freedesktop.resolve1", "/org/freedesktop/resolve1",
                       "org.freedesktop.resolve1.Manager")
    value = dict(props)
    value["DNSEx"] = [item[1:] for item in props.get("DNSEx", []) if int(item[0]) == 0]
    value["Domains"] = [item[1:] for item in props.get("Domains", []) if int(item[0]) == 0]
    current = props.get("CurrentDNSServerEx", ())
    value["CurrentDNSServerEx"] = current[1:] if len(current) == 5 and int(current[0]) == 0 else ()
    return value


def _reload(bus):
    # systemd >= 256 reloads resolved's configuration on SIGHUP. This fixed
    # unit/signal operation needs neither network capabilities nor a restart.
    manager = dbus.Interface(bus.get_object("org.freedesktop.systemd1", "/org/freedesktop/systemd1"),
                             "org.freedesktop.systemd1.Manager")
    manager.KillUnit("systemd-resolved.service", "main", 1, timeout=dns.DBUS_CALL_TIMEOUT)


def _write_configuration(text):
    temporary = CONFIG_PATH.with_suffix('.tmp')
    if temporary.is_symlink():
        raise ValueError('Secure DNS temporary configuration is a symlink')
    temporary.write_text(text, encoding='utf-8')
    os.chmod(temporary, 0o644)
    os.replace(temporary, CONFIG_PATH)


def _same_link(props, snapshot):
    return (dns._dns_ex(props) == snapshot.get("dns_ex") and
            [[str(item[0]), bool(item[1])] for item in props.get("Domains", [])] == snapshot.get("domains"))


def restore(bus):
    """Remove only our public scope and restore only a still-matching link."""
    snapshot = dns._read(SNAPSHOT_PATH, {})
    if _owned_configuration():
        # SIGHUP does not clear an omitted Domains= assignment. Explicitly
        # empty our scope first; retaining this known marker permits retry
        # after a failed reload instead of leaving an orphaned root route.
        _write_configuration(RESET_CONFIGURATION)
        _reload(bus)
        deadline = time.monotonic() + dns.DBUS_CALL_TIMEOUT
        while True:
            current = _global(bus)
            if not current['DNSEx'] and not current['Domains']:
                break
            if time.monotonic() >= deadline:
                raise ValueError('Secure DNS scope removal was not observed')
            time.sleep(0.05)
        CONFIG_PATH.unlink()
        _reload(bus)
    if snapshot:
        try:
            _, current = dns._resolved_link(bus, int(snapshot["ifindex"]))
        except dbus.DBusException as error:
            if error.get_dbus_name() != 'org.freedesktop.resolve1.NoSuchLink':
                raise
            SNAPSHOT_PATH.unlink(missing_ok=True)
            return
        if (_same_link(current, snapshot) and not bool(current.get("DefaultRoute", True)) and
                str(current.get("DNSOverTLS", "")) == (snapshot["dns_over_tls"] or "no") and
                str(current.get("DNSSEC", "")) == (snapshot["dnssec"] or "no")):
            manager = dbus.Interface(bus.get_object("org.freedesktop.resolve1", "/org/freedesktop/resolve1"),
                                     "org.freedesktop.resolve1.Manager")
            manager.SetLinkDefaultRoute(snapshot["ifindex"], snapshot["default_route"], timeout=dns.DBUS_CALL_TIMEOUT)
            manager.SetLinkDNSOverTLS(snapshot["ifindex"], snapshot["dns_over_tls"], timeout=dns.DBUS_CALL_TIMEOUT)
            manager.SetLinkDNSSEC(snapshot["ifindex"], snapshot["dnssec"], timeout=dns.DBUS_CALL_TIMEOUT)
        SNAPSHOT_PATH.unlink(missing_ok=True)


def active_private_addresses(bus):
    """Authorize resolved only, to the observed private scope's exact servers."""
    snapshot = dns._read(SNAPSHOT_PATH, {})
    owner = _owned_configuration()
    if not snapshot or owner not in dns.PROVIDERS:
        return set()
    _, props = dns._resolved_link(bus, int(snapshot["ifindex"]))
    global_props = _global(bus)
    if (not _same_link(props, snapshot) or bool(props.get("DefaultRoute", True)) or
            not dns._managed(global_props, dns.PROVIDERS[owner]) or
            list(global_props["Domains"]) != [(".", True)] or not snapshot.get("domains") or
            any(item[0] == "." for item in snapshot["domains"])):
        return set()
    return {str(dns.ipaddress.ip_address(bytes(item[1]))) for item in snapshot["dns_ex"]}


def reconcile(bus, device, props, base, policy):
    if _owned_configuration() == 'reset':
        restore(bus)
        props = dns._link(bus, device['ifindex'])
    snapshot = dns._read(SNAPSHOT_PATH, {})
    if snapshot and (int(snapshot["ifindex"]) != device["ifindex"] or not _same_link(props, snapshot)):
        restore(bus)
        snapshot = {}
        props = dns._link(bus, device["ifindex"])
    owner = _owned_configuration()
    global_props = _global(bus)
    if not owner and (global_props["DNSEx"] or global_props["Domains"]):
        base.update(effective_policy="Unavailable", degradation_reason="SplitDnsAmbiguous")
        return base
    if not snapshot:
        snapshot = dns._snapshot(device["ifindex"], props)
        snapshot["domains"] = [[str(item[0]), bool(item[1])] for item in props.get("Domains", [])]
        dns._write(SNAPSHOT_PATH, snapshot, 0o600)
    manager = dbus.Interface(bus.get_object("org.freedesktop.resolve1", "/org/freedesktop/resolve1"),
                             "org.freedesktop.resolve1.Manager")
    # Empty modes inherit the global setting. Pin the original effective
    # private policy before introducing the strict public scope.
    if str(props.get("DNSOverTLS", "")) != (snapshot["dns_over_tls"] or "no"):
        manager.SetLinkDNSOverTLS(device["ifindex"], snapshot["dns_over_tls"] or "no", timeout=dns.DBUS_CALL_TIMEOUT)
    if str(props.get("DNSSEC", "")) != (snapshot["dnssec"] or "no"):
        manager.SetLinkDNSSEC(device["ifindex"], snapshot["dnssec"] or "no", timeout=dns.DBUS_CALL_TIMEOUT)
    if bool(props.get("DefaultRoute", True)):
        manager.SetLinkDefaultRoute(device["ifindex"], False, timeout=dns.DBUS_CALL_TIMEOUT)
    base.update(public_scope="system", private_resolvers=[str(dns.ipaddress.ip_address(bytes(item[1]))) for item in snapshot["dns_ex"]])
    for key in policy["provider_order"]:
        provider = dns.PROVIDERS[key]
        if owner != key or not dns._managed(_global(bus), provider):
            _write_configuration(_configuration(provider))
            _reload(bus)
            owner = key
        deadline = time.monotonic() + dns.DBUS_CALL_TIMEOUT
        while not dns._managed(_global(bus), provider):
            if time.monotonic() >= deadline:
                raise ValueError("Secure DNS public scope reload was not observed")
            time.sleep(0.05)
        encrypted, validated, error = dns._probe(bus, 0)
        current = _global(bus)
        base.update(resolver=dns._server(current), provider=key)
        private_props = dns._link(bus, device["ifindex"])
        if (not error and encrypted and validated and dns._matches_provider(current, provider) and
                list(current["Domains"]) == [(".", True)] and _same_link(private_props, snapshot) and
                not bool(private_props.get("DefaultRoute", True))):
            base.update(effective_policy="SecureProvider", effective_owner="Greyward", effective_transport="DoT",
                        encryption="Enabled", validation="Enabled", degradation_reason=None,
                        last_successful_reconciliation=dns._stamp())
            return base
    # Keep the strict public scope on failure: private DNS must never become
    # an unadvertised fallback for public names.
    base.update(effective_policy="Unavailable", effective_owner="None", effective_transport="None",
                encryption="Unavailable", validation="Unavailable", degradation_reason="AllProvidersUnavailable")
    return base
