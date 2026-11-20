"""Import selected, trusted incoming connection records into Network Activity."""

import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import uuid
from functools import lru_cache
from pathlib import Path

from .telemetry import INBOUND_SPOOL_PATH, event, spool_event, stamp
from .network_flows import flow_key

FIREWALL = "firewalld"
SSH = "sshd"
INBOUND_SOURCES = (FIREWALL, SSH)
MAX_READ = 4096
MAX_EXPORT_PER_SOURCE = 96
RECOVERY_MINUTES = 10
SSH_RECOVERY_MINUTES = 60
MAX_LISTENER_RECORDS = 1024
FIREWALL_RETRY_SECONDS = 30
DENIAL = re.compile(r"(FINAL_REJECT|STATE_INVALID_DROP|rpfilter_DROP|filter_[\w.-]{1,80}_(?:DROP|REJECT)):\s+")
SSH_ACCEPTED = re.compile(r"Accepted (?:publickey|password|keyboard-interactive(?:/pam)?|gssapi-with-mic|hostbased) for \S+ from (\S+) port ([0-9]{1,5}) ssh2(?:[: ]|$)")
SSH_LISTENING = re.compile(r"Server listening on \S+ port ([0-9]{1,5})\.")
PACKET_FIELD = re.compile(r"(?:^|\s)(IN|OUT|SRC|DST|PROTO|SPT|DPT)=([^\s]*)")


def _address(value):
    try:
        address = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return None
    if address.is_unspecified or address.is_multicast:
        return None
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address.compressed


def _port(value):
    return int(value) if isinstance(value, str) and re.fullmatch(r"[0-9]{1,5}", value) and 0 < int(value) <= 65535 else None


def _id(source, *fields):
    digest = hashlib.sha256(json.dumps(fields, separators=(",", ":")).encode()).hexdigest()[:32]
    return f"inbound-{source}-{digest}"


def _journal_event(entry, **fields):
    value = event(**fields)
    try:
        value["boot_id"] = str(uuid.UUID(str(entry.get("_BOOT_ID"))))
    except ValueError:
        value["boot_id"] = None
    return value


def classify(entry):
    when = entry.get("__REALTIME_TIMESTAMP")
    cursor = entry.get("__CURSOR")
    message = entry.get("MESSAGE")
    if not isinstance(when, dt.datetime) or not isinstance(cursor, str) or not isinstance(message, str) or len(message) > 4096:
        return None
    if entry.get("_SYSTEMD_UNIT") == "sshd.service" and entry.get("_COMM") in {"sshd", "sshd-session"}:
        match = SSH_ACCEPTED.match(message)
        if not match:
            return None
        peer, peer_port = _address(match[1]), _port(match[2])
        if not peer or peer_port is None:
            return None
        return _journal_event(entry,
            event_id=_id(SSH, cursor), occurred_at=stamp(when), component="inbound-network",
            source=SSH, category="NETWORK", event_type="SSH_SESSION_ACCEPTED",
            action="AUTHENTICATE", outcome="ALLOWED", decision="ALLOWED",
            application="SSH", destination={"ip": peer}, protocol="tcp",
            details={"peer_port": peer_port},
        )

    if entry.get("_TRANSPORT") != "kernel":
        return None
    match = DENIAL.match(message)
    if not match:
        return None
    packet = dict(PACKET_FIELD.findall(message[match.end():]))
    incoming, outgoing = packet.get("IN"), packet.get("OUT")
    if incoming is None or outgoing is None or not (incoming or outgoing):
        return None
    direction = "LOCAL" if "lo" in (incoming,outgoing) else "FORWARDED" if incoming and outgoing else "INBOUND" if incoming else "OUTBOUND"
    origin, target = _address(packet.get("SRC")), _address(packet.get("DST"))
    peer = origin if direction == "INBOUND" else target
    local = target if direction == "INBOUND" else origin if direction == "OUTBOUND" else None
    protocol = str(packet.get("PROTO", "")).lower()
    if protocol in {"ipv6-icmp", "icmp6"}:
        protocol = "icmpv6"
    peer_port, local_port = _port(packet.get("SPT")), _port(packet.get("DPT"))
    if not origin or not target or protocol not in {"tcp", "udp", "icmp", "icmpv6"}:
        return None
    if protocol in {"tcp", "udp"} and (peer_port is None or local_port is None):
        return None
    window = int(when.timestamp()) // FIREWALL_RETRY_SECONDS
    return _journal_event(entry,
        event_id=_id(FIREWALL, str(entry.get("_BOOT_ID", "")), origin, peer_port, target, local_port, protocol, window),
        occurred_at=stamp(when), component="inbound-network", source=FIREWALL,
        category="NETWORK", event_type="FIREWALL_DENIAL",
        action="FILTER", outcome="BLOCKED", decision="BLOCKED", severity="NOTICE",
        assessment="NOTEWORTHY", application="firewalld", protocol=protocol, port=local_port,
        destination={"ip": peer, "port": local_port},
        details={"peer_port": peer_port if direction == "INBOUND" else local_port, "local_ip": local,
                 "interface": incoming or outgoing, "rule_name": match[1], "direction": direction,
                 "origin_ip": origin, "origin_port": peer_port, "target_ip": target, "target_port": local_port,
                 "flow_key": flow_key(protocol, origin, peer_port, target, local_port)},
    )


def _ssh_invocation(entry):
    try:
        return uuid.UUID(str(entry.get("_SYSTEMD_INVOCATION_ID"))).hex
    except ValueError:
        return None


def ssh_listener_port(entries, invocation, accepted_at):
    """Use a single journaled port from the same service invocation."""
    ports = set()
    for index, entry in enumerate(entries):
        if index >= MAX_LISTENER_RECORDS:
            return None
        when = entry.get("__REALTIME_TIMESTAMP")
        if (entry.get("_SYSTEMD_UNIT") != "sshd.service" or entry.get("_COMM") != "sshd"
                or _ssh_invocation(entry) != invocation
                or not isinstance(when, dt.datetime) or when > accepted_at):
            continue
        message = entry.get("MESSAGE")
        match = SSH_LISTENING.fullmatch(message) if isinstance(message, str) else None
        port = _port(match[1]) if match else None
        if port is not None:
            ports.add(port)
    return next(iter(ports)) if len(ports) == 1 else None


def ingest(reader, checkpoint, publish=spool_event, *, resolve_ssh_port=None, recovery_minutes=RECOVERY_MINUTES):
    try:
        saved = checkpoint.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        saved = ""
    except UnicodeError:
        saved = ""
    if saved and len(saved) < 1024:
        try:
            reader.seek_cursor(saved)
            entry = reader.get_next()
            found = entry.get("__CURSOR") == saved
        except (ValueError, OSError):
            found = False
    else:
        found = False
    if not found:
        reader.seek_realtime(dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=recovery_minutes))

    exported = {source: 0 for source in INBOUND_SOURCES}
    dropped = 0
    seen = set()
    last = None
    for _ in range(MAX_READ):
        entry = reader.get_next()
        if not entry:
            break
        value = classify(entry)
        if value and value["event_id"] not in seen:
            source = value["source"]
            if source == SSH and resolve_ssh_port:
                port = resolve_ssh_port(entry)
                if port is not None:
                    value["port"] = port
                    value["destination"]["port"] = port
                    value["details"]["port_evidence"] = "sshd-listener"
            if exported[source] >= MAX_EXPORT_PER_SOURCE:
                # Keep the last processed cursor for authenticated sessions.
                # The next batch picks up this session without a gap.
                if source == SSH:
                    break
                dropped += 1
            elif not publish(value, INBOUND_SPOOL_PATH):
                raise OSError("Inbound telemetry handoff is unavailable")
            else:
                exported[source] += 1
            seen.add(value["event_id"])
        last = entry.get("__CURSOR")
    if last:
        candidate = checkpoint.with_suffix(".tmp")
        candidate.write_text(last + "\n", encoding="ascii")
        os.replace(candidate, checkpoint)
    return exported, dropped


def main():
    from systemd import journal

    state = Path(os.environ["RUNTIME_DIRECTORY"])
    flags = journal.LOCAL_ONLY | journal.SYSTEM

    @lru_cache(maxsize=8)
    def listener_entries(invocation):
        with journal.Reader(flags=flags) as reader:
            reader.add_match(_SYSTEMD_UNIT="sshd.service", _COMM="sshd", _SYSTEMD_INVOCATION_ID=invocation)
            reader.seek_head()
            return tuple(entry for _, entry in zip(range(MAX_LISTENER_RECORDS + 1), reader))

    def lookup(entry):
        invocation = _ssh_invocation(entry)
        if not invocation:
            return None
        return ssh_listener_port(listener_entries(invocation), invocation, entry["__REALTIME_TIMESTAMP"])

    for source, match in ((SSH, {"_SYSTEMD_UNIT": "sshd.service"}), (FIREWALL, {"_TRANSPORT": "kernel"})):
        with journal.Reader(flags=flags) as reader:
            reader.add_match(**match)
            if source == SSH:
                _, dropped = ingest(reader, state / "sshd-ports-v2.cursor",
                                    resolve_ssh_port=lookup, recovery_minutes=SSH_RECOVERY_MINUTES)
            else:
                _, dropped = ingest(reader, state / "firewalld.cursor")
        if dropped:
            print(f"{source}: skipped {dropped} incoming records above the batch limit.")


if __name__ == "__main__":
    main()
