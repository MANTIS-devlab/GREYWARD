"""Read-only host conntrack evidence for Network Activity."""

import collections
import datetime as dt
import hashlib
import ipaddress
import json
import os
import queue
import re
import subprocess
import threading
import time
from pathlib import Path

from .telemetry import FLOW_SPOOL_PATH, FLOW_STATUS_PATH, boot_id, event, spool_event, stamp
from .network_merge import FILTER_STAGES, OPEN, OPEN_STATISTICS, transport_protocol

CONNTRACK = "/usr/sbin/conntrack"
OPEN_STATE = Path("/run/greyward-security-context/network-protection.json")
MAX_PENDING = 512
MAX_ACTIVE_IDS = 8192
FIRST_FIELDS = re.compile(r"(?:^|\s)(src|dst|sport|dport|type|code|id|zone)=([^\s]+)")
TRANSPORT = re.compile(r"(?:^|\s)([a-z][a-z0-9-]{0,15})\s+(\d{1,3})(?=\s)")
TIMESTAMP = re.compile(r"^\[\s*(\d{9,12}(?:\.\d+)?)\s*\]")
EVENT_PHASE = re.compile(r"\[(NEW|UPDATE|DESTROY)\]")
TCP_STATE = re.compile(r"\b(SYN_SENT2?|SYN_RECV|ESTABLISHED|FIN_WAIT|CLOSE_WAIT|TIME_WAIT|LAST_ACK|CLOSE)\b")


def normalized_ip(value):
    try:
        address = ipaddress.ip_address(value)
        return str(getattr(address, "ipv4_mapped", None) or address)
    except (ValueError, TypeError):
        return None


def _number(value, limit=65535):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if 0 <= parsed <= limit else None


def flow_key(protocol, source_ip, source_port, target_ip, target_port):
    left, right = normalized_ip(source_ip), normalized_ip(target_ip)
    source_port, target_port = _number(source_port), _number(target_port)
    protocol = transport_protocol(protocol)
    if protocol not in {"tcp", "udp", "sctp", "dccp", "udplite"} or not left or not right or source_port is None or target_port is None:
        return None
    return hashlib.sha256(f"{protocol}|{left}|{source_port}|{right}|{target_port}".encode()).hexdigest()[:40]


def read_flow(line, fallback):
    if len(line) > 4096:
        return None
    candidate = TIMESTAMP.match(line)
    when = fallback
    if candidate:
        try:
            when = dt.datetime.fromtimestamp(float(candidate[1]), dt.timezone.utc)
        except (OverflowError, ValueError, OSError):
            return None
    positions = list(re.finditer(r"\bsrc=", line))
    if len(positions) != 2:
        return None
    start, reply = (match.start() for match in positions)
    transports = list(TRANSPORT.finditer(line[:start]))
    if not transports:
        return None
    protocol = transport_protocol(transports[-1][1])
    original = dict(FIRST_FIELDS.findall(line[start:reply]))
    response = dict(FIRST_FIELDS.findall(line[reply:]))
    remote_src, remote_dst = normalized_ip(original.get("src")), normalized_ip(original.get("dst"))
    reply_src = normalized_ip(response.get("src"))
    if not remote_src or not remote_dst:
        return None
    state = TCP_STATE.search(line[:start])
    phase = EVENT_PHASE.search(line[:start])
    return {
        "protocol": protocol, "origin_ip": remote_src, "target_ip": remote_dst, "reply_ip": reply_src,
        "origin_port": _number(original.get("sport")), "target_port": _number(original.get("dport")),
        "kernel_id": response.get("id"), "zone": response.get("zone", "0"),
        "transport_state": state[1] if state else None, "when": when,
        "phase": phase[1] if phase else None, "userspace": "[USERSPACE]" in line.upper(),
        "reply_seen": "[UNREPLIED]" not in line,
    }


def _local(address, addresses):
    return bool(address and (address in addresses or ipaddress.ip_address(address).is_loopback))


def describe(flow, addresses, machine_boot, *, snapshot=False):
    origin, target = flow["origin_ip"], flow["target_ip"]
    origin_port, target_port = flow["origin_port"], flow["target_port"]
    protocol = flow["protocol"]
    source_local = _local(origin, addresses)
    target_local = _local(flow["reply_ip"] or target, addresses)
    if source_local and target_local:
        direction = "LOCAL"
    elif source_local:
        direction = "OUTBOUND"
    elif target_local:
        direction = "INBOUND"
    elif addresses:
        direction = "FORWARDED"
    else:
        direction = "UNKNOWN"
    peer = origin if direction == "INBOUND" else target
    phase = flow["phase"]
    physical = not snapshot and not flow["userspace"] and bool(phase)
    confirmed = physical and (phase == "NEW" or flow["reply_seen"])
    decision = "ALLOWED" if confirmed and direction in FILTER_STAGES else "UNKNOWN"
    details = {
        "direction": direction, "origin_ip": origin, "target_ip": target,
        "origin_port": origin_port, "target_port": target_port,
        "local_ip": (flow["reply_ip"] or target) if direction == "INBOUND" else origin if source_local else None,
        "peer_port": origin_port if direction == "INBOUND" else target_port,
        "transport_state": flow["transport_state"], "snapshot": snapshot,
        "transport_observed_at": flow["when"].astimezone(dt.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "reply_seen": flow["reply_seen"], "tracking_ended": phase == "DESTROY",
        "filter_evidence": "conntrack-confirmed" if decision == "ALLOWED" else None,
        "filter_stage": FILTER_STAGES.get(direction) if decision == "ALLOWED" else None,
        "flow_key": flow_key(protocol, origin, origin_port, target, target_port),
    }
    identity = json.dumps([machine_boot, flow["zone"], flow["kernel_id"], protocol, origin, origin_port,
                           target, target_port, None if flow["kernel_id"] else flow["when"].isoformat()], separators=(",", ":"))
    return event(
        event_id="flow-" + hashlib.sha256(identity.encode()).hexdigest()[:32],
        occurred_at=stamp(flow["when"]), component="network-flow",
        source="conntrack", category="NETWORK", event_type="TRACKED_FLOW",
        action="OBSERVE", outcome=decision, decision=decision, assessment="UNKNOWN",
        destination={"ip": peer, "port": target_port}, port=target_port, protocol=protocol, details=details,
        quality={"source_state": "AVAILABLE", "attribution": "UNKNOWN", "confidence": "OBSERVED"},
    )


def match_opensnitch(value, candidates):
    """Recognize the running control plane's exact UID/PID/tuple digest."""
    d = value["details"]
    if d.get("direction") not in {"OUTBOUND", "LOCAL"} or not d.get("flow_key"):
        return None
    if any(d.get(key) is None for key in ("origin_ip", "origin_port", "target_ip", "target_port")):
        return None
    when = dt.datetime.fromisoformat(value["occurred_at"].replace("Z", "+00:00"))
    try:
        origin = ipaddress.ip_address(d["origin_ip"])
        origin_forms = {str(origin), origin.exploded}
    except (TypeError, ValueError):
        return None
    matches = []
    for record in candidates:
        if not isinstance(record, dict) or record.get("source") not in OPEN:
            continue
        dst = record.get("destination")
        if not isinstance(dst, dict) or normalized_ip(dst.get("ip")) != d["target_ip"] or dst.get("port") != d["target_port"]:
            continue
        proto = record.get("protocol")
        if transport_protocol(proto) != transport_protocol(value["protocol"]) or record.get("actor_uid") is None:
            continue
        try:
            observed = dt.datetime.fromisoformat(record["occurred_at"].replace("Z", "+00:00"))
            if abs((observed-when).total_seconds()) > 8:
                continue
        except (KeyError, TypeError, ValueError):
            continue
        # The old producer hashed the native spelling. Compare canonical
        # addresses/protocols, but reproduce the actual hash it sent.
        keys = ("|".join(map(str, (record["actor_uid"], record.get("pid") or 0, proto, address,
                                   d["origin_port"], dst["ip"], d["target_port"]))) for address in origin_forms)
        verified = any(hashlib.sha256(key.encode()).hexdigest()[:40] == record.get("connection_key") for key in keys)
        identity = record.get("event_id")
        if verified and isinstance(identity, str) and re.fullmatch(r"network-[0-9a-f]{24}", identity):
            matches.append(record)
    exact = {record["event_id"]: record for record in matches}
    if len(exact) == 1:
        return next(iter(exact.values()))
    if len(exact) == 2:
        statistics = [record for record in exact.values() if record["source"] in OPEN_STATISTICS]
        equivalent = {(record.get("connection_key"), record.get("decision")) for record in exact.values()}
        if len(statistics) == 1 and len(equivalent) == 1:
            return statistics[0]
    return None


def _read_addresses():
    try:
        result = subprocess.run(["/usr/sbin/ip", "-j", "address", "show"], check=True, capture_output=True, timeout=3)
        return {address for link in json.loads(result.stdout) for info in link.get("addr_info", [])
                if (address := normalized_ip(info.get("local")))}
    except (OSError, ValueError, subprocess.SubprocessError):
        return frozenset()


def running_opensnitch_activity():
    try:
        with OPEN_STATE.open("rb") as file:
            raw = file.read(8 * 1024 * 1024 + 1)
            if len(raw) > 8 * 1024 * 1024:
                return []
            value = json.loads(raw)
        if not isinstance(value, dict):
            return []
        return value["activity"][-4096:] if isinstance(value.get("activity"), list) else []
    except (OSError, ValueError):
        return []


def _status(state, gaps):
    value = {"state": state, "missed": gaps, "at": stamp()}
    temp = FLOW_STATUS_PATH.with_suffix(".tmp")
    temp.write_text(json.dumps(value), encoding="utf-8")
    os.chmod(temp, 0o640)
    import grp
    os.chown(temp, 0, grp.getgrnam("wheel").gr_gid)
    os.replace(temp, FLOW_STATUS_PATH)


def main():
    _status("STARTING", 0)
    pending = queue.Queue(MAX_PENDING)
    overflow = 0
    process = subprocess.Popen([CONNTRACK, "-E", "-e", "NEW,UPDATES,DESTROY", "-o", "timestamp,extended,id,userspace",
                                "-b", "1048576"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def read():
        nonlocal overflow
        for line in process.stdout:
            try:
                pending.put_nowait((line.decode("ascii", "replace"), False))
            except queue.Full:
                overflow += 1

    def diagnostics():
        nonlocal overflow
        for line in process.stderr:
            text = line.decode("utf-8", "replace").strip()
            if "enobufs" in text.lower() or "no buffer space" in text.lower():
                overflow += 1
            if text:
                print(text[:512], flush=True)

    threading.Thread(target=diagnostics, daemon=True).start()
    thread = threading.Thread(target=read, daemon=True)
    thread.start()
    active = collections.OrderedDict()
    initial = []
    try:
        for family in ("ipv4", "ipv6"):
            with subprocess.Popen([CONNTRACK, "-L", "-f", family, "-o", "extended,id"],
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as dump:
                # Reserve queue capacity for live entries arriving during startup.
                for line in dump.stdout:
                    if len(initial) >= 512:
                        overflow += 1
                        dump.terminate()
                        break
                    initial.append((line.decode("ascii", "replace"), True))
                dump.wait(timeout=4)
        boot = boot_id()
        addresses = _read_addresses()
        refreshed = time.monotonic()
        published = 0.0
        status_at = 0.0
        batch = initial
        while True:
            if not thread.is_alive() and pending.empty():
                raise RuntimeError("The kernel connection event subscription ended")
            now = time.monotonic()
            if now - refreshed >= 15:
                addresses = _read_addresses()
                refreshed = now
            try:
                batch.append(pending.get(timeout=0.5))
            except queue.Empty:
                pass
            if batch and (now - published >= 2 or len(batch) >= 256):
                candidates = running_opensnitch_activity()
                for line, snapshot in batch:
                    flow = read_flow(line, dt.datetime.now(dt.timezone.utc))
                    if not flow:
                        continue
                    identity = (flow["zone"], flow["kernel_id"], flow["protocol"], flow["origin_ip"],
                                flow["origin_port"], flow["target_ip"], flow["target_port"])
                    # Track meaningful lifecycle changes on the original row.
                    # Uncorrelated UPDATE/DESTROY records cannot seed a flow.
                    previous = active.get(identity) if flow["kernel_id"] else None
                    if flow["userspace"] or (not previous and not snapshot and flow["phase"] != "NEW"):
                        continue
                    value = describe(flow, addresses, boot, snapshot=snapshot)
                    details = value["details"]
                    signature = (details["transport_state"], details["reply_seen"], details["tracking_ended"], details["filter_evidence"])
                    if previous:
                        if signature == previous[1]:
                            continue
                        value["event_id"] = previous[0]
                    elif not snapshot:
                        matched = match_opensnitch(value, candidates)
                        if matched:
                            value["event_id"] = matched["event_id"]
                    if spool_event(value, FLOW_SPOOL_PATH):
                        if flow["kernel_id"] and not details["tracking_ended"]:
                            active[identity] = (value["event_id"], signature)
                            active.move_to_end(identity)
                        elif details["tracking_ended"]:
                            active.pop(identity, None)
                        if len(active) > MAX_ACTIVE_IDS:
                            active.popitem(last=False)
                    else:
                        overflow += 1
                batch = []
                published = now
            if now - status_at >= 5:
                _status("DEGRADED" if overflow else "OPERATING", overflow)
                status_at = now
    finally:
        if process.poll() is None:
            process.terminate()
        _status("DEGRADED", overflow + 1)


if __name__ == "__main__":
    main()
