"""Coalesce kernel flow evidence with a verified connection decision."""

import datetime as dt
import json
import re

KERNEL = "conntrack"
OPEN_STATISTICS = {"opensnitch-statistics", "opensnitch-stats"}
OPEN = OPEN_STATISTICS | {"opensnitch", "greyward-policy", "opensnitch-notification"}
NETWORK_SOURCES = OPEN | {KERNEL, "firewalld", "sshd"}
FILTER_STAGES = {"INBOUND": "INGRESS", "OUTBOUND": "EGRESS", "FORWARDED": "FORWARD", "LOCAL": "LOCAL_EGRESS"}
TRANSPORT_KEYS = ("transport_state", "transport_observed_at", "reply_seen", "tracking_ended")
TRANSPORT_ALIASES = {
    "tcp6": "tcp", "udp6": "udp", "sctp6": "sctp", "dccp6": "dccp", "udplite6": "udplite",
    "ipv6-icmp": "icmpv6", "icmp6": "icmpv6",
}


def transport_protocol(value):
    protocol = str(value or "").lower()
    return TRANSPORT_ALIASES.get(protocol, protocol)



def previous_kernel_verdict(value):
    """Upgrade the previous collector's live NEW records, with explicit provenance."""
    details = value.get("details") or {}
    stage = FILTER_STAGES.get(details.get("direction"))
    if (value.get("source") == KERNEL and value.get("event_type") == "TRACKED_FLOW"
            and value.get("decision") == "UNKNOWN" and details.get("snapshot") is False
            and not details.get("transport_observed_at") and stage):
        return {**value, "outcome": "ALLOWED", "decision": "ALLOWED",
                "details": {**details, "filter_evidence": "conntrack-legacy", "filter_stage": stage}}
    return value


def _window(value, before, after):
    when = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    return tuple((when + dt.timedelta(seconds=delta)).astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
                 for delta in (-before, after))


def _candidates(connection, value):
    details = value.get("details") or {}
    identity = value["event_id"]
    alias = connection.execute("SELECT event_id FROM network_flow_aliases WHERE alias_id=?", (identity,)).fetchone()
    if alias is not None:
        identity = alias["event_id"]
    exact = connection.execute(
        "SELECT * FROM events WHERE category='NETWORK' AND event_id=?", (identity,)).fetchone()
    if exact is not None:
        return [exact] if (alias is not None or exact["source"] == KERNEL or value["source"] == KERNEL) else []
    process_flow = details.get("connection_key")
    if value["source"] in OPEN and isinstance(process_flow, str) and re.fullmatch(r"[0-9a-f]{40}", process_flow):
        start, end = _window(value["occurred_at"], 8, 8)
        matches = connection.execute(
            """SELECT * FROM events WHERE category='NETWORK' AND source<>? AND boot_id IS ?
               AND source IN ('opensnitch','opensnitch-statistics','greyward-policy','opensnitch-stats','opensnitch-notification')
               AND json_extract(details_json,'$.connection_key')=? AND occurred_at BETWEEN ? AND ? LIMIT 2""",
            (value["source"], value.get("boot_id"), process_flow, start, end),
        ).fetchall()
        if matches:
            return matches
    key = details.get("flow_key")
    if isinstance(key, str) and re.fullmatch(r"[0-9a-f]{40}", key) and not details.get("snapshot"):
        start, end = _window(value["occurred_at"], 8, 8)
        if value["source"] == KERNEL:
            source = "source IN ('opensnitch','opensnitch-statistics','greyward-policy','opensnitch-stats','opensnitch-notification','firewalld')"
        else:
            source = """(source='conntrack' OR
                         EXISTS (SELECT 1 FROM json_each(events.details_json,'$.evidence_sources') WHERE value='conntrack'))"""
        candidates = connection.execute(
            f"""SELECT * FROM events WHERE category='NETWORK' AND {source}
                  AND json_extract(details_json,'$.flow_key')=? AND boot_id IS ?
                  AND occurred_at BETWEEN ? AND ?
                  AND COALESCE(json_extract(details_json,'$.snapshot'),0)=0 LIMIT 6""",
            (key, value.get("boot_id"), start, end)).fetchall()
        if candidates:
            return candidates
    direction = details.get("direction")
    source = value["source"]
    port = value.get("port")
    peer_port = details.get("peer_port")
    peer_ip = (value.get("destination") or {}).get("ip")
    if source not in {"sshd", KERNEL} or direction != "INBOUND" or value.get("protocol") != "tcp":
        return []
    if type(port) is not int or type(peer_port) is not int or not peer_ip:
        return []
    start, end = _window(value["occurred_at"], 0 if source == KERNEL else 150, 150 if source == KERNEL else 0)
    return connection.execute(
        """SELECT * FROM events WHERE category='NETWORK' AND source=? AND protocol='tcp'
              AND port=? AND json_extract(destination_json,'$.ip')=?
              AND json_extract(details_json,'$.peer_port')=? AND occurred_at BETWEEN ? AND ?
              AND COALESCE(json_extract(details_json,'$.snapshot'),0)=0 LIMIT 2""",
        ("sshd" if source == KERNEL else KERNEL, port, peer_ip, peer_port, start, end)).fetchall()


def _rank(source, decision):
    if decision not in {"ALLOWED", "BLOCKED"}:
        return 0
    if source == "firewalld" and decision == "BLOCKED":
        return 2
    if source in OPEN_STATISTICS:
        return 4
    if source in OPEN:
        return 3
    if source == "sshd":
        return 2
    return 1 if source == KERNEL else 0


def _policy_conflict(left, right):
    return (left["source"] != KERNEL and right["source"] != KERNEL
            and {left["decision"], right["decision"]} == {"ALLOWED", "BLOCKED"})


def merge(connection, value, safe):
    if value.get("category") != "NETWORK" or value.get("source") not in NETWORK_SOURCES:
        return False
    try:
        matches = _candidates(connection, value)
    except (TypeError, ValueError):
        return False
    if len(matches) != 1 or _policy_conflict(matches[0], value):
        return False
    amend(connection, matches[0], value, safe)
    return True


def amend(connection, previous, value, safe):
    prefer = _rank(value["source"], value.get("decision")) > _rank(previous["source"], previous["decision"])
    old_details = json.loads(previous["details_json"])
    incoming = {k: v for k, v in (value.get("details") or {}).items() if v is not None}
    if old_details.get("transport_observed_at", "") > incoming.get("transport_observed_at", ""):
        incoming = {k: v for k, v in incoming.items() if k not in TRANSPORT_KEYS}
    details = {**old_details, **incoming}
    if old_details.get("reply_seen"):
        details["reply_seen"] = True
    sources = {previous["source"], value["source"], *old_details.get("evidence_sources", []),
               *(value.get("details") or {}).get("evidence_sources", [])}
    if len(sources) > 1:
        details["evidence_sources"] = sorted(sources)
    if old_details.get("snapshot") is False:
        details["snapshot"] = False
    if previous["source"] in OPEN and not prefer:
        details["application_event_id"] = old_details.get("application_event_id") or previous["event_id"]
    elif value["source"] in OPEN:
        details["application_event_id"] = value["event_id"]
    if previous["source"] != KERNEL and not prefer:
        details.update({k: old_details[k] for k in ("direction", "process_key", "pid", "rule_name") if old_details.get(k)})
    if value["event_id"] != previous["event_id"]:
        connection.execute("INSERT OR IGNORE INTO network_flow_aliases(alias_id,event_id) VALUES(?,?)",
                           (value["event_id"], previous["event_id"]))
    if prefer:
        destination = {**json.loads(previous["destination_json"]), **(value.get("destination") or {})}
        application = value.get("application") or previous["application"]
        # A firewall's verdict can supersede OpenSnitch's decision while
        # retaining the established application identity.
        if value["source"] == "firewalld" and previous["source"] in OPEN:
            application = previous["application"]
        connection.execute("""UPDATE events SET component=?, source=?, event_type=?, action=?, outcome=?,
                              severity=?, assessment=?, decision=?, application=?, details_json=?, destination_json=?
                              WHERE event_id=?""",
                           (value["component"], value["source"], value["event_type"], value["action"], value["outcome"],
                            value["severity"], value["assessment"], value["decision"], application,
                            json.dumps(safe(details), separators=(",", ":")), json.dumps(safe(destination), separators=(",", ":")),
                            previous["event_id"]))
    else:
        if details != old_details:
            connection.execute("UPDATE events SET details_json=?, application=COALESCE(application,?) WHERE event_id=?",
                               (json.dumps(safe(details), separators=(",", ":")), value.get("application"), previous["event_id"]))

def collect_duplicate(connection, preferred, duplicate, row_value, safe):
    """Keep the original OpenSnitch row and redirect references to it."""
    if preferred["source"] not in OPEN or _policy_conflict(preferred, duplicate):
        return False
    if _rank(preferred["source"], preferred["decision"]) < _rank(duplicate["source"], duplicate["decision"]):
        return False
    kept, removed = preferred["event_id"], duplicate["event_id"]
    if kept == removed:
        return False
    amend(connection, preferred, row_value(duplicate), safe)
    connection.execute("UPDATE network_flow_aliases SET event_id=? WHERE event_id=?", (kept, removed))
    connection.execute(
        """INSERT OR IGNORE INTO event_relations(event_id,related_event_id,relation,confidence,basis)
           SELECT event_id,?,relation,confidence,basis FROM event_relations
           WHERE related_event_id=? AND event_id NOT IN (?,?)""",
        (kept, removed, kept, removed),
    )
    # A duplicate can be linked from a retained row, or link to another row.
    connection.execute(
        """INSERT OR IGNORE INTO event_relations(event_id,related_event_id,relation,confidence,basis)
           SELECT ?,related_event_id,relation,confidence,basis FROM event_relations
           WHERE event_id=? AND related_event_id NOT IN (?,?)""",
        (kept, removed, kept, removed),
    )
    connection.execute("DELETE FROM event_relations WHERE event_id=? OR related_event_id=?", (removed, removed))
    connection.execute("DELETE FROM events WHERE event_id=?", (removed,))
    return True
