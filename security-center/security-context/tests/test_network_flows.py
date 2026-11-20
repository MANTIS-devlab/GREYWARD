import datetime as dt
import hashlib
import tempfile
import unittest
from pathlib import Path

from greyward_security_context import network_flows as flows
from greyward_security_context.telemetry import TelemetryStore, event


class NetworkFlowTests(unittest.TestCase):
    def setUp(self):
        self.time = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        self.store_path = tempfile.TemporaryDirectory()
        self.addCleanup(self.store_path.cleanup)
        self.store = TelemetryStore(Path(self.store_path.name) / "events.sqlite")

    def flow(self, source="192.0.2.10", target="198.51.100.6", *, reply=None, port=443):
        suffix = f"src={source} dst={target} sport=52123 dport={port} src={reply or target} dst={source} sport={port} dport=52123"
        line = f"[{self.time.timestamp():.6f}] [NEW] ipv4 2 tcp 6 120 SYN_SENT {suffix} [UNREPLIED] id=42"
        parsed = flows.read_flow(line, self.time)
        self.assertIsNotNone(parsed)
        return parsed

    def test_recorded_confirmation_preserves_filter_direction_and_scope(self):
        flow = self.flow()
        value = flows.describe(flow, {"192.0.2.10"}, "boot")
        self.assertEqual(value["details"]["direction"], "OUTBOUND")
        self.assertEqual(value["decision"], "ALLOWED")
        self.assertEqual(value["details"]["filter_stage"], "EGRESS")
        self.assertEqual(value["destination"]["ip"], "198.51.100.6")
        incoming = flows.describe(flow, {"198.51.100.6"}, "boot")
        self.assertEqual(incoming["details"]["direction"], "INBOUND")
        self.assertEqual(incoming["destination"]["ip"], "192.0.2.10")
        self.assertEqual(incoming["details"]["filter_stage"], "INGRESS")
        local = flows.describe(flow, {"192.0.2.10", "198.51.100.6"}, "boot")
        self.assertEqual(local["details"]["filter_stage"], "LOCAL_EGRESS")
        self.assertFalse(local["details"]["reply_seen"])
        snapshot = flows.describe(flow, {"192.0.2.10"}, "boot", snapshot=True)
        self.assertEqual(snapshot["decision"], "UNKNOWN")
        injected = flows.describe({**flow, "userspace": True}, {"192.0.2.10"}, "boot")
        self.assertEqual(injected["decision"], "UNKNOWN")
        self.assertEqual(flows.describe(flow, {"192.0.2.1"}, "boot")["details"]["direction"], "FORWARDED")
        nat = self.flow(reply="192.0.2.30")
        self.assertEqual(flows.describe(nat, {"198.51.100.6"}, "boot")["details"]["direction"], "FORWARDED")
        later = {**flow, "when": self.time + dt.timedelta(seconds=30)}
        self.assertEqual(flows.describe(later, {"192.0.2.10"}, "boot", snapshot=True)["event_id"], value["event_id"])
        v6 = self.flow("2001:db8::1", "2001:db8::2")
        self.assertEqual(flows.describe(v6, {"2001:db8::1"}, "boot")["destination"]["ip"], "2001:db8::2")

    def test_matching_the_active_provider_requires_exact_uid_pid_and_tuple(self):
        value = flows.describe(self.flow(), {"192.0.2.10"}, "boot")
        digest = hashlib.sha256(b"1000|8|tcp|192.0.2.10|52123|198.51.100.6|443").hexdigest()[:40]
        row = {"event_id": "network-" + "b" * 24, "source": "opensnitch-statistics", "actor_uid": 1000,
               "pid": 8, "protocol": "tcp", "destination": value["destination"], "occurred_at": value["occurred_at"],
               "connection_key": digest}
        self.assertEqual(flows.match_opensnitch(value, [row]), row)
        self.assertIsNone(flows.match_opensnitch(value, [{**row, "pid": 9}]))
        self.assertIsNone(flows.match_opensnitch(value, [row, {**row, "event_id": "network-" + "c" * 24}]))

    def test_runtime_witness_preserves_ipv6_spelling_for_the_native_digest(self):
        origin, destination = "2001:db8::1", "2001:db8::2"
        value = flows.describe(self.flow(origin,destination), {origin}, "boot")
        expanded = "2001:0db8:0000:0000:0000:0000:0000:0001"
        digest = hashlib.sha256(f"1000|8|tcp6|{expanded}|52123|{destination}|443".encode()).hexdigest()[:40]
        native = {"event_id": "network-" + "a" * 24, "source": "opensnitch-statistics",
                  "actor_uid":1000, "pid":8, "protocol":"tcp6", "destination":value["destination"],
                  "occurred_at":value["occurred_at"], "connection_key":digest, "decision":"ALLOWED"}
        self.assertEqual(flows.match_opensnitch(value,[native]),native)
        self.assertEqual(flows.flow_key("tcp6",origin,52123,destination,443),value["details"]["flow_key"])
        app = event(event_id=native["event_id"], occurred_at=value["occurred_at"], component="opensnitch-control-plane",
                    source="opensnitch-statistics", category="NETWORK", event_type="CONNECTION_ATTEMPT",
                    action="CONNECT", outcome="ALLOWED", decision="ALLOWED", destination=value["destination"],
                    protocol="tcp6", port=443)
        value["boot_id"] = app["boot_id"]
        self.store.record_many([app,value])
        self.assertEqual(self.store.reconcile_network_duplicates([native],flows.match_opensnitch),1)
        rows = self.store.query({"category":"NETWORK"})["events"]
        self.assertEqual([(row["event_id"],row["protocol"]) for row in rows],[(native["event_id"],"tcp6")])

    def test_runtime_witness_collapses_already_recorded_duplicates_to_original_opensnitch_id(self):
        kernel = flows.describe(self.flow(), {"192.0.2.10"}, "boot")
        # The old collector's persisted OpenSnitch row had no tuple key.
        open_id = "network-" + "d" * 24
        app = event(event_id=open_id, occurred_at=kernel["occurred_at"], component="opensnitch-control-plane",
                    source="opensnitch-statistics", category="NETWORK", event_type="CONNECTION_ATTEMPT",
                    action="CONNECT", outcome="ALLOWED", decision="ALLOWED", application="browser",
                    destination={**kernel["destination"], "host":"example.test"}, protocol="tcp", port=443,
                    details={"rule_name":"retained-rule"})
        # Real rows both carry the same native boot identity.
        kernel["boot_id"] = app["boot_id"]
        digest = hashlib.sha256(b"1000|8|tcp|192.0.2.10|52123|198.51.100.6|443").hexdigest()[:40]
        runtime = {"event_id":open_id,"source":app["source"],"actor_uid":1000,"pid":8,"protocol":"tcp",
                   "destination":app["destination"],"occurred_at":app["occurred_at"],
                   "connection_key":digest,"decision":"ALLOWED"}
        self.store.record_many([kernel,app])
        self.assertEqual(self.store.reconcile_network_duplicates([runtime],flows.match_opensnitch),1)
        self.store.record_many([kernel,app])
        events = self.store.query({"category":"NETWORK"})["events"]
        self.assertEqual([row["event_id"] for row in events],[open_id])
        self.assertEqual(events[0]["destination"]["host"],"example.test")
        self.assertEqual(events[0]["details"]["rule_name"],"retained-rule")
        self.assertEqual(events[0]["details"]["evidence_sources"],["conntrack","opensnitch-statistics"])
        self.assertEqual(self.store.related(kernel["event_id"])["seed_event_id"],open_id)

    def test_exact_overlap_keeps_conflicting_policy_decisions(self):
        kernel = flows.describe(self.flow(), {"192.0.2.10"}, "boot")
        details = kernel["details"]
        policy = event(event_id="allowed", occurred_at=kernel["occurred_at"], component="opensnitch-control-plane",
                       source="opensnitch-statistics", category="NETWORK", event_type="CONNECTION_ATTEMPT",
                       action="CONNECT", outcome="ALLOWED", decision="ALLOWED", destination=kernel["destination"],
                       protocol="tcp", port=443, details=details)
        kernel["boot_id"] = policy["boot_id"]
        blocked = event(event_id="blocked", occurred_at=kernel["occurred_at"], component="inbound-network",
                        source="firewalld", category="NETWORK", event_type="FIREWALL_DENIAL",
                        action="FILTER", outcome="BLOCKED", decision="BLOCKED", destination=kernel["destination"],
                        protocol="tcp", port=443, details=details)
        self.store.record_many([kernel,policy,blocked])
        self.assertEqual({row["decision"] for row in self.store.query({"category":"NETWORK"})["events"]},{"ALLOWED","BLOCKED"})

    def test_exact_evidence_enriches_one_history_record_and_is_idempotent(self):
        kernel = flows.describe(self.flow(), {"192.0.2.10"}, "boot")
        application = event(
            event_id="application-1", occurred_at=kernel["occurred_at"], component="opensnitch-control-plane",
            source="opensnitch-statistics", category="NETWORK", event_type="CONNECTION_ATTEMPT",
            action="CONNECT", outcome="ALLOWED", decision="ALLOWED", application="browser",
            destination={**kernel["destination"], "host": "example.test"}, protocol="tcp", port=443,
            details={"direction": "OUTBOUND", "flow_key": kernel["details"]["flow_key"]},
        )
        self.store.record_many([kernel, application, kernel, application])
        rows = self.store.query({"category": "NETWORK", "direction": "OUTBOUND", "port": 443})["events"]
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["application"], rows[0]["decision"]), ("browser", "ALLOWED"))
        self.assertEqual(rows[0]["details"]["transport_state"], "SYN_SENT")
        self.assertEqual(rows[0]["details"]["evidence_sources"], ["conntrack", "opensnitch-statistics"])
        summary = self.store.network_window_summary(kernel["occurred_at"])
        self.assertEqual((summary["total"], summary["allowed"]), (1, 1))
        self.assertEqual(sum(bucket["total"] for bucket in summary["buckets"]), 1)

    def test_latest_transport_state_survives_out_of_order_replay_without_changing_id(self):
        first = self.flow()
        established = {**first, "phase": "UPDATE", "transport_state": "ESTABLISHED", "reply_seen": True,
                       "when": first["when"] + dt.timedelta(seconds=1)}
        ended = {**established, "phase": "DESTROY", "transport_state": "CLOSE",
                 "when": first["when"] + dt.timedelta(seconds=2)}
        records = [flows.describe(value, {"192.0.2.10"}, "boot") for value in (first, established, ended)]
        self.store.record_many([*records, records[0], records[1]])
        rows = self.store.query({"category": "NETWORK", "decision": "ALLOWED"})["events"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["occurred_at"], records[0]["occurred_at"])
        self.assertEqual(rows[0]["details"]["transport_state"], "CLOSE")
        self.assertTrue(rows[0]["details"]["reply_seen"])
        self.assertTrue(rows[0]["details"]["tracking_ended"])

    def test_migration_upgrades_only_live_records_from_the_old_collector(self):
        first = self.flow()
        observed = flows.describe(first, {"192.0.2.10"}, "boot")
        snapshot = flows.describe({**first, "kernel_id": "55"}, {"192.0.2.10"}, "boot", snapshot=True)
        self.store.record_many([observed, snapshot])
        connection = self.store._connect()
        try:
            with connection:
                connection.execute(
                    """UPDATE events SET decision='UNKNOWN', outcome='UNKNOWN',
                       details_json=json_remove(details_json,'$.transport_observed_at','$.filter_evidence','$.filter_stage')
                       WHERE event_id=?""", (observed["event_id"],))
        finally:
            connection.close()
        self.store.reconcile_network_verdicts()
        allowed = self.store.query({"category": "NETWORK", "decision": "ALLOWED"})["events"]
        self.assertEqual([item["event_id"] for item in allowed], [observed["event_id"]])
        self.assertEqual(allowed[0]["details"]["filter_evidence"], "conntrack-legacy")

    def test_ssh_merges_only_a_unique_recent_incoming_socket(self):
        kernel = flows.describe(self.flow(port=22), {"198.51.100.6"}, "boot")
        ssh = event(event_id="ssh-1", occurred_at=kernel["occurred_at"], component="inbound-network", source="sshd",
                    category="NETWORK", event_type="SSH_SESSION_ACCEPTED", action="AUTHENTICATE", outcome="ALLOWED",
                    decision="ALLOWED", destination=kernel["destination"], port=22, protocol="tcp", application="SSH",
                    details={"peer_port": 52123})
        self.store.record_many([kernel, ssh, ssh])
        rows = self.store.query({"category": "NETWORK", "direction": "INBOUND", "port": 22})["events"]
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["source"], rows[0]["decision"]), ("sshd", "ALLOWED"))
        self.assertEqual(rows[0]["details"]["evidence_sources"], ["conntrack", "sshd"])


if __name__ == "__main__":
    unittest.main()
