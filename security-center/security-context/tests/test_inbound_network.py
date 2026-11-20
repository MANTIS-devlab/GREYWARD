import datetime as dt
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from greyward_security_context import inbound_network as inbound
from greyward_security_context.telemetry import TelemetryStore


class Reader:
    def __init__(self, entries):
        self.entries = entries
        self.offset = 0

    def seek_realtime(self, when):
        self.offset = 0

    def seek_cursor(self, cursor):
        self.offset = next((i for i, item in enumerate(self.entries) if item["__CURSOR"] == cursor), len(self.entries))

    def get_next(self):
        if self.offset >= len(self.entries):
            return {}
        entry = self.entries[self.offset]
        self.offset += 1
        return entry


class IncomingNetworkTests(unittest.TestCase):
    def setUp(self):
        self.when = dt.datetime.now(dt.timezone.utc).replace(second=0, microsecond=0)

    def ssh(self, cursor="s1", message="Accepted publickey for example from 2001:db8::1 port 50222 ssh2: ED25519 secret"):
        return {"_SYSTEMD_UNIT": "sshd.service", "_COMM": "sshd-session", "__CURSOR": cursor,
                "__REALTIME_TIMESTAMP": self.when, "MESSAGE": message}

    def firewall(self, cursor="f1", **fields):
        packet = {"IN": "eth0", "OUT": "", "SRC": "192.0.2.8", "DST": "192.0.2.9", "PROTO": "TCP", "SPT": "50122", "DPT": "22", **fields}
        return {"_TRANSPORT": "kernel", "_BOOT_ID": "66a59bbb77694ecfa39a3f288fffa845", "__CURSOR": cursor,
                "__REALTIME_TIMESTAMP": self.when,
                "MESSAGE": "FINAL_REJECT: " + " ".join(f"{key}={value}" for key, value in packet.items())}

    def test_ssh_retains_only_the_remote_endpoint_from_an_authenticated_session(self):
        value = inbound.classify(self.ssh())
        self.assertEqual(value["source"], "sshd")
        self.assertEqual(value["decision"], "ALLOWED")
        self.assertIsNone(value["port"])
        self.assertEqual(value["destination"], {"ip": "2001:db8::1"})
        self.assertEqual(value["details"], {"direction": "INBOUND", "peer_port": 50222})
        self.assertNotIn("secret", repr(value))
        self.assertIsNone(inbound.classify(self.ssh(message="pam_unix(sshd:session): session opened")))
        self.assertIsNone(inbound.classify({**self.ssh(), "_SYSTEMD_UNIT": "user@1000.service"}))

    def test_only_authoritative_firewall_denials_are_imported(self):
        value = inbound.classify(self.firewall())
        self.assertEqual((value["source"], value["decision"], value["port"]), ("firewalld", "BLOCKED", 22))
        self.assertEqual(value["details"]["local_ip"], "192.0.2.9")
        self.assertEqual(value["boot_id"], "66a59bbb-7769-4ecf-a39a-3f288fffa845")
        self.assertEqual(inbound.classify(self.firewall("retry", DPT="22"))["event_id"], value["event_id"])
        self.assertNotEqual(inbound.classify(self.firewall("another-flow", SPT="50123"))["event_id"], value["event_id"])
        self.assertEqual(inbound.classify(self.firewall(SRC="2001:db8::5", DST="2001:db8::6"))["destination"]["ip"], "2001:db8::5")
        self.assertEqual(inbound.classify(self.firewall(SRC="2001:db8::5", DST="2001:db8::6", PROTO="ICMPv6"))["protocol"], "icmpv6")
        self.assertEqual(inbound.classify(self.firewall(IN="", OUT="eth0"))["details"]["direction"], "OUTBOUND")
        self.assertEqual(inbound.classify(self.firewall(OUT="eth1"))["details"]["direction"], "FORWARDED")
        self.assertEqual(inbound.classify(self.firewall(IN="lo"))["details"]["direction"], "LOCAL")
        self.assertIsNone(inbound.classify({**self.firewall(), "_TRANSPORT": "syslog"}))
        self.assertIsNone(inbound.classify({**self.firewall(), "MESSAGE": "unrelated: " + self.firewall()["MESSAGE"]}))

    def test_cursor_retry_dedup_and_provider_filter(self):
        with tempfile.TemporaryDirectory() as d:
            state = Path(d)
            store = TelemetryStore(state / "test.sqlite")
            checkpoint = state / "cursor"
            records = [self.firewall(), self.firewall("f2"), self.ssh()]
            publish = lambda value, path: store.record(value)
            self.assertEqual(inbound.ingest(Reader(records), checkpoint, publish)[0], {"firewalld": 1, "sshd": 1})
            self.assertEqual(checkpoint.read_text().strip(), "s1")
            self.assertEqual(sum(inbound.ingest(Reader(records), checkpoint, publish)[0].values()), 0)
            self.assertEqual(len(store.query({"category": "NETWORK"})["events"]), 2)
            self.assertEqual(len(store.query({"category": "NETWORK", "network_origin": "firewalld", "decision": "BLOCKED"})["events"]), 1)
            self.assertEqual(len(store.query({"category": "NETWORK", "network_origin": "application"})["events"]), 0)
            with self.assertRaises(OSError):
                inbound.ingest(Reader([*records, self.ssh("s2")]), checkpoint, lambda value, path: False)
            self.assertEqual(checkpoint.read_text().strip(), "s1")

    def test_listener_evidence_requires_exact_invocation_and_one_port(self):
        invocation = "66a59bbb77694ecfa39a3f288fffa845"
        then = self.when - dt.timedelta(seconds=1)
        first = {**self.ssh(), "_COMM": "sshd", "_SYSTEMD_INVOCATION_ID": invocation,
                 "__REALTIME_TIMESTAMP": then, "MESSAGE": "Server listening on 0.0.0.0 port 22."}
        ipv6 = {**first, "MESSAGE": "Server listening on :: port 22."}
        second_port = {**first, "MESSAGE": "Server listening on :: port 2222."}
        self.assertEqual(inbound.ssh_listener_port([first, ipv6], invocation, self.when), 22)
        self.assertIsNone(inbound.ssh_listener_port([first, second_port], invocation, self.when))
        self.assertIsNone(inbound.ssh_listener_port([first], "different", self.when))
        self.assertIsNone(inbound.ssh_listener_port([first], invocation, then - dt.timedelta(seconds=1)))

    def test_port_enrichment_updates_the_journal_id_without_creating_a_second_row(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            store = TelemetryStore(folder / "history.sqlite")
            row = self.ssh()
            original = inbound.classify(row)
            store.record(original)
            inbound.ingest(Reader([row]), folder / "cursor", lambda value, _: store.record(value),
                           resolve_ssh_port=lambda entry: 2222)
            records = store.query({"category": "NETWORK", "network_origin": "sshd", "port": 2222})["events"]
            self.assertEqual([item["event_id"] for item in records], [original["event_id"]])
            self.assertEqual(records[0]["details"]["port_evidence"], "sshd-listener")
            self.assertEqual(records[0]["destination"]["port"], 2222)
            self.assertEqual(store.query({"category": "NETWORK"})["source_state"]["count"], 1)

    def test_ssh_batch_limit_resumes_at_first_unprocessed_session(self):
        with tempfile.TemporaryDirectory() as d, patch.object(inbound, "MAX_EXPORT_PER_SOURCE", 1):
            cursor = Path(d) / "cursor"
            rows = [self.ssh("first"), self.ssh("second")]
            recorded = []
            publish = lambda value, _: recorded.append(value["event_id"]) or True
            inbound.ingest(Reader(rows), cursor, publish)
            self.assertEqual(cursor.read_text().strip(), "first")
            inbound.ingest(Reader(rows), cursor, publish)
            self.assertEqual(cursor.read_text().strip(), "second")
            self.assertEqual(recorded, [inbound.classify(row)["event_id"] for row in rows])

    def test_noisy_source_has_a_bounded_output(self):
        with tempfile.TemporaryDirectory() as d, patch.object(inbound, "MAX_EXPORT_PER_SOURCE", 1):
            output = []
            _, dropped = inbound.ingest(
                Reader([self.firewall(), self.firewall("f2", SPT="80"), self.ssh()]),
                Path(d) / "cursor", lambda value, path: output.append(value["source"]) or True)
            self.assertEqual(output, ["firewalld", "sshd"])
            self.assertEqual(dropped, 1)


if __name__ == "__main__":
    unittest.main()
