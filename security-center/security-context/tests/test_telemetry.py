import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from greyward_security_context.telemetry import TelemetryError, TelemetryStore, derive_device_identity, event, import_root_spool, spool_event


def make_event(index, *, retention="investigation", occurred=None, details=None):
    return event(
        event_id=f"event-{index}",
        # Keep ordinary fixture events inside the retention window regardless
        # of the wall clock on the developer or Fedora build host. Tests that
        # exercise expiry provide an explicit historical timestamp below.
        occurred_at=occurred or "2099-01-01T10:00:00Z",
        component="test",
        source="fixture",
        category="TEST",
        event_type="OBSERVATION",
        action="OBSERVE",
        outcome="SUCCESS",
        application="fixture-app",
        correlation={"operation_id": "operation-1"},
        details=details or {"index": index},
        retention_class=retention,
    )


class TelemetryStoreTests(unittest.TestCase):
    def test_forensic_filters_and_size_limited_pages_keep_every_matching_row(self):
        with tempfile.TemporaryDirectory() as directory:
            store = TelemetryStore(Path(directory) / "events.sqlite3")
            for i in range(8):
                value = make_event(i, details={"pid": 42, "process_key": f"k-{i % 2}", "rule_name": "Office_Allow"})
                value.update(category="NETWORK", port=443, destination={"ip": "2001:db8::1", "host": "example.test"})
                store.record(value)
            filters = {"category": "NETWORK", "port": 443, "pid": 42, "process_key": "k-0",
                       "destination_ip": "2001:db8::1", "search": "office_allow", "limit": 4}
            with patch("greyward_security_context.telemetry.MAX_QUERY_BYTES", 2300):
                first = store.query(filters, read_only=True)
                self.assertTrue(first["size_limited"])
                found = [item["event_id"] for item in first["events"]]
                while first["next_cursor"]:
                    first = store.query({**filters, "cursor": first["next_cursor"]}, read_only=True)
                    found.extend(item["event_id"] for item in first["events"])
            self.assertEqual(found, ["event-6", "event-4", "event-2", "event-0"])
            self.assertEqual(store.query({**filters, "search": "office%allow"})["events"], [])
            related = store.related("event-0", 2, read_only=True)
            self.assertEqual([item["event_id"] for item in related["events"]], ["event-0", "event-6", "event-4"])
            self.assertEqual({rel["relation"] for rel in related["events"][0]["relations"]}, {"SAME_PROCESS_INSTANCE"})

    def test_spool_appends_before_rotation_and_imports_complete_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spool = root / "events.jsonl"
            self.assertTrue(spool_event(make_event(1), spool))
            original = spool.read_bytes()
            before = spool.stat().st_ino
            with spool.open("ab") as stream:
                stream.write(b'{"interrupted"')
            store = TelemetryStore(root / "db.sqlite3")
            self.assertEqual(import_root_spool(store, spool)["invalid"], 0)
            self.assertTrue(spool_event(make_event(2), spool))
            self.assertEqual(spool.stat().st_ino, before)
            self.assertTrue(spool.read_bytes().startswith(original))
            with patch("greyward_security_context.telemetry.MAX_ROOT_SPOOL_BYTES", len(original) * 4):
                for i in range(3, 16):
                    self.assertTrue(spool_event(make_event(i), spool))
                self.assertLessEqual(spool.stat().st_size, len(original) * 4)
            self.assertEqual(json.loads(spool.read_bytes().splitlines()[-1])["event_id"], "event-15")

    def test_security_scope_filters_network_before_limit_and_preserves_pagination(self):
        with tempfile.TemporaryDirectory() as directory:
            store = TelemetryStore(Path(directory) / "events.sqlite3")
            for index in range(8):
                value = make_event(index, occurred=f"2099-01-01T10:00:0{index}Z")
                value["category"] = "NETWORK" if index >= 4 else "RECOVERY"
                store.record(value)
            first = store.query({"scope": "SECURITY", "limit": 2})
            second = store.query({"scope": "SECURITY", "limit": 2, "cursor": first["next_cursor"]})
            self.assertEqual([item["event_id"] for item in first["events"]], ["event-3", "event-2"])
            self.assertEqual([item["event_id"] for item in second["events"]], ["event-1", "event-0"])
            self.assertIsNone(second["next_cursor"])
            self.assertEqual(len(store.query({"category": "NETWORK"})["events"]), 4)
            with self.assertRaises(TelemetryError):
                store.query({"scope": "arbitrary SQL"})

    def test_device_identity_is_keyed_and_uncertain_without_stable_material(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "identity.key"
            metadata = {"stable_id": "serial-value", "vendor_id": "1234", "product_id": "5678", "device_class": "EXTERNAL_STORAGE"}
            first, confidence = derive_device_identity(metadata, key)
            second, same_confidence = derive_device_identity(metadata, key)
            other, _ = derive_device_identity({**metadata, "stable_id": "other"}, key)
            low, low_confidence = derive_device_identity({"device_class": "EXTERNAL_UNKNOWN"}, key)
            self.assertEqual(first, second)
            self.assertEqual(confidence, same_confidence)
            self.assertNotEqual(first, other)
            self.assertIsNone(low)
            self.assertEqual(low_confidence, "LOW")
            port_only, port_confidence = derive_device_identity({"via_port": "1-2", "device_class": "EXTERNAL_UNKNOWN"}, key)
            self.assertIsNone(port_only)
            self.assertEqual(port_confidence, "LOW")
            self.assertNotIn(b"serial-value", key.read_bytes())

    def test_network_history_filters_by_search_and_decision(self):
        with tempfile.TemporaryDirectory() as directory:
            store = TelemetryStore(Path(directory) / "events.sqlite3")
            for event_id, host, decision in (("allowed", "safe.test", "ALLOWED"), ("blocked", "bad.test", "BLOCKED")):
                store.record(event(event_id=event_id, component="opensnitch", source="opensnitch", category="NETWORK", event_type="CONNECTION_ATTEMPT", action="CONNECT", outcome=decision, application="browser", destination={"host": host, "ip": "192.0.2.1", "port": 443}, protocol="tcp", port=443, decision=decision))
            result = store.query({"category": "NETWORK", "search": "bad.test", "decision": "BLOCKED"})
            self.assertEqual([item["event_id"] for item in result["events"]], ["blocked"])

    def test_findings_are_stable_and_filterable(self):
        with tempfile.TemporaryDirectory() as directory:
            store = TelemetryStore(Path(directory) / "events.sqlite3")
            store.upsert_finding({"finding_id": "update_failure:tx-1", "kind": "UPDATE_FAILURE", "subject_key": "tx-1", "state": "UNRESOLVED", "severity": "ERROR", "title": "Update failed", "summary": "The update failed.", "destination": "updates", "evidence": ["event-1"]})
            store.upsert_finding({"finding_id": "device-unknown:usb-1", "kind": "UNKNOWN_EXTERNAL_DEVICE", "subject_key": "usb-1", "state": "HISTORY_ONLY", "severity": "WARNING", "title": "Unknown device", "summary": "Recent device.", "destination": "devices"})
            findings = store.list_findings(unresolved_only=True)
            self.assertEqual([item["finding_id"] for item in findings], ["update_failure:tx-1"])
    def test_persisted_event_is_semantic_and_redacted(self):
        with tempfile.TemporaryDirectory() as directory:
            store = TelemetryStore(Path(directory) / "events.sqlite3")
            value = make_event(1, details={"reason": "blocked", "password": "do-not-store", "message": "token=private-value"})
            store.record(value)
            result = store.query({"category": "TEST"})
            self.assertEqual(len(result["events"]), 1)
            details = json.dumps(result["events"][0]["details"])
            self.assertNotIn("do-not-store", details)
            self.assertNotIn("private-value", details)
            self.assertEqual(result["events"][0]["retention_class"], "investigation")

    def test_network_history_keeps_only_the_approved_projection(self):
        with tempfile.TemporaryDirectory() as directory:
            store = TelemetryStore(Path(directory) / "events.sqlite3")
            value = event(
                event_id="network-1",
                component="opensnitch-control-plane",
                source="opensnitch",
                category="NETWORK",
                event_type="CONNECTION_ATTEMPT",
                action="CONNECT",
                outcome="BLOCKED",
                application="curl",
                destination={"host": "example.test", "ip": "192.0.2.10", "port": 443, "url": "https://example.test/private"},
                protocol="tcp",
                port=443,
                decision="BLOCKED",
                details={"rule_name": "deny", "args": "--token secret", "env": "SECRET=hidden", "url": "/private"},
            )
            store.record(value)
            saved = store.query({"category": "NETWORK"})["events"][0]
            self.assertEqual(saved["destination"], {"host": "example.test", "ip": "192.0.2.10", "port": 443})
            self.assertEqual(saved["details"], {"rule_name": "deny"})

    def test_query_supports_deterministic_cursor_pagination(self):
        with tempfile.TemporaryDirectory() as directory:
            store = TelemetryStore(Path(directory) / "events.sqlite3")
            for index in range(4):
                store.record(make_event(index, occurred=f"2099-01-01T10:00:0{index}Z"))
            first = store.query({"limit": 2})
            self.assertTrue(first["truncated"])
            second = store.query({"limit": 2, "cursor": first["next_cursor"]})
            self.assertEqual({item["event_id"] for item in first["events"]} & {item["event_id"] for item in second["events"]}, set())
            self.assertEqual(len(second["events"]), 2)

    def test_related_events_are_bounded_and_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            store = TelemetryStore(Path(directory) / "events.sqlite3")
            root = make_event(1)
            child = make_event(2)
            child["relations"] = [{"event_id": root["event_id"], "relation": "CAUSED_BY", "confidence": "EXACT", "basis": "operation_id"}]
            store.record(root)
            store.record(child)
            result = store.related(root["event_id"])
            self.assertEqual({item["event_id"] for item in result["events"]}, {"event-1", "event-2"})

    def test_expired_and_size_pressure_events_are_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.sqlite3"
            store = TelemetryStore(path, max_bytes=128 * 1024)
            old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=40)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            store.record(make_event(1, retention="semantic", occurred=old))
            for index in range(20):
                store.record(make_event(index + 2, details={"payload": "x" * 240}))
            result = store.query({"limit": 512})
            self.assertNotIn("event-1", {item["event_id"] for item in result["events"]})
            self.assertLessEqual(store.status()["size_bytes"], 128 * 1024)

    def test_root_spool_imports_into_user_history_without_sharing_root_database(self):
        with tempfile.TemporaryDirectory() as directory:
            spool = Path(directory) / "runtime" / "events.jsonl"
            user_db = Path(directory) / "user" / "events.sqlite3"
            value = make_event(99, details={"reason": "root event", "token": "never-persist"})
            self.assertTrue(spool_event(value, spool))
            user_store = TelemetryStore(user_db)
            result = import_root_spool(user_store, spool)
            self.assertEqual(result["state"], "AVAILABLE")
            self.assertEqual(result["imported"], 1)
            saved = user_store.query({"category": "TEST"})["events"]
            self.assertEqual([item["event_id"] for item in saved], ["event-99"])
            self.assertNotIn("never-persist", json.dumps(saved))
            self.assertLessEqual(spool.stat().st_size, 2 * 1024 * 1024)

    def test_root_spool_import_uses_one_batch_write(self):
        class CountingStore(TelemetryStore):
            def __init__(self, path):
                super().__init__(path)
                self.batch_calls = 0

            def record_many(self, values):
                self.batch_calls += 1
                return super().record_many(values)

        with tempfile.TemporaryDirectory() as directory:
            spool = Path(directory) / "runtime" / "events.jsonl"
            user_store = CountingStore(Path(directory) / "user" / "events.sqlite3")
            for index in range(4):
                self.assertTrue(spool_event(make_event(index), spool))
            result = import_root_spool(user_store, spool)
            self.assertEqual(result["imported"], 4)
            self.assertEqual(user_store.batch_calls, 1)


if __name__ == "__main__":
    unittest.main()
