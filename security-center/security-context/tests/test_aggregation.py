import tempfile
import unittest
import datetime as dt
import sqlite3
from contextlib import closing
from unittest import mock
from pathlib import Path

from greyward_security_context.aggregation import build_security_digest
from greyward_security_context.telemetry import TelemetryStore, event, stamp


class AggregationTests(unittest.TestCase):
    def test_blocked_network_is_not_an_unresolved_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            store = TelemetryStore(Path(directory) / "events.sqlite3")
            store.record(event(event_id="blocked", component="opensnitch", source="opensnitch", category="NETWORK", event_type="CONNECTION_ATTEMPT", action="CONNECT", outcome="BLOCKED", decision="BLOCKED", application="browser", destination={"host": "example.test"}))
            digest = build_security_digest(store=store)
            self.assertEqual(digest["unresolved_count"], 0)
            self.assertEqual(digest["network"]["blocked_recent"], 1)

    def test_naive_runtime_timestamp_does_not_break_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            store = TelemetryStore(Path(directory) / "events.sqlite3")
            store.record(event(
                event_id="runtime-naive-time",
                occurred_at="2026-08-28 20:00:00",
                component="opensnitch",
                source="opensnitch-statistics",
                category="NETWORK",
                event_type="CONNECTION_ATTEMPT",
                action="CONNECT",
                outcome="ALLOWED",
                decision="ALLOWED",
                application="browser",
                destination={"host": "example.test"},
            ))
            digest = build_security_digest(store=store)
            self.assertEqual(digest["source_state"]["state"], "AVAILABLE")

    def test_disconnected_unknown_device_is_history_not_active_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            store = TelemetryStore(Path(directory) / "events.sqlite3")
            store.sync_devices([{"identity_id": "usb-hmac-1", "identity_confidence": "HIGH", "name": "Unknown USB", "device_class": "EXTERNAL_UNKNOWN", "trusted": False, "state": "ALLOW", "observed_at": "2026-08-26T10:00:00Z"}])
            store.sync_devices([])
            state = {"source_state": "AVAILABLE", "devices": [{"identity_id": "usb-hmac-1", "identity_confidence": "HIGH", "name": "Unknown USB", "device_class": "EXTERNAL_UNKNOWN", "trusted": False, "reviewed": False, "connected": False, "state": "ALLOW", "first_seen": "2026-08-26T10:00:00Z", "last_seen": "2026-08-26T10:00:00Z"}]}
            digest = build_security_digest(store=store, device_state=state, now_value=dt.datetime(2026, 8, 27, tzinfo=dt.timezone.utc))
            self.assertEqual(digest["unresolved_count"], 0)
            self.assertEqual(digest["devices"]["new_unknown_count"], 1)

    def test_connected_unknown_device_is_one_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            store = TelemetryStore(Path(directory) / "events.sqlite3")
            state = {"source_state": "AVAILABLE", "devices": [{"identity_id": "usb-hmac-1", "identity_confidence": "HIGH", "name": "Unknown USB", "device_class": "EXTERNAL_UNKNOWN", "trusted": False, "reviewed": False, "connected": True, "state": "ALLOW", "first_seen": "2026-08-26T10:00:00Z", "last_seen": "2026-08-26T10:00:00Z"}]}
            store.sync_devices(state["devices"])
            first = build_security_digest(store=store, device_state=state)
            second = build_security_digest(store=store, device_state=state)
            self.assertEqual(first["unresolved_count"], 1)
            self.assertEqual(second["unresolved_count"], 1)
            self.assertEqual(first["unresolved_findings"][0]["finding_id"], second["unresolved_findings"][0]["finding_id"])

    @staticmethod
    def failure(identifier="failure", when=None):
        return event(event_id=identifier, occurred_at=when, component="updates", source="update-center",
                     category="UPDATE", event_type="UPDATE_PHASE", action="APPLY", outcome="FAILED",
                     correlation={"transaction_id": "tx-1"}, details={"error": "failure token=private"})

    def test_failure_is_ingested_atomically_and_reads_or_replay_do_not_reopen_it(self):
        with tempfile.TemporaryDirectory() as directory:
            store = TelemetryStore(Path(directory) / "events.sqlite3")
            value = self.failure()
            store.record(value)
            finding = store.list_findings()[0]
            self.assertNotIn("private", finding["summary"])
            self.assertEqual(finding["state"], "UNRESOLVED")
            finding.update(state="RESOLVED", resolved_at=stamp())
            store.upsert_finding(finding)
            store.record(value)
            with mock.patch.object(store, "_connect", side_effect=AssertionError("Projection attempted a writer connection")):
                for _ in range(2):
                    self.assertEqual(build_security_digest(store=store)["unresolved_count"], 0)
            self.assertEqual(store.list_findings()[0]["state"], "RESOLVED")
            with closing(store._connect_readonly()) as connection:
                with self.assertRaises(sqlite3.OperationalError):
                    connection.execute("DELETE FROM findings")

    def test_missing_or_corrupt_history_stays_unavailable_without_creating_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "absent" / "events.sqlite3"
            self.assertEqual(build_security_digest(store=TelemetryStore(path))["source_state"]["state"], "UNAVAILABLE")
            self.assertFalse(path.parent.exists())
            corrupt = Path(directory) / "corrupt.sqlite3"
            corrupt.write_bytes(b"invalid SQLite bytes")
            self.assertEqual(build_security_digest(store=TelemetryStore(corrupt))["source_state"]["state"], "UNAVAILABLE")
            self.assertEqual(corrupt.read_bytes(), b"invalid SQLite bytes")

    def test_device_reconciliation_and_review_own_finding_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            store = TelemetryStore(Path(directory) / "events.sqlite3")
            store.sync_devices([{"identity_id": "device", "device_class": "EXTERNAL_UNKNOWN", "trusted": False}])
            self.assertEqual(store.list_findings()[0]["state"], "UNRESOLVED")
            store.sync_devices([], source_quality="UNAVAILABLE")
            self.assertEqual(store.list_findings()[0]["state"], "UNRESOLVED")
            store.sync_devices([])
            self.assertEqual(store.list_findings()[0]["state"], "HISTORY_ONLY")
            store.sync_devices([{"identity_id": "device", "device_class": "EXTERNAL_UNKNOWN", "trusted": False}])
            self.assertTrue(store.set_device_reviewed("device"))
            self.assertEqual(store.list_findings()[0]["state"], "RESOLVED")
            self.assertEqual(build_security_digest(store=store)["unresolved_count"], 0)

    def test_legacy_finding_backfill_resumes_across_vacuum_and_preserves_resolution(self):
        with tempfile.TemporaryDirectory() as directory:
            store = TelemetryStore(Path(directory) / "events.sqlite3")
            with mock.patch("greyward_security_context.telemetry.event_finding", return_value=None):
                store.record_many([self.failure("a"), self.failure("b"), self.failure("c")])
            self.assertEqual(build_security_digest(store=store)["unresolved_count"], 0)
            self.assertEqual(store.reconcile_findings(limit=1), {"complete": False, "processed": 1})
            finding = store.list_findings()[0]
            finding.update(state="RESOLVED", resolved_at=stamp())
            store.upsert_finding(finding)
            connection = store._connect()
            connection.execute("VACUUM")
            connection.close()
            self.assertFalse(store.reconcile_findings(limit=1)["complete"])
            self.assertFalse(store.reconcile_findings(limit=1)["complete"])
            self.assertTrue(store.reconcile_findings(limit=1)["complete"])
            self.assertEqual(store.list_findings()[0]["state"], "RESOLVED")
            self.assertEqual(store.reconcile_findings(), {"complete": True, "processed": 0})

    def test_interrupted_backfill_does_not_advance_its_cursor(self):
        with tempfile.TemporaryDirectory() as directory:
            store = TelemetryStore(Path(directory) / "events.sqlite3")
            with mock.patch("greyward_security_context.telemetry.event_finding", return_value=None):
                store.record(self.failure())
            with mock.patch.object(store, "_upsert_finding", side_effect=RuntimeError("Interrupted worker")):
                with self.assertRaises(RuntimeError):
                    store.reconcile_findings()
            self.assertEqual(store.reconcile_findings(), {"complete": True, "processed": 1})
            self.assertEqual(len(store.list_findings()), 1)


if __name__ == "__main__":
    unittest.main()
