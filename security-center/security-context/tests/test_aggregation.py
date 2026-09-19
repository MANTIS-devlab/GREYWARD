import tempfile
import unittest
import datetime as dt
from pathlib import Path

from greyward_security_context.aggregation import build_security_digest
from greyward_security_context.telemetry import TelemetryStore, event


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
            state = {"source_state": "AVAILABLE", "devices": [{"identity_id": "usb-hmac-1", "identity_confidence": "HIGH", "name": "Unknown USB", "device_class": "EXTERNAL_UNKNOWN", "trusted": False, "reviewed": False, "connected": False, "state": "ALLOW", "first_seen": "2026-08-26T10:00:00Z", "last_seen": "2026-08-26T10:00:00Z"}]}
            digest = build_security_digest(store=store, device_state=state, now_value=dt.datetime(2026, 8, 27, tzinfo=dt.timezone.utc))
            self.assertEqual(digest["unresolved_count"], 0)
            self.assertEqual(digest["devices"]["new_unknown_count"], 1)

    def test_connected_unknown_device_is_one_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            store = TelemetryStore(Path(directory) / "events.sqlite3")
            state = {"source_state": "AVAILABLE", "devices": [{"identity_id": "usb-hmac-1", "identity_confidence": "HIGH", "name": "Unknown USB", "device_class": "EXTERNAL_UNKNOWN", "trusted": False, "reviewed": False, "connected": True, "state": "ALLOW", "first_seen": "2026-08-26T10:00:00Z", "last_seen": "2026-08-26T10:00:00Z"}]}
            first = build_security_digest(store=store, device_state=state)
            second = build_security_digest(store=store, device_state=state)
            self.assertEqual(first["unresolved_count"], 1)
            self.assertEqual(second["unresolved_count"], 1)
            self.assertEqual(first["unresolved_findings"][0]["finding_id"], second["unresolved_findings"][0]["finding_id"])


if __name__ == "__main__":
    unittest.main()
