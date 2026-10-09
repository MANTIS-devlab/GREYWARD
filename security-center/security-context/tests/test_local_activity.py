import datetime as dt
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from greyward_security_context import local_activity
from greyward_security_context.telemetry import TelemetryError, TelemetryStore, event, stamp


def item(index, *, occurred=None, detail="Local presentation"):
    return {"event_id": f"action-{index}", "category": "Action", "severity": "Information",
            "occurred_at": occurred or dt.datetime.now(dt.timezone.utc).isoformat(),
            "title": "Local action", "detail": detail, "related_check_id": None}


class LocalActivityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "activity.json"
        self.store = TelemetryStore(Path(self.directory.name) / "history/events.sqlite3")
        selection = patch.object(local_activity, "legacy_path", return_value=self.path)
        selection.start()
        self.addCleanup(selection.stop)

    def test_transactional_migration_deduplicates_and_keeps_original_for_rollback(self):
        value = item(1)
        self.path.write_text(json.dumps([value, value]))
        original = self.path.read_bytes()
        self.assertEqual(local_activity.migrate(self.store)["processed"], 2)
        first = local_activity.read(self.store)
        self.assertEqual(len(first["items"]), 1)
        self.assertEqual(first["items"][0]["event_id"], value["event_id"])
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(local_activity.migrate(self.store)["processed"], 0)
        self.assertEqual(local_activity.read(self.store), first)
        records = self.store.query({"category": local_activity.CATEGORY})["events"]
        self.assertEqual(records[0]["outcome"], "OBSERVED")
        self.assertEqual(records[0]["quality"]["attribution"], "UNVERIFIED")
        self.assertFalse(records[0]["quality"]["authoritative"])
        self.assertEqual(records[0]["quality"]["origin"], "USER_PRESENTATION")
        self.assertEqual(records[0]["native_evidence"], {})
        self.assertEqual(self.store.list_findings(), [])

    def test_failed_commit_preserves_source_and_replay_has_no_partial_import(self):
        self.path.write_text(json.dumps([item(1), item(2)]))
        count = 0
        actual = self.store._record_value

        def interrupted(connection, value):
            nonlocal count
            count += 1
            if count == 2:
                raise sqlite3.OperationalError("synthetic interruption")
            actual(connection, value)

        with patch.object(self.store, "_record_value", side_effect=interrupted):
            with self.assertRaises(TelemetryError):
                local_activity.migrate(self.store)
        self.assertEqual(self.store.query({})["events"], [])
        self.assertTrue(self.path.is_file())
        self.assertEqual(local_activity.migrate(self.store)["processed"], 2)
        self.assertEqual(len(local_activity.read(self.store)["items"]), 2)

    def test_expired_entries_age_out_without_changing_the_semantic_retention(self):
        now = dt.datetime.now(dt.timezone.utc)
        old = item(1, occurred=(now - dt.timedelta(days=31)).isoformat())
        new = item(2, occurred=(now - dt.timedelta(days=29)).isoformat())
        self.path.write_text(json.dumps([old, new]))
        local_activity.migrate(self.store, now=now)
        self.assertEqual([value["event_id"] for value in local_activity.read(self.store)["items"]], [new["event_id"]])
        record = self.store.query({})["events"][0]
        self.assertEqual(record["retention_class"], "semantic")
        self.assertGreater(record["expires_at"], stamp(now))

    def test_clear_is_scoped_verified_and_does_not_resurrect_legacy_or_other_history(self):
        self.path.write_text(json.dumps([item(1)]))
        other = event(event_id="authoritative-fixture", component="usb", source="usbguard/dbus",
                      category="DEVICES", event_type="DEVICE_CONNECTED", action="CONNECT", outcome="SUCCESS")
        self.store.record(other)
        local_activity.record(json.dumps(item(2)), self.store)
        self.assertEqual(len(local_activity.read(self.store)["items"]), 2)
        self.assertEqual(local_activity.clear(self.store)["state"], "AVAILABLE")
        local_activity.migrate(self.store)
        self.assertEqual(local_activity.read(self.store)["items"], [])
        self.assertEqual([row["event_id"] for row in self.store.query({})["events"]], [other["event_id"]])
        self.assertTrue(self.path.exists())

    def test_metadata_redaction_precedes_chunking_and_preserves_bounded_detail(self):
        long = "x" * 153 + " token=example-secret /home/alice/private-file"
        local_activity.record(json.dumps(item(1, detail=long)), self.store)
        output = json.dumps(local_activity.read(self.store))
        self.assertNotIn("example-secret", output)
        self.assertNotIn("alice", output)
        self.assertIn("REDACTED", output)
        self.assertIn("PRIVATE_PATH", output)
        full = item(2, detail="a" * 320)
        local_activity.record(json.dumps(full), self.store)
        self.assertEqual(local_activity.read(self.store)["items"][-1]["detail"], full["detail"])

    def test_inventory_and_reply_stay_bounded_and_subsecond_order_survives(self):
        start = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)
        for index in range(70):
            local_activity.record(json.dumps(item(index, occurred=(start + dt.timedelta(microseconds=index)).isoformat())), self.store)
        values = local_activity.read(self.store)["items"]
        self.assertEqual(len(values), 64)
        self.assertEqual(values[0]["event_id"], "action-6")
        self.assertEqual(values[-1]["event_id"], "action-69")

    def test_projections_do_not_create_or_migrate_storage(self):
        with self.assertRaises(TelemetryError):
            local_activity.read(self.store)
        self.assertFalse(self.store.path.exists())
        self.assertFalse(self.path.exists())

    def test_forged_authority_unknown_fields_bad_time_and_invalid_classification_refused(self):
        now = dt.datetime.now(dt.timezone.utc)
        for change in ({"source": "kernel"}, {"decision": "BLOCKED"}, {"category": "APPLICATION_SECURITY"},
                       {"category": []}, {"occurred_at": "not-a-time"},
                       {"occurred_at": (now + dt.timedelta(minutes=5)).isoformat()},
                       {"related_check_id": "/home/alice/private"}, {"event_id": "../other"}):
            with self.subTest(change=change), self.assertRaises(TelemetryError):
                local_activity.normalize({**item(1), **change})

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "Linux descriptor checks")
    def test_symlink_hardlink_oversized_malformed_sources_are_retained_and_refused(self):
        target = self.path.with_name("original.json")
        target.write_text(json.dumps([item(1)]))
        self.path.symlink_to(target)
        with self.assertRaises(TelemetryError):
            local_activity.migrate(self.store)
        self.path.unlink()
        os.link(target, self.path)
        with self.assertRaises(TelemetryError):
            local_activity.migrate(self.store)
        self.path.unlink()
        for raw in (b"[", b"x" * (local_activity.MAX_INPUT_BYTES + 1), json.dumps([item(1)] * 65).encode()):
            self.path.write_bytes(raw)
            with self.assertRaises(TelemetryError):
                local_activity.migrate(self.store)
            self.assertEqual(self.path.read_bytes(), raw)


if __name__ == "__main__":
    unittest.main()
