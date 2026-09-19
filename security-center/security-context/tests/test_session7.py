import json
import tempfile
import unittest
from unittest.mock import patch
from datetime import datetime, timezone
from pathlib import Path

from greyward_security_context.persistence import PersistenceMonitor, diff, snapshot
from greyward_security_context.summaries import weekly_summary


class Session7SummaryTests(unittest.TestCase):
    def test_weekly_summary_is_deterministic_and_aggregates_evidence(self):
        end = datetime(2026, 8, 22, tzinfo=timezone.utc)
        events = [
            {"event_id": "ssh-1", "kind": "INBOUND_ATTACK_ACTIVITY", "occurred_at": "2026-08-21T12:00:00Z", "detail": "private host"},
            {"event_id": "app-1", "kind": "APP_CONNECTION_BLOCKED", "occurred_at": "2026-08-21T12:00:00Z", "detail": "/home/alice/secret"},
            {"event_id": "scan-1", "kind": "USB_SCAN_RESULT", "state": "CLEAN", "occurred_at": "2026-08-21T12:00:00Z", "detail": "/media/alice"},
        ]
        first = weekly_summary(events, window_end=end)
        self.assertEqual(first, weekly_summary(list(reversed(events)), window_end=end))
        self.assertEqual(first["lines"], ["Weekly security summary", "1 inbound security attempts blocked", "1 application connections blocked", "1 removable-media scans", "No known malware detected in available scan results"])
        self.assertNotIn("alice", json.dumps(first))

    def test_old_and_duplicate_events_are_excluded(self):
        end = datetime(2026, 8, 22, tzinfo=timezone.utc)
        events = [
            {"event_id": "old", "kind": "APP_CONNECTION_BLOCKED", "occurred_at": "2026-08-14T00:00:00Z"},
            {"event_id": "new", "kind": "APP_CONNECTION_BLOCKED", "occurred_at": "2026-08-21T00:00:00Z"},
            {"event_id": "new", "kind": "APP_CONNECTION_BLOCKED", "occurred_at": "2026-08-21T00:00:01Z"},
        ]
        self.assertEqual(weekly_summary(events, window_end=end)["counts"], {"APP_CONNECTION_BLOCKED": 1})


class Session7PersistenceTests(unittest.TestCase):
    def test_recent_observation_survives_read_and_restart_without_reemission(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / 'home'
            (home / '.config/autostart').mkdir(parents=True)
            monitor = PersistenceMonitor(home, Path(directory) / 'baseline.json')
            with patch('greyward_security_context.persistence.time.time', return_value=1000):
                monitor.scan()
                (home / '.config/autostart/test.desktop').write_text('[Desktop Entry]\n')
                self.assertEqual(len(monitor.scan()), 1)
                self.assertEqual(monitor.scan(), [])
                self.assertEqual(len(PersistenceMonitor(home, monitor.state_path).recent_changes()), 1)
            with patch('greyward_security_context.persistence.time.time', return_value=1301):
                self.assertEqual(monitor.recent_changes(), [])

    def test_baseline_add_remove_and_change(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            state = Path(directory) / "state.json"
            (home / ".config/autostart").mkdir(parents=True)
            (home / ".config/autostart/example.desktop").write_text("[Desktop Entry]\nType=Application\n", encoding="utf-8")
            monitor = PersistenceMonitor(home, state)
            self.assertEqual(monitor.scan(), [])
            self.assertEqual(PersistenceMonitor(home, state).scan(), [])
            self.assertEqual(monitor.scan(), [])
            (home / ".config/autostart/example.desktop").write_text("[Desktop Entry]\nType=Application\nX=1\n", encoding="utf-8")
            changed = monitor.scan()
            self.assertEqual([(item["category"], item["change"]) for item in changed], [("XDG autostart", "changed")])
            (home / ".config/autostart/new.desktop").write_text("[Desktop Entry]\n", encoding="utf-8")
            added = monitor.scan()
            self.assertEqual([(item["category"], item["change"]) for item in added], [("XDG autostart", "added")])
            (home / ".config/autostart/example.desktop").unlink()
            removed = monitor.scan()
            self.assertEqual([(item["category"], item["change"]) for item in removed], [("XDG autostart", "removed")])
            self.assertNotIn(str(home), json.dumps(removed))

    def test_snapshot_is_bounded_to_approved_surfaces(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            (home / ".config/autostart").mkdir(parents=True)
            (home / "unmonitored").mkdir()
            (home / "unmonitored/secret.desktop").write_text("secret", encoding="utf-8")
            result = snapshot(home)
            self.assertEqual(result["entries"], [])
            self.assertLessEqual(len(result["entries"]), 128)


if __name__ == "__main__":
    unittest.main()
