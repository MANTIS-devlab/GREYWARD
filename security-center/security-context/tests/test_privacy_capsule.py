import unittest
import io
from datetime import datetime, timedelta, timezone

from greyward_security_context.privacy_capsule import PrivacyCapsule, clipboard_classification
from greyward_security_context.clipboard_watch import classify_stdin


class PrivacyCapsuleTests(unittest.TestCase):
    def setUp(self):
        self.start = datetime(2026, 9, 2, 12, 0, tzinfo=timezone.utc)

    def signal(self, state="INACTIVE", signal_id="microphone"):
        return {
            "signal_id": signal_id,
            "category": "ACTIVE_SENSOR",
            "capability": "SUPPORTED",
            "state": state,
            "title": "Microphone in use",
            "fresh_until": "2026-09-02T12:00:08Z",
        }

    def test_initial_active_state_does_not_create_new_event(self):
        capsule = PrivacyCapsule(session_epoch="test")
        capsule.update([self.signal("ACTIVE")], self.start)
        first = capsule.snapshot(self.start)
        self.assertEqual(first["active_count"], 1)
        self.assertEqual(first["recent_events"], [])
        self.assertFalse(first["has_new_event"])

    def test_transition_keeps_event_id_and_generation_across_reads(self):
        capsule = PrivacyCapsule(session_epoch="test")
        capsule.update([self.signal()], self.start)
        self.assertTrue(capsule.update([self.signal("ACTIVE")], self.start.replace(second=1)))
        first = capsule.snapshot(self.start.replace(second=1))
        second = capsule.snapshot(self.start.replace(second=2))
        active_first = next(item for item in first["signals"] if item["state"] == "ACTIVE")
        active_second = next(item for item in second["signals"] if item["state"] == "ACTIVE")
        self.assertEqual(active_first["event_id"], active_second["event_id"])
        self.assertEqual(active_first["generation"], active_second["generation"])
        self.assertEqual(len(first["recent_events"]), 1)

    def test_recent_events_are_bounded_and_expire(self):
        capsule = PrivacyCapsule(session_epoch="test")
        capsule.update([self.signal()], self.start)
        capsule.update([self.signal("ACTIVE")], self.start.replace(second=1))
        capsule.update([self.signal()], self.start.replace(second=2))
        self.assertEqual(len(capsule.snapshot(self.start.replace(second=2))["recent_events"]), 2)
        self.assertEqual(capsule.snapshot(self.start + timedelta(seconds=63))["recent_events"], [])

    def test_expired_supported_activity_becomes_stale(self):
        capsule = PrivacyCapsule(session_epoch="test")
        stale = self.signal("ACTIVE")
        stale["fresh_until"] = "2026-09-02T11:59:59Z"
        capsule.update([stale], self.start)
        current = capsule.snapshot(self.start)
        signal = next(item for item in current["signals"] if item["signal_id"] == "microphone")
        self.assertEqual(signal["capability"], "SUPPORTED")
        self.assertEqual(signal["state"], "STALE")
        self.assertEqual(current["active_count"], 0)

    def test_clipboard_classifier_does_not_return_content(self):
        self.assertEqual(clipboard_classification("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"), "PRIVATE_KEY")
        self.assertEqual(clipboard_classification("api_key=ghp_123456789012345678"), "STRUCTURED_CREDENTIAL")
        self.assertEqual(clipboard_classification("ordinary text with high entropy abcdef0123456789"), None)
        self.assertIsNone(clipboard_classification("x" * (256 * 1024 + 1)))

    def test_clipboard_observer_accepts_text_only_and_returns_metadata(self):
        stream = io.TextIOWrapper(io.BytesIO(b"password=example-secret"), encoding="utf-8")
        self.assertEqual(classify_stdin(stream), {"category": "STRUCTURED_CREDENTIAL"})
        binary = io.TextIOWrapper(io.BytesIO(b"\xff\xfe"), encoding="utf-8", errors="ignore")
        self.assertEqual(classify_stdin(binary), {"category": None})

    def test_screen_share_contract_has_a_distinct_category(self):
        capsule = PrivacyCapsule(session_epoch="test")
        screen = self.signal("ACTIVE", "screen-share:browser")
        screen["category"] = "SCREEN_SHARE"
        screen["title"] = "Screen sharing active"
        capsule.update([screen], self.start)
        current = capsule.snapshot(self.start)
        self.assertEqual(current["signals"][0]["category"], "SCREEN_SHARE")
        self.assertEqual(current["signals"][0]["state"], "ACTIVE")


if __name__ == "__main__":
    unittest.main()
