import unittest
from datetime import datetime, timezone

from greyward_security_context.shell_summary import build_shell_summary


class ShellSummaryTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)

    def test_projection_keeps_canonical_posture_and_prioritizes_review(self):
        value = build_shell_summary(
            {
                "state": "REVIEW NEEDED",
                "review_count": 2,
                "generated_at": "2026-08-24T12:00:00Z",
                "fresh_until": "2026-08-24T12:02:00Z",
                "recent_events": [
                    {
                        "event_id": "opensnitch-1",
                        "kind": "APP_CONNECTION_BLOCKED",
                        "notification": "AGGREGATABLE",
                        "title": "Application connection blocked",
                        "detail": "/usr/bin/python3 was blocked from connecting to example.net:443.",
                    },
                    {
                        "event_id": "persist-1",
                        "kind": "PERSISTENCE_CHANGE_DETECTED",
                        "notification": "ACTION_REQUIRED",
                        "title": "Startup item changed",
                        "detail": "Review the startup item.",
                    },
                ],
                "live_states": [],
            },
            network={"opensnitch": {"state": "OPERATING"}, "activity": []},
            clamav={"status": "CURRENT", "database_age_seconds": 10},
            profile={"ok": True, "available": True, "profile": "STANDARD"},
            transaction={"phase": "COMPLETE"},
            secure_dns={"effective_policy": "SecureProvider", "effective_transport": "DoT", "provider": "quad9"},
            now_value=self.now,
        )
        self.assertEqual(value["schema"], "greyward.security.shell/v1")
        self.assertEqual(value["posture"]["state"], "REVIEW NEEDED")
        self.assertEqual(value["priority"]["kind"], "PERSISTENCE_CHANGE_DETECTED")
        self.assertNotIn("/usr/bin", value["priority"]["detail"])
        self.assertFalse(value["update"]["active"])
        self.assertEqual(value["network_profile"]["state"], "STANDARD")
        self.assertEqual(value["firewall"]["state"], "UNAVAILABLE")
        self.assertEqual(value["secure_dns"]["state"], "SECUREPROVIDER")
        self.assertEqual(value["secure_dns"]["transport"], "DOT")
        self.assertEqual(value["fresh_until"], "2026-08-24T12:00:30Z")

    def test_profile_and_firewall_are_available_when_profile_is_fresh(self):
        value = build_shell_summary(
            {"state": "PROTECTED", "fresh_until": "2026-08-24T12:02:00Z", "live_states": [], "recent_events": []},
            profile={"available": True, "profile": "PRIVATE", "firewall_zone": "Public"},
            secure_dns={"effective_policy": "SecureProvider", "effective_transport": "DoT", "provider": "quad9"},
            now_value=self.now,
        )
        self.assertEqual(value["network_profile"], {"state": "PRIVATE", "available": True})
        self.assertEqual(value["firewall"], {"state": "PUBLIC"})
        self.assertEqual(value["secure_dns"]["provider"], "quad9")

    def test_active_update_is_distinct_from_ready_or_terminal(self):
        base = {"state": "PROTECTED", "fresh_until": "2026-08-24T12:02:00Z", "live_states": [], "recent_events": []}
        active = build_shell_summary(base, transaction={"phase": "INSTALLING", "progress": 42}, now_value=self.now)
        ready = build_shell_summary(base, transaction={"phase": "READY_TO_RESTART"}, now_value=self.now)
        complete = build_shell_summary(base, transaction={"phase": "COMPLETE"}, now_value=self.now)
        self.assertTrue(active["update"]["active"])
        self.assertEqual(active["update"]["progress"], 42)
        self.assertFalse(ready["update"]["active"])
        self.assertEqual(ready["update"]["phase"], "READY_TO_RESTART")
        self.assertFalse(complete["update"]["active"])

    def test_threat_event_is_the_highest_priority_signal(self):
        value = build_shell_summary(
            {
                "state": "REVIEW NEEDED",
                "fresh_until": "2026-08-24T12:02:00Z",
                "live_states": [],
                "recent_events": [
                    {"event_id": "scan", "kind": "USB_SCAN_RESULT", "state": "THREAT", "title": "Threat detected"},
                    {"event_id": "block", "kind": "APP_CONNECTION_BLOCKED", "title": "Application blocked"},
                ],
            },
            now_value=self.now,
        )
        self.assertEqual(value["priority"]["severity"], "CRITICAL")

    def test_unavailable_context_does_not_preserve_stale_posture(self):
        value = build_shell_summary(
            {"state": "SECURE", "fresh_until": "2026-08-24T12:02:00Z", "live_states": [], "recent_events": []},
            profile={"ok": False, "available": False},
            now_value=self.now,
        )
        self.assertEqual(value["posture"]["state"], "SECURE")
        value = build_shell_summary(
            {"state": "UNAVAILABLE", "fresh_until": "2026-08-24T12:02:00Z", "live_states": [], "recent_events": []},
            now_value=self.now,
        )
        self.assertEqual(value["posture"]["state"], "UNAVAILABLE")
        self.assertEqual(value["fresh_until"], "2026-08-24T12:00:00Z")

    def test_stale_context_hides_dependent_values_and_actions(self):
        value = build_shell_summary(
            {
                "state": "REVIEW NEEDED",
                "review_count": 2,
                "unavailable_count": 1,
                "fresh_until": "2026-08-24T11:59:00Z",
                "live_states": [],
                "recent_events": [],
            },
            profile={"available": True, "profile": "PRIVATE"},
            security_digest={"unresolved_count": 9, "devices": {"connected_external": 2, "new_unknown_count": 1}},
            now_value=self.now,
        )
        self.assertEqual(value["freshness"], "STALE")
        self.assertEqual(value["posture"]["state"], "UNAVAILABLE")
        self.assertIsNone(value["posture"]["review_count"])
        self.assertIsNone(value["security"]["unresolved_count"])
        self.assertIsNone(value["security"]["external_devices"])
        self.assertFalse(value["capabilities"]["privacy_profile_change"])
        self.assertEqual(value["network_profile"]["state"], "UNAVAILABLE")
        self.assertEqual(value["firewall"]["state"], "UNAVAILABLE")
        self.assertEqual(value["secure_dns"]["state"], "UNAVAILABLE")
        self.assertIsNone(value["priority"])
        self.assertEqual(value["notification_events"], [])
        self.assertEqual(value["cached"]["posture"]["state"], "REVIEW NEEDED")


if __name__ == "__main__":
    unittest.main()
