import tempfile
import unittest
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

try:
    import greyward_security_context.user_bus as user_bus
except ModuleNotFoundError as error:
    if error.name == "gi" or str(error.name or "").startswith("dbus"):
        user_bus = None
    else:
        raise


@unittest.skipIf(user_bus is None, "Security Context runtime dependencies are unavailable on this host")
class UsbSummaryTests(unittest.TestCase):
    def test_summary_reuses_the_usbguard_snapshot_for_device_overview(self):
        context = object.__new__(user_bus.UsbContext)
        calls = []

        class Adapter:
            def list_devices(self):
                calls.append(True)
                return []

        context.adapter = Adapter()
        context.events = []
        context.blocked = set()
        context.telemetry = SimpleNamespace(
            list_devices=lambda: {"devices": []},
            sync_devices=lambda observations: {"devices": []},
        )

        with tempfile.TemporaryDirectory() as directory:
            with patch.object(user_bus, "STATE_PATH", Path(directory) / "missing-summary.json"):
                context.summary()

        self.assertEqual(len(calls), 1)


@unittest.skipIf(user_bus is None, "Security Context runtime dependencies are unavailable on this host")
class BoundedProbeCacheTests(unittest.TestCase):
    def test_explicit_invalidation_clears_all_mutable_state_caches(self):
        context = object.__new__(user_bus.SecurityContext)
        context._summary_cache = "cached-summary"
        context._summary_cache_at = 123.0
        context._summary_cache_lock = user_bus.threading.Lock()
        previous_posture = user_bus._AUTHORITATIVE_POSTURE_CACHE
        previous_network = user_bus._NETWORK_HEALTH_CACHE
        try:
            user_bus._AUTHORITATIVE_POSTURE_CACHE = (123.0, {"state": "PROTECTED"})
            user_bus._NETWORK_HEALTH_CACHE = (123.0, (True, True))
            context._invalidate_caches()
            self.assertIsNone(context._summary_cache)
            self.assertEqual(0.0, context._summary_cache_at)
            self.assertIsNone(user_bus._AUTHORITATIVE_POSTURE_CACHE)
            self.assertIsNone(user_bus._NETWORK_HEALTH_CACHE)
        finally:
            user_bus._AUTHORITATIVE_POSTURE_CACHE = previous_posture
            user_bus._NETWORK_HEALTH_CACHE = previous_network

    def test_authoritative_posture_reuses_a_recent_result(self):
        previous = user_bus._AUTHORITATIVE_POSTURE_CACHE
        try:
            user_bus._AUTHORITATIVE_POSTURE_CACHE = None
            result = SimpleNamespace(
                stdout=json.dumps(
                    {
                        "posture": {"state": "PROTECTED"},
                        "metrics": {"review_needed": 0, "unavailable": 0},
                    }
                )
            )
            with patch.object(user_bus.subprocess, "run", return_value=result) as run:
                first = user_bus.authoritative_posture()
                second = user_bus.authoritative_posture()

            self.assertEqual(first, second)
            run.assert_called_once()
        finally:
            user_bus._AUTHORITATIVE_POSTURE_CACHE = previous

    def test_network_service_health_reuses_both_liveness_probes(self):
        previous = user_bus._NETWORK_HEALTH_CACHE
        try:
            user_bus._NETWORK_HEALTH_CACHE = None
            with patch.object(user_bus, "_service_active", side_effect=[True, True]) as probe:
                first = user_bus._network_service_health()
                second = user_bus._network_service_health()

            self.assertEqual((True, True), first)
            self.assertEqual(first, second)
            self.assertEqual(2, probe.call_count)
        finally:
            user_bus._NETWORK_HEALTH_CACHE = previous


if __name__ == "__main__":
    unittest.main()
