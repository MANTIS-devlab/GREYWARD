import tempfile
import unittest
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from greyward_security_context.application_security import SCHEMA as APPLICATION_SECURITY_SCHEMA

try:
    import greyward_security_context.user_bus as user_bus
except ModuleNotFoundError as error:
    if error.name == "gi" or str(error.name or "").startswith("dbus"):
        user_bus = None
    else:
        raise


@unittest.skipIf(user_bus is None, "Security Context runtime dependencies are unavailable on this host")
class UsbSummaryTests(unittest.TestCase):
    def test_dbus_thread_support_precedes_service_observer_construction(self):
        import greyward_security_context.session10_bus as session10
        for module, constructor in [(user_bus, 'SecurityContext'), (session10, 'Session10SecurityContext')]:
            with self.subTest(entrypoint=module.__name__):
                events = []
                with patch.object(module.dbus.mainloop.glib, 'threads_init', side_effect=lambda: events.append('threads')), \
                     patch.object(module.dbus.mainloop.glib, 'DBusGMainLoop'), \
                     patch.object(module.dbus, 'SessionBus'), patch.object(module.dbus.service, 'BusName'), \
                     patch.object(module, 'UsbContext', side_effect=lambda: events.append('usb')), \
                     patch.object(module, 'SensorContext'), patch.object(module, constructor), \
                     patch.object(module.GLib, 'MainLoop'):
                    module.main()
                self.assertEqual(events, ['threads', 'usb'])

    def test_safe_open_start_is_not_success_and_later_failure_replaces_it(self):
        context = object.__new__(user_bus.SecurityContext)
        context.usb = SimpleNamespace(events=[], telemetry=None)
        context.safe_open_processes = {}
        context.application_workflows = object()
        context._application_actor = lambda sender: (1002, 10, 123)
        outcomes = []
        context._record_file_security_event = lambda event, action, outcome, *args: outcomes.append(outcome)
        process = object()
        with patch.object(user_bus, "launch_safe_open", return_value=(process, Path("/synthetic/document.txt"))), patch.object(user_bus, "monitor_safe_open") as monitor:
            result = json.loads(context.SafeOpen("/synthetic/document.txt"))
            self.assertEqual(result["state"], "LAUNCHED")
            self.assertIn("Session protection remains separately reported", result["detail"])
            self.assertEqual(context.usb.events[0]["title"], "Safe Open starting")
            monitor.call_args.args[1](1)
        self.assertEqual(len(context.usb.events), 1)
        self.assertEqual(context.usb.events[0]["title"], "Safe Open context failed")
        self.assertEqual(context.safe_open_processes, {})
        self.assertEqual(outcomes, ["STARTED", "FAILURE"])

    def test_invalid_safe_open_input_keeps_its_typed_refusal(self):
        context = object.__new__(user_bus.SecurityContext)
        context.usb = SimpleNamespace(events=[], telemetry=None)
        context.application_workflows = object()
        context._application_actor = lambda sender: (1002, 10, 123)
        context._record_file_security_event = lambda *args, **kwargs: None
        with patch.object(user_bus, "launch_safe_open", side_effect=user_bus.SafeOpenError("Invalid selected file")):
            result = json.loads(context.SafeOpen("bad\0path"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "FAILED")
        self.assertNotIn("file_ref", context.usb.events[0])

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
    def test_local_history_forwarding_keeps_unavailable_distinct_from_empty(self):
        context = object.__new__(user_bus.SecurityContext)
        empty = {"schema": user_bus.local_activity.SCHEMA, "state": "AVAILABLE", "items": []}
        with patch.object(user_bus.local_activity, "read", return_value=empty):
            self.assertEqual(json.loads(context.GetLocalActivity()), empty)
        with patch.object(user_bus.local_activity, "read", side_effect=user_bus.TelemetryError("unavailable")):
            self.assertIsNone(json.loads(context.GetLocalActivity())["items"])
        with patch.object(user_bus.local_activity, "record", return_value=empty) as writer:
            self.assertEqual(json.loads(context.RecordLocalActivity('{"fixed":"metadata"}')), empty)
            writer.assert_called_once_with('{"fixed":"metadata"}')
        with patch.object(user_bus.local_activity, "clear", side_effect=user_bus.TelemetryError("failed readback")):
            self.assertEqual(json.loads(context.ClearLocalActivity())["state"], "UNAVAILABLE")

    def test_application_read_adapter_preserves_typed_arguments_and_unavailable_state(self):
        context = object.__new__(user_bus.SecurityContext)
        unavailable = {"schema": APPLICATION_SECURITY_SCHEMA,
                       "source_state": {"state": "UNAVAILABLE", "reason": "BROKER_UNAVAILABLE"}, "projection": None}
        reference = "installation_" + "a" * 64
        with patch.object(user_bus, "ApplicationSecurityReads") as factory:
            factory.return_value.coverage.return_value = unavailable
            factory.return_value.applications.return_value = unavailable
            factory.return_value.application.return_value = unavailable
            self.assertEqual(json.loads(context.GetApplicationCoverage()), unavailable)
            self.assertEqual(json.loads(context.ListApplications(10, True, 2, reference)), unavailable)
            factory.return_value.applications.assert_called_once_with(10, True, 2, reference)
            self.assertEqual(json.loads(context.GetApplication(reference)), unavailable)
            factory.return_value.application.assert_called_once_with(reference)
            factory.return_value.application.side_effect = user_bus.ApplicationReadError("INVALID_REQUEST")
            self.assertIsNone(json.loads(context.GetApplication("../secret"))["projection"])

    def test_history_reads_do_not_import_or_mutate_storage(self):
        store = SimpleNamespace(
            query=lambda filters, **options: {"read_only": options["read_only"], "events": []},
            related=lambda identity, limit, **options: {"read_only": options["read_only"], "events": []},
        )
        with patch.object(user_bus, "user_store", return_value=store), \
                patch.object(user_bus, "import_root_spool", side_effect=AssertionError("Read attempted import")):
            self.assertTrue(user_bus.telemetry_query('{}')["read_only"])
            self.assertTrue(user_bus.telemetry_related('{"event_id":"event"}')["read_only"])
            self.assertEqual(user_bus.telemetry_related('{}')["source_state"]["state"], "UNAVAILABLE")

    def test_history_reconciliation_migrates_only_the_existing_store(self):
        calls = []
        store = SimpleNamespace(reconcile_findings=lambda: calls.append("migrate") or {"complete": True, "processed": 0})
        with patch.object(user_bus, "user_store", return_value=store), \
                patch.object(user_bus, "import_root_spool", side_effect=lambda selected: calls.append("import") or {}), \
                patch.object(user_bus.local_activity, "migrate", return_value={"complete": True, "processed": 0}):
            context = object.__new__(user_bus.SecurityContext)
            self.assertEqual(context.reconcile_history()["state"], "AVAILABLE")
        self.assertEqual(calls, ["import", "migrate"])

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

    def test_shared_checks_keep_center_posture_despite_detail_transport_failure(self):
        checks = [{"check_id": "devices.usbguard.posture", "state": "PROTECTED", "accepted_deviation": True}]
        canonical = {"state": "PROTECTED", "review_count": 0, "unavailable_count": 1,
                     "attention_count": 1, "detail": "Shared evaluator", "checks": checks}
        value = {"state": "UNAVAILABLE", "live_states": [{"kind": "USB", "state": "UNAVAILABLE"}],
                 "review_count": 3, "unavailable_count": 3}
        with patch.object(user_bus, "authoritative_posture", return_value=canonical):
            result = user_bus.apply_authoritative_posture(value)
        self.assertEqual(result["state"], "PROTECTED")
        self.assertEqual(result["evaluated_checks"], checks)
        self.assertEqual(result["review_count"], 0)
        self.assertEqual(result["unavailable_count"], 1)
        self.assertEqual(result["live_states"][0]["state"], "UNAVAILABLE")

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
