import importlib
import importlib.machinery
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).parents[1]))


class FakeDictionary(dict):
    def __init__(self, values=None, signature=None):
        super().__init__(values or {})
        self.signature = signature


class FakeDbusException(Exception):
    pass


def load_update_center_bus():
    """Import the D-Bus service with the small API surface this unit test needs."""
    names = (
        "dbus",
        "dbus.service",
        "dbus.mainloop",
        "dbus.mainloop.glib",
        "gi",
        "gi.repository",
        "greyward_security_context.update_center",
        "greyward_security_context.update_center_bus",
    )
    missing = object()
    previous = {name: sys.modules.get(name, missing) for name in names}
    dbus = types.ModuleType("dbus")
    dbus.Boolean = bool
    dbus.Dictionary = FakeDictionary
    dbus.DBusException = FakeDbusException
    dbus.SystemBus = lambda: None
    service = types.ModuleType("dbus.service")
    service.Object = object
    service.method = lambda *args, **kwargs: lambda function: function
    mainloop = types.ModuleType("dbus.mainloop")
    glib = types.ModuleType("dbus.mainloop.glib")
    glib.DBusGMainLoop = lambda *args, **kwargs: None
    dbus.service = service
    dbus.mainloop = mainloop
    mainloop.glib = glib
    gi = types.ModuleType("gi")
    repository = types.ModuleType("gi.repository")
    repository.GLib = types.SimpleNamespace()
    gi.repository = repository
    sys.modules.update({
        "dbus": dbus,
        "dbus.service": service,
        "dbus.mainloop": mainloop,
        "dbus.mainloop.glib": glib,
        "gi": gi,
        "gi.repository": repository,
    })
    try:
        sys.modules.pop("greyward_security_context.update_center_bus", None)
        sys.modules.pop("greyward_security_context.update_center", None)
        return importlib.import_module("greyward_security_context.update_center_bus")
    finally:
        for name, value in previous.items():
            if value is missing:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value


update_center_bus = load_update_center_bus()


class FakeSession:
    def __init__(self):
        self.calls = []

    def upgrade(self, packages, options, **kwargs):
        self.calls.append(("upgrade", packages, options, kwargs))

    def install(self, packages, options, **kwargs):
        self.calls.append(("install", packages, options, kwargs))

    def resolve(self, options, **kwargs):
        self.calls.append(("resolve", options, kwargs))
        return ([{"name": "kernel", "action": "upgrade"}], 0)

    def do_transaction(self, options, **kwargs):
        self.calls.append(("do_transaction", options, kwargs))

    def schedule_for_next_boot(self, options, **kwargs):
        self.calls.append(("schedule_for_next_boot", options, kwargs))
        return True, ""


class FakeRoot:
    def __init__(self):
        self.options = None

    def open_session(self, options, **kwargs):
        self.options = options
        return "/org/rpm/dnf/v0/session/1"


class FakePrivilegedProcess:
    def __init__(self, lines, returncode=0):
        self.stdout = iter(lines)
        self.returncode = returncode

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.returncode = -9


class UpdateCenterBusTests(unittest.TestCase):
    def setUp(self):
        update_center_bus._native_session = None
        update_center_bus._native_session_path = None
        update_center_bus._native_root = None
        update_center_bus._native_bus = None

    def tearDown(self):
        update_center_bus._native_session = None
        update_center_bus._native_session_path = None
        update_center_bus._native_root = None
        update_center_bus._native_bus = None

    def test_native_session_uses_a_typed_empty_options_dictionary(self):
        root = FakeRoot()
        bus = types.SimpleNamespace(get_object=lambda name, path: root if path == update_center_bus.DNF_ROOT else object())
        with patch.object(update_center_bus.dbus, "SystemBus", return_value=bus), patch.object(update_center_bus, "register_progress_signals"):
            update_center_bus.native_session()
        self.assertIsInstance(root.options, FakeDictionary)
        self.assertEqual(root.options.signature, "sv")
        self.assertEqual(dict(root.options), {})

    def test_pending_snapshot_uses_only_the_selected_system_provider(self):
        with patch.object(update_center_bus, "selected_system_provider", return_value=("DNF5", None)):
            value = update_center_bus.pending_snapshot()

        self.assertEqual(set(value["providers"]), {"DNF5", "Flatpak", "fwupd", "freshclam/ClamAV"})
        self.assertNotIn("rpm-ostree", value["providers"])

    def test_apply_uses_one_privileged_transaction_for_system_providers(self):
        data = {
            "records": [
                {"provider": "DNF5", "category": "system", "update_available": True, "metadata": {}},
                {"provider": "Flatpak", "category": "application", "update_available": True, "metadata": {"scope": "system"}},
                {"provider": "fwupd", "category": "firmware", "update_available": True, "metadata": {}},
            ],
            "providers": {},
        }
        completion = {
            "recovery_point": {"id": "recovery-test", "status": "valid"},
            "provider_results": [{"provider": "DNF5", "state": "SUCCESS"}],
        }
        with (
            patch.object(update_center_bus, "snapshot", return_value=data),
            patch.object(update_center_bus, "cache_snapshot"),
            patch.object(update_center_bus, "selected_system_provider", return_value=("DNF5", None)),
            patch.object(update_center_bus, "essential_driver_package_names", return_value=["kernel-modules-extra"]),
            patch.object(update_center_bus, "transaction_copy", return_value={"id": "dnf5-test"}),
            patch.object(update_center_bus, "set_transaction", side_effect=lambda **values: values),
            patch.object(update_center_bus, "run_privileged_update", return_value=completion) as privileged,
            patch.object(update_center_bus, "run_optional_provider_updates", return_value={"phase": "READY_TO_RESTART"}) as optional,
        ):
            value = update_center_bus.apply_all_worker()

        self.assertEqual(value["phase"], "READY_TO_RESTART")
        privileged.assert_called_once_with(
            "dnf5-test", system=True, system_flatpak=True, firmware=True,
            driver_packages=["kernel-modules-extra"],
        )
        optional.assert_called_once()

    def test_recovery_polkit_rule_does_not_require_the_user_service_pid_to_be_active(self):
        rule = (Path(__file__).parents[1] / "polkit" / "49-greyward-recovery.rules").read_text(encoding="utf-8")

        self.assertIn('subject.isInGroup("wheel")', rule)
        self.assertIn('action.id === "org.freedesktop.policykit.exec"', rule)
        self.assertIn('action.lookup("program")', rule)
        self.assertIn('/usr/libexec/greyward-recovery-point', rule)
        self.assertIn('/usr/libexec/greyward-update-action', rule)
        self.assertNotIn("subject.local", rule)
        self.assertNotIn("subject.active", rule)

    def test_update_helper_is_bound_to_one_self_authentication_policy(self):
        policy = (Path(__file__).parents[1] / "polkit" / "org.greyward.Update1.policy").read_text(encoding="utf-8")
        rule = (Path(__file__).parents[1] / "polkit" / "49-greyward-recovery.rules").read_text(encoding="utf-8")

        self.assertIn("/usr/libexec/greyward-update-action", policy)
        self.assertIn("<allow_active>auth_self</allow_active>", policy)
        self.assertIn('action.id === "org.greyward.Update1.apply"', rule)
        self.assertNotIn("auth_self_keep", policy)
        self.assertNotIn("polkit.Result.YES", rule)

    def test_privileged_update_uses_one_pkexec_and_streams_safe_phases(self):
        process = FakePrivilegedProcess([
            '{"greyward_update_event":"phase","phase":"CHECKPOINTING","message":"Creating a recovery point."}\n',
            '{"greyward_update_event":"recovery","recovery_point":{"id":"point-1","status":"valid"}}\n',
            '{"greyward_update_event":"complete","provider_results":[]}\n',
        ])
        transitions = []
        with (
            patch.object(update_center_bus.Path, "exists", return_value=True),
            patch.object(update_center_bus.subprocess, "Popen", return_value=process) as popen,
            patch.object(update_center_bus, "set_transaction", side_effect=lambda **values: transitions.append(values) or values),
            patch.object(update_center_bus, "transaction_copy", return_value={"provider_results": []}),
        ):
            result = update_center_bus.run_privileged_update(
                "dnf5-123", system=True, system_flatpak=True,
                driver_packages=["kernel-modules-extra"],
            )

        self.assertEqual(result["provider_results"], [])
        command = popen.call_args.args[0]
        self.assertEqual(command[:3], [update_center_bus.POLKIT_EXEC, update_center_bus.UPDATE_HELPER, "apply"])
        self.assertEqual(command.count(update_center_bus.POLKIT_EXEC), 1)
        self.assertIn("--system", command)
        self.assertIn("--system-flatpak", command)
        self.assertIn("CHECKPOINTING", [value.get("phase") for value in transitions])
        self.assertIn("VALID", [value.get("recovery_point_status") for value in transitions])

    def test_interrupted_transaction_is_reset_after_a_reboot(self):
        with patch.object(update_center_bus, "current_boot_id", return_value="new-boot"):
            value = update_center_bus.reconcile_transaction({
                "phase": "PREPARING_RESTART",
                "boot_id": "old-boot",
                "finished_at": None,
            })

        self.assertEqual(value["phase"], "FAILED")
        self.assertFalse(value["cancellable"])
        self.assertIn("interrupted", value["error"])

    def test_ready_transaction_reports_a_new_boot_without_claiming_install_verification(self):
        with patch.object(update_center_bus, "current_boot_id", return_value="new-boot"):
            value = update_center_bus.reconcile_transaction({
                "phase": "READY_TO_RESTART",
                "boot_id": "old-boot",
                "updated_at": update_center_bus.stamp(),
            })

        self.assertEqual(value["phase"], "COMPLETE")
        self.assertIn("observed a new boot", value["details"])
        self.assertNotIn("verified", value["details"].lower())

    def test_ready_dnf_transaction_requires_successful_post_reboot_history(self):
        transaction = {
            "phase": "READY_TO_RESTART",
            "boot_id": "old-boot",
            "started_at": "2026-09-06T16:12:42Z",
            "updated_at": "2026-09-06T16:20:00Z",
            "provider_results": [{"provider": "DNF5", "state": "SUCCESS"}],
        }
        with (
            patch.object(update_center_bus, "current_boot_id", return_value="new-boot"),
            patch.object(update_center_bus, "dnf_offline_history_result", return_value={"id": 70, "status": "Ok"}),
        ):
            value = update_center_bus.reconcile_transaction(transaction)

        self.assertEqual(value["phase"], "COMPLETE")
        self.assertIn("transaction 70", value["details"])

    def test_dnf_post_reboot_history_matches_only_an_offline_update(self):
        completed = types.SimpleNamespace(
            returncode=0,
            stdout='[{"id":72,"command_line":"/usr/bin/dnf5 upgrade --offline --assumeyes","start_time":1000,"status":"Ok"},{"id":71,"command_line":"dnf install package","start_time":999,"status":"Ok"}]',
            stderr="",
        )
        with patch.object(update_center_bus.subprocess, "run", return_value=completed) as run:
            value = update_center_bus.dnf_offline_history_result("1970-01-01T00:16:40Z")

        self.assertEqual(value["id"], 72)
        self.assertEqual(run.call_args.args[0], [update_center_bus.DNF_CLI, "history", "list", "--json"])
        self.assertEqual(run.call_args.kwargs["timeout"], 30)

    def test_restarting_dnf_transaction_uses_the_same_post_reboot_verification(self):
        transaction = {
            "phase": "RESTARTING",
            "boot_id": "old-boot",
            "started_at": "2026-09-06T16:12:42Z",
            "updated_at": "2026-09-06T16:20:00Z",
            "provider_results": [{"provider": "DNF5", "state": "SUCCESS"}],
        }
        with (
            patch.object(update_center_bus, "current_boot_id", return_value="new-boot"),
            patch.object(update_center_bus, "dnf_offline_history_result", return_value={"id": 71, "status": "Ok"}),
        ):
            value = update_center_bus.reconcile_transaction(transaction)

        self.assertEqual(value["phase"], "COMPLETE")
        self.assertIn("transaction 71", value["details"])

    def test_restarting_without_a_new_boot_does_not_become_false_success(self):
        transaction = {
            "phase": "RESTARTING",
            "boot_id": "same-boot",
            "started_at": "2026-09-06T16:12:42Z",
            "updated_at": "2026-09-06T15:00:00Z",
            "provider_results": [{"provider": "DNF5", "state": "SUCCESS"}],
        }
        with (
            patch.object(update_center_bus, "current_boot_id", return_value="same-boot"),
            patch.object(update_center_bus.time, "time", return_value=1788714000),
        ):
            value = update_center_bus.reconcile_transaction(transaction)

        self.assertEqual(value["phase"], "FAILED")
        self.assertEqual(value["restart_required"], "REQUIRED")
        self.assertIn("did not restart", value["error"])

    def test_ready_dnf_transaction_surfaces_missing_post_reboot_history(self):
        transaction = {
            "phase": "READY_TO_RESTART",
            "boot_id": "old-boot",
            "started_at": "2026-09-06T16:12:42Z",
            "updated_at": "2026-09-06T16:20:00Z",
            "provider_results": [{"provider": "DNF5", "state": "SUCCESS"}],
        }
        with (
            patch.object(update_center_bus, "current_boot_id", return_value="new-boot"),
            patch.object(update_center_bus, "dnf_offline_history_result", return_value=None),
        ):
            value = update_center_bus.reconcile_transaction(transaction)

        self.assertEqual(value["phase"], "FAILED")
        self.assertIn("did not produce", value["error"])
        self.assertIn("missing", value["details"])

    def test_new_resolve_operation_clears_stale_transaction_feedback(self):
        previous = dict(update_center_bus._transaction)
        try:
            update_center_bus._transaction.update({
                "id": "dnf5-old",
                "phase": "FAILED",
                "progress": 71,
                "current_item": "Old package",
                "error": "Old error",
                "details": "Old details",
                "provider_results": [{"provider": "DNF5", "state": "DEGRADED"}],
                "downloaded": 7,
                "download_total": 10,
                "processed": 4,
                "total": 9,
                "restart_required": "REQUIRED",
            })
            with (
                patch.object(update_center_bus, "new_operation_id", return_value="dnf5-new"),
                patch.object(update_center_bus, "save_transaction"),
                patch.object(update_center_bus, "record_event"),
                patch.object(update_center_bus, "current_boot_id", return_value="boot-test"),
                patch.object(update_center_bus.threading, "Thread") as thread,
            ):
                value = update_center_bus.start_operation("resolve")

            self.assertEqual(value["id"], "dnf5-new")
            self.assertEqual(value["phase"], "RESOLVING")
            self.assertIsNone(value["error"])
            self.assertIsNone(value["details"])
            self.assertEqual(value["provider_results"], [])
            self.assertEqual(value["downloaded"], 0)
            self.assertEqual(value["processed"], 0)
            self.assertEqual(value["restart_required"], "UNKNOWN")
            thread.return_value.start.assert_called_once_with()
        finally:
            update_center_bus._transaction.clear()
            update_center_bus._transaction.update(previous)

    def test_terminal_transaction_clears_stale_progress_and_busy_state(self):
        previous = dict(update_center_bus._transaction)
        try:
            update_center_bus._transaction.update({
                "id": "dnf5-terminal-test",
                "phase": "INSTALLING",
                "progress": 87,
                "current_item": "Updating kernel.",
                "cancellable": False,
            })
            with patch.object(update_center_bus, "save_transaction"), patch.object(update_center_bus, "record_event"), patch.object(update_center_bus, "current_boot_id", return_value="boot-test"):
                value = update_center_bus.set_transaction(phase="COMPLETE", summary={"packages": 1})
            self.assertIsNone(value["progress"])
            self.assertIsNone(value["current_item"])
            self.assertFalse(value["cancellable"])
        finally:
            update_center_bus._transaction.clear()
            update_center_bus._transaction.update(previous)

    def test_apply_all_runs_provider_updates_when_dnf_has_no_updates(self):
        provider_result = {"phase": "COMPLETE", "provider_results": []}
        data = {"records": [], "providers": {}}
        with patch.object(update_center_bus, "snapshot", return_value=data), patch.object(update_center_bus, "cache_snapshot"), patch.object(update_center_bus, "selected_system_provider", return_value=("DNF5", None)), patch.object(update_center_bus, "run_optional_provider_updates", return_value=provider_result) as run_optional, patch.object(update_center_bus, "run_privileged_update") as privileged:
            value = update_center_bus.apply_all_worker()

        run_optional.assert_called_once_with(data, initial_results=[], privileged_plan={"system": False, "system_flatpak": False, "firmware": False})
        privileged.assert_not_called()
        self.assertEqual(value, provider_result)

    def test_update_all_is_resolve_only_and_cannot_start_provider_mutations(self):
        service = object.__new__(update_center_bus.UpdateCenter)
        with patch.object(update_center_bus, "start_operation", return_value={"operation": "resolve"}) as start:
            value = service.UpdateAll()

        start.assert_called_once_with("resolve")
        self.assertIn('"operation":"resolve"', str(value))

    def test_dnf_helper_retries_without_only_the_unavailable_optional_codec_repo(self):
        helper_path = Path(__file__).parents[1] / "bin" / "greyward-update-action"
        loader = importlib.machinery.SourceFileLoader("greyward_update_action", str(helper_path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        failed = types.SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="Cannot download mozilla-openh264: all mirrors were tried",
        )
        succeeded = types.SimpleNamespace(returncode=0, stdout="", stderr="")
        placeholder = types.SimpleNamespace(returncode=0)
        status = types.SimpleNamespace(returncode=0, stdout="", stderr="")
        scheduled = types.SimpleNamespace(returncode=0, stdout="", stderr="")
        with (
            patch.object(helper.subprocess, "run", side_effect=[failed, placeholder, succeeded, status, scheduled]) as run,
            patch.object(helper, "offline_restart_is_scheduled", return_value=True),
        ):
            self.assertEqual(helper.prepare_dnf([]), (0, True))

        self.assertEqual(run.call_args_list[2].args[0][-1], "--disablerepo=fedora-cisco-openh264")
        self.assertEqual(run.call_args_list[0].kwargs["timeout"], helper.PROVIDER_TIMEOUT)
        self.assertEqual(run.call_args_list[1].kwargs["timeout"], helper.RPM_QUERY_TIMEOUT)
        self.assertEqual(run.call_args_list[2].kwargs["timeout"], helper.PROVIDER_TIMEOUT)
        self.assertEqual(run.call_args_list[4].kwargs["env"]["DNF_SYSTEM_UPGRADE_NO_REBOOT"], "1")

    def test_dnf_helper_installs_only_validated_driver_packages_in_same_prepare(self):
        helper_path = Path(__file__).parents[1] / "bin" / "greyward-update-action"
        loader = importlib.machinery.SourceFileLoader("greyward_update_action_driver", str(helper_path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        transaction = types.SimpleNamespace(returncode=0, stdout="", stderr="")
        status = types.SimpleNamespace(returncode=0, stdout="", stderr="")
        scheduled = types.SimpleNamespace(returncode=0, stdout="", stderr="")
        with (
            patch.object(helper, "run", side_effect=[transaction, status, scheduled]) as run,
            patch.object(helper, "offline_restart_is_scheduled", return_value=True),
        ):
            self.assertEqual(helper.prepare_dnf(["kernel-modules-extra"]), (0, False))

        self.assertEqual(
            run.call_args_list[0].args[0],
            [
                helper.DNF, "do", "--offline", "--assumeyes",
                "--action=upgrade", "*",
                "--action=install", "kernel-modules-extra",
            ],
        )
        self.assertEqual(run.call_args_list[1].args[0], [helper.DNF, "offline-upgrade", "status"])
        self.assertEqual(run.call_args_list[2].args[0], [helper.DNF, "offline", "reboot", "--assumeyes"])
        self.assertEqual(run.call_args_list[2].kwargs["extra_env"], {"DNF_SYSTEM_UPGRADE_NO_REBOOT": "1"})

    def test_dnf_helper_fails_when_the_offline_boot_target_was_not_scheduled(self):
        helper_path = Path(__file__).parents[1] / "bin" / "greyward-update-action"
        loader = importlib.machinery.SourceFileLoader("greyward_update_action_schedule", str(helper_path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        completed = types.SimpleNamespace(returncode=0, stdout="", stderr="")
        with (
            patch.object(helper, "run", return_value=completed),
            patch.object(helper, "offline_restart_is_scheduled", return_value=False),
        ):
            self.assertEqual(helper.prepare_dnf([]), (1, False))

    def test_dnf_helper_rejects_untrusted_driver_package_arguments(self):
        helper_path = Path(__file__).parents[1] / "bin" / "greyward-update-action"
        loader = importlib.machinery.SourceFileLoader("greyward_update_action_validation", str(helper_path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        with self.assertRaises(ValueError):
            helper.validate_driver_packages(["kernel-modules-extra;rm"])

    def test_update_helper_creates_recovery_before_preparing_dnf(self):
        helper_path = Path(__file__).parents[1] / "bin" / "greyward-update-action"
        loader = importlib.machinery.SourceFileLoader("greyward_update_action_order", str(helper_path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        order = []
        create = lambda reason, operation_id: order.append(("recovery", reason, operation_id)) or {"id": "point-1", "status": "valid"}
        prepare = lambda packages: order.append(("dnf", packages)) or (0, False)
        args = types.SimpleNamespace(operation_id="dnf5-123", system=True, system_flatpak=False, firmware=False, driver_package=["kernel-modules-extra"])
        with patch.object(helper, "load_recovery_create", return_value=create), patch.object(helper, "prepare_dnf", side_effect=prepare), patch.object(helper, "emit"):
            self.assertEqual(helper.apply(args), 0)

        self.assertEqual(order, [("recovery", "pre-update", "dnf5-123"), ("dnf", ["kernel-modules-extra"])])


if __name__ == "__main__":
    unittest.main()
