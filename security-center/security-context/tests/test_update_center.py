import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

import sys

sys.path.insert(0, str(Path(__file__).parents[1]))

from greyward_security_context import update_center


class UpdateHistoryTests(unittest.TestCase):
    def test_essential_pci_scan_ignores_nonessential_and_unbound_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            display = root / "pci-display"
            display.mkdir()
            (display / "class").write_text("0x030000\n", encoding="utf-8")
            (display / "modalias").write_text("pci:v00008086d00001234sv*sd*bc03sc00i00\n", encoding="utf-8")
            (display / "vendor").write_text("0x8086\n", encoding="utf-8")
            (display / "device").write_text("0x1234\n", encoding="utf-8")
            other = root / "pci-other"
            other.mkdir()
            (other / "class").write_text("0x0c0330\n", encoding="utf-8")

            devices = update_center.essential_pci_devices(root)

        self.assertEqual([item["sysfs_name"] for item in devices], ["pci-display"])
        self.assertEqual(devices[0]["modalias"], "pci:v00008086d00001234sv*sd*bc03sc00i00")

    def test_driver_record_uses_only_a_non_debug_uninstalled_provider(self):
        device = {
            "sysfs_name": "pci-display",
            "class_code": "0x030000",
            "modalias": "pci:v00008086d00001234sv*sd*bc03sc00i00",
            "vendor": "0x8086",
            "device": "0x1234",
            "label": None,
        }
        with (
            patch.object(update_center, "essential_pci_devices", return_value=[device]),
            patch.object(update_center, "dnf5_driver_candidates", return_value=(
                [{"name": "kernel-debug-modules", "evr": "1", "arch": "x86_64", "repo_id": "fedora", "full_nevra": "debug"},
                 {"name": "kernel-modules", "evr": "2", "arch": "x86_64", "repo_id": "updates", "full_nevra": "normal"}],
                None,
            )),
        ):
            records, errors = update_center.essential_driver_records({})

        self.assertEqual(errors, [])
        self.assertEqual(records[0]["metadata"]["package_name"], "kernel-modules")
        self.assertTrue(records[0]["update_available"])
        self.assertEqual(records[0]["metadata"]["resolution"], "AVAILABLE")

    def test_driver_record_does_not_reinstall_a_matching_installed_package(self):
        device = {"sysfs_name": "pci-network", "class_code": "0x020000", "modalias": "pci:test", "vendor": None, "device": None, "label": None}
        with (
            patch.object(update_center, "essential_pci_devices", return_value=[device]),
            patch.object(update_center, "dnf5_driver_candidates", return_value=([{"name": "kernel-modules", "evr": "2", "arch": "x86_64", "repo_id": "updates", "full_nevra": "normal"}], None)),
        ):
            records, _errors = update_center.essential_driver_records({("kernel-modules", "x86_64"): "2"})

        self.assertFalse(records[0]["update_available"])
        self.assertEqual(records[0]["metadata"]["resolution"], "UNRESOLVED")

    def test_system_provider_selection_matches_the_booted_host(self):
        with patch.object(update_center, "is_ostree_host", return_value=False):
            name, collector = update_center.selected_system_provider()
        self.assertEqual(name, "DNF5")
        self.assertIs(collector, update_center.dnf5)

        with patch.object(update_center, "is_ostree_host", return_value=True):
            name, collector = update_center.selected_system_provider()
        self.assertEqual(name, "rpm-ostree")
        self.assertIs(collector, update_center.rpm_ostree)

    def test_snapshot_exposes_only_the_selected_system_provider(self):
        timestamp = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            previous_path = Path(directory) / "previous-records.json"
            with (
                patch.object(update_center, "selected_system_provider", return_value=("DNF5", lambda: ({"state": "AVAILABLE"}, []))),
                patch.object(update_center, "flatpak", return_value=({"state": "AVAILABLE"}, [])),
                patch.object(update_center, "fwupd", return_value=({"state": "AVAILABLE"}, [])),
                patch.object(update_center, "freshclam", return_value=({"state": "AVAILABLE"}, [])),
                patch.object(update_center, "load_previous_records", return_value=[]),
                patch.object(update_center, "update_history", return_value=[]),
                patch.object(update_center, "previous_records_path", return_value=previous_path),
                patch.object(update_center, "now", return_value=timestamp),
            ):
                value = update_center.snapshot()

        self.assertEqual(set(value["providers"]), {"DNF5", "Flatpak", "fwupd", "freshclam/ClamAV"})
        self.assertNotIn("rpm-ostree", value["providers"])

    def test_provider_json_failure_is_not_treated_as_valid_data(self):
        completed = SimpleNamespace(returncode=1, stdout='{"updates": []}', stderr="provider failed")
        with patch.object(update_center.subprocess, "run", return_value=completed), patch.object(update_center.shutil, "which", return_value="/usr/bin/provider"):
            payload, error = update_center.run_json(["provider", "--json"])

        self.assertIsNone(payload)
        self.assertIn("provider failed", error)

    def test_flatpak_update_query_failure_is_degraded_and_not_available_zero(self):
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            if "remote-ls" in argv:
                return SimpleNamespace(returncode=1, stdout="", stderr="remote unavailable")
            return SimpleNamespace(returncode=0, stdout="org.example.App\tExample\t1\tflathub\tx86_64\tstable\truntime\n", stderr="")

        with patch.object(update_center.shutil, "which", return_value="/usr/bin/flatpak"), patch.object(update_center.subprocess, "run", side_effect=fake_run):
            health, records = update_center.flatpak()

        self.assertEqual(health["state"], "DEGRADED")
        self.assertIn("remote unavailable", health["reason"])
        self.assertEqual(len(records), 2)
        self.assertTrue(all(record["update_available"] is False for record in records))
        self.assertTrue(any("remote-ls" in call for call in calls))

    def test_flatpak_successful_empty_update_query_is_available(self):
        def fake_run(argv, **kwargs):
            listing = "org.example.App\tExample\t1\tflathub\tx86_64\tstable\truntime\n"
            return SimpleNamespace(returncode=0, stdout=listing if "list" in argv else "", stderr="")

        with patch.object(update_center.shutil, "which", return_value="/usr/bin/flatpak"), patch.object(update_center.subprocess, "run", side_effect=fake_run):
            health, records = update_center.flatpak()

        self.assertEqual(health["state"], "AVAILABLE")
        self.assertEqual(len(records), 2)
        self.assertTrue(all(record["update_available"] is False for record in records))

    def test_dnf_check_upgrade_exit_100_is_accepted(self):
        completed = SimpleNamespace(returncode=100, stdout='{"upgrades": []}', stderr="")
        with patch.object(update_center.subprocess, "run", return_value=completed), patch.object(update_center.shutil, "which", return_value="/usr/bin/dnf5"):
            payload, error = update_center.run_json(["dnf5", "check-upgrade", "--json"], accepted_returncodes=(0, 100))

        self.assertEqual(payload, {"upgrades": []})
        self.assertIsNone(error)

    def test_fwupd_urgency_does_not_infer_a_reboot_requirement(self):
        payload = {"Devices": [{"DeviceId": "device-1", "Name": "Device", "Version": "1", "Releases": [{"Version": "2", "IsUrgent": True}]}]}
        with patch.object(update_center, "run_json", return_value=(payload, None)), patch.object(update_center.shutil, "which", return_value="/usr/bin/fwupdmgr"):
            _health, records = update_center.fwupd()

        self.assertEqual(records[0]["reboot_required"], "UNKNOWN")
        self.assertTrue(records[0]["metadata"]["urgent"])

    def test_history_normalizes_identity_versions_and_keeps_unknown_result_honest(self):
        previous = [{
            "id": "system.dnf5.kernel.x86_64",
            "current_version": "6.14.7-200.fc44",
        }]
        records = [{
            "id": "system.dnf5.kernel.x86_64",
            "identity": "kernel",
            "category": "system",
            "name": "kernel",
            "provider": "DNF5",
            "source": "updates",
            "current_version": "6.14.7-201.fc44.x86_64",
            "observed_at": "2026-09-01T10:00:00Z",
            "metadata": {"arch": "x86_64"},
        }]
        with tempfile.TemporaryDirectory() as directory:
            history_file = Path(directory) / "history.json"
            with patch.object(update_center, "history_path", return_value=history_file):
                history = update_center.update_history(previous, records)

        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["identity"], "kernel")
        self.assertEqual(history[0]["previous_version"], "6.14.7-200.fc44")
        self.assertEqual(history[0]["new_version"], "6.14.7-201.fc44")
        self.assertEqual(history[0]["result"], "UNKNOWN")
        self.assertEqual(history[0]["timestamp"], "2026-09-01T10:00:00Z")
        self.assertEqual(history[0]["provider"], "DNF5")

    def test_history_does_not_create_a_transition_from_first_observation(self):
        record = {
            "id": "application.flatpak.user.org.example.App",
            "identity": "org.example.App",
            "category": "application",
            "name": "Example App",
            "provider": "Flatpak",
            "current_version": "1.2",
            "observed_at": "2026-09-01T10:00:00Z",
            "metadata": {"app_id": "org.example.App"},
        }
        with tempfile.TemporaryDirectory() as directory:
            history_file = Path(directory) / "history.json"
            with patch.object(update_center, "history_path", return_value=history_file):
                history = update_center.update_history([], [record])
        self.assertEqual(history, [])


if __name__ == "__main__":
    unittest.main()
