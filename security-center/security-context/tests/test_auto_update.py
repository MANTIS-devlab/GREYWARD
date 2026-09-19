import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT_PATH = ROOT / "security-center" / "security-context" / "bin" / "greyward-auto-update"
SERVICE_PATH = ROOT / "security-center" / "security-context" / "systemd" / "greyward-auto-update.service"
TIMER_PATH = ROOT / "security-center" / "security-context" / "systemd" / "greyward-auto-update.timer"


class AutomaticUpdateContractTests(unittest.TestCase):
    def test_script_uses_fixed_check_apply_and_notification_paths(self):
        source = SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertIn('[DNF, "check-upgrade", "--json"]', source)
        self.assertIn('[UPDATE_HELPER, "apply", "--operation-id", operation_id, "--system"]', source)
        self.assertIn("notify(\"System update ready\"", source)
        self.assertNotIn("pkexec", source)
        self.assertNotIn("shell=True", source)
        self.assertNotIn("os.system", source)

    def test_service_is_root_only_and_hardened(self):
        source = SERVICE_PATH.read_text(encoding="utf-8")
        for required in (
            "User=root",
            "Group=root",
            "NoNewPrivileges=yes",
            "PrivateTmp=yes",
            "ProtectHome=read-only",
            "RestrictSUIDSGID=yes",
        ):
            self.assertIn(required, source)

    def test_timer_runs_every_two_days_and_catches_missed_wakeups(self):
        source = TIMER_PATH.read_text(encoding="utf-8")
        self.assertIn("OnUnitActiveSec=2d", source)
        self.assertIn("Persistent=true", source)
        self.assertIn("RandomizedDelaySec=30min", source)


if __name__ == "__main__":
    unittest.main()
