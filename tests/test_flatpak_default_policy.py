"""Preserve reviewed policy during fresh-install default reconciliation."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("flatpak_defaults", ROOT / "environment/flatpak/seed-system-permissions.py")
defaults = importlib.util.module_from_spec(spec)
spec.loader.exec_module(defaults)


class Provider:
    def __init__(self, global_policy="", app_policy=None):
        self.global_policy = global_policy
        self.app_policy = dict(app_policy or {})
        self.writes = []
        self.failed_read = False
        self.failed_readback = False

    def __call__(self, arguments):
        if arguments[:3] == ["override", "--system", "--show"]:
            if self.failed_read:
                raise defaults.DefaultPolicyError("Unavailable")
            if len(arguments) == 3:
                return self.global_policy
            return self.app_policy.get(arguments[3], "")
        if arguments[:2] != ["override", "--system"] or len(arguments) != 4:
            raise AssertionError("Unexpected provider operation")
        _, _, option, app = arguments
        self.writes.append((app, option))
        if not self.failed_readback:
            if option == "--filesystem=xdg-config/bazaar:ro":
                self.app_policy[app] = "[Context]\nfilesystems=xdg-config/bazaar:ro;\n"
            elif option == "--unshare=network":
                self.app_policy[app] = "[Context]\nshared=!network;\n"
            else:
                raise AssertionError("Unknown default operation")
        return ""


class FlatpakDefaultPolicyTests(unittest.TestCase):
    def test_fresh_defaults_are_written_and_second_run_preserves_them(self):
        provider = Provider()
        first = defaults.seed_defaults(provider)
        self.assertEqual([item["decision"] for item in first], ["SEEDED", "SEEDED"])
        self.assertEqual(len(provider.writes), 2)
        second = defaults.seed_defaults(provider)
        self.assertEqual([item["decision"] for item in second], ["PRESERVED", "PRESERVED"])
        self.assertEqual(len(provider.writes), 2)

    def test_existing_app_permissions_are_preserved_byte_for_byte(self):
        values = {"io.github.kolunmi.Bazaar": "[Context]\nfilesystems=!home;~/selected:ro;\n",
                  "org.kde.haruna": "[Context]\nshared=network;\n[Environment]\nTOKEN=synthetic-private\n"}
        provider = Provider(app_policy=values)
        self.assertEqual([item["decision"] for item in defaults.seed_defaults(provider)], ["PRESERVED", "PRESERVED"])
        self.assertEqual(provider.app_policy, values)
        self.assertEqual(provider.writes, [])

    def test_global_policy_is_not_implicitly_overridden_by_app_defaults(self):
        provider = Provider("[Context]\nfilesystems=!home;\nshared=network;\n")
        self.assertEqual([item["decision"] for item in defaults.seed_defaults(provider)], ["PRESERVED", "PRESERVED"])
        self.assertEqual(provider.writes, [])

    def test_failure_is_not_interpreted_as_absent_policy(self):
        provider = Provider()
        provider.failed_read = True
        with self.assertRaises(defaults.DefaultPolicyError):
            defaults.seed_defaults(provider)
        self.assertEqual(provider.writes, [])

    def test_failed_readback_never_reports_success(self):
        provider = Provider()
        provider.failed_readback = True
        with self.assertRaises(defaults.DefaultPolicyError):
            defaults.seed_defaults(provider)
        self.assertEqual(len(provider.writes), 1)

    def test_nonempty_markers_are_existing_policy(self):
        provider = Provider(app_policy={app: "[Context]\n" for app, *_ in defaults.DEFAULTS})
        self.assertEqual([item["decision"] for item in defaults.seed_defaults(provider)], ["PRESERVED", "PRESERVED"])
        self.assertEqual(provider.writes, [])


if __name__ == "__main__":
    unittest.main()
