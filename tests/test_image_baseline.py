"""Run with python3 -m unittest discover -s tests -p test_image_baseline.py."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("baseline", ROOT / "environment/image/baseline.py")
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class BaselineTests(unittest.TestCase):
    def sample(self):
        return {"schema": b.SCHEMA, "fedora": "44", "rpms": {"bash.x86_64": ["0", "5.3", "1"]},
                "flatpaks": {"org.example.App": {"ref": "app/org.example.App/x86_64/stable", "commit": "a" * 64}}}

    def test_validate(self):
        b.validate(self.sample())

    def test_reject_bad_commit(self):
        value = self.sample(); value["flatpaks"]["org.example.App"]["commit"] = "--invalid"
        with self.assertRaises(ValueError): b.validate(value)

    def test_reject_other_branch_architecture(self):
        value = self.sample(); value["flatpaks"]["org.example.App"]["ref"] = "app/org.example.App/aarch64/stable"
        with self.assertRaises(ValueError): b.validate(value)

    def test_reject_wrong_release(self):
        value = self.sample(); value["fedora"] = "43"
        with self.assertRaises(ValueError): b.validate(value)

    def test_reject_empty(self):
        value = self.sample(); value["rpms"] = {}
        with self.assertRaises(ValueError): b.validate(value)

    def test_portable_preferences_exclude_machine_details(self):
        default = {"fontFamily": "Inter", "customThemeFile": "/usr/share/theme.json",
                   "barConfigs": [{"id": "default", "spacing": 7, "screenPreferences": ["all"]}]}
        live = {"fontFamily": "Noto Sans", "customThemeFile": "/home/private/theme.json",
                "weatherLocation": "private", "barConfigs": [{"id": "default", "spacing": 12,
                "screenPreferences": ["Virtual-1"]}]}
        result = b.portable(live, default)
        self.assertEqual(result["fontFamily"], "Noto Sans")
        self.assertEqual(result["barConfigs"][0]["spacing"], 12)
        self.assertEqual(result["barConfigs"][0]["screenPreferences"], ["all"])
        self.assertNotIn("private", json.dumps(result))
        self.assertEqual(result, b.portable(result, default))

    def test_no_type_confusion(self):
        self.assertEqual(b.portable({"spacing": "99"}, {"spacing": 7}), {"spacing": 7})

    def test_stage_rejects_stale_policy_before_writing(self):
        value = self.sample(); value["policy_sha256"] = "stale"
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "baseline.json"; b.write(source, value)
            target = Path(tmp) / "stage"
            with patch.object(b, "policy", return_value={}), self.assertRaises(ValueError):
                b.stage(ROOT, source, target)
            self.assertFalse(target.exists())

    def test_verify_version_floor_and_missing_dev_package(self):
        try:
            import rpm
        except ImportError:
            self.skipTest("RPM comparison is tested on the Fedora build host")
        value = self.sample(); value["rpms"]["build-only.x86_64"] = ["0", "99", "1"]
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "baseline.json"; b.write(source, value)
            def info(*args):
                return "a" * 64 if "--show-commit" in args else "app/org.example.App/x86_64/stable"
            with patch.object(b, "run", side_effect=info):
                with patch.object(b, "packages", return_value={"bash.x86_64": ["0", "5.10", "1"]}):
                    b.verify(source)
                with patch.object(b, "packages", return_value={"bash.x86_64": ["0", "5.2", "1"]}):
                    with self.assertRaisesRegex(ValueError, "below baseline"): b.verify(source)

    def test_inventory_ignores_signing_keys_and_selects_latest_kernel(self):
        try:
            import rpm
        except ImportError:
            self.skipTest("Fedora RPM bindings required")
        rows = "gpg-pubkey\t(none)\t0\t1234\t5678\nkernel-core\tx86_64\t0\t7.1.9\t1\nkernel-core\tx86_64\t0\t7.1.13\t1\n"
        with patch.object(b, "run", return_value=rows):
            self.assertEqual(b.packages(), {"kernel-core.x86_64": ["0", "7.1.13", "1"]})

    def test_verify_flatpak_drift(self):
        try:
            import rpm
        except ImportError:
            self.skipTest("Fedora RPM bindings required")
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "baseline.json"; b.write(source, self.sample())
            with patch.object(b, "packages", return_value={}), patch.object(b, "run", return_value="drift"):
                with self.assertRaisesRegex(ValueError, "differs from baseline"): b.verify(source)


if __name__ == "__main__": unittest.main()
