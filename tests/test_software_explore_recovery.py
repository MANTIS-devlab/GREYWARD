"""Real shell startup behavior and stale/missing ISO input rejection."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "environment/flatpak/greyward-bazaar-start"
spec = importlib.util.spec_from_file_location(
    "software_inputs", ROOT / "environment/image/verify-software-inputs.py"
)
inputs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inputs)


@unittest.skipUnless(os.name == "posix" and shutil.which("sh"), "native POSIX shell required")
class StartupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.trace = self.root / "trace.jsonl"
        self.env = {
            **os.environ, "HOME": str(self.root / "home"),
            "XDG_CACHE_HOME": str(self.root / "cache with spaces"),
            "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "TRACE": str(self.trace),
        }
        # External executables are fixtures; all startup/branch logic is the
        # unmodified production helper. Observe ordering, arguments and errors.
        for name in ("gsettings", "bazaar-daemon"):
            path = self.bin / name
            path.write_text(
                "#!/usr/bin/env python3\nimport json,os,sys\n"
                "with open(os.environ['TRACE'],'a') as f: "
                "f.write(json.dumps([os.path.basename(sys.argv[0]),*sys.argv[1:]])+'\\n')\n"
                "sys.exit(int(os.environ.get('SETTINGS_EXIT' if "
                "os.path.basename(sys.argv[0])=='gsettings' else 'APP_EXIT','0')))\n"
            )
            path.chmod(0o755)

    def cache(self):
        root = self.env.get("XDG_CACHE_HOME") or str(Path(self.env["HOME"]) / ".cache")
        return Path(root) / "io.github.kolunmi.Bazaar/core/flathub-cache"

    def run_helper(self, *arguments):
        result = subprocess.run(["sh", str(HELPER), *arguments], env=self.env,
                                capture_output=True, text=True, timeout=10)
        trace = [json.loads(line) for line in self.trace.read_text().splitlines()]
        return result, trace

    def test_missing_cache_forces_refresh_before_normal_launch(self):
        result, trace = self.run_helper("--extra-curated-config", "/config/with spaces.yaml")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(trace, [
            ["gsettings", "set", "io.github.kolunmi.Bazaar", "last-refresh-time", "0"],
            ["bazaar-daemon", "--extra-curated-config", "/config/with spaces.yaml"],
        ])
        self.assertFalse(self.cache().exists(), "only Bazaar may create its real cache")

    def test_empty_cache_forces_refresh(self):
        self.cache().parent.mkdir(parents=True)
        self.cache().touch()
        _, trace = self.run_helper()
        self.assertEqual(trace[0][0], "gsettings")

    def test_existing_cache_and_refresh_preference_are_preserved(self):
        self.cache().parent.mkdir(parents=True)
        self.cache().write_bytes(b"opaque existing state owned by Bazaar")
        result, trace = self.run_helper("--search", "editor; $(touch ignored)")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(trace, [["bazaar-daemon", "--search", "editor; $(touch ignored)"]])
        self.assertEqual(self.cache().read_bytes(), b"opaque existing state owned by Bazaar")

    def test_default_cache_directory_uses_sandbox_home(self):
        self.env.pop("XDG_CACHE_HOME")
        self.cache().parent.mkdir(parents=True)
        self.cache().write_bytes(b"existing")
        _, trace = self.run_helper()
        self.assertEqual(trace, [["bazaar-daemon"]])

    def test_settings_failure_is_visible_without_breaking_store_launch(self):
        self.env["SETTINGS_EXIT"] = "7"
        result, trace = self.run_helper()
        self.assertEqual(result.returncode, 0)
        self.assertIn("could not enable cold-cache Explore refresh", result.stderr)
        self.assertEqual(trace[-1], ["bazaar-daemon"])

    def test_application_exit_status_is_preserved(self):
        self.env["APP_EXIT"] = "23"
        result, _ = self.run_helper()
        self.assertEqual(result.returncode, 23)

    def test_wrapper_renders_and_runs_helper_through_existing_sandbox(self):
        assets = self.root / "assets"
        assets.mkdir()
        (assets / HELPER.name).write_bytes(HELPER.read_bytes().replace(b"\r\n", b"\n"))
        (assets / "greyward-privacy.yaml").write_text("home: __GREYWARD_HOME__\n")
        fake_flatpak = self.bin / "flatpak"
        fake_flatpak.write_text(
            "#!/usr/bin/env python3\nimport json,os,sys\n"
            "with open(os.environ['TRACE'],'a') as f:f.write(json.dumps(sys.argv[1:])+'\\n')\n"
            "assert sys.argv[1:4]==['run','--command=sh','io.github.kolunmi.Bazaar']\n"
            "os.execvp('sh',['sh',*sys.argv[4:]])\n"
        )
        fake_flatpak.chmod(0o755)
        # Relocate only the two installed absolute roots for an unprivileged
        # filesystem fixture; retain the complete production shell logic.
        wrapper = self.root / "wrapper"
        wrapper.write_text((ROOT / "environment/flatpak/greyward-software").read_text()
                           .replace("/usr/share/greyward/bazaar", str(assets))
                           .replace("/usr/bin/flatpak", str(fake_flatpak)))
        self.env["XDG_CONFIG_HOME"] = str(self.root / "config with spaces")
        result = subprocess.run(["bash", str(wrapper), "--search", "test value"], env=self.env,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        trace = [json.loads(line) for line in self.trace.read_text().splitlines()]
        self.assertEqual(trace[0][:3], ["run", "--command=sh", "io.github.kolunmi.Bazaar"])
        self.assertEqual(trace[-1][-2:], ["--search", "test value"])
        self.assertEqual(trace[-1][1], "--extra-curated-config")
        self.assertEqual((Path(self.env["XDG_CONFIG_HOME"]) / "bazaar" / HELPER.name).read_bytes(),
                         HELPER.read_bytes().replace(b"\r\n", b"\n"))


class ImageInputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.stage = Path(self.temporary.name)
        for target, source in inputs.INPUTS.items():
            path = self.stage / target
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / source).read_bytes().replace(b"\r\n", b"\n"))

    def test_current_staging_passes(self):
        inputs.verify(ROOT, self.stage)

    def test_missing_helper_is_rejected(self):
        (self.stage / "flatpak/greyward-bazaar-start").unlink()
        with self.assertRaisesRegex(ValueError, "missing"):
            inputs.verify(ROOT, self.stage)

    def test_old_wrapper_or_helper_or_provisioner_is_rejected(self):
        for target in inputs.INPUTS:
            with self.subTest(target=target):
                path = self.stage / target
                current = path.read_bytes()
                path.write_bytes(b"#!/bin/sh\n# old payload with a self-consistent manifest\n")
                with self.assertRaisesRegex(ValueError, "differs"):
                    inputs.verify(ROOT, self.stage)
                path.write_bytes(current)

    def test_both_composition_boundaries_enforce_current_sources(self):
        builder = (ROOT / "environment/image/build-iso.sh").read_text()
        guard = 'python3 "$repo_root/environment/image/verify-software-inputs.py"'
        self.assertEqual(builder.count(guard), 2)
        first = builder.index(guard)
        last = builder.rindex(guard)
        self.assertLess(first, builder.index("\nmkksiso "))
        self.assertGreater(last, builder.index("-extract /greyward/production"))
        self.assertIn('--repo "$repo_root" --stage "$stage/production"', builder)
        self.assertIn('--repo "$repo_root" --stage "$publication/production"', builder)

    def test_provisioner_installs_helper_and_acceptance_checks_both_files(self):
        provision = (ROOT / "environment/production/provision.sh").read_text()
        self.assertIn('install -D -m 0644 "$flatpak/greyward-bazaar-start" '
                      '/usr/share/greyward/bazaar/greyward-bazaar-start', provision)
        acceptance = (ROOT / "environment/production/production-acceptance.sh").read_text()
        self.assertIn('for software_input in greyward-software greyward-bazaar-start', acceptance)
        self.assertIn('cmp -s "$source" "$installed"', acceptance)
        stager = (ROOT / "environment/image/build.sh").read_text()
        self.assertIn('cp -a "$flatpak" "$output/flatpak"', stager)


if __name__ == "__main__":
    unittest.main()
