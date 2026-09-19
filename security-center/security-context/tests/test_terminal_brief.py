import importlib.util
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
RENDERER_PATH = REPOSITORY_ROOT / "environment" / "production" / "zsh" / "greyward-terminal-brief.py"
SPEC = importlib.util.spec_from_file_location("greyward_terminal_brief", RENDERER_PATH)
RENDERER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RENDERER)


class TerminalBriefTests(unittest.TestCase):
    def setUp(self):
        self.fresh_until = (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
        self.value = {
            "freshness": "FRESH",
            "fresh_until": self.fresh_until,
            "posture": {"state": "PROTECTED"},
            "network": {"state": "OPERATING"},
            "network_profile": {"state": "STANDARD"},
            "firewall": {"state": "PUBLIC"},
            "secure_dns": {"state": "SECUREPROVIDER", "transport": "DOT"},
            "update": {"phase": "COMPLETE"},
        }

    def test_full_brief_uses_terminal_safe_logo_and_core_state(self):
        output = RENDERER.render(self.value, color=False, width=100)
        self.assertIn("+-- GREYWARD", output)
        self.assertIn("kernel", output)
        self.assertIn("memory", output)
        self.assertIn("shell", output)
        self.assertNotIn("Security", output)
        self.assertNotIn("Network", output)
        self.assertNotIn("DNS", output)
        self.assertNotRegex(output, r"\x1b\[")
        self.assertTrue(all(ord(character) < 128 for character in output))

    def test_narrow_brief_remains_compact(self):
        output = RENDERER.render(self.value, color=False, width=55)
        self.assertEqual(output.splitlines()[0], "+-- GREYWARD --+")
        self.assertIn("kernel", output)
        self.assertIn("memory", output)
        self.assertNotIn("Security", output)

    def test_rapid_session_brief_is_one_line(self):
        output = RENDERER.render_compact(self.value, color=False)
        self.assertEqual(output.count("\n"), 0)
        self.assertIn("GREYWARD |", output)
        self.assertIn("memory", output)
        self.assertNotIn("Security", output)
        self.assertNotIn("DNS", output)

    def test_expired_projection_is_neutral(self):
        self.value["fresh_until"] = "2000-01-01T00:00:00Z"
        output = RENDERER.render(self.value, color=False, width=100)
        self.assertIn("GREYWARD", output)
        self.assertIn("kernel", output)

    def test_startup_does_not_require_security_context_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            previous = os.environ.get("XDG_RUNTIME_DIR")
            os.environ["XDG_RUNTIME_DIR"] = directory
            try:
                output = RENDERER.render({}, color=False, width=100)
            finally:
                if previous is None:
                    os.environ.pop("XDG_RUNTIME_DIR", None)
                else:
                    os.environ["XDG_RUNTIME_DIR"] = previous
        self.assertIn("GREYWARD", output)
        self.assertIn("kernel", output)


if __name__ == "__main__":
    unittest.main()
