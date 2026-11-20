"""MailCraft's desktop defaults and upstream release trust boundary."""

import base64
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SOURCE = Path(__file__).resolve().parents[1] / "environment/production/mailcraft"


def module(name):
    spec = importlib.util.spec_from_file_location(f"mailcraft_{name}", SOURCE / f"{name}.py")
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


launch = module("launch")
refresh = module("refresh")


class MailCraftTests(unittest.TestCase):
    def test_first_launch_is_dark_and_keeps_later_user_choice(self):
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder)
            launch.seed_defaults(config)
            prefs = config / "mailcraft/ui.json"
            self.assertEqual(json.loads(prefs.read_bytes()), {
                "theme": "dark", "darkStyle": "neutral", "accent": "teal",
            })
            prefs.write_bytes(b'{"theme":"light","view":{"sort":"from"}}')
            launch.seed_defaults(config)
            self.assertEqual(prefs.read_bytes(), b'{"theme":"light","view":{"sort":"from"}}')

    def test_only_signed_unique_checksum_is_used(self):
        key = Ed25519PrivateKey.generate()
        public = base64.b64encode(key.public_key().public_bytes_raw())
        filename = "mailcraft-0.14.0-linux-x86_64.rpm"
        expected = "a" * 64
        sums = f"{expected}  {filename}\n".encode()

        def signature(payload):
            return base64.b64encode(key.sign(payload))

        self.assertEqual(refresh.signed_digest(sums, signature(sums), filename, (public,)), expected)
        with self.assertRaisesRegex(ValueError, "not trusted"):
            refresh.signed_digest(sums.replace(b"a", b"b", 1), signature(sums), filename, (public,))
        with self.assertRaisesRegex(ValueError, "exactly once"):
            refresh.signed_digest(sums * 2, signature(sums * 2), filename, (public,))
        with self.assertRaisesRegex(ValueError, "exactly once"):
            refresh.signed_digest(sums, signature(sums), filename + ".other", (public,))

    def test_only_official_stable_tags_are_accepted(self):
        release = {
            "tag_name": "v0.14.0", "draft": False, "prerelease": False,
            "html_url": f"https://github.com/{refresh.PROJECT}/releases/tag/v0.14.0",
        }
        self.assertEqual(refresh.release_version(release), "0.14.0")
        for change in ({"prerelease": True}, {"draft": True}, {"html_url": "https://example.com"},
                       {"tag_name": "v0.14.0-rc.1"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                refresh.release_version({**release, **change})


if __name__ == "__main__":
    unittest.main()
