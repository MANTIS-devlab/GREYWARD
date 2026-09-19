import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from greyward_security_context.provenance import provenance, sanitize_copy
from greyward_security_context.safe_open import SafeOpenError


class Session10Tests(unittest.TestCase):
    def test_notifications_do_not_expose_a_parallel_quarantine_action(self):
        router = (Path(__file__).parents[1] / "greyward_security_context" / "notification_router.py").read_text(encoding="utf-8")
        session = (Path(__file__).parents[1] / "greyward_security_context" / "session10_bus.py").read_text(encoding="utf-8")
        self.assertNotIn('"QuarantineThreat"', router)
        self.assertNotIn("--action=quarantine", router)
        self.assertNotIn("def QuarantineThreat", session)

    def test_unknown_provenance_is_bounded_and_redacted(self):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root) / "home"; home.mkdir()
            path = home / "Downloads" / "report.txt"; path.parent.mkdir(); path.write_text("x", encoding="utf-8")
            result = provenance(str(path), [{"kind": "USB_SCAN_RESULT", "state": "CLEAN", "file_ref": "other", "detail": str(path)}], [path.parent])
            self.assertEqual(result["source"]["state"], "UNKNOWN")
            self.assertEqual(result["scan"][0]["state"], "UNKNOWN")
            self.assertNotIn(str(path), str(result))
            self.assertEqual(result["trust"], "UNKNOWN")
            self.assertEqual(result["first_observed"]["state"], "UNKNOWN")
            self.assertIn("Before GREYWARD", result["first_observed"]["detail"])

    def test_scan_and_safe_open_context_are_file_specific(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "Downloads" / "report.txt"; path.parent.mkdir(); path.write_text("x", encoding="utf-8")
            first = provenance(str(path), roots=[path.parent])
            events = [{"kind": "USB_SCAN_RESULT", "state": "CLEAN", "file_ref": first["file_ref"], "detail": "clean"}, {"kind": "SAFE_OPEN_RESULT", "file_ref": first["file_ref"], "occurred_at": "2026-08-22T14:32:00Z"}]
            result = provenance(str(path), events, [path.parent])
            self.assertEqual(result["scan"][0]["state"], "CLEAN")
            self.assertEqual(result["safe_open"][0]["state"], "OBSERVED")

    def test_text_sanitization_creates_separate_copy(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "Downloads" / "notes.txt"; path.parent.mkdir(); path.write_text("hello", encoding="utf-8")
            result = sanitize_copy(str(path), [path.parent])
            self.assertTrue(result["original_unchanged"])
            self.assertEqual(Path(result["output"]).read_text(encoding="utf-8"), "hello")
            self.assertEqual(path.read_text(encoding="utf-8"), "hello")

    def test_unsupported_type_fails_honestly_without_copy(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "Downloads" / "archive.zip"; path.parent.mkdir(); path.write_bytes(b"zip")
            with self.assertRaisesRegex(SafeOpenError, "unsupported"):
                sanitize_copy(str(path), [path.parent])
            self.assertFalse((path.with_name("archive (sanitized).zip")).exists())


if __name__ == "__main__":
    unittest.main()

