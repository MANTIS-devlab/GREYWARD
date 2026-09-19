import os
import threading
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from greyward_security_context.file_security import FileSecurityManager, _parse_found, _safe_detected_file, _unlink_verified_source, file_activity_items
from greyward_security_context.telemetry import TelemetryStore

CURRENT_UID = getattr(os, "getuid", lambda: None)()


class FileSecurityContractTests(unittest.TestCase):
    def test_legacy_results_share_durable_detection_store_and_deduplicate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'sample.txt'
            source.write_text('test fixture')
            store = TelemetryStore(root / 'events.sqlite3')
            manager = FileSecurityManager(store)
            result = {'state': 'THREAT', 'detection_name': 'Fixture', 'detail': 'Detected'}
            manager.record_legacy_result(str(source), result)
            manager.record_legacy_result(str(source), result)
            self.assertEqual(len(manager.detections()), 1)
            self.assertTrue(store.list_file_scans(1)[0]['ended_at'])
            recovered = FileSecurityManager(store)
            self.assertEqual(recovered.detections()[0]['state'], 'DETECTED')

    def test_found_output_is_bounded_and_typed(self):
        self.assertEqual(_parse_found("/tmp/sample: Eicar-Signature FOUND"), ("/tmp/sample", "Eicar-Signature"))
        self.assertIsNone(_parse_found("/tmp/sample: OK"))
        path, name = _parse_found("/tmp/a: " + ("X" * 300) + " FOUND")
        self.assertLessEqual(len(path), 4096)
        self.assertLessEqual(len(name), 160)

    def test_scan_rejects_symlink_and_non_owned_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "sample.txt"
            source.write_text("safe", encoding="utf-8")
            link = root / "link.txt"
            try:
                link.symlink_to(source)
            except OSError:
                self.skipTest("symlink creation is unavailable in this test environment")
            manager = FileSecurityManager(TelemetryStore(root / "events.sqlite3"))
            # The production scanner has PrivateTmp=yes; this unit test is
            # exercising ownership and symlink policy, not that service
            # namespace boundary.
            with patch("greyward_security_context.file_security.PRIVATE_TMP_ROOTS", ()):
                with self.assertRaises(ValueError):
                    manager.start("FILE", [str(link)], owner_uid=CURRENT_UID)
                if CURRENT_UID is not None:
                    with self.assertRaises(PermissionError):
                        manager.start("FILE", [str(source)], owner_uid=CURRENT_UID + 1)

    def test_detection_remediation_rejects_parent_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir()
            source = real / "sample.txt"
            source.write_text("safe", encoding="utf-8")
            alias = root / "alias"
            try:
                alias.symlink_to(real, target_is_directory=True)
            except OSError:
                self.skipTest("symlink creation is unavailable in this test environment")
            with self.assertRaisesRegex(ValueError, "symlink"):
                _safe_detected_file(str(alias / source.name))

    def test_quarantine_copy_does_not_follow_a_raced_source_symlink(self):
        if not hasattr(os, "O_NOFOLLOW"):
            self.skipTest("the host has no no-follow open primitive")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            source.write_text("safe", encoding="utf-8")
            alias = root / "alias.txt"
            try:
                alias.symlink_to(source)
            except OSError:
                self.skipTest("symlink creation is unavailable in this test environment")
            with self.assertRaises(OSError):
                FileSecurityManager._copy_verified(alias, root / "copy.txt")

    def test_verified_source_removal_rejects_a_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            target = root / "target.txt"
            source.write_text("safe", encoding="utf-8")
            target.write_text("outside", encoding="utf-8")
            try:
                source.unlink()
                source.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable in this test environment")
            with self.assertRaises((OSError, ValueError)):
                _unlink_verified_source(source)
            self.assertTrue(target.exists())

    def test_operation_and_detection_state_are_durable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "sample.txt"
            source.write_text("fixture", encoding="utf-8")
            store = TelemetryStore(root / "events.sqlite3")
            manager = FileSecurityManager(store)
            with patch("greyward_security_context.file_security.PRIVATE_TMP_ROOTS", ()), patch("greyward_security_context.file_security.clamav_status", return_value={"status": "CURRENT", "engine_version": "1", "database_version": "2"}), patch.object(manager, "_run"):
                operation = manager.start("FILE", [str(source)], owner_uid=CURRENT_UID)
            self.assertEqual(operation["state"], "QUEUED")
            detection = store.upsert_file_detection({
                "detection_id": "det-fixture",
                "operation_id": operation["operation_id"],
                "original_path": str(source),
                "file_ref": "file-fixture",
                "detection_name": "Test.Signature",
                "state": "DETECTED",
            })
            self.assertEqual(store.get_file_detection(detection["detection_id"])["state"], "DETECTED")
            self.assertEqual(manager.status(operation["operation_id"])["detections"][0]["detection_id"], "det-fixture")

    def test_last_scan_scope_and_non_clean_states_remain_durable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = TelemetryStore(root / "events.sqlite3")
            store.create_file_scan({
                "operation_id": "scan-partial",
                "mode": "FOLDER",
                "scope": {"label": "Downloads", "path": "/home/user/Downloads"},
                "state": "SCANNING",
                "phase": "SCANNING",
                "started_at": "2026-08-30T10:00:00Z",
            })
            store.update_file_scan(
                "scan-partial",
                state="PARTIAL",
                phase="PARTIAL",
                ended_at="2026-08-30T10:01:00Z",
                files_inspected=7,
                error_count=1,
            )
            result = store.get_file_scan("scan-partial")
            self.assertEqual(result["state"], "PARTIAL")
            self.assertEqual(result["phase"], "PARTIAL")
            self.assertEqual(result["scope"], {"label": "Downloads", "path": "/home/user/Downloads"})
            self.assertEqual(result["ended_at"], "2026-08-30T10:01:00Z")

    def test_orphaned_active_scan_is_durably_interrupted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = TelemetryStore(root / "events.sqlite3")
            store.create_file_scan({
                "operation_id": "scan-orphaned",
                "mode": "FILE",
                "scope": {"label": "sample.txt", "path": "/home/user/sample.txt"},
                "state": "SCANNING",
                "phase": "SCANNING",
                "started_at": "2026-08-30T10:00:00Z",
                "files_inspected": 4,
            })
            recovered = FileSecurityManager(store)
            result = recovered.status("scan-orphaned")
            self.assertEqual(result["state"], "INTERRUPTED")
            self.assertEqual(result["phase"], "INTERRUPTED")
            self.assertEqual(result["files_inspected"], 4)
            self.assertTrue(result["ended_at"])
            self.assertEqual(store.get_file_scan("scan-orphaned")["state"], "INTERRUPTED")
            self.assertIsNone(recovered._active())

    def test_scan_is_not_queued_when_clamav_cannot_produce_a_current_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "sample.txt"
            source.write_text("fixture", encoding="utf-8")
            store = TelemetryStore(root / "events.sqlite3")
            manager = FileSecurityManager(store)
            with patch("greyward_security_context.file_security.PRIVATE_TMP_ROOTS", ()), patch("greyward_security_context.file_security.clamav_status", return_value={"status": "OUTDATED", "engine_version": "1"}):
                with self.assertRaisesRegex(RuntimeError, "current security database"):
                    manager.start("FILE", [str(source)], owner_uid=CURRENT_UID)
            self.assertEqual(store.list_file_scans(64), [])

    def test_detected_files_are_counted_once_and_clean_files_are_inspected_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clean = root / "clean.txt"
            threat = root / "threat.txt"
            clean.write_text("clean", encoding="utf-8")
            threat.write_text("threat", encoding="utf-8")
            store = TelemetryStore(root / "events.sqlite3")
            store.create_file_scan({"operation_id": "scan-count", "mode": "FOLDER", "scope": {"path": str(root)}, "state": "QUEUED", "phase": "QUEUED", "started_at": "2026-08-31T10:00:00Z"})
            manager = FileSecurityManager(store)

            class Process:
                pid = 1
                stdout = iter([f"{clean}: OK\n", f"{threat}: Test.Signature FOUND\n", f"{threat}: Test.Signature FOUND\n", f"{clean}: OK\n"])
                def wait(self, timeout=None): return 1
                def poll(self): return 0

            with patch("greyward_security_context.file_security.clamav_status", return_value={"status": "CURRENT", "engine_version": "1", "database_version": "2"}), patch("greyward_security_context.file_security.subprocess.Popen", return_value=Process()):
                manager._run("scan-count", "FOLDER", {"path": str(root)}, threading.Event())
            result = store.get_file_scan("scan-count")
            self.assertEqual(result["state"], "COMPLETED")
            self.assertEqual(result["files_inspected"], 2)
            self.assertEqual(result["detection_count"], 1)
            self.assertEqual(len(store.list_file_detections(operation_id="scan-count")), 1)

    def test_scanner_detection_exit_without_actionable_path_is_not_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = TelemetryStore(root / "events.sqlite3")
            store.create_file_scan({
                "operation_id": "scan-unparsed-detection",
                "mode": "FILE",
                "scope": {"path": str(root / "sample.txt")},
                "state": "QUEUED",
                "phase": "QUEUED",
                "started_at": "2026-08-31T10:00:00Z",
            })
            manager = FileSecurityManager(store)

            class Process:
                pid = 1
                stdout = iter([])

                def wait(self, timeout=None):
                    return 1

                def poll(self):
                    return 0

            with patch("greyward_security_context.file_security.clamav_status", return_value={"status": "CURRENT", "engine_version": "1", "database_version": "2"}), patch("greyward_security_context.file_security.subprocess.Popen", return_value=Process()):
                manager._run("scan-unparsed-detection", "FILE", {"path": str(root / "sample.txt")}, threading.Event())

            result = store.get_file_scan("scan-unparsed-detection")
            self.assertEqual(result["state"], "PARTIAL")
            self.assertIn("no actionable detection", result["detail"])

    def test_private_tmp_namespace_is_rejected_before_queueing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "sample.txt"
            source.write_text("fixture", encoding="utf-8")
            manager = FileSecurityManager(TelemetryStore(root / "events.sqlite3"))
            with patch("greyward_security_context.file_security.PRIVATE_TMP_ROOTS", (root,)), patch("greyward_security_context.file_security.clamav_status", return_value={"status": "CURRENT", "engine_version": "1"}):
                with self.assertRaisesRegex(ValueError, "not visible"):
                    manager.start("FILE", [str(source)], owner_uid=CURRENT_UID)

    def test_file_activity_projection_covers_terminal_and_remediation_events(self):
        event_types = [
            "FILE_SCAN_COMPLETED", "FILE_SCAN_CANCELLED", "FILE_SCAN_PARTIAL",
            "FILE_SCAN_FAILED", "FILE_DETECTION", "FILE_QUARANTINED",
            "FILE_RESTORED", "FILE_DELETED", "SANITIZATION_RESULT",
            "SAFE_OPEN_RESULT",
        ]
        values = [
            {"event_id": f"event-{event_type}", "event_type": event_type,
             "outcome": "SUCCESS", "occurred_at": "2026-08-31T10:00:00Z",
             "details": {"message": "recorded"}}
            for event_type in event_types
        ]
        projected = file_activity_items(values, limit=32)
        self.assertEqual({item["event_id"] for item in projected}, {f"event-{event_type}" for event_type in event_types})
        self.assertEqual({item["category"] for item in projected}, {"FILE_SECURITY"})

    def test_quarantine_restore_and_delete_are_explicit_and_collision_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "sample.txt"
            source.write_text("fixture", encoding="utf-8")
            store = TelemetryStore(root / "events.sqlite3")
            manager = FileSecurityManager(store)
            # Keep the fake quarantine root independent of the real owner UID
            # so the unit fixture exercises the workflow without depending on
            # the production /var/lib/greyward/quarantine layout.
            manager._quarantine_root = lambda owner_uid: root / "quarantine"
            detection = store.upsert_file_detection({
                "detection_id": "det-action",
                "operation_id": "scan-action",
                "original_path": str(source),
                "file_ref": "file-action",
                "detection_name": "Test.Signature",
                "file_hash": None,
                "state": "DETECTED",
            })
            quarantined = manager.quarantine_detection(detection["detection_id"])
            self.assertEqual(quarantined["state"], "QUARANTINED")
            self.assertFalse(source.exists())
            staging = root / "review" / "restored.txt"
            staging.parent.mkdir()
            staging.write_text("existing", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                manager.restore_detection(detection["detection_id"], str(staging))
            staging.unlink()
            restored = manager.restore_detection(detection["detection_id"], str(staging))
            self.assertEqual(restored["state"], "RESTORED")
            self.assertEqual(restored["restore_staging_path"], str(staging))
            self.assertEqual(
                store.get_file_detection(detection["detection_id"])["restore_staging_path"],
                str(staging),
            )
            store.upsert_file_detection({**restored, "state": "QUARANTINED"})
            deleted = manager.delete_detection(detection["detection_id"])
            self.assertEqual(deleted["state"], "DELETED")


if __name__ == "__main__":
    unittest.main()
