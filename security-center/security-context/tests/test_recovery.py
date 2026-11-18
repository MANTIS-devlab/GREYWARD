import json
import os
import tempfile
import unittest
import subprocess
from pathlib import Path
from unittest.mock import patch

from greyward_security_context import recovery, restic_backup


class RecoveryTests(unittest.TestCase):
    def test_inspection_does_not_count_missing_snapshot_as_available(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root) / "points"
            for name in ("present", "missing"):
                point = base / name
                recovery.atomic_write(point / "metadata.json", {
                    "id": name, "status": "valid", "snapshots": [{"path": "root", "read_only": True}],
                })
            (base / "present" / "root").mkdir()
            with patch.object(recovery, "state_dir", return_value=Path(root)), patch.object(recovery.shutil, "which", return_value="/usr/bin/btrfs"), patch.object(recovery, "run", return_value=subprocess.CompletedProcess([], 0, "btrfs\n", "")):
                self.assertEqual({p["id"]: p["status"] for p in recovery.inspect_points()["points"]}, {
                    "present": "valid", "missing": "incomplete",
                })

    def test_root_probe_failure_preserves_the_permission_error(self):
        result = subprocess.CompletedProcess([], 1, "", "ERROR: Operation not permitted")
        with patch.object(recovery.shutil, "which", return_value="/usr/bin/btrfs"), patch.object(recovery, "run", return_value=result):
            with self.assertRaisesRegex(recovery.RecoveryError, "Operation not permitted"):
                recovery.ensure_btrfs_root()

    def test_root_state_directory_cannot_be_redirected_by_environment(self):
        with patch.dict(os.environ, {"GREYWARD_RECOVERY_STATE_DIR": "/tmp/untrusted-recovery"}):
            self.assertEqual(recovery.state_dir(), recovery.DEFAULT_STATE_DIR)

    def test_manual_point_records_exclusions_and_metadata(self):
        with tempfile.TemporaryDirectory() as root:
            with patch.object(recovery, "DEFAULT_STATE_DIR", Path(root)), patch.object(recovery, "ensure_btrfs_root"), patch.object(recovery, "is_subvolume", return_value=False), patch.object(recovery, "capture_boot", return_value={"sha256": "digest", "bytes": 5}), patch.object(recovery, "run") as command:
                command.return_value.returncode = 0
                value = recovery.create("manual")
                self.assertEqual(value["status"], "valid")
                self.assertEqual(value["operation_id"], None)
                self.assertIn("/home", value["excluded"])
                self.assertNotIn("/boot", value["excluded"])
                self.assertEqual(value["boot_archive"]["bytes"], 5)
                self.assertTrue((Path(root) / "points" / value["id"] / "metadata.json").exists())

    def test_failed_boot_capture_leaves_no_valid_point(self):
        with (
            tempfile.TemporaryDirectory() as root,
            patch.object(recovery, "DEFAULT_STATE_DIR", Path(root)),
            patch.object(recovery, "ensure_btrfs_root"),
            patch.object(recovery, "is_subvolume", return_value=False),
            patch.object(recovery, "capture_boot", side_effect=recovery.RecoveryError("Boot unavailable")),
            patch.object(recovery, "run"),
            patch.object(recovery, "record_event"),
        ):
            with self.assertRaisesRegex(recovery.RecoveryError, "Boot unavailable"):
                recovery.create("pre-update", "dnf5-123")
            point, = recovery.list_points()
            self.assertEqual(point["status"], "failed")
            self.assertNotIn("boot_archive", point)

    def test_cleanup_keeps_three_valid_points(self):
        with tempfile.TemporaryDirectory() as root:
            with patch.object(recovery, "DEFAULT_STATE_DIR", Path(root)):
                base = Path(root) / "points"
                for index in range(4):
                    point = base / f"point-{index}"; point.mkdir(parents=True)
                    (point / "metadata.json").write_text(json.dumps({"id": point.name, "created_at": f"2026-01-0{index + 1}T00:00:00Z", "status": "valid", "snapshots": []}), encoding="utf-8")
                result = recovery.cleanup()
                self.assertEqual(len(result["kept"]), 3)
                self.assertEqual(result["removed"], ["point-0"])

    def test_cleanup_refuses_unsafe_snapshot_metadata(self):
        with tempfile.TemporaryDirectory() as root, patch.object(recovery, "DEFAULT_STATE_DIR", Path(root)):
            point = Path(root) / "points" / "failed-point"
            point.mkdir(parents=True)
            (point / "metadata.json").write_text(json.dumps({
                "id": "failed-point",
                "created_at": "2026-01-01T00:00:00Z",
                "status": "failed",
                "snapshots": [{"path": "../home"}],
            }), encoding="utf-8")
            with self.assertRaises(recovery.RecoveryError):
                recovery.cleanup()


class ResticBackupTests(unittest.TestCase):
    @staticmethod
    def _result(stdout="", returncode=0):
        return subprocess.CompletedProcess(["restic"], returncode, stdout, "")

    @staticmethod
    def _mount(target, source, uuid):
        return subprocess.CompletedProcess(["findmnt"], 0, json.dumps({
            "filesystems": [{"target": target, "source": source, "fstype": "ext4", "uuid": uuid}],
        }), "")

    def test_repository_identity_parses_pretty_printed_restic_config(self):
        output = '{\n  "version": 2,\n  "id": "abc123",\n  "chunker_polynomial": "31c7c6c5235e31"\n}\n'
        self.assertEqual(restic_backup._repository_id_from_config_output(output), "restic:abc123")

    def test_status_requires_explicit_configuration(self):
        with tempfile.TemporaryDirectory() as root, patch.object(restic_backup, "CONFIG_PATH", Path(root) / "config.json"), patch.object(restic_backup, "STATE_PATH", Path(root) / "state.json"):
            value = restic_backup.status()
            self.assertFalse(value["configured"])
            self.assertNotIn("default_destination", value)

    def test_empty_configuration_path_is_refused(self):
        with tempfile.TemporaryDirectory() as root, patch.object(restic_backup, "CONFIG_PATH", Path(root) / "config.json"), patch.object(restic_backup, "STATE_PATH", Path(root) / "state.json"):
            with self.assertRaisesRegex(restic_backup.BackupError, "mounted backup destination"):
                restic_backup.configure("", "secret", "secret")

    def test_failed_reconfiguration_preserves_existing_configuration(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            config_path = root / "config.json"
            state_path = root / "state.json"
            destination = root / "mounted"
            destination.mkdir()
            mount = {"target": "/mnt/drive", "source": "/dev/test", "filesystem": "ext4", "uuid": "test-uuid"}
            previous = {
                "schema": "greyward.restic-backup/v1",
                "destination": "/mnt/previous",
                "repository": "/mnt/previous/.greyward-restic",
                "repository_id": "restic:previous",
            }
            with patch.object(restic_backup, "CONFIG_PATH", config_path), patch.object(restic_backup, "STATE_PATH", state_path), patch.object(restic_backup, "_validated_destination", return_value=(destination, mount)), patch.object(restic_backup, "restic", side_effect=restic_backup.BackupError("repository could not be initialized")):
                restic_backup.atomic_write(config_path, previous)
                with self.assertRaises(restic_backup.BackupError):
                    restic_backup.configure(str(destination), "secret", "secret")
            self.assertEqual(json.loads(config_path.read_text(encoding="utf-8")), previous)

    def test_configuration_records_mount_identity(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            config_path = root / "config.json"
            state_path = root / "state.json"
            destination = root / "mounted"
            destination.mkdir()
            mount = {"target": "/mnt/drive", "source": "/dev/test", "filesystem": "ext4", "uuid": "test-uuid"}
            with patch.object(restic_backup, "CONFIG_PATH", config_path), patch.object(restic_backup, "STATE_PATH", state_path), patch.object(restic_backup, "_validated_destination", return_value=(destination, mount)), patch.object(restic_backup, "restic", return_value=self._result("")), patch.object(restic_backup, "repository_identity", return_value="restic:new"):
                restic_backup.configure(str(destination), "secret", "secret")
            value = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertEqual(value["mount"], mount)
            self.assertEqual(value["repository_id"], "restic:new")

    def test_backup_requires_a_configured_destination(self):
        with tempfile.TemporaryDirectory() as root, patch.object(restic_backup, "CONFIG_PATH", Path(root) / "config.json"), patch.object(restic_backup, "STATE_PATH", Path(root) / "state.json"), patch.object(restic_backup, "sources", return_value=[Path(root) / "Documents"]):
            Path(root, "Documents").mkdir()
            with self.assertRaisesRegex(restic_backup.BackupError, "No backup destination"):
                restic_backup.backup("secret")

    def test_mount_probe_timeout_is_reported_as_destination_failure(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as home:
            destination = Path(root) / "mounted"
            destination.mkdir()
            with patch.object(restic_backup.Path, "home", return_value=Path(home)), patch("greyward_security_context.restic_backup.shutil.which", return_value="/usr/bin/findmnt"), patch.object(restic_backup.subprocess, "run", side_effect=subprocess.TimeoutExpired("findmnt", 8)):
                with self.assertRaisesRegex(restic_backup.BackupError, "mount could not be validated"):
                    restic_backup.destination(str(destination))

    def test_home_destination_is_rejected_before_mount_probe(self):
        with tempfile.TemporaryDirectory() as home:
            destination = Path(home) / "backup"
            destination.mkdir()
            with patch.object(restic_backup.Path, "home", return_value=Path(home)), patch.object(restic_backup.subprocess, "run") as probe:
                with self.assertRaisesRegex(restic_backup.BackupError, "outside the home directory"):
                    restic_backup.destination(str(destination))
            probe.assert_not_called()

    def test_non_mounted_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as home:
            destination = Path(root) / "backup"
            destination.mkdir()
            result = self._mount("/", "/dev/root", "root-uuid")
            with patch.object(restic_backup.Path, "home", return_value=Path(home)), patch("greyward_security_context.restic_backup.shutil.which", return_value="/usr/bin/findmnt"), patch.object(restic_backup.subprocess, "run", return_value=result):
                with self.assertRaisesRegex(restic_backup.BackupError, "not mounted"):
                    restic_backup.destination(str(destination))

    def test_valid_mount_subdirectory_is_accepted(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as home:
            destination = Path(root) / "mounted" / "backup"
            destination.mkdir(parents=True)
            result = self._mount("/run/media/test/My Backup", "/dev/sdb1", "test-uuid")
            with patch.object(restic_backup.Path, "home", return_value=Path(home)), patch("greyward_security_context.restic_backup.shutil.which", return_value="/usr/bin/findmnt"), patch.object(restic_backup.subprocess, "run", return_value=result):
                self.assertEqual(restic_backup.destination(str(destination)), destination.resolve())

    def test_malformed_mount_probe_is_reported_as_validation_failure(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as home:
            destination = Path(root) / "backup"
            destination.mkdir()
            result = subprocess.CompletedProcess(["findmnt"], 0, stdout="/run/media/test/device\n", stderr="")
            with patch.object(restic_backup.Path, "home", return_value=Path(home)), patch("greyward_security_context.restic_backup.shutil.which", return_value="/usr/bin/findmnt"), patch.object(restic_backup.subprocess, "run", return_value=result):
                with self.assertRaisesRegex(restic_backup.BackupError, "mount could not be validated"):
                    restic_backup.destination(str(destination))

    def test_missing_mount_provider_is_reported_explicitly(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as home:
            destination = Path(root) / "backup"
            destination.mkdir()
            with patch.object(restic_backup.Path, "home", return_value=Path(home)), patch("greyward_security_context.restic_backup.shutil.which", return_value=None):
                with self.assertRaisesRegex(restic_backup.BackupError, "findmnt is unavailable"):
                    restic_backup.destination(str(destination))

    def test_mount_command_failure_is_reported_as_validation_failure(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as home:
            destination = Path(root) / "backup"
            destination.mkdir()
            result = subprocess.CompletedProcess(["findmnt"], 1, stdout="", stderr="findmnt: failed")
            with patch.object(restic_backup.Path, "home", return_value=Path(home)), patch("greyward_security_context.restic_backup.shutil.which", return_value="/usr/bin/findmnt"), patch.object(restic_backup.subprocess, "run", return_value=result):
                with self.assertRaisesRegex(restic_backup.BackupError, "mount could not be validated"):
                    restic_backup.destination(str(destination))

    def test_symlink_destination_is_rejected_before_mount_probe(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as home:
            target = Path(root) / "target"
            target.mkdir()
            link = Path(root) / "link"
            try:
                link.symlink_to(target, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"directory symlinks are unavailable: {error}")
            with patch.object(restic_backup.Path, "home", return_value=Path(home)), patch.object(restic_backup.subprocess, "run") as probe:
                with self.assertRaisesRegex(restic_backup.BackupError, "available directory"):
                    restic_backup.destination(str(link))
            probe.assert_not_called()

    def test_restic_rejects_disappeared_mount_before_starting_restic(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as home:
            destination = Path(root) / "mounted"
            destination.mkdir()
            config_path = Path(root) / "config.json"
            mount = {"target": "/run/media/test/device", "source": "/dev/sdb1", "filesystem": "ext4", "uuid": "test-uuid"}
            with patch.object(restic_backup, "CONFIG_PATH", config_path), patch.object(restic_backup.Path, "home", return_value=Path(home)), patch("greyward_security_context.restic_backup.shutil.which", return_value="/usr/bin/findmnt"), patch.object(restic_backup.subprocess, "run", return_value=self._mount("/", "/dev/root", "root-uuid")) as probe:
                restic_backup.atomic_write(config_path, {"destination": str(destination), "repository": str(restic_backup.repository(destination)), "mount": mount})
                with self.assertRaisesRegex(restic_backup.BackupError, "not mounted"):
                    restic_backup.restic(["snapshots"], "secret")
            self.assertEqual(probe.call_count, 1)
            self.assertEqual(probe.call_args.args[0][0], "findmnt")

    def test_restic_rejects_a_different_filesystem_at_the_same_mountpoint(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as home:
            destination = Path(root) / "mounted"
            destination.mkdir()
            config_path = Path(root) / "config.json"
            mount = {"target": "/run/media/test/device", "source": "/dev/sdb1", "filesystem": "ext4", "uuid": "test-uuid"}
            current = self._mount("/run/media/test/device", "/dev/sdc1", "replacement-uuid")
            with patch.object(restic_backup, "CONFIG_PATH", config_path), patch.object(restic_backup.Path, "home", return_value=Path(home)), patch("greyward_security_context.restic_backup.shutil.which", return_value="/usr/bin/findmnt"), patch.object(restic_backup.subprocess, "run", return_value=current) as probe:
                restic_backup.atomic_write(config_path, {"destination": str(destination), "repository": str(restic_backup.repository(destination)), "mount": mount})
                with self.assertRaisesRegex(restic_backup.BackupError, "mount identity has changed"):
                    restic_backup.restic(["snapshots"], "secret")
            self.assertEqual(probe.call_count, 1)
            self.assertEqual(probe.call_args.args[0][0], "findmnt")

    def test_status_does_not_require_a_passphrase_or_run_check(self):
        with tempfile.TemporaryDirectory() as root, patch.object(restic_backup, "CONFIG_PATH", Path(root) / "config.json"), patch.object(restic_backup, "STATE_PATH", Path(root) / "state.json"):
            restic_backup.atomic_write(restic_backup.CONFIG_PATH, {"repository": "/mnt/drive/.greyward-restic", "destination": "/mnt/drive"})
            value = restic_backup.status()
            self.assertTrue(value["configured"])
            self.assertIsNone(value["last_check_at"])

    def test_status_preserves_the_current_destination_problem(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as home:
            root = Path(root)
            destination = root / "mounted"
            destination.mkdir()
            config_path = root / "config.json"
            state_path = root / "state.json"
            mount = {"target": "/run/media/test/device", "source": "/dev/sdb1", "filesystem": "ext4", "uuid": "test-uuid"}
            with patch.object(restic_backup, "CONFIG_PATH", config_path), patch.object(restic_backup, "STATE_PATH", state_path), patch.object(restic_backup.Path, "home", return_value=Path(home)), patch("greyward_security_context.restic_backup.shutil.which", return_value="/usr/bin/findmnt"), patch.object(restic_backup.subprocess, "run", return_value=self._mount("/", "/dev/root", "root-uuid")):
                restic_backup.atomic_write(config_path, {"destination": str(destination), "repository": str(restic_backup.repository(destination)), "mount": mount, "repository_id": "restic:test"})
                value = restic_backup.status()
            self.assertFalse(value["destination_available"])
            self.assertEqual(value["destination_problem"], "DESTINATION_NOT_MOUNTED")

    def test_status_does_not_report_stale_operation_without_configuration(self):
        with tempfile.TemporaryDirectory() as root, patch.object(restic_backup, "CONFIG_PATH", Path(root) / "config.json"), patch.object(restic_backup, "STATE_PATH", Path(root) / "state.json"):
            restic_backup.atomic_write(restic_backup.STATE_PATH, {"last_backup_status": "FAILED", "last_backup_problem": "TRY_AGAIN"})
            value = restic_backup.status()
            self.assertFalse(value["configured"])
            self.assertIsNone(value["last_backup_status"])
            self.assertIsNone(value["last_backup_problem"])
            self.assertIsNone(value["operation"])

    def test_repository_switch_hides_previous_repository_state(self):
        with tempfile.TemporaryDirectory() as root, patch.object(restic_backup, "CONFIG_PATH", Path(root) / "config.json"), patch.object(restic_backup, "STATE_PATH", Path(root) / "state.json"):
            restic_backup.atomic_write(restic_backup.CONFIG_PATH, {"repository": "/mnt/a/.greyward-restic", "destination": "/mnt/a", "repository_id": "restic:a"})
            restic_backup.atomic_write(restic_backup.STATE_PATH, {"repositories": {"restic:a": {"last_backup_status": "SUCCESSFUL", "last_check_status": "VERIFIED"}}})
            self.assertEqual(restic_backup.status()["last_backup_status"], "SUCCESSFUL")

            restic_backup.atomic_write(restic_backup.CONFIG_PATH, {"repository": "/mnt/b/.greyward-restic", "destination": "/mnt/b", "repository_id": "restic:b"})
            switched = restic_backup.status()
            self.assertEqual(switched["repository_id"], "restic:b")
            self.assertIsNone(switched["last_backup_status"])
            self.assertIsNone(switched["last_check_status"])

            restic_backup.atomic_write(restic_backup.CONFIG_PATH, {"repository": "/mnt/a/.greyward-restic", "destination": "/mnt/a", "repository_id": "restic:a"})
            returned = restic_backup.status()
            self.assertEqual(returned["last_backup_status"], "SUCCESSFUL")
            self.assertEqual(returned["last_check_status"], "VERIFIED")

    def test_missing_repository_identity_hides_legacy_global_state(self):
        with tempfile.TemporaryDirectory() as root, patch.object(restic_backup, "CONFIG_PATH", Path(root) / "config.json"), patch.object(restic_backup, "STATE_PATH", Path(root) / "state.json"):
            restic_backup.atomic_write(restic_backup.CONFIG_PATH, {"repository": "/mnt/a/.greyward-restic", "destination": "/mnt/a"})
            restic_backup.atomic_write(restic_backup.STATE_PATH, {"last_backup_status": "SUCCESSFUL", "last_check_status": "VERIFIED"})
            value = restic_backup.status()
            self.assertTrue(value["configured"])
            self.assertIsNone(value["repository_id"])
            self.assertIsNone(value["last_backup_status"])
            self.assertIsNone(value["last_check_status"])

    def test_backup_updates_success_without_checking_repository(self):
        with tempfile.TemporaryDirectory() as root, patch.object(restic_backup, "CONFIG_PATH", Path(root) / "config.json"), patch.object(restic_backup, "STATE_PATH", Path(root) / "state.json"), patch.object(restic_backup, "sources", return_value=[Path(root) / "Documents"]), patch.object(restic_backup, "repository_identity", return_value="restic:test"), patch.object(restic_backup, "restic") as run:
            Path(root, "Documents").mkdir()
            run.side_effect = [self._result('{"message_type":"summary","snapshot_id":"abc123"}\n'), self._result()]
            restic_backup.atomic_write(restic_backup.CONFIG_PATH, {"repository": "/mnt/drive/.greyward-restic", "destination": "/mnt/drive"})
            value = restic_backup.backup("secret")
            self.assertEqual(value["status"], "SUCCESSFUL")
            self.assertEqual([call.args[0][0] for call in run.call_args_list], ["backup", "forget"])

    def test_partial_backup_keeps_previous_success_and_skips_pruning(self):
        with tempfile.TemporaryDirectory() as root, patch.object(restic_backup, "CONFIG_PATH", Path(root) / "config.json"), patch.object(restic_backup, "STATE_PATH", Path(root) / "state.json"), patch.object(restic_backup, "sources", return_value=[Path(root) / "Documents"]), patch.object(restic_backup, "repository_identity", return_value="restic:test"), patch.object(restic_backup, "restic") as run:
            restic_backup.atomic_write(restic_backup.CONFIG_PATH, {"repository": "/mnt/drive/.greyward-restic"})
            restic_backup.atomic_write(restic_backup.STATE_PATH, {"repositories": {"restic:test": {"last_backup_at": "2026-01-01T12:00:00Z", "last_snapshot_id": "last-good"}}})
            run.return_value = self._result('{"message_type":"summary","snapshot_id":"partial"}\n', 3)
            result = restic_backup.backup("secret")
            self.assertFalse(result["ok"])
            self.assertEqual(result["problem"], "SOURCE_UNREADABLE")
            record = restic_backup.load_state()["repositories"]["restic:test"]
            self.assertEqual(record["last_snapshot_id"], "last-good")
            self.assertEqual(record["last_backup_at"], "2026-01-01T12:00:00Z")
            self.assertEqual(run.call_count, 1)

    def test_retention_failure_keeps_completed_backup_successful(self):
        with tempfile.TemporaryDirectory() as root, patch.object(restic_backup, "CONFIG_PATH", Path(root) / "config.json"), patch.object(restic_backup, "STATE_PATH", Path(root) / "state.json"), patch.object(restic_backup, "sources", return_value=[Path(root) / "Documents"]), patch.object(restic_backup, "repository_identity", return_value="restic:test"), patch.object(restic_backup, "restic") as run:
            Path(root, "Documents").mkdir()
            run.side_effect = [
                self._result('{"message_type":"summary","snapshot_id":"abc123"}\n'),
                restic_backup.BackupError("prune could not acquire the repository lock"),
            ]
            restic_backup.atomic_write(restic_backup.CONFIG_PATH, {"repository": "/mnt/drive/.greyward-restic", "destination": "/mnt/drive"})
            value = restic_backup.backup("secret")
            self.assertEqual(value["status"], "SUCCESSFUL")
            self.assertEqual(value["retention_status"], "FAILED")
            state = json.loads((Path(root) / "state.json").read_text(encoding="utf-8"))
            record = state["repositories"]["restic:test"]
            self.assertEqual(record["last_backup_status"], "SUCCESSFUL")
            self.assertEqual(record["last_retention_status"], "FAILED")
            self.assertEqual(record["last_retention_problem"], "TRY_LATER")

    def test_list_files_preserves_exact_older_version_and_types(self):
        older = "a" * 64
        newer = "b" * 64
        home = Path.home().resolve().as_posix()
        versions = [
            {"id": older, "time": "2026-01-01T12:00:00Z", "paths": [f"{home}/Documents"]},
            {"id": newer, "time": "2026-01-02T12:00:00Z", "paths": [f"{home}/Documents"]},
        ]
        with patch.object(restic_backup, "ensure_repository_identity"), patch.object(restic_backup, "restic") as run:
            run.side_effect = [self._result(json.dumps(versions)), self._result("\n".join([
                json.dumps({"struct_type": "node", "path": f"{home}/Documents", "type": "dir"}),
                json.dumps({"struct_type": "node", "path": f"{home}/Documents/report.txt", "type": "file"}),
                json.dumps({"struct_type": "node", "path": f"{home}2/Documents/other.txt", "type": "file"}),
            ]))]
            value = restic_backup.list_files("secret", older)
            self.assertEqual(run.call_args.args[0], ["ls", older, "--json"])
            self.assertEqual(value["snapshot"], older)
            self.assertEqual(value["versions"][0]["id"], newer)
            self.assertEqual(value["files"], [f"{home}/Documents", f"{home}/Documents/report.txt"])
            self.assertEqual([item["kind"] for item in value["candidates"]], ["DIRECTORY", "FILE"])

    @unittest.skipUnless(os.name == "posix", "Native restore uses absolute Linux paths")
    def test_missing_repository_does_not_reuse_historical_check_as_availability(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            repo = restic_backup.repository(path)
            config = {"destination": str(path), "repository": str(repo), "repository_id": "restic:test"}
            check = {"last_backup_status": "SUCCESSFUL", "last_check_status": "VERIFIED", "last_check_at": "2026-11-07T01:00:00Z"}
            with patch.object(restic_backup, "load_config", return_value=config), \
                 patch.object(restic_backup, "load_state", return_value={"repositories": {"restic:test": check}}), \
                 patch.object(restic_backup, "_validated_configuration", return_value=(path, {})):
                missing = restic_backup.status()
                self.assertTrue(missing["destination_available"])
                self.assertFalse(missing["repository_available"])
                self.assertEqual(missing["last_check_at"], check["last_check_at"])
                self.assertEqual(missing["last_check_scope"], "FULL_DATA")
                repo.mkdir()
                self.assertFalse(restic_backup.status()["repository_available"])
                (repo / "config").write_bytes(b"fixture")
                self.assertTrue(restic_backup.status()["repository_available"])

    def test_restore_verifies_output_and_records_terminal_state(self):
        snapshot = "a" * 64
        with tempfile.TemporaryDirectory() as root, patch.object(restic_backup, "CONFIG_PATH", Path(root) / "config.json"), patch.object(restic_backup, "STATE_PATH", Path(root) / "state.json"), patch.object(restic_backup.Path, "home", return_value=Path(root) / "home"), patch.object(restic_backup, "repository_identity", return_value="restic:test"), patch.object(restic_backup, "restic") as run:
            home = Path(root, "home")
            home.mkdir()
            selected = f"{home.as_posix()}/Documents/name[1].txt"
            def write_fixture(argv, _password):
                if argv[0] == "restore":
                    self.assertEqual(argv[1], snapshot)
                    self.assertIn("--verify", argv)
                    self.assertTrue(argv[-1].endswith(r"name\[1\].txt"))
                    target = Path(argv[3]) / selected.lstrip("/")
                    target.parent.mkdir(parents=True)
                    target.write_text("older content", encoding="utf-8")
                return self._result()
            run.side_effect = write_fixture
            value = restic_backup.restore("secret", snapshot, [selected])
            self.assertEqual(value["status"], "STAGED")
            operation = restic_backup.load_state()["repositories"]["restic:test"]["operation"]
            self.assertEqual(operation["state"], "COMPLETED")
            self.assertTrue(operation["completed_at"])
            run.side_effect = None
            run.return_value = self._result()
            with self.assertRaisesRegex(restic_backup.BackupError, "does not contain every"):
                restic_backup.restore("secret", snapshot, [selected])
            self.assertEqual(restic_backup.load_state()["repositories"]["restic:test"]["operation"]["state"], "FAILED")

    def test_restore_selection_limit_is_reported_before_restore(self):
        with self.assertRaisesRegex(restic_backup.BackupError, "Select fewer files"):
            restic_backup.restore("secret", "a" * 64, [str(Path.home())] * (restic_backup.MAX_RESTORE_SELECTION + 1))

    def test_restore_rejects_system_paths(self):
        with self.assertRaises(restic_backup.BackupError):
            restic_backup.restore("secret", "a" * 64, ["/etc/passwd"])

    def test_failed_check_is_recorded_separately(self):
        with tempfile.TemporaryDirectory() as root, patch.object(restic_backup, "STATE_PATH", Path(root) / "state.json"), patch.object(restic_backup, "repository_identity", return_value="restic:test"), patch.object(restic_backup, "restic", side_effect=restic_backup.BackupError("repository is incomplete")):
            with self.assertRaises(restic_backup.BackupError):
                restic_backup.verify("secret")
            state = json.loads((Path(root) / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(state["repositories"]["restic:test"]["last_check_status"], "FAILED")


if __name__ == "__main__":
    unittest.main()
