"""Focused maintenance admission/authentication contracts, no host mutation."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "security-center/packaging/application-security/maintenance.py"
SPEC = importlib.util.spec_from_file_location("greyward_maintenance", SOURCE)
maintenance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(maintenance)


class MaintenanceContracts(unittest.TestCase):
    def tree(self):
        return {"blockdevices": [{"path": "/dev/dm-0", "type": "crypt", "fstype": "btrfs",
                "children": [{"path": "/dev/sda3", "type": "part", "fstype": "crypto_LUKS",
                              "uuid": "12345678-1234-1234-1234-123456789abc"}]}]}

    def test_normal_duplicate_or_ambiguous_boot_cannot_enter_maintenance(self):
        for command in ("quiet", "systemd.unit=multi-user.target",
                        "systemd.unit=greyward-maintenance.target systemd.unit=graphical.target",
                        "systemd.unit=greyward-maintenance.target systemd.unit=greyward-maintenance.target"):
            self.assertFalse(maintenance.selected_boot(command))
        self.assertTrue(maintenance.selected_boot("quiet systemd.unit=greyward-maintenance.target"))

    def test_all_uid_forms_block_admission_including_setuid_root(self):
        self.assertTrue(maintenance.ordinary_uid("1003 0 0 0"))
        self.assertTrue(maintenance.ordinary_uid("0 0 1003 0"))
        self.assertFalse(maintenance.ordinary_uid("0 0 0 0"))
        self.assertFalse(maintenance.ordinary_uid("996 996 996 996"))
        for invalid in ("1003", "0 0 nope 0", "0 0 0 0 0"):
            with self.assertRaises(maintenance.Unavailable):
                maintenance.ordinary_uid(invalid)

    def test_only_encrypted_mounted_root_ancestry_is_an_authentication_source(self):
        self.assertEqual(maintenance.encrypted_root_device(self.tree()),
                         ("/dev/sda3", "12345678-1234-1234-1234-123456789abc"))
        tree = self.tree()
        tree["blockdevices"][0]["type"] = "part"
        with self.assertRaises(maintenance.Unavailable):
            maintenance.encrypted_root_device(tree)
        tree = self.tree()
        tree["blockdevices"].append(tree["blockdevices"][0])
        with self.assertRaises(maintenance.Unavailable):
            maintenance.encrypted_root_device(tree)

    def test_duplicate_encrypted_dependencies_or_foreign_devices_refuse(self):
        tree = self.tree()
        child = dict(tree["blockdevices"][0]["children"][0], path="/dev/sdb3")
        tree["blockdevices"][0]["children"].append(child)
        with self.assertRaises(maintenance.Unavailable):
            maintenance.encrypted_root_device(tree)
        for path in ("/tmp/disk", "/dev/disk;command", "../../dev/sda3"):
            tree = self.tree()
            tree["blockdevices"][0]["children"][0]["path"] = path
            with self.assertRaises(maintenance.Unavailable):
                maintenance.encrypted_root_device(tree)

    def test_mixed_plaintext_and_encrypted_root_dependencies_refuse(self):
        encrypted = self.tree()["blockdevices"][0]
        tree = {"blockdevices": [{"path": "/dev/dm-1", "type": "lvm", "fstype": "btrfs",
                "children": [encrypted, {"path": "/dev/sdb3", "type": "part", "fstype": "LVM2_member"}]}]}
        with self.assertRaises(maintenance.Unavailable):
            maintenance.encrypted_root_device(tree)

    def test_normal_boot_and_authentication_identity_changes_never_execute_shell(self):
        with mock.patch.object(maintenance, "require_quiescent_boot", side_effect=maintenance.Unavailable("normal boot")), \
             mock.patch.object(maintenance.subprocess, "call") as shell, \
             mock.patch.object(maintenance.sys, "argv", ["maintenance"]):
            with self.assertRaises(maintenance.Unavailable):
                maintenance.main()
            shell.assert_not_called()
        with mock.patch.object(maintenance, "require_quiescent_boot"), \
             mock.patch.object(maintenance, "require_console"), \
             mock.patch.object(maintenance, "root_device", side_effect=[("/dev/sda3", "first"), ("/dev/sdb3", "second")]), \
             mock.patch.object(maintenance.getpass, "getpass", return_value="synthetic-password"), \
             mock.patch.object(maintenance, "verify_passphrase", return_value=True), \
             mock.patch.object(maintenance.subprocess, "call") as shell, \
             mock.patch.object(maintenance.sys, "argv", ["maintenance"]):
            with self.assertRaises(maintenance.Unavailable):
                maintenance.main()
            shell.assert_not_called()

    def test_fresh_passphrase_uses_stdin_never_argv_env_file_or_tokens(self):
        with mock.patch.object(maintenance.subprocess, "run", return_value=mock.Mock(returncode=0)) as run:
            self.assertTrue(maintenance.verify_passphrase("/dev/sda3", "synthetic-password"))
            arguments, options = run.call_args
            self.assertNotIn("synthetic-password", " ".join(arguments[0]))
            self.assertIn("--test-passphrase", arguments[0])
            self.assertIn("--key-file=-", arguments[0])
            self.assertEqual(options["input"], b"synthetic-password")
            self.assertEqual(options["env"], maintenance.ENVIRONMENT)
            self.assertEqual(options["stdout"], subprocess.DEVNULL)
            self.assertEqual(options["stderr"], subprocess.DEVNULL)

    def test_wrong_or_absent_authentication_does_not_produce_a_shell(self):
        with mock.patch.object(maintenance.subprocess, "run", return_value=mock.Mock(returncode=2)):
            self.assertFalse(maintenance.verify_passphrase("/dev/sda3", "synthetic-wrong"))
        with mock.patch.object(maintenance.subprocess, "run") as run:
            for invalid in ("", "a\0b", "a" * 4097):
                self.assertFalse(maintenance.verify_passphrase("/dev/sda3", invalid))
            run.assert_not_called()
        with mock.patch.object(maintenance.os, "getuid", return_value=1003, create=True), \
             mock.patch.object(maintenance.subprocess, "call") as shell:
            with self.assertRaises(maintenance.Unavailable):
                maintenance.require_quiescent_boot()
            shell.assert_not_called()


@unittest.skipUnless(os.environ.get("GREYWARD_LUKS_FIXTURE") == "1",
                     "Explicit Linux/root synthetic LUKS fixture only")
class SyntheticLuksContracts(unittest.TestCase):
    def test_real_fresh_passphrase_and_normal_boot_refusal(self):
        self.assertEqual(os.getuid(), 0)
        self.assertFalse(maintenance.selected_boot(Path("/proc/cmdline").read_text()))
        with self.assertRaises(maintenance.Unavailable):
            maintenance.require_quiescent_boot()
        # A private file container, never the installation's disk or mapper.
        # This dummy credential has no relationship to an actual user password.
        with tempfile.TemporaryDirectory(prefix="greyward-maintenance-test-", dir="/run") as temporary:
            device = Path(temporary) / "synthetic.luks"
            descriptor = os.open(device, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.ftruncate(descriptor, 32 * 1024 * 1024)
            finally:
                os.close(descriptor)
            subprocess.run(["/usr/sbin/cryptsetup", "luksFormat", "--type", "luks2",
                            "--batch-mode", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000",
                            "--key-file=-", str(device)], input=b"GREYWARD_SYNTHETIC_LUKS_FIXTURE",
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           env=maintenance.ENVIRONMENT, timeout=30, check=True)
            self.assertTrue(maintenance.verify_passphrase(str(device), "GREYWARD_SYNTHETIC_LUKS_FIXTURE"))
            self.assertFalse(maintenance.verify_passphrase(str(device), "GREYWARD_SYNTHETIC_WRONG"))


if __name__ == "__main__":
    unittest.main()
