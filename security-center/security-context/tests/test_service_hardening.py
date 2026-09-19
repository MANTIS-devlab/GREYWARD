import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]


class ServiceHardeningTests(unittest.TestCase):
    def test_root_services_keep_only_operation_specific_capabilities(self):
        expected = {
            "greyward-opensnitch-control-plane.service": "CapabilityBoundingSet=CAP_CHOWN",
            "greyward-opensnitch-policy.service": "CapabilityBoundingSet=\n",
            "greyward-secure-dns.service": "CapabilityBoundingSet=\n",
            "greyward-clamav-scan.service": "CapabilityBoundingSet=CAP_DAC_READ_SEARCH",
        }
        for unit, capability in expected.items():
            text = (ROOT / "systemd" / unit).read_text(encoding="utf-8")
            self.assertIn(capability, text, unit)
            for setting in (
                "NoNewPrivileges=yes",
                "PrivateDevices=yes",
                "PrivateTmp=yes",
                "ProtectKernelModules=yes",
                "ProtectKernelTunables=yes",
                "RestrictNamespaces=yes",
                "RestrictSUIDSGID=yes",
                "SystemCallArchitectures=native",
                "RestrictAddressFamilies=AF_UNIX",
            ):
                self.assertIn(setting, text, f"{unit}: {setting}")

    def test_clamav_runtime_is_not_world_writable_or_world_readable_by_default(self):
        text = (ROOT / "systemd" / "greyward-clamav-scan.service").read_text(encoding="utf-8")
        self.assertIn("RuntimeDirectoryMode=0711", text)
        self.assertIn("UMask=0077", text)

    def test_secure_dns_state_directory_is_private(self):
        text = (ROOT / "systemd" / "greyward-secure-dns.service").read_text(encoding="utf-8")
        self.assertIn("RuntimeDirectoryMode=0700", text)


if __name__ == "__main__":
    unittest.main()
