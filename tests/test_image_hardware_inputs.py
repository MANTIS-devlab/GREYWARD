"""Check that the hardware inventory gate rejects missing inputs."""
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'environment/image/verify-hardware-inputs.py'
spec = importlib.util.spec_from_file_location('hardware_inputs', SCRIPT)
hardware = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hardware)


class HardwareInputsTests(unittest.TestCase):
    def test_builtin_drivers_and_compressed_firmware(self):
        drivers, firmware = hardware.inventory(
            ['usr/lib/modules/7.3/kernel/drivers/scsi/virtio_scsi.ko.xz',
             '/usr/lib/firmware/xe/lnl_guc_70.bin.zst',
             'usr/lib/modules/7.3/modules.builtin'],
            'kernel/drivers/ata/ahci.ko\nkernel/drivers/hid/hid-generic.ko\n',
        )
        self.assertEqual(drivers, {'virtio_scsi', 'ahci', 'hid_generic'})
        self.assertEqual(firmware, {'xe/lnl_guc_70.bin'})
        self.assertIn('installer: NVMe and Intel VMD: missing vmd',
                      hardware.check_inventory('installer', drivers, firmware))

    def test_pci_alias_alone_is_insufficient(self):
        aliases = '\n'.join(
            f'alias pci:v0000{v}d0000{d}sv*sd*bc*sc*i* {driver}'
            for _, v, d, _, driver in hardware.PCI_PROFILES
        )
        drivers = {profile[-1] for profile in hardware.PCI_PROFILES}
        self.assertEqual(hardware.check_aliases(aliases, drivers), [])
        self.assertIn('installer: NVIDIA GA106 (10DE:2520) has no usable nouveau alias',
                      hardware.check_aliases(aliases, drivers - {'nouveau'}))
