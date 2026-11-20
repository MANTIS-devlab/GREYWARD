#!/usr/bin/env python3
"""Check hardware-enablement files in the installer and its selected Fedora RPMs."""
import argparse
from fnmatch import fnmatchcase
import json
from pathlib import Path
import re
import subprocess
import tempfile


BOOT_DRIVERS = {
    "SATA and legacy IDE": ("ahci", "ata_piix"),
    "NVMe and Intel VMD": ("nvme", "vmd"),
    "USB boot and keyboard": ("xhci_pci", "usb_storage", "uas", "usbhid", "hid_generic"),
    "Laptop I2C HID": ("i2c_hid_acpi",),
    "QEMU storage": ("virtio_blk", "virtio_scsi"),
    "Hyper-V storage and display": ("hv_storvsc", "hyperv_drm"),
    "VMware display": ("vmwgfx",),
    "KVM display": ("virtio_gpu",),
    "Encrypted Btrfs": ("dm_crypt", "btrfs"),
}
DISPLAY_DRIVERS = ("i915", "xe", "amdgpu", "nouveau")
PCI_PROFILES = (
    ("Intel Tiger Lake", "8086", "9A49", "030000", "i915"),
    ("AMD Cezanne", "1002", "1638", "030000", "amdgpu"),
    ("NVIDIA GA106", "10DE", "2520", "030000", "nouveau"),
)
GPU_FIRMWARE = ("i915/*.bin", "xe/*.bin", "amdgpu/*.bin", "nvidia/*")
WIFI_FIRMWARE = ("iwlwifi-*.ucode", "rtw89/*.bin", "mediatek/*.bin", "ath10k/*", "brcm/*")


def run(*command, cwd=None):
    return subprocess.run(command, cwd=cwd, check=True, text=True, capture_output=True).stdout


def inventory(paths, builtins):
    drivers = set()
    firmware = set()
    for path in paths:
        path = path.lstrip("./")
        if re.search(r"(?:^|/)lib/modules/", path) and re.search(r"\.ko(?:\.(?:xz|zst|gz))?$", path):
            drivers.add(Path(path).name.split(".ko")[0].replace("-", "_"))
        if match := re.match(r"(?:usr/)?lib/firmware/(.+)", path):
            firmware.add(re.sub(r"\.(?:xz|zst|gz)$", "", match[1]))
    drivers.update(Path(path).stem.replace("-", "_") for path in builtins.splitlines() if path.endswith(".ko"))
    return drivers, firmware


def check_inventory(phase, drivers, firmware, wifi=False):
    failures = []
    for profile, modules in (BOOT_DRIVERS | {"Native graphics": DISPLAY_DRIVERS}).items():
        for module in modules:
            if module not in drivers:
                failures.append(f"{phase}: {profile}: missing {module}")
    for pattern in GPU_FIRMWARE + (WIFI_FIRMWARE if wifi else ()):
        if not any(fnmatchcase(path, pattern) for path in firmware):
            failures.append(f"{phase}: no firmware payload matching {pattern}")
    return failures


def installer_inventory(image):
    listing = run("lsinitrd", str(image))
    paths = re.findall(r"(?:^|\s)((?:usr/)?lib/(?:modules|firmware)/\S+)", listing)
    versions = {path.split("/modules/", 1)[1].split("/", 1)[0]
                for path in paths if path.endswith("/modules.builtin")}
    if len(versions) != 1:
        raise ValueError("Could not identify one installer kernel in the initramfs")
    version, = versions
    prefix = next(path.removesuffix("modules.builtin") for path in paths if path.endswith("/modules.builtin"))
    with tempfile.TemporaryDirectory(prefix="greyward-kernel-index-") as unpack:
        run("lsinitrd", "--unpack", str(image.resolve()), prefix + "modules.builtin",
            prefix + "modules.alias", cwd=unpack)
        builtins = (Path(unpack) / (prefix + "modules.builtin")).read_text()
        aliases = (Path(unpack) / (prefix + "modules.alias")).read_text()
    return version, aliases, inventory(paths, builtins)


def check_aliases(aliases, drivers):
    rows = [line.split() for line in aliases.splitlines() if line.startswith("alias pci:")]
    failures = []
    for name, vendor, device, cls, module in PCI_PROFILES:
        alias = f"pci:v0000{vendor}d0000{device}sv00000000sd00000000bc{cls[:2]}sc{cls[2:4]}i{cls[4:]}"
        if module not in drivers or not any(driver.replace("-", "_") == module and fnmatchcase(alias, pattern)
                                            for _, pattern, driver in rows):
            failures.append(f"installer: {name} ({vendor}:{device}) has no usable {module} alias")
    return failures


def target_inventory(repo):
    kernels = sorted(path for path in repo.rglob("kernel-modules*.rpm") if "debug" not in path.name)
    core = sorted(repo.rglob("kernel-core-*.rpm"))
    firmware = sorted(path for path in repo.rglob("*firmware*.rpm") if path.is_file())
    if len(core) != 1 or not kernels or not firmware:
        raise ValueError("Expected one Fedora kernel-core and its module and firmware RPMs")
    paths = run("rpm", "-qpl", *map(str, core + kernels + firmware)).splitlines()
    version = run("rpm", "-qp", "--qf", "%{VERSION}-%{RELEASE}.%{ARCH}", str(core[0]))
    with subprocess.Popen(["rpm2cpio", str(core[0])], stdout=subprocess.PIPE) as rpm:
        result = subprocess.run(["cpio", "-i", "--quiet", "--to-stdout", f"*/{version}/modules.builtin"],
                                stdin=rpm.stdout, capture_output=True, text=True, check=True)
        rpm.stdout.close()
        if rpm.wait() or not result.stdout.strip():
            raise ValueError("Could not read built-in modules from the selected kernel RPM")
    return version, inventory(paths, result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--initramfs", type=Path, required=True)
    parser.add_argument("--rpm-dir", type=Path, required=True)
    args = parser.parse_args()
    installer_version, aliases, (drivers, firmware) = installer_inventory(args.initramfs)
    failures = check_inventory("installer", drivers, firmware) + check_aliases(aliases, drivers)
    target_version, target = target_inventory(args.rpm_dir)
    failures += check_inventory("target RPMs", *target, wifi=True)
    if failures:
        raise SystemExit("\n".join(failures))
    print(json.dumps({
        "scope": "static hardware dependencies and representative installer PCI aliases",
        "installer_kernel": installer_version,
        "installed_kernel": target_version,
        "profiles": list(BOOT_DRIVERS) + ["Native graphics", "Wi-Fi firmware families"],
        "representative_pci_ids": [f"{v}:{d}" for _, v, d, _, _ in PCI_PROFILES],
        "boot_tested": False,
    }, indent=2))


if __name__ == "__main__":
    main()
