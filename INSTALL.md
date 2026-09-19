# Install and test GREYWARD

GREYWARD is pre-release software intended for testing, hardware validation, and development feedback. Do not rely on the current alpha for production or security-critical use.

## 1. Download

Current public image:

`GREYWARD-0.1.0-alpha.1-Obsidian-x86_64.iso`

Download the ISO and its SHA-256 file from the [GREYWARD SourceForge release directory](https://sourceforge.net/projects/greyward/files/v0.1.0-alpha.1/).

## 2. Verify the image

Linux:

```bash
sha256sum -c GREYWARD-0.1.0-alpha.1-Obsidian-x86_64.iso.sha256
```

PowerShell:

```powershell
Get-FileHash .\GREYWARD-0.1.0-alpha.1-Obsidian-x86_64.iso -Algorithm SHA256
Get-Content .\GREYWARD-0.1.0-alpha.1-Obsidian-x86_64.iso.sha256
```

Compare the reported SHA-256 values before writing the image.

## 3. Create boot media

Use a trusted image-writing tool and write the ISO to a USB drive as an image, not as a normal file copy.

On Linux, first identify the target device carefully, then:

```bash
sudo dd if=GREYWARD-0.1.0-alpha.1-Obsidian-x86_64.iso of=/dev/sdX bs=4M status=progress conv=fsync
```

Replace `/dev/sdX` with the whole USB device. This command destroys the existing contents of that device.

On Windows, use a reputable bootable-media writer that supports raw ISO images.

## 4. Boot and install

Boot the machine from the USB device and follow the installer.

For the first public alpha:

- prefer a spare machine or disposable test system;
- keep a backup of any data you care about;
- expect hardware-specific failures and incomplete validation;
- encrypted storage is part of the intended GREYWARD installation path;
- record the hardware model and relevant device IDs if something fails.

VM testing is useful for software integration, but it does not replace physical-hardware validation.

## 5. First test pass

After installation:

1. reboot twice without the installation media;
2. confirm login and the GREYWARD Wayland session;
3. test Ethernet/Wi-Fi and, if used, VPN connectivity;
4. test audio, Bluetooth, USB devices, lock/unlock, suspend/resume, and external displays;
5. open Security Center and note any `UNKNOWN`, `UNAVAILABLE`, or unexpected security state;
6. test updates;
7. if configured, exercise recovery and backup workflows.

For the more complete test sequence, see [HARDWARE_TESTING.md](HARDWARE_TESTING.md).

## 6. Report what happens

Use the repository issue forms:

- **Bug report** for reproducible software problems;
- **Hardware report** for physical-device, driver, firmware, suspend, display, audio, networking, or installation results;
- **Design / security challenge** when the implementation or security assumption itself appears wrong.

Before attaching logs or screenshots, remove usernames, hostnames, serial numbers, MAC/IP addresses, SSIDs, credentials, document names, and unrelated personal data.

Security-sensitive vulnerabilities should follow [SECURITY.md](SECURITY.md), not a normal public issue.

## Useful references

- [Architecture](ARCHITECTURE.md)
- [Threat model](THREAT_MODEL.md)
- [Testing model](TESTING.md)
- [Contributing](CONTRIBUTING.md)
