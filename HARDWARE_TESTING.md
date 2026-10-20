# Hardware testing

GREYWARD expects hardware-specific failures. This file is the public matrix for
reproducible physical-system evidence; architecture or VM results do not replace
it.

## Evidence status

The user confirms that the feature workflows described in the post-0.3.8
follow-up were tested on bare-metal `<validation-host>`. The exact OMEN model, firmware
revision, kernel build, and originating ISO checksum were not captured, so
these observations do not constitute a complete, reproducible machine record
or clean-install validation. The device-family and edge-case matrix below is
broader than that single machine. Hyper-V/VMware evidence remains separate from
physical-hardware validation.

The tested graphics devices were an AMD GPU (`1002:1638`) and NVIDIA GPU
(`10de:2520`). The display setup included the laptop's eDP panel and two
external displays connected over HDMI and DisplayPort through a KVM. The
system also has an Intel Wi-Fi 6 AX200 and Intel Bluetooth controller. The
protected USB approval check used a USB 2.1 hub (`05e3:0610`); an earlier USB
2.0 hub (`214b:7260`) was also observed. Exact laptop, monitor, KVM, and hub
product models were not recorded.

On bare-metal `<validation-host>`, an Intel Wi-Fi 6 AX200 and its Bluetooth controller were
detected, but Fedora's split firmware packages were absent. Installing the
official firmware packages and re-probing the controllers restored firmware
loading. NetworkManager detected nearby Wi-Fi networks; BlueZ reported a
powered controller and discovered nearby Bluetooth devices. Ethernet, SSH and
DNS remained available; SELinux stayed Enforcing and USBGuard continued to
allow the integrated Bluetooth device. No Wi-Fi connection or Bluetooth
pairing was attempted. The production package contract includes the firmware
and first-boot acceptance requires it. The production manifest now selects
Fedora firmware for Intel, Realtek, MediaTek, Qualcomm/Atheros,
Broadcom/Cypress, NXP, TI WiLink and legacy Marvell Libertas families. The
offline stage validator checks Anaconda's generated install set for every
declared firmware RPM; installed acceptance checks the same manifest. The nine
newly selected RPMs add about 103.4 MiB of package data from Fedora 44 Updates
metadata; existing Intel dependencies are not counted twice. This is source and
metadata coverage, not bare-metal validation for those other vendors. Clean-ISO
hardware acceptance remains pending.

| Area | Minimum scenario | Recorded bare-metal configurations | Known limitations / unknowns |
|---|---|---|---|
| GPU | install, native Wayland session, acceleration, lock/unlock, suspend | AMD `1002:1638` + NVIDIA `10de:2520`; the user confirmed the desktop appeared on both external displays after the protected renderer fix | exact GPU models, acceleration benchmarks, lock/unlock, suspend/resume, and proprietary-driver behavior unknown |
| Wi-Fi | join WPA2/WPA3, roam, reconnect, suspend, VPN | `<validation-host>`: Intel firmware loaded and networks discovered; source now includes broad Fedora firmware families | connection, roaming, suspend, VPN, non-Intel vendor hardware, chipset/firmware diversity and captive portals unknown |
| Ethernet | DHCP, link loss/reconnect, trust-zone change | none recorded | adapters, docks, VLAN and enterprise auth unknown |
| Bluetooth | pair/reconnect audio and one input device | `<validation-host>`: Intel firmware loaded, controller powered and nearby devices discovered; source also includes Realtek, MediaTek, Qualcomm/Atheros, Broadcom/Cypress, NXP and TI WiLink firmware | pairing, reconnection, audio/input profiles, suspend and non-Intel controller/codec diversity unknown |
| TPM | posture detection and behavior with/without TPM 2.0 | none recorded | vendor firmware and clear/reset cases unknown |
| Secure Boot | install and boot enabled/disabled; report accurate state | Secure Boot was enabled on the tested machine and GREYWARD reported it secure; separate fwupd HSI findings remained | key enrollment, Secure Boot disabled state, and third-party module paths unknown |
| Firmware | enumerate and exercise no-update/update/error paths | none recorded | LVFS/vendor coverage and interrupted update recovery unknown |
| Audio | speakers, headphones, microphone, hot-plug, suspend | none recorded | PipeWire profiles/codecs/docks unknown |
| Suspend/resume | repeated cycles with networking, lock, audio, USB | none recorded | platform sleep modes and long-duration reliability unknown |
| Storage | encrypted install on SATA/NVMe; low-space and SMART/error visibility | none recorded | RAID, unusual sector sizes, multi-disk and existing-layout coexistence unknown |
| External displays | hot-plug, scale, rotate, suspend with one/two displays | HP OMEN: eDP panel plus two external HDMI/DisplayPort displays; user confirmed both external displays showed the desktop | exact monitor models, mixed DPI/refresh, dock changes, rotation, suspend, and more than two external displays unknown |
| USB devices | known/unknown device lifecycle and USBGuard state | USB 2.0 hub: user completed protected **Trust always**; exact device/kernel authorization and persistent rule were read back, with the matching alert cleared | reconnect/reboot persistence and other hub, dock, storage, phone, and composite-device behavior unknown |
| Installation | boot media, storage/account flow, first boot, login | French AZERTY selected on the tested installation; production source now carries the installer choice to greeter and protected/regular sessions | the new source has not been verified in a clean ISO installation; other locales and UEFI/storage recovery remain unknown |
| Update | DNF5 offline update, Flatpak, firmware, restart, cancellation | none recorded | power loss, partial providers, low space and rollback unknown |
| Recovery | Btrfs point, cleanup, Restic backup/verify/file restore | none recorded | full machine recovery and non-Btrfs layouts unknown |

## Recording a result

Add a row or link an issue with:

- GREYWARD commit and image checksum;
- Fedora kernel and installed GREYWARD package versions;
- system/motherboard model and firmware version;
- relevant device model and PCI/USB ID;
- Secure Boot/TPM/storage layout state when relevant;
- exact steps, expected result, observed result, and reproducibility;
- whether logs were captured before or after a reboot.

Redact usernames, hostnames, serial numbers, MAC addresses, public/private IP
addresses, Wi-Fi SSIDs, account identifiers, document names, credentials, and
unrelated logs. Prefer `lspci -nnk` excerpts for the affected device over a
complete hardware dump. Review `journalctl` output before attaching it.

## Suggested test sequence

1. Verify the image checksum and record the commit.
2. Install with encrypted storage and complete first boot.
3. Reboot twice without installation media and verify login/session.
4. Exercise networking, VPN/DNS, audio, Bluetooth, USB, lock, and suspend.
5. Connect/disconnect external displays and docks.
6. Apply available updates and verify the offline-update restart.
7. Create a recovery point and a Restic backup; verify and restore sample files.
8. Repeat important actions after provider/service restart.
9. File one issue per independently reproducible failure.

Use the **Hardware report** issue form in `.github/ISSUE_TEMPLATE/`. A pass is
specific to the recorded configuration; it is not a general compatibility
claim.
