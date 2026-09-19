# Hardware testing

GREYWARD expects hardware-specific failures. This file is the public matrix for
reproducible physical-system evidence; architecture or VM results do not replace
it.

## Evidence status

No complete, machine-identifiable bare-metal result set is currently recorded
in this repository. Existing Hyper-V/VMware development evidence is useful for
software integration but is not counted as physical-hardware validation below.
The table therefore records unknowns rather than inventing passes.

| Area | Minimum scenario | Recorded bare-metal configurations | Known limitations / unknowns |
|---|---|---|---|
| GPU | install, native Wayland session, acceleration, lock/unlock, suspend | none recorded | Intel/AMD/NVIDIA generations and proprietary-driver behavior unknown |
| Wi-Fi | join WPA2/WPA3, roam, reconnect, suspend, VPN | none recorded | chipset/firmware diversity and captive portals unknown |
| Ethernet | DHCP, link loss/reconnect, trust-zone change | none recorded | adapters, docks, VLAN and enterprise auth unknown |
| Bluetooth | pair/reconnect audio and one input device | none recorded | controller/codec diversity unknown |
| TPM | posture detection and behavior with/without TPM 2.0 | none recorded | vendor firmware and clear/reset cases unknown |
| Secure Boot | install and boot enabled/disabled; report accurate state | none recorded | key enrollment and third-party module paths unknown |
| Firmware | enumerate and exercise no-update/update/error paths | none recorded | LVFS/vendor coverage and interrupted update recovery unknown |
| Audio | speakers, headphones, microphone, hot-plug, suspend | none recorded | PipeWire profiles/codecs/docks unknown |
| Suspend/resume | repeated cycles with networking, lock, audio, USB | none recorded | platform sleep modes and long-duration reliability unknown |
| Storage | encrypted install on SATA/NVMe; low-space and SMART/error visibility | none recorded | RAID, unusual sector sizes, multi-disk and existing-layout coexistence unknown |
| External displays | hot-plug, scale, rotate, suspend with one/two displays | none recorded | mixed DPI/refresh, docks, projectors and more than two displays unknown |
| USB devices | known/unknown device lifecycle and USBGuard state | none recorded | hubs, docks, storage, phones, composite devices unknown |
| Installation | boot media, storage/account flow, first boot, login | none recorded | UEFI implementations, existing OS layouts and failure recovery unknown |
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
