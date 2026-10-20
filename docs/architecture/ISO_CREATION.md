# GREYWARD ISO candidate — 20 October 2026

The internal `0.4.2-Dawn` offline installer ISO was composed using the package
versions recorded for the bare-metal `<validation-host>` production reference.
Five installed component RPMs were imported by verified hash; their source
reproducibility was not performed. Session 22 was rebuilt from the installed
package-owned defaults because its original RPM was unavailable.

| Evidence | Result |
| --- | --- |
| ISO | `GREYWARD-0.4.2-Dawn-x86_64.iso` |
| SHA-256 | `f181bb79c84b98fb90096e4f76664bf50a5e78b47843248c5785033b7ef2a8a1` |
| Size | 5,423,562,752 bytes |
| Fedora Everything input SHA-256 | `bd285201494dd0ba09b54d05ac707de1401668b8512a573edb5922dcf9d7067e` |
| Production package tuple | DMS 1.6.2-26; Files 1.0.0-17; Session 0.1.0-22; Security Center 0.1.0-115; Security Context 0.1.0-108; Application Security 0.1.0-69; Enrollment 0.1.0-60; Branding 0.1.0-16 |
| Image checks | Production stage and extracted-stage validation passed; transferred SHA-256 matched; VMware ISO validation passed (`required_paths=40`) |
| Test-VM boot | GRUB appeared, then Anaconda reached Installation Summary and opened its disk-encryption passphrase dialog. No install was started. |
| Install/runtime acceptance | Not performed. The ISO manifest has `installed_system_tested: false`; installer dependency resolution passed and network is not required. |

This confirms boot into the installer only. It does not establish clean-install
or installed-desktop acceptance. The candidate remains internal and unreleased.

# Installer source build

The public installer implementation is `environment/image/`. Its entry point
is `build-iso.sh`; staging, offline dependency resolution and installer contracts
are owned by the adjacent scripts. Private ISO-factory host configuration,
account credentials, disks and diagnostic reports are not public inputs.

Use a disposable Fedora builder with the documented dependencies and sufficient
storage. Build component RPMs using their package-owner scripts and pinned
upstream inputs. The verified DMS receipt is
`environment/production/dms-release.json`; the Security Center build creates a
source/package manifest. Do not bypass checksum, source-byte or dependency checks.

Inspect `build-iso.sh --help` for the actual command contract. Supply your own
verified Fedora base ISO, its checksum, builder baseline, matched component RPMs
and Security Center manifest. Outputs include an ISO checksum and provenance.
Offline RPM and Flatpak closure and the embedded installer payload are checked.

Protected USB approval is a mandatory next-image input. Complete staging rejects
stale selected RPM payloads through `environment/image/verify-usbguard-inputs.py`,
including the authentication assembler, Python entrypoint, metadata materializer,
SELinux compiler inputs and Go source receipts. Build the matched versions in
`docs/security-center/USB_APPROVAL.md`; do not reuse earlier same-name artifacts.
Source gates and the validated installed hotfix do not certify a fresh ISO.

Retain native Labwc edge/corner snapping and top-edge maximization in the next
candidate. Static checks protect enabled defaults, and staging compares the
Session RPM's actual Labwc configuration against canonical source. Enrollment
must copy those defaults into its root-owned compositor closure. See
`docs/architecture/WINDOW_MANAGEMENT.md` for the contract and partial
installed validation; the remaining gestures need clean-install acceptance.
Recording this requirement does not build or publish an ISO.

A successful build does not prove installation, enrollment, permissions or
recovery. Test clean installation in a separate disposable VM through the normal
installer; do not pre-answer authentication. Preserve SELinux Enforcing and
test Protected Data, Administration and failure/recovery boundaries independently.
Consult current status for supported and experimental features. No automatically
published release or installation is implied by source validation.
