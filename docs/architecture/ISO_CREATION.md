# Current published installer — 25 October 2026

The latest public installer is **0.5.2 Sophon**. Its exact component tuple,
checksums, frozen corresponding sources and validation limits are in the
[Sophon notes](../../docs/patch-notes/0.5.2-sophon.md). The SourceForge directory
also provides four complete Office source RPMs with vendored dependencies.
Current public main is not the exact ISO source; use those frozen inputs when
inspecting or rebuilding this release. No public Office RPM feed is operational.

The DMS 2.0 input is `environment/production/dms-2.0-candidate.json`. Pass it as
the third argument to `packaging/greyward-dms/build.sh` when building that DMS
RPM, and select `--dms-candidate` in the image entrypoints. This leaves the
separate validated 1.6 manifest intact. Keep the package, source-manifest and
image checks active; candidate selection does not grant release acceptance.

# Historical corrected candidate — 21 October 2026

The internal 0.4.5-Dawn candidate includes the R6 greeter-readiness and fresh
ordinary-role fixes, plus per-screen desktop icon ownership. The verified
package tuple is DMS 1.6.2-26, Files 1.0.0-18, Session 0.1.0-23, Security Center
0.1.0-115, Context 0.1.0-108, Application Security 0.1.0-70, Enrollment 0.1.0-61
and Branding 0.1.0-16. Do not reuse older same-version cached artifacts.

The 5,423,824,896-byte ISO has SHA-256
`e5a06edf7b5b6b7a67eb97360e5805188ece5101201d95195ea0f082004f5bc1`.
Offline dependency resolution, networkless verification, extracted-stage hashes
and the 40-path media validator pass. All eight selected RPM hashes match in
both embedded locations. The recorded source snapshot includes explicitly
inventoried working-tree inputs; this is not a clean-checkout reproducibility
claim. R6 reached the media's GRUB menu. Clean installation, enrolled runtime,
recovery and physical three-screen acceptance remain unverified for this image.
Files 18 is installed on the production reference with clean RPM verification;
its physical placement check remains pending. This source update publishes no
ISO asset or release; the README retains the existing published download link.

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

# Historical internal candidate — 20 October 2026

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
