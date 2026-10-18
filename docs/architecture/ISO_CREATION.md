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
