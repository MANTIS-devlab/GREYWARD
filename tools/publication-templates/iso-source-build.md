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

A successful build does not prove installation, enrollment, permissions or
recovery. Test clean installation in a separate disposable VM through the normal
installer; do not pre-answer authentication. Preserve SELinux Enforcing and
test Protected Data, Administration and failure/recovery boundaries independently.
Consult current status for supported and experimental features. No automatically
published release or installation is implied by source validation.
