# Security Center remediation — 2026-08-31 File Security core workflow

## Scope

- SC-FILE-001: ClamAV definitions lifecycle and truthful readiness.
- SC-FILE-002: durable File Security event/activity projection.
- SC-FILE-003: inspected-file accounting for clean and detected files.
- SC-FILE-004: hardened quarantine, restore, and delete workflow.
- SC-FILE-005: picker validation against missing, unreadable, symlinked, and
  service-private namespaces.
- SC-FILE-006: explicit Safe Open supported-handler resolution.

## Root causes

- The image listed ClamAV but did not make the packaged definition updater a
  production dependency/enablement target. Status also treated historical
  freshclam warnings as a current failure and had no initializing/updating
  lifecycle states.
- File Security activity was not projected from the normalized
  `FILE_SECURITY` telemetry stream. Root-owned scan/remediation events and
  user-session Safe Open/sanitization events therefore did not share the page's
  activity source.
- The scanner counted only `: OK` lines. A `FOUND` line created a detection but
  did not increment inspected, and repeated output could create duplicate
  records.
- The root service attempted to unlink user files and create restore files while
  correctly running with `ProtectHome=read-only`; the resulting failures were
  real confinement failures, not evidence that quarantine had succeeded.
- Picker validation checked ownership and path shape but did not reject the
  `/tmp` namespace hidden by `PrivateTmp`, or unreadable user-owned sources.
- Safe Open trusted one configured desktop entry, omitted the system Flatpak
  export directory, and had no explicit supported MIME/no-handler model.

## Implementation

- Added `clamav-update` and packaged `clamav-freshclam` enablement to the
  production package/provisioning paths. `clamav.status()` now reports
  `CURRENT`, `INITIALIZING`, `UPDATING`, `OUTDATED`, and `UNAVAILABLE`, with
  current-log failure detection and actionable detail; scan admission refuses
  every non-current state.
- Added bounded normalized File Activity projection for scan start/completion,
  cancellation/partial/failure, detections, quarantine/restore/delete success
  and failure, Safe Open, and sanitization. The Rust facade consumes this
  canonical projection instead of the legacy generic activity JSON for the File
  Security page.
- Counted each detected file once, counted detected files as inspected, and
  added distinct terminal telemetry event types for cancelled and partial
  scans.
- Added root prepare/commit/fail D-Bus methods. Quarantine copies and verifies
  before the user bus removes an owned source; restore stages a verified object
  under `/run/greyward-file-security/<uid>` and the user bus creates a
  no-overwrite home copy before commit. `ProtectHome=read-only` remains in
  force.
- Rejected private temporary namespaces and unreadable user-owned scan sources
  before operation creation. Safe Open now supports an explicit text/common
  image MIME model and discovers normal user/system and user/system Flatpak
  desktop exports, while preserving bubblewrap network/filesystem confinement.
- Replaced the Rust Safe Open `gdbus` display-text parser with the typed D-Bus
  string method path, preserving filenames containing shell-sensitive
  characters.

## Source validation

- `PYTHONPATH=security-center/security-context python -m unittest discover -s security-center/security-context/tests -p 'test_*.py'`: 87 passed, 15 skipped.
- Python compilation of the Security Context modules passed.
- `node --test security-center/tauri/frontend/ux-contract.test.mjs`: 43 passed.
- `pwsh -NoProfile -File .\tests\static.ps1`: passed.
- `pwsh -NoProfile -File .\tools\validate-repository.ps1`: passed.
- `git diff --check`: passed; Git reported only existing line-ending warnings.
- `cargo fmt --all -- --check`: passed.

## Runtime validation

The backend/runtime source was deployed to the Fedora GREYWARD-DEV VM with
`tools/greyward-dev/deploy-security-center.ps1` as release
`20260831T190020Z` (`greyward-security-center-0.1.0-45.fc44.x86_64` and
`greyward-security-context-0.1.0-44.fc44.noarch`). The final UI-only activity
visibility correction was then rebuilt, reinstalled, and launched as release
`20260831T192735Z` with the same package NEVRAs. The real session D-Bus
workflow then passed:

- `clamav.status()`: `CURRENT`, engine `1.4.6`, database `bytecode.cvd`,
  `clamav-freshclam.service`: `ACTIVE`.
- Clean file scan: `COMPLETED`, 1 inspected, 0 detections.
- Clean folder scan: `COMPLETED`, 1 inspected, 0 detections.
- EICAR scan: `COMPLETED`, 1 inspected, 1 detection; quarantine, restore to
  the ordinary user home review directory, and permanent quarantine-object
  delete all returned their successful terminal states.
- Picker rejection: `/tmp`, missing, unreadable, and symlink sources all
  returned `FAILED` with boundary-specific detail before queueing.
- Safe Open: supported text and PNG handlers launched through the temporary
  test desktop entry; an unsupported binary returned `ok=false` with the
  explicit unsupported-type detail.
- Sanitization: created a separate copy and left the original unchanged.
- The returned activity list contained `Scan completed`, `Threat detected`,
  `File quarantined`, `File restored for review`, `Quarantined file deleted`,
  `Safe Open`, and `Sanitized copy`. After restarting both the user and system
  File Security services, the same activity set remained present.
- Service/package boundary: `greyward-security-context` requires both
  `clamav` and `clamav-update`; `ProtectHome=read-only` remains active and
  `/run/greyward-file-security` is the dedicated transfer path.

The no-compatible-handler branch is isolated in the source suite because the
VM has an unrelated installed handler for the test text MIME type; the runtime
fixture cannot honestly claim “no handler” without changing system
associations.

## Status

| Finding | Status | Evidence / limitation |
| --- | --- | --- |
| SC-FILE-001 | RUNTIME VERIFIED | Packaged `clamav-update`, active `clamav-freshclam.service`, current definitions, and scan admission were observed on Fedora. |
| SC-FILE-002 | RUNTIME VERIFIED | Canonical `FILE_SECURITY` activity entries were observed and remained after restarting both File Security services. |
| SC-FILE-003 | RUNTIME VERIFIED | Clean, folder, and EICAR runs reported 1 inspected file in both clean/detected cases; duplicate-output accounting remains unit-tested. |
| SC-FILE-004 | RUNTIME VERIFIED | Confined root/user D-Bus execution completed quarantine, ordinary-home restore, and delete while `ProtectHome=read-only` remained active. |
| SC-FILE-005 | RUNTIME VERIFIED | Home file/folder scans passed; `/tmp`, missing, unreadable, and symlink inputs were rejected before queueing with truthful details. |
| SC-FILE-006 | RUNTIME VERIFIED + UNIT VERIFIED | Text/PNG launches and unsupported-type refusal passed on Fedora; no-handler, Flatpak-export, special-name, and bubblewrap contracts pass isolated source tests. |

## New issues and limitations

- The root service's in-memory pending prepare records are intentionally short
  lived. If the service exits after publishing a quarantine object but before
  the user-session commit, reconciliation can retain evidence but requires a
  future recovery/readiness workflow rather than guessing that source removal
  happened.
- The runtime pass used a temporary user desktop entry backed by `/usr/bin/true`
  to verify Safe Open argument/handler resolution without changing installed
  desktop associations.
- Existing unrelated repository changes were left untouched; this record does
  not reclassify earlier audit findings outside SC-FILE-001..006.
