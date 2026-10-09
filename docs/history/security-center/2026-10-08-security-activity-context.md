# Security Activity context delivery — 8 October 2026

Status: scoped installed-development evidence. This is not release acceptance.

## Delivered behavior

Security History and application/resource activity share the contextual renderer
in `security-history.js`. Rows show the supplied actor, action, registered-resource
label, recorded outcome and explanation. Application names resolve through bounded
root-backed inventory reads; observed executables use distinct functional glyphs.
Compact native disclosures reveal the historical PID, attribution limits, source,
resource references, policy revision at collection and occurrence time. Material,
navigation and typed authorization owners remain unchanged.

Runtime 27 retains optional historical kernel PID/executable basename and audit
time from the existing AVC/failed-syscall correlation. Context 71 validates them
before ingestion and formats occurrence times through the shared UTC formatter.
No executable path, process title, argv, secret content, new event database or
network lookup is added. Application identity remains UNKNOWN without independent
identity evidence. Older records are not retroactively attributed. Resource labels
are registry observations at refresh, not historical captured names. Completed
policy changes never imply an allowed resource access. Invalid registration
previews cannot claim PROTECTED before authoritative readback.

## Installed tuple and integrity

| Package | RPM SHA-256 |
|---|---|
| `greyward-security-center-0.1.0-75.fc44.x86_64` | `66117bbccad686f16404c7a35d5df8b2d6131cffe8180219478a461cfd16fcb0` |
| `greyward-security-context-0.1.0-71.fc44.noarch` | `8e8008bf5643eb4dea47518a72718e0acc7a0b108b7f622c1a4ca418541456bf` |
| `greyward-application-security-experimental-0.1.0-27.fc44.x86_64` | `26e4b572b5e452fd817f0208d489b6cd54c9d2d88d7ea5cd092622801a7dfff5` |

Center executable: `4da7f5ac6662e8eb99b3ead851c79eed7004beec6811661de95c5a9965bc9c1c`.
Center source archive: `c44378aa278c552ad0ddba4afea0b349f12c098252f1a5409f40b69c59693982`.
Center spec: `94e66438f27a03c717ecb5fbaeaae58091e2017ddbf09a19948fade868ab2500`.
Guard executable: `d6b4c9013dab1dd18ecc38a6178ef6e0a310bdcda1d18e76e987c4603aea4019`.
Protected desktop manifest remains
`5073490e79c72dda4c26bab442f5ea38da5615600b54b00b37a7f63946be6946`.

Cached offline Fedora builds were used. The guest had 5.0 GiB available before
building; no cleanup, reboot, logout, seat replacement or enrollment change was
performed. Intermediate Center 74/Context 70 were development candidates only.
The active receipt is `/var/lib/greyward-development/application-security-live/active.json`.

## Validation evidence

- Actual ordinary/direct `cat` and Python reads of the registered SSH key were
  denied on UID 1001 in `greyward_guard_t`; no key contents were output.
- The existing root collector, installed Context, Tauri facade and normal desktop
  show those same records with `cat`/`python3.14`, READ, the actual registered
  resource, DENIED and kernel decision evidence. Application identity stays
  UNKNOWN. Final occurrence times use the existing UTC telemetry format.
- Actual installed UI was visually inspected at 1440×900 and 1100×700: default
  rows, expanded evidence, category changes, local presentation activity and
  shared Protected Data activity. No horizontal overflow or injected preview.
  The live history was too short to offer pagination; cursor behavior is covered
  by focused source tests, not claimed as a live pagination pass.
- Fresh root verification succeeds; normal UI reports connected/PROTECTED
  coverage and resource state. Actual running Center matches the installed
  executable hash and confined domain. All three package payloads pass `rpm -V`.
  Labwc/native DMS authentication retain their existing processes and closure;
  SSH recovery and installed Flatpak inventory remain available.
- 121 focused frontend tests, 12 Context workflow tests, 11 telemetry tests,
  two runtime audit tests and Rust formatting pass. Both repository gates pass.
  EN/FR catalogue behavior is source-tested; this pass's actual captures are EN.

Ignored local evidence is in `output/security-activity-20261008/` and the guest's
`/var/tmp/greyward-application-security-build/activity-center75/`. Center is left
open on Security History in the normal installed desktop.

## Recovery and limits

Root-only mode-0700 backup directory
`/var/lib/greyward-development/application-security-live/activity-20261008`
retains the previous 73/69/26 RPM tuple, prior receipts, policy database backup
and delivered RPMs. Matching package rollback requires the saved tuple and
broker/Context restart; no enrollment, labels or policy revision were changed
by this delivery. Do not blindly restore a database over later user operations.
No new rollback rehearsal is claimed for this UI pass.

Allowed sensitive-data accesses are not collected by the current denial feed;
the UI does not manufacture them from successful launches or grants. Historical
PID/basename evidence is not generation-bound application identity. More complete
attribution, exhaustive provider/deputy matrices, performance, physical-seat,
suspend, clean-image and production lifecycle acceptance remain
**DEFERRED HARDENING** under the existing implementation plan.
