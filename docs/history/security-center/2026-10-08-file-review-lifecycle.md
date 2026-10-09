# File detection review lifecycle — 2026-10-08

Scoped development evidence; not image or production acceptance.
The current contract is [File Security](../../security-center/FILE_SECURITY.md).

## Problem and implementation

The installed Files & scans page kept quarantined detections in active review
and offered quarantine for two August EICAR records whose source no longer
existed. A real new EICAR scan/quarantine succeeded, demonstrating that the
defect was stale review presentation rather than the scanner or verified-copy
quarantine transaction.

Center 76 separates unresolved review from collapsed handled history. Context
72 projects fresh source existence for DETECTED records without modifying
their durable detection state or action history. Missing sources have an
explicit historical label and no quarantine action. Unknown existence,
aliases, failed actions and restored files remain reviewable. Quarantined
objects retain restore/delete controls in history. Viewing a record does not
silently acknowledge it or declare the file safe.

## Validation

- IMPLEMENTED: focused Python tests cover fresh disappearance/reappearance,
  preserved history, permission failure and symlink uncertainty.
- VALIDATED: 17 File Security and eight ClamAV tests; 121 frontend tests,
  including active/contained/missing/failed/restored review partition behavior.
- VALIDATED: exact installed Center 76 / Context 72 / runtime 27 native UI
  scan/quarantine and stale-source readback on the normal `.149` desktop.
  Both August sources report MISSING while their original DETECTED records
  remain historical. A new real ClamAV EICAR detection appears in active review;
  clicking Move to quarantine clears active review and the Review needed banner.
  The verified root-owned 0600 copy matches the known EICAR SHA-256, and restore/
  delete controls remain in collapsed history. The test copy was then deleted.
- VALIDATED: running Center PID 70035 matches the installed executable hash and
  remains in `greyward_guard_t`; RPM integrity and the protected desktop verifier
  pass. SSH recovery and the existing desktop remain available.

Package receipts:

- Center RPM: `1f06cc5298c8e0a8377d51eb26424d87c141fab19503b0751028f2d604db46a1`.
- Context RPM: `4a681da24f85b30c708fed365e84c47c071b455435c0df8b8fe33daf9bd98097`.
- Running Center: `66afcf76258fb371afc8aab78b8b7d43be4d836bcfdabde4c7365424c0ef163b`.

Ignored local evidence is under `output/malware-check-20261008/`, including
`final-evidence.json` and `quarantine-cleared.png`. These are supporting
development artifacts, not a second product specification.

The development deployment keeps the preceding 75/71/27 package tuple and
root-owned selector receipt under
`/var/lib/greyward-development/application-security-live/file-review-20261008/`
for rollback. This patch adds no policy/schema
migration, enrollment, authentication change or reboot. Test inputs are unique
user-owned harmless EICAR files; existing user files/history remain intact.
