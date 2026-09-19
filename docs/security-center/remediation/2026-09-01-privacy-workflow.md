# SECURITY_CENTER_REMEDIATION_08

Date: 2026-09-01

Scope: `SC-PRV-001` Privacy profile state synchronization and `SC-PRV-002`
Privacy export destination feedback.

## 1. Finding results

| Finding | Result | Status |
| --- | --- | --- |
| SC-PRV-001 | Profile transitions now serialize, return the confirmed effective profile, force an authoritative Privacy readback, preserve pending state, and refresh the DMS shell projection. | SOURCE FIXED; ALPHA PROFILE READBACK PASSED; DEPLOYED; FULL INTERACTION GATE PENDING |
| SC-PRV-002 | Export now returns and displays the backend path persistently; success requires a non-empty returned destination and failures retain meaningful feedback. | SOURCE FIXED; EXPORT RUNTIME CHECK PASSED; FULL GATE BLOCKED |

## 2. Root causes

The Tauri `ActionResult` discarded both the confirmed profile and export path.
The Privacy page used a delayed reload after profile/export actions, allowing a
freshly confirmed state or visible feedback to be replaced by a cached page.
The failed profile-helper response echoed the requested profile even after a
transaction had rolled back, and concurrent helper calls were not explicitly
serialized.

## 3. Implementation

- Added typed optional `profile` and `path` fields to the Tauri action result.
- Profile actions accept success only when the returned effective profile equals
  the requested profile, then force `get_privacy` readback before rendering.
- Added a single-flight Privacy pending model and invalidated Privacy cache and
  in-flight page data on authoritative refreshes.
- Failed native profile changes now read back the effective post-rollback state;
  Security Context profile reads/mutations share a bounded process lock.
- DMS verifies the returned profile and forces a new `GetShellSummary` request,
  invalidating an older pending summary request when needed.
- Export feedback keeps the exact backend path visible and rejects success when
  the backend omits that path. The fixed local export contract is documented in
  `docs/security-center/PRIVACY.md`.
- Extended the existing semantic UX contract and Tauri interaction tests only.

## 4. Runtime Tauri validation

The first canonical run was stopped by the test harness’s SSH readback:
applying the intended `Private` drop zone cut the SSH control channel before the
test could complete. The interaction test was changed to use the app’s own
authoritative Tauri `get_privacy` readback for profile confirmation, and the
runner now launches the driver, app, and Node test entirely inside the guest;
the host only polls a bounded result marker and retrieves the log afterward. A
guest-local watchdog is armed before the first profile mutation and is canceled
after normal return to `Standard`.

The subsequent guest-local run reached the real Tauri app and passed the export
workflow, including the visible backend-returned destination
`/home/stendev/.local/state/greyward/security-center/exports/posture-latest.json`,
mode `600`, valid JSON, and exact-file cleanup. The run then failed to publish a
result within the 360-second bound while continuing through the combined legacy
interaction scenarios. SSH remained unreachable afterward. No canonical
`GREYWARD-DEV` VM or `CLEAN-GREYWARD-DEV` checkpoint is currently registered in
local Hyper-V, so the existing recovery tool cannot restore the guest for a
further run without an external runtime recovery action.

During the later Alpha recovery, the running Hyper-V console was inspected
with VMConnect screenshots. The installed official launcher was started in
the guest, and the Overview was visible. The active `TRAVEL` profile was
confirmed to have put `eth0` into firewalld `drop`; the canonical helper then
applied `STANDARD`, and direct SSH plus profile, firewalld and NetworkManager
readbacks all passed. The full interaction sequence, including restart and
navigation persistence, remains pending. The optimized RPM deployment was
subsequently completed through the canonical runner, and the installed app was
relaunched and health-checked successfully.

## 5. Tests

- `node --test security-center/tauri/frontend/ux-contract.test.mjs`: 59 passed,
  0 failed after the unavailable-posture UX correction.
- Guest-local harness dependency installation: locked `npm ci` completed with 321 packages.
- `PYTHONPATH=security-center/security-context python -m unittest discover -s security-center/security-context/tests -p 'test_*.py'`: 113 passed, 22 expected skips.
- `cargo fmt --manifest-path security-center/Cargo.toml --all -- --check`: passed.
- Guest Fedora workspace tests: 27 passed, 0 failed; canonical optimized RPM
  deployment and installed-package checks passed.
- Windows Rust compilation could not run because this host has no MSVC
  `link.exe`; the Fedora runner is the intended Rust/Tauri build environment.

## 6. Package validation

The optimized package deployment and installed-package checks passed through
the canonical runner. Full profile-sequence, navigation and restart
persistence validation remains pending.

## 7. Documentation

Updated `docs/security-center/PRIVACY.md`, this remediation record, the
remediation index, and `docs/REPOSITORY_MAP.md`.

## 8. Remaining limitations

Runtime evidence is incomplete until a guest-local runner can complete the
profile sequence, navigation/restart persistence, and the affected interaction
scenarios. The disposable development VM’s `Private`/`Travel` profiles can
intentionally block its SSH management path; this audit restored Alpha through
the supported console/helper path. The package deployment itself is no longer
pending, but it does not replace the missing full interaction run.

## 9. Remaining audit findings

No additional Privacy finding was opened. `SC-PRV-001` and `SC-PRV-002` remain
source-fixed pending the clean runtime gate above.
