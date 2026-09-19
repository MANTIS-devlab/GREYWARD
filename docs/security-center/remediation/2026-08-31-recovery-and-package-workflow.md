# SECURITY_CENTER_REMEDIATION_04

## 1. File Security regression check

The four Python errors reported after the previous File Security remediation were
reproduced in the GREYWARD-DEV discovery run and classified before changing code:

| Reported error | Classification | Disposition |
| --- | --- | --- |
| Operation/detection durability rejected `/tmp` | Development-test fixture crossed the production scanner's `PrivateTmp=yes` namespace boundary | Test fixture corrected to exercise ownership/ClamAV policy without claiming service-private paths are visible |
| Quarantine restore reported the object missing | Stale mocked quarantine-root fixture | Mock corrected to match the current quarantine root contract |
| ClamAV-unavailable scan admission stopped at `/tmp` visibility | Same `PrivateTmp` fixture boundary | Test fixture corrected; production admission behavior unchanged |
| Symlink/non-owned scan test stopped at `/tmp` visibility | Same `PrivateTmp` fixture boundary | Test fixture corrected; production ownership/symlink policy unchanged |

The corrected complete Python discovery passed 95/95 tests. No File Security
production behavior was changed for this discrepancy; the existing File Security
remediation remains closed on its original scope.

## 2. Package workflow optimization

The canonical package deployment now keeps a persistent guest-side Cargo target at
`~/.cache/greyward/package-cargo-target`. It runs the Rust workspace tests once
against the exact clean staged source, then reuses that target for the release/Tauri
build and passes an explicit skip flag so the RPM `%check` does not compile the same
Rust test graph a second time. The build script retains normal `%check` behavior for
standalone RPM builds; only the deployment path can skip it after its pre-build test
has succeeded. Clean staging, both RPM builds, installation, packaged checks, launch,
and the health gate remain required.

The deployment prints coarse `GREYWARD_TIMING` markers for source synchronization,
Rust tests, Tauri build, each RPM, package total, installation, packaged checks,
application launch, and health. The final measured values are recorded below from
the single final package run.

## 3. Finding results

| Finding | Status | Evidence |
| --- | --- | --- |
| SC-REC-001 | FIXED + RUNTIME VERIFIED | Repository identity is read from Restic config and state is keyed by that identity; disposable A/B switch test isolated and restored state correctly |
| SC-REC-002 | FIXED + RUNTIME VERIFIED | Backup, verify, and restore write per-repository operation records with explicit terminal states and `completed_at` |
| SC-REC-003 | FIXED + RUNTIME VERIFIED | Restore candidates preserve `FILE`/`DIRECTORY`/`UNKNOWN` types; disposable list/restore path accepted a file and directory and produced a staged restore |

## 4. Root causes

- Recovery state was effectively global to the configured destination, so changing
  repositories could expose the previous repository's backup/check truth.
- Operation records did not consistently model preparation, execution, failure, and
  terminal completion as durable per-repository state.
- Restic listing flattened candidates to strings, losing file/directory semantics and
  allowing the UI to present stale or ambiguous selections.
- The package workflow built the Rust test graph once during a staged pre-check and
  again during RPM `%check`, while the disposable guest target was not separated from
  the package target with explicit timing output.

## 5. Implementation

- `restic_backup.py` now reads the actual Restic repository ID from pretty-printed
  `restic cat config` output, persists it in configuration, and stores all backup,
  verification, and restore state below `state["repositories"][repository_id]`.
  Legacy global fields are not projected as current state.
- Backup and verification persist `RUNNING`, `FAILED`, or `COMPLETED` operation
  records; restore persists `PREPARING`, `RUNNING`, `FAILED`, or `COMPLETED`, with
  terminal completion timestamps.
- `list-files` returns typed `candidates` while preserving the legacy path list for
  compatibility. The frontend labels candidate types, shows operation wording that
  follows the actual terminal state, and clears the picker after successful restore or
  cancellation.
- `build-security-center.sh`, both RPM specs, and
  `deploy-security-center.ps1` share the persistent package Cargo target and emit
  stage timings. The explicit deployment skip is only set after the staged workspace
  test succeeds.

## 6. Runtime validation

In GREYWARD-DEV, a disposable Restic workflow passed with temporary XDG config/state
and temporary repositories under the user runtime mount:

- repository A configured, backed up, and verified;
- repository B configured and confirmed to have null prior backup/check/operation state;
- repository B backed up and verified;
- typed candidates identified a fixture file as `FILE` and directory as `DIRECTORY`;
- both candidates restored into a staging directory;
- status reported restore operation `COMPLETED` with `completed_at`;
- repository A reconfigured and its previous successful backup/check state returned.

The fixture and exact temporary repository root were removed after the run. This is
development-VM runtime evidence, not an ISO or release-image claim.

## 7. Tests

Source-focused validation completed before final packaging:

- Recovery Python tests: 19 passing, including pretty-printed Restic identity parsing,
  repository switching, legacy-state hiding, typed candidates, and terminal restore
  state.
- Full Security Context Python discovery in GREYWARD-DEV: 95 passing (including the
  four corrected File Security regression fixtures).
- Frontend contract tests: 50 passing, one configured-CDP interaction skip.
- `build-security-center.sh`: remote `bash -n` syntax check passed.

The exact final package command and its staged Rust test result are recorded in the
next sections after execution.

## 8. Final package validation

The single final command was `tools/greyward-dev/deploy-security-center.ps1` and
passed clean staging, the staged Rust tests, both RPM builds, installation, packaged
checks, application launch, and `health.ps1` (`RESULT: HEALTHY`). The installed
packages were `greyward-security-center-0.1.0-45.fc44.x86_64` and
`greyward-security-context-0.1.0-44.fc44.noarch`, release `20260831T214107Z`.

Measured coarse timings were: source sync 7,241 ms; staged Rust tests 97 s; Tauri
release build 430 s; Security Center RPM 440 s; Security Context RPM 3 s; package
workflow through RPM production 446 s; RPM install 13 s; packaged checks 0 s; launch
3 s; health 2,922 ms. The RPM `%check` printed
`rust-tests seconds=0 (already passed against staged source)`, confirming the
deployment-only duplicate test graph was skipped after the staged pass.

## 9. Documentation

Updated `docs/development/DEVELOPMENT.md` with the persistent package target, single
staged Rust test pass, explicit deployment-only `%check` skip, required gates, and
timing markers. Updated `docs/REPOSITORY_MAP.md` and this remediation index so the
canonical workflow and evidence record remain discoverable.

## 10. Remaining limitations

- The Windows authoring host cannot run/link the Linux Rust target; Rust tests and
  package validation run in GREYWARD-DEV.
- At the time of this historical record, the configured frontend interaction test
  was skipped without a CDP environment; the Recovery evidence was backend/CLI
  and packaged launch validation rather than a visual UI click trace. The
  current WebDriver path is documented in the 2026-09-01 Network Activity record.
- No VM image, ISO, hardware, or release acceptance claim is made here.

## 11. Remaining audit findings

This remediation intentionally does not change or close unrelated findings,
including Network Activity partial coverage, SC-EVD-001 and SC-DMS-003 visual retests,
Updates, Privacy, Applications, localization/dialog/accessibility/general visual work,
or the Quickshell descriptor-leak finding. Those remain governed by their prior scope
and evidence records.
