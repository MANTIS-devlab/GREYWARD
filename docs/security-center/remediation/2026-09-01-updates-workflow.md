# SECURITY_CENTER_REMEDIATION_07

## Scope

This bounded record covers SC-UPD-001, SC-UPD-002, and SC-UPD-003 for the
Security Center Updates workflow. Download, apply, reboot, and full Update
Center production readiness remain outside this session.

## Findings and root causes

| Finding | Status | Root cause |
| --- | --- | --- |
| SC-UPD-001 | FIXED + RUNTIME VERIFIED | The frontend selected `COMPLETE` before checking current available records. |
| SC-UPD-002 | FIXED + RUNTIME VERIFIED | History was a thin provider/version delta without normalized identity or readable result/version fallbacks. |
| SC-UPD-003 | FIXED + RUNTIME VERIFIED | Hero, progress, actions, and feedback used separate phase conditionals; terminal progress was not cleared at the transaction boundary. |

## Implementation

- Added one Updates presentation model with explicit precedence for checking,
  active phases, ready-to-restart, failure, current availability, provider
  degradation/unavailability, and terminal historical states.
- Changed the visible Check action to the resolve-only Tauri command so a check
  cannot enter the optional-provider update path.
- Reset terminal transaction progress and cancellability in the Update Center
  service and normalized bounded history identity, versions, source, timestamp,
  provider, and result fields.
- Extended the existing WebDriver interaction test with semantic Updates
  selectors and terminal/progress/history assertions.

## Evidence

- Real Tauri run: `tools/greyward-dev/run-security-center-interaction.ps1`.
- Updates trace: busy phase observed; terminal `RESOLVED` review state; 395
  available updates; progress reset; 200 history rows; no stale progress text.
- The same run retained the passing Network Activity interaction trace.
- Focused frontend and Python update tests passed.

## Package validation

Single final validation passed for release `20260901T054237Z`:

- `greyward-security-center-0.1.0-45.fc44.x86_64`
- `greyward-security-context-0.1.0-44.fc44.noarch`
- locked Rust workspace tests: `25` passed in `25s`;
- source sync: `51082ms`; release Tauri build: `172s`; RPM build: `202s`
  (`188s` center and `6s` context); RPM reinstall: `12s`; packaged checks: `0s`;
- application launch: `2s`; packaged health: `RESULT: HEALTHY`.

## 2026-09-06 apply/reboot follow-up

The development VM completed the reviewed workflow through its native offline
boot. DNF5 history transaction `70` records command
`/usr/bin/dnf5 upgrade --offline --assumeyes`, result `Ok`, and 894 altered
packages. Security Center matched that newer successful history record and
reported the transaction `COMPLETE`; the restarted host is running kernel
`7.1.13-200.fc44.x86_64`. This validates installed result reconciliation on the
development VM, not clean-image or release acceptance.

The same observation found a presentation defect: the conditional status unit
ran, but the custom theme remained on `Starting GREYWARD` throughout the native
DNF5 work. The branding source now explicitly enters Plymouth `updates` mode,
uses the supported display-message operation to select an update-only surface,
and registers Plymouth's system-update callback. The surface says that updates
are installing, warns against powering off, and renders a provider-reported
progress bar/percentage, with a truthful non-numeric preparing fallback. Static
and package checks may validate the source and payload; the visual behavior
remains pending the user's next intentional update/reboot and was not exercised
while applying this patch.

## Remaining limitations

Clean-image apply/reboot acceptance, user-observed update-mode branding after
this patch, provider-specific native history quality beyond the successful DNF5
case above, and unavailable/degraded provider runtime manipulation remain open.
