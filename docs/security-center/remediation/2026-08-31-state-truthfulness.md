# Security Center remediation — state truthfulness cluster — 2026-08-31

## Scope

This record covers SC-NET-001, SC-NET-002, SC-NET-004, SC-DEV-001, SC-EVD-001,
and SC-DMS-003. Unrelated File Security, Recovery, Updates, Privacy, and
Network Activity findings remain outside this remediation.

## Root causes established

- Firewall controls rendered both transitions from the same unqualified action
  set instead of deriving them from the authoritative active zone.
- Network Protection combined provider fields without qualifying heartbeat
  freshness, Secure DNS effective policy, or the firewalld zone; stale and
  insecure-fallback states could therefore reach a Protected hero.
- OpenSnitch package presence, process liveness, heartbeat freshness, and
  runtime capabilities were represented by overlapping fields.
- Devices presented USBGuard package availability as if it proved active
  enforcement.
- Overview/Evidence/DMS did not share check-level attention semantics; the DMS
  shell projection also retained dependent values after its freshness deadline.

## Implementation

- `security-center/tauri/src-tauri/src/lib.rs` now counts check-level protected,
  review, and unavailable results for the shared overview metrics and projects
  USBGuard installation separately from enforcement.
- `security-center/security-context/greyward_security_context/control_plane.py`
  and `user_bus.py` expose freshness-qualified OpenSnitch health and runtime
  capabilities. Stale-but-live, degraded, and unavailable states are distinct
  and converge on recovery.
- `security-center/security-context/greyward_security_context/shell_summary.py`
  makes current posture, counters, network/malware/USB values, profile control,
  priority, and notifications unavailable after expiry while retaining an
  explicit cached projection.
- `security-center/tauri/frontend/app.js` derives Network Protection from the
  same effective firewall, DNS, and OpenSnitch state; zone actions are
  directional, compatibility fallback is attention, accepted deviations are
  excluded from actionable findings, and successful zone transitions reload
  immediately. `SecureWidget.qml` suppresses stale dependent counters/actions.
- `tools/greyward-dev/iterate-security-center.ps1` adds persistent guest source
  and Cargo target locations, component synchronization/restart, incremental
  frontend execution, Rust `cargo check`, and an explicit `-Reset`.

## Runtime validation

The fast workflow was exercised in GREYWARD-DEV for Python, Rust, frontend, and
DMS components; the frontend fast launch completed in about 14 seconds after
the persistent Cargo target was warm. The final packaged runtime then reported
OpenSnitch healthy with installed/activity/rule capabilities and Secure DNS
`SecureProvider / DoT`. Controlled outage/recovery checks produced:

- OpenSnitch healthy → unavailable with inactive daemon/control-plane and
  unavailable runtime capabilities → healthy/idle after restart.
- Secure DNS healthy → `Unavailable / ServiceUnavailable` while the service was
  runtime-masked → SecureProvider after unmask/start.
- USBGuard running → `REVIEW_NEEDED` with `policy=Stopped` while the package
  remained available → secure with `policy=Running` after restart.
- firewalld public → trusted → public, with the original active interface/zone
  restored.

The packaged Overview readback reported `protected=12`, `review_needed=0`, and
`unavailable=1`. At the time of this historical record, DMS reported an
unavailable current posture with null dependent review/device counters and
disabled profile change, rather than presenting stale values as current. A
later remediation corrected the compact Overview aggregation: the same VM now
reports `PROTECTED` with one optional unavailable check while retaining that
limitation in the evidence view. During the
packaged OpenSnitch outage readback, `installed=true` remained separate from
unavailable activity/rules/mutation, then all runtime capabilities recovered.

## Tests and package validation

Focused frontend contracts passed 47 with one configured-CDP skip. The Fedora
focused Python suite passed 21/21 and the backend Rust suite passed 25/25; the
canonical staged workspace test pass also passed 36 Rust tests. The final
package command was `tools/greyward-dev/deploy-security-center.ps1`; it built
and reinstalled `greyward-security-center-0.1.0-45.fc44.x86_64.rpm` and
`greyward-security-context-0.1.0-44.fc44.noarch.rpm`, verified packaged helpers
and desktop metadata, and launched the installed Tauri application. The final
`tools/greyward-dev/health.ps1` gate was healthy.
The deployment reported release `20260831T205420Z`.

## Status

| Finding | Status | Evidence / limitation |
| --- | --- | --- |
| SC-NET-001 | FIXED + RUNTIME VERIFIED | Directional zone actions and both transitions verified in the packaged runtime. |
| SC-NET-002 | FIXED + RUNTIME VERIFIED | Healthy and degraded required-provider states verified from the packaged authoritative projection. |
| SC-NET-004 | FIXED + RUNTIME VERIFIED | Healthy, stale/degraded, unavailable, and recovered OpenSnitch projections verified. |
| SC-DEV-001 | FIXED + RUNTIME VERIFIED | Installed USBGuard capability is distinct from active enforcement in packaged Devices data. |
| SC-EVD-001 | FIXED + SOURCE VERIFIED | Shared check-level metrics, accepted-deviation filtering, and DMS attention semantics are covered by Rust/Python/frontend contracts; the packaged runtime also agrees on its current unavailable state. A deterministic accepted-deviation click trace was not run. |
| SC-DMS-003 | FIXED + SOURCE VERIFIED | Freshness-qualified shell projection and stale-counter suppression are covered by Python/frontend contracts; packaged DMS readback is honest while the current posture is unavailable. A direct visual stale-expiry trace was not run. |

## Limitations and new issues

- The Windows authoring host cannot link the Linux Rust target; Rust package
  tests and checks therefore run in GREYWARD-DEV.
- A full Python discovery run still contains four unrelated File Security test
  errors in the development VM; those tests were not changed as part of this
  cluster. The secure-DNS fixture exercised by this cluster was corrected and
  passes in the focused suite.
- At the time of this historical record, a real application UI click trace was
  less automated than the authoritative D-Bus and packaged projection checks;
  the current WebDriver path is documented in the 2026-09-01 Network Activity
  record.
