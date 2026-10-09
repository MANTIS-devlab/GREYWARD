# Installed Application Security UI integration — 7 October 2026

Historical execution evidence, not a production enrollment guarantee. The
[delivery authority](../../security-center/APPLICATION_SECURITY_PLAN.md) and
[enrollment authority](../../security-center/APPLICATION_SECURITY_ENROLLMENT.md)
describe supported behavior and remaining essential work.

## Reproduced disconnect and correction

On the normal UID-1001 desktop, installed Center 61 displayed four real broker
inventory records and its managed-isolation action. After the five-second
projection lease expired, the records/action disappeared and the UI described
the provider as unavailable, although native Tauri reads still reached it.
The expiry callback rerendered expired data without requesting new evidence.
Waiting for the separate Flatpak collector could also exhaust the Guard lease
before its initial display.

The controller now serializes fresh reads while its route is visible, cancels
its route subscription, rejects late replies and retains expiry as a fail-closed
backstop. Flatpak collection no longer delays the Guard workspace. Unchanged
projections preserve detail, focus and search state. Connectivity is shown
separately from enforcement. Protected Data explains why registration and grant
changes are unavailable when the actual capability is false.

Center 63 constrains Overview's overall success claim using fresh mandatory
Guard coverage. Legacy system checks alone cannot produce a fully Protected
Overview. Installed Center 64 applies the same constraint to the Applications
row and removes duplicated review wording. The actual normal-desktop Overview
reports Applications UNAVAILABLE alongside the live connection indicator.

Runtime 20 replaces the default coverage snapshot with fresh enrollment
prerequisites from the root database, authenticated kernel-bound peer and actual
SELinux filesystem. Missing enrollment or an unconfined caller is UNAVAILABLE.
A journal cannot provide positive session, label, remote-session or deputy
coverage. Those fields remain false until independently established.

## Actual installed checks

The native WebKit driver launched `/usr/bin/greyward-security-center` on the
existing `wayland-0`, normal user bus and normal HOME/configuration. No mocked
Tauri bridge, private display, alternate account or fixture application was
used. Normal desktop captures also show the user's installed window and DMS bar.

- Center 63 / Context 67 / runtime 20: native reads, four actual registered
  applications and isolation capability; no resource/grant capability.
- Center 64 / Context 67 / runtime 20: the same native route/refresh checks pass
  on the normal desktop; Overview's Applications row is UNAVAILABLE rather than
  the former Secure. This is the final installed integration tuple.
- Applications and Protected Data remain connected after 7.5 seconds.
  Inventory/actions match the real typed responses. Coverage is UNAVAILABLE,
  effective profile absent; no synthetic registered resource was displayed.
- Stopping the real broker removes stale inventory/isolation actions and reports
  disconnection. Restarting restores the view without navigation or a manual
  refresh. Existing Context owner-pinning/recovery remains in use.
- The Overview screenshot reports Review needed and session protection
  unavailable. It does not retain the former all-protections-active claim.
- DMS PID 4888 and Labwc PID 4813 retain their original 6 October start times;
  SSH remains available and SELinux Enforcing. Neither was restarted.
- Managed-isolation rollback `--check` passes. This is a checked prerequisite,
  not a new withdrawal rehearsal or enrollment rollback. Earlier actual
  runtime-19 withdrawal/reactivation remains historical evidence.
- The owned native driver session was closed and its driver stopped. The
  installed canonical launcher reopened Center 64 normally on Applications.
  Its actual desktop screenshot shows live connection, registered records and
  Run isolated; PID 2873790's `/proc/PID/exe` digest matches the package binary.
  The window remains open for review. Protected Data enrollment is incomplete.
- 104 focused frontend tests, four broker transport tests, seven enrollment
  tests, workspace formatting and both repository gates pass.
- The additional Clippy attempt did not pass. The installed Fedora packages
  identify Cargo/Rust/Clippy as 1.98, but `cargo clippy --version` reports 1.99.
  The shared target failed with incompatible Rust metadata; an independent
  target then failed on the existing `fetch_update` deprecation in the backend.
  No passing current all-target Clippy result is claimed. Earlier scoped
  authentication receipts retain their historical toolchain results.

Ignored local evidence: `output/application-security/20261007-live-development/`
contains before/after native responses, desktop PNGs, broker-loss/recovery
results and source/build logs. Root-private inputs and previous packages remain
under `/var/lib/greyward-development/application-security-live/` on `.149`.

| Installed input | RPM SHA-256 |
|---|---|
| Center 63 | `9c88220d03c977f83eafa7bc7978421f53f6bc22ac596f3b8b7f06f8f35bf654` |
| Center 64 | `f11b1f4613258b8aba3644f79095c85f8e1938db826b2f9248a75b15e2d83f77` |
| Context 67 | `cde7d8f7edd69a552fab631eda99e2b84956c3432f1ee3736d716f46420c5f5b` |
| Runtime 20 | `e6e43d5e2390783972f11a9eedfdbc8ba467567b3e9827c4b75a3f770cbf0f1d` |

Center-63 installed/running executable SHA-256:
`310e2f10f0d029e594c85519b47b442c09dd36bc07eca87b282d04fef86bcc70`.
Center-64 installed/running executable SHA-256:
`98804402d0079916a32db8c68d6397bad21f08d9c7d1fca973d04d87f6f92cb1`.

## Essential enrollment remains incomplete

The normal account remains unconfined and has no enrollment, protected-resource
or grant record. UI integration success is not whole-session protection or a
successful sensitive-grant workflow.

Separate authentication-domain proof covered process/FD separation and
private-display authentication. It did not establish this desktop's trusted
input/compositor path, normal-session admission or positive coverage.
Read-only normal-desktop protocol inspection now confirms the actual compositor
peer is `unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023`. Its ordinary
connection advertises virtual keyboard, virtual pointer, both capture protocols,
security-context management, session locking and layer-shell. No protocol other
than registry inspection was bound; no input, capture or authentication was
attempted. This is direct evidence that the current socket is not the proposed
restricted ordinary-client connection, not a demonstrated exploit.
[Labwc 0.9.6's exact filter](https://raw.githubusercontent.com/labwc/labwc/0.9.6/src/server.c)
excludes virtual input, capture, session locking and layer-shell from
security-context clients. The full desktop shell cannot simply use that
restricted connection; ordinary clients and immutable trusted desktop/
authentication subjects require distinct connections and verified admission.
Assigning the mutable ordinary shell an authentication role would not implement
that boundary. This remains essential implementation, not DEFERRED HARDENING.

Enrolling the normal account before splitting these authorities would either
retain an unverified credential-input deputy or remove interfaces required by
the existing desktop. The next essential implementation is the fixed trusted
desktop/authentication admission and ordinary security-context connection,
followed by the fresh-session boundary and authoritative coverage. Installing
the broker or changing only the login mapping does not resolve this blocker.

No login mapping, PAM/authselect configuration, real credential label, account,
ISO or VM boot configuration was changed by these integration fixes.
