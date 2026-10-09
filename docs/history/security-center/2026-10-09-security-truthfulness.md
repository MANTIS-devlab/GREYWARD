# Targeted security truthfulness correction — 9 October 2026

**Scope:** repository source and local tests only. No package build/deployment,
policy update, service restart, grant mutation or graphical-session interruption
on `.149` is authorized or performed. Existing working-tree changes are retained.
This record supersedes earlier source semantics only; prior installed receipts
remain historical evidence for their exact tuples.

## Fix 1: confined ClamAV status

The ordinary session is denied ClamAV database metadata and scanner execution.
The previous collector swallowed database access errors and inferred INITIALIZING
from an active freshclam process. Root read-only inspection still reports ClamAV
1.4.6, daily definitions dated 9 October, an active existing scanner service and
SELinux Enforcing. This is before-change evidence, not candidate acceptance.

The existing `clamav_service.py` system service now exposes the fixed, read-only
`GetClamAvStatus` method. Its D-Bus policy admits this metadata read, without
admitting scan mutations or ordinary database access. `user_bus.py` uses the
shared `clamav.system_status` transport for summary, status and fallback reads.
No second daemon, ordinary scanner execution or SELinux allow rule is added.
The method does not reconcile scan history or run an update/scan.

The collector separates engine, definitions, freshness, updater and scan activity.
CURRENT means current metadata and an executable engine for on-demand scanning;
it never means real-time protection or a completed clean scan. Activity remains
UNKNOWN here; File Security's existing active operation supplies scan activity.
Missing evidence is UNAVAILABLE, stale definitions OUTDATED, conflicting clocks
or updater failures ERROR. Fresh provider timestamps and reply bounds reject
stale/malformed responses. Definition mtime is displayed as a definition timestamp;
last successful update remains null without transaction evidence.

The Rust `ClamAvStatus` contract admits these additive optional metadata fields,
with defaults for older payloads. Existing scan/quarantine/restore code is retained.
Old Center binaries with strict field decoding must not consume the new payload;
ship the matched Center and Context candidates together.

## Fix 2: security claims

| Area | Before | Source correction |
|---|---|---|
| Portal/deputies | Seat and labels asserted complete portal/deputy coverage | Legacy boolean false means not independently verified. Verified baseline checks remain required; optional portal/deputy isolation is excluded from the baseline badge and explicitly disclosed as unverified. |
| VPN | Detected interface asserted VPNProtected, Enabled and provider verification | VPNTunnel records tunnel/DNS route observations; encryption, validation, leaks and kill switch remain Unknown. Routing observations are not leak tests. No network mutation algorithm is changed. |
| Accepted deviations | Measured checks overwritten as PROTECTED | Original measured check states retained. Recommendation aggregation is quiet after acceptance, while evidence rows show accepted limitations and actual states. Missing recovery prerequisites remain visible. |
| Grants | Generic-sounding Review tool access | Review SSH key inspection, with explicit script/IDE/Flatpak limitations. Existing supported review, registration and revocation remain available; no generic grant provider is implemented. |

`PROTECTED` is a scoped baseline/posture designation with accepted limitations,
not a universal no-bypass or fully secure desktop guarantee. The backend domain
aggregate still represents accepted policy risk; source check states are the
measured result. No user acceptance creates enforcement or changes permissions.

## Validation

Local WSL Linux Context suite: 331 tests, 29 skipped, no failures. The skipped
runtime/hardware checks are not acceptance evidence. Frontend suite: 141 tests,
138 passed, 3 live Tauri checks skipped. Repository static and documentation checks, formatting and tracked diff whitespace checks pass at handoff.
Focused tests cover current/missing/denied/unavailable/stale/conflicting ClamAV
metadata, failed/stale system providers, optional portal coverage, unmeasured VPN
assurances, retained accepted check states and narrow supported-grant copy.
Rust domain/backend tests: 84 passed, one host integration test ignored.
`cargo fmt --all -- --check` passes. Runtime compilation succeeds; broad runtime
unit execution on WSL reports 54 passed, five ignored and three failures in
unchanged `policy_intent` fixtures requiring a SELinux process context. WSL
AppArmor labels cannot supply that evidence; this is not a Fedora acceptance
pass. The seven scoped enrollment tests pass locally.
Clippy with the new local Rust 1.99 toolchain reports pre-existing deprecated
`fetch_update` and new assertion-style lint errors outside these fixes. No
unrelated code is rewritten to satisfy a different toolchain. Full Tauri/Fedora
workspace compilation and installed confined-session checks remain pending.

## Required deployment and live validation — not performed

Obtain separate authorization before deploying matched Context, Center and
Application Security runtime packages plus the narrow existing scanner D-Bus
read policy. Record package receipts and back up the matched old packages and
existing D-Bus policy. Activation must respect the no-restart/no-logout constraint;
if an existing service must restart to load source, seek explicit approval first.
Never restart the bus, greetd or Labwc, and never reboot `.149`.

After approved activation, compare root provider and the real confined
`SecurityContext1.GetClamAvStatus` metadata and Center Files & scans display.
Check missing/denied/stale provider behavior in a private fixture, not by changing
the live definitions. Exercise a synthetic scan/detection/quarantine/restore with
explicit live-mutation approval. Confirm ordinary database/scanner restrictions
remain denied and SELinux remains Enforcing. Inspect live VPN ownership and
Unknown assurances without changing NetworkManager/DNS. Inspect accepted checks,
portal caveats, narrow grant review and existing revoke workflow in real Center.

Rollback restores the matched old packages and exact scanner D-Bus policy under
approved activation. No data/database migration is introduced; preserve detection
history, protected-resource labels, grants, enrollment and Administration state.
Rollback restores the old reporting defect as well as its previous compatibility.
Do not restore unrelated files or reset the current working tree.

Both fixes: **IMPLEMENTED BUT REQUIRES LIVE VALIDATION**.
No network-authorization, USBGuard, update/recovery, isolation or other audit
finding is modified. Production release and generic Flatpak permissions remain
outside scope.
