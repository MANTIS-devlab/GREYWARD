# Security Center shell redesign runtime record

Historical development evidence — 2026-09-16. Not release-image acceptance.
Current behavior: [Live Privacy Capsule](../../security-context/LIVE_PRIVACY_CAPSULE.md).

## Scope and installed boundary

The source changes cover the Security Center widget, scoped DMS popup/current/history
cards, shared presentation/delivery, PipeWire classification, USBGuard actions,
and the existing scan entry points. No alternate security authority was installed.
The Fedora 44 VMware guest ran a user-level development overlay under
`~/.local/share/greyward/security-shell-dev`, selected by the
`60-security-shell-dev.conf` drop-ins for the Security Context and DMS user units.
The privileged scanner remained the previously installed package. The overlay is
intentionally left active for review; it is not production installation evidence.

## Evidence matrix

| Case | Observed result / limit |
|---|---|
| Widget and notifications | Real guest captures show stable emblem, opaque graphite cards, separate activity, readable hierarchy and visible trust actions. DMS loaded without QML runtime errors. |
| Real microphone | VMware capture to `/dev/null`: attribution appeared and cleared; two applications grouped without losing names. Review count stayed 3 before/during/after capture. No ordinary capture popup. |
| Camera | No camera in host/guest inventory. Active/paused/error graph and monitor-source exclusions passed labelled synthetic tests; no physical-camera pass. |
| USB | Four USBGuard entries inspected; UHCI/EHCI controllers excluded. Virtual mouse/hub remain legitimate blocked devices. Native Polkit prompt appeared after the interactive-authorization flag fix. No password was entered. Successful trust-once/always, real removal/reconnect and external storage remain hardware/authentication gaps. |
| Authorization lifecycle | Fedora tests cover immediate pending publication, duplicate coalescing, attachment removal, late results, distinct once/always readback and provider loss. Real authorization timeout was exercised; final indeterminate handling is covered by source/tests. |
| Threat scan | Real EICAR through StartScan: queued → completed/detection → one critical shell item/notification → quarantine → both clear. Canonical DeleteDetection removed the quarantined test payload. Earlier clean and legacy-boundary EICAR runs were also exercised. |
| Legacy scan integration | Shared durable detection/operation recording and deduplication pass Python tests. Newly changed privileged ScanPath publication was not installed; package-level validation remains open. |
| Network protection | Existing real OpenSnitch allow/block activity inspected; public firewall and encrypted DNS present. Enabled Feodo with unavailable feed produces an explanatory warning. Controlled new firewall block and degradation/recovery remain unverified live; aggregation and transitions tested with local fixtures. No malicious endpoint contacted. |
| Startup change + DND | Created a disabled, harmless autostart fixture: informational backend item and drawer entry appeared, no popup under DND. Fixture removed; DND and animation preference restored. Repeated reads/restart retention and expiry tested. |
| Backend unavailable | Paused session provider for 40 seconds: widget displayed Status unavailable and hid stale actions/activity. Provider resumed and recovered. |
| DMS/backend restart | Current items rehydrated quietly; notification history remained 44 entries across the measured restart. No renewed attention caption. |
| Updates/profile/clipboard | Existing update activity surfaced; unavailable privacy profile does not offer Change. Clipboard deferred in this guest; content handling remains metadata-only. No update application or profile mutation performed. |
| Accessibility/materials | Opaque fallback and constrained flyout inspected live at 100% and 200%; the flyout stayed inside the viewport. The surrounding pre-existing full bar is crowded at 200%. Keyboard/focus contracts and reduced-motion setting are implemented. Full keyboard traversal, intermediate scaling, long-name and camera+critical+USB composition remain visual acceptance gaps. State-sheet examples are simulations. |

## Checks

- Windows Python discovery: 194 tests, 38 environment-dependent skips.
- Fedora affected lifecycle/provider suite: 69 tests, no skips.
- Frontend UX contracts: 78 passed.
- Rust formatting: passed. Cargo backend tests and Clippy blocked before compilation
  by missing Windows MSVC `link.exe`; guest has no Rust toolchain.
- DMS patch dry-run against pinned v1.5.3: passed, including history cards.
- `tests/static.ps1` and `tools/validate-repository.ps1`: passed.
- Full Fedora repository-wide Python discovery was not an acceptance pass: the
  partial overlay lacks repository-relative fixtures, and unrelated installed-state
  assumptions differ. The affected suite above ran against the actual Fedora runtime.

Generated state sheet, screenshots and detailed command logs are local review
artifacts in `tmp/security-redesign/` (not canonical architecture or shipped assets).
No real sensor media was retained; the EICAR and startup fixtures were cleaned up.

## Remaining acceptance

A supported Rust build environment, installation of the rebuilt privileged scanner,
authenticated USB testing with passthrough hardware, camera/storage hardware, and
full accessibility/scaling review are needed before both acceptance gates can be
called complete. Do not treat the simulated state sheet as hardware evidence.
