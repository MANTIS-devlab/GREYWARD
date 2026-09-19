# Security Center remediation — 2026-08-31

## Scope

- SC-NET-003: Network Activity **Always Allow** and **Always Block** actions.
- SC-ACT-003: Network Activity history loading.
- SC-IPC-001: Security Context D-Bus JSON values containing shell-sensitive filenames.
- SC-DMS-001: DMS deep links to supported Security Center destinations.

## Root causes

- The frontend sent Tauri command fields at the top level, while the Rust commands
  accept `payload` and `filters` objects; the removal command also needs the
  camel-case `ruleId` field.
- The Tauri facade and the unprivileged policy client parsed `gdbus` display text
  as if it were a transport format. Apostrophes and quoting can corrupt that text.
- During real Tauri navigation, the first typed-D-Bus implementation passed the
  fully qualified `interface.member` string as the D-Bus member name. The Rust
  D-Bus client rejects that invalid member and the WebKit IPC callback aborted
  the application.
- The route helper accepted only `updates`, although DMS uses both `devices` and
  `updates`, and the running application consumed only the former route.
- The network-state snapshot did not immediately include rules just saved by the
  authoritative typed policy service.

## Implementation

- Wrapped Tauri invocations in `{ payload }` / `{ filters }` and use `{ ruleId }`
  for rule removal.
- Replaced Security Context JSON `gdbus` output parsing with typed session D-Bus
  calls in the Rust facade and the policy caller. The facade now separates the
  D-Bus member from the qualified application-level method identifier before the
  typed call.
- Added the root-owned `ListRules` D-Bus projection and merge it into the network
  summary so the UI refresh reads the saved policy immediately.
- Whitelisted every current Security Center destination in the route helper and
  consume each in the single running Tauri instance.

## Verification

- `node --test security-center/tauri/frontend/ux-contract.test.mjs`: 43 passed.
- `PYTHONPATH=security-center/security-context python -m unittest discover -s security-center/security-context/tests -p 'test_*.py'`: 80 passed, 15 skipped.
- `cargo fmt --all -- --check` passed in `security-center`.
- Fedora deployment rebuilt the release Security Center crate with `dbus`, ran
  35 Rust tests, rebuilt both RPMs, reinstalled them, and launched the Tauri
  application successfully. The active development Security Context override
  was then refreshed from this source before endpoint testing.
- Runtime session-D-Bus checks passed for provenance requests using filenames
  with a space, apostrophe, double quote, and non-ASCII character; each returned
  the exact filename without an unavailable result.
- Runtime `GetNetworkHistory` returned a JSON projection. Typed Always Allow
  and Always Block rules for `/usr/bin/curl` and isolated `.test` destinations
  were saved, immediately projected with their exact scope and action, then
  removed and verified absent. No fixture rule remains.
- Runtime `devices` and `updates` route requests were consumed by the running
  Security Center and visibly opened their respective pages; the existing
  instance remained single, and an unsupported route exited with status 64.
- Real AT-SPI navigation reached Network Protection, Network Activity, Live,
  and populated History without a crash after the member-name correction.

## Status

| Finding | Status | Evidence / limitation |
| --- | --- | --- |
| SC-NET-003 | PARTIAL (historical status at this record) | Typed endpoint and authoritative projection were verified; the bounded 2026-09-01 follow-up had not yet delivered guest UI input at the time of this record. Current status is maintained in [2026-09-01 Network Activity interaction remediation](2026-09-01-network-activity-interaction.md). |
| SC-ACT-003 | PARTIAL (historical status at this record) | The 2026-09-01 follow-up had added source and optional real-window coverage, but its real click trace was still unavailable at the time of this record. Current status is maintained in [2026-09-01 Network Activity interaction remediation](2026-09-01-network-activity-interaction.md). |
| SC-IPC-001 | FIXED + RUNTIME VERIFIED | Typed Rust and Python D-Bus calls, difficult filename endpoint round trips, and live typed page navigation are verified. |
| SC-DMS-001 | FIXED + RUNTIME VERIFIED | A single running window visibly consumed both Devices and Updates handoffs; invalid routes fail with status 64. |

The Fedora RPM workflow rebuilt the corrected Rust source and ran its Rust test
suite before its final terminal was interrupted. A separately completed
production-mode Cargo release build of the same staged source was installed only
into the disposable development VM for the follow-up live window verification;
this is development-runtime evidence, not a release-image claim.
