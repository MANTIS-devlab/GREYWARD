# Security Center remediation — 2026-09-01

## 1. Scope and finding results

This bounded session covered only the Network Activity interaction cluster:
SC-ACT-001, SC-ACT-002, the remaining SC-ACT-003 history cases, and the
remaining SC-NET-003 rule-action case. Network Protection redesign and the
other audit clusters were out of scope.

| Finding | Result | Evidence / limitation |
| --- | --- | --- |
| SC-ACT-001 | FIXED + RUNTIME VERIFIED | Real Tauri WebDriver paused live activity, generated harmless curl traffic, observed the pending count, confirmed frozen rows, resumed without duplicate event IDs, and repeated the cycle. |
| SC-ACT-002 | FIXED + RUNTIME VERIFIED | Real Tauri WebDriver exercised search, decision, protocol, port, live updates, Clear Filters, and Live → History → Live while confirming retention and reset. |
| SC-ACT-003 | FIXED + RUNTIME VERIFIED | Real Tauri WebDriver exercised 6-hour and 24-hour History, populated and empty filtered results, search, Clear Filters, and History → Live. Pagination was available in the run. |
| SC-NET-003 | FIXED + RUNTIME VERIFIED | Real Tauri WebDriver expanded activity rows, saved Always Allow and Always Block through the UI, confirmed feedback, read back each authoritative typed policy, rendered the rule, removed it through the UI, and confirmed clean readback. |

## 2. Root causes

- Live polling replaced the rendered list on every response and counted payload
  rows rather than newly observed event IDs, so pause could not be authoritative.
- Activity controls were independently rendered and synchronized, allowing the
  DOM and filter model to drift across partial updates and mode changes.
- Activity action buttons were dynamically rendered but were not bound by the
  activity content binder, so real Always Allow/Always Block clicks had no
  handler until that focused binding was added.

## 3. Implementation

- Added immutable default filter construction and a model-derived activity
  toolbar with explicit mode state, `aria-pressed`, disabled Clear Filters, and
  live status text.
- Added control synchronization after incremental data updates and gated list
  replacement while paused.
- Changed live updates to merge by `event_id` and count only newly added events;
  Resume clears the pending indicator and renders the authoritative merged set.
- Documented state ownership: switching Live ↔ History deliberately preserves
  the shared search, decision, protocol, port, and range snapshot; Clear Filters
  is the explicit reset path.
- Extended the focused source contract tests and the optional real-window test
  with pause/resume, history ranges, empty filtering, Clear Filters, and mode
  return checks.
- Added a live activity status region, bound dynamically rendered network-rule
  actions, and routed the existing Activity Refresh control through the narrow
  live delta request so paused pending counts can be observed deterministically.

## 4. Runtime interaction validation

- `tools/greyward-dev/run-security-center-interaction.ps1` passed against the
  development Tauri binary using `tauri-driver` 2 and
  `/usr/bin/WebKitWebDriver`; WebDriver port 4444 was forwarded to localhost.
- The run printed `RUNTIME_EVIDENCE pagination=available` and
  `RUNTIME_EVIDENCE network_activity=pass pause_resume=pass filters=pass
  history=pass rule_allow_block_cleanup=pass`.
- Temporary Allow and Block rules were removed through the UI and authoritative
  policy readback was clean at the end of the run.
- VMConnect remains visual-only and was not used as automation evidence. CDP
  was not used or required.

## 5. Tests

- `node --check security-center/tauri/frontend/app.js` — passed.
- `node --test security-center/tauri/frontend/*.test.mjs` — passed with the
  real interaction test skipped when its WebDriver environment is absent.
- `pwsh -NoProfile -File .\tools\greyward-dev\run-security-center-interaction.ps1`
  — 1 real Tauri interaction test passed, 0 failed.
- Final package Rust workspace tests — 25 passed, 0 failed.

## 6. Package validation

The single final package run completed successfully:

- release: `20260831T234819Z`
- `greyward-security-center-0.1.0-45.fc44.x86_64`
- `greyward-security-context-0.1.0-44.fc44.noarch`
- RPM reinstall, packaged checks, launch, and health validation passed.

This is disposable development-VM evidence, not a release-image or hardware
claim.

## 7. Remaining limitations

The bounded Network Activity findings are closed. Induced provider-failure
interaction was outside this session's requested closure trace. No Network
Protection behavior outside the requested rule-action trace was changed.

## 8. Documentation

The remediation index and development documentation now point to the
WebDriver-backed closure path. The earlier VMConnect limitation remains
historical evidence for the prior session; no duplicate historical record was
created.
