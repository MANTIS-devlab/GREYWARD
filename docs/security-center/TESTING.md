# Testing strategy

## Principles

Test claims, not just code paths. A backend “working” means evidence is correct,
failures are honest, privilege is bounded, the UI communicates limitations, and
rollback works. Fixtures supplement but do not replace runtime/physical tests.

## Test layers

### Domain tests

- Exhaustive semantic state/requiredness/applicability aggregation.
- Determinism: shuffled evidence/order produces identical results.
- Fresh/stale/boot-changed/time-skew behavior.
- Snapshot v1 round-trip, limits, migration aliases, unknown version/enum.
- Remediation availability independent from posture state.
- Property tests proving `PROTECTED` cannot coexist with unresolved required
  evidence.

### Adapter contract tests

For every adapter: available, absent, unsupported, denied, failed, timeout,
cancelled, malformed, oversized, owner restart, version mismatch, stale and
partial evidence. Assert no localized command-output parsing and no silent
fallback.

### Security/fuzz tests

- Fuzz serialized snapshots, D-Bus variant normalization, event fields, device
  rules, app IDs, SSIDs, endpoints, and action inputs.
- Markup/control-character/invalid-UTF-8 and extreme-length rendering.
- Cache/config owner/mode/symlink/hard-link/non-regular/atomic-write attacks.
- D-Bus service disappearance/owner replacement and stale object identity.
- Polkit cancel/deny/no-agent/replay/unrelated action/concurrent state change.
- Prove no generic executor, root UI, caller-supplied privileged path, or
  background authorization prompt.

### Backend scenarios

| Area | Required cases |
|---|---|
| SELinux | enforcing, permissive, disabled, runtime/config mismatch, denied |
| Boot/kernel | UEFI Secure Boot on/off, legacy, variables inaccessible, lockdown/taint supported/absent |
| Storage | plain/LUKS1/LUKS2, Btrfs, LVM, root/home/swap combinations, removable/live, malformed graph |
| TPM | TPM 2.0 usable, disabled/unowned/error, VM/no TPM |
| fwupd/HSI | supported device, no device, stale metadata, individual attr pass/fail/not-applicable, daemon/version failure |
| DNF5 | daemon absent, cached current/stale/empty, advisory match, offline, denied, malformed/version mismatch |
| Network | wired/Wi-Fi/open/WPA2/WPA3 where available, IPv4/IPv6, split DNS, DNSSEC/DoT modes, VPN/no VPN, captive/offline |
| firewalld control | cancel, deny, success, mismatch, restart, connection replacement, undo, expiry, unrelated-state preservation |
| Flatpak/portal | Flatpak absent, user/system apps, overrides, portal absent/multiple, known/unknown tables, revoke/restore/race |
| Network Activity | allowed/blocked/unknown, missing attribution, cursor delta/reset, bounded flood, duplicate, source restart, privacy redaction, no remote enrichment |
| USB | USBGuard absent/present, safe device types, malformed rule, hotplug read-only, serial/hash redaction |
| Recovery | encrypted/plain, recovery metadata available/unknown, firmware supported/unsupported, no secret access |

### Product-clarity workflow gate

- Verify every product action uses a target-specific working, success, and
  failure state and never renders raw Restic, provider, D-Bus, or helper error
  text as primary feedback.
- In File Security, verify a current/clean scan, detection, quarantine,
  restore-to-review, permanent deletion, Safe Open, and sanitized-copy result
  survive a route refresh. Confirm the restored review path is shown and the
  original remains unchanged where promised.
- In Recovery V1, verify an unconfigured destination, unavailable destination,
  incorrect passphrase, busy repository, successful backup, retention retry,
  explicit verification, empty restore list, selection limit, and staged
  restore. The UI must show the durable helper operation state rather than a
  frontend-invented result.
- In Application Access, compare each displayed access category and review
  count against Flatpak manifest permissions plus local overrides. Verify raw
  grants only appear in the technical disclosure.
- In Technical Details, verify the first-level content is title, result,
  recorded outcome, and recommendation. Check IDs, reason codes, and timestamps
  must be hidden until the technical record is opened.
- Exercise English and French desktop locales. Assert semantic catalog parity,
  no literal-markup replacement, translated action feedback, and translated DMS
  widget copy.
- Assert that Overview and Technical details render backend-owned semantic
  presentation keys, interpolation values, and remediation routes directly;
  there must be no frontend check-ID routing or copy table.

### Privacy/network tests

- Capture process/network activity on cold launch, navigation, refresh, idle,
  resume, action flows, and shutdown.
- Assert no Security Center external request during ordinary collection.
- Verify Privacy-page viewing does not invoke public-IP providers.
- Compare repository endpoints/manifest and fail on undisclosed drift.
- Verify the Network Identity pill renders distinct globe and LAN icon values,
  never substitutes the local address for a failed or pending public lookup,
  and does not restore a public address from persistent state.
- Turn `Public IP check` off, restart DMS, and change networks; verify the switch
  remains off and neither provider is contacted. Verify only a manual switch-on
  resumes a fresh lookup.
- Inspect logs/cache/default export for IPs, SSIDs, paths, serials, command lines,
  journal payloads, tokens, keys, and recovery material.
- Confirm clear-state affects only Security Center user data.

### Network Protection / Network Activity runtime gate

- Run OpenSnitch and firewalld together on GREYWARD-DEV; keep their evidence
  and ownership visibly separate.
- Generate real traffic from multiple applications (at minimum curl, a
  script runtime, and a graphical browser or equivalent desktop application).
- Verify application attribution, domain/IP/port/protocol, allowed/blocked/
  unknown result, matched rule, bounded aggregation, cursor updates, pause/
  resume, filters, expanded details, state refresh, and navigation performance
  from the live Security Center surface.
- Confirm the default row hierarchy is application → destination → decision;
  protocol, port, and time remain secondary and `type` is not duplicated when
  it conveys the same information as protocol.
- Confirm opening or polling Network Activity creates no remote favicon,
  domain, DNS, reputation, or server-location request; when one or more local
  country sources are installed, country flags come from the observed public IP
  through the local resolver. A deterministic country remains rendered even
  when sources disagree, with a low-confidence accessibility/hover detail;
  only when no local source answers is the neutral world marker rendered. A
  valid ccTLD may render a compact last-resort hint only when no IP source
  answers; it must not override an IP result or be presented as endpoint proof.
  Reverse DNS, provider hints, and private IPs must never produce a location
  result.
- Verify rule rendering, typed application and application-plus-destination
  saves, GREYWARD-owned removal, and honest failure when the policy boundary
  is unavailable. Never call a save confirmed until the backend reports it.
- Stop/restart OpenSnitch and the control plane; verify operating, degraded,
  and unavailable states without turning firewalld evidence into OpenSnitch
  evidence.
- Interactive prompts remain disabled unless the runtime proves request,
  user decision, authoritative daemon action, confirmation, timeout, and
  default behavior end to end. Fixtures alone cannot satisfy this gate.

### Telemetry enrichment gate

- Verify `GetSecurityCenterDigest` and `GetShellSummary` agree on shared
  finding and device counters while remaining bounded projections.
- Verify HMAC device identities, low-confidence fallback, internal-device
  exclusion, stable reconnect deduplication, and disconnected seven-day
  history.
- Verify repeated blocked network events remain noteworthy unless an explicit
  deterministic escalation signal exists.
- Verify Live/History mode preserves filters, scroll, focus, expanded rows, and
  stable ordering without full-page replacement. History search and port input
  should debounce local queries, and an older response must never replace a
  newer filter result.

### UI and accessibility tests

- All semantic/domain combinations and priority ordering.
- Loading, cancellation, stale, offline, empty, unavailable, denied, malformed,
  version mismatch, partial and retry states.
- Both controls through preview/auth/success/failure/undo.
- Keyboard-only navigation, focus visibility/order, accessible names, live
  announcements, screen reader, high contrast, reduced motion, text scaling.
- Narrow/large windows, supported scale factors, long/translated strings, RTL
  readiness, light/dark themes.
- Copy/export redaction and safe markup.

### Packaging/integration tests

- Clean reproducible build with locked dependencies and SBOM/license inventory.
- RPM file ownership, permissions, dependency closure, signature candidate.
- Clean install, update, uninstall, optional user-state purge.
- Desktop entry validation, DMS discovery/launch, icon, app ID/window matching.
- Assert no service enablement, Polkit/helper, DMS patch/config, shell placeholder,
  auth/boot/security configuration, or unexpected network installer.

### Performance and reliability

Record cold/warm startup, initial/local refresh duration, idle/load CPU and RSS,
wakeups, snapshot size, bounded activity query, 1,000+ synthetic activity
events, hidden-window polling/wakeup counts, Security Context provider-call counts, batched root telemetry imports, and repeated refresh/action lifecycle. Test backend hangs, cancellation, rapid signals, suspend/resume,
network reconnect, rapid navigation with in-flight route reads, service restarts,
reboot, and low disk space. Repeated reads of the same logical route should be
deduplicated while the first request is pending.

Thresholds must be established from V0 measurements on the target VM and
representative hardware, then recorded in acceptance evidence. A test may not
hide poor behavior by increasing timeouts without justification.

## Runtime environments

1. Unit/fixture environment with no privileges.
2. Canonical GREYWARD Fedora 44 Hyper-V VM.
3. Disposable fault-injection VM/checkpoint for service/version/malformed cases.
4. Physical matrix for TPM, Secure Boot, LUKS, fwupd/HSI, Wi-Fi/VPN, and USB.

VM evidence cannot pass hardware-only acceptance. Missing hardware is recorded
as a validation blocker/condition, not guessed.

## Traceability

Each acceptance criterion has a stable ID in `ACCEPTANCE.md`. The historical
Session 10 exercise produces a matrix: criterion ID, test/evidence artifact,
environment, result, date, and known residual risk. Failures are not converted
to accepted behavior by changing the criterion during validation.

## Historical Session 10 execution contract

The executable gate is `security-center/tests/session10-gate.sh`. Run it from
Fedora or GREYWARD-DEV:

```bash
bash security-center/tests/session10-gate.sh --report /path/to/session-10-run.md
```

It runs the fast Rust, Python, and frontend checks where the required toolchain
exists, then requires explicit command hooks for real Tauri, RPM lifecycle,
Network Activity, File Security, Recovery/Restic, telemetry/privacy, UX,
no-remote-request, and dependency-artifact evidence. Missing hooks are
`BLOCKED`; they are never treated as a pass. The small real-window suite is
`security-center/tauri/frontend/interaction.test.mjs`. Run the canonical
Fedora WebDriver harness with
`tools/greyward-dev/run-security-center-interaction.ps1`; it uses
`tauri-driver` plus `/usr/bin/WebKitWebDriver` and does not require CDP or
VMConnect input.

That historical run may be marked PASS only when its matrix has traceable
evidence for every applicable acceptance criterion. Its dated result is in
`SESSION_10_REPORT.md`; it is not the current project-wide status.
