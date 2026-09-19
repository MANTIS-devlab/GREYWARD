# Live Privacy Capsule

Status: **IMPLEMENTED FOUNDATION / PARTIAL SIGNAL COVERAGE**.

The Live Privacy Capsule is the compact live-activity surface inside the
existing `greywardSecure` DMS widget. It is not a second taskbar widget and it
does not replace the Security Center history or evidence views.

## Contract and ownership

The existing user Security Context service owns the projection:

```text
systems.mantis.greyward.SecurityContext1
  GetPrivacyCapsule() -> string
  PrivacyCapsuleChanged(uint64 revision)
```

The capsule remains the authoritative sensor projection. The DMS widget now
reads the composed `GetShellPresentation()` (`greyward.security.experience/v1`)
and subscribes to `ShellSummaryChanged(uint64 revision)`. That presentation
combines the capsule with existing posture, device, network and file providers.
The notification router consumes the same items. The widget's 15-second
watchdog is recovery only, deliberately ahead of the projection's 30-second
freshness lease. While its replacement read is in flight it retains the last
confirmed presentation, but disables mutation actions once that lease expires;
no frontend security monitor or notification emitter is installed.

Security Context owns collection, event generations, freshness, aggregation,
and policy interpretation. DMS owns only presentation, accessibility, flyout
navigation, and typed action dispatch.

## Taskbar presentation

The Security Center emblem remains visible in every state. The idle indicator
is 36 × 32 logical pixels; up to two distinct activity icons and an overflow
count may accompany it. A separate exclamation badge indicates unresolved
conditions. Microphone/camera use is live activity, never an unresolved review.
New actionable conditions can expand the caption for ten seconds; initial
rehydration does not animate. Equal-priority items retain stable order.

The viewport-constrained 400-pixel flyout orders status/reason, the highest
priority item, live activity, disclosed protection details and Open Security
Center. Other items stay available through disclosure. Critical > actionable >
warning; privacy indicators remain independent. The canonical small emblem is
`branding/source/greyward-security-status.svg`. Graphite opaque surfaces, silver
edges, 16/14/13/12-pixel type and 34-pixel action targets are shared with the
GREYWARD-only DMS notification patch. DMS's None animation setting removes the
widget's size and color transitions. Deferred capabilities remain hidden.

## Shared lifecycle and actions

`RequestUsbTrust(connection_ref, mode)` accepts only `once` or `always` and
returns an operation acknowledgement. The connection reference binds the
USBGuard bus owner and attachment ID. Both shell surfaces use this method;
USBGuard owns authorization and persistent rules. Interactive authorization is
requested on its existing D-Bus method, off the UI service thread. Readback must
confirm allowed state (and a matching persistent rule for `always`). Trust once
lasts for the current attachment, not for the widget/service process lifetime.
Removal clears the item; an authorized non-controller device becomes quiet presence.

The existing session service owns one collection scheduler, provider signal
subscriptions and a bounded fallback refresh. Notification replacement IDs and
dismissal acknowledgements live in a mode-0600 runtime delivery ledger, separate
from security truth. Dismissal does not resolve a finding. Normal activity is
silent; actionable/warning popups last ten seconds, requested scan results four
seconds, and unresolved critical notifications persist. Recovery updates are
quiet and do not create another history entry. Resolution closes the matching
notification. DMS still owns DND, dismissal and keyboard navigation. Critical
escalation can reopen an acknowledged item. Provider failure preserves the
last confirmed USB/threat presentation as explicitly unconfirmed, without
mutation actions; it cannot establish permission or resolution.

Both scan entry points write the existing File Security operation/detection
store in the privileged scanner; `FileSecurityChanged` invalidates the shell
projection. No volatile legacy threat list or second scan-notification emitter
remains. Authorization timeout is indeterminate until readback confirms the
result or the attachment disappears. USBGuard's generic AccessDenied cannot
distinguish every user cancellation from a denial; the UI does not claim it can.

Startup changes remain bounded observations in the existing persistence
baseline for five minutes, including across session-service restart. They are
informational notices, not invented unresolved threats; repeated reads do not
create new events. The baseline still stores only approved surface identifiers
and hashes, never file contents.

## Signal state contract

Each signal exposes `capability` independently from `state`:

| Capability | State | Meaning |
|---|---|---|
| `SUPPORTED` | `ACTIVE` | Current activity is confirmed. |
| `SUPPORTED` | `INACTIVE` | The source is available and inactive. |
| `SUPPORTED` | `STALE` or `UNAVAILABLE` | The source exists but cannot currently prove live state. |
| `DEFERRED` | `DEFERRED` | No sufficiently reliable or lightweight source is shipped. |

The service never converts stale, unavailable, or deferred evidence into an
inactive assertion.

## Event privacy and retention

Event identities and generations are stable for the lifetime of a logical
transition. Reads do not create new events or replay DMS attention states. A
signal already active when the service starts is initial state, not a new event.

`recent_events` is an in-memory transition buffer only. It is capped at four
entries and expires after 60 seconds. It is never written to telemetry,
SQLite, logs, or persistent state.

Clipboard observation, when enabled, accepts text formats only and limits
classification to approximately 256 KiB. Clipboard contents remain in memory
only and never enter D-Bus payloads, logs, telemetry, or persistent state.

## Current signal coverage

- Microphone, camera, and ScreenCast use one persistent metadata-only PipeWire
  monitor plus Portal owner/session-close lifecycle signals. They report active links into running
  capture streams from source nodes, not permissions. Paused/error links and
  audio sink monitors are excluded; a missing monitor or Portal owner is
  explicitly `UNAVAILABLE`, never inferred from a process name.
- Secure DNS uses the existing effective-policy and degradation semantics.
- USB uses the existing USBGuard state and does not expose raw identifiers.
- ScreenCast is `ACTIVE` only when the Portal owner is present and the
  PipeWire monitor confirms a screen-marked capture stream. This remains a
  bounded activity signal: it exposes neither screen content nor a capture
  target.
- Clipboard classification is implemented as a bounded pure classifier. When
  Wayland and `wl-clipboard` are available, the service uses a minimal
  read-only observer that emits classification metadata only; the user
  service starts after the graphical session and requires `WAYLAND_DISPLAY` so
  early user-manager startup does not create a false deferred state. Otherwise
  the signal remains deferred.
- Application high-network-load remains deferred until real local RX/TX
  accounting attributable to applications is available. OpenSnitch event or
  connection counts are not used as a throughput approximation.
- Safe Unmount is not exposed until UDisks2 or the proper desktop storage
  mechanism is available with target revalidation.

## Privacy boundary

The capsule never collects microphone audio, camera frames, screen content,
clipboard contents, network payloads, DPI data, packet captures, or raw USB
serials. No new privileged daemon, eBPF collector, packet-inspection path, or
clipboard manager is introduced by this feature.

## Validation

Pure contract and classifier tests live in
`security-center/security-context/tests/test_privacy_capsule.py`. The DMS
subscription contract is checked by the existing frontend UX contract tests.
Runtime validation uses the existing DMS iteration, reload, health, and capture
workflow. Hardware-dependent microphone, camera, ScreenCast, USB, and storage
acceptance remain environment-specific and must not be claimed on a VM that
does not provide the required device.

The broader presentation, delivery and action tests are `test_shell_experience.py`,
`test_notification_router.py`, `test_shell_runtime.py`, `test_usbguard_lifecycle.py`
and `test_sensors.py`. Run the runtime-dependent tests on Fedora. Generate the
explicitly simulated design sheet with
`python tools/greyward-dev/security-shell-state-sheet.py`; it does not connect to
providers and is not hardware acceptance evidence.
