# Live Privacy Capsule

Status: **IMPLEMENTED FOUNDATION / PARTIAL SIGNAL COVERAGE**.

## Security and privacy notifications

`security_notices.py` adds observations inside the existing session runtime;
`notification_router.py` remains the only native publisher. Native DMS notification
settings, Do Not Disturb and history still apply. Informational notices do not
change the protection posture or replace continuous microphone/camera indicators.

VPN-interruption notifications are not implemented; existing VPN status
presentation is unchanged.

- Security-update availability requires Update Center's fresh successful
  provider/record evidence and explicit `SECURITY_FIX`, excluding compatibility
  holds and unknown classifications. Metadata older than fifteen minutes,
  provider failure and checking state cannot establish availability. Restart
  notifications require its `READY_TO_RESTART` transaction, explicit `REQUIRED`
  and the current boot ID; merely listing an update that might need a reboot
  does not qualify. Notifications only open Update Center; they never apply an
  update or restart. Metadata checks reuse its asynchronous cache at fifteen
  minute intervals with a bounded initial completion poll, while cheap
  transaction reads observe readiness. Each category reminds at most daily,
  across dismissals, provider flaps and subsequent logins. The local
  `$XDG_STATE_HOME/greyward/notification-reminders.json` stores only two delivery
  timestamps, not package or application inventories.
- Optional microphone/camera start notifications are off by default. Enable
  them in Security Center → Privacy → Privacy notifications. The typed session
  methods `GetNotificationPreferences()` and `SetSensorStartNotifications(bool)`
  read/write only `$XDG_CONFIG_HOME/greyward/security-notifications.json`.
  A confirmed new per-application sensor use produces one short informational
  notification; refreshes, initial rehydration, enabling the preference during
  existing use and observer recovery do not replay it. Stop then start is a
  new use. Unknown attribution remains explicitly unidentified. No media is
  recorded and no device permission is changed.

Tests: `test_security_notices.py`, `test_notification_router.py`,
`test_shell_runtime.py` and the frontend preference readback/rollback contract.
Installed and physical acceptance are recorded separately in `docs/STATUS.md`.

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
The server computes `notification_items` once from the live items and the
continuous-warning rule. It sends that exact list both to the native desktop
notification publisher and in `GetShellPresentation()`; the taskbar cards,
attention caption and badge consume that same list. The taskbar has no separate
warning timer, so its alert lifecycle cannot drift from desktop notifications.
Live posture and activity remain visible immediately. The widget's 5-second
watchdog is recovery only, deliberately ahead of the projection's 30-second
freshness lease. While its replacement read is in flight it retains the last
confirmed presentation, but disables mutation actions once that lease expires;
no frontend security monitor or notification emitter is installed.

The presentation has separate deadlines: `fresh_until` remains the evidence
and action lease; additive `display_fresh_until` permits a confirmed unavailable
observation to explain its warnings for 30 seconds and keeps a confirmed status
visible through the bounded 10-second collection cycle. During that short gap,
the taskbar says it is refreshing and disables actions/attention. This never
renews positive security evidence or enables actions. Deadline-only renewal does
not change the content revision or repeat notifications. Missing detection
source files remain in history but leave active shell alerts. Both GLib D-Bus
entrypoints initialize threading before starting observers.
See the development stability receipt (private development evidence).

Secure DNS, firewall and device-protection warning items carry a
`notification_stability_seconds` presentation hint. The Security Center keeps
their live state visible immediately, while both taskbar alerts and native
desktop notifications use the server's shared list after the same warning has
been continuously observed for 30 seconds. Critical events and unrelated
warnings remain immediate. The in-memory timer restarts after a service
restart, so a recovered notification ledger cannot bypass a fresh stability
check.

Protection review uses the same evaluated check results and accepted-deviation
store as Security Center, exposed additively by the fixed read-only posture
helper. Detailed USB reads and privacy-profile reads are not independent health
evaluators. Unresolved firewall/device checks route to `evidence`, the existing
System checks review workflow. Accepted exceptions remain disclosed in details;
they do not grant device permissions. Scanner readiness comes from the same
`GetFileSecuritySummary().clamav` response that the Files & scans page uses.
Missing shared checks remain unavailable rather than inheriting overall success.

Security Context owns collection, event generations, freshness, aggregation,
and policy interpretation. DMS owns only presentation, accessibility, flyout
navigation, and typed action dispatch.

The protected DMS compositor has its own private session bus and intentionally
cannot subscribe to the ordinary user's Security Context bus. When that private
bus has no `GetShellPresentation()` owner, the taskbar reads
`ApplicationSecurity1.GetSystemPosture()` over the system bus. This fallback
contains only aggregate system posture and bounded counts, never per-user
activity, notification items or actions. A confirmed result remains displayable
through a short read-refresh gap; its evidence lease is not extended. If both
providers are unavailable, the taskbar reports that state consistently and
retries without creating alerts.

## Taskbar presentation

The Security Center emblem remains visible in every state. The idle indicator
is 36 × 32 logical pixels; up to two distinct activity icons and an overflow
count may accompany it. A separate exclamation badge indicates unresolved
conditions. Microphone/camera use is live activity, never an unresolved review.
ClamAV's first definition download (`INITIALIZING`) is preparation activity,
with scanning readiness explicitly unconfirmed. It does not create a generic
Review item or establish a Protected status. Missing services, stale definitions
and unsuccessful protection remain actionable warnings; unknown database age
is never represented as zero.
New actionable conditions can expand the caption for ten seconds; initial
rehydration does not animate. Equal-priority items retain stable order.

The viewport-constrained 400-pixel flyout orders status/reason, the highest
priority item, live activity, disclosed protection details and Open Security
Center. Other items stay available through disclosure. Critical > actionable >
warning; privacy indicators remain independent. The canonical small emblem is
`branding/source/greyward-security-status.svg`, shared with the launcher and
running-app taskbar through the [application identity contract](../../branding/BRANDING.md#security-center-application-identity).
Graphite opaque surfaces, silver
edges, 16/14/13/12-pixel type and 34-pixel action targets are shared with the
GREYWARD-only DMS notification patch. DMS's None animation setting removes the
widget's size and color transitions. Deferred capabilities remain hidden.

### Multiple displays

Each DMS output creates its own `greywardSecure` widget, while DMS's process
service is shared by the whole shell and indexes pending commands by request
ID. Reusing a fixed ID let one output replace another output's completion
callback, leaving some taskbar instances without refreshed status or action
feedback. The widget now scopes every DMS process request to both its output
name and a per-instance token. Each output reads the same Security Context
presentation and keeps its own action feedback; a click dispatches once through
the existing protected path. This changes callback routing only: it adds no
authority, persistent data or security-policy exception. The source regression
check is in `tests/test_application_authentication.py` and `tests/static.ps1`;
the live multi-display check on `<validation-host>` remains pending.

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
silent unless sensor-start notices are explicitly enabled; actionable/warning popups last ten seconds, requested scan results four
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

## DMS 2.0 candidate card presentation

The migration candidate uses the existing single summary owner for taskbar,
Security tab and three dashboard cards. Fresh confirmed protection is green,
review/unknown/stale/loading is amber and explicit critical/failure evidence is
red, accompanied by text and status glyphs. A per-control breakdown does not
extend the evidence lease or certify unrelated providers. Network requires both
firewall and application-filtering evidence for a green card, including the
provider's exact `OPERATING` state. Informational network events do not create a
review requirement. Observed VPN-owned DNS is shown as `VPN active`, with DNS
ownership disclosed; it does not claim full-tunnel routing, encrypted DNS or a
kill switch. Actual warnings/actions/failures still take precedence and stale
evidence cannot stay green. DNS is separately shown. Idle update availability remains unknown until Update Center supplies its
own result; no count or Up to date status is synthesized. The cards introduce
no independent collector, poll or authority. The candidate `StatusModel.js` and generated
state palette are owned in the repository map; native tests and synthetic
renders are separate from physical acceptance. See the
[DMS 2.0 migration](../architecture/DMS_2_0_MIGRATION.md).

The ordinary launcher binds the [Qt QML disk cache](https://doc.qt.io/qt-6/qmldiskcache.html)
to the verified release-receipt digest. This prevents unchanged reproducible RPM
timestamps from reusing pre-update compiled card code at fixed plugin URLs.
Caching remains enabled; prior namespaces are retained. This does not alter the
protected authentication runtime or create a new posture/evidence source.

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

## Network protection, VPN and offline observations

The DMS 2.0 Network card makes filtering status primary. Confirmed firewall and
application filtering produce **Protection active**; explicit disabled/stopped
controls produce **Protection inactive**. Actual warnings and unavailable
filtering evidence retain their severity. VPN is secondary information and its
absence does not create a warning.

The existing Secure DNS observer also observes VPN links. The bounded shell
summary adds `vpn.state` (`ACTIVE`, `OFF`, `UNAVAILABLE`), with no link names.
`OFF` requires a valid schema, successful observation and a generation timestamp
no more than 60 seconds old; expired, missing, contradictory or unavailable data
cannot establish absence. The existing shell evidence lease remains bounded.
Split VPN with separately managed DNS still displays Active. This observation
establishes neither encryption, full-tunnel routing nor a kill switch.
`shell_experience.py` emits a `VPN` detail with explicit machine state; the card
never parses arbitrary/localized text as absence. Older summaries can establish
Active from VPN-owned DNS but cannot establish Off from other DNS modes.

A confirmed network disconnect is distinct from failed collection. The shared
Rust collector checks the local firewall even without an active interface;
only successful NetworkManager absence plus a successful firewalld `RUNNING`
read can satisfy that offline firewall check. The existing root network service
exposes the no-input `OpenSnitchPolicy1.GetFirewallState` method to ordinary
callers, with a fixed two-second provider timeout and only `running`,
`not-running` or `unavailable` replies. It reads the live daemon state; it does
not infer health from systemd, a cache or connectivity. The Rust client has a
three-second call bound and no `firewall-cmd --state` fallback: that property
read triggers firewalld CONFIG authorization for desktop callers. No policy
grant or mutation authorization is broadened. Unknown connection evidence and
failed firewall probes remain uncertain. The global posture algorithm is not
relaxed, and other security failures remain visible. Offline fixtures exercise
the command boundary without disconnecting a physical machine or changing its
network policy. See current status for installed versus future protected builds.

The explicit Fedora packaged-byte regression is run as root with an extracted
Context RPM and posture executable, not by disconnecting a reference desktop:

```bash
PYTHONPATH=/private/context/usr/lib/greyward-security-context \
GREYWARD_OFFLINE_POSTURE=/private/center/usr/libexec/greyward-security-posture \
GREYWARD_OFFLINE_POLICY=/private/context/etc/dbus-1/system.d/systems.mantis.greyward.OpenSnitchPolicy1.conf \
GREYWARD_OFFLINE_TEST_USER=nobody \
python3 -m unittest discover -s tests -p test_offline_firewall_boundary.py -v
```

It uses the packaged bus policy and real read method on a private bus, forwards
only the fixed upstream state read to the real firewall, and runs the ordinary
helper in a network namespace with confirmed no-link input. Four samples are
spaced 12 seconds apart; provider loss must remain uncertain. Any desktop
`firewall-cmd` call fails the check. Optional `GREYWARD_OFFLINE_PREDECESSOR`
points to the prior packaged helper for a negative control. No installed
service, host link or policy is changed. This isolated check does not establish
fresh-install or physical desktop acceptance.

VPN freshness is evaluated at completion of the existing provider collection.
The posture summary retains its original sampling time and evidence lease;
a later DNS GetState refresh must neither appear to be a future observation
nor renew older posture evidence. The real GetShellSummary caller regression
and pure projection fixture cover this ordering. Current installed evidence is
recorded in STATUS; physical offline acceptance remains separate from canaries.
