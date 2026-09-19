# GREYWARD Security Context architecture

## Status

Current post-V0 contract. Security Context implementation slices 1–4 and
6–10 are complete; slice 5 is a superseded prototype. The additive slice 12
DMS shell integration is implemented, while slice 11 remains not started.
This numbering is local to Security Context and is separate from the historical
Security Center Session 10 validation backlog in
`docs/security-center/SESSION_10_REPORT.md`.
Physical-device acceptance remains environment-dependent. Portmaster remains
rejected in `PORTMASTER.md`.
OpenSnitch v1.8.0 is admitted through the installed
`greyward-security-context` package: a root-only gRPC/protobuf control plane, a
redacted bounded summary handoff, and the Security Context session-bus service.
Secure DNS is admitted as a separate, hardened, per-link system D-Bus
reconciler; see `docs/security/SECURE_DNS_IMPLEMENTATION_PLAN.md`.
GREYWARD Feodo threat blocking is a bounded extension of the same OpenSnitch
control-plane path: GREYWARD fetches and validates the official recommended
feed, while OpenSnitch remains the only application-network enforcement engine.

## Boundary

`greyward-security-domain` owns the versioned normalized contract. `greyward-security-backends` owns adapter translation, notification classification, redaction, freshness, and bounded retention. The unprivileged Security Context user-bus service exposes the redacted `SecurityContextSummary` plus the bounded `SecurityShellSummary`; Security Center renders details and policy, and DMS renders only the indicator, flyout, and classified notifications. DMS consumes `GetShellPresentation` and typed shell actions and never reads OpenSnitch, firewalld, NetworkManager, ClamAV, USBGuard, PipeWire, or update-provider state directly. Neither UI interprets upstream security events.

`SecurityContextSummary` uses `greyward.security.context/v1` and contains posture-derived state, freshness, attention count, live states, and at most 64 recent events for the current summary. Historical normalized events use the separate `greyward.telemetry.event/v1` contract and bounded SQLite store; raw network, USB serial, sensor, or detailed Portmaster history is not duplicated.

## Ownership

- firewalld: inbound baseline, zones, trust, SSH/service exposure, and its nftables state.
- OpenSnitch: application interception, attribution, rules, and only its own nftables state. GREYWARD uses the documented v1.8.0 gRPC/protobuf server contract over a protected local Unix socket; it does not ship Qt/UI/database code.
- GREYWARD: read/present combined state; never write raw nftables or proxy arbitrary privileged requests.
- USBGuard: upstream USB enforcement and rule owner. GREYWARD uses its supported system D-Bus/Polkit interface through the Security Context boundary; it neither writes raw USB authorization nor creates broad trust rules.
- ClamAV, NetworkManager, and systemd: upstream capability/policy owners.
- PipeWire/WirePlumber: upstream media graph owners. GREYWARD reads only linked stream metadata through `pw-dump`; it records sensor type, state, and reliable application label only. It captures no media and offers no revoke action without proven upstream semantics.
- NetworkManager and systemd-resolved: connection, VPN, routing-domain and resolver owners. The GREYWARD Secure DNS reconciler uses only their typed D-Bus APIs, never a global resolver file or a second resolver daemon.
- GREYWARD Secure DNS: the narrow root-owned reconciler owns only its explicit per-link DoT/DNSSEC overrides and measured state. VPN/private split-DNS ownership remains authoritative upstream.
- GREYWARD Feodo integration: the fixed-feed updater owns retrieval, validation, normalized snapshots, threat metadata, and the Security Center projection; it does not own nftables, domain matching, or OpenSnitch daemon changes.

GREYWARD does not ship or depend on the OpenSnitch GUI. A narrow privileged system control-plane service serves the daemon; the unprivileged Security Context user-bus service consumes only normalized/redacted state.

The context package enables both `usbguard.service` and
`usbguard-dbus.service`. Its packaged Polkit rule grants the `wheel` group
read-only access to USBGuard device and rule listings, which is required for
the unprivileged Security Context projection. Device policy changes remain
covered by USBGuard's upstream authentication actions; GREYWARD does not
grant write access through this rule.

## User-bus contract

Reserved name: `systems.mantis.greyward.SecurityContext1`.
Reserved object: `/systems/mantis/greyward/SecurityContext1`.

The service provides `GetSummary`, `GetShellSummary`, a user-initiated
`Refresh`, the narrow `GetNetworkProtection` application-network projection,
and `GetThreatProtection` plus its typed enable/disable operation.
`GetShellSummary` returns `greyward.security.shell/v1`: canonical
posture, freshness, one prioritized event, bounded sensor/network/malware/USB
signals, update transaction phase, current privacy profile, and fixed
capability flags. It never exposes evidence secrets, raw OpenSnitch protobuf,
raw nftables, absolute paths, or generic actions.

The shell supports typed `SetPrivacyProfile`, `RequestUsbTrust(connection_ref,
mode)` and capability-gated clipboard clearing. Profile changes keep the closed
values `STANDARD`, `PRIVATE`, and `TRAVEL` and the existing transactional helper.
USB actions delegate to USBGuard's upstream Polkit authorization and require
state readback. The shared presentation separates posture, live activity and
unresolved operations; see [LIVE_PRIVACY_CAPSULE.md](LIVE_PRIVACY_CAPSULE.md) for
shell presentation and delivery semantics. Network rules, file remediation and
updates remain targeted Security Center workflows.

The DMS `greywardSecure` plugin uses the shell projection through `/usr/bin/gdbus`
and declares the DMS process permission required for those local calls. Its
polling guard prevents overlapping requests; it does not use the optional
`Proc.runCommand` debounce argument as a transport timeout.

The composed live image enables the same user-bus provider on the user
manager's default target as well as the graphical-session target, because the
greetd/Labwc handoff does not guarantee activation of the latter.

Typed application-network policy saves/removals use the
`systems.mantis.greyward.OpenSnitchPolicy1` system-bus boundary, restricted to
the wheel group and validated to application/destination/action/duration
fields. The Tauri frontend only calls the user-bus service. Interactive
connection prompts remain deferred until the complete daemon decision
lifecycle is proven.

The user-bus service also exposes the read-only `QueryTelemetry` and
`GetRelatedTelemetry` methods. They return bounded normalized history through
the Security Context boundary; they do not expose the database or unrestricted
journald. Live OpenSnitch activity continues to use `GetNetworkActivity` and
its separate 30-minute/4,096-event working set. See
[`docs/telemetry/README.md`](../telemetry/README.md) for the retention and
privacy contract.

Purpose-built projections are also available for the product surfaces:
`GetSecurityCenterDigest`, `GetNetworkHistory`, `GetDeviceOverview`, and
`GetCapabilityHistory`. `GetShellSummary` is the compact DMS projection.
`GetSecurityCenterDigest` and `GetShellSummary` share one backend aggregation
path; neither frontend interprets raw history.

Secure DNS is exposed through `GetSecureDnsState`, `SetSecureDnsMode`,
`SetSecureDnsProvider`, and `RetrySecureDns` on this user bus. These methods
forward only closed, typed values to the root-owned
`systems.mantis.greyward.SecureDns1` service. The service keeps desired and
effective policy/owner/transport separate, classifies ordinary DNS inside an
encrypted VPN as `VPNProtected`, and never permits frontend command execution.

## Failure and retention

An unavailable adapter yields `UNKNOWN` or `UNAVAILABLE`, never a protected result. Events are sanitized, bounded, ordered, and aged out deterministically. Immediate/actionable notifications are deduplicated by event ID; packet-level background blocks aggregate into summaries or history.






