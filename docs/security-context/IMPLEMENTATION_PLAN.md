# Security Context implementation plan

## Plan status

TOTAL SESSIONS: 12
IMPLEMENTED TRACKS: 10 (Sessions 1–4, 6–10, and 12; Session 4 physical acceptance deferred; Session 5 superseded)
CURRENT: None
NEXT: Session 11 — Fingerprint/browser privacy (NOT STARTED)

Session 12 is a post-V0 shell-integration track; it does not imply that Session
11 was completed or that every item in the historical Security Center Session
10 validation backlog passed.
All sessions must update this status and return the standard short session report.

Dated session records below are historical implementation evidence. Current
architecture, release-gate, and runtime truth belongs to the linked canonical
documents and the current status report.

## Session 1 — Context foundation

**Status:** PASS  
**Goal:** Provide the single normalized event/state/summary contract, bounded retention/redaction, notification classes, and Security Center read boundary.  
**Dependencies:** Existing Security Center domain/backends.  
**Read before:** `ARCHITECTURE.md`; `../security-center/ARCHITECTURE.md`; `../security-center/DATA_MODEL.md`; `../security-center/PRIVACY.md`.
**Implementation contract:** Add the closed event/live-state/notification contract, deterministic retention, summary generation, and tests. Reserve the user-bus ABI; do not introduce a privileged daemon.  
**Out of scope:** Portmaster, DMS UI, USBGuard mutation, ClamAV, sensor policy, and profiles.  
**Acceptance:** Contract serializes; packet blocks aggregate; events are redacted/bounded; unavailable evidence is honest.  
**Validation:** Domain/backend unit tests and a Fedora user-session D-Bus smoke test when the service packaging lands.  
**Rollback:** Remove only Session 1 crates/files; no running system state changes.  
**Next:** Session 2.

## Session 2 — OpenSnitch admission and backend

**Status:** PASS — 22 August 2026.  
**Goal:** Admit OpenSnitch daemon as the GREYWARD application-network enforcement and telemetry foundation.  
**Dependencies:** Session 1.  
**Read before:** ARCHITECTURE.md; OPENSNITCH.md; upstream v1.8.0 proto/ui.proto; the v1.8.0 daemon UI client and rule handling source.  
**Implementation contract:** Use the bounded upstream gRPC/protobuf server interface on a protected local Unix socket. The GREYWARD control plane receives node state and connection events, returns typed rules/decisions, and sends typed daemon control messages where required. It owns no OpenSnitch UI, database, history replication, or raw nftables. firewalld remains system/inbound owner.  
**Out of scope:** Qt UI shipping or integration, generic privileged proxying, DMS work, Portmaster retesting, raw nftables management, domain matching, arbitrary feeds, Suricata/Zeek, and OpenSnitch daemon changes. Feodo threat snapshot retrieval and the narrow Security Center threat surface are admitted as a bounded GREYWARD-owned extension of this control-plane path.
**PASS checklist:** v1.8.0 protocol has five bounded RPCs; daemon connected directly to a non-Qt gRPC server; Subscribe and Notifications exposed node state; AskRule yielded normalized process/destination events; an always rule persisted through daemon-owned storage; an independent-process deny was enforced; firewalld remained active beside OpenSnitch; no AVC denial was observed.  
**Smallest validation:** Disposable Fedora 44 VM with SELinux enforcing; hash-verified official daemon; direct /run Unix-socket gRPC proof; curl persistent allow; Python one-shot deny; inspect daemon-owned rule and nftable ownership. Earlier Session 2 enforcement/restart/firewalld cleanup evidence remains valid and was not repeated.  
**Failure behavior:** Previous prototype proved daemon restart and stop/start preserve firewalld and recover normal networking without stale interception state. In this spike a no-server/deny policy failed closed only while connected by documented daemon behavior; restarting with the control plane restored normal application traffic.  
**Rollback:** Restore the disposable VM checkpoint and remove it; no package, service, rule, socket, or firewall state remains in the canonical image.  
**Next:** Session 3 — Secure DMS context, NOT STARTED.  
**Completion report template:** SESSION OBJECTIVE; RESULT; OPENSNITCH; CONTROL PLANE; PROTOCOL; PROVEN; GREYWARD CODE REQUIRED; HUMAN PRIORITY CHECK; IMPORTANT ISSUE; NEXT.

**Actual result:** PASS. Phase 1, OpenSnitch admission and exact v1.8.0 protocol proof, completed in the disposable spike. Phase 2, production integration, is now complete: the greyward-security-context RPM installs the root-only gRPC control plane, OpenSnitch daemon drop-in, redacted bounded summary handoff, Security Center backend reader, and Security Context session-bus service. Fedora validation proved curl allow, typed Python deny, a single normalized APP_CONNECTION_BLOCKED event over GetSummary, root-only socket permissions, service restart, firewalld coexistence, and no Qt UI dependency.
## Session 3 — Secure DMS context

**Status:** PASS — 22 August 2026.  
**Goal:** Add the Secure indicator, compact popout, and important notifications.  
**Dependencies:** Sessions 1–2.  
**Read before:** `ARCHITECTURE.md`; `../../environment/session/dankmaterialshell/plugins/greywardPublicIp/PublicIpWidget.qml`; installed DMS `PluginComponent.qml`.
**Implementation contract (superseded by Session 12):** the production
`greywardSecure` plugin now consumes only
`systems.mantis.greyward.SecurityContext1.GetShellSummary` and its typed shell
actions. The legacy `GetSummary` consumer remains supported for older clients,
but is no longer the production DMS integration. ACTION_REQUIRED events remain
deduplicated by event ID for five minutes and sent through the DMS notification
daemon.
**Out of scope:** policy interpretation; DMS control paths; new public-IP or sensor collection; Security Center redesign; Session 4.  
**PASS checklist:** enabled first-party DMS Secure pill and popout; protected/attention/stale/unavailable mappings; public-IP/mic/camera live-state rendering; user-bus-only input; notification dedupe; Security Center click-through; no DMS QML load error.  
**Historical validation:** GREYWARD-DEV loaded the earlier plugin and user-bus
fallback; current runtime validation is recorded under Session 12.
**Rollback:** remove `greywardSecure` from the DMS settings/deployment and restart `greyward-dms.service`; no security policy or firewall state is changed.  
**Next:** Session 4 — Active USB protection, NOT STARTED.  
**Completion report template:** SESSION OBJECTIVE; RESULT; DMS SUMMARY INPUT; NOTIFICATIONS; HUMAN PRIORITY CHECK; IMPORTANT ISSUE; NEXT.
## Session 4 — Active USB protection

**Status:** IMPLEMENTATION COMPLETE / PHYSICAL ACCEPTANCE DEFERRED — 22 August 2026. **Goal:** USBGuard allow-once, narrow trust, revoke, and state. **Dependencies:** Session 1. **Read before:** USBGuard D-Bus docs and recovery notes. **Implementation:** the Security Context user-bus service now exposes normalized device state plus typed temporary allow, narrowly-scoped persistent allow, keep-blocked, and exact-rule revoke calls. It delegates directly to Fedora 44 USBGuard D-Bus/Polkit (`org.usbguard1`, `Devices1`, `Policy1`); persistent trust is refused unless the device rule has a specific VID:PID and serial, hash, or port discriminator. **Out of scope:** custom authorization engine. **Validation:** syntax passed; Fedora 44 USBGuard and usbguard-dbus were installed in a disposable checkpoint; the documented versioned D-Bus endpoints and methods were verified; unprivileged access was denied by Polkit as expected. **Remaining acceptance:** physical unknown-device hotplug; approved Polkit action; allow-once/persistent/block/revoke behavior; keyboard/mouse/dock recovery; Security Center action UI; clean rollback. This is a release blocker, not a development blocker. **Next:** Session 5.

## Session 5 — Removable-media scanning

**Status:** HISTORICAL PROTOTYPE / SUPERSEDED by `docs/security-center/FILE_SECURITY.md`. The earlier `ScanHighRiskPath` contract covered only caller-owned removable-media or Downloads paths through `clamdscan`. The current File Security contract uses the same existing Security Context boundary but adds explicit file, folder, and authorized local-system operation states, durable detection/action records, safe quarantine/remediation, and separate incomplete/unavailable results. The old removable-media validation remains useful evidence; it is not the current product scope. **Deferred hardware acceptance:** physical removable-media hotplug/pass-through remains environment-dependent. **Out of scope:** on-access scanning, boot recovery, and complete OS restore. **Next:** retain runtime acceptance in GREYWARD-DEV for the current contract.
## Session 6 — Sensor privacy context

**Status:** PASS — 22 August 2026. **Goal:** PipeWire/WirePlumber mic/camera observation and attribution. **Dependencies:** Session 1. **Implementation:** metadata-only `pw-dump` adapter observes only linked `Stream/Input/Audio` and `Stream/Input/Video` nodes. Client application names are emitted only when reliable; portal, PipeWire, WirePlumber, and missing attribution become `An application` / `AMBIGUOUS`. It collects no media content or raw stream records. Active/inactive transitions become bounded `MICROPHONE_*` / `CAMERA_*` events and DMS-visible live states; Security Center reads the same redacted user-session summary. No Block action is exposed: no demonstrated upstream revoke semantics. **Validation:** Fedora 44 PipeWire 1.6.8 and WirePlumber 0.5.14 supported interface inspection; canonical RPM includes `pipewire-utils`; fixture tests cover reliable native, ambiguous portal, and unlinked inactivity; user-bus summary and runtime handoff validated; PipeWire/WirePlumber restart passed; DMS consumes the existing user-bus sensor live states. **Deferred hardware evidence:** GREYWARD-DEV has no physical microphone/camera, so real hardware start/stop and native/portal hardware attribution remain physical acceptance work. **Next:** Session 7 — NOT STARTED.

## Session 7 — Summaries and persistence alerts

**Status:** PASS — 22 August 2026. **Goal:** Deterministic weekly aggregation and scoped user persistence changes. **Dependencies:** Session 1.

**Implementation:** Added a bounded persistence monitor for only XDG autostart, user systemd service/timer units, shell startup files, browser native-messaging manifests, and user background-agent environment files. It stores a redacted content fingerprint baseline in the user state directory and emits deterministic addition, removal, and content-change events without reading broad filesystem state or exposing file contents/absolute paths. Added deterministic weekly aggregation over normalized Security Context events with a seven-day window, event-ID deduplication, bounded output, and honest malware evidence wording. Added `GetWeeklySummary` to the existing user session-bus Security Context service; persistence changes enter the existing normalized event stream as `PERSISTENCE_CHANGE_DETECTED`.

**Validation:** Synthetic fixtures cover deterministic summaries, seven-day filtering, duplicate suppression, clean/threat/unavailable scan wording, persistence baseline, monitor-instance restart, addition/removal/change cases, bounded approved-surface snapshots, and redaction. Existing ClamAV and sensor fixtures plus Python syntax validation pass. No broad filesystem monitoring, process surveillance, or Session 8 work was added.

**Known issue / plan deviation:** The existing OpenSnitch producer does not currently provide a distinct SSH-specific inbound event, so summaries use only the normalized `INBOUND_ATTACK_ACTIVITY` evidence that is present and do not invent an SSH count. Physical/runtime acceptance remains environment-dependent as documented by prior sessions.

**Next:** Session 8 — Privacy profiles and identity, NOT STARTED.

## Session 8 — Privacy profiles and identity

**Status:** PASS — 22 August 2026. **Goal:** Standard, Private, and Travel profiles through native NetworkManager and firewalld interfaces. **Dependencies:** Session 2.

**Implementation:** Added transactional `PrivacyProfile` control over NetworkManager MAC policy and firewalld zone state. Standard uses a stable per-network identity and Public zone; Private uses stable per-network identity and Drop zone; Travel uses NetworkManager random-on-reconnect and Drop zone. Travel changes only the reconnect policy and never continuously rotates an active connection. Every mutation captures the prior observed state, applies native settings, verifies both resulting policies, and rolls back plus re-verifies on failure. Added actual-state inference and a normalized optional `privacy_profile` field to Security Context, plus Security Center profile controls and actual identity/firewall/VPN expectation rows.

**Validation:** Transaction fixtures cover Standard → Private → Travel transitions and injected rollback failure. Rust formatting and JavaScript syntax checks pass. The focused Rust test command was attempted but could not link on this Windows host because `link.exe` is unavailable. Fedora/GREYWARD-DEV runtime validation of NetworkManager, firewalld, reconnect MAC behavior, VPN/public-IP, and reboot persistence remains environment-dependent acceptance work.

**Known issue / plan deviation:** VPN/public-IP is reported as an honest local expectation because this profile transaction does not collect or mutate public-IP state. No fake VPN or resolver control was added.

**Next:** Session 9 — Safe Open, PASS.

## Session 9 — Safe Open

**Status:** PASS — 22 August 2026. **Goal:** disposable restricted opening for untrusted files. **Dependencies:** Session 1. **Implementation:** Added a fail-closed Safe Open user-bus method backed by bubblewrap. It binds only the explicitly selected regular file read-only at /run/greyward-open/input, uses private namespaces and explicit network unsharing, denies home/credential access, and emits normalized SAFE_OPEN_RESULT launch/refusal/cleanup events. Security Center exposes the typed Safe Open action with explicit failure feedback; it never falls back to normal open. **Canonical installation:** GREYWARD-DEV now runs greyward-security-context-0.1.0-17.fc44.noarch and the Session 9 GREYWARD Safe Open binary; only the required user Security Context service was restarted. **Runtime acceptance:** SafeOpen is owned and introspected on the user bus; a permitted Downloads launch returned LAUNCHED; /etc/passwd remained denied; GetSummary contained SAFE_OPEN_RESULT; SELinux remained Enforcing. **UX completion:** Added the Security Center “Safe Open file…” action and native top-level Nautilus “Open with Safe Open” context-menu extension (the legacy Scripts entry was removed); both call the canonical user-bus SafeOpen method, with explicit refusal notifications and no UI sandbox duplication. The Nautilus fixture launch passed. Installed standard text/PDF/image handlers and configured MIME defaults; Safe Open launches text, PDF, and PNG fixtures through the live method. The restricted context now carries only the user MIME map and active Wayland socket required for the selected GUI application to display; no normal-open fallback was added. Safe Open now resolves the configured desktop entry and launches that application directly inside the namespace, preserving the bound file for its lifetime. Safe Open forces the supported dark-theme environment and presents the bound document as “Safe Open - <filename>” so readers expose a clear mode cue in their document/title label. A universal attached shield badge is deferred because the current Labwc/Wayland stack does not expose reliable toplevel coordinates or decoration attachment; no compositor hack or per-application titlebar patch is used in Session 9. **Next:** Session 10 — Provenance and sanitized sharing, NOT STARTED.

## Session 10 — Provenance and sanitized sharing

**Status:** PASS — 22 August 2026. **Goal:** bounded provenance context and metadata-sanitized sharing copies. **Dependencies:** Sessions 5 and 9. **Implementation:** Added a bounded provenance module and Session 10 user-bus extension over the existing Security Context service. Provenance reports only known location context, file-specific normalized scan/Safe Open events, detached signature results when a verifier is available, and explicit UNKNOWN/UNAVAILABLE states; it never presents provenance as proof of safety and never exposes absolute paths in the result. Added typed GetProvenance and SanitizeCopy methods. Sanitization creates a separate output, preserves the original, supports metadata-free text copies, rewrites supported images without source metadata when Pillow is available, uses exiftool for PDFs only when present, and refuses unsupported/incomplete types honestly. Security Center exposes Review provenance and Create sanitized copy actions using the typed API; no DMS provenance database or policy engine was added. **UX completion:** Nautilus now exposes a direct top-level Security Context action that launches the GREYWARD-owned contextual window with the selected file passed through the existing launcher. The window reads live GetProvenance data and delegates Safe Open, Scan Again, and Create Sanitized Copy to canonical Security Context methods. Canonical GREYWARD-DEV runs greyward-security-context-0.1.0-19.fc44.noarch with the user-bus service active. **Validation:** deterministic known/unknown provenance, valid/invalid signature, clean/threat/unavailable scan context, redaction, separate text copy/original unchanged, live unsupported refusal, normalized SANITIZATION_RESULT event, D-Bus introspection, SELinux Enforcing, Python/JavaScript syntax, and Rust formatting passed. Windows Rust compile remains unavailable because link.exe is not installed. **Next:** Session 11 — Fingerprint/browser privacy, NOT STARTED.

## Session 11 — Fingerprint/browser privacy

**Status:** NOT STARTED. **Goal:** remove/normalize/safely randomize only through owning interfaces. **Dependencies:** Session 8. **Implementation contract:** no inconsistent synthetic identities. **Acceptance/validation:** per-control regressions. **Next:** Complete.

## Session 12 — DMS Secure shell evolution

**Status:** IMPLEMENTED — 24 August 2026.
**Goal:** Make DMS Secure a quiet, contextual GREYWARD shell surface without
duplicating Security Center or reading providers directly.
**Implementation:** Added the additive `GetShellSummary` contract
(`greyward.security.shell/v1`) with canonical posture/freshness, one prioritized
event, bounded sensor/network/malware/USB signals, privacy profile state, and
update transaction phases. Added typed `SetPrivacyProfile` through the
Security Context user bus. The Rust profile helper reuses the existing
transactional NetworkManager/firewalld implementation and is packaged with
Security Center; the Tauri action now uses the same user-bus authority.
**DMS behavior:** The taskbar keeps the posture shield and adds at most one
contextual badge. The flyout uses a single hierarchy with a curated snapshot,
explicit unavailable states, readable native DMS buttons, privacy-profile
confirmation, and Security Center launch. Active update badges are restricted
to real active transaction phases; terminal records and restart markers are
not labelled as updating.
**Packaging:** Production Packer/provisioning now copies the checked-in
`greywardSecure` plugin to `/etc/skel` and the target user. Development
deployment and production assets share the same QML/metadata source.
**Validation:** Python Security Context tests pass; the Linux GREYWARD-DEV
Rust workspace build and 15 backend/domain tests pass; the live user bus
exposes `GetShellSummary`. Physical sensor/profile mutation and visual
acceptance remain runtime gates.

## Completion report

SESSION:  
RESULT: PASS / PARTIAL / FAIL  
WHAT THIS SESSION WAS SUPPOSED TO DELIVER:  
- ...  
WHAT ACTUALLY CHANGED:  
- ...  
PRIORITY THINGS FOR USER TO VERIFY:  
1. ...  
KNOWN ISSUE / PLAN DEVIATION:  
- ...  
SESSIONS REMAINING: X  
NEXT: Session X — ...










