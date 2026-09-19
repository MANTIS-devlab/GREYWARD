# Decision log

## Accepted decisions

### SC-001 — Standalone product

**Decision:** Security Center is a standalone GREYWARD application. DMS owns
generic desktop functionality and discovers the app through a desktop entry.

**Reason:** Security posture, evidence, privacy, and remediation form a distinct
security boundary and product experience.

### SC-002 — Rust and Tauri 2

**Decision:** Use Rust for the domain, adapters, and Tauri 2 application facade; keep the webview presentation-only.

**Reason:** Memory/type safety is valuable for untrusted evidence and D-Bus data;
Tauri 2 enables the required GREYWARD composition while retaining Rust safety and the existing desktop identity. The new build stack
is acceptable for a standalone product.

### SC-003 — Semantic posture, no score

**Decision:** Use only the six states in `POSTURE_MODEL.md` and deterministic
aggregation. No numeric score, grade, percentage, or hidden model.

**Reason:** Numeric summaries imply unsupported precision and can hide missing
evidence.

### SC-004 — No V0 GREYWARD root helper

**Decision:** V0 uses unprivileged inspection and stable upstream D-Bus/Polkit
mechanisms. A GREYWARD helper is gated post-V0.

**Reason:** Wrapping mature privileged services would add attack surface without
adding authority separation.

### SC-005 — Two V0 control families

**Decision:** V0 controls only active-network trust zone and verified portal
permissions, with confirmation, verification, and bounded undo.

**Reason:** These are mature, scoped APIs with practical reversibility. Firmware,
updates, encryption, TPM, USB, and application firewall changes require stronger
testing or belong to other workflows.

### SC-006 — Network Identity enabled with persistent public-lookup control

**Decision:** Retain the current enabled default, disclose both providers,
cadence, transmitted metadata, memory-only retention/fallback behavior, and the
persistent pill-switch disable path. Show the locally resolved address beside
the public result without sending it to a provider. Load a saved off state
before any automatic request and resume only through a manual switch-on.

**Reason:** The at-a-glance identity is an explicit product choice, while the
control removes mandatory third-party disclosure and stale-cache ambiguity.
Transparency is mandatory and Security Center must not trigger its own lookup.

### SC-007 — OpenSnitch is the GREYWARD application-network backend

**Decision:** OpenSnitch v1.8.0 is admitted behind the GREYWARD-owned root
control plane and redacted user-bus network contract. Direct
firewalld/NetworkManager remains the system/inbound network owner. The
upstream OpenSnitch GUI is not shipped.

**Reason:** The pinned daemon/protobuf boundary passed Fedora/SELinux,
firewalld coexistence, restart, attribution, allow/deny, and rule persistence
validation. The server-oriented prompt lifecycle is still deferred until a
real GREYWARD-DEV end-to-end decision test passes.

### SC-008 — Ten V0 sessions

**Decision:** V0 is exactly the ten substantial sessions in
`EXECUTION_PLAN.md`. Post-V0 work is tracked as milestones, not additional V0
sessions.

**Reason:** The earlier 23-session proposal fragmented naturally related work and
made progress harder to understand.

### SC-009 — Bounded state, no V0 event database

**Decision:** Persist one redacted snapshot and preferences; query bounded events
without duplicating journal/audit history.

**Reason:** Minimizes privacy and integrity risk while supporting useful startup
context.

## Plan deviations

### PD-001 — Historical shell placeholder

**PLAN DEVIATION:**

**HISTORICAL IDEA:** The legacy GREYWARD shell and old roadmap reserved an inert
Security Center panel placeholder.

**EVIDENCE:** Canonical runtime now uses DMS v1.5.3. The legacy QML file remains
only in rollback-era source and is not an active current surface.

**BETTER DIRECTION:** Install a standalone desktop application discovered by DMS;
consider only a small first-party summary widget after V0.

**IMPACT:** No placeholder creation/removal work and no DMS fork in V0.

### PD-002 — Generic GREYWARD privileged layer

**PLAN DEVIATION:**

**HISTORICAL IDEA:** Route all security operations through a GREYWARD privileged
service.

**EVIDENCE:** firewalld, NetworkManager, fwupd, DNF5, portals, and USBGuard expose
typed APIs and existing authorization boundaries. V0 needs only two mutations.

**BETTER DIRECTION:** Call upstream APIs directly; add a GREYWARD helper only for
a later proven operation that lacks a safe upstream interface.

**IMPACT:** Smaller V0 privilege surface and no custom Polkit policy in V0.

## Decision procedure

New decisions or deviations append an ID, date/evidence, direction, impact, and
affected acceptance criteria. Session reports never rewrite historical entries.
