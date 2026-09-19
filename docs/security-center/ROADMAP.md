# Roadmap

Roadmap phases describe product outcomes. Only the ten numbered V0 sessions in
`EXECUTION_PLAN.md` count toward V0 progress.

## V0 — truthful local posture and minimal safe control

Outcome: a packaged standalone Security Center that evaluates six domains,
shows evidence/activity/recovery, discloses privacy behavior, and safely performs
only active-network trust-zone and verified portal-permission controls.

V0 consists of exactly 10 Luna sessions:

1. Application foundation and domain contract.
2. Evidence framework and core system posture.
3. Firmware and update readiness.
4. Network posture and reversible trust control.
5. Application isolation and portal permissions.
6. Privacy transparency and security activity.
7. Device and recovery readiness.
8. Complete Security Center UX.
9. Visual, accessibility, and desktop integration.
10. Security hardening and validation evidence.

V0 does not depend on application-aware network control, active USB policy,
Sensitive Files, Travel Mode, richer event correlation, or AI.

## V1 candidates

### Posture monitor and DMS widget

Add an unprivileged user service and small first-party DMS widget exposing only
domain summary, freshness, and app launch. Gate on negligible idle cost, stale
handling, stable D-Bus versioning, and no raw evidence or mutation.

### Richer activity

Add only event sources that improve user decisions without new broad log
privilege, indefinite retention, or SOC-style presentation. This may be rejected
if evidence is noisy or privacy cost is disproportionate.

### Active USB trust

If the USBGuard prototype passes, add reviewed baseline creation, device prompts,
policy status, safe temporary/permanent decisions, and tested recovery. It must
remain separate from V0 observation.

## Application-network protection and Network Protection surface

OpenSnitch v1.8.0 is admitted behind the GREYWARD control plane. The historical
selection list below is retained for audit; the selected result is
`OPENSNITCH SELECTED`. The remaining
milestone is the live Network Protection acceptance gate: bounded activity,
application attribution, distinct firewalld evidence, typed policy saves,
restart/degraded behavior, and real GREYWARD-DEV traffic.

- `PORTMASTER SELECTED`
- `OPENSNITCH SELECTED`
- `DIRECT FIREWALLD/NFTABLES LAYER SELECTED`
- `HYBRID ARCHITECTURE`
- `PROTOTYPE REQUIRED`
- `NEITHER SUITABLE`

Interactive decision prompts remain deferred until their complete lifecycle is
validated. The upstream OpenSnitch GUI is never part of the GREYWARD UI.

## Later differentiated prototypes

### Sensitive Files

Prototype local classification, label storage, privacy, accuracy, application
identity, and realistic enforcement boundaries. Classification without reliable
enforcement must be presented as organization/awareness, not protection.

### High-Risk/Travel Mode

Prototype a declared policy bundle with preflight, conflict detection,
transactional application, verification, expiry, automatic rollback, offline
recovery, and physical-hardware testing. Do not ship a switch that can silently
break VPN, DNS, USB, remote access, login, boot, or recovery.

### Advanced application policy

Blocked until an application-network backend is selected and stable application
identity/rule semantics are proven. It cannot use raw nftables rules submitted
by the UI.

### AI-mediated assistance

Deferred to a local-only explanation/recommendation prototype. AI output cites
the deterministic evidence and cannot change posture, authorize actions, or
execute privileged operations.

## Release discipline

Each post-V0 milestone gets a bounded execution plan only after its prerequisites
pass. It never increments V0 completion. A failed prototype results in explicit
deferral/rejection, not an indefinite partially supported feature.
