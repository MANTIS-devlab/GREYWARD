# GREYWARD Security Center planning system

Status: Sessions 1–9 describe the original implementation sequence. The former
Session 10 report is retained as a dated validation backlog, not as the current
project release gate. GREYWARD is now in alpha/beta development, with intensive
bare-metal and edge-case testing still required. See
[SESSION_10_REPORT.md](SESSION_10_REPORT.md). The admitted
OpenSnitch application-network backend is surfaced through the bounded Network
Protection surface, including the GREYWARD Feodo Threat Protection view.
OpenSnitch remains the enforcement owner; GREYWARD owns only the fixed-feed
snapshot, policy tiering, activity projection, and notification handoff.
The upstream OpenSnitch GUI is not part of GREYWARD.

This directory is the complete planning authority for the standalone GREYWARD
Security Center. It is the production GREYWARD-specific security/privacy surface
alongside DMS Settings, which owns general desktop/system settings. The former
standalone GREYWARD Settings application has been removed. The documents define a local-first, privacy-first,
evidence-based product that observes and explains the security posture of a
Fedora desktop before it attempts narrowly scoped remediation.

The current performance audit and its measured limits are recorded in
[PERFORMANCE.md](PERFORMANCE.md).

## Reading order

1. [PRODUCT.md](PRODUCT.md) defines the product promise, audience, principles,
   scope, and non-goals.
2. [ACCEPTANCE.md](ACCEPTANCE.md) defines the original V0 validation contract
   independently of what is easy to implement.
3. [THREAT_MODEL.md](THREAT_MODEL.md),
   [PRIVILEGE_MODEL.md](PRIVILEGE_MODEL.md), and [PRIVACY.md](PRIVACY.md) define
   the security boundaries and non-negotiable safeguards.
4. [RESEARCH.md](RESEARCH.md),
   [CAPABILITY_MATRIX.md](CAPABILITY_MATRIX.md), and
   [BACKENDS.md](BACKENDS.md) record dated evidence and prevent the UI from
   promising unsupported capabilities.
5. [ARCHITECTURE.md](ARCHITECTURE.md), [DATA_MODEL.md](DATA_MODEL.md), and
   [POSTURE_MODEL.md](POSTURE_MODEL.md) define components, interfaces, data, and
   deterministic posture semantics.
6. [UX_SPEC.md](UX_SPEC.md) defines the canonical user experience and content
   contract; [DESIGN.md](DESIGN.md) defines durable visual rules; and
   [UX_REMEDIATION_PLAN.md](UX_REMEDIATION_PLAN.md) defines active delivery
   order. Superseded UX and visual material is in `docs/history/`.
7. [ROADMAP.md](ROADMAP.md), [EXECUTION_PLAN.md](EXECUTION_PLAN.md),
   [TESTING.md](TESTING.md), and [LUNA_RUNBOOK.md](LUNA_RUNBOOK.md) define how
   Luna implements and validates the product.
8. [DECISIONS.md](DECISIONS.md) records accepted decisions and deviations;
   [OPEN_QUESTIONS.md](OPEN_QUESTIONS.md) contains only unresolved evidence
   gates.

## Sources of truth

| Subject | Authority |
|---|---|
| Product promise and exclusions | `PRODUCT.md` |
| Security Center validation contract | `ACCEPTANCE.md` |
| Threats and mitigations | `THREAT_MODEL.md` |
| Privileged operations and Polkit | `PRIVILEGE_MODEL.md` |
| Capability maturity and phase | `CAPABILITY_MATRIX.md` |
| Backend contracts | `BACKENDS.md` |
| File Security workflow and operation lifecycle | `FILE_SECURITY.md` |
| Component boundaries | `ARCHITECTURE.md` |
| Serialized/runtime types | `DATA_MODEL.md` |
| Posture states and aggregation | `POSTURE_MODEL.md` |
| Data collection and external services | `PRIVACY.md` |
| GREYWARD normalized telemetry and historical retention | `../telemetry/README.md` |
| Navigation, interaction, and content | `UX_SPEC.md` |
| UX delivery order | `UX_REMEDIATION_PLAN.md` |
| Appearance and visual validation | `DESIGN.md` and `VISUAL_QA.md` |
| Phase outcomes | `ROADMAP.md` |
| Ordered implementation work | `EXECUTION_PLAN.md` |
| Test strategy | `TESTING.md` |
| Operational session protocol | `LUNA_RUNBOOK.md` |

Normative rules are stated once in the authority above. Other documents link to
the authority instead of restating it. Dated versions, runtime observations,
prototype measurements, and implementation status belong in `RESEARCH.md`,
`CAPABILITY_MATRIX.md`, or session reports rather than stable product documents.

## Delivery tracks

- **V0:** exactly ten implementation sessions. V0 observes, explains,
  recommends, and offers only two bounded control families: active-network trust
  zone changes and verified portal-permission revocation/restoration.
- **V1 / post-V0:** separately planned milestones such as the DMS posture widget
  and USBGuard control. The Network Protection surface is implemented in the
  current GREYWARD Security Center and does not rewrite the completed V0
  contract.
- **Prototype:** evidence-gathering work that may end in rejection. Portmaster,
  Sensitive Files, Travel Mode, and advanced policy remain prototype/deferred
  work; OpenSnitch admission is complete but its live Network Protection gate
  remains mandatory.
- **Deferred:** ideas with no safe, generally enforceable implementation yet,
  including autonomous AI security actions.

## Current repository and runtime basis

The plan was grounded on the repository and a reachable GREYWARD development
VM on 2026-08-20. That runtime evidence is dated. As of 2026-08-30, a
reachable internal-alpha Fedora VM is available for diagnosis, but it is
development-contaminated and does not replace clean-install or bare-metal
evidence. Canonical desktop functionality is DMS v1.5.3
on Labwc. The
former QML `SecurityPlaceholder.qml` shell code was removed and is not an
active DMS surface. The plan creates no replacement placeholder.

Runtime evidence and upstream citations are maintained in `RESEARCH.md`. A
development VM is not a production-security reference device: its unencrypted
root, absent usable TPM, and missing optional backends must be reported honestly,
not special-cased into protected results.

## Implementation status

- Planning documents: complete when the validation checks described in this
  directory pass.
- The original V0 implementation sequence is complete enough for continued
  alpha/beta testing. Session 10 is a historical validation backlog, not a
  feature-completion counter or project-wide release gate.
- Session 1: PASS; report recorded in `docs/history/security-center/sessions/SESSION_1_REPORT.md`.
- Historical OpenSnitch admission and Network Protection runtime acceptance are
  recorded as PASS for real GREYWARD-DEV curl/Python traffic, typed policy
  save/remove, and unavailable/degraded recovery. The current live Network
  Protection runtime evidence remains relevant; interactive prompts remain
  deferred.





