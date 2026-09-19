# GREYWARD documentation index

This is the starting point for contributors and repository automation. Read the current
status first, then the repository map before editing a subsystem.

## Mandatory before ISO creation

Read the [ISO rebuild quickstart](architecture/ISO_REBUILD_QUICKSTART.md), then
the full [ISO creation and installation runbook](architecture/ISO_CREATION.md)
before creating, attaching, or validating any GREYWARD installer ISO. It is
the canonical recipe and incident-prevention record for the internal alpha
image path; do not rely on an old session report or an unrecorded VM workflow.
The runbook also records the known-good 2026-09-11 Flatpak-finalization ISO
and the update/rollback protocol for evolving components without replacing a
working candidate prematurely.

## Thirty-second project model

GREYWARD is a Fedora-based desktop distribution plus its local Security Center.
The repository contains two layers:

```text
environment/production/ + environment/development/ = GREYWARD-DEV
```

`environment/production/` is the installed-system definition. The development
overlay and `tools/greyward-dev/` add SSH, credentials, Hyper-V access, and
authoring tools; they are not product features. Labwc is the canonical
compositor, DMS owns general desktop settings, and Security Center owns
GREYWARD-specific security and privacy. An internal standalone alpha ISO
path now exists under `environment/image/build-iso.sh`. GREYWARD is in
pre-release alpha/beta development; the main remaining work is broader
bare-metal, recovery, failure-path, and edge-case validation.

## Efficient contributor reading order

For any task, read only this minimum context before opening a large subsystem:

1. `AGENTS.md` — repository rules and required checks.
2. `docs/STATUS.md` — what is true now, what is incomplete, and what is not a
   release claim.
3. The matching row in `docs/REPOSITORY_MAP.md` — implementation, authority,
   tests, and validation command.
4. The linked domain README or canonical specification — the contract to keep.

Then inspect the smallest implementation and test files named by the map. Read
`docs/history/` only when historical evidence or a migration decision is
relevant; it never overrides current documentation.

## Task routing

| If the task concerns | Start with | Then inspect |
|---|---|---|
| Installed OS, packages, login, encrypted root, image inputs | `docs/architecture/PRODUCTION_VS_DEVELOPMENT.md` and [ISO creation runbook](architecture/ISO_CREATION.md) | `environment/production/`, `environment/http/`, `environment/image/` |
| Development VM, deployment, capture, host access | `docs/development/DEVELOPMENT.md` | `environment/development/`, `tools/greyward-dev/` |
| Shell, Labwc, DMS, branding, wallpapers | `docs/architecture/ARCHITECTURE.md` | `environment/session/`, `branding/`, `packaging/greyward-branding/` |
| Security Center UX, backend, packaging, acceptance | `docs/security-center/README.md` | `security-center/`, `docs/security-center/ACCEPTANCE.md` |
| Security Context services or typed operations | `docs/security-context/README.md` | `security-center/security-context/` |
| Normalized events, history, privacy, correlation | `docs/telemetry/README.md` | `docs/telemetry/`, Security Context telemetry modules |
| Recovery points or Restic | `docs/recovery/README.md` | `docs/recovery/`, Security Context recovery modules |
| Updates and DNF boundary | `docs/architecture/UPDATE_CENTER_ARCHITECTURE.md` | `environment/production/`, update-center modules |
| Flatpak, Bazaar, default applications | `docs/software/FLATPAK_BAZAAR_INTEGRATION_PLAN.md` | `environment/flatpak/`, `environment/production/` |
| Secure DNS or network providers | `docs/security/SECURE_DNS_IMPLEMENTATION_PLAN.md` | `docs/security-context/OPENSNITCH.md`, Security Context adapters |
| Tests, documentation links, structure | `docs/DOCUMENTATION_POLICY.md` | `tests/`, `tools/validate-repository.ps1`, `tests/static.ps1` |

## Validation ladder

Run the smallest relevant checks while iterating, then the repository checks
before handoff:

```text
docs/path change       -> tools/validate-repository.ps1
production/branding    -> tests/static.ps1
Security Context       -> Python unittest suite
Rust/backend           -> cargo fmt, cargo test, cargo clippy (Fedora)
frontend               -> ux-contract.test.mjs; real Tauri suite for release evidence
VM/image behavior      -> documented GREYWARD-DEV or production acceptance gate
```

A passing source test is not runtime evidence. Keep `UNAVAILABLE`, `BLOCKED`,
`INCOMPLETE`, and `DEGRADED` distinct from success in both documentation and
implementation.

## Current truth

- [../ARCHITECTURE.md](../ARCHITECTURE.md) — public system architecture,
  authority, state, and reconciliation boundaries.
- [../THREAT_MODEL.md](../THREAT_MODEL.md) — current threats, assumptions,
  limitations, and long-term direction.
- [../TESTING.md](../TESTING.md) and
  [../HARDWARE_TESTING.md](../HARDWARE_TESTING.md) — source/runtime evidence
  boundaries and the physical-hardware matrix.
- [security/privilege-model.md](security/privilege-model.md) — inspectable
  privileged interface inventory.

- [STATUS.md](STATUS.md) — implemented state, active work, and deferred work.
- [ALPHA_RELEASE.md](ALPHA_RELEASE.md) — internal-alpha checklist, supported
  environment, validation gates, and known limitations.
- [REPOSITORY_MAP.md](REPOSITORY_MAP.md) — feature ownership, source files,
  documentation, tests, and validation commands.
- [DOCUMENTATION_POLICY.md](DOCUMENTATION_POLICY.md) — canonical versus
  historical documentation rules.
- [../LICENSING.md](../LICENSING.md) and
  [../THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) — publication-license
  boundary and third-party inventory.
- [PUBLICATION.md](PUBLICATION.md) — mandatory clean-history export procedure
  for creating a future public repository without exposing private history.

## Project-wide authorities

- [architecture/ARCHITECTURE.md](architecture/ARCHITECTURE.md) — system
  boundaries and ownership.
- [architecture/PRODUCTION_VS_DEVELOPMENT.md](architecture/PRODUCTION_VS_DEVELOPMENT.md)
  — installed system versus development overlay.
- [architecture/UPDATE_CENTER_ARCHITECTURE.md](architecture/UPDATE_CENTER_ARCHITECTURE.md)
  — update ownership and provider boundary.
- [security/SECURE_DNS_IMPLEMENTATION_PLAN.md](security/SECURE_DNS_IMPLEMENTATION_PLAN.md)
  — Secure DNS implementation boundary.
- [security/crypto-policy.md](security/crypto-policy.md) — production crypto
  policy, compatibility scope, validation, and rollback.
- [development/DEVELOPMENT.md](development/DEVELOPMENT.md) — development loop
  and safety rules.
- [plans/ROADMAP.md](plans/ROADMAP.md) — current project phases.
- [decisions/H4-COMPARISON.md](decisions/H4-COMPARISON.md) — compatibility
  decision record.
- [decisions/DANK_MODULES.md](decisions/DANK_MODULES.md) and
  [decisions/DANK_UPSTREAM.md](decisions/DANK_UPSTREAM.md) — DMS/module
  decisions and upstream pin policy.

## Product domains

- [security-center/README.md](security-center/README.md) — Security Center
  documentation index and authority table.
- [security-center/SESSION_10_REPORT.md](security-center/SESSION_10_REPORT.md)
  — current Security Center release-gate result and blockers.
- [security-context/README.md](security-context/README.md) — Security Context
  boundary, services, and implementation status.
- [telemetry/README.md](telemetry/README.md) — normalized event model,
  bounded investigation history, retention, and query contract.
- [recovery/README.md](recovery/README.md) — Recovery V1 and rollback prototype
  boundary.
- [software/FLATPAK_BAZAAR_INTEGRATION_PLAN.md](software/FLATPAK_BAZAAR_INTEGRATION_PLAN.md)
  — current Software/Flatpak integration plan.

## Historical material

Historical migration notes, session reports, screenshots, and superseded plans
are under [history/](history/README.md). They explain decisions or evidence but are not
sources of current architecture.
