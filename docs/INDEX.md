# GREYWARD documentation index

[Repository consolidation and ISO preparation, 10 October](history/migrations/2026-10-10-release-preparation.md)
records source/package checks, safe publication and measured build storage.
ISO construction remains NO-GO; no deployment or release approval is implied.

Source-only [targeted security truthfulness fixes](history/security-center/2026-10-09-security-truthfulness.md)
correct confined ClamAV status collection and narrow portal/VPN/accepted-risk/grant
claims. Local checks are distinct from pending installed-session validation;
`.149` remains on its existing package tuple with no deployment or service change.


This is the starting point for contributors and repository automation. Read the current
status first, then the repository map before editing a subsystem.

## Mandatory before ISO creation

Read the [ISO rebuild quickstart](architecture/ISO_REBUILD_QUICKSTART.md), then
the full [ISO creation and installation runbook](architecture/ISO_CREATION.md)
before creating, attaching, or validating any GREYWARD installer ISO.
Also read the active [installer compatibility investigation](architecture/ISO_INSTALLER_COMPATIBILITY.md):
only the product ISO may boot during acceptance; no answer media or preseeded interactions. It is
the canonical recipe and incident-prevention record for the internal alpha
image path; do not rely on an old session report or an unrecorded VM workflow.
The runbook also records the known-good 2026-09-11 Flatpak-finalization ISO
and the update/rollback protocol for evolving components without replacing a
working candidate prematurely.

## Thirty-second project model

Latest scoped development recovery: [enrolled graphical login](history/security-center/2026-10-08-enrolled-login-recovery.md).
Follow-up: [post-reboot resources, graphical Flatpak and public-IP recovery](history/security-center/2026-10-08-session-resource-flatpak-recovery.md).
Permission experiment: [bounded hybrid launch and shared-bus prerequisite](history/security-center/2026-10-09-hybrid-flatpak-bootstrap.md)
(BLOCKED; no Flatpak grant/bridge delivered). Current authority remains the
[Application Security plan](security-center/APPLICATION_SECURITY_PLAN.md).
The [D-Bus boundary follow-up](history/security-center/2026-10-09-dbus-boundary-proof.md)
validates a reversible live inspection correction and existing native preview
ownership; portal-to-Flatpak request binding and product gates remain unpassed.

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

The active [DMS 1.6.2 migration tracker](architecture/DMS_1_6_MIGRATION_PLAN.md)
defines candidate packaging, exact patch assembly and acceptance gates. It is not a
release-validation record.

The 4 October [final architecture audit](architecture/FINAL_ARCHITECTURE_AUDIT.md)
and [build/ISO audit](architecture/BUILD_ISO_AUDIT.md) assess the actual local
candidate and development guest. Their [pre-release backlog](plans/PRE_RELEASE_IMPROVEMENTS.md)
contains proposed engineering work; the audit does not change release acceptance
or replace the executable ISO runbook.

## Task routing

The [first-use permission prerequisite receipt](history/security-center/2026-10-09-first-use-permission-proof.md)
records the stopped generic Flatpak experiment: namespace invisibility, shared
FileChooser attribution and host FUSE alias boundaries. The
[Application Security authority](security-center/APPLICATION_SECURITY_PLAN.md)
marks both feature gates unpassed; no generic Flatpak grant delivery is claimed.

Practical sudo administration is owned by the
[enrollment authority](security-center/APPLICATION_SECURITY_ENROLLMENT.md), with
[scoped 9 October evidence](history/security-center/2026-10-09-practical-administration.md).
The [normal-seat compatibility follow-up](history/security-center/2026-10-09-desktop-compatibility.md)
records approved activation and real Administration/portal/Flatpak/grant checks.
Full desktop rollback and production rescue remain unproven.
The [Administration visual follow-up](history/security-center/2026-10-09-administration-visual-polish.md)
records the scoped native-console warning, materials and terminal-color repair.
The [obsidian follow-up](history/security-center/2026-10-09-administration-obsidian.md)
records embedded canonical branding, the red title, sudo explanation and real
desktop validation of the refined finish.

The approved [Application Security plan](security-center/APPLICATION_SECURITY_PLAN.md)
tracks Application Guard and Protected Data implementation. Whole-session
enforcement is a mandatory release gate; the plan is not a protection claim.
Its functional continuation records typed GUI reviews/revocation, shared Safe
Open, scripts/AppImages, private graphical isolation and shared Activity, with
isolated-account evidence and explicitly unavailable providers. Source truth
and historical receipts were reconciled on 7 October. The
[production enrollment design](security-center/APPLICATION_SECURITY_ENROLLMENT.md)
records approved decisions and initial journal/provider/maintenance source.
Separate authentication and bounded-tool checks have [scoped evidence](history/security-center/2026-10-07-application-security-authentication.md).
The [normal-session receipt](history/security-center/2026-10-08-application-security-normal-session.md)
records actual deliberate enrollment of the normal `.149` account: protected
native DMS authentication, confined desktop/user manager/SSH, real resources,
tested grants and deny/allow/revoke. Installed Center 66 / Context 68 / runtime 25 pass live GUI revocation and
package readback. Automatic production/image lifecycle remains unvalidated. The subsequent
[workspace receipt](history/security-center/2026-10-08-security-center-workspace.md)
records grouped navigation, restored dedicated Network Activity and separate
Security History; [UX_SPEC.md](security-center/UX_SPEC.md) owns current presentation.
The [refresh/theme receipt](history/security-center/2026-10-08-protection-refresh-theme.md)
records Center 70 / Context 69 / runtime 26, live lease renewal and restoration
of the root-owned GREYWARD compositor decorations.
The [normal-session recheck](history/security-center/2026-10-08-normal-session-recheck.md)
confirms that exact installed tuple against real coverage, resource denial,
Flatpak behavior and the normal desktop's stable protection presentation.
The [visual polish receipt](history/security-center/2026-10-08-security-center-visual-polish.md)
records the previous Center 72 / Context 69 / runtime 26 tuple, coherent materials,
EN/FR desktop review and preserved real protection boundaries.
The [focused quality/regression receipt](history/security-center/2026-10-08-security-center-quality-regressions.md)
records previous Center 73 / Context 69 / runtime 26, historical visual comparison,
actual native screen/interaction review and recovery evidence.
The earlier [live development](history/security-center/2026-10-07-application-security-live-development.md),
[live integration](history/security-center/2026-10-07-application-security-live-integration.md)
and [desktop review](history/security-center/2026-10-07-application-security-desktop-review.md)
receipts are historical. The enrollment design owns activation, upgrade,
coverage and LUKS recovery; it is not an automatic install recipe.
[Historical evidence](history/security-center/2026-10-07-application-security-evidence.md)
retains older receipts without overriding current capability status.
The user-driven [Application Guard and Protected Data acceptance guide](security-center/USER_ACCEPTANCE_APPLICATION_GUARD.md)
records prepared `.149` desktop scenarios and the current limitation: Center
can review and revoke the tested permission, but has no visible reviewed-tool
launch action to prove an allowed application read. The guide is not a test
result.
The [Security Activity context receipt](history/security-center/2026-10-08-security-activity-context.md)
records previous Center 75 / Context 71 / runtime 27, actual kernel-denial context,
shared disclosures and normal-desktop/package validation.
The [file review lifecycle receipt](history/security-center/2026-10-08-file-review-lifecycle.md)
records the scoped correction for handled detections and missing-source history;
[File Security](security-center/FILE_SECURITY.md) owns the current contract.

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

- [Security Center application identity](../branding/BRANDING.md#security-center-application-identity)
  — shared shield-G artwork for the launcher, taskbar plugin and system notifications.

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

The [5 October pre-release implementation record](history/migrations/2026-10-05-pre-release-implementation.md)
documents the published migration, installer and portable-DNS changes and their
validation limits.

Historical migration notes, session reports, screenshots, and superseded plans
are under [history/](history/README.md). They explain decisions or evidence but are not
sources of current architecture.

- [Security Center performance development receipt](history/security-center/2026-10-08-security-center-performance.md) — measured Center 80 → 84 changes, actual desktop tests and unresolved latency.
- [Integrated window chrome development receipt](history/security-center/2026-10-08-integrated-window-chrome.md) — installed inputs, actual visual evidence and remaining physical gesture checks.

- [Security plugin stability development receipt](history/security-center/2026-10-08-security-plugin-stability.md) — actual desktop flyout, Context threading, negative-display freshness and retained provider warnings.

- [Security plugin and Center state parity](history/security-center/2026-10-08-security-plugin-parity.md) — shared evaluated checks, accepted exceptions and scanner readiness.
