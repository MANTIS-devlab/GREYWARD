# GREYWARD documentation index

15 October native window placement: retain Labwc edge/corner snapping in the
next ISO. Static defaults and actual Session RPM payload guards protect the
configuration; real left-half and control-button checks are partial acceptance,
not proof of every drag gesture. See [window placement](architecture/WINDOW_MANAGEMENT.md).

14 October internal ISO candidate: `GREYWARD-0.4.0-Dawn-x86_64.iso` includes
Files 17, DMS 17, Session 21, Application Security 51, Enrollment 32, Security
Center 100, Security Context 92 and Branding 16. The canonical offline factory,
29-path pre/post extraction checks, checksum, boot volume ID and independent
Windows 39-path media validator pass. It is not installed or booted; acceptance
gates remain open. See [current status](STATUS.md) and [ISO evidence](architecture/ISO_CREATION.md).

14 October native-icon candidate: Files 17 is installed in development,
retaining the source-built revision-15 executable. The normal desktop review
confirms shared icon silhouettes, balanced semantic accents and SVG thumbnails.
Three Rust and twelve Fedora Python checks pass. Installed ordinary-domain
preview/secret-denial checks and real preview, duplicate/rename/Trash/restore
interactions pass; remaining migration and image gates stay explicit. Build-pressure session loss during
revision 15 is recorded separately. See [file manager integration](architecture/FILE_MANAGER_DESKTOP.md).

14 October preview dependencies: Files 14 now declares external renderer
commands that were previously present only by coincidence on the development
host. Installed sandbox-helper image/PDF/video checks pass and the registered
mock secret stays denied. Normal-window preview and full ISO closure remain
NON VÉRIFIÉ. See [file manager integration](architecture/FILE_MANAGER_DESKTOP.md).

14 October icon review correction: Files 13 replaces the remaining mixed
extension artwork and embedded Strata application icon. Installed resource
checks and six focused tests pass. After user unlock, the reopened Strata grid
confirms shared folder/text artwork and launcher identity. Launcher-file icons
and ODT thumbnail differences remain; full visual acceptance is not claimed. The user's rejection of revision
11 supersedes any whole-interface acceptance interpretation of the earlier
folder/text checks. See [file manager integration](architecture/FILE_MANAGER_DESKTOP.md).

14 October native-lock candidate: ordinary DMS lock routing is prepared for
the existing protected owner, and its private Qt clipboard interfaces are
suppressed through native configuration. Runtime 51 / Enrollment 32 / Session
18 build and focused tests pass. After explicit user approval, all three packages
are installed and the protected runtime refreshed; SSH, Enforcing and greetd
remain available. New-session lock/PAM and stability checks remain pending.
A later natural native lock on the old runtime is verified; intermittent stability remains unresolved. See
[file manager integration](architecture/FILE_MANAGER_DESKTOP.md).

14 October icon unification: the native Greyward theme and icon-only Strata
resource overlay share the Obsidian/Platinum family. Installed revision 11 fixes
both the ignored PCManFM theme setting and GIO's missing folder alias; real
desktop/Strata comparison passes for folders and text in column/grid views.
The later automatic-lock/session-closure defect remains unresolved. See
[the owning file/desktop record](architecture/FILE_MANAGER_DESKTOP.md).

13 October file manager migration: verified Strata 1.0.0 and Fedora PCManFM-Qt
2.4.1 now run as confined ordinary applications in a reversible development proof.
The native transparent desktop preserves the DMS wallpaper. See
[file manager and desktop integration](architecture/FILE_MANAGER_DESKTOP.md)
for evidence, remaining implementation and rollback; this is not ISO acceptance.
The installed proof now includes automatic icons, native taskbar shortcut
creation and the canonical file-manager folder icon. Earlier entries below
describe historical states.

13 October rollback: `<development-host>` now has DMS 1.6.2-14, Application Security 41,
Enrollment 16 and Session 16 on disk; PCManFM-Qt and Kvantum were removed, and
desktop-icon test files were archived under the user's local state directory.
RPM verification is clean and SELinux remains Enforcing. The already-running
protected session still has the previous DMS 1.6.2-16/Application Security 48
runtime loaded. Its migration explicitly refuses to replace the protected
desktop while that session is active, so a logout/login is still needed before
the visible desktop can use the restored packages. The user cannot currently
authenticate remotely, so that session was left intact. Source now selects DMS
1.6.2-15 with the stable software-renderer policy; no ISO was rebuilt. See
[current status](STATUS.md) and the [DMS monitor/session record](architecture/DMS_MONITOR_CONFIGURATION.md).

12 October: R6 still started at 1024×768 with the previous 0.3.5 Dawn image
because its mode request was in the writable-user autostart, not the root-owned
autostart used by the protected compositor. A replacement candidate now puts a
bounded 1920×1080 request in that protected path for VM output `Virtual-1`.
Build, payload and Windows media checks pass; installation on R6 and runtime
resolution acceptance remain pending. See [current status](STATUS.md), the
[monitor configuration record](architecture/DMS_MONITOR_CONFIGURATION.md) and
[ISO build evidence](architecture/ISO_CREATION.md).

10 October: the user accepts the R5 installation/login fix. R6 is built, hash-verified on Windows and mounted in the existing R5 VM with the output-management commit 8c130a662b047a33406c695d54adf524cc302d99 and a greeter-only CPU OpenGL renderer correction for the canonical wallpaper. Private compiled-protocol and actual embedded-greeter rendering checks pass; installed R6 greeter and DMS apply remain pending. See the candidate evidence (private development evidence).

Earlier entries below are dated evidence, not current acceptance claims.

10 October r5 candidate: Enrollment 5 corrects the confirmed mode-0700 program-directory login failure. The repaired r4 installation reaches the desktop (user confirmation and console evidence). R5 composition, embedded payload checks and Windows SHA-256 verification pass; fresh r5 installation, default session selection and installed security acceptance remain pending. See the candidate evidence (private development evidence).

10 October installed r4 acceptance: installation completed according to the user, but GREYWARD Labwc login fails and the greeter defaults to Hyprland. R4 is not accepted. Only the new test VM is in an approved rescue investigation; .149 remains the unchanged build host. See the failure evidence (private development evidence).

10 October ISO rebuild: r3 failed clean installation because private installer-origin storage was missing; it is rejected. Enrollment revision 4 is rebuilt, eleven lifecycle tests pass, and the actual packaged broker reproduces the missing-directory failure then succeeds with corrected private storage in a synthetic clean root. The r4 ISO has built, passed payload checks, and hash-matched on Windows. It is attached to the new empty test VM without runtime activation on `<development-host>`. Clean-install acceptance remains pending. See the candidate evidence (private development evidence).

10 October enrollment ISO candidate: matched installer enrollment inputs are now
packaged without activating them on `<development-host>`. The copied offline SELinux store
links successfully and the packaged compositor digest matches. The build host
remains the running development system. Candidate composition has passed;
clean-install, graphical enrollment and encrypted recovery acceptance remain
pending on the separate test VM. See the [enrollment authority](security-center/APPLICATION_SECURITY_ENROLLMENT.md).

The earlier 10 October blocker receipts below are historical snapshots; their
pre-assembly NO-GO findings are superseded only by the scoped checks recorded
above, not by production acceptance. See the candidate evidence (private development evidence).


Enrollment-required ISO readiness (private development evidence)
records the cleared storage gate, observed protected login and actual revision-8
authentication assembly failure. Mandatory enrollment/recovery gates remain open.


Enrolled login routing recovery (private development evidence)
records session 9's installed fail-closed routing repair; real login retry is pending.

Final ISO blockers (private development evidence)
records the Python toolchain correction, unchanged verification and unresolved
production enrollment/package/recovery gates. ISO construction remains NO-GO.

Repository consolidation and ISO preparation, 10 October (private development evidence)
records source/package checks, safe publication and measured build storage.
ISO construction remains NO-GO; no deployment or release approval is implied.

Source-only targeted security truthfulness fixes (private development evidence)
correct confined ClamAV status collection and narrow portal/VPN/accepted-risk/grant
claims. Local checks are distinct from pending installed-session validation;
`<development-host>` remains on its existing package tuple with no deployment or service change.


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

Latest scoped development recovery: enrolled graphical login (private development evidence).
Follow-up: post-reboot resources, graphical Flatpak and public-IP recovery (private development evidence).
Permission experiment: bounded hybrid launch and shared-bus prerequisite (private development evidence)
(BLOCKED; no Flatpak grant/bridge delivered). Current authority remains the
[Application Security plan](security-center/APPLICATION_SECURITY_PLAN.md).
The D-Bus boundary follow-up (private development evidence)
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

The first-use permission prerequisite receipt (private development evidence)
records the stopped generic Flatpak experiment: namespace invisibility, shared
FileChooser attribution and host FUSE alias boundaries. The
[Application Security authority](security-center/APPLICATION_SECURITY_PLAN.md)
marks both feature gates unpassed; no generic Flatpak grant delivery is claimed.

Practical sudo administration is owned by the
[enrollment authority](security-center/APPLICATION_SECURITY_ENROLLMENT.md), with
scoped 9 October evidence (private development evidence).
The normal-seat compatibility follow-up (private development evidence)
records approved activation and real Administration/portal/Flatpak/grant checks.
Full desktop rollback and production rescue remain unproven.
The Administration visual follow-up (private development evidence)
records the scoped native-console warning, materials and terminal-color repair.
The obsidian follow-up (private development evidence)
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
Separate authentication and bounded-tool checks have scoped evidence (private development evidence).
The normal-session receipt (private development evidence)
records actual deliberate enrollment of the normal `<development-host>` account: protected
native DMS authentication, confined desktop/user manager/SSH, real resources,
tested grants and deny/allow/revoke. Installed Center 66 / Context 68 / runtime 25 pass live GUI revocation and
package readback. Automatic production/image lifecycle remains unvalidated. The subsequent
workspace receipt (private development evidence)
records grouped navigation, restored dedicated Network Activity and separate
Security History; [UX_SPEC.md](security-center/UX_SPEC.md) owns current presentation.
The refresh/theme receipt (private development evidence)
records Center 70 / Context 69 / runtime 26, live lease renewal and restoration
of the root-owned GREYWARD compositor decorations.
The normal-session recheck (private development evidence)
confirms that exact installed tuple against real coverage, resource denial,
Flatpak behavior and the normal desktop's stable protection presentation.
The visual polish receipt (private development evidence)
records the previous Center 72 / Context 69 / runtime 26 tuple, coherent materials,
EN/FR desktop review and preserved real protection boundaries.
The focused quality/regression receipt (private development evidence)
records previous Center 73 / Context 69 / runtime 26, historical visual comparison,
actual native screen/interaction review and recovery evidence.
The earlier live development (private development evidence),
live integration (private development evidence)
and desktop review (private development evidence)
receipts are historical. The enrollment design owns activation, upgrade,
coverage and LUKS recovery; it is not an automatic install recipe.
Historical evidence (private development evidence)
retains older receipts without overriding current capability status.
The user-driven [Application Guard and Protected Data acceptance guide](security-center/USER_ACCEPTANCE_APPLICATION_GUARD.md)
records prepared `<development-host>` desktop scenarios and the current limitation: Center
can review and revoke the tested permission, but has no visible reviewed-tool
launch action to prove an allowed application read. The guide is not a test
result.
The Security Activity context receipt (private development evidence)
records previous Center 75 / Context 71 / runtime 27, actual kernel-denial context,
shared disclosures and normal-desktop/package validation.
The file review lifecycle receipt (private development evidence)
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

- [../README.md](../README.md) — product overview, user-facing capabilities,
  pre-release limitations and entry points. Detailed validation and component
  versions belong in the status and domain documents below.
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

The 5 October pre-release implementation record (private development evidence)
documents the published migration, installer and portable-DNS changes and their
validation limits.

Historical migration notes, session reports, screenshots, and superseded plans
are under [history/](history/README.md). They explain decisions or evidence but are not
sources of current architecture.

- Security Center performance development receipt (private development evidence) — measured Center 80 → 84 changes, actual desktop tests and unresolved latency.
- Integrated window chrome development receipt (private development evidence) — installed inputs, actual visual evidence and remaining physical gesture checks.

- Security plugin stability development receipt (private development evidence) — actual desktop flyout, Context threading, negative-display freshness and retained provider warnings.

- Security plugin and Center state parity (private development evidence) — shared evaluated checks, accepted exceptions and scanner readiness.
