# Session 1 report

> Historical implementation report; not a current architecture document.

SESSION OBJECTIVE REVIEW

THIS SESSION WAS SUPPOSED TO:
- Create the Rust workspace, empty GTK4/libadwaita application, build/RPM skeleton, test harness, stable domain types, snapshot v1 serialization, semantic states, and deterministic evaluator.
- Prove clean Fedora build/test/lint, strict bounded parsing, exhaustive aggregation semantics, package inventory, non-root execution, and real launch under canonical DMS/Labwc.

RESULT:
PASS

COMPLETED:
- Added the `security-center/` Rust workspace with the backend-independent `greyward-security-domain` crate and fixture-only `greyward-security-center` GTK application.
- Added closed posture/domain/capability/runtime/remediation enums, bounded evidence/check/snapshot types, v1 schema validation, explicit check-ID migration alias, applicability/freshness/evaluation helpers, and normative domain aggregation.
- Added JSON round-trip, forward-version, unknown-enum, malformed, bounds, alias, freshness, applicability, evaluator, and exhaustive six-state/three-requiredness tests.
- Added locked dependencies, Fedora build instructions, desktop entry, RPM spec, and JSON fixtures.
- Verified Fedora 44 GTK 4.22.4/libadwaita 1.9.3 build dependencies, release build, `cargo fmt --check`, 12 tests, and `cargo clippy --workspace --all-targets --locked -- -D warnings`.
- Built and inspected the RPM: binary and desktop entry only; no service, Polkit action, helper, or live backend.
- Installed the RPM temporarily, launched through `gtk-launch` under active DMS/Labwc, observed UID 1000 and bus name `systems.mantis.greyward.securitycenter`, captured a 2560x1440 Wayland frame, then removed the RPM and verified DMS remained active and the legacy shell inactive.

NOT COMPLETED:
- No live security backend, D-Bus control, subprocess adapter, DMS plugin, root service, or security-setting mutation was implemented, per Session 1 scope.
- A fixed DHCP reservation could not be established from this repository: the actual Hyper-V guest is `GREYWARD-DEV` on the Default Switch with a dynamic lease. The approved helper repaired the `greyward-dev` alias to the observed lease.

SELF-DETECTED ISSUES:
- Initial Fedora Clippy findings (conditional form and missing Rustdoc error section) were corrected and revalidated.
- The first RPM archive attempt included `target/` and exceeded the VM `/tmp` quota; only those temporary validation artifacts were removed and the bounded source archive rebuilt successfully.
- The supplied VM label `GREYWARD-DEV-BUILD` does not exist in Hyper-V; repository/runtime evidence identifies `GREYWARD-DEV` as the canonical development guest.

VALIDATION:
- build: PASS — Fedora 44 release build and RPM build.
- tests: PASS — 2 UI tests, 10 domain tests, RPM `%check`.
- runtime: PASS — DMS active, legacy shell inactive, UID 1000, application bus name observed, package install/remove verified.
- logs: PASS — launch log contained no application error; Mesa/portal warnings were VM graphics/runtime warnings and did not prevent launch.
- visual validation: PASS — native GTK/libadwaita window launched under Wayland/Labwc; 2560x1440 `grim` capture saved as `output/security-center-session1.png`.

REMAINING PLAN

SESSIONS REMAINING: 9

SESSION 2:
Objective: Implement the evidence framework and read-only core system posture adapters for SELinux, boot/kernel, storage encryption, and TPM.

SESSION 3:
Objective: Implement read-only firmware/HSI and DNF5 security-update readiness with cached/offline/stale behavior.

SESSION 4:
Objective: Implement NetworkManager, DNS, VPN-presence, firewalld inspection, and the single reversible active-connection trust-zone control.

SESSION 5:
Objective: Implement Flatpak/application isolation visibility, portal health, verified permission schemas, and revoke/restore controls.

SESSION 6:
Objective: Implement privacy transparency, external-service disclosure, bounded retention/export, and recent security activity.

SESSION 7:
Objective: Implement read-only USBGuard/device capability visibility and composed recovery-readiness views.

SESSION 8:
Objective: Build the complete V0 Security Center UX across overview, domains, activity, recovery, evidence, recommendations, controls, and error states.

SESSION 9:
Objective: Finish visual/accessibility/localization quality, RPM ownership, desktop integration, clean install/update/uninstall, and DMS discovery.

SESSION 10:
Objective: Execute V0 hardening, abuse/fuzz/privacy/performance testing, VM/physical validation, rollback verification, and the final release gate.

POST-V0 MILESTONES:
- V1 posture monitor and DMS widget: NOT STARTED
- Application-network backend prototype: NOT STARTED
- Application-network integration: BLOCKED BY PROTOTYPE
- USBGuard active control: NOT STARTED
- Richer security activity: NOT STARTED
- Sensitive Files: NOT STARTED
- High-Risk/Travel Mode: NOT STARTED
- Advanced application policy: NOT STARTED
- AI-mediated security: NOT STARTED

NEXT SESSION:
Session 2 — Evidence framework and core system posture. Do not start automatically.

PLAN DEVIATION:

HISTORICAL IDEA:
Use the user-supplied `GREYWARD-DEV-BUILD` VM name and a fixed lease IP for canonical validation.

EVIDENCE:
Hyper-V exposes no `GREYWARD-DEV-BUILD`; it exposes the running `GREYWARD-DEV`. The guest was on the Hyper-V Default Switch with a dynamic lease; the historical MAC and private address are intentionally redacted. The repository helper targets `GREYWARD-DEV` and successfully repaired `greyward-dev` to the observed endpoint.

BETTER DIRECTION:
Use the repository's approved lifecycle/helper discovery and the SSH alias, without inventing a static guest address or modifying external DHCP infrastructure.

IMPACT:
Session 1 was fully built and validated against the actual canonical DMS/Labwc guest. The SSH endpoint remains lease-dependent and requires the helper's discovery on future sessions; no Security Center architecture or scope changed.
