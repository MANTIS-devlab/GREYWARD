# GREYWARD Security Center UX redesign execution plan

> Historical plan. Current UX authority: `docs/security-center/UX_SPEC.md`.

## Objective

Deeply improve the current GREYWARD Security Center in its existing Rust +
Tauri 2 architecture. The result must make current security capabilities
understandable and actionable while preserving backend authority, native desktop
integration, and honest capability boundaries.

This plan covers the presentation redesign and the minor interface changes
needed to expose existing functionality correctly. It does not authorize new
security-engineering milestones.

## Non-negotiable product contract

The only product-facing posture states are:

- `SECURE` — all applicable recommendations are satisfied with no unresolved
  review items or accepted deviations;
- `PROTECTED` — no unresolved review decisions remain, but accepted deviations
  exist;
- `REVIEW NEEDED` — one or more conditions require a human decision;
- `UNAVAILABLE` — GREYWARD cannot reliably determine posture.

`SECURE` and `PROTECTED` are distinct. `ATTENTION` and `ACTION_REQUIRED` must
not appear as active global product states. Internal finding metadata may retain
more specific reasons, but the frontend must render the backend-authoritative
canonical posture and must not create a competing vocabulary.

## Scope and boundaries

- Keep Rust, Tauri 2, the current presentation technology, Security Context,
  system services, packaging, and native Labwc decorations.
- Refactor presentation architecture deeply when it improves maintainability,
  state handling, or visual quality; do not migrate frontend frameworks.
- Inventory the real commands, providers, controls, and installed runtime before
  exposing them in the new UI.
- Integrate existing supported functionality only. Missing capability ideas are
  documented as later work rather than implemented as placeholder controls.
- Keep Rust/backend authoritative for posture, normalization, authorization,
  remediation, update orchestration, and verification.
- Do not add generic shell, D-Bus, filesystem, privilege, or frontend security
  logic.

## Startup robustness requirement

The application must not become stuck indefinitely on “Loading local posture”.

The implementation must:

- render the shell and primary posture region within a bounded deadline;
- load optional and secondary providers independently;
- convert timeout, absence, denial, and provider failure into explicit degraded
  or unavailable content;
- keep the application usable while secondary data resolves;
- preserve current data with stale treatment during refresh;
- support retry and provider recovery without requiring relaunch;
- validate launch and relaunch behavior in the installed GREYWARD-DEV runtime.

## Product and information architecture

Begin with the candidate grouping below, then validate it against the real
rendered product rather than treating it as a required sitemap:

- Overview;
- Protection;
- Files;
- Updates;
- Privacy;
- Activity;
- Recovery.

Luna may merge, remove, regroup, promote, demote, or simplify sections when
runtime inspection shows a better result. Do not create a page merely because a
backend capability exists. Optimize for understanding → decision → action →
feedback with minimal navigation depth.

Evidence, provenance, timestamps, and technical identifiers remain available
through progressive disclosure. They should support the normal user experience,
not turn Security Center into a forensic or administrative console.

## Update experience

Where the existing installed update backend supports the operation, present one
coherent GREYWARD flow:

Check → Review → Update All → native authorization → real provider progress →
complete → restart when required.

DNF5, Flatpak, fwupd, and freshclam are provider details. Expose them when they
help explain transparency or failure, but do not require normal users to
operate providers separately. Do not fabricate progress, expose terminal or
raw sudo interaction, add duplicate authentication, or show controls for
unsupported providers.

If capability audit proves that a requested update action is not supported by
the installed backend, keep the UI read-only or handoff-based and document the
gap for later work.

## Broad execution passes

Every pass includes implementation, focused testing, development deployment,
real GREYWARD-DEV inspection, and correction. Use the fast installed development
loop for visual changes; reserve full RPM/package validation for integration and
release checkpoints.

### Pass 1 — Contract, capability, and startup foundation

- Reconcile this plan with `POSTURE_MODEL.md`, `PRODUCT.md`,
  `CAPABILITY_MATRIX.md`, and the actual installed runtime.
- Inventory current commands, providers, existing controls, update operations,
  file workflows, privacy actions, and recovery evidence.
- Establish canonical posture mapping and prevent presentation code from
  creating alternative global states.
- Refactor startup so primary UI rendering is bounded and optional providers do
  not block the whole application.
- Add focused launch, relaunch, timeout, unavailable, retry, and provider
  recovery tests.
- Deploy and inspect startup and relaunch on GREYWARD-DEV before proceeding.

### Pass 2 — Product structure and interaction model

- Replace mixed navigation and hidden-detail behavior with the strongest
  runtime-proven structure; the candidate sitemap may be simplified.
- Establish a clear primary task for each surface and remove competing or
  misplaced secondary workflows.
- Refactor monolithic rendering/binding into maintainable route, state, and
  reusable component boundaries using the existing frontend technology.
- Preserve backend-provided posture, finding reasons, capability states, and
  action availability.
- Test navigation, deep links if retained, keyboard operation, empty states,
  and narrow-window behavior.
- Deploy and inspect every substantially changed surface on GREYWARD-DEV.

### Pass 3 — Existing workflow integration

- Integrate only confirmed existing network, portal, file, privacy, recovery,
  and update functionality.
- Implement the coherent Update All experience with native authorization and
  real progress where the backend supports it.
- Present existing actions with explicit target, consequence, authorization,
  verified result, and backend-supported undo/restore behavior.
- Keep unsupported controls absent or clearly unavailable.
- Validate action success, cancellation, denial, timeout, mismatch, provider
  failure, restart-required, and recovery states.
- Deploy and inspect real workflows on GREYWARD-DEV rather than relying only on
  fixtures.

### Pass 4 — Visual refinement and final simplification

- Consolidate CSS override layers and repair icons, encoding, wrapping, focus,
  and responsive composition.
- Improve hierarchy, density, proportion, typography, whitespace, alignment,
  and desktop coherence without prescribing effects or surface counts.
- Compare weaker pages against the strongest page and raise their quality.
- Stop adding features. Remove unnecessary elements, excessive surfaces,
  developer-looking content, awkward placement, redundant copy, and confusing
  workflows.
- Re-run important normal, degraded, error, startup, update, and action states
  in the real runtime and correct every material defect found.

## Testing and visual validation

- Maintain focused functional tests for launch, navigation, bounded loading,
  optional-provider failure/recovery, important existing actions, Update All,
  update failure/restart, and remediation workflows.
- Use fixture states to exercise canonical posture, internal finding reasons,
  stale, unavailable, empty, malformed, and partial data presentation.
- Use real GREYWARD-DEV workflows for backend, authorization, progress,
  provider recovery, relaunch, and installed-package acceptance.
- Review screenshots and interactions at the default target size and smallest
  supported practical size.
- Apply the questions and golden states in `VISUAL_QA.md`; do not replace real
  visual critique with scoring paperwork.
- Preserve native Labwc titlebar behavior and confirm DMS Secure remains aligned
  with backend-authoritative posture.

## Deliverables before application redesign

- `docs/security-center/DESIGN.md`
- `docs/security-center/VISUAL_QA.md`
- `docs/history/security-center/plans/UX_REDESIGN_PLAN.md`

These documents must be reviewed for posture vocabulary, capability accuracy,
startup behavior, Update All semantics, design latitude, and runtime acceptance
before frontend implementation begins.

## Definition of done

- Canonical posture is preserved: `SECURE`, `PROTECTED`, `REVIEW NEEDED`, and
  `UNAVAILABLE` only.
- `SECURE` and `PROTECTED` remain visibly and meaningfully distinct.
- `ATTENTION` is absent from active product UI and design guidance.
- The redesign is substantial in composition and user experience.
- Current GREYWARD capabilities are integrated coherently without invented
  security functionality or implied unsupported enforcement.
- Startup and relaunch never remain indefinitely blocked by optional providers.
- Core UI remains usable while secondary data loads, times out, fails, or
  recovers.
- Updates provide one coherent Update All experience where existing backend
  support permits it, with native authorization, real progress, completion, and
  restart-required handling.
- Important existing actions work through their real backend and preserve
  verification and security boundaries.
- Normal, degraded, loading, unavailable, empty, stale, error, threat,
  remediation, update, and recovery states are polished.
- The application remains useful at target and smaller supported window sizes.
- No obvious alignment, layout, icon, typography, spacing, wrapping, encoding,
  focus, or material-treatment defects remain.
- Native Labwc titlebar and desktop integration are preserved.
- DMS Secure continues to show the same backend-authoritative canonical posture.
- Rust/Tauri/backend security authority is preserved.
- Installed GREYWARD-DEV launch, relaunch, navigation, update, action, failure,
  and recovery workflows are validated.
- Final visual review finds no remaining material defect worth correcting.
