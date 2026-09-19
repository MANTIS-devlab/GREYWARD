# Security Center UX remediation plan

`UX_SPEC.md` is the acceptance contract. This plan orders focused engineering
sessions; it does not authorize new security capabilities or frontend-derived
posture decisions.

## 1. Runtime visibility and audit baseline

- Restore visible, focused installed-window launch under Labwc, including
  single-instance/deep-link restoration.
- Capture all ten current routes at 1440x900 and 1100x700 against live backend
  data; record unavailable routes and provider limitations rather than guessing.
- Accept when the installed process creates a visible toplevel, route requests
  bring it forward, and captures identify live posture and package build.

## 2. Inventory and state contract

- Audit every visible element/string/action against its route renderer and
  typed backend source; maintain the inventory in `UX_SPEC.md`.
- Reconcile navigation and posture vocabulary against `POSTURE_MODEL.md` and
  `CAPABILITY_MATRIX.md`; classify requested, effective, stale, degraded,
  unsupported, unavailable, pending, and failed values.
- Accept when every user-visible state has a plain-language meaning, owner,
  and canonical location.

## 3. Information architecture and duplication

- Enforce five task-oriented primary destinations and contextual detail routes;
  remove page summaries that merely restate Overview or a selected domain.
- Move technical IDs, reason codes, provider values, timestamps, and raw
  diagnostics behind disclosure without removing evidence access.
- Accept when Overview answers posture/next action at a glance and each fact
  has one primary home plus an intentional drill-down.

## 4. Actions, feedback, and recovery

- Standardize all update, trust-zone, OpenSnitch rule, Secure DNS, deviation,
  Safe Open, sanitize, privacy export/clear/profile, and launcher workflows.
- Add target-specific labels, working state, verification, partial/failure
  message, retry/undo/handoff where backend-supported, and accessible result
  announcement.
- Accept when no click ends without intelligible feedback and no requested
  setting is presented as effective protection.

## 5. Copy and reusable components

- Replace generic, repetitive, and implementation-facing copy across normal,
  loading, empty, degraded, dialog, success, and failure states.
- Consolidate status rows, empty/error states, actions, freshness treatment,
  and technical disclosure patterns in the existing vanilla frontend.
- Accept when representative screenshots contain direct factual copy with no
  duplicate state treatment or raw backend errors in primary content.

## 6. Visual hierarchy and accessibility

- Apply the specification's focal-plane, typography, status, action, responsive
  and reduced-motion rules consistently; preserve native Labwc decorations.
- Validate keyboard order/focus, accessible names/live announcements, contrast,
  text scaling, long values, narrow layout, and non-color status meaning.
- Accept when all primary and contextual views are usable at both supported
  window sizes.

## 7. End-to-end review

- Re-run real GREYWARD-DEV workflows, provider interruption/recovery, relaunch,
  and before/after screenshot comparison. Fixtures exercise unavailable,
  malformed, partial, and stale values but never replace runtime validation.
- Add focused tests for navigation, bounded loading, state mapping, copy
  regressions, action feedback, and accessibility semantics.
- Accept only after every material defect is corrected or recorded as a
  capability-boundary issue with a user-facing explanation.

## Backend information still needed for complete UX state coverage

The frontend must not manufacture these states. The live contract currently
needs the following additions before every state can be presented with the
same certainty as a normal, healthy response:

| Missing contract field | Affected surface | Required user treatment until supplied |
|---|---|---|
| Per-provider observation time and explicit stale threshold | Updates, network, applications, devices | Show the last supplied observation only; do not claim it is current. |
| Stable operation ID, phase, percent, and terminal result for network, DNS, privacy, Safe Open, and deviation actions | Action feedback | Show `Working` while the request is pending; re-read measured state after success. Do not invent progress. |
| Typed retryability and recovery action | All degraded/unavailable responses | Offer Retry only for read/operation failures; otherwise state that the feature is unavailable. |
| User-safe cause and capability boundary separate from diagnostic detail | Network, devices, applications, technical evidence | Present the concise cause in the primary view and retain diagnostics in technical details. |
| Explicit support/unsupported distinction for each collector | All contextual routes | Use `Unsupported` where a check cannot apply; reserve `Unavailable` for a failed or missing observation. |

These are follow-up backend requirements, not frontend fallbacks. The current
UI keeps measured state, configured state, and unavailable evidence distinct
until the typed values exist.

## Application inventory contract

The Applications route derives one effective-access model in the Rust backend:
the manifest context is evaluated first, then local Flatpak overrides (including
explicit removals). Primary rows use its categories and concise review reasons;
the manifest and override records stay separate in technical disclosure. The
collector reads both user and system scopes without an arbitrary inventory cap.
If one scope cannot be read, the route reports a partial, discovered-only
inventory; if neither can be read, it reports unavailable rather than an empty
application list.

## Deferred restore-browser design review

The current Restic helper deliberately returns a bounded first page of restore
paths while a restore request accepts a smaller, explicit selection limit. The
Security Center reports both numbers and prevents oversized submission; it does
not present that first page as a complete browser. A searchable, lazy-loaded
tree or folder navigator needs a separate product and accessibility review
before it replaces the compact list. That review must preserve staged restore,
bounded queries, selection feedback, and the no-overwrite guarantee.
