# GREYWARD Security Center visual QA

## Purpose

Visual QA exists to find and fix obvious product defects in the real GREYWARD
runtime. It is not a scoring exercise and must not become paperwork that
displaces product improvement.

Required loop:

implementation → focused test → development deployment → real GREYWARD-DEV
launch/relaunch → screenshot and interaction review → critique → correction

Fixture screenshots expose difficult states, but they do not replace real
backend, authorization, update, remediation, or service-recovery validation.

## Runtime targets

Review the installed application under the real Fedora/WebKitGTK GREYWARD-DEV
environment with native Labwc server-side decorations intact.

Review at minimum:

- the default desktop capture at the configured **1440×900** logical window;
- the actual configured minimum practical window: **1100×700** logical pixels;
- keyboard-only navigation and visible focus;
- normal and degraded provider availability;
- relaunch after clean exit and after provider/service interruption.

Do not accept a source-only or Windows-preview result as visual authority.

The minimum target is the product's configured minimum, not a historical
fixture size. Do not optimize below it unless the product deliberately changes
the supported minimum. At the two required targets, assess real readability:
quiet does not excuse faint text, and 10 px tracked labels are decorative-only.

## Redesign-depth review

For the deep redesign, review the page composition as well as its polish:

- Overview is visibly recomposed, not a split status/decision hero with a
  metric strip in new styling.
- Protection is visibly rebuilt and does not return to an equal-weight domain
  card grid.
- Files, Updates, Privacy, and Activity are materially recomposed for their
  distinct tasks.
- A colors/fonts/spacing/borders/cards/buttons-only change fails review.
- Planned composition names are hypotheses. If the live capture is generic,
  overly sparse, dense, awkward, weak, or insufficiently premium, iterate past
  the written layout and record the better durable decision.

## Golden state matrix

Each state should be reviewed for hierarchy, copy, action clarity, wrapping,
focus, and recovery behavior.

### Posture and findings

- `SECURE` with all applicable recommendations satisfied;
- `PROTECTED` with an accepted deviation clearly explained;
- `REVIEW NEEDED` with recommendation and required-decision reasons visible;
- `UNAVAILABLE` with the missing capability or evidence boundary explained;
- mixed domain states and multiple review reasons;
- stale, partial, denied, malformed, contradictory, and version-mismatched
  evidence;
- empty findings without reassuring or alarmist wording.

`ATTENTION` and `ACTION_REQUIRED` must not appear as product posture labels in
these reviews. If internal fixtures use more specific metadata, the UI must map
them to the canonical product posture and show the reason separately.

### Startup and provider behavior

- shell usable while optional data is loading;
- bounded primary posture loading;
- optional provider timeout;
- provider unavailable or service stopped;
- provider recovery and retry;
- relaunch after a failed or interrupted collection;
- stale results retained with clear freshness treatment during refresh.

### Existing workflows

- update check with no updates;
- updates available and reviewable;
- Update All authorization, real progress, partial provider result, failure,
  completion, and restart required;
- network or portal control only if the installed backend supports it;
- native authorization cancellation or denial;
- verified action success and backend-reported mismatch/failure;
- file threat evidence, quarantine, scan failure, Safe Open refusal, and
  sanitized-copy result;
- privacy profile, disclosure, retention, export, and clear-history states;
- activity populated, empty, source unavailable, and redacted;
- recovery ready, partial, unavailable, and handoff-only states.

### Composition and accessibility

- first viewport has one clear primary purpose;
- no unnecessary stacking of equally prominent surfaces;
- strong alignment, spacing, proportion, and readable density;
- smaller-window layout remains useful without clipped primary actions;
- long labels, provider names, paths, endpoints, timestamps, and translated
  strings wrap or disclose safely;
- icons are consistent and never silently fall back to unrelated glyphs;
- encoding is correct and technical values remain copyable;
- state is understandable without color;
- focus order, focus visibility, accessible names, reduced motion, text scaling,
  and high contrast remain usable.

## Lightweight review rubric

Use these questions as decision aids, not numeric gates:

- Can a user tell what the current posture means?
- Can a user identify the next useful decision or action?
- Does the page show only information that helps the current task?
- Are canonical posture and internal finding reasons clearly separated?
- Are unavailable, stale, loading, and failed states honest and recoverable?
- Are typography, spacing, alignment, density, and icons coherent?
- Does the page belong naturally inside GREYWARD’s desktop environment?
- Is there any obvious defect worth correcting?

If the answer to the last question is yes, fix it before moving on. Do not pass
because a score or screenshot checklist is complete.

## Acceptance evidence

### Native-system copy audit

- Visible headings and actions use short, functional system language; slogans
  and implementation terms are absent from normal surfaces.
- State, evidence, decisions, timestamps, and controls remain comfortably
  readable in the live runtime. Tracked 10 px text is decorative-only.
- Review the full copy set on Overview, Protection, File Security, Updates,
  Privacy, Activity, detail surfaces, dialogs, loading, empty, unavailable,
  and failed states at both supported window targets.

Keep a small representative set of screenshots and interaction notes for the
golden states above. Record real runtime evidence for startup, relaunch,
provider failure/recovery, Update All, important existing actions, and native
Labwc integration. Do not generate a large screenshot archive for its own sake.

Finish with a simplification-only review. New visual features are forbidden in
that pass; remove redundant status treatment, unnecessary rectangles, weak
micro-typography, noisy icon containers, accidental empty space, and generic
controls. Do not pass while a competent reviewer can still identify an obvious
unfinished or generic visual defect.
