# GREYWARD Security Center — Deep Visual Redesign Plan

> Historical plan. Current visual authority: `docs/security-center/DESIGN.md`.

## Status and authority

This is the approved **deep visual and compositional redesign** plan for
Security Center. It changes presentation only: it must not change security logic,
backend behavior, posture evaluation, D-Bus contracts, providers, update
architecture, remediation semantics, permissions, or product scope.

The real installed GREYWARD-DEV application is the final visual authority. A
faithful implementation of a written layout is not sufficient when the live
result is generic, sparse, dense, awkward, weak, or insufficiently premium.
Screenshot-driven iteration may replace a planned composition and update this
document or `DESIGN.md` when it establishes a better durable decision.

## Current-state visual audit

The current application is coherent and restrained, but it still reads as a
dark administration dashboard: a persistent admin-style rail, command bar,
split posture/decision hero, metric strip, repeated bordered rectangles, and
equal-weight grids. Its desktop build is more polished than the earlier
implementation, but the hierarchy is too often supplied by containers rather
than composition.

- The shell gives rail, header, and content similar visual authority. The
  selected rounded navigation item is familiar rather than distinctive.
- Overview reads in this order: page title, two equal hero panels, four metric
  cells, then lists. Posture and next decision compete; counts repeat context
  already available elsewhere.
- Protection is the clearest generic pattern: a 2×2 set of near-identical
  domain blocks, each repeating icon, category, status, description, and
  action. The page does not express priority or relationship between domains.
- Files, Updates, and Privacy each divide a connected task into stacked,
  similarly weighted sections. Activity is a competent list but not a
  deliberate temporal record. Detail surfaces remain clearer than the top
  level but rely too heavily on panels and small metadata.
- Inter is appropriate, but current small muted metadata risks becoming too
  faint in real runtime. Quiet must come from contrast, hierarchy, and space,
  never from making required information tiny.
- Surface treatment overuses dark fills, 1 px boundaries, soft icon boxes, and
  dots/pills. The result is orderly but not distinctly GREYWARD without the
  wordmark.

## Redesign-depth contract

| Surface | Decision | Required perceptual change |
|---|---|---|
| Application shell and navigation | RECOMPOSE | Replace the generic rail/header relationship with a quieter security index and contextual canvas. |
| Overview | RECOMPOSE | It must not read as split status cards plus a metric dashboard. |
| Protection | REBUILD | It must not read as an equal-weight 2×2 domain grid. |
| File Security | RECOMPOSE | It must read as a coherent safe-handling task, not stacked feature panels. |
| Updates | RECOMPOSE | It must read as a single bounded transaction, not telemetry plus commands. |
| Privacy | RECOMPOSE | It must read as a local-data explanation and control relationship, not independent cards. |
| Activity | RECOMPOSE | It must read as a calm record of time, not generic rows. |
| Network, Applications, Devices, Evidence, dialogs | REFINE | Preserve information scope while using the new reading-surface, disclosure, and action patterns. |
| Loading, empty, unavailable, and failure states | RECOMPOSE | Make them contextual, bounded, and as polished as the normal path. |

No CSS-only redesign is valid. The implementation must rework page composition,
markup/component structure, information priority, and action placement where
the table requires it. It must not return to generic equal-weight card grids.

## Alternative directions explored

| Direction | Composition | Clarity / quietness / premium identity | Scalability and density | Complexity |
|---|---|---|---|---|
| Editorial security brief | Open posture field, asymmetric action annotation, typography-led ledgers, minimal containers | Very quiet and premium; can become too sparse on operational pages | Strong at low-to-medium density; weak if technical density grows | Medium |
| Operational ledger | Persistent state index, dense vertical register, inline expansion | Highest scan clarity; risks feeling forensic or utilitarian | Strong at high density | Medium |
| Layered perimeter | Framed focal plane, navigational spine, grouped protection layers | Distinct desktop character; risks recreating card framing | Good at medium density | Medium-high |

### Selected direction: Calibrated Security Brief

Use the strengths of the editorial brief and operational ledger: one
asymmetric focal composition per page, followed by precise typographic ledgers
and progressive disclosure. Calibrated Security Brief and its planned
expressions—such as a posture field, protection register, transaction runway,
privacy contract, and handling workflow—are hypotheses, not immutable layouts.
They describe the intended perceptual transformation only. Replace or abandon
them during live review if a different composition produces clearer hierarchy,
quieter confidence, a more premium character, or better desktop usability.

## GREYWARD visual signature and system

### Signature

Use these recurring, subtle characteristics across the product:

1. **Machined rules:** precise platinum-toned baseline rules and aligned edges
   establish structure more often than containers.
2. **One active plane:** use at most one raised/focal surface in a major page
   viewport; all supporting material recedes into the canvas.
3. **Calibrated rhythm:** use a 4 px implementation rhythm with deliberate
   macro intervals, shared text edges, and no accidental empty columns.
4. **Placed status language:** combine a concise state label, a restrained
   marker, and intentional placement. Do not repeat state text, dots, pills,
   and semantic color inside the same local context.

### Typography and readability

Typography is a principal visual material. These are starting hierarchy roles,
not a license to make text faint:

| Role | Starting treatment | Constraint |
|---|---|---|
| Application identity / decorative eyebrow | 10–11 px, tracked, strong contrast | 10 px is decorative-only and must remain readable in GREYWARD-DEV. |
| Page title | 36–40 px, medium weight, tight tracking | Clear first-read anchor. |
| Posture / major state | 42–52 px, medium weight | Never confused with a score or celebration. |
| Section title | 18 px, semibold | Readable structural anchor. |
| Primary item and body | 14 px minimum starting point | Required names, explanations, state, evidence, decisions, and actions remain comfortably readable. |
| Metadata / timestamp / status annotation | normally 12 px or larger | Muted but legible; never the only carrier of essential meaning. |

Validate size, contrast, line-height, wrapping, and visual weight in the real
GREYWARD-DEV application at both supported window targets. Quiet != faint.

### Material, controls, icons, and status

- Define canvas, structural plane, interactive plane, focal plane, and overlay.
  Prefer whitespace and rules; use raised material only for focal work,
  confirmation, or bounded workflow context.
- Maintain obsidian, graphite, platinum, pearl/silver, and sparse semantic
  accents. Monochrome screenshots must still look deliberate and GREYWARD.
- Use one 1.5 px rounded-stroke icon language. Icon containers appear only when
  they add structure; do not use arbitrary rounded boxes.
- Use compact explicit primary commands, quiet secondary/text/trailing
  commands, contextual row actions, and isolated destructive commands. Do not
  hide necessary interaction merely to remove buttons.
- `SECURE`, `PROTECTED`, `REVIEW NEEDED`, and `UNAVAILABLE` retain their
  existing semantics. State uses text, structure, icon/marker, and restrained
  color; `SECURE` recedes, `PROTECTED` discloses accepted context, `REVIEW
  NEEDED` directs a decision without alarm, and `UNAVAILABLE` clearly bounds
  capability.

## Page-by-page composition plan

| Page | Target reading order and focal area | Supporting information, action, and density strategy | What disappears / changes visibly |
|---|---|---|---|
| Overview | Posture → interpretation/freshness → next decision → priority ledger | Attach the valid next action to the posture interpretation; coverage and recent context become secondary registers | Split peer hero panels, metric strip, and repeated local status labels disappear. |
| Protection | Priority grouping → selected domain → its context/evidence/action | A vertical domain register with inline/full-width expansion replaces equal blocks; actions stay within the selected domain | The 2×2 status dashboard disappears entirely. |
| File Security | Definition readiness → Safe Open decision → quarantine → recent evidence | One handling flow with actions beside their consequence; use a ledger for quarantine/activity | Disconnected fact grids and stacked feature-card rhythm disappear. |
| Updates | Current transaction state → valid command → manifest → progress/restart | Treat all providers as one bounded transaction; show counts only when they affect a decision | Hero-plus-statistics telemetry treatment disappears. |
| Privacy | Local-data assurance → retention/control → profile → disclosures → history | Make data boundary and local control primary; use a longitudinal selector and disclosure ledger | Independent assurance/profile/control cards no longer compete. |
| Activity | Date/context → meaningful event → time → provider history | A quiet journal/timeline expresses time and provenance; maintain bounded history | Generic undifferentiated activity rows disappear. |
| Detail and dialogs | Meaningful fact/decision → explanation → disclosed evidence → action | Use a reading surface and progressive disclosure; dialogs are focused decision sheets | Technical values no longer dominate boxed surfaces. |

## Before/after transformation contracts

- Overview must visibly change from “status card + next-action card + metrics”
  to one deliberate posture-and-decision composition.
- Protection must visibly change from an equal 2×2 set of cards to a prioritized
  and inspectable protection register.
- File Security must visibly change from stacked feature sections to a safe
  handling workflow.
- Updates must visibly change from telemetry/cards to a coherent transaction.
- Privacy must visibly change from a collection of controls to a local-data
  contract and disclosure relationship.
- Activity must visibly change from an administrative list to a calm temporal
  record.

These changes must be obvious in screenshots without using a diff viewer.

## Interaction, responsive behavior, and states

- Use restrained 160–200 ms continuity for navigation, hover, focus, press,
  refresh, async replacement, and disclosure. Respect reduced motion.
- Preserve the shell while providers resolve; reserve the focal region, keep
  usable data during refresh, and give each empty/degraded/failure state a
  bounded explanation and relevant retry or action. Avoid giant spinners,
  developer placeholders, and disproportionate warning boxes.
- The supported default window is **1440×900 logical pixels**. The actual
  configured minimum is **1100×700 logical pixels**. These are the two required
  visual acceptance targets. Do not spend redesign effort below that minimum
  unless a separate product decision changes it.
- At the minimum, recompose rather than squeeze: reduce the navigation index to
  a compact icon form where needed, move attached actions below focal content,
  collapse side-by-side content into a readable sequence, retain action labels,
  and avoid clipped controls or giant empty columns.

## Implementation sequence

1. Establish the visual-system primitives, typography readability checks,
   semantic materials, action/status/icon rules, and the recomposed shell.
2. Recompose Overview and rebuild Protection first; inspect live screenshots
   before treating their planned metaphors as settled.
3. Recompose Files, Updates, Privacy, and Activity; refine detail and dialog
   surfaces with the proven patterns.
4. Implement responsive reflow, focus, loading, empty, degraded, action, and
   reduced-motion states without changing backend contracts or semantics.
5. Use the visual QA loop for every major surface and state.
6. Enter a mandatory **simplification-only pass**. Adding visual features is
   forbidden; remove unnecessary rectangles, repeated statuses, weak
   typography, noisy icon boxes, awkward empty space, and generic controls.

## Visual QA and acceptance

Every pass follows: implement → run installed GREYWARD-DEV → capture screenshot
at 1440×900 and 1100×700 → inspect hierarchy, readability, density, action
clarity, and desktop fit → critique → correct → repeat. Screenshots supplement
real interaction, keyboard-focus, provider, action, and degraded-state checks;
they never replace them.

Representative reviews include all canonical postures; mixed/review states;
long labels and values; empty, unavailable, stale, loading, denied, failed, and
recovered providers; valid actions and async feedback; dialogs; reduced motion;
and the normal/minimum window pair.

### Micro-change failure test

Before acceptance, ask whether changing only fonts, spacing, colors, borders,
cards, and buttons could satisfy the result. If yes, the redesign has failed:
return to page composition and information hierarchy. The visual definition of
done is a recognizably new GREYWARD Security Center generation whose important
screens do not look like refined versions of the current dashboard.
