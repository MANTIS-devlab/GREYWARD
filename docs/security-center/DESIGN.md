# GREYWARD Security Center — Durable Design System

## Purpose and authority

This document defines the durable experience and visual-system decisions for
GREYWARD Security Center. It governs semantic presentation, readability,
material, interaction, responsive behavior, and visual review. Current page
composition belongs in `UX_SPEC.md`; superseded composition plans are retained
under `docs/history/`.

The installed GREYWARD-DEV application is the final visual authority. Do not
consider a written layout complete because it was implemented faithfully. When
real rendering demonstrates a clearer, quieter, more premium, or more usable
solution, update this document if the decision is durable and retain the
supporting evidence in the historical session record when appropriate.

Security Center remains a native-feeling first-party GREYWARD desktop product,
not a dark web administration dashboard. Preserve native Labwc server-side
decorations; do not introduce a custom titlebar or a second window-chrome
system.

## Product truth and presentation boundaries

Security Center presents evaluated posture and explanations. It
does not recompute posture, invent security truth from display strings, change
security logic, or turn provider absence into a failure claim.

| Posture | Meaning | Presentation intent |
|---|---|---|
| `SECURE` | All applicable recommendations are satisfied; no unresolved review items or ignored recommendations remain. | Calm, stable confidence; never celebratory or gamified. |
| `PROTECTED` | No unresolved review decision exists; one or more ignored recommendations remain. | Stable, with ignored context visibly available. |
| `REVIEW NEEDED` | A condition requires a human decision. | Clearly decision-oriented without alarmism. |
| `UNAVAILABLE` | GREYWARD cannot reliably determine posture. | Honest capability boundary with a useful explanation. |

Specific backend reasons—such as recommendation, accepted deviation, degraded
capability, stale evidence, denial, threat, or remediation—explain the
canonical posture. They are not competing global posture labels. Color never
forms the only state signal.

Only existing, supported backend actions may appear as controls. Each action
must communicate its target, consequence, authorization expectation, progress,
and verified outcome. Unsupported actions are absent or explicitly unavailable.

## Experience principles

- Establish understanding before decision, action, and feedback.
- Give each major viewport one obvious focal purpose; supporting information
  must visibly recede without becoming difficult to read.
- Keep valid actions close to the relevant condition, not in an unrelated
  global command area.
- Prefer plain language and progressive disclosure over technical density.
- Treat unavailable, stale, partial, failed, and accepted states as meaningful
  context; do not hide them or make them sound more severe than they are.
- Do not use scores, grades, percentages, threat counters, fear-based red
  surfaces, neon SOC metaphors, or security theatre.
- Do not add a surface merely because a backend component exists.

## System voice

Visible copy uses the calm, direct language of a native desktop utility. Name
the current state, the user decision, or the available action first. Prefer
short functional titles and verbs such as `Review`, `Open`, `Check`, `Retry`,
and `Clear`. Remove slogans, self-congratulatory claims, and implementation
language from normal surfaces; terms such as evaluator, provider, transaction,
backend-authoritative, and evidence-backed belong only in technical details or
documentation when they are necessary for accuracy. Do not repeat the same
state in a heading, badge, and action. Quiet means restrained hierarchy and
good spacing, never faint text.

## Readability and typography

Quiet does not mean faint. Quiet is achieved with contrast, hierarchy,
alignment, line length, and intentional space—not with small type or low
contrast.

- Required state, evidence, explanations, decisions, action labels, timestamps
  that establish freshness, and controls must remain comfortably readable in
  the real GREYWARD-DEV runtime.
- Tracked 10 px text is decorative-only: it may be used for truly
  non-essential eyebrow information and must still be visibly readable.
- Primary item names and body copy start at a comfortable 14 px scale; metadata
  normally starts at 12 px and is never the sole carrier of essential meaning.
- Page titles are clear first-read anchors; major posture may be larger, but it
  remains textual rather than score-like. Section titles create structure;
  micro-labels do not replace headings.
- Validate rendered type at the normal and minimum supported windows. CSS
  values alone do not prove readability.

## GREYWARD visual language

GREYWARD uses an AMOLED-black canvas, graphite, platinum, pearl/silver, restrained off-white,
and sparse semantic accents. Its identity comes primarily from composition,
proportion, type, material hierarchy, and exact alignment. It must remain
recognizable in a largely monochrome screenshot.

Normal supporting copy uses a deliberately readable cool-silver contrast, and
only decorative labels may use the quieter metadata tone. Light/platinum
controls always use a near-obsidian foreground for text and icons in default,
hover, pressed, disabled, and working states; a pale control must never rely on
opacity for legibility. Semantic accents remain markers and labels, not filled
regions or the sole expression of a security state.

The reusable signature is:

1. **Precise metallic rules:** platinum-toned baseline rules and shared edges
   establish structure without enclosing every group.
2. **One active plane:** a major viewport has at most one raised/focal material;
   supporting information stays close to the canvas.
3. **Calibrated rhythm:** implementation follows a 4 px spacing rhythm with
   deliberate macro intervals, not arbitrary gaps or empty columns.
4. **Placed status language:** a concise state label, restrained marker/icon,
   and intentional location communicate state without repeated dots, pills,
   labels, and color in the same local context.

### Material hierarchy

Use five semantic material roles:

- **Canvas:** the quiet obsidian application field.
- **Structural plane:** no fill; grouping comes from alignment, whitespace, and
  fine rules.
- **Interactive plane:** transparent at rest; hover, pressed, and focus clarify
  affordance without creating a card.
- **Focal plane:** restrained raised graphite/silver material reserved for the
  current posture, consequential workflow, or explicit decision.
- **Overlay:** bounded confirmation, detail, or modal material that clearly
  separates temporary work from the underlying canvas.

The signature frosted material is a translucent light-grey plane with a fine
platinum edge and dark shadow over the black canvas. It is reserved for
navigation, current posture, and consequential work; it must preserve its
contrast when compositor or webview blur is unavailable. Blur is enhancement,
never a prerequisite for legibility.

Cards, borders, gradients, blur, and transparency are optional tools. Use them
only when they clarify a relationship. Equal-weight card grids must not be used
as a default organization device.

### Icons, actions, and status

- Use one coherent 1.5 px rounded-stroke icon registry. Use containers only
  when they add structural meaning; never use emoji, arbitrary Unicode, or
  mixed icon styles.
- Primary actions are compact, explicit commands. Secondary actions are quiet
  text, trailing, inline, or contextual commands when their target is clear.
  Destructive actions remain explicit and isolated.
- State presentation combines text, position/structure, marker or icon, and
  restrained semantic color. Avoid redundant `SECURE` + green dot + `SECURE`
  patterns.
- Focus is consistently visible and keyboard interaction remains as clear as
  pointer interaction.

## Composition and responsive behavior

Composition is task-led. Use typography, edges, whitespace, and progressive
disclosure before introducing a container. Do not preserve a layout because it
is convenient to implement; do not preserve named compositional metaphors when
real rendering shows a better result.

The supported desktop targets are the configured default **1440×900 logical
pixels** and configured minimum **1100×700 logical pixels**. Do not optimize
below that minimum unless the product deliberately changes its supported window
size. Between those targets, recompose rather than squeeze:

- compact the navigation index without losing clear labels or accessible names;
- move attached actions below focal content when horizontal competition harms
  reading;
- sequence adjacent content vertically when its columns no longer have useful
  width;
- retain readable action labels, safe wrapping, and visible focus; and
- avoid clipped controls, orphaned commands, squeezed cards, and giant empty
  columns.

## Motion and operational states

Motion improves continuity rather than decoration. Use restrained, short
transitions for navigation, hover, focus, pressed state, refresh, async
replacement, and disclosure. Respect reduced-motion preferences by removing
nonessential movement.

Loading, empty, degraded, denied, failed, and recovered states are first-class
surfaces. Preserve useful content during refresh, render a useful shell while
optional providers resolve, bound loading, clearly explain capability limits,
and provide a relevant retry or next step. Avoid giant spinners, developer
placeholders, raw technical status, and disproportionate warning boxes.

## Visual quality gate

Use the real GREYWARD-DEV loop: implement → launch/relaunch → capture at
1440×900 and 1100×700 → inspect hierarchy, readability, density, controls, and
desktop fit → critique → correct → repeat. Screenshots complement real
keyboard, action, provider, and degraded-state checks; they do not replace
them.

Before acceptance, apply the micro-change failure test: if altering only fonts,
spacing, colors, borders, cards, or buttons could satisfy the result, the work
is not a deep redesign. Finish with a simplification-only pass: add no new
visual features; remove redundant statuses, unnecessary rectangles, weak
micro-typography, noisy icon boxes, awkward empty space, and generic controls.
