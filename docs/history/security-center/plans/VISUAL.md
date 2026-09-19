# Visual direction

> Historical supporting context. Current visual authority: `docs/security-center/DESIGN.md`.

## Character

Security Center uses GREYWARD's obsidian/graphite/silver identity with restrained
depth, clear boundaries, and high information legibility. Security status is not
gamified. Avoid gauges, shields filled to percentages, radial scores, neon SOC
maps, terminal cosplay, threat animations, and fear-based red surfaces.

Tauri 2/WebKitGTK remains responsible for the desktop window surface while semantic HTML, CSS, and explicit Rust IPC provide the UI behavior, accessibility,
navigation, typography metrics, focus, and platform interaction. GREYWARD adds
semantic tokens and branded materials without replacing mature widgets.

## Layout

- Default desktop window: approximately 1100 × 720 logical pixels, responsive
  down to a narrow single-column layout.
- Use a responsive navigation rail and toolbar/header bar.
- Overview domain cards form a two- or three-column grid based on width.
- Detail pages use readable content widths; evidence tables can expand but must
  not force the whole window horizontally.
- Primary actions stay close to the affected check, not in a global command bar.

## Semantic treatment

Every state combines icon, label, and restrained accent:

| State | Visual intent |
|---|---|
| `PROTECTED` | cool silver/green accent, stable and quiet |
| `ATTENTION` | amber accent, review without alarm |
| `ACTION REQUIRED` | warm red accent, reserved for confirmed required failures |
| `UNKNOWN` | violet/neutral accent with question mark |
| `UNAVAILABLE` | muted neutral with capability-off icon |
| `NOT APPLICABLE` | subdued neutral with explanatory dash |

Exact colors must pass WCAG contrast in light, dark, and high-contrast contexts.
Do not encode state in background color alone. Large colored page backgrounds
are prohibited.

## Components

- **Domain card:** icon, title, state pill, reason, timestamp, and chevron.
- **Finding row:** state icon, concise summary, source/freshness secondary text,
  and optional action affordance.
- **Evidence group:** definition list or bounded table with copy buttons and
  visible redaction labels.
- **Capability notice:** neutral inset banner for unavailable, prototype, or
  hardware-gated behavior.
- **Confirmation dialog:** exact target, before/after values, consequence,
  authorization expectation, and reversibility.
- **Undo toast/banner:** affected object and countdown/expiry without implying
  rollback after the token is invalid.
- **External-service card:** owner, endpoint/operator, cadence, data, last known
  activity, and disable route.

## Motion

Use short CSS navigation transitions and subtle state replacement. No
pulsing threat indicators. Collection uses a small progress indication only
while active. Respect reduced motion by removing nonessential transitions.

## Icons and branding

Use symbolic platform icons for concepts and the canonical GREYWARD symbol for
the application identity. Do not invent independent shield branding before the
product icon is reviewed. State symbols must remain distinguishable at 16 px and
must not reuse the GREYWARD product symbol as a protection claim.

## Evidence density

Default pages remain plain-language. Technical evidence expands inline and uses
monospace only for identifiers/values, not entire panels. Long values wrap or
truncate with explicit expansion. Raw JSON is an export/debug aid, not the main
view.

## Required visual validation

Session 9 captures and reviews:

- Overview with each possible domain state.
- Mixed protected/unknown/action-required evidence.
- Missing backend, stale evidence, offline, denied, and malformed states.
- Network trust preview, Polkit wait/cancel, success, failure, and undo.
- Portal revoke/restore flows.
- Public-IP disclosure and long endpoint/operator text.
- Empty and populated Activity/Recovery views.
- 100%, 125%, 150%, and 200% scaling where supported.
- Minimum/narrow and large window sizes.
- Keyboard focus, screen-reader labels, reduced motion, light, dark, and high
  contrast.
- Long localized strings and right-to-left readiness where GTK supports it.

Screenshots alone do not constitute PASS; controls must also be exercised.
