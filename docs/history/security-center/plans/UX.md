# User experience

> Historical supporting context. Current UX authority: `docs/security-center/UX_SPEC.md`.

## Experience goals

Security Center should feel calm, exact, and useful. It presents the most
important truthful next step without manufacturing alarm. A user can understand
the headline without Linux expertise and inspect the underlying source without
leaving the application.

## Navigation

Use a responsive Tauri navigation rail:

- **Overview** — six domain cards, highest-priority findings, last observation,
  and refresh state.
- **System** — SELinux, boot, firmware, TPM, kernel, and updates.
- **Applications** — sandbox availability, Flatpak posture, portals and grants.
- **Network** — connection trust, firewall, DNS, and VPN presence.
- **Data** — storage encryption and future capability placeholders only as
  clearly labeled roadmap information, not active controls.
- **Devices** — hardware capability and read-only USB trust visibility.
- **Privacy** — external services, retention, exports, and permission grants.
- **Activity** — bounded recent normalized security-relevant events.
- **Recovery** — readiness evidence and trusted handoffs.

On narrow windows the sidebar becomes navigation pages without losing the
current location. Deep links use stable page/check IDs and degrade to Overview
when an optional capability is absent.

## Overview

The header shows “Device posture” with a semantic state and timestamp, never a
score. Six domain cards contain:

- domain name and semantic state;
- one-sentence reason;
- number of actionable/unknown checks only when it aids navigation;
- freshness indicator; and
- activation target for the domain page.

The priority section orders confirmed `ACTION_REQUIRED`, then `ATTENTION`, then
required `UNKNOWN`. `UNAVAILABLE` is visible but not dramatized as a threat.

## Check detail

Every check detail provides:

1. State and plain-language summary.
2. “What this means,” limited to the verified protection.
3. Evidence with source, observation time, freshness, and redaction indicators.
4. “What GREYWARD can do” showing control, handoff, recommendation, or no safe
   action.
5. Capability status and why the result may be unavailable.
6. Technical details, collapsed by default.

Never put technical source strings in the headline. Never hide evidence behind
a green status.

## Refresh

Local refresh is explicit but does not prompt or access the network. The UI
shows per-domain progress and allows cancellation. Existing results remain
visible with a refreshing/stale label.

Any refresh that could access remote metadata is a separate action with provider
and network disclosure. V0 may omit such refresh controls rather than blur this
boundary.

## Network trust-zone flow

1. User selects the active connection in Network.
2. The UI shows the current upstream zone name and its practical scope.
3. “Change network trust” lists installed supported zones with upstream names
   and explanations; it does not invent a universal safe choice.
4. Preview identifies the exact connection, old/new zone, expected inbound
   impact, and undo availability.
5. User confirms; the upstream Polkit agent may authenticate.
6. Progress is modal only for the operation, not the application.
7. Success appears only after re-read verification and offers Undo.
8. Cancellation, denial, timeout, owner restart, or mismatch shows a precise
   non-success state and refreshes evidence.

Advanced zone creation, rules, ports, or panic mode are not shown.

## Network Protection flow

Network Protection is application-oriented. It leads with OpenSnitch health,
then groups observed applications, recent connection outcomes, and bounded
rules. Domain is shown before IP/port/protocol; raw technical detail is
progressive disclosure. Allowed, blocked, and unknown results remain distinct.

firewalld is shown as a separate system/inbound source and is never presented
as proof that OpenSnitch application interception is operating. If either
source is stale or unavailable, the UI names that source and its degraded
capability.

Typed GREYWARD policy actions are limited to application or
application-plus-destination allow/block rules. Primary connection decisions
remain one-time in the conceptual model; persistence is an explicit “remember”
action. Current upstream rules are read-only unless GREYWARD ownership and
authoritative mutation are confirmed. Interactive prompts remain deferred
until their full daemon lifecycle is validated.

## Portal permission flow

Applications shows verified grants grouped by application and resource category.
Unknown PermissionStore tables are not decoded. Revocation confirmation explains
the immediate effect and how the app can request access again. Document grant
revocation explicitly says the underlying file is not deleted. After mutation,
the entry is re-read and a bounded Restore action is offered where valid.

## Privacy view

The external-service section always includes the enabled GREYWARD public-IP
widget disclosure from `PRIVACY.md`, including both providers, trigger/cadence,
cached data, necessary network disclosure, and DMS disable route. Viewing this
page must not make a provider request.

The page also exposes Security Center local-state categories, clear-state
control, and export preview. It separates “GREYWARD component,” “Fedora/backend,”
and “user-enabled service.”

## Activity

Activity is a short chronological explanation, not a threat counter. Filters are
fixed categories and a bounded time range. An empty state says either “No events
were visible in this period” or “This source is unavailable,” never “No threats.”
Selecting an event opens normalized detail and, when appropriate, the related
check.

## Recovery

Recovery lists readiness facts: encryption observed, recovery mechanism status
when safely knowable, firmware-update readiness, and documented recovery paths.
It never displays or validates secret recovery material in V0. Handoffs explain
that completion occurs outside Security Center and requires re-collection.

## Error and unavailable states

- Missing backend: explain what is absent and whether installation is a future
  product decision; do not offer terminal commands.
- Permission denied: explain that evidence could not be read; do not loop Polkit
  for read-only collection.
- Stale: show prior time and make clear it is not current.
- Malformed/version mismatch: disable only that capability and invite support
  export.
- Offline: continue local checks and distinguish cached update metadata.

## Accessibility

- Full keyboard navigation with predictable focus and no pointer-only action.
- Accessible names include domain/check and state, not color descriptions.
- State icons have text labels; color is never the only carrier.
- Screen readers announce collection/action completion without repeatedly
  announcing live progress.
- Respect reduced motion, text scaling, high contrast, and system font choices.
- Confirmation/default focus avoids accidental destructive activation.
- Technical evidence is selectable and copyable after redaction.
