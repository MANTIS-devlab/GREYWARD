# Security Center UX specification

Status: canonical UX and content authority. Historical UX and visual plans
provide supporting rationale; this document resolves presentation rules for
current product work.

## Product contract

Security Center answers, in this order: **Is the device OK? What needs my
attention? What can I do? What happened?** It presents measured local state,
not requested configuration or backend implementation detail. General desktop
settings remain in DMS Settings.

### Information hierarchy

1. **Immediate state** — canonical posture, freshness, and the one most useful
   next decision.
2. **Action and explanation** — the affected item, practical consequence, and
   a specific safe action or handoff.
3. **Technical details** — evidence source, identifiers, provider values,
   timestamps, and diagnostics, collapsed until requested.

Only the first level belongs in the initial Overview viewport. A fact may be
summarized on Overview and detailed in its owning contextual view, but it must
not also be repeated as a badge, paragraph, recommendation, and card.

## Vocabulary and state

### Posture

Only these labels describe the product-wide posture: `SECURE`, `PROTECTED`,
`REVIEW NEEDED`, and `UNAVAILABLE`. Internal `REVIEW_NEEDED` and
`ACTION_REQUIRED` values map to `REVIEW NEEDED`; their reason belongs in the
finding, not a competing global label. `ATTENTION` is accepted only as a legacy
serialized alias and must not be emitted by current code.

| Concept | Required language | Rule |
|---|---|---|
| Requested configuration | `Configured` / `Not configured` | Never imply it is active. |
| Measured protection | `Active`, `Inactive`, or a feature-specific verified fact | State the observed scope. |
| Capability | `Available`, `Unsupported`, `Unavailable`, `Degraded` | Name what cannot be checked or used. |
| Freshness | `Checked <time>`, `Refreshing`, `Stale` | Stale data never claims current protection. |
| Operation | `Working`, `Completed`, `Partially completed`, `Failed`, `Canceled` | Success follows authoritative re-read only. |

Use text plus an icon/marker and restrained color. Color, a dot, or a status
pill alone is never sufficient. Do not call a configured Secure DNS policy
"secure" until its effective resolver state confirms that claim.

## Navigation and ownership

Primary navigation is exactly: Overview, System security, Network security,
Privacy, and Updates. File security, Application access, Devices & recovery,
System checks, and Network activity are contextual destinations reached
from their named hub, a finding, or a related action. The primary menu has no
ordinal numbering. The frontend accepts `system` and the historical
`protection` route and normalizes both to `evidence` (System checks).

System security opens System checks directly; its contextual navigation keeps
File security, Application access, and Devices & recovery one click away.
The selected primary destination remains visible while using contextual tools.
The assessment's internal policy identifier belongs inside All checks, not in
the primary summary. Overview presents a two-column domain register with
name, state, and explanation; repeated check counts are not primary content.

Recent security activity uses the supplied digest even when it is empty. Only
an absent digest activity array falls back to local posture history; the heading
does not promise a 24-hour window for that fallback. Update history is shown
newest first with localized timestamps, five immediately visible records, and
all remaining records available in an Older update records disclosure. Missing
update names and unknown outcomes remain explicit; the UI does not reconstruct
identity or success from a version string.

## Materials and task composition

Preserve GREYWARD's silver frosted-glass identity. Navigation and primary
working panels use translucent silver gradients, restrained grain, light edges,
and depth against the dark workspace. Supporting rows remain quieter; text
contrast and selected controls must stay distinct on both materials.

Privacy profiles explain their firewall and network-identity effects before
selection, with pending/result feedback beside the choices. Recovery controls
precede device inventory; a queue appears only for actual pending or running
operations. File security prioritizes unresolved detections, keeps an active scan
visible first, and collapses deleted detections and historical activity. Application
access leads with applications needing review and discloses runtime diagnostics.

## Responsiveness and freshness

Refresh and update polling preserve the current disclosure and keyboard context.
Repeated requests cannot overwrite a busy button's original label or enable an
unavailable control. Cached mutable views show refresh activity until readback.
Local action feedback appears once beside its control; messages without a local
target use the visible application feedback surface. The whole page is not a
live region.

Scan, restore, permanent deletion, and history clearing use one modal confirmation
primitive. It names the action and consequences, initially focuses Cancel, supports
Escape and keyboard focus containment, and restores focus on dismissal. Destructive
confirmation is visually distinct. Dialogs survive background page refreshes.
Motion stays brief and honors reduced-motion preferences; silver surfaces have
an opaque fallback when reduced transparency is requested.

Page collection and privacy profile changes dispatch off Tauri's window thread. The typed
Security Context command, authorization, and confirmed-profile readback remain
unchanged; finishing a profile change cannot navigate the user away from another task.

Overview and System checks retain separate narrow payloads and may reuse their
own cached data for up to five seconds. An explicit Refresh and a refresh
of the page already being viewed always re-read the authoritative local state.
Other contextual views retain their own narrow queries and never cause an
ordinary Security Center view to make a remote request.

The interface follows the desktop-session language: `fr*` selects French and
all other locales select English. Product-owned labels, controls, feedback,
and help copy are catalogued in both languages. Backend facts and provider
evidence remain verbatim rather than being inferred or translated by the UI.
Route renderers must request that copy by semantic catalog key; literal-text
replacement over rendered markup, attributes, or live regions is prohibited.
Backend projections that need product language carry semantic copy keys,
bounded interpolation values, and any available remediation route. Overview
and Technical details consume that contract directly; neither route duplicates
check-specific copy or routing logic in the frontend. Action feedback uses the
same catalog and a product-safe error classifier, while raw provider output is
kept out of primary status surfaces.
The DMS companion widget uses Qt `qsTr()` for its owned visible copy and never
uses a provider detail as action feedback.

| Surface | Primary user task | Canonical content | Contextual detail |
|---|---|---|---|
| Overview | Understand posture and choose the next decision | posture, freshness, priority findings, direct domain access | full domain register, activity |
| System security | Review and resolve system findings | System checks with typed actions; contextual file, application, and recovery tools | complete evidence behind All checks |
| Network security | Choose a network-protection task | firewall, application connection control, Secure DNS, direct activity access | Network activity and connection evidence |
| Updates | Complete one update transaction | availability, command, real progress, restart | provider records and history |
| Privacy | Choose network privacy and control local data | explained profiles, measured network facts, local export/clear | retention and disclosure details |
| Network activity | Understand observed application connections | bounded live security activity | connection evidence and typed policy action |
| Technical details | Inspect evidence | source, timestamp, reason, identifiers | never the default posture view |

## Inventory and current cleanup targets

| Route or state | Source | Current issue to remove | Required treatment |
|---|---|---|---|
| Overview | `get_overview` | posture, review count, domain state, and explanatory copy repeat | one posture statement; one priority ledger; domain links only |
| System checks | evaluator snapshot | repeated posture and generic tutorial compete with findings | lead with actionable findings; retain complete evidence in All checks |
| Network | `get_network_protection`, Secure DNS, firewalld | product, provider, policy, and control language compete | one Network Protection surface with Firewall, Application Control, and Secure DNS |
| Applications | Flatpak and portal collectors | implementation terms and inventory density dominate | show user-relevant access first; retain raw grants as detail |
| Devices & recovery | USB and recovery evidence | read-only facts lack a clear next step | state availability and a handoff only when one exists |
| File Security | ClamAV and Security Context | prototype exposed Safe Open without a complete scan/remediation workflow | make scan scope, measured result, detection state, and recovery path explicit |
| Updates | Update Center transaction | provider telemetry competes with transaction outcome | one transaction state and one valid command |
| Privacy | local state and disclosure manifest | profile names alone do not explain consequences | show incoming-connection and network-identity effects beside each profile; keep local controls visible below |
| Network Activity | bounded OpenSnitch activity projection | generic activity history and provider details compete | prioritize application, destination, and decision; keep technical fields secondary |
| Technical details | evaluator snapshot | raw IDs/reasons are exposed as normal content | collapse by domain and identify values as technical evidence |
| Loading/error/empty/degraded | per-route IPC failures | raw or generic failure copy and inconsistent retry | state what failed, what still works, and the recovery action |

Every visible heading, paragraph, label, tooltip, dialog, success, empty,
loading, error, and degraded message is owned by its route renderer in
`tauri/frontend/app.js`; backend strings may supply measured facts, never
unreviewed primary UX copy.

Application Access is an effective-access inventory, not a Flatpak manifest
viewer. The backend resolves the manifest context first and then applies local
override additions and removals before deriving the normalized categories and
review reasons shown in the primary row. Manifest permissions and local
overrides remain separate technical detail. A complete inventory reports total,
shown, and review-needed counts; a partial inventory labels those counts as
discovered-only, and an unavailable collector is never presented as an empty
installed-app list.

Technical Details is product-first even when it exposes technical evidence:
the primary row contains a title, measured result, recorded outcome, and
recommendation. Check references, reason codes, and timestamps are in a
per-row technical record, never the identifying label of the row.

### Action inventory

| Workflow | Before | During | Verified outcome / recovery |
|---|---|---|---|
| Refresh | scope and last observation | `Refreshing`; retain prior result | current result or stale/unavailable explanation with Retry |
| Updates | affected providers, authorization, restart consequence | current item and real provider progress | completed, partial, failed, canceled, or restart-required state |
| Trust zone | active connection, old/new zone, inbound impact, undo | authorization and re-read | verified zone plus Undo where supported; denial/failure leaves prior zone clear |
| Network rule | application/destination, allow or block, persistence | `Saving rule` / `Removing rule` | re-read rule or explain that no matching policy changed |
| Secure DNS | configured mode and measured effective resolver | `Saving` / `Retrying` | measured transport/owner or a degraded fallback explanation |
| Privacy profile, export, clear | exact local data or network effect | target-specific working label | verified profile, export location, or cleared history; recovery on failure |
| Ignore recommendation | recommendation being ignored or shown again | `Recording` / `Removing` | visible working/result feedback, refreshed posture, and visible ignored context |
| Safe Open and sanitize | selected path and consequence | restricted context or copy creation | explicit result, unchanged-original statement on refusal, next step |
| Open Software | handoff destination | `Opening Software` | app opened or a concise retryable failure |

## Interaction and content rules

### Network surfaces

Network Protection is the single user-facing place for overall network health,
firewall state, application network control, and Secure DNS. These remain
separate evidence sources internally, but provider names are secondary detail,
not navigation.

Network Activity is a bounded live security view, not a generic telemetry
platform. Its default row hierarchy is **Application → destination →
allowed/blocked/unknown**. Protocol, port, and observed time are secondary.
`type` means a connection classification only when it adds information beyond
the transport `protocol`; redundant fields are omitted. Throughput, active
connection counts, DNS history, reputation, server-location enrichment, and
persistent network history are out of scope. Destination identity may include
an endpoint-country flag when Security Context resolves the observed public IP
from local GeoIP and/or geofeed sources. If sources disagree, the deterministic
best local match is still shown; a last-resort domain suffix hint is rendered
with the same compact flag geometry and explained only on hover/accessibility
text. A domain suffix is used only as a clearly weak last-resort hint; reverse
DNS, provider ownership hints, and remote lookup are not used.
Generic, private, and unknown IP destinations show a visible neutral world
marker instead of an invented country.

Activity polling updates the existing view in place. It preserves scroll,
focus, filters, expanded rows, and pause state. A pause stops visible movement
and reports newly collected rows for later review.

Network Activity has `Live` and bounded local `History` modes with the same
application → destination → decision row hierarchy. History supports
application, destination, decision, protocol, port, and time-range filters.
`type` is a semantic event classification; `protocol` is transport/application
protocol. The default row omits redundant type/protocol fields.

Overview shows unresolved findings separately from important activity in the
last 24 hours. Devices & recovery owns current external devices and seven-day
unknown-device history. The DMS plugin keeps its Security Center emblem, independent live activity
icons and unresolved-state badge; it does not load raw telemetry. Its current
visual and notification contract is in
[Live Privacy Capsule](../security-context/LIVE_PRIVACY_CAPSULE.md).

Application identity uses local desktop metadata when available or a
deterministic fallback. Domain identity never uses remote favicons, website
requests, DNS lookups, or third-party icon services. Opening this view must not
create traffic toward an observed destination.

- Label controls with a target and consequence: `Enable firewall`, `Retry
  secure DNS`, `Remove override`, `Open Software`, `Clear local history`.
  Avoid `Fix`, `Apply`, `Manage`, `Continue`, and `Resolve` without a target.
- Before a consequential action, show target, expected effect, authorization,
  reversibility, and the state that will be checked afterward. Ordinary
  reversible operations do not need a modal.
- During an action, disable conflicting controls, preserve the previous state,
  use a visible working label, and announce it to assistive technology.
- After an action, show verified effective state. Failure states say what
  failed, what remains functional, and the recovery action; technical backend
  diagnostics stay behind details.
- Recommendations are evidence-backed, actionable where supported, and removed
  or updated after the authoritative state changes. Never add scores or filler
  recommendations.
- Use direct desktop-utility copy. Delete heading repetition, generic security
  reassurance, implementation terminology, and paragraphs that describe an
  obvious control.

## Accessibility and visual rules

- All controls have an accessible name, visible focus, keyboard operation, and
  a text state independent of color or icon.
- Use readable body text (14 px baseline) and metadata (12 px baseline); 10 px
  tracked text is decorative only. Validate at 1440x900 and 1100x700 logical
  pixels with long labels and scaled text.
- Preserve GREYWARD's restrained obsidian/platinum direction. Use alignment,
  whitespace, and rules before introducing a panel; one viewport has at most
  one focal plane.
- Respect reduced motion. Announce action completion once, not every progress
  update. Technical values remain selectable and copyable after redaction.

## Runtime acceptance

The installed Labwc application must visibly launch, restore, and focus its
single window. Validate every route and relevant healthy, degraded, unknown,
unsupported, loading, working, success, failure, and stale state in
GREYWARD-DEV. Each action proves either `action → feedback → measured state`
or `action → understandable failure → recovery path`.
