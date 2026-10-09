# Security Center UX specification

## Targeted truthfulness correction — source only, 9 October

The verified session baseline covers enrolled execution routes and registered
resource labels. `deputies_and_portals=false` means **not independently verified**;
it is no longer derived from seat/labels or required to display that narrower
baseline. It does not authorize generic portal/Flatpak grants. Portal attribution
and complete deputy isolation remain UNKNOWN and are explicitly disclosed.
Accepted deviations retain their measured check state and visible limitation;
only recommendation aggregation suppresses repeated attention. Acceptance never
activates Secure Boot, a TPM, recovery or another missing safeguard. Overview's
PROTECTED label refers to verified protections with accepted limitations, not
“All required protections are active.” Reviewed access is labelled SSH key
inspection; generic native/Flatpak/script/IDE access remains unavailable.

These are source changes with local regression evidence, not a new `.149`
installed tuple. See the [scoped receipt](../history/security-center/2026-10-09-security-truthfulness.md)
for validation limits and matched deployment/rollback requirements.


Status: canonical UX and content authority. Historical UX and visual plans
provide supporting rationale; this document resolves presentation rules for
current product work.

## Product contract

Security Center answers, in this order: **Is the device OK? What needs my
attention? What can I do? What happened?** It presents measured local state,
not requested configuration or backend implementation detail. The quiet graphite navigation rail groups labelled tasks and scrolls at small window heights. General desktop
settings remain in DMS Settings.

The focused quality pass preserves this navigation and its typed workflows.
Structural planes use neutral graphite with local grain and restrained silver
edges; the activity ledger is compact without shrinking essential text.
Distinct navigation, resource/provider and operation symbols follow the shared
registry in `app.js`. Marks explain function, never security trust. See
[DESIGN.md](DESIGN.md) for the durable material and icon rules.

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

Current navigation is grouped by the task, with one owning destination for each
workflow. `workspace.css` owns the shell/navigation; `styles.css` owns feature
composition. `materials.css` centralizes tokens and material/interaction rules;
its installed Center 72 package passes actual EN/FR desktop visual review.
Product copy is
catalogued in EN/FR.

| Group | Destination | Responsibility |
|---|---|---|
| Home | Overview | Measured posture, prioritized actions, domain links and concise session protection. |
| Protection | Applications | Registered native tools, real protection/grants, isolation launch and visible Flatpak permissions. |
| Protection | Protected Data | Registered resource categories, actual coverage, descriptor registration, reviewed grants/revocation. |
| Protection | Files & scans | Scanning, detections, quarantine and shared Safe Open. |
| Protection | Network security | OpenSnitch, firewall, Secure DNS and contextual threat blocking. |
| Protection | System & devices | System checks and a contextual Devices view for USB/camera/microphone evidence. |
| Monitor | Network Activity | Dedicated connection monitoring with existing live/history, pause, filters, details and pagination. |
| Monitor | Security History | Local non-network policy, file, device, update and recovery events. |
| Maintain | Updates | Existing reviewed transaction, progress, restart and update history. |
| Maintain | Backup & recovery | Recovery points, personal backup, verification/restore and real queued operations. |
| Preferences | Privacy & data | Network privacy choices, retained local data, export and clearing. |

Network Activity retains canonical route `activity`, its own narrow network
query and live subscription. It never embeds Application Guard or other security
history. `history` uses the existing telemetry database, with `scope=SECURITY`
excluding NETWORK before the limit/cursor. It does not certify live protection;
only the existing kernel-evidence contract can render a sensitive denial as
confirmed. Unknown outcomes remain unknown. Provider unavailability is distinct
from a valid empty history. Categories and older/latest navigation use bounded
queries, with independent query identities so old filter responses cannot replace
the current view. Application/resource details keep relevant contextual events.

Recovery has canonical route `recovery`, reusing the existing device/recovery
read projection and typed actions; it is absent from Devices. Network policy has
one edit workflow. Applications exposes provider permissions in a visible section
without inventing native identities or equating Flatpak permissions to Guard
coverage. `system`/`protection` remain aliases for `evidence`; existing routes and
contextual links are preserved. Selected parents remain visible for devices and
threat-blocking views. No presentation change broadens authority.

The assessment's internal policy identifier belongs inside All checks. Overview
presents current posture first, a compact authoritative session summary and domain
register. Background renewal preserves the current focus/disclosures and withdraws
positive session state when its lease expires. The sidebar uses the shared Security
Center shield, centered above its branding, with larger navigation labels. The
former local-security footer is removed; navigation uses the remaining height and
scrolls when necessary. Protection status remains in authoritative page summaries.

Recent security activity uses the supplied digest even when it is empty. Only
an absent digest activity array falls back to local posture history; the heading
does not promise a 24-hour window for that fallback. Update history is shown
newest first with localized timestamps, five immediately visible records, and
all remaining records available in an Older update records disclosure. Missing
update names and unknown outcomes remain explicit; the UI does not reconstruct
identity or success from a version string.

## Materials and task composition

Preserve GREYWARD's silver frosted-glass identity. Primary working panels use translucent silver gradients, restrained grain, light edges,
and depth against the dark workspace. Supporting rows remain quieter; text
contrast and selected controls must stay distinct on both materials.

Privacy profiles explain their firewall and network-identity effects before
selection, with pending/result feedback beside the choices. Recovery has its own maintenance destination; a queue appears only for actual pending or running
operations. File security prioritizes unresolved detections, keeps an active scan
visible first, and collapses deleted detections and historical activity. Application
access leads with applications needing review and discloses runtime diagnostics.

## Responsiveness and freshness

Refresh and update polling preserve the current disclosure and keyboard context.
Application Guard renewal uses the earliest actual provider lease and the
measured complete-read cost, with a transport margin. Unchanged fresh state
renews expiry without replacing the page; changing evidence age alone is not
a product state change. A real failed read or expired lease still withdraws
positive protection. Background inventory reads pause during reviewed
authentication/operations and never extend cached authority.
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
| System & devices | Review and resolve system/device findings | System checks with typed actions and contextual Devices | complete evidence behind All checks |
| Network security | Choose a network-protection task | firewall, application connection control, Secure DNS and threat blocking | linked dedicated Network Activity |
| Updates | Complete one update transaction | availability, command, real progress, restart | provider records and history |
| Privacy | Choose network privacy and control local data | explained profiles, measured network facts, local export/clear | retention and disclosure details |
| Network activity | Understand observed application connections | bounded live security activity | connection evidence and typed policy action |
| Technical details | Inspect evidence | source, timestamp, reason, identifiers | never the default posture view |

## Historical audit inventory and retained treatment rules

The issues below are the earlier audit rationale, not a list of current regressions. The navigation and ownership table above is current.

| Route or state | Source | Historical issue | Retained treatment |
|---|---|---|---|
| Overview | `get_overview` | posture, review count, domain state, and explanatory copy repeat | one posture statement; one priority ledger; domain links only |
| System checks | evaluator snapshot | repeated posture and generic tutorial compete with findings | lead with actionable findings; retain complete evidence in All checks |
| Network | `get_network_protection`, Secure DNS, firewalld | product, provider, policy, and control language compete | one Network Protection surface with Firewall, Application Control, and Secure DNS |
| Applications | Flatpak and portal collectors | implementation terms and inventory density dominate | show user-relevant access first; retain raw grants as detail |
| Backup & recovery | USB and recovery evidence | read-only facts lack a clear next step | state availability and a handoff only when one exists |
| File Security | ClamAV and Security Context | prototype exposed Safe Open without a complete scan/remediation workflow | make scan scope, measured result, detection state, and recovery path explicit |
| Updates | Update Center transaction | provider telemetry competes with transaction outcome | one transaction state and one valid command |
| Privacy | local state and disclosure manifest | profile names alone do not explain consequences | show incoming-connection and network-identity effects beside each profile; keep local controls visible below |
| Network Activity | bounded OpenSnitch activity projection | generic activity history and provider details compete | prioritize application, destination, and decision; keep technical fields secondary |
| Technical details | evaluator snapshot | raw IDs/reasons are exposed as normal content | collapse by domain and identify values as technical evidence |
| Loading/error/empty/degraded | per-route IPC failures | raw or generic failure copy and inconsistent retry | state what failed, what still works, and the recovery action |

Every visible heading, paragraph, label, tooltip, dialog, success, empty,
loading, error, and degraded message is owned by its route renderer or shared
presentational module; backend strings may supply measured facts, never
unreviewed primary UX copy.

Application Access is an effective-access inventory, not a Flatpak manifest
viewer. Flatpak supplies the effective context with system/user global/app
override precedence already applied. The backend summarizes that context into categories and
review reasons shown in the primary row. Effective context and local
overrides remain separate technical records; a lower-priority override is never reapplied. Permission-read failure is unavailable, not a scoped sandbox. Explicit absolute filesystem grants are disclosed as additional file access. Environment values are excluded from the access projection. A complete inventory reports total,
shown, and review-needed counts; a partial inventory labels those counts as
discovered-only, and an unavailable collector is never presented as an empty
installed-app list.

Technical Details is product-first even when it exposes technical evidence:
the primary row contains a title, measured result, recorded outcome, and
recommendation. Check references, reason codes, and timestamps are in a
per-row technical record, never the identifying label of the row.

### Application Security workflow scope

Current source provides descriptor/category registration, native persistent
READ grant review/apply/cancel/revoke, isolated ELF/script/AppImage launch and
private graphical ISOLATED. Show exact resources, generation, scope and risk;
in-process extensions share raw grants. Revocation readback cannot recall
already-read contents. WRITE/timed access and unsupported handlers are
unavailable, not disabled buttons implying an installed working provider.

Overview protection remains independent of operation success: UNKNOWN when
whole-session evidence is missing, UNAVAILABLE for missing providers, DEGRADED
for incomplete coverage. Ordinary denied accesses use existing Security History and
aggregated Review/Dismiss presentation, no instant Allow or malware inference.
Safe Open uses the shared runner and refuses protected-label copying; configured
Flatpak handlers are unavailable pending a native provider, without substitution.

EN/FR source contracts and actual normal-session registration, reviewed
key-inspection grants, repeated launch and GUI revocation pass. Unsupported tool
profiles remain unavailable. See [current evidence](APPLICATION_SECURITY_PLAN.md).
The current shell/navigation CSS is consolidated. Further feature-component
extraction, exhaustive CSS cleanup and broader accessibility/release matrices
are DEFERRED HARDENING. [Production enrollment](APPLICATION_SECURITY_ENROLLMENT.md)
is a proposed administrative lifecycle, not a current onboarding flow.

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
last 24 hours. Devices owns current external devices and seven-day
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

## Contextual Security History

`security-history.js` owns the shared event row used by Security History and
application/resource activity. The collapsed row shows the recorded actor or
an explicit unknown process, a relevant application/functional glyph, action,
registered-resource label, outcome and evidence-supported explanation. The
compact disclosure reveals historical process metadata, attribution limits,
source, references, policy revision at collection and occurrence time.

Kernel executable basenames are observed processes, not verified applications;
no brand is guessed for them. Registry names are resolved through bounded typed
reads and described as labels at refresh. Missing/deleted/unreadable labels do
not hide events. Older unattributed records remain unknown. Successful policy
operations say completed, never that data access was allowed. Sensitive blocks
require the existing correlated kernel-denial contract and offer Review only.
Local presentation activity remains distinct from enforcement evidence.
Network Activity retains its existing independent owner and connection view.

## Runtime acceptance

The installed Labwc application must visibly launch, restore, and focus its
single window. Validate every route and relevant healthy, degraded, unknown,
unsupported, loading, working, success, failure, and stale state in
GREYWARD-DEV. Each action proves either `action → feedback → measured state`
or `action → understandable failure → recovery path`.
