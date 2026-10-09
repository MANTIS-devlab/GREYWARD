# Architecture

## Context

Security Center is a standalone Tauri 2 Rust application with a presentation-only webview. It coexists
with canonical DMS v1.6.2 on Labwc. Native DMS locking remains canonical.
DMS Settings owns generic desktop/system settings;
Security Center owns GREYWARD-specific security and privacy workflows and does not
duplicate the generic settings surface.

## Component model

`window-chrome.js` owns persistent, accessible client-side controls outside
route refresh; `window-chrome.css` extends the same canvas without a header
separator. `window_chrome.rs` accepts only fixed main-window actions. Native
Tauri handles moving/minimizing/maximizing/closing; the pinned GTK runtime
supplies compositor resize drags. It grants no security-policy or process
execution authority. Application scrolling is inside `#app`, leaving the
controls fixed and preventing content from scrolling underneath them. The
Labwc SVGs remain canonical; `tools/generate-security-center-window-controls.ps1`
copies/verifies the bundled artwork without independent redesign.

The navigation shell stays mounted across route changes; only route content is
replaced, and navigation listeners bind once. Activity/scan callbacks belong to
both the current visit and operation, so late responses cannot replace a newer
view. Guard renewal uses the earliest provider deadline, measured read cost and
a transport margin; it does not extend evidence leases or cache kernel proof.

Overview posture/coverage is independent of optional recent history.
`get_overview` returns history as `LOADING`; the bounded, asynchronous
`get_overview_activity` reuses the existing Context history reader. The frontend
updates only the disclosure body, preserving its focus/open state. Failures stay
`UNAVAILABLE`, rather than becoming an apparently empty history. This changes
presentation scheduling, not posture evaluation, authorization or event storage.

Current presentation composition is owned by [UX_SPEC.md](UX_SPEC.md).
`app.js` retains route/read lifecycle and existing typed actions;
`application-security.js` owns bounded reviewed operations and fresh projections;
`application-view.js` renders their evidence. `security-history.js` renders a
bounded SECURITY query from the existing telemetry store. Network Activity keeps
its independent live/history collector, state and route. `workspace.css` is the
single shell/navigation style authority; feature components remain in
`styles.css`. Neither navigation nor historical outcomes authorize access or
establish protection. Backup/recovery reuses its existing typed backend instead
of adding another owner.

```text
Tauri application (unprivileged webview + Rust facade)
        |
        v
Security domain + deterministic evaluator
        |
        v
Typed capability adapters
   | user APIs       | upstream system D-Bus/Polkit    | read-only libraries
   v                 v                                 v
Portals/Permission   NM, firewalld, fwupd, DNF5       SELinux, block/boot facts

V1 shell surface:
DMS Secure plugin -> SecurityContext1.GetShellSummary / typed shell actions
                      -> unprivileged Security Context -> normalized providers

Additional narrow root owners (Secure DNS and experimental Application Security):
UI -> typed adapter -> narrow GREYWARD system D-Bus service -> Polkit
```

The existing `ClamAvScan1` system-bus adapter is a narrow post-V0 exception for
bounded File Security scan and remediation operations. It is not a general
command or filesystem API; its product contract is defined in
`FILE_SECURITY.md`.

The Tauri process always runs as the logged-in user; the webview has only explicit commands. The Tauri facade calls the Security Context through typed session D-Bus values and parses only the returned typed JSON payload, never human-readable `gdbus` output. Adapter output is typed facts;
only the evaluator maps facts to posture. UI components never execute backend
commands or infer protection from display strings.

## Application Security source boundary

The [delivery authority](APPLICATION_SECURITY_PLAN.md) distinguishes current
source from the installed tuple. The [enrollment design](APPLICATION_SECURITY_ENROLLMENT.md)
has approved decisions and actual normal-account development admission on
`.149`. A root-owned matched compositor, generated auth-only native DMS shell
and separate Fedora helper domains protect authentication. Fresh root readback
checks real session/user-manager/SSH roles, scope, immutable generation,
authentication readiness, kernel decisions and registered labels. Tested
key-inspection grants pass normal-session deny/allow/revoke. See the
[normal-session receipt](../history/security-center/2026-10-08-application-security-normal-session.md).
Automatic production lifecycle and clean-image acceptance remain unvalidated.
No existing unconfined desktop is protected merely because SELinux
is enforcing or a broker process is running.

```text
Center typed facade → Security Context owner-pinned adapter → root broker
Guard CLI / Safe Open ────────────────────────────────────────┘
  broker → shared identity/revision/database → fixed kernel policy provider
         → prepared immutable code/selected document → native worker
         → SELinux + Landlock + namespaces + seccomp + private display
  authoritative denials → Context ingestion → existing telemetry/publisher
```

The following default/private-bus description is historical foundation behavior
from 7 October, superseded for the normal `.149` account by the normal-session
receipt above. It is not the current live coverage/activation state.

The default `systems.mantis.greyward.ApplicationSecurity1` service is inert
until explicitly started and exposes five reads: applications, one application,
coverage, resources and one resource. The separate development bus name
`systems.mantis.greyward.ApplicationSecurityDevelopment1` uses the same fixed
interface/object and implements registration/grant/revocation reviews,
authorized apply, operations and prepared launches. Its policy, resource and
worker provider remains fixed to isolated UID 1002 in the installed development
entry point. Source adds per-owner bindings and serialized enrollment dispatch,
but no production enrollment, live coverage or multi-user kernel proof exists.
On `.149`, the explicitly enabled installed workflow unit now runs that same
dispatcher on the public bus/store. An isolation-only binding permits normal
local users to prepare restrictive workloads, with no resource/grant mutations.
Separate typed capability flags are not enforcement evidence. Root-owned scratch
parents remain private; explicit internal modes withstand umask 0077 and PID 1
mounts the disposable home in the worker namespace. Display binding verifies the
actual UID and pinned Labwc peer. See the
[live receipt](../history/security-center/2026-10-07-application-security-live-development.md).

The source Context/Tauri allowlist contains typed reads and workflows, not a
generic forwarding or root execution API. Root-owner pinning, kernel peer
identity, bounded responses, exact generation/revision, fresh owner Polkit
review and readback protect mutations. The root schema-four source database holds
policy intent, original-label and enrollment journals, not a second event history.
Opening an older production schema refuses until explicit offline migration;
the future lifecycle coordinator must preserve rollback inputs first.
Stored intents and available transport do not establish protection. Current
read snapshots use absent enforcement evidence: UNKNOWN with no effective
profile. Missing/changed broker, stale or invalid data invalidates the lease.

Descriptor-held directory registration labels supported objects and verifies
policy/object readback. Tested native tools can reuse reviewed persistent READ
access through root-prepared immutable entry and disjoint subjects, only when
installation/code generation, resource scope and policy revision still match.
The initial profile is nonexporting SSH key inspection; generic legacy grants
cannot activate or launch. Unsupported tools remain unavailable. Revoke uses the
grant reference and verifies held/new read denial. WRITE/timed raw grants,
approved-source update trust and automatic full inventory population remain
unavailable. In-process extensions share raw grants; already-read data cannot
be recalled. The current generated denial covers the test ordinary subject;
production must cover all enabled subjects and preserve grant-only transitions.

Managed ELF, fixed interpreter scripts and validated Type-2 AppImages share
`isolated_launch.rs`, `payload.rs` and `greyward-native-worker`. Worker readiness
verifies UID/capabilities, SELinux, private namespaces, Landlock ABI 9 and
seccomp before exec. Graphical isolation creates a private nested Labwc and
clipboard/Xwayland over a broker-created host security-context connection.
No unrestricted host socket, host X11, session bus or network is exposed to
the payload. Host security-context alone does not provide private clipboard.

Safe Open retains the selected descriptor through classification and native
handler preparation into this same runner. Protected-label copying is refused;
there is no standalone bubblewrap or unrestricted fallback. Configured Flatpak
selected-document handlers return UNAVAILABLE until a native provider preserves
their portal/sandbox semantics. Flatpak effective-context collection and scoped
registry intake preserve existing overrides and explicit incomplete evidence;
provider permission mutation and production population remain pending.

`access_events.rs` normalizes bounded root AVC/failed-syscall resource denials.
Runtime 27 includes historical kernel PID/basename and audit time; application
attribution remains UNKNOWN. Context 70 strictly validates this additive metadata
and retains the existing telemetry/privacy boundary. `security-history.js` owns
the contextual row shared with application/resource activity, resolving bounded
registry labels for presentation only.
Context writes existing telemetry; the existing router publishes aggregated
Review/Dismiss items with UNKNOWN attribution. No instant Allow, malware
inference or audit-completeness claim is introduced. Rotation/buffer gaps are
reported; raw-byte backlog and kernel-loss accounting remain incomplete.

Shared `application-view.js` components present one coverage summary, searchable
Applications, grouped Protected Data, contextual details and local activity.
Stored grants stay separate from effective enforcement. Tested-profile metadata
passes through domain/Context/Tauri validation into structured GUI reviews.
The source UI adds descriptor/category selection,
READ-grant review/apply/cancel/revoke, private isolated launch and related
Activity. Source workflow and private GUI review/cancel pass scoped tests;
the original private-only Center 59/Context 64/runtime 15 statement is historical.
Normal-account resource/grant/revocation and confined-session validation is
recorded in [the current implementation authority](APPLICATION_SECURITY_PLAN.md).
Production lifecycle acceptance remains unvalidated.

Fixed read/provider workers bound admission, response sizes and caller waits.
Capacity remains occupied until stalled work exits; timeout alone cannot cancel
kernel-stalled filesystem work. Saturation is explicit failure, not an empty
safe inventory. Prepared isolated workers provide the separate hostile-code
execution boundary. A frontend wait expiry never claims backend cancellation.

Frontend startup instrumentation and request wait handling live in bundled
`startup.js` and `request-adapter.js`. Script CSP allows bundled self-origin
scripts without an inline-script exception. Request timers are cleaned up on
success, failure, synchronous transport throws and expiry. Expiry ends only the
presentation wait: it does not cancel backend work, and the EN/FR message says
the operation may still be running. A stale Updates poll cannot overwrite a
later visit to the same route. Full route/controller/component separation is
still planned; these modules introduce no frontend framework or extra authority.

## Rust workspace boundary

The repository-local `security-center/` workspace uses these package boundaries:

- `greyward-security-domain`: enums, check definitions, evidence types,
  evaluator, serialization, redaction, and application-security wire types;
- `greyward-security-backends`: asynchronous typed adapters and interface
  version checks;
- `greyward-security-center`: Tauri application facade, frontend, and user actions;
- `greyward-application-security`: shared policy/broker/worker source, with an
  explicitly separated development provider;
- fixture/test packages kept non-privileged except explicit owned Fedora tests.

Dependency direction remains domain ← backends ← UI. The broker owns policy;
the presentation and adapters never acquire that authority.

## Collection flow

1. The app creates a presentation request generation and wait deadline. Actual
   backend cancellation requires a provider operation that supports it;
   frontend timeout alone does not cancel collection or a mutation.
2. Independent read-only adapters run concurrently with per-backend timeouts.
3. Adapters validate and normalize bounded evidence without selecting posture.
4. The evaluator applies versioned check policy and freshness rules.
5. The UI receives an immutable snapshot and renders all states, including
   backend failures.
6. A redacted bounded snapshot is persisted atomically for startup context.
7. D-Bus change signals or relevant lifecycle events invalidate only affected
   checks and trigger debounced recollection.

Opening the app must not refresh package metadata, firmware metadata, public-IP
data, or any other network source automatically. Network-bearing refreshes are
separate, labeled user actions.

The Network Activity page uses a narrow `GetNetworkActivity` user-bus query
over the existing redacted OpenSnitch projection. It retrieves session-local
sequence deltas and bounded decision summaries. Approved redacted events also
enter the separate bounded GREYWARD telemetry history through the read-only
`QueryTelemetry` and `GetRelatedTelemetry` methods; this adds no telemetry
daemon, remote enrichment, packet history, or unrestricted journal access.

## Control flow

V0 controls use upstream APIs directly:

1. The UI constructs a typed request from a selected authoritative object.
2. The adapter re-reads current state and prepares a preview with expected
   effect and prior value.
3. The user confirms from an active local session.
4. The adapter invokes the upstream D-Bus method; upstream Polkit owns any
   administrative authorization.
5. The adapter re-reads the same object and verifies the expected predicate.
6. Success and bounded undo are offered only after verification.

Network rule actions preserve the selected application and optional destination
scope through the typed UI → Tauri → Security Context contract. The UI refreshes
the authoritative rule projection after a verified backend result; a callback
alone is not treated as evidence that a rule exists.

No common “execute,” “write file,” or “run as root” interface exists.

## V0 backend ownership

- NetworkManager remains owner of connection profiles.
- firewalld remains owner of firewall zones and nftables policy.
- fwupd remains owner of firmware metadata and operations.
- DNF5 remains owner of package metadata and transactions.
- Portal services remain owner of user permission stores.
- systemd-journald/audit sources remain native evidence owners; GREYWARD's
  approved normalized history is retained separately under the telemetry
  contract.
- USBGuard remains owner of USB policy when installed.

Security Center reads, explains, and invokes only explicitly supported methods.
It never edits those backends' configuration files behind their APIs.

## DMS integration

V0 installs a desktop entry named by the application ID and relies on DMS's
normal application index. There is no panel placeholder and no DMS fork.

The production DMS Secure plugin is a small first-party presentation surface.
It consumes only the versioned GREYWARD user-bus contract:

```text
systems.mantis.greyward.SecurityContext1
  GetShellSummary() -> greyward.security.shell/v1 JSON
  Refresh() -> normalized context summary
  SetPrivacyProfile(s) -> typed verified result
```

The shell contract exposes no raw evidence or arbitrary mutation. The taskbar
is a glanceable posture icon with one contextual badge; the flyout is a curated
snapshot and privacy-profile quick control. Investigation, evidence, history,
network rules, USB trust, threat remediation, and complex update actions stay
in Security Center. If the snapshot is stale or the monitor is absent, the
plugin displays `UNAVAILABLE` rather than preserving stale security truth.

The packaged `greyward-security-center-route` helper accepts the current
Security Center route model and writes a bounded per-user navigation request.
The already-running single instance consumes, focuses, and routes that request;
unsupported destinations fail deliberately instead of being silently remapped.

## Approved privileged Secure DNS exception

The hardened `systems.mantis.greyward.SecureDns1` system-bus reconciler is the
one GREYWARD-owned privileged exception admitted for Secure DNS. It talks only
to NetworkManager and systemd-resolved, applies measured per-link DoT/DNSSEC,
preserves VPN and split-DNS ownership, and exposes verb-specific methods
through the unprivileged Security Context. It never provides generic command
execution or global resolver configuration. Runtime mutation is active by
default; `/etc/greyward/secure-dns-read-only` is the explicit emergency
read-only rollback path.

Recovery V1 is the separate fixed-path Polkit helper exception described in
`PRIVILEGE_MODEL.md`; it is limited to local Btrfs point creation and cleanup
and is not exposed through the Security Context bus. Other new privileged
helpers remain future work and require that gate.

## Failure behavior

- One adapter failure cannot crash the app or erase other domain results.
- Timeouts cancel work and return typed `UNKNOWN` evidence.
- Missing services remain visible as `UNAVAILABLE`.
- Version mismatch disables only the affected capability.
- A failed or unverifiable control never reports success.
- A corrupt local snapshot is ignored and replaced only after a successful
  collection; it cannot influence authorization or backend mutation.

## Packaging and supply chain

Build a conventional Fedora RPM from pinned Rust dependencies with a recorded
source lockfile. The separate `greyward-security-context` RPM owns the
approved Secure DNS service and its typed D-Bus contract; it must not modify
PAM/boot/authentication, install a second resolver, alter DMS configuration, or
create generic root execution.
