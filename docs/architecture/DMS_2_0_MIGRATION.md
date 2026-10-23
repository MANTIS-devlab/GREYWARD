# DMS 2.0 desktop migration

Status: revision-7 physical successor activated with the settings-schema and
Security dashboard refresh. Fresh protected-seat and runtime-schema readback pass;
physical workflow acceptance remains pending; not release accepted.
The active production manifest remains DMS 1.6.2-26 until the candidate passes
the gates below. The old 1.6 migration tracker is historical for this new work.

## Product decisions

- Keep the protected Labwc compositor; no alternative compositor in this test.
- Strata is the sole file browser. Move Safe Open, Scan and Security Context
  actions into Strata before removing Nautilus and its extension dependency.
  Retain only the private desktop-icon component, rejecting browsing mode and
  routing folder opens to Strata. Do not install Dux Files.
- Refine the bottom taskbar and provide a reversible compact dock preset.
  Preserve custom pins, output choices, desktop positions and personal files.
- Keep GREYWARD's visual identity while exploring better materials, typography,
  spacing and motion. Use shared palette sources across the shell, Strata,
  desktop icons, Security Center and file-context presentation.
- Add Protection, Updates and Network dashboard cards, a Security tab and
  searchable existing Security Center routes. Policy and evidence stay in the
  existing typed services. Authentication never loads ordinary plugins.
- Expose functioning Labwc-compatible customization; unsupported controls remain
  explicitly unavailable. Online integrations and tracking remain opt-in.

## Delivery gates

1. Preserve the existing dirty source tree and installed system; capture exact
   RPM availability, settings, policies, integrity receipts and performance.
   A backup without exact RPMs and a restore rehearsal is not proven rollback.
2. Pin upstream v2.0.0 source/vendor/common inputs and build toolchain; assemble
   offline and port reviewed patches onto actual 2.0 components. Record removal,
   replacement or retention of every previous patch. Do not patch deprecated
   wrappers and assume that changed the implementation.
3. Port and test the matched ordinary/protected shell, Session, Application
   Security and Enrollment closure. Preserve Fedora PAM, protected input,
   output/readiness fixes, USBGuard readback and SELinux Enforcing.
4. Build matched packages and headless/visual fixtures away from the active
   physical desktop. Stage experience changes in identifiable groups.
5. Obtain the agreed activation window before closing a session, rebooting,
   suspending or changing protected runtime inputs. Preserve strict verified
   SSH recovery. Failures of login/input/protection require rollback.
6. Validate real three-screen hotplug, mixed DPI, lid, lock/Polkit, Administration,
   USB persistent approval, Strata operations/protected denials, portals,
   network/VPN/DNS, Flatpak and updates; rehearse rollback and reactivation.
7. Complete 24 hours of daily-use observation. No key/password/content/title
   recording and no scheduled automation. Report every pending scenario.

The later explicit user request authorizes a new internal ISO using the matched
physical package set. Use the image entrypoints' explicit `--dms-candidate` option;
the default release and incomplete acceptance gates remain unchanged. No public
GitHub action is authorized by this migration or by local ISO composition.
Physical migration acceptance does not establish fresh-install acceptance.
After acceptance, update candidate pipeline inputs and canonical current docs
together. Do not promote an untested candidate merely because it builds.

## Evidence tools

`tools/greyward-dev/desktop-baseline.py` captures installed metadata without
contacting the user's bus or starting a desktop client. Its explicit root backup
mode creates a new private archive preserving ACLs, xattrs and SELinux labels.
Never publish this machine-local recovery data. It does not claim performance,
visual, restore or security acceptance.

`tools/greyward-dev/desktop-performance-gate.py BASELINE CANDIDATE` compares
`greyward.desktop-performance/v1` evidence. Conditions must identify identical
hardware/output/workload/renderer/accounting. Each panel needs 30 non-auth UI
samples and p95 rendered latency in milliseconds for `first` and `repeat` modes
of launcher, dashboard, settings, control-center, security-center and strata
(keys such as `launcher:first`). Idle evidence requires at least 600 seconds.
Record idle CPU as percent of
one core and steady memory in bytes over the complete declared process groups.
Missing or incomparable evidence must not pass. CLI response time is not render
latency. The existing `dms-measure.py` provides service idle accounting only.

Regression limits: p95 grows by at most max(10%, 50 ms), idle CPU by at most
0.5 percentage points of one core and steady memory by at most 10%. Continuing
memory/subscription growth blocks acceptance. Target at least 15% improvement
in two measured slow workflows. Passing regression limits alone does not prove
improvement. Test with `python -m unittest discover -s tests -p
'test_desktop_migration_evidence.py'`, then run the repository gates.

## Initial implementation evidence

The following records initial preparation; subsequent sections supersede its
package/activation state. Current installed evidence is in `docs/STATUS.md`.

- Original staged/unstaged tracked changes are preserved in a private Git
  preservation reference and an independent file/patch backup. Work proceeds in
  the attached isolated migration worktree.
- The physical reference still selects DMS 1.6.2-26. Installed DMS, Files and
  Session RPM verification is clean; SELinux reports Enforcing.
- A private recovery archive and metadata receipt were captured without changing
  a service or session. Exact old RPM availability and restore rehearsal remain
  pending at capture time. All seven exact previous RPM versions have since
  been staged privately and their digests verified. Six match installed files;
  Context differs only at its mutable application-network policy, covered by the
  configuration backup. No restore/reinstall has been performed. Only the
  internal display was connected at the original capture.
- The existing Fedora builder is now unlocked and reachable. Builds run as an
  unprivileged account on its existing dedicated disk, with bounded memory/CPU,
  a private network namespace and only loopback enabled for HTTP test fixtures.
  No desktop package was installed there. A verified Go 1.27.3 archive supplies
  this build only; the host compiler and active desktop remain unchanged.
- Initial source work provides literal-argv Strata actions through its existing
  native command-action mechanism, avoiding an extra provider process or Rust
  menu fork. The companion supports fixed `--safe-open` dispatch and does not
  turn missing launch/scan evidence into success. Files 19 / Center 116 are
  source candidates only. Nautilus remains installed until real parity passes.
- The separate `environment/production/dms-2.0-candidate.json` pins upstream
  v2.0.0/API 38, DCommon and the Go toolchain. Its backend inventory and exact
  patch preimages assemble successfully. Retained patches cover Labwc popout
  reclamation, output readiness, grouped minimize, tray/Flatpak icons, quiet
  protection notifications and desktop shortcuts. Native dock spacing and
  startup-lock recovery replace the older corresponding patches.
- The initial offline RPM build passed all upstream Go tests and the USB helper
  tests. The first attempts exposed overly long Unix socket paths and disabled
  loopback in the build fixture; short private paths and loopback-only networking
  resolved these without skipping tests. A later candidate adds managed settings
  routing also passes the full build. Its RPM digest/payload checks pass, with
  all 1,613 shell files and the binary matching the generated receipt. Native
  managed-settings routing and the complete protected Lock component load in
  private headless Labwc; this is not an installed-desktop visual review.
- `environment/session/dms-2.0/` owns reviewed added QML. Its closed file map and
  hashes are included in the assembled receipt. Account creation, protected
  authentication and update pages route to a truthful GREYWARD managed page,
  including direct settings navigation. Ordinary desktop appearance options
  remain native. Protected appearance customization is not yet implemented.
- The protected 2.0 adapter retains native PAM/Polkit flow handling, one protected
  entry field, masked multi-output mirrors, Administration coordination and the
  USB approval IPC. Exact 2.0 preimages are distinct from the validated 1.6 pins.
  The private headless Labwc focus test passes; removing late keyboard-entry
  restoration fails its negative control. This is synthetic input, not physical
  keyboard, PAM, Polkit or installed SELinux/session acceptance. The protected
  profile/config namespace initially used schema 29 (later corrected to 42; see
  the settings-schema follow-up below) and separate
  root-prepared config/state/cache/data roots preserve the 1.6 profile and avoid
  automatic legacy migration. All six Linux profile/clipboard fixtures, fifteen
  desktop fixtures and fifteen authentication fixtures pass. The complete
  matched installed package closure and live validation remain pending.
- Explicit incomplete-candidate receipts fail startup, selection-only and
  compatibility projection before RPM/IPC operations. The build-only revisions
  cannot activate. The later physical-trial receipt explicitly records its test
  scope and incomplete release acceptance; the production 1.6 selector is unchanged.
- Local checks: 25 focused tests pass (evidence 7, file actions 6, DMS build
  inputs 10, preference preservation 2), Bash syntax and both repository gates
  pass. The unchanged Safe Open backend suite was also attempted on Windows:
  six tests pass and eight error because Linux `os.O_PATH` is unavailable.
  The full fourteen-test Safe Open suite subsequently passes on Fedora. This
  does not establish installed GUI, isolation or physical acceptance.
- Explicit LF rules for desktop entries, audit rules, environment/TOML files and
  production zsh inputs prevent a fresh Windows checkout from manufacturing
  failures in the existing static checks. No check has been disabled.
- Preparation was committed locally as `acb4075`; signing uses the native
  Windows OpenSSH agent successfully. No publication was performed. Source
  work continues in the migration branch; the physical reference remains on
  its validated packages. Plugin/dashboard integration, coherent theme adapters,
  Strata-only browsing, exact RPM rollback/restore rehearsal, performance,
  activation and the complete live/24-hour acceptance remain pending.

## Native 2.0 experience adapters — source/headless stage

`environment/session/dms-2.0-plugins/` is the reviewed candidate plugin source;
the active 1.6 plugin directory stays unchanged. The package recipe selects one
explicit directory and checks its closed source map before bundling it.

- Security Center is a native composite plugin: one daemon owns the existing
  typed Context/USB requests, taskbar surfaces share its lease and pending-action
  state, and a Security tab and bounded launcher routes reuse the same owner.
  Protection, Network and Updates are native dashboard cards. Missing individual
  evidence remains unavailable; overall posture does not certify networking or
  update status. Mutations remain in the existing protected service/helper.
- Native Material controls/theme roles replace the custom taskbar buttons and
  fixed colors. One summary watcher and coalesced revision signals serve all
  views. This removes duplicated reads by construction; performance gains have
  not been measured. Network Identity keeps its shared in-memory ownership and
  saved opt-ins; new/default external lookups start off.
- The explicit private headless fixture loads the taskbar, Security tab, cards,
  launcher, Network Identity, traffic and Software surfaces without QML binding
  errors. Two taskbar views and dashboard surfaces reference the same client;
  stale synthetic USB requests refuse before invocation. The real native loader/registry also resolves the preset cards, tab and launcher;
  unload/reload keeps a single daemon with live references. Physical multi-output
  and real authorization acceptance remain pending.
- The protected derivative replaces the pinned native plugin loader with an
  empty read-only service. Even transitive first-touch cannot discover ordinary
  QML plugins there. Its complete native Lock component verifies that the empty
  loader is active in the private headless fixture. The ordinary loader is
  unchanged.
- The ordinary migration snapshots all four XDG roots before invoking the
  unchanged upstream directory migration. Conflicting generations refuse before
  any merge, and exit status alone is insufficient: directory identity is read
  back. A real unprivileged 2.0 binary passes movement/repeat/backup fixtures.
  Only exact previous system-plugin copies are reconciled after backup; edited
  copies are preserved. Compatibility of customized 1.6 plugins remains a user
  review requirement.
- Session 26 is the current trial source candidate. Its new experience preset seeds the Security
  tab and three cards only where no layout exists, preserves empty/custom
  layouts, pins, explicit plugin opt-outs and ordinary idle preferences, and
  leaves weather/location/lyrics/animated-cover discovery opt-in. Native update
  polling is parked; refresh/apply/cancel route to GREYWARD Update Center.
  Runtime readiness derives the API from the verified selected receipt and
  recognizes both socket naming generations, rejecting an old backend for API
  38. Matched package construction and activation remain pending.


## Desktop browsing boundary candidate

The third pinned PCManFM source patch rejects browsing CLI arguments, leaves
FileManager1 ownership to Strata and routes folder/mount requests to the fixed
Strata executable with encoded URI arguments. A failed launch cannot fall back
to another browser. Desktop preferences and the validated multi-output code
remain available. Translations are packaged in its private asset directory,
removing the RPM dependency on the public PCManFM application and its extra
terminal/sudo front ends. Native linked routing/output tests pass;
actual installed Strata action parity is still required before Nautilus removal.
The linked fixture checks exact decoded destinations because GIO and Qt encode
a legal semicolon differently. Literal arguments, spaces, option-shaped names,
empty requests and failed launches retain the Strata-only boundary.
The exact Files 19 RPM executable also passes a separate private three/two/three
output run, private D-Bus ownership and rejection of browsing requests. Its
inherited unsupported-CLI path exits zero with a warning; this is not used as
approval or file-operation success evidence. These are synthetic tests, not
physical multi-screen acceptance.

Files construction uses a separate read-only Fedora build root on the dedicated
build disk because development headers would upgrade host runtime libraries.
Dependencies are acquired into that root; compilation is unprivileged and has
no host network or application bus. The builder's installed libraries stay
unchanged. Build-root-only package scriptlet warnings are not desktop activation
or release validation.


## Shared palette candidate

The 23 October physical appearance capture extends the candidate experience
preset with the full active bar configuration and global launcher/clipboard
appearance. It preserves the native background choices: Security Center,
clock and power retain one background; other widgets are bare. Only monitor
selection is generalized to all displays; hardware identifiers and a disabled
experimental bar are excluded. Fresh accounts receive it before shell startup;
established account preferences remain authoritative.

Fresh DMS 2.0 taskbars also pin native Settings (`dms_settings`) after Brave,
Black Box and Strata. `greyward-dms-session-migrate` owns this default in
Session 34. Existing pin lists, including intentionally empty lists, remain
user-owned; the reference account already has this pin. The legacy generation's
default list is unchanged. Image staging compares the packaged pin helper with
source, so an older helper cannot satisfy the candidate input contract.

The native plugin adapter forwards the existing Background option to both
pill orientations. Security Center supplies content and a keyboard focus ring,
without another filled capsule. Its icon size follows the native bar scale.
The built-in Settings launcher uses a standalone silver gear SVG. Public-IP
refresh keeps the last in-memory identity and flag, while failure/opt-out still
clear it and cold start has no remembered address. The protected lock profile
uses the canonical GREYWARD wallpaper, independently of mutable desktop state;
this change requires the normal protected migration and fresh login.

R6 follow-up: the physical reference retained an unowned native DMS theme with
darker surfaces than the first generated image. The canonical palette now has
closed native `dms.dark` overrides for that reference appearance; common
application surfaces remain unchanged. Session 32 takes ownership of the system
theme. Its new-account Overview grid matches the reference; established user
layouts, including intentionally empty ones, still win. Candidate image staging
compares both theme copies and the Overview preset with actual RPM payloads.
The explicit built-Session fixture rejects changed theme/preset inputs.

The ordinary shared client keeps a rich snapshot through a positive aggregate
fallback only until its original fresh deadline. It never renews authority or
suppresses new negative evidence. Aggregate-only Network state is unavailable,
not a fabricated review finding. Private native expiry, warning and pending-action
fixtures pass. The later supplied R6 report confirms the RC1 tuple and a working
Protected session presentation; the user no longer observes flapping. Its
separate system fallback reports reviews during the two-minute capture, without
identifying the checks. These non-simultaneous observations do not prove status
agreement or the original transient cause. The candidate fix is still undeployed;
theme/Overview settings were absent from the report. See current status for
the captured evidence and remaining activation/media gates.

The canonical desktop palette generates closed adapters for native DMS roles,
Strata Obsidian/Silver themes, the private Qt desktop style and Security Center
semantic tokens. This retains Security Center's established dark treatment;
light mode there and automatic cross-application mode synchronization are not
implemented. Body labels and semantic text meet 4.5:1 contrast in both generated
palettes. The approved icon artwork is unchanged.

Strata's exact previous factory theme is backed up once before refreshing its
colors. Customized files, selected themes and symlinks are preserved. Silver is
added as an optional theme. Generated-adapter closure, contrast, preference and
backup tests pass; rendered and installed multi-output review remain pending.

Earlier DMS 2.0 revision 1 and Session 24 build iterations succeeded on the
isolated builder. The completed build-only set uses DMS 2.0.0-2, Session 25,
Files 19, Center 116, Application Security 71 and Enrollment 62. These distinct
identities keep earlier experimental artifacts from being mistaken for the
matched migration set. All six packages now build, including their normal RPM
checks. DMS passes its upstream Go and helper checks; Center/Application Security
retain the explicitly ignored privileged fixtures as untested. No check was
disabled to obtain the builds. The separate compiler sandbox preserves real
root ownership on read-only system code, uses a private ext4 fixture directory,
and runs compilation with an ordinary UID and zero capabilities. Root runtime
libraries on the builder were not upgraded.

RPM digests, selected payload/source closure, 55 private desktop translations
and transfer hashes pass. The physical reference accepts the complete six-RPM
dependency/conflict transaction with `rpm --test`; no installation occurred.
Context 108 remains unchanged. Current-generation native shell/plugin/focus
fixtures pass, as do 59 Linux source contracts and 98 frontend UX checks.
Three connected/enabled DRM outputs and stored output profiles are captured
privately. The existing exact factory Strata theme matches the guarded refresh
preimage; customized themes still remain untouched.

The earlier private recovery archive restores to an isolated directory and
passes GNU tar content/metadata comparison (3,306 members). No live file was
overwritten or restored program executed. This proves archive extraction, not
an installed rollback, policy recovery or a consistent quiescent snapshot.
Final quiet-state capture, rollback/reapply rehearsal, real performance,
physical activation and daily-use acceptance remain pending. Revision 2 still
refuses activation.

The first physical-trial successor was DMS 2.0.0-3 / Session 26 / Files 19 / Center 116 /
Application Security 72 / Enrollment 63 / Context 108. Its explicit
`physical-migration-test` activation scope is separate from `releaseAccepted`,
which remains false with recovery, physical, performance and daily-use gates
open. The verifier rejects a malformed trial or a trial pretending that those
release gates have passed, and still requires the installed compatibility tuple.
The protected derivative carries the same trial classification. This permits a
deliberate test selection after the user-approved window; it does not promote
the production selector or authorize interrupting a session. All four successor
RPMs build with normal checks; the unchanged Files/Center RPMs are reused with
their exact prior hashes. The complete staged trial passes the physical
reference's dependency/conflict dry run, and exact prior RPMs pass a separate
reinstallation/downgrade dry run. Neither transaction was applied.

The successor's 1,613 shell files, 20 plugin files, executable and selected
Python/session payloads match their source/receipts. Its packaged authentication
assembler preserves the trial and incomplete-acceptance metadata. Current native
shell/plugin tests pass; protected focus passes with an intentionally broken
negative control. All 36 POSIX authentication/profile/desktop fixtures pass on
Fedora, plus six real-CLI state fixtures and 41 offline-image source contracts.
The POSIX ownership fixture is unavailable on Windows and was not relaxed to
make it pass there. Physical input/authorization and installed recovery remain
open. Final capture, activation and any later rollback/reapply test still require
the user's separately approved session-interruption window.

The unchanged installed seat returns `verified: true` through a fixed read-only
PID-1-started verifier before activation. Direct invocation from the SSH recovery
domain cannot read protected process metadata and is not an equivalent check;
that denial must not be repaired by weakening policy. This sampled seat readback
does not certify the new trial's input, authorization, graphics or performance.


## First physical activation — sampled seat verified

The user approved the activation window and logged out to the unchanged greeter.
A final quiet-state archive covers both policy stores, prepared desktop and
Administration inputs, application state, user preferences and USB/firewall
configuration. The policy database main/WAL/journal and key receipts did not
change across capture; all 5,131 archive members restore/compare privately.
This is stronger than the earlier running-session archive, but still does not
prove an installed rollback/reapply.

The six matched RPMs were installed after hash and transaction checks. The fixed
protected-shell migration assembled the 2.0 derivative, applied the existing
scoped USB approval policy/labels and refreshed authentication/session receipts.
All 1,642 prepared-file hashes and the Administration cross-reference match.
The selected DMS verifier and installed RPM verification pass. Only the security
workflow broker was restarted after daemon reload, while the user was logged out.
SSH, greetd, USBGuard, Polkit and firewalld remain active; SELinux is Enforcing.
The USB persistent rule file is unchanged. The independent greeter, SSH access
configuration and production/ISO selector were not changed. No reboot or hot
compositor restart occurred.

The ordinary four-root migration loaded at the first normal login; the active
seat returns `verified: true` through the fixed PID-1-started read-only verifier.
Broker request/reply headers and kernel credentials show ordinary enrolled-user
coverage, device and Administration reads returning normally. Root-domain
activity reads are rejected at their caller boundary; this does not authorize
relaxing that boundary. No request bodies, password input or window content
were captured.

Physical input/authorization and multi-output acceptance remain pending. Strata
action parity and the later public-browser removal, rollback/reapply, actual
rendered performance and daily-use gates also remain open. No synthetic result
substitutes for those tests.

## Protected settings-schema follow-up

The first active native session reported schema 42. An explicit regression test
against the actual pinned `Common/SettingsData.qml` fails on the initial protected
profile (`29 != 42`). Its read-only settings would otherwise replay upstream
migrations at login. The corrected profile uses 42 for the explicitly reviewed
2.0 successor, retaining 18 for 1.6 and refusal for unreviewed generations. The
assembler now refuses absent, malformed, duplicate or changed native schema
declarations against the manifest pin. Fixture tests cover those refusals; the
actual-source test prevents tests and profile from agreeing on a wrong constant.

The schema-only revision-5 packages pass private payload/native checks. The next
schema-only matched source tuple includes the Strata launcher correction: DMS 2.0.0-6 /
Session 29 / Files 20 / Center 116 / Application Security 75 / Enrollment 66 /
Context 108. The intermediate revision-4
build was rejected before deployment after an unintended text-encoding diff;
its artifacts are historical, not usable migration inputs. The four successor packages now build with normal checks, pass payload/source
closure, 104 private native/profile/source tests, six actual-CLI fixtures and the
physical reference dependency/conflict dry run. They are staged but not installed.
The protected correction still requires a newly approved quiet window; do not
replace protected inputs in the active session. The production
selector stays on 1.6 and release acceptance stays false.

## Strata launcher regression

The first physical user report identified a nonstarting Strata. Exact installed
wrapper bytes contain `0d 0a` in the shebang: kernel execution fails before the
seeder or native ELF starts. ELF dependencies resolve and package verification
alone passes because the malformed bytes were packaged. A scoped private backup
and atomic LF correction retain ownership, executable mode and SELinux label
without changing policy or restarting the session. The user confirms Strata
opens after the correction.

Files 20 fixes the extensionless launcher checkout attribute and normalizes its
installed script. RPM checks execute both source and packaged wrappers directly
through the kernel, with only the two fixed callees replaced by synthetic stubs;
they preserve interpreter bytes and literal argv. A CRLF negative control raises
the same missing-interpreter error. This gate complements ELF/desktop routing
tests, which previously bypassed the public launcher. Files 20 builds with its normal checks and passes all three kernel-wrapper
tests. The extracted exact RPM desktop passes three-two-three output
reconciliation, private bus ownership, no public FileManager1 ownership, browsing
refusal and absence of missing Qt signals in an isolated headless seat. It is
installed on the physical reference with clean RPM verification and a fresh
protected-seat `verified: true` readback, without an explicit service restart or
session change. The wrapper has the same hash as the user-confirmed fix; opening
the rebuilt native payload remains to confirm. This is not installed Strata action
parity or physical visual acceptance.

## Security dashboard visual follow-up

The requested candidate refresh gives Protection, Network and Updates native
semantic colors: fresh confirmed protection is green, review/unavailable/loading
is amber, and explicit failures/critical findings are red. Text and distinct
status glyphs accompany every color. The taskbar gains a small status dot while
retaining the approved shield identity. Static vector emblems, subtle tinted
surfaces and a compact footer replace the empty card treatment; no downloaded
artwork, shader, looping animation, new observer or polling loop is introduced.

Cards reuse the single existing client and bounded summary. Protection displays
reported device protection, pending items and privacy indicators. Network exposes
firewall, application-filtering and available DNS details separately; a positive
firewall alone cannot make the complete card green. The v1 legacy detail display
vocabulary is matched exactly and conservatively, with explicit state taking
precedence if supplied. Unknown/localized values and stale evidence stay amber.
System-default DNS is a configuration fact, not an invented encryption claim.

Updates displays actual reported activity or failure. The idle summary does not
provide last-check results or update counts, so the card says Check updates in
amber and routes to Update Center. Overall Protected never becomes Up to date.
No permission, policy, authentication or notification-delivery behavior changes.

The shared canonical palette generates the state-color JS adapter. Contrast
checks cover both modes and the actual tinted surfaces. Seven Node cases guard
state precedence, scope, missing data and expiry. Three native plugin fixtures
cover the actual loader/shared client and dark/light compact relayout, rejecting
binding/layout errors. Private synthetic dark/light renders have been visually
reviewed; they do not establish installed visual acceptance.

The matched visual successor is DMS 2.0.0-7 / Session 30 / Files 20 / Center 116 /
Application Security 76 / Enrollment 67 / Context 108. It retains schema 42 and
supersedes the staged revision-6 set and installed revision-3 trial.
All four packages build with normal checks and pass staged hash and
dependency/conflict validation on the physical reference. The 1,613 shell files
and 22 plugin files match their receipts. Full code-input comparison covers
363 Application Security source files; only six Cargo TOML manifests differ
by LF/CRLF, with both normalized bytes and parsed objects proven identical.
The native/profile/source/palette suite passes 108 checks, plus six real-CLI
fixtures and seven Node cases. No source check accepts a CR in an interpreter
line. After explicit user approval, the four packages and canonical protected
migration were applied while the physical reference was already at the greeter.
All 1,642 prepared-file digests and the Administration cross-reference verify;
selected DMS and installed RPM verification pass. The broker was reloaded within
that quiet window. SELinux remains Enforcing, recovery services remain active
and persistent USB rules are byte-identical. A fresh 6,559-member quiet archive
passes isolated extraction and metadata/content comparison; this is not an
installed rollback/reapply rehearsal. The fresh-login fixed seat verifier returns
`verified: true`; actual protected settings use schema 42 and remain root-owned,
read-only. Real keyboard authorization, Strata reopening and installed visual
acceptance remain required. No forced session closure, reboot or hot compositor restart
occurred. No GitHub publication or ISO promotion is authorized.

## Network card VPN correction

The first package-only correction below is historical; the cache follow-up
supersedes its installed version and reload state. Current facts are in status.

Physical readback found healthy OpenSnitch `OPERATING`, a secure evaluated
firewall check, zero network checks to review and VPN-owned DNS. The card's old
positive vocabulary omitted `OPERATING`, producing an incorrect amber headline.
The model now recognizes that exact state. With both controls confirmed and no
actionable findings, VPN-owned DNS produces a green `VPN active` card and a DNS
ownership detail. Informational events do not become outstanding reviews. Actual
warnings/actions/failures still override VPN information; stale or missing
filtering evidence remains amber. No full-tunnel, DNS-encryption or kill-switch
guarantee is inferred.

The follow-up targets DMS RPM 2.0.0-7.2, preserving installed Enrollment 67,
runtime/protected generation `v2.0.0-7` and all other installed packages.
`build.rpmRelease` separates the ordinary-plugin package correction from the
unchanged runtime identity. A pinned three-executable payload check gates the
predecessor's exact runtime provide; extracted runtime, helpers and shell must
also be byte-identical before installation. Enrollment is not updated on the
running desktop. Fresh-image staging retains its strict matched-package check:
new Enrollment 69 targets the new package pin, with separate future clean-install
acceptance. The image component identity guard consumes the same package pin.
DMS 7.2 is now installed: full RPM/selector validation and the unchanged active
protected seat pass. The only payload changes are the card model, plugin version
and release receipt. Protected receipts, Enrollment inputs and USB rules remain
unchanged. Ordinary-shell reload and physical color/text confirmation remain pending.
No ISO or public publication is authorized. Installed readback is recorded in
[current status](../STATUS.md).

## Compiled-card cache follow-up

The user reported old card visuals after the ordinary-shell reload. The runtime
and installed source were current, but the compiled cache for the exact card URL
contained the old implementation. Reproducible RPM source timestamps had not
changed. Removing the stale file alone did not refresh a process still mapping
it. The current ordinary launcher therefore sets `QML_DISK_CACHE_PATH` to a
namespace named by the verified receipt digest. This preserves caching and
rollback namespaces, and leaves the separate protected authentication runtime
unchanged. `tests/test_dms_qml_cache.py` exercises the real wrapper with same-mtime
receipt updates, warm-key reuse, XDG fallback and preservation of old caches.
Its optional native Quickshell replay is explicitly unavailable when that
fixture emits no disk-cache units; no warm-cache replay success is claimed.

DMS 2.0.0-7.3 / Session 31 are installed, with Enrollment 67 retained through the
exact unchanged-runtime provide. Source-built Enrollment 70 is the new matched
image input and remains undeployed on the active desktop. After reloading only
the ordinary shell through its existing user service manager, new processes map
the current compiled design and VPN model from the expected receipt namespace.
The same login and protected seat remain verified, with SELinux Enforcing and
protected receipts/USB rules unchanged. Physical visual confirmation is pending.
See [current status](../STATUS.md) for package and validation evidence.

## Previous patch disposition

| 1.6 patch | 2.0 candidate disposition |
| --- | --- |
| `apps-dock-spacing` | Native per-dock item spacing/padding controls; no equivalent fork. |
| `apps-dock-taskbar-labels` | Native rewritten dock/bar settings terminology; visual acceptance pending. |
| `apps-dock-toggle-minimize` | Ported to actual `DockAppButton` grouped-window implementation. |
| `greyward-flatpak-icon-resolution` | Ported active export discovery and icon search roots. |
| `greyward-labwc-runtime` | Ported bounded closed-popout reclamation; performance unmeasured. |
| `greyward-security-notifications` | Ported quiet popup/audio/history behavior and severity grouping; native visual cards retained. |
| Settings curation | Update authority retained; managed account/auth pages added; remaining visual curation still under review. |
| `greyward-tray-icon-fallback` | Ported icon resolution/fallback to current tray owner. |
| `launcher-canonical-hitbox` | Old wrappers no longer canonical; actual 2.0 launcher/dock hitbox acceptance pending. |
| `polkit-auth-dialog` | Ordinary floating-dialog geometry is not used by the protected owner; protected native-control adapter is tested separately. |
| `greyward-native-lock-recovery` | Native startup checks both locked state and locked hint; full lock/recovery acceptance pending. |
| `greyward-wlr-output-readiness` | Ported response-based readiness and bounded retry. |
| `greyward-desktop-shortcuts` | Ported verified helper workflow to actual dock context menu. |

Every pending entry remains an acceptance requirement. This table records source
choices, not proof that the physical workflow has passed.

### 23 October protection-first refinement

The successor uses neutral graphite cards and functional semantic accents,
removing oversized background decoration. Network filtering remains the primary
assessment; explicit VPN Active/Off is secondary and does not control its color.
The existing Context projection supplies bounded observed VPN state, including
split VPN and stale/missing-evidence cases. The canonical Rust collector now
requires independent live firewall readback for confirmed offline sessions;
network absence alone no longer creates a provider-loss result. It never turns
probe failures into successful observations or changes overall aggregation.

The future matched source tuple advances DMS to 7.6, Center to 118, Context to
110, Application Security to 78 and Enrollment to 73. Protected generation 7
remains pinned. The ordinary live update may retain protected AppSec 76 /
Enrollment 67; the protected broker's compiled fallback is updated only in a
separate matched activation window. Main shell presentation uses the canonical
unprivileged posture helper. Build/installed evidence belongs in current status;
source changes do not establish physical offline or release acceptance.

The first follow-up Center 117 build failed the payload audit: its standalone
posture helper was unchanged and returned UNKNOWN for a known-offline canary.
It was not deployed. Canonical Center/AppSec packaging now rebuilds first-party
release executables explicitly, keeping dependency caches. A spec-execution
regression models stale old-mtime executables, and an isolated packaged-CLI
canary checks confirmed offline versus failed NetworkManager/firewall probes.
DMS 7.4 / Center 117 / AppSec 77 / Enrollment 71 artifacts are retained as
non-admitted build evidence, not installed or release-accepted versions.

Installed refinement: DMS 7.5 / Center 118 / Context 110 retains protected AppSec
76 / Enrollment 67. Context 110 compares VPN evidence after provider collection
while preserving the original posture sample/lease. Actual readback confirms
PROTECTED, OPERATING, SECURE network check and ACTIVE VPN; the bound card model
shows Protection active with VPN active secondary. Root services/configuration,
protected inputs/USB rules and protected process identities are unchanged; fresh
seat verification passes. The future metadata-matched DMS 7.6 / Enrollment 73
builds separately for image staging, with AppSec 78; normal builds and
source/hash closure pass. Physical offline/user design
acceptance remains unclaimed. See current status for complete scoped evidence.

### Matched physical activation and internal ISO

The later approved quiet window installs DMS 7.6 / AppSec 78 / Enrollment 73
alongside Center 118 / Context 110 / Session 31 / Files 20. The canonical migration
confirms existing protected generation-7 inputs already match. A fresh login then
passes the fixed protected-seat verifier, broker executable identity and ordinary
shell cache-namespace checks. Root recovery/network services and USB rules remain
unchanged; SELinux is Enforcing. Current facts supersede the earlier retained
protected-package tuple above.

The requested 0.5.0 DMS2 RC1 ISO uses explicit candidate selection, the fresh
portable physical baseline and those exact matched component artifacts. Factory
networkless dependency/Flatpak installation, extracted production-stage checks,
Windows transfer SHA-256 and the 40-path media contract pass. All eight embedded
first-party RPM hashes agree with the reviewed inputs. Composition does not close
fresh-install, physical workflow, performance, recovery or daily-use acceptance.
See current status for the immutable artifact hash; no public release is claimed.

The subsequent RC2 uses source `f208e15` and the installed DMS 7.9 / Session 34 /
AppSec 79 / Enrollment 76 follow-up. It incorporates the captured appearance,
darker palette, native Settings pin/gear, larger security emblem, protected
wallpaper, native widget backgrounds and application cleanup. Its new portable
baseline, canonical offline factory checks, extracted payload and copied Windows
media checks pass, including all 16 first-party RPM copies. Current status owns
the exact artifact identity. Fresh-install and hardware acceptance remain open;
RC1 is retained and neither candidate is a public release.
