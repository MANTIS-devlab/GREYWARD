# GREYWARD current status

## 24 October publication preparation

The owner authorizes updating the sanitized public source and uploading the
latest existing ISO. [RC3 notes](patch-notes/0.5.0-dms2-rc3.md) record the exact
artifact, its package tuple and outstanding acceptance. RC3 predates Center 120 /
Context 112 notification work; source publication does not add those packages
to the existing ISO. No successor image is being composed for this request.
Public export now masks forward-slash Windows paths as well as backslash paths.
An exact upstream QML preimage false positive is scoped to its one pinned hash
in the secret-scanner configuration; all other scanner checks remain active.

## Security/privacy notifications installed — 24 October

The physical reference now runs Center 120 / Context 112 with Application
Security 82 / Enrollment 79 unchanged. Verified security updates and a prepared
restart can produce daily reminders; microphone/camera start notices are opt-in
in Privacy, off by default, and retain the continuous activity indicators. VPN
interruption notifications are excluded; existing VPN status is unchanged.
See [the canonical notification contract](security-context/LIVE_PRIVACY_CAPSULE.md#security-and-privacy-notifications).

The optimized RPM build and normal Rust workspace checks pass, along with Rust
formatting, Clippy with warnings denied, 418 Fedora Python tests and 99 frontend
contracts. The final extracted package also passes four offline readbacks at
12-second intervals on a private bus/network namespace, plus provider-loss
readback, without using the desktop firewall command. The 44 Windows image
contract tests pass with two native-only tests skipped; no ISO was composed.
The normalized component source fingerprint matches the package manifest:
`5d5a857dde972d08db0708a115b16aa5d0dcf36452458812e7b4aba503948a85`.

Installed package payloads match; the existing mutable OpenSnitch policy remains
customized. All 52 installed production-contract files have the expected RPM
owner. The new module is required by that contract for future compositions.
The restarted session service runs in `greyward_guard_t`, reads the installed
modules and exposes the new preference methods. Native API write/read/restore
passed and the preference remains off, with per-user files mode 0600. No old
Center process was left running. Update Center verified 27 security updates at
the readback; DMS accepted notification ID 1 while protection remained Protected.
Reminder persistence and unchanged delivery are checked across refreshes.
No microphone/camera was activated for testing; physical sensor-start and visual
popup acceptance remain separate from the API and transition tests.

The protected-seat verifier passes with SELinux Enforcing. The graphical session,
greeter, Polkit, OpenSnitch engine/control plane, Secure DNS and scanner stayed
running with their original invocations. Only the root policy reader and user
Context were restarted. Rollback RPMs and private verification receipts are
retained on the reference. No GitHub publication or ISO is part of this task.

## 23 October DMS2 RC3 composed and verified

The requested successor combines the user-accepted Polkit presentation and
native GREYWARD lock appearance with a correction for RC2's disconnected
Polkit loop. The Rust offline collector now calls the fixed, read-only
`OpenSnitchPolicy1.GetFirewallState` system method rather than executing
`firewall-cmd --state` as the desktop user. The existing root network boundary
reads the live daemon property with a two-second timeout; no caller-selected
properties or mutations are accepted. Failed/missing providers remain uncertain.
Mutation reviews and their fresh Polkit authentication are unchanged.

The source candidate selects Center 119, Context 111, Application Security 83
and Enrollment 80, retaining DMS 7.9, Session 34, Files 20 and Branding 16.
The final extracted Center/Context RPMs pass the private-bus/network-namespace
regression: the old packaged helper triggers the rejected desktop command,
while four new ordinary-user samples at 12-second intervals read the real host
firewall through the fixed method. Provider loss remains uncertain without a
desktop fallback. The packaged bus policy is used with the non-wheel `nobody`
account and a no-active-link NetworkManager fixture. This proves the isolated
collector path, not an installed desktop with its physical network disconnected.
The authentication assembler, emblem and materializer in AppSec 83 are identical
to the user-accepted AppSec 82 bytes.

The resulting ISO is
`<local workspace>`,
with checksum, provenance and `verification.json` sidecars. Size: 5,284,036,608
bytes. SHA-256:
`198a4cb0e4f9b3bfe4f447909a06a8f2ae5d3d93b384a8b0e8632a34d79a024a`.
The source is frozen at `046edd6a85eb4f4145b414fb6262822e77e78514`, with a fresh
portable reference capture at `2026-10-23T19:30:45.468610+00:00`.

Normal RPM build/check phases pass, as do workspace formatting and Clippy,
410 Context tests, 98 frontend contracts, the Linux image suite (72 passed,
one explicit gate skipped), 17 assembly, six clipboard and 13 migration checks.
Both repository gates pass. Canonical factory checks validate source/package
closure, networkless dependency resolution and Flatpak installation, the
composed installer contract, extracted stage (30 declared paths), payload hashes
and recursive-copy hashes. The Windows copy has the same checksum and passes
the 40-path media contract. All eight RPMs match their selected bytes in both
embedded locations (16 checks); six staged source files and the portable
baseline match. OBS, QTerminal, public PCManFM and the Haruna app remain excluded.

RC2 is retained. Fresh installation, physical offline, three-screen, recovery
and performance acceptance of RC3 are not established; `installed_system_tested`
and release acceptance remain false. The existing `<validation-host>` graphical session and
R6 were not modified. Nothing was published to GitHub; remote main's prior CI
results do not validate these unpublished commits.

## 23 October native lock wallpaper correction user-validated

The user's RC2 screenshot still showed the stock DMS lock background. The
private JSON contained the correct wallpaper, but the reference's running
authentication shell returned default `lockPamPath`/managed flags. Native 2.0
settings discovery waits for a threaded `config.d` scan; the confined runtime
logs worker-creation failures. The derivative now loads its one immutable
profile and canonical theme synchronously without folder discovery. Ordinary
DMS settings loading is unchanged. Settings/theme/background upstream preimages
are pinned alongside the selected receipt, with no SELinux permission changes.

The native wallpaper initially decoded but rendered black in the private
software-rendering preview because of the GPU blur layer. The protected
derivative now draws the image and native scrim directly on software. Native
options select a single-color digital clock/date, Inter and a quiet pill field
without the generic avatar. The corrected private render shows the actual
GREYWARD texture and emblem; an unavailable-worker negative control fails on
the predecessor and passes on the candidate.

Application Security 82 / Enrollment 79 are built with normal RPM checks,
selected by the candidate manifest and installed on the physical reference in
an approved logout window. Migration verifies all 1,643 protected file digests
and the linked Administration receipt. RPM verification passes, the selected
DMS release and USB rules are unchanged, and SELinux remains Enforcing. Fresh
runtime readback confirms settings loaded, the canonical wallpaper in Fill mode,
the custom theme with surface `#050607` and Inter. The protected seat verifies
in the broker's service context. The user confirms the real GREYWARD background
and successful lock/unlock, and explicitly accepts this version. The
Polkit visual files match their user-validated predecessor; native focus,
external-screen actions and complete lock-component tests pass privately.
At that visual validation point no new ISO was constructed or published, and
the separate RC2 offline Polkit loop was unresolved. The RC3 entry above records
the subsequent collector correction and media checks.

Validation: 17 assembly, six clipboard, 13 migration, ten packaged-input and
nine candidate tests pass on Fedora, as does the actual Application Security 82
RPM/source closure check. Three native authorization checks, three native DMS
checks and the wallpaper rendering/negative-control check pass on the reference's
private display. Repository static and documentation gates pass. These results
do not constitute a successor ISO build or clean-install acceptance.

## 23 October protected Polkit visual successor user-validated

The requested visual successor uses the canonical GREYWARD emblem, an
Obsidian/Platinum palette and one shared card for input and mirrored outputs.
Long requests scroll instead of being truncated; keyboard actions, visible
focus and disabled busy actions are included. The existing authorization,
PAM and protected-input ownership remain in place. Native isolated rendering
and synthetic keyboard tests pass on the physical reference, including narrow
layout and mirror checks. The first candidate, Application Security 80 /
Enrollment 77, was built with its normal RPM checks and installed on the
physical reference during the approved logout window. The
protected migration passes, all 1,643 receipt-bound files and the linked
Administration receipt verify, RPM verification passes, USB rules and DMS
selection are unchanged, and SELinux remains Enforcing. The exact previous
RPMs and protected tree backup are retained. A fresh session starts and the
seat verifies in the broker's SELinux service context; a direct SSH-domain
readback cannot read the protected actor's `/proc` entry and is not equivalent.
The user then reported a blank emblem and ineffective Cancel on an external
output. Therefore 80 / 77 is not accepted. The 81 / 78 correction
compiles the exact SVG into synchronous geometry and routes mirror cancellation
directly to the shared Polkit flow. A synthetic missing-controller case fails
against the old mirror and passes against the corrected one. Those matched
packages are now installed after a second approved logout. Migration, all 1,643
protected file digests, the linked Administration receipt and RPM verification
pass; USB rules and the selected DMS release remain unchanged with SELinux
Enforcing. The fresh session verifies in the broker's SELinux service context.
The user confirms that the emblem is visible and external-screen Cancel closes
the real request, and explicitly accepts this visual version. This does not
claim a new password/USB workflow or complete three-screen security acceptance.
No successor ISO was constructed during that Polkit visual validation.

Validation: 16 assembly, six clipboard and 13 migration tests pass on Fedora;
three native focus/presentation checks pass on the reference's private display,
including real mouse events through the generated mirror and an unavailable
input-controller case. The normal RPM checks pass for both final packages.
The Windows clipboard fixture cannot model Unix ownership and fails there;
the same six fixtures pass on Fedora without altering their checks. Ten ISO
input and nine candidate tests, the source-aware actual-RPM check and both
repository gates pass. These results do not establish real authentication or
physical three-screen acceptance. The future media guard now requires the
canonical emblem as well as the assembler, refusing stale or missing artwork.

Historical RC2 diagnosis (the successor correction is tracked above): its periodic no-active-link
collector invokes `firewall-cmd --state`; firewalld 2.4.4 requests configuration
authorization for that property read, repeatedly prompting the ordinary user.
R6 logs identify this caller/action and the user reports that restoring the
network stops the loop. Internet loss with an active link has not been shown
to cause it. The existing composition/integrity evidence below does not cover
this failure. RC2 is not release accepted; fix and offline desktop validation
are required before a replacement ISO. The visual change does not fix this bug.

## 23 October DMS2 RC2 composed and verified

The requested successor is available at
`<local workspace>`,
with checksum, provenance and verification sidecars. Size: 5,284,036,608 bytes.
SHA-256: `4a873b12471d723517cc7d3affba3e97c5a01d060b34d4b180f4a8131ac46c0a`.
Its frozen source is `f208e1587579cef0dc042a529a05e2ff29c78770`; a new portable
physical-reference baseline was captured at `2026-10-23T17:01:54.830240+00:00`.
The eight component RPMs are DMS 2.0.0-7.9, Session 34, Files 20, Center 118,
Context 110, AppSec 79, Enrollment 76 and Branding 16. These include the full
appearance/Overview defaults, darker palette, native Settings gear and pin,
larger security emblem, native single-pill background, refresh-stable network
identity, protected lock wallpaper and retired-application exclusions.

All 73 Linux image tests and both repository gates pass. Canonical factory
checks pass for source/package and USB approval inputs, networkless RPM
resolution and Flatpak installation, the composed installer contract, extracted
production stage (30 declared paths), payload hashes and recursive-copy hashes.
The copied Windows ISO matches the builder checksum and passes the 40-path media
contract. All eight first-party RPM hashes match in both embedded locations
(16 checks); six staged source files and the embedded baseline also match.
The final RPM closure excludes OBS, QTerminal and public PCManFM, and the
selected Flatpak inventory excludes Haruna. The explicit seed copy drops its
retired Haruna app ref while retaining required shared runtimes.

RC1 is retained. No test VM was booted or changed for this composition; no fresh
installation, physical offline/three-screen, recovery or performance acceptance
is claimed. Candidate release acceptance remains false. Nothing was published
to GitHub. The entries below record the preceding installed and media states.

## 23 October native Settings taskbar default and installed readback

The reference account's persisted taskbar pins already include native Settings
after Brave, Black Box and Strata. Session 34 now seeds that same list for fresh
DMS 2.0 accounts. Existing lists, including deliberately empty lists, and the
legacy generation's defaults remain unchanged. The candidate package manifest
selects Session 34; image staging already rejects a packaged pin helper that
differs from source.

Session 34 is built and installed on the physical reference. Payload comparison
with 33 changes only the session pin helper; the exact previous RPM is retained
for rollback. Native Bash/jq state tests pass (seven run, one explicit binary
fixture unavailable), as do all 44 Linux image tests against the actual RPM,
nine candidate tests and both repository gates. Installed readback verifies
DMS 2.0.0-7.9 / Session 34 / Files 20 / Center 118 / Context 110 / AppSec 79 /
Enrollment 76. RPM verification passes, allowing only the existing mutable
OpenSnitch policy configuration. The Settings gear, larger security emblem,
protected lock wallpaper, durable pins and retired-application absence are
confirmed from installed files and configuration. Strata remains installed.

Both ordinary shell processes use the installed shell and current receipt-keyed
QML cache; no old or deleted QML mappings are observed. These changes are
package-owned rather than cache-only overrides. Legitimate matching caches
remain enabled. Protected profile hashes, active-seat verification, taskbar
preferences, USB rules, session and service generations are unchanged; SELinux
remains Enforcing. No reload, logout, successor ISO or publication was performed
for this follow-up. The appearance and emblem entries below describe the
preceding installed revisions.

## 23 October Security Center taskbar emblem refinement

The taskbar emblem now adds four pixels to its native bar-scaled size in both
orientations. Content-measured width and the single native pill are retained;
activity glyphs, other widgets and the flyout emblem are unchanged. The reference
now runs DMS 2.0.0-7.9 / Enrollment 76, retaining Session 33 / AppSec 79. Both
package builds, normal package checks and five private native plugin fixtures
pass. DMS payload comparison changes only the ordinary widget and its receipt;
the generated shell and three pinned executables remain byte-identical.

The rebuilt Enrollment source compositor and its input digest differ from 75;
they are not described as identical protected payloads. The running protected
desktop uses its independently copied, verified profile. Every file in that
profile and Administration remains unchanged across the package update, and the
fresh seat verifier passes. No protected migration, logout, compositor restart
or root-service restart was performed. A separate ordinary-panel reload loads
the new receipt-keyed cache, with no old/deleted QML mappings. Installed RPM
verification, unchanged taskbar preferences, session, USB rules and root-service
generations pass; SELinux remains Enforcing. The appearance tuple below precedes
this refinement. No successor ISO or publication is claimed.

## 23 October physical appearance capture and desktop cleanup

The reference account's current appearance is captured in the candidate
`experience.json`: transparent bottom bar, 1.13 text / 1.1 icon scaling,
155-percent app icons with 140-percent hover enlargement, the exact widget
order/options, per-widget backgrounds, spacing, borders, shadows and opacity.
Security Center, clock and power retain backgrounds; other widgets are bare.
The optional dock stays disabled. Geometric centering, compact clipboard and
the four-pixel launcher border are included. Screen names/models and the
disabled experimental bar are not portable defaults. New accounts receive the
portable layout; established accounts retain their preferences.

The candidate forwards DMS's native per-widget Background option into both
plugin pill orientations. Security Center uses that single background and
native scaled icons, with content-measured width. The Settings launcher uses a
standalone silver gear SVG. Network identity retains the last confirmed address
and country flag while refreshing; cold startup still shows Checking. Failed
lookups remain unavailable and opt-out clears identity. Address data remains
memory-only. The public-IP globe is removed from both orientations and flyout.
The protected lock profile pins the canonical GREYWARD wallpaper and Fill mode.
Its activation requires a quiet protected-profile migration and fresh login.

OBS, QTerminal and Haruna have been removed from the physical reference after
configuration backup. Removing QTerminal also removes Fedora's public PCManFM
package, which requires it; Strata and the independently packaged private
desktop binary remain installed. Security/recovery service PIDs and USB rules
are unchanged. Fresh-image package floors, exclusions, default Flatpaks,
curation and MIME assignments no longer bring these applications back.

After approval for one logout, the reference now runs DMS 2.0.0-7.8 / Session 33 /
AppSec 79 / Enrollment 75. The first attempt correctly refused the still-closing
logind session before making protected changes; retry after it disappeared used
the same approved quiet window. The 6,561-member recovery archive passes private
extraction/comparison; exact candidate and rollback RPM transactions pass. All
four package builds and their normal checks pass. Payload readback verifies 22
plugin files, the shell receipt, three unchanged pinned executables, the gear,
factory appearance/migration bytes and protected materializer. Five private
native plugin tests pass, including both pill-background toggles and refresh
identity retention. All 44 Linux image cases pass against the actual Session 33
RPM, including visual-byte and retired-application negative controls.

The protected migration and fresh-login runtime readback pass: the active seat
verifies, protected processes and the workflow broker use their current
executables, and the two ordinary shell processes use only the current receipt
cache namespace without old/deleted QML mappings. The protected runtime's lock
wallpaper and Fill mode match the canonical wallpaper. The user's taskbar options
are retained with the native security background enabled. Fresh state is
Protected with zero reviews, Operating filtering and VPN Active; SELinux is
Enforcing, USB rules and unrelated service generations are unchanged. These
are configured/runtime checks; visual lock/gear/flag acceptance is still separate.
No new ISO or public publication is claimed. The previous RC1 remains unchanged.

## 23 October R6 follow-up — current readback, candidate activation pending

The user now reports no visible flapping. The supplied normal-session diagnostic
capture confirms the RC1 tuple on R6: DMS 2.0.0-7.6 / Session 31 / Center 118 /
Context 110 / AppSec 78 / Enrollment 73 / Files 20, with SELinux Enforcing.
The four captured Context source hashes match the canonical sources. The active
bus owner is the expected session10 entrypoint; Context and DMS both report zero
restarts. Live introspection exports `GetShellPresentation`, and the call succeeds
with Protected, Operating network protection, Secure firewall, Encrypted DNS,
VPN Off and no items or notification items. The earlier UnknownMethod response
is not reproduced; its original cause remains unestablished.

The separate system-posture capture spans 16:35:28–16:37:27 CEST: one loading /
Unavailable reply followed by 54 Review Needed replies with two reviews and
three or four unavailable checks. This differs from the earlier 16:34 session
presentation; it is not a simultaneous trace of both paths and does not prove
visible flapping or identify the underlying checks. Do not label the captured
system fallback healthy or attribute the user's improvement to the undeployed
candidate fix. The archive contains no theme/Overview settings and its journal
read was permission-denied. RPM verification also encountered protected files
unreadable by the ordinary account; those reports do not establish missing
files or complete integrity acceptance. No guest change was made for this review.

The preparation and unavailable-channel evidence below precede this supplied
capture. Candidate activation, visual settings readback and successor media
remain separate pending work.

The user reports brief Protection and Network warnings on R6 after installing
the new ISO, without the same symptom on the physical reference. Read-only
comparison found that the reference's live DMS theme was an unowned, darker
file, whereas the image used the generated graphite theme. Canonical palette
input now records the reference's native dark shell roles; existing Strata and
Security Center application roles are retained. Session 32 owns the system theme
as well as its factory copy. Its Overview preset uses the observed reference
grid: three security cards, full-width media, calendar, disk, memory and CPU.
Existing user layouts and privacy opt-outs remain preserved.

The shared shell client now retains detailed evidence within its original lease
when a fresh positive aggregate fallback arrives. It does not renew that lease,
resolve pending actions, or suppress a new negative aggregate. Missing filtering
details render unavailable instead of inventing a Network review finding. All
five private native plugin tests pass, including expiry/negative/pending-action
regressions and the actual DMS theme loader's resolved dark surfaces.
At that preparation stage, the transient R6 warning had not been captured; this
source correction does not establish that its entire live cause is resolved.
The fresh R6 install has no development SSH path, and console text pasting fails;
a normal-session presentation readback has been requested. R6 later auto-locked;
unlocking has been requested without automating authentication. No R6 policy or
session change and no physical-reference deployment has been made for this follow-up.
The subsequent user capture shows `UnknownMethod` for `GetShellPresentation`.
The exact Context 110 RPM contains that method and passes a private native
D-Bus export check through `Session10SecurityContext` with a synthetic read
provider. This proves packaged method registration only. R6's installed RPM,
source-method presence and actual bus owner have been requested to distinguish
an installed-version, running-process or call-target mismatch; none is yet
established as the cause.
The user is remote and cannot perform these reads. The observed guest address
does not accept TCP connections on port 22; no SSH verification was bypassed.
Guest file transfer is disabled, KVP reports no contact, and no serial pipe is
configured. VMConnect capture works, but fresh accessibility controls are rejected
by the input tool and console text delivery cannot be verified. No guest access
configuration was changed. Live diagnosis and activation remain pending an
available guest channel rather than treating the prepared fallback fix as proof.

Candidate inputs target DMS 2.0.0-7.7 / Session 32 / Enrollment 74, retaining
Center 118 / Context 110 / AppSec 78 / Files 20. All three package builds and
normal package checks pass. Readback verifies all 22 packaged plugin files and
the three pinned executable hashes. The built-Session visual test passes all
43 image cases on Linux, including actual RPM payload and changed-input refusal.
Its first run exposed RPM's hard-link encoding of duplicate themes; the contract
now extracts the closed three-file set together rather than reading an empty
individual link member. Session build inputs remain byte-identical to the
source snapshot used for its retained artifact. All three Windows artifact
copies have matching SHA-256 hashes. Enrollment's newly built protected Labwc
and its input digest differ from revision 73; it has not been hot-deployed or
declared a metadata-only update. Recoverable candidate activation
and a corrected successor ISO remain pending. RC1 is historical media
for these corrections, not a claim that they are already embedded. Candidate ISO
staging now rejects a Session RPM whose actual system theme, factory theme or
Overview preset differs from source. Public publication remains unapproved.

## 23 October matched activation and DMS 2.0 ISO candidate

After explicit approval for one graphical logout, the physical reference now has
DMS 2.0.0-7.6 / Session 31 / Files 20 / Center 118 / Context 110 / AppSec 78 /
Enrollment 73. The quiet 6,561-member recovery archive passes private extraction
and comparison. Exact package digests and the RPM transaction pass; the canonical
protected migration verifies that generation 7 already has the matching inputs.
Only the workflow broker was restarted within that quiet window. RPM verification,
the full selected DMS verifier, unchanged USB rules and unrelated root service
generations pass; SELinux remains Enforcing. The user confirms a successful fresh
login. Independent readback verifies the protected seat, the newly installed broker
executable and the two ordinary shell processes. Their active QML mappings use only
the current verified receipt namespace; no deleted or prior cache mapping is
observed. Fresh Context reports PROTECTED with zero reviews, OPERATING filtering
and ACTIVE VPN. Valid receipt-keyed caching remains enabled.

The explicitly requested internal ISO is now composed. The image entrypoints
now accept `--dms-candidate`, selecting the separate candidate receipt and plugin
inventory while retaining exact payload/source checks. The validated default stays
unchanged and candidate acceptance remains false.

Artifact: `GREYWARD-0.5.0-DMS2-RC1-x86_64.iso`, 5,446,631,424 bytes, SHA-256
`c17280fa3de30c4faadfc7aaf48bb829d2767c532eb4f3c882b4745c39a935b8`.
Image source is `882080ac9ee34d85fa55734524a795383326f60a`; all eight embedded
first-party RPMs match the selected artifact hashes and the physical package set.
The fresh portable baseline, package dependencies, Flatpak commits, empty-root
networkless dependency transaction and complete Flatpak installation pass, as do
the extracted payload and production-stage checks. RPM scriptlets were not run
by that dependency solve; it does not prove an installed OS.
The Windows copy has the same SHA-256 and passes the 40-path media contract.
The later user-authorized R6 boot attaches this exact ISO and reaches Anaconda's
installation summary with the disk-encryption passphrase dialog, observed through
the real VMConnect console. The original disk-first boot order is restored; the
ISO stays attached. No installation was started and no new VM was created.
Clean installation, encrypted recovery, physical
offline/three-screen acceptance and daily-use/performance gates remain separate.
No GitHub publication, tag or release was performed.

## Historical: 23 October ordinary follow-up — before matched protected activation

At this stage the physical reference ran DMS 2.0.0-7.5 / Session 31 / Files 20 /
Center 118 / Context 110, retaining protected AppSec 76 / Enrollment 67 and
runtime generation 7. Fresh installed Context readback shows PROTECTED with
zero reviews, OPERATING application filtering, a SECURE network check and
explicit ACTIVE VPN state. The card model applied to those observed bounded
fields returns green `Protection active`, with `VPN active` underneath. An
observed VPN off does not downgrade healthy filtering; missing/stale evidence
cannot establish Off. Explicit stopped/disabled controls remain inactive.
The cards use graphite surfaces, functional semantic icons/text and restrained
accents, with decorative rings and oversized watermarks removed. Private native
normal/compact layout checks and a synthetic desktop preview pass; final user
visual confirmation of this refinement is still separate.

The offline defect was in the canonical network collector: without an active
interface it returned unknown without checking the firewall. That made the
Network domain unknown and therefore the aggregate posture unavailable. The
replacement distinguishes successful NetworkManager absence from probe failure,
then requires a live firewalld reply before satisfying the offline firewall
check. Missing/malformed observations and failed probes stay uncertain. Overall
aggregation and other required checks are unchanged. A private packaged-helper
canary returns SECURE for confirmed offline plus running firewall, and UNKNOWN
for failed NetworkManager/firewall probes. No physical network disconnect was
performed, so installed physical offline acceptance remains unclaimed.

The first Center 117 build reused an old standalone posture helper; its packaged
canary reproduced UNKNOWN for the confirmed offline case. It was not deployed.
Canonical Center/AppSec RPM builds now explicitly rebuild first-party release
executables while retaining dependency caches. Center 118 passes that same
packaged canary. A Linux spec-execution regression also passes against stale
cached executable outputs. All normal Center/AppSec package checks pass;
explicitly ignored hardware/privileged fixtures remain unclaimed.

Context 109 initially compared the refreshed VPN observation with the earlier
summary sample time and conservatively rendered it unavailable. Context 110
compares VPN freshness at provider completion without renewing the original
posture lease. The real GetShellSummary caller and pure projection regressions
pass, alongside all 409 Context tests, 98 frontend checks, 10 card cases and
three private native plugin fixtures. The 4,809-file canonical build snapshot
and exact overlays verify; final evidence prose is maintained separately.

Payload admission verified the four DMS file changes and rebuilt Center helper.
Context's only functional changes are shell projection/collection; its root
network module exactly matches the existing installed hot fix. Two Polkit
source differences normalize line endings only, preserving authorization logic.
Installed RPM verification passes apart from the preserved customized OpenSnitch
configuration. Predecessor downgrade dry runs and private backups are retained.
Root-network scriptlet restarts were suppressed and only ordinary shell/Context
units explicitly reloaded. Root service generations, network configuration,
protected inputs, USB rules and original protected compositor/authentication
PIDs are unchanged. SELinux stays Enforcing, and fresh protected-seat verification
returns true. No logout, compositor restart, reboot or publication occurred.

The future matched image source tuple is DMS 7.6 / Center 118 / Context 110 /
AppSec 78 / Enrollment 73. All five package builds and their source/hash closure
pass; the future protected packages remain uninstalled. The protected broker's compiled fallback requires a
separate matched activation window; it was not hot-updated. The active shell
uses the newly built canonical unprivileged posture helper. Production defaults
retain the validated release and migration acceptance remains incomplete.

## Historical: 23 October initial cache correction — superseded by protection-first refinement

The physical reference now has DMS 2.0.0-7.3 / Session 31, retaining Files 20 /
Center 116 / Application Security 76 / Enrollment 67 / Context 108 and protected
runtime generation 7. Healthy `OPERATING` filtering and VPN-owned DNS map to
green `VPN active`; actual findings retain precedence. The earlier UI-only
correction was insufficient: the user reported the old card design after reload.
The compiled cache for the exact canonical `StatusCard.qml` path still contained
the pre-redesign implementation despite current installed source bytes. Package
timestamps were unchanged. The old running process retained that deleted cache
mapping and predated the cache fix.

The canonical ordinary-shell wrapper now keys `QML_DISK_CACHE_PATH` by the fully
verified release receipt's SHA-256. It preserves caching and prior namespaces;
protected authentication and its private runtime are unchanged. The obsolete
compiled card was privately backed up and removed. Through the existing user
service manager, only the ordinary taskbar/dashboard was reloaded. Readback
confirms new DMS/Quickshell processes, the expected cache key, and actual mapped
compiled card/model units in that namespace. The current compiled card contains
the new footer and no old Update Center headline; the compiled model contains
`VPN active` and `OPERATING`. The user confirms that Network is green. Follow-up work will restore network protection as the primary state and keep VPN as secondary information; offline aggregation remains a distinct diagnosed issue.

The exact package payload delta is three DMS files (model, plugin version,
receipt) and one Session file (ordinary wrapper). Runtime binaries, helpers and
shell files are byte-identical to generation 7. Protected desktop/Administration
receipts, Enrollment inputs and USB rules remain unchanged. Full installed RPM
verification, selector validation and predecessor downgrade dry runs pass. The
fixed seat verifier still returns `verified: true`; the original graphical
session remains open, SELinux stays Enforcing and recovery/security services
remain active. No compositor restart, logout, reboot or protected migration was
performed. New matched Enrollment 70 builds for future image staging and is not
installed on the active desktop. No publication or ISO composition occurred.

Eight card-state cases, three private native plugin fixtures, 14 build contracts,
nine candidate contracts and eight Linux verifier fixtures pass. The source and
payload closure covers 4,808 files. The direct-kernel wrapper regression confirms
cache-key changes even with identical receipt mtimes, stable warm-key reuse,
default XDG handling and preservation of prior caches. The optional private
Quickshell warm-cache fixture does not emit disk-cache units on this builder and
is explicitly skipped; it is not evidence of a native warm-cache replay. Actual
installed cache mappings/code tokens provide separate scoped evidence above.

## Historical: 22 October first Network card correction — superseded by cache fix

Readback on the physical reference confirms healthy application filtering
(`OPERATING`), a secure evaluated network check, zero network reviews and
VPN-owned DNS. The dashboard's positive-state vocabulary omitted `OPERATING`,
causing an incorrect amber review headline. The source now recognizes it and
shows green `VPN active` when both filtering controls are confirmed and no real
finding needs attention. DNS ownership is disclosed without claiming encrypted
DNS, full-tunnel routing or a kill switch. Informational events do not create a
review requirement; real warnings/actions/failures and stale evidence retain
precedence. Eight state cases and three private native plugin fixtures pass.
The installed package-only correction is DMS 2.0.0-7.2, retaining Enrollment 67,
the exact runtime/protected generation 7 and all other packages. The build pins
the three existing executable digests before providing the predecessor's exact
runtime dependency. The first rebuilt Enrollment candidate changes its embedded
compositor package note and digest; it is not eligible for this live UI-only
update. New matched Enrollment 69 is built separately for future image staging;
it is not installed on the physical reference. Normal DMS package checks pass,
alongside 14 build contracts, nine candidate contracts, eight Linux installed
verifier fixtures and eight card-state cases. The 4,807-file source comparison
passes. Extracted DMS payload differs only at the model, plugin version and
release receipt; every runtime executable, shell file and helper is identical.
The installed dependency/conflict dry run, full RPM verification, selected-DMS
validation and predecessor downgrade dry run pass. Protected desktop and
Administration receipts, Enrollment inputs and USB rules are unchanged. The same
graphical session remains open, its fixed protected-seat verifier still returns
`verified: true`, and SELinux remains Enforcing. No protected migration, session
closure or compositor restart occurred. The user has been asked to reload only
the ordinary shell from its normal terminal; physical color/text confirmation is
pending. No publication or ISO composition occurred.

## 22 October Security dashboard cards — successor active; physical review pending

The user-requested refresh adds green/amber/red state accents, native vector
emblems, per-control rows and a small taskbar status dot. The existing shared
observer and typed routes remain unchanged. Unknown or stale evidence stays
amber; explicit failure is red. Network shows firewall/application/DNS evidence
separately. Updates never inherits an Up to date claim from overall protection;
idle update counts and last-check results are not present in this summary.

Seven focused Node cases, palette/contrast checks and three native plugin
fixtures pass. Synthetic dark/light renders were inspected and compact layout
fits; physical appearance remains pending. The installed matched set is DMS 2.0.0-7 /
Session 30 / Application Security 76 / Enrollment 67, retaining Files 20 / Center
116 / Context 108. It includes the schema-42 correction. All four packages build
with normal checks; 108 native/profile/source/palette
checks, six real-CLI fixtures and seven Node cases pass. Package hashes, source
closure and the physical dependency/conflict dry run pass. After the user approved
activation, the physical reference was already at the greeter with no enrolled
graphical session. The four revision-7 packages and canonical protected-profile
migration are now applied; Files 20 / Center 116 / Context 108 are retained.
All 1,642 protected file digests and the Administration cross-reference verify;
installed RPM verification and selected-DMS validation pass. The workflow broker
was reloaded in the approved quiet window. SELinux remains Enforcing and SSH,
greetd, USBGuard, Polkit and firewalld remain active. The USB rule file is unchanged:
11 persistent rules, 15 allowed devices and no blocked/rejected devices at readback.
The new quiet recovery archive has 6,559 members and passes isolated extraction
and metadata/content comparison; installed rollback/reapply remains untested.
After a fresh login, the PID-1-started fixed seat verifier returns `verified: true`.
The actual protected runtime settings report schema 42 and remain root-owned,
read-only. Real keyboard authorization, Strata reopening and physical appearance
remain pending user confirmation.
No session was forcibly closed, reboot, hot compositor restart, ISO composition
or publication occurred. Revision 6 is a retained predecessor.


## Historical: 22 October first DMS 2.0 physical trial — superseded by revision 7

The following records the earlier revision-3 trial, superseded by the activation
above. After the user approved the activation window and logged out normally, the six
matched packages were installed on the physical reference: DMS 2.0.0-3 / Session
26 / Files 19 / Center 116 / Application Security 72 / Enrollment 63. Files has
since been upgraded to corrected revision 20 without closing the session. Context 108
and the independent pinned 1.6 greeter remain unchanged. The production source
manifest and ISO inputs still select the validated 1.6 release. No publication
or ISO composition occurred.

The final quiet-session backup includes both SELinux stores, protected desktop
and Administration inputs, application state, ordinary preferences and USB/firewall
policy. Graphical sessions/protected processes were absent; policy database
main/WAL/journal and key receipts stayed stable across capture. The 5,131-member
archive restores and compares with its saved content/metadata in an isolated
directory. Exact old RPMs and downgrade/reinstallation dry runs are available;
installed rollback/reapply has not been rehearsed.

Protected authentication was migrated to 2.0 with all 1,642 prepared-file hashes
and the Administration cross-reference verified. Its ordinary-plugin loader is
disabled. Installed RPM verification and the selected DMS validator pass. The
security broker was reloaded in the approved quiet window. SELinux stays
Enforcing; SSH, greetd, USBGuard, Polkit and firewalld stay active. The persistent
USB rule file is byte-identical to the pre-migration backup; no manual allow rule
was added. No reboot or hot compositor restart occurred.

Source, package, native headless shell/plugin/focus, profile, real-CLI migration,
image-source and frontend gates pass as recorded in the
[migration authority](architecture/DMS_2_0_MIGRATION.md). Shared palette, native
Security dashboard/tab/search and private Strata desktop routing are candidates
for physical review. The original dirty worktree is preserved separately.

The old installed seat passed a fresh metadata readback before logout. After
the new login, the PID-1-started fixed verifier also returns `verified: true`.
Ordinary application requests for coverage, device protection and Administration
return normally; rejected SSH-root activity reads do not establish a desktop
regression and must not be addressed by weakening the caller boundary.

A new actual-source regression test exposed a protected settings mismatch:
the native pinned shell requires schema 42, while the first trial seeded 29.
The corrected source selects 42, preserves legacy schema 18 and checks the
manifest pin against the actual native declaration during assembly. The schema-only
predecessor candidate is DMS 2.0.0-6 / Session 29 / Files 20 / Application Security 75 /
Enrollment 66, retaining exact Center 116 / Context 108. Intermediate
revision-4 build artifacts were rejected before deployment after a text-encoding
diff; no admitted package identity is reused for different bytes. The four successor RPMs now build with their normal checks, have closed
source/payload receipts and pass the installed dependency/conflict dry run.
All 104 native/profile/source contracts and six actual-CLI migration fixtures
pass on Fedora. A new approved quiet activation window is still required. The active desktop remains on revision 3.

The user confirms first-login success but reports that Strata does not open.
Direct package-byte inspection finds CRLF in `/usr/bin/strata`, making the kernel
look for `/usr/bin/sh` with a trailing carriage return. A private backup precedes
an atomic LF-only launcher correction on the physical reference; its interpreter
syntax passes and no other script in the six installed trial packages has a
broken shebang. The user confirms that Strata now opens normally. Files 20 adds the canonical
LF checkout attribute, installation normalization and a direct-kernel wrapper
test with a failing CRLF negative control. The source-built Files 20 RPM now passes normal checks, three source/packaged
wrapper kernel tests and the exact packaged desktop three-two-three output
fixture. It is installed with clean RPM verification; the wrapper matches the
confirmed LF correction and the protected seat still verifies with SELinux
Enforcing. The user confirmed reopening after the launcher correction; a fresh
open of the rebuilt native payload remains to confirm. No explicit session or
service restart was used. The protected follow-up is staged, awaiting the new
approval; it has not been activated.

Three-screen workflows, real password input/authorization, Strata security-action
parity, rollback/reapply, rendered-performance comparison and 24-hour daily use
remain pending. Nautilus removal is still gated on installed Strata parity. No
measured speed-up or complete installed security acceptance is claimed.

## 21 October desktop icons on multiple outputs — 0.4.5 media verified

Files 18 separates icons from DMS wallpaper and reconciles connected outputs.
Each entry has unique screen ownership, drag/menu placement, disconnect fallback
and restored preference on reconnection. The four native headless scenarios and
23 layout checks pass; the actual packaged PIE desktop also reconciles three,
two and three outputs without Qt signal errors. All 835 icon assets match Files
17. These are synthetic results; physical acceptance is deferred by the user.
The earlier `<validation-host>` snapshot showed three connected outputs and a verified seat.
The provisional Files 17 executable replacement is now superseded by the full
Files 18 RPM, identical to the 0.4.5 image input. Installed RPM verification is
clean, both executable hashes match the build evidence, and SELinux remains
Enforcing. Installation occurred at the greeter without restarting any service;
the next normal login loads the packaged desktop. Physical placement and
hotplug acceptance remain pending; no active-seat check is claimed at the greeter.

The requested internal ISO **0.4.5** is now built and copied to Windows. Its
offline dependency checks, composed/extracted payload validation, recursive-copy
verification and Windows 40-path/hash validator pass. All eight selected RPM
hashes match in both the staged and installer-repository copies (16 checks),
including canonical first-boot/provisioner bytes. The candidate contains Files
18, Session 23, Application Security 70 and Enrollment 61; DMS 26, Center 115,
Context 108 and Branding 16 are retained. Package checks pass: three Rust file
metadata tests, 210 Application Security tests with 22 privileged tests ignored,
three Enrollment Meson tests and six exact Session payload checks. Session 23
normalizes the otherwise equivalent factory-default line endings through a
canonical rebuild. No user session/compositor was restarted; `<development-host>` retained
its active session throughout. No new VM was created. The existing R6 was later
booted from this ISO and its GREYWARD GRUB menu was observed in VMConnect;
this establishes media boot only, not completed installation or enrollment.

Clean installation, recovery and physical three-screen acceptance are **not
verified** for this ISO. At composition time, public `main` CI had a pre-existing
failed run. Public source CI remains separate from image acceptance. Full media
path, hash, input provenance and
limits: [ISO creation](architecture/ISO_CREATION.md). Runtime details:
[desktop integration](architecture/FILE_MANAGER_DESKTOP.md).

## 21 October R6 first-boot and role-closure defects — live seat verified

The approved second rescue repair snapshots both SELinux stores and the
affected files, removes only the reviewed USB helper's ordinary-attribute
membership, and refreshes the ordinary, desktop, Administration and installer
input receipts. The offline compiled-policy and file readbacks passed. Account
mappings and the broker enrollment journal were preserved; that journal's
initial generation remains historical, with the migration binding old/new
file hashes separately. The first-boot helper is restored to canonical corrected
source, without its temporary appended observer.

After the user's normal reboot/login, the installed verifier returns true
three times through the broker's exact bounded path (0.848, 0.513 and 0.517
seconds), and three direct diagnostic readbacks also return true. `getenforce`
reports `Enforcing`. The user confirms that Administration opens after normal
authentication. These are observed live-seat/Administration results on repaired
R6. The user confirms removal of the temporary observer unit/script and a
successful daemon reload; the report and repair backups are retained. The
repair DVD is ejected and the installed disk's boot priority restored. These
results do not establish a clean installation from an unmodified ISO.
Ten verifier/generator tests, eight RPM
payload-gate tests, 41 offline-image contracts and both repository gates pass;
three isolated Linux migration tests cover successful backup, compilation
failure and incorrect compiled membership with rollback.

Earlier evidence, before the role-closure repair:

With approval, R6's first-boot script was backed up and hot-patched in rescue;
the user rebooted and reached the installed Labwc desktop. A bounded root
observer then returned `verified: false` three times in 0.37–0.50 seconds.
The unsuppressed verifier error was `Ordinary role coverage changed` on all
three samples. This rules out its three-second deadline for those samples;
Protected Data and Administration acceptance remain unpassed.

R6's installed `ordinary.json` lists `greyward_usbguard_approval_t` in both
the role domains and ordinary types. The verifier deliberately rejects this
helper in ordinary coverage. Read-only comparison confirms `<validation-host>` has the
helper in its live role but neither its ordinary attribute nor saved ordinary
inventory. The fresh-enrollment generator previously excluded only the display
domain. Source now also excludes the reviewed USB helper, retaining it in the
role inventory and retaining every other ordinary domain and restriction.
The new regression fails against the previous generator and passes after the
correction; the live verifier is unchanged. The subsequent offline migration
and live-seat result are recorded above.

The ISO builder now checks this generator and verifier inside the selected
Application Security RPM for both source builds and installed-RPM imports.
The old `<validation-host>` RPM is therefore not sufficient input for the next image:
rebuild matched packages containing the correction. The corrected package/image
follow-up is tracked in the 0.4.5 candidate entry above. No publication is authorized.

R6's initial rescue readback confirmed installer and broker phase `PENDING_SESSION`,
matching account/origin records, all three enrollment-input digests and all
1,014 protected desktop file digests. The completion marker was absent, while
pending and production-ready were present. The retained setup log reaches
final checks three times, then refuses later retries with an active desktop.
The retained failure file shows an active greetd and a seat0 greeter session;
it contains no greetd startup error. These observations do not prove a healthy
rendered greeter or live protected-seat coverage.

A definite first-boot predicate defect was identified: it requires a live
`dms-greeter` process, but the pinned 1.6.2 launcher execs Labwc and starts
Quickshell. The correction checks the greeter-owned compositor and UI instead.
A completed user handoff requires the existing root-only live seat verifier;
arbitrary Labwc/DMS processes cannot satisfy it. Six isolated Linux shell tests
pass, including missing UI/compositor, false/malformed/timed-out verification,
failed session enumeration and wrong-seat/nonhuman cases. The 41 offline-image
contracts also pass. The rescue hot patch above is installed on R6; no newly
composed installer ISO contains the source correction.

Read-only SSH comparison of `<validation-host>` confirms AppSec 69 / Enrollment 60 /
DMS 1.6.2-26 / Session 22, the same verifier/session sources and a 1,014-file
manifest. Its live verifier returns true twice, in approximately 0.61 seconds,
under the broker's SELinux context. `<validation-host>` remains Enforcing and unchanged.
This working installed/migrated reference does not establish clean-install
acceptance for R6. The later R6 readback above identifies its role-closure failure.

The multi-output greeter UI was added on 19 October; the obsolete readiness
predicate is already present in the 11 October revision. The later physical-GPU renderer change
retains the VM's Pixman branch. Their temporal relationship alone does not
establish that multi-output rendering caused R6's failure. Keep the feature
while validating the corrected readiness predicate separately. See the
[enrollment package](../packaging/greyward-enrollment/README.md) and
[ISO creation](architecture/ISO_CREATION.md).

## 20 October R6 enrollment investigation — source retry fix only

Read-only Hyper-V metadata confirms that R6 has the 0.4.4 candidate attached;
it does not establish which ISO populated its installed disk. The user reports
R6 is running the `example-user` desktop without working root access. The user
supplied `id -Z`: `greyward_guard_u:greyward_guard_r:greyward_guard_t:s0`.
This confirms that shell's confinement, not the protected seat or account receipt.
No screen control, SSH, reboot, session change or deployment was performed in this
continuation. The protected installation transaction and live seat failure
remain unknown.

Direct extraction confirms that 0.4.4 contains the current first-boot,
provisioner, zsh configurator and acceptance scripts, but Enrollment 60 lacks
the `PENDING_SESSION` retry correction. The regression fails against the
helper extracted from that RPM and passes against corrected source. All 23
installer-enrollment tests pass under isolated Linux/Python 3.12; 61 image
contracts pass on Windows with nine additional Linux-only checks skipped, and static and
repository checks pass. These are source/media observations, not installed
Fedora enforcement evidence. The correction is not yet packaged, deployed or
included in a new ISO and is not established as the cause of R6's initial
failure or degraded seat. See the [enrollment package](../packaging/greyward-enrollment/README.md).

## Current production reference: `<validation-host>` — 20 October

Use the bare-metal `<validation-host>` installation as the version authority for production:
DMS 1.6.2-26, GREYWARD Files 1.0.0-17, Session 0.1.0-22, Security Center
0.1.0-115, Security Context 0.1.0-108, Application Security 0.1.0-69,
Enrollment 0.1.0-60 and Branding 0.1.0-16. The next ISO candidate must be
composed from RPM payloads verified against that installation and pass
embedded-package and runtime-baseline checks; matching version labels by
themselves are not enough. The five DMS/Security Center/AppSec/Enrollment RPMs
are imported byte-for-byte from `<validation-host>`; their import receipt explicitly records
that source reproducibility was not verified. Session 22 is rebuilt from its
exact installed package-owned defaults because its original RPM was unavailable.
The 0.4.2 ISO was installed on R6 and failed on first boot: enrollment refused
with `Account has live workloads; enrollment refused`, leaving Protected Data
degraded and Administration unavailable. The 0.4.3 ISO added static login
gates, but the user installed it and confirmed the same symptoms. The gate
change did not fix enrollment itself. Source review found that the first-boot
provisioner runs account-owned zsh/Git setup before enrollment, while
enrollment deliberately refuses to change an account mapping if any process
belongs to that account. The R6 journal did not capture the blocking PID. On
`<development-host>`, `/etc/pam.d/runuser` does not load `pam_systemd`, so the earlier theory
that `runuser` alone left a user manager is not proven.

Candidate 0.4.4 keeps the login boundary gated and the default target in text
mode until acceptance passes. It selects the final zsh shell without running
as the account, prepares enrollment while the account is quiescent, then runs
the user-owned zsh/Git setup and checks enrollment again. The configurator uses
`setpriv` rather than PAM to switch credentials. If enrollment still finds
processes, first boot records their PID and process name. The build and media
checks now pass. The candidate is at
`<local workspace>`,
SHA-256 `edf89ce48bd8a966b9b2d9e45a1a44df9e5558302a56fa852d034c37e9eb09d0`.
Installation and runtime acceptance on R6 are still required; this ISO is a
test candidate, not a confirmed fix or release. Both earlier candidates remain
unaccepted. See
[ISO creation](architecture/ISO_CREATION.md).

### Security Center update status and Polkit display correction

The Security Center **System checks** warning came from DNF5's real output on
`<validation-host>`: `dnf5 check-upgrade --json --security` exits successfully and prints
`{}` when there are no security updates. The parser previously required an
`upgrades` field and treated this valid empty result as unknown. Security Center
115 now interprets only that successful empty object as zero updates; an
unsuccessful command, malformed JSON or unknown result shape still produces an
unverified status. The exact `<validation-host>` command was rerun after installation and
returned `{}` with exit code 0.

The previous `<validation-host>` Polkit change showed a keyboard-language label and marked
other displays view-only. That missed the requested behavior. The replacement
keeps one protected password field as the authority and mirrors the same
authorization request, action buttons and masked character count on every
other protected display. Secondary surfaces receive only the count used to
draw bullets, never the password string. Clicking a mirrored field returns
focus to the protected input; Cancel and Authenticate invoke the same active
Polkit request. The request summary is now a bounded, styled card so long
network-policy details do not stretch or clip the dialog. The selected XKB
layout still configures the protected compositor but is no longer shown in the
Polkit prompt. The primary and mirror cards use the same bounded GREYWARD
layout; only one surface receives the protected text input.

Security Center 0.1.0-115, Application Security 0.1.0-69 and Enrollment
0.1.0-60 are installed on `<validation-host>`; Security Context 0.1.0-108 was already
installed. RPM verification is clean, the protected migration completed to
DMS 1.6.2-26, and the deployed QML has the bounded primary card and masked
multi-output mirror. Authentication tests, package builds, and repository
gates pass. Structural checks do not prove the actual rendered result: visual
confirmation on all three physical screens still needs a fresh login and a
Polkit prompt. The migration asks for a fresh login to load the new protected
shell. Candidate 0.4.2 includes the installed packages but its R6 installation
failed during first-boot enrollment as described above; it has not passed
installed-system acceptance.

The first screenshot's firewalld warning is also resolved in the current
`<validation-host>` API state: Security Context 108 is installed and its service is active.
`GetRules(provider=incoming)` returns the firewalld catalog, `detail: null`,
and `capabilities.edit: true`. The screenshot was captured before this state
was refreshed; the visible page still needs a refresh after login.

The dated entries below preserve what was known at each point in time. Their
candidate tuples and pending/deployed labels are historical; use this section
and the latest ISO-candidate record above for current state.

## 19 October 0.4.1 ISO package mismatch — cause found; corrected rebuild pending

Both 0.4.1 candidate ISOs used the same DMS 1.6.2-26, Security Center 113 and
Security Context 106 RPM bytes. Their SHA-256 values did not match the RPMs
installed on bare-metal `<validation-host>`, despite identical displayed versions. The
previous “exact150” copy was placed in an unused import directory; composition
continued selecting the older cached RPMs. The images also use Application
Security 63 / Enrollment 54, which do match `<validation-host>`, and Session 22, retained for
the corrected protected Labwc startup. Source now has an explicit installed-RPM
import path that checks SHA-256 and RPM header identity and marks source
validation as not performed. No corrected ISO has been built or boot-validated
yet. See [ISO creation](architecture/ISO_CREATION.md).

The user confirms that the feature workflows in the
[post-0.3.8 bare-metal follow-up](patch-notes/post-0.3.8-bare-metal-follow-up.md)
were tested on physical `<validation-host>` (an HP OMEN laptop), including its AMD/NVIDIA
graphics, two external displays, Intel AX200 Wi-Fi, Intel Bluetooth, and USB
hub. The matched source package set has not yet been composed into a new ISO;
bare-metal testing of the installed system is distinct from clean-install
acceptance of that future image.

## 19 October Polkit blank authorization surface — defect traced; corrected package pending

The `<validation-host>` desktop was on Application Security 65 / Enrollment 56 / DMS
1.6.2-26, but the Polkit authorization display remained blank on an external
screen. The installed generated lock QML used `modelData.name` inside a
`WlSessionLockSurface` (whose screen is exposed as `screen`) and contained a
literal line break inside a quoted QML string. Both can prevent the protected
authorization card from rendering. A monitor disappearing during the prompt
also left its selected screen name stale. Source now reads
`lockSurface.screen.name`, retargets when Quickshell reports screen changes,
and emits a valid escaped newline. The previous source correction only forced
the lock and added a readiness message; it did not fix these render defects.

The 66 / 57 pair was the first corrected candidate. It was superseded by
Application Security 67 / Enrollment 58, then by 68 / 59 on 20 October. The
68 / 59 pair is now installed and migrated on `<validation-host>`. Visual acceptance still
requires a fresh login and authorization prompt. No ISO validation is claimed.

## 19 October Network Rules firewalld status — startup race fixed in source; live API recovered

The first Network Rules screenshot showed the incoming firewalld provider as
unavailable, even though firewalld was running. A direct call to firewalld
worked; GREYWARD's incoming-rules API did not. The root service only created its
firewalld D-Bus adapter if firewalld already owned its bus name at service
startup, and kept `None` permanently if it started a moment earlier. The
adapter now uses lazy D-Bus proxies that follow firewalld name-owner changes.
On `<validation-host>`, the incoming-rules API returned the firewalld catalog, external
zone state and editing capability after restarting only
`greyward-opensnitch-policy.service`. Context 0.1.0-108 built successfully;
firewall adapter, rule transaction and normalization tests pass. Installation
of Context 108 and a boot-startup readback remain pending.

## 19 October Network Protection and Protected Data status — source correction validated; deployment pending

On `<validation-host>`, the Security Center screenshot's stale-heartbeat warning was
reproduced after a quiet period: the OpenSnitch summary stopped changing, while
both system services remained active and `ss` showed an established
`opensnitchd` connection to GREYWARD's root-only Unix socket. The old check used
the timestamp of the last daemon statistics report as a heartbeat, so ordinary
quiet time looked like a monitoring failure. Source now confirms the connected
socket and labels a quiet stream as idle; it keeps the warning when that peer is
gone. A real `<validation-host>` check ran the candidate as the ordinary `example-user` user and
returned `OPERATING / IDLE / FRESH` after 42 seconds without application
traffic. The 30 network tests and 14 user-bus tests pass on Fedora `<validation-host>`; the
frontend's 107 tests, `cargo fmt`, `tests/static.ps1` and
`tools/validate-repository.ps1` pass. The candidate tuple is Security Center
0.1.0-114 and Security Context 0.1.0-107. It is not installed: `<validation-host>` has no
`rpm-build`, and no package or service was changed.

Correction to the earlier `<validation-host>` coverage note: the `GetCoverage` probe ran as
SSH root (UID 0, SELinux `unconfined_t`), so its `UNAVAILABLE` result and six
false fields described root, not `example-user`'s protected desktop. The active
UID-1000 seat verifier returns `verified: true` when run in the broker's
`unconfined_service_t` context. The installer-origin receipt matches the local
account, the enrollment record is `PENDING_SESSION` (accepted by the provider),
and a read-only replay of the 312 SELinux enrollment-boundary policy decisions
found no failures. This rules out the seat verifier and those policy-boundary
checks as the cause on `<validation-host>`; it does not substitute for a coverage snapshot
from the real protected desktop client.

The tested ISO screenshot reports `DEGRADED`, but it does not contain the
runtime coverage fields. Its old portal/deputy sentence was static UI copy, not
proof that baseline coverage had passed. The current source only shows that
caveat after baseline verification and lists missing required checks for a
degraded response. The exact ISO check remains unknown until `GetCoverage` is
read from that ISO's real protected session; no `<validation-host>` result can stand in for
it. This UI correction does not mark protection available.

The 19 October sections below preserve the source-review snapshot as it stood
before the subsequent bare-metal results were reported. The follow-up note is
the current summary of those user-confirmed feature tests and the remaining
ISO-build gates.

## 19 October Greeter and protected Polkit multi-display work — deployed on <validation-host>; external outputs not currently visible to DRM

Read-only inspection of <validation-host> found /etc/greetd/config.toml still explicitly
set WLR_RENDERER=pixman and launched the embedded DMS Greeter UI. The GREYWARD
QML surface and username correction already existed in the production source,
but were not deployed to the machine. The first live deployment copied those
files to their persistent `/usr/share` and `/usr/local/libexec` locations; they
are not RPM-owned, matching the existing production provisioner. The greetd
configuration now selects that external shell, and its journal confirms the
custom shell loads. The first load exposed an invalid visual `Repeater` for
nonvisual `TextMetrics`; source now uses `Instantiator`, and the fresh `<validation-host>`
load completed without that QML delegate warning.

The previous external-display fix selected wlroots GLES2 for the protected
desktop worker, but the greeter starts its own Labwc compositor and had been
left to auto-select a renderer. Its production launcher now explicitly selects
the same validated GLES2 path on physical systems, with Pixman retained for
known virtual GPUs or systems without DRM render nodes. The source launcher was
installed atomically on <validation-host> and greetd restarted from the greeter. The active
Labwc process receives `WLR_RENDERER=gles2`. At the latest readback, however,
DRM reported only the built-in eDP panel; the two external connectors had no
EDID and Nouveau logged DisplayPort training failures. The per-output QML and
renderer path are present, but three-screen behavior cannot be claimed until
the external links are detected again.

The stale `/var/lib/greyward/application-security/installation/source` tree is
not the active source: its October 12 `session.py` predates the renderer fix,
has no RPM owner, and has no runtime consumer in the installed service or
launcher paths. The active package source and integrity-checked protected copy
have matching October 19 hashes. The stale tree was left untouched rather than
deleted; current deployments use the package-owned Application Security source
and the canonical production overlay.

The protected DMS Polkit form now has GREYWARD's dark security styling. One
display owns the password field for each authorization request; other protected
surfaces show the selected display name and state that they are informational
only. The PAM/Polkit flow and password value remain in the existing protected
form and are never rendered on secondary screens. The installed Application
Security 0.1.0-64 / Enrollment 0.1.0-55 tuple contains this Polkit change.
No new ISO has been built or validated.

## 19 October firmware review and protected taskbar fallback — source changed, live install pending

The firmware adapter now compares each current fwupd HSI `HsiResult` with its
`HsiResultSuccess`; it no longer recursively mixes current attributes with
historical security events or assumes every successful result is the literal
string `valid`. System Checks lists the failing/unsupported attribute names,
measured and expected values, descriptions and supported configuration hints.
Firmware security review no longer links to Updates when no firmware release
is available. GREYWARD will not change UEFI settings automatically.

The DMS presentation keeps a confirmed status visible across its bounded
10-second collector cycle. The widget labels that gap as refreshing and disables
attention/actions; the separate `fresh_until` evidence/action deadline is
unchanged. This addresses the verified 5-second evidence lease versus 10-second
collector cadence. It is a source change only: no package was installed on
`<validation-host>`, and neither live DMS behavior nor the revised firmware UI has been
validated. The protected widget now has a read-only `GetSystemPosture()` system-
bus fallback for the known private-bus mismatch. It projects only global state
and bounded counts; no per-user activity, notifications or actions cross the
boundary. The root broker refreshes this projection in a separate, on-demand
worker so posture reads cannot block administration or USB approval. Initial
collection has a 20-second display window; a one-off system-bus read failure
keeps only the last confirmed aggregate visible for at most 12 seconds, with
actions and alerts cleared. This is display smoothing, not extended evidence.

Read-only inspection of `<validation-host>` on 19 October confirms Secure Boot is enabled and
the root posture helper reports `system.boot.secure-boot` as `SECURE`, while
`system.firmware.hsi` and security updates independently need review and portal
health is unavailable. Installed versions remain Security Center 0.1.0-111,
Security Context 0.1.0-105, DMS 1.6.2-25 and Application Security experimental
0.1.0-61. These source changes are not yet built or installed, and no fresh
login, package, hardware or ISO validation is claimed.

`mokutil --sb-state` and the current `fwupdmgr security` report confirm Secure
Boot is enabled. The current HSI report still has distinct findings: Platform
Secure Boot and SPI write protection are disabled; UEFI db is invalid; UEFI NX
protection is disabled. Other HSI checks are not supported or have their own
firmware/OS settings. These are the specific rows the updated System Checks
view is designed to expose; no firmware setting was changed.

At the time of this firmware-review change, the candidate package tuple was
Security Center 0.1.0-112, Security Context 0.1.0-106, DMS 1.6.2-26,
Application Security experimental 0.1.0-63 and Enrollment 0.1.0-54. The newer
matched candidate tuple is recorded above. Package builds and protected-session
migration remain pending; installed versions above are unchanged.

## 18 October broad Wi-Fi/Bluetooth firmware baseline — source complete

The production manifest selects Fedora 44 firmware for Intel MVM/DVM and legacy
Intel, Realtek, MediaTek, Qualcomm/Atheros, Broadcom/Cypress, NXP, Texas
Instruments WiLink and legacy Marvell Libertas adapters. Fedora resolves
`iwlwifi-mld-firmware` through the existing `iwlwifi-mvm-firmware` selection;
the shared `linux-firmware-whence` dependency is already pulled by
`linux-firmware`. Selection is independent of build-host hardware, and these
RPMs add no background service.

The production kernel closure already includes `kernel`, `kernel-modules` and
`kernel-modules-extra`. Offline Fedora-signed package resolution stays
centralized on `packages.txt`; stage validation now checks that every declared
firmware package appears in the generated Anaconda selection, while installed
acceptance checks the same immutable package manifest. Fedora 44 Updates
Fedora 44 Updates metadata revision `1792283140` lists 108,400,809 RPM bytes for
the nine new direct packages (103.4 MiB). Already-selected Intel RPMs and shared
dependencies are excluded, as is the small generated repository-metadata
change. A composed ISO's exact byte delta is not measured.

Focused image tests (40), static validation and repository validation pass.
The local Windows environment has no Fedora DNF/RPM toolchain, so a real offline
transaction and generated Anaconda payload were not built. No `<validation-host>` system was
changed for this broader selection, and no ISO was built.
Only Intel radio discovery has bare-metal evidence; clean-install and other
vendor hardware acceptance remain pending.

## 18 October `<validation-host>` Wi-Fi/Bluetooth — firmware fix installed, discovery verified

The active bare-metal system has an Intel Wi-Fi 6 AX200 and an Intel Bluetooth
controller. Their kernel drivers were present, but the kernel could not find
the requested firmware files. Fedora 44 provides them in
`iwlwifi-mvm-firmware` and `iwlbluetooth-firmware`, with
`iwlwifi-mld-firmware` selected as a dependency. GREYWARD had only listed the
base `linux-firmware` package. This was a production package-manifest omission,
not a DMS, rfkill, SELinux or USBGuard block.

Local commit `44f88c0` adds both direct firmware packages to the production
manifest; the offline builder resolves and verifies their signed dependency
closure, and production acceptance fails if either is absent. The 40 offline
image tests, static checks and repository validation passed.

On `<validation-host>`, DNF installed the three Fedora firmware packages and targeted
controller re-probes succeeded. The kernel loaded Wi-Fi firmware, NetworkManager
exposed the Wi-Fi interface and a scan found nearby networks. The Bluetooth
firmware loaded, BlueZ reported a powered controller, and a scan discovered
nearby devices. No network connection or Bluetooth pairing was attempted.
Ethernet/SSH and DNS remained functional; NetworkManager, Bluetooth, USBGuard,
firewalld and SSH remained active; SELinux stayed Enforcing; the integrated
Bluetooth device remained allowed by USBGuard. No targeted SELinux AVCs were
observed after the repair. Clean-ISO hardware acceptance, Wi-Fi connection,
Bluetooth pairing/reconnection, roaming and suspend/resume remain untested.

## 18 October keyboard layout — installer selection carried through

`<validation-host>` currently uses the French AZERTY layout selected during its install; its
greeter fix is active. The earlier source fix had hardcoded that layout, which
would be wrong for a future installation selecting another keyboard. Production
provisioning now reads Anaconda/systemd-localed's root-owned XKB record and
validates the model, layout, variant and options. It feeds the same values to
the greetd compositor, ordinary Labwc session defaults and the root-owned
protected-session receipt. The protected compositor does not read user-writable
environment files. Production acceptance compares the greeter and both session
paths with Anaconda's installed selection. Source-level tests cover alternate
layouts and reject malformed values; no new ISO has been built or installed.

## 18 October DMS multi-display fix — installed on `<validation-host>`

The previous `<validation-host>` session used DMS 1.6.2-21 while the plugin source fixes
were in DMS 1.6.2-25. DMS 25 requires matching protected-session packages, so
Application Security 0.1.0-61 and Enrollment 0.1.0-52 were built and installed
with it. At the user's greeter, the existing quiescent migration refreshed the
protected desktop and its receipts to DMS 1.6.2-25. The full DMS verifier and
RPM verification pass; SELinux remains Enforcing. No desktop session was
restarted by the migration. The next user login loads the new plugins; their
behavior on both external displays still needs visual confirmation.

## 18 October Administration console — launch error diagnosed

The user's `<validation-host>` screenshot showed Python rejecting the `sudo` handoff before
it could contact the protected broker. `/usr/bin/greyward-administration` was
installed with CRLF line endings; Linux passed the trailing carriage return in
its `#!/usr/bin/python3 -I` shebang as part of `-I`, producing Python's
“Unknown option” error. A direct interpreter reproduction confirmed the cause.
The source now enforces LF in Windows checkouts and both RPM payload copies,
with Application Security 59 matched to Enrollment 50. The live `<validation-host>` wrapper
is normalized with a root-only backup; no service, session or protection policy
was restarted or weakened. The wrapper's RPM verification will show the live
hotfix until a matched package set is built and installed. Source tests pass;
the user still needs to retry an actual graphical `sudo` request.

The user's retry then exposed a separate protected-session verifier failure:
`greyward_usbguard_approval_t` was added to the confined role by the USB
approval policy, but the verifier required the entire role-domain list to
remain equal to its saved snapshot. The `greyward_as_ordinary` set itself is
unchanged. Source now accepts that single reviewed non-ordinary domain and
recognizes a running helper only when UID, SELinux context, executable and
active logind session cgroup all match. Any other role addition, ordinary-set
change or helper mismatch still fails closed. Application Security 61 /
Enrollment 52 are source targets; `<validation-host>` remains on 53 / 43. Its running
protected generation has an integrity receipt, so it must be refreshed through
the existing quiescent migration before the desktop retry. No live protected
files have been changed for this follow-up. The candidate verifier returned
`verified: true` when run in a transient unconfined service against `<validation-host>`'s
active seat and actual SELinux policy; the installed graphical Administration
retry remains pending migration and user confirmation.

## 18 October DMS multi-display fix — user confirmed working

The user confirmed that Network Identity and Security Center plugins work on
the external displays. The DMS 1.6.2-25 correction scopes Security Center
process callbacks per output and widget; Network Identity shares one fresh
address snapshot across outputs. The protected desktop migration and package
integrity checks passed. Later DMS source/package revisions are documented
separately; see the [bare-metal follow-up](patch-notes/post-0.3.8-bare-metal-follow-up.md).

## 18 October Security Center package reconciliation — installed on `<validation-host>`

The installed releases had diverged: `<development-host>` had Security Center 0.1.0-110 /
Context 0.1.0-100, while `<validation-host>` had Security Center 0.1.0-100 / Context
0.1.0-103. The `<development-host>` Security Center contained the firewall rule editor, and
the newer `<validation-host>` Context release did not replace that missing UI. Current source
was built as Security Center 0.1.0-111 / Context 0.1.0-105, combining the rule
editor with the installed-application catalog and reviewed IP-rule behavior.

The canonical `environment/development/build-security-center.sh` build passed
on `<development-host>`; its Rust workspace tests passed, 88 Fedora Context network tests and
21 frontend rule-editor tests passed, as did `tests/static.ps1` and
`tools/validate-repository.ps1`. RPMs were installed on `<validation-host>`; `rpm -V` is
clean, SELinux remains Enforcing, and firewalld, OpenSnitch and its policy
service remain active. The editor/API files are present in Context 105. No
firewall rule was created or changed. The normal Security Center window has not
yet been visually checked after the update.

| Package | NEVRA | SHA-256 |
|---|---|---|
| Security Center | `greyward-security-center-0.1.0-111.fc44.x86_64` | `b5d2d1e02a99e206d2a8fe76e1588289e9b04000c865edca1fb67e6f9becfb27` |
| Security Context | `greyward-security-context-0.1.0-105.fc44.noarch` | `6e2b6b10ffba470c7e9820ae9530134207aff8d886b50d7d9a2ffc03b2df2f82` |

## 18 October `<validation-host>` hybrid-GPU display fix — external screens validated

The protected display worker now selects wlroots GLES2 on capable physical
systems, while authentication surfaces and known VMware/Hyper-V or systems
without DRM render nodes retain Pixman. `<validation-host>` is a physical HP OMEN laptop
with AMD and NVIDIA GPUs and two DRM render nodes; it previously logged
`Renderer did not support importing DMA-BUFs`. The backed-up worker source was
migrated into the active protected desktop generation while the greeter was
active. The user confirmed both external screens display the desktop after
reconnecting, and the running Labwc process reports `WLR_RENDERER=gles2`.
SELinux remains Enforcing; no device permissions or policy changed. Live RPMs
remain Application Security 53 / Enrollment 43; source targets 57 / 48. Kernel
logs also contain Nouveau DisplayPort training/watermark warnings, but both
screens currently work. Reconnect/reboot persistence is untested. This is a
bare-metal result, not a VM test. The next matched source tuple is Application
Security 59 / Enrollment 50.

## 18 October `<validation-host>` Trust always — installed workflow validated

The user confirms successful reconnection, physical-keyboard password entry,
protected authorization and disappearance of the matching USB2.1 Hub alert.
This completes the installed taskbar → protected IPC → Polkit → USBGuard →
verified device/persistent rule → matching-alert flow for the tested hub.
No approval was synthesized or allow rule created by the agent.

At the 10:58 readback, USB2.1 Hub `05e3:0610`, device 22 on `3-1`, is ALLOW,
authorized=true/trusted=true in both upstream USBGuard and the root projection;
its sysfs authorization is 1. Rule 24 is present in `/etc/usbguard/rules.conf`,
bound to its own stable hash, parent hash and interfaces. Protected PAM
successful-authentication/accounting records corroborate the user decisions.
Two separately approved child-device rules are present. The earlier USB2.0 HUB
`214b:7260` and other unapproved devices remain blocked. Root SSH could not read
the ordinary user-bus transport; matching-alert clearance is the user's actual
installed-UI confirmation, not an inferred result from helper exit status.

The scoped corrections address five concrete integration failures:

- FileView atomic replacement lost the readiness filename's intended label.
  A dedicated typed directory/default file transition now protects bounded
  PID/Polkit availability metadata; the internal heartbeat remains atomic/private.
- The Qt IPC client needed its own typed anonymous buffers and private socket
  primitives, without generic tmpfs, cgroup or protected-auth-file access.
- The fixed Python executor defined `main()` but never invoked it. Its isolated
  CLI now returns structured results and meaningful exit status.
- Password focus was not restored on late Qt window activation. The protected
  form now handles window entry/visibility without a focus-stealing timer.
- USB rule parsing confused `parent-hash` with the device's own `hash`.

Validation includes seven Fedora USB action tests, fourteen authentication
assembly tests, nine migration tests and the explicit offscreen focus regression
(previous generation fails; corrected generation passes with button navigation
preserved). A real auth-domain atomic FileView proof produces ten correctly
labelled replacement inodes. Thirteen enforcing kernel boundary decisions pass;
the legacy auth-domain USBGuard write pair was removed against canonical source.
Both repository gates pass. No general command execution or direct USBGuard
write access was granted to ordinary applications, the taskbar or the auth UI.

Two explicitly approved graphical-session closures activated the corrections.
SSH, USBGuard, Polkit and greetd remain active; SELinux stays Enforcing. Installed
RPMs remain DMS 21 / Application Security 53 / Enrollment 43 / Context 103:
these are backed-up matched source hotfixes, not newly built 22/54/45 RPMs.
Canonical next-build inputs are DMS 25 / Context 104 / Application Security 59 /
Enrollment 50; complete ISO staging rejects stale USB approval payloads. See
[the USB approval contract](security-center/USB_APPROVAL.md).
No reboot, GitHub publication or agent-created trust decision occurred.
Persistence across actual unplug/replug or reboot remains untested. No further
logout is authorized; this result does not establish ISO/release acceptance.

## 18 October `<validation-host>` session start — DMS verifier hotfix

The 09:38 login remained on “Starting your secure desktop” because the ordinary
DMS selector, running as the confined desktop user, tried to hash
`/usr/libexec/greyward-usbguard-auth-approval`. SELinux correctly denied this
cross-domain read, so `greyward-dms.service` exited and retried continuously;
the desktop-icons service consequently could not find a ready DMS backend.
This was a verifier integration bug, not a missing executable or a reason to
loosen SELinux.

The source verifier now hashes the protected helper only for root full
verification. Ordinary DMS startup still verifies its selected shell and
unprivileged taskbar helper but does not inspect the authentication-only
executable. On `<validation-host>`, the verifier was replaced directly with this source fix
and relabeled with `restorecon`; SELinux stayed Enforcing. The next DMS attempt
logged `Ready!`, Quickshell `Configuration Loaded`, a connected DMS API v34,
and the runtime checker reported `SHELL_READY` with `pong: true` at 09:47:18.
Those are service-level signals; the user has not yet confirmed that the normal
desktop is visible. The live RPM remains DMS 1.6.2-21 / Application Security
0.1.0-53 / Enrollment 0.1.0-43; source targets 1.6.2-22 / 0.1.0-54 / 0.1.0-45.
No USB approval was requested and no USBGuard rule was changed.

## 18 October USBGuard approval workflow — migration and login history

Before migration, the Trust always click reached the taskbar helper but failed
before Polkit: SELinux denied its read of `authentication-ready.json`, which
still had the general authentication-runtime label. The screenshot's
“protected authorization session is unavailable” was that fail-closed
response. No USB approval request or rule change occurred.

The installed tuple was DMS 1.6.2-21 / Application Security 0.1.0-53 /
Enrollment 0.1.0-43. The user logged out, and a closing-but-abandoned session
left Labwc and DMS processes behind. After the user authorized cleanup of only
that inactive session, migration completed and the greeter remained active.
SELinux is Enforcing; helper executable labels match their separate domains.
Existing readiness, instance-lock and IPC socket endpoints in `/run` also
needed targeted relabeling because they survived the old session. Their
expected labels now verify.

The next login attempt exposed a separate packaging defect: Python interpreted
`\\r`/`\\n` inside the generated QML template, splitting a JavaScript regular
expression and preventing Quickshell from loading `shell.qml`. The source fix
uses an LF character split and adds a generated-output regression check.
Application Security 0.1.0-54 and Enrollment 0.1.0-45 are prepared in source;
they are not yet built or installed on `<validation-host>`. No USB device is trusted yet,
and the Trust always / Polkit / rule-readback test remains pending. See
[Security Center architecture](security-context/ARCHITECTURE.md) and the
[ISO runbook](architecture/ISO_CREATION.md).

## 17 October Update Center on `<validation-host>`

The resolved system update plan failed at Apply because the update socket had
been created before enrollment loaded its dedicated SELinux file-context rule.
Its stale `var_run_t` label blocked the authenticated confined helper even
after Polkit authentication. On `<validation-host>`, the existing root-owned mode-0600
socket was relabeled to `greyward_update_runtime_t`; SELinux remains Enforcing,
the socket remains active, and the read-only worker preflight reports
`AVAILABLE`. No packages were prepared or installed. Enrollment now reapplies
the label after loading policy so a fresh installation does not repeat the
first-boot ordering bug. The Security Center desktop Apply action still needs
user confirmation after this repair. See [Update Center architecture](architecture/UPDATE_CENTER_ARCHITECTURE.md).

Center 110 / Context 100 is installed on the development desktop. Separate
application/IP workspaces use real installed applications and native services.
Checks pass: 392 Context, 160 frontend (three optional browser checks skipped),
208 Rust (22 ignored). A real outgoing-IP block/control/removal passes.
A static rule dialog used 202.4% WebKit CPU; the tested Hyper-V CPU-painting
mode used 1.0%. The packaged launcher now selects it automatically only when
all detected DRM cards use hyperv_drm; its normal installed launch is verified.
Final unlocked visual acceptance and protected GUI authentication remain pending;
the native WebKit clipboard crash remains open. See
[network rules](security-context/NETWORK_RULES.md).

## 16 October network rules — installed development candidate

Center 103 / Context 98 adds reviewed application/incoming rule editing,
stable revisions, bounded persistence, lifetimes, native firewalld recovery and
fresh per-transaction protected Polkit. Installed OpenSnitch UID/executable,
disable/re-enable, persistence and stale-request checks pass. Native incoming
source/port and runtime/permanent checks pass from a separate machine, followed
by verified removal. Non-admin and locked-admin writes are refused. The normal
Context service uses the installed code; its old development override is
preserved but disabled. Running Center and installed ELF hashes match.
Protected GUI authentication and visual acceptance remain pending.
A CRLF packaging incident briefly stopped OpenSnitch; repaired RPMs,
service recovery and deferred coupled activation are documented in the contract.
Generic Flatpak/script identity scopes and interactive prompts are unavailable.
Center 103 corrects the startup ReferenceError introduced in Center 102 by
initializing the network editor after its escaping helper. The regression now
executes all bundled scripts in HTML order, including the enabled network module.
The normal installed process restarts successfully; its live accessibility tree
contains Network protection, Rules and the editor controls rather than the
startup failure. VMConnect is minimized, so this readback is not visual acceptance.
See [network rules](security-context/NETWORK_RULES.md).

## 15 October native window placement retained for the next ISO

The existing production defaults enable Labwc edge/corner snapping and top-edge
maximization. Static validation now protects those settings, and ISO staging
rejects a Session RPM whose Labwc configuration differs from canonical source.
Real left-half snapping and native maximize/restore controls pass; other drag
gestures remain inconclusive. No ISO is generated for this change. See
[window placement](architecture/WINDOW_MANAGEMENT.md).

Publication reconciliation also checks the installed development tuple: Files
17, DMS 17, Session 18, AppSec 51, Enrollment 32, Center 100, Context 92 and
Branding 16 have clean RPM verification. Nineteen selected installed runtime,
enrollment, plugin and file-manager source inputs match the checkout after text
line-ending normalization. This is scoped source/integrity evidence, not a new
binary build or security-acceptance claim. Session 21 remains the newer image
default; it is not silently substituted for the installed Session 18.

## 14 October GREYWARD 0.4.0 Dawn internal ISO candidate

The canonical builder created `GREYWARD-0.4.0-Dawn-x86_64.iso` on `<development-host>` and
copied it to `<local workspace>`. SHA-256 is
`4ab9c4fc54cfdabceabb521378cae4dfcf81aa0bd778a4d29268c8ae9b717b10`.
The sidecar matches, and the ISO volume ID is `GREYWARD-INSTALLER-44`.

The candidate contains Files 1.0.0-17, DMS 1.6.2-17, session 0.1.0-21,
Application Security 0.1.0-51, Enrollment 0.1.0-32, Security Center
0.1.0-100, Security Context 0.1.0-92, Branding 0.1.0-16 and OpenSnitch
1.8.0-1. Session 21 carries the Strata taskbar default from current source;
it was built for this ISO and is not installed on `<development-host>` (which remains on
Session 18). The DMS package's first-party plugin payload matches the selected
source after CRLF normalization, including the Security Center launcher.

Static and repository validation pass. Fedora image tests (67), the combined
build/DMS/enrollment/authentication/display suite (63), and desktop tests (6)
pass. Production stage checks pass before and after ISO extraction (29 declared
paths); the offline Fedora media repository resolves; the independent Windows
Rock Ridge validator passes all 39 required paths. The build reused the DNF and
Flatpak cache and verified the six selected Flatpak commits. The receipt records
`installation_requires_network=false`,
`installer_dependency_resolution_tested=true` and
`installed_system_tested=false`.

This remains an internal candidate. It has not been installed or booted. Fresh
installation, actual Security Center button interaction, protected lock/unlock,
Administration/Safe Open regressions, USB, SMB/SFTP and multimonitor behavior
remain unverified. See [ISO evidence](architecture/ISO_CREATION.md) and the
[file-manager integration record](architecture/FILE_MANAGER_DESKTOP.md).

## 14 October native-icon and preview candidate

Files 17 is installed in development, retaining revision 15's pinned-source
executable and balancing the shared icon accents. The user accepts revision 17's
icon color balance on 14 October. The normal desktop review
confirms matching silhouettes, visibly blue DOCX/ODT and green XLSX/CSV badges,
plus SVG thumbnail rendering. Three Rust metadata checks and twelve Fedora
Python checks pass for revision 15; revisions 16–17's incremental offline RPM builds
repeat the three Rust checks and preserve the release ELF. Package integrity,
SSH and SELinux Enforcing checks pass; the active normal session remains open
through revisions 16–17 build/install. Matched rollback packages are retained.
Installed ordinary-domain SVG/PDF/video helpers and registered-secret denials
pass, confirmed by enforcing AVCs. Actual Strata previews, one-second video
playback, duplicate/rename and approved Trash/restore pass with unchanged data.
USB, SMB/SFTP, multimonitor, renewed Administration/lock and clean-image gates
remain NON VÉRIFIÉ; keyboard Space/Delete injection remains inconclusive.
Revision-15 construction previously coincided with guardian heartbeat expiry,
loss of the desktop and compiler OOM; that incident is recorded separately and
is not evidence that native locking is fixed. See
[the owning record](architecture/FILE_MANAGER_DESKTOP.md).

## 14 October preview runtime requirements

Files 14 is installed with explicit dependencies for seven external helper
programs. Offline build, package metadata and integrity checks pass; the
existing executable and shared icon assets are unchanged. Installed helpers
render synthetic image/PDF/video previews and reject the registered mock secret.
These are backend mechanism checks; GUI preview, visual icon acceptance,
native-lock activation and full offline ISO/fresh-install gates remain pending.
See [the owning record](architecture/FILE_MANAGER_DESKTOP.md).

## 14 October icon consistency review correction

Files 13 is installed. Strata extension resources now resolve to the same full
native MIME artwork, and its embedded application icon uses the canonical Files
identity. Six focused tests, repository gates, RPM verification and all 455
embedded-icon/821 installed-asset checks pass. The desktop-icon unit is refreshed
without ending the session. After user unlock and Strata relaunch, the real grid
shows shared folder/text artwork and the GREYWARD Files identity. Strata still
shows launcher files as generic documents and lacks native ODT thumbnails; these
require source integration, not additional icon overlays. Whole-interface visual
acceptance remains pending, with further console checks currently interrupted
by truncated VMConnect capture. Revision 11's folder/text checks were partial;
the user rejects its overall consistency. Native-lock activation remains pending.
See [the owning record](architecture/FILE_MANAGER_DESKTOP.md).

## 14 October native-lock correction activated; live acceptance pending

Runtime 51, Enrollment 32 and Session 18 are installed after explicit approval
to end the graphical session. Protected runtime migration and RPM verification
pass; SSH, workflow broker and greetd are active, and SELinux remains Enforcing.
The console confirms return to greetd; user reconnection and live lock/PAM
acceptance remain pending. No reboot occurs. The existing
native DMS custom action routes enrolled ordinary lock requests to Guard;
unconfined sessions retain local native locking. The helper waits for root-verified
lock status. The private authentication worker disables only Qt clipboard
interfaces, complementing its already disabled backend collector. Installed Qt
registry probes preserve the seat while suppressing clipboard bindings. Forty-two
focused Python tests pass on Fedora; package checks, rollback preparation and
the three-package dependency dry run pass. Real post-activation PAM unlock and
post-correction stability remain pending. No policy, PAM or greetd change is made.

The old Runtime 50 later acquires a real native lock without retiring its session;
the console and broker confirm it. This is acquisition evidence only, and does
not disprove the earlier intermittent exit or validate the new candidate. See
[the owning record](architecture/FILE_MANAGER_DESKTOP.md).

## 14 October shared icon family

Files 1.0.0-11 is installed on the development desktop. The native theme and
Strata's icon-only resource overlay use one catalog; real column/grid and
desktop checks confirm the shared folder/plain-text appearance. Package builds,
five focused tests, repository gates and installed asset/resource coverage pass.
The upstream Strata ELF and third-party application logos are preserved. Real
thumbnails remain content previews, not themed icons. Broader image acceptance
is pending; see [the owning record](architecture/FILE_MANAGER_DESKTOP.md).

The 00:15 automatic-lock attempt coincides with another real session closure:
the guardian reports authentication-owner-exited and logind removes the session.
It precedes icon installation. This is not ordinary lock-screen behavior and
its cause remains unresolved. Clipboard/drag/drop successes do not prove native
locking or overall session stability. No auth/compositor policy was relaxed.

## 13 October Strata and transparent desktop proof

Strata 1.0.0 (verified checksum and upstream build attestation) and Fedora
PCManFM-Qt 2.4.1 are installed for a reversible ordinary-user experiment.
Both use `greyward_guard_t`; the real desktop displays PCManFM icons over the
unchanged DMS wallpaper and keeps the taskbar. A synthetic original folder opens
in Strata. Nautilus remains available, the folder MIME preference is backed up,
and no compositor, authentication or SELinux policy was changed. The shortcut
helper verifies installed launchers and preserves explicit executable trust review.
The Obsidian theme and scoped icon-free desktop menu now render on the real
desktop. The verified Strata payload, native wrappers and desktop user unit are
packaged as `greyward-files` 1.0.0-6 and installed; RPM verification is clean.
Real reconnects exposed and corrected a systemd cycle and wallpaper/icon startup
ordering. Approved matched activation installs DMS 17, runtime 47 and Enrollment
28; the real login and automatic icons work. The native taskbar creates verified
shortcuts. Their existing warnings were removed at the user's request through
native launcher approval, and Strata now has the canonical Obsidian/Platinum
folder icon. Remaining security/workflow acceptance and offline ISO integration
are not complete. Earlier entries below are historical snapshots. See
[the owning implementation record](architecture/FILE_MANAGER_DESKTOP.md).

Further installed validation advances Files to revision 8 and Session to 17:
FileManager1 routes to confined Strata, the desktop startup probe reports only
`SHELL_READY`, and real clipboard copy to the desktop preserves the original's
digest. Strata replaces Files in the taskbar. A later guardian-driven spontaneous
session closure remains unresolved; the approved repeat did not reproduce it or
complete drag/drop. Exit diagnostics pass eleven Fedora tests and are activated
through an approved logout as runtime 49/Enrollment 30; normal login succeeds.
Desktop-to-Strata paste then reproduces the closure: `readiness-io`, with the
authentication UI PID gone before seat teardown. Its exit cause and the reverse
clipboard transfer remain unresolved. The approved monitored repeat captures a
fatal private-backend Wayland EOF and `authentication-owner-exited`. Runtime
50/Enrollment 31 now disable only that private backend's unnecessary clipboard
collector using its native configuration; three Fedora tests and offline builds
pass. The real post-correction paste succeeds with matching SHA-256 and the same
protected authentication PID. Automated drag/drop is inconclusive, but the user's
manual transfer succeeds and real destination/digest/session checks pass. Ordinary
protected mock-file access remains denied. This is not image/security acceptance.

## 13 October DMS plugin recovery (historical; superseded by the 14 October candidate)

A rollback to DMS 1.6.2-14 had restored the old `greywardSecure` plugin, whose
Security Center button had neither working launch behavior nor feedback. A
manual file replacement was rejected by DMS's first-party integrity check, so
it was not left as an untracked live override. `<development-host>` now has the matched DMS
1.6.2-15, Application Security 0.1.0-45 and Enrollment 0.1.0-26 packages;
Security Center 0.1.0-90, Security Context 0.1.0-81 and Session 0.1.0-16 were
left in place. The DMS 15 plugin matches the last ISO's fixed launcher and
opening/success/failure feedback. RPM verification is clean, the plugin hash
matches the built RPM, the DMS user service is active and its journal records
`greywardSecure` loaded. SELinux remains Enforcing. Only DMS was restarted; the
VM and Labwc session were not restarted. The button has not yet been clicked by
the user, so visible launch acceptance remains pending.

DMS 14 must not be restored for the launcher-feedback fix: its plugin payload
is the broken version, and installed Enrollment 16 requires exact DMS 14.
Restoring DMS 15 requires its matched Application Security and Enrollment
packages. The desktop
icon experiment remains rolled back: PCManFM-Qt and Kvantum were removed, and
its generated autostart, profiles, launchers and test shortcuts remain archived
at `/home/example-user/.local/state/greyward-rollback/20261013-desktop/`. The source
still selects DMS 1.6.2-15 and keeps the protected 1920×1080 fallback and safe
interrupted-enrollment recovery. No ISO was rebuilt.

## 12 October 0.3.5 Dawn protected-display candidate

The replacement candidate was built at
`/mnt/greyward-build/build-20261012-display-fallback-fix/output/GREYWARD-0.3.5-Dawn-x86_64.iso`;
SHA-256 `492493695ceeb8a60dfe4a742b0c4d9a9252a88de140330359e2bf02b3918867`.
Its matched inputs are DMS 1.6.2-15, session 0.1.0-16, Center 0.1.0-100,
Context 0.1.0-92, branding 0.1.0-16, Application Security 0.1.0-45 and
Enrollment 0.1.0-22. The latter requires AppSec 45 exactly. Application
Security's installed RPM contains the protected-compositor autostart request
for `Virtual-1` at 1920×1080. The candidate retains the launcher feedback and
shared 30-second transient-alert filter.

The canonical image builder passed the source/package guards, offline
dependency resolution and both pre- and post-extraction production-stage checks
(29 declared paths). The ISO sidecar SHA-256 matches, and the independent
Windows media validator passed for 39 required paths. The build receipt says
`installer_dependency_resolution_tested=true` and
`installed_system_tested=false`. This image has not yet been installed or
booted on R6, so its runtime resolution result is still pending. See [ISO
creation evidence](architecture/ISO_CREATION.md).

### Previous candidate display failure and source correction — 12 October

The prior candidate at
`output/iso/rebuild-20261012-r6-fix/GREYWARD-0.3.5-Dawn-x86_64.iso` (SHA-256
`e69b923a6b4561e74bc1351d5e2f2030a07d07cbb3906112acbfe00317f2c421`) was
installed on R6; the user reports that its session still started at 1024×768.
The mode request was in the account's writable Labwc autostart, while the
protected compositor loads a separate root-owned configuration whose generated
autostart was empty. The source now puts the fixed `Virtual-1` 1920×1080 request
in that protected autostart. The matched package tuple and validation for the
replacement are recorded above; runtime resolution remains unverified until R6
is installed and checked.

The previous candidate at
`/mnt/greyward-build/build-20261012-rebuild/output/GREYWARD-0.3.5-Dawn-x86_64.iso`
is rejected: R6 reported `Matched DMS package shell/receipt required` because
the exact release allowlist ended at DMS 1.6.2-14. Its authentication source
hashes still matched the reviewed pins; the replacement above adds 1.6.2-15.

## Source publication audit — 11 October

The earlier per-account DMS keyboard preference implementation is preserved as
unpromoted development work. It is absent from the current package sources:
its source checks and package assembly did not establish installed next-login
keyboard behavior. It must be reconciled with the newer desktop generation
before promotion. Current source CI does not prove ISO installation, live
desktop behavior or offline recovery acceptance.

11 October ISO rebuild: `GREYWARD-0.3.5-Dawn-x86_64.iso` was composed from
the existing cache and validated. SHA-256 is
`46ed1156b7096f905f3c0b1e990c4775da8d82c93030c58d77e2d225dab6302e`;
the ISO sidecar checksum passed on `<development-host>`. It includes DMS 1.6.2-15 with the
current Security Context plugin (launcher feedback and synchronized alert
projection), session 0.1.0-16 with a bounded 1920×1080 request for the exact
`Virtual-1` virtual output before DMS starts, and Enrollment 0.1.0-18 matched
to DMS 1.6.2-15. The source-to-package guards and production-stage validation
passed; the ISO carries its boot records and validated offline installation
payload. The build reused the existing DNF/Flatpak caches. No VM was created or
booted, and installed-system display behavior remains untested. See the
[monitor configuration record](architecture/DMS_MONITOR_CONFIGURATION.md).

11 October Security Context alert synchronization: the DMS plugin was using a
second client-side 30-second timer, so its cards and badge could appear on a
different schedule from native desktop notifications. Source now computes one
`notification_items` list for both consumers; Security Center live posture
remains immediate. The corrected files are installed in the `<development-host>` development
overlay with backups, original ownership/modes and SELinux labels preserved;
remote hashes match the deployed source. All 21 focused tests passed on Fedora.
The user restarted the Context and DMS services after deployment; the DMS
journal confirms `greywardSecure` loaded at 19:56:06 CEST. SELinux remains
Enforcing. Naturally persistent warning behavior has not been exercised after
that reload.

The taskbar's **Open Security Center** action now focuses an existing window or
launches the desktop entry through DMS `SessionService`, with opening, success
and failure feedback. Frontend and static contracts cover the launch path.

11 October login, display and notification follow-up: the next protected
desktop generation reuses the mode selected by the greeter. Its login broker
still waits for Polkit registration, but its readiness signal polls every
100 ms during startup and returns to a one-second heartbeat after registration.
New sessions seed a 1920×1080 profile only for a `Virtual-1` output; physical
displays retain their selected mode, while existing user profiles are
preserved. Secure DNS, firewall and device-protection warnings now remain
visible in live Security Center status immediately, while desktop attention and
notification prompts wait for 30 seconds of continuous warning. Critical
events remain immediate. `<development-host>`
currently runs at 2560×1440 and has an existing migration marker, so its
resolution choice is not overwritten. The user restarted only
`greyward-security-context-user.service`; the user manager logged a successful
start of the updated development overlay at 13:54 CEST, while Labwc and DMS
remained unchanged and SELinux stayed Enforcing.

11 October protected-session startup follow-up: Application Security 0.1.0-41,
Enrollment 0.1.0-16 and DMS v1.6.2-14 are installed on `<development-host>`. Enrollment 14
refreshed the verified session worker and integrity receipts through its
quiescent migration. The earlier successful login took 6.35 seconds to reach
DMS; the startup backdrop now appears before the desktop, and the user accepts
that visual transition workaround for now. This improves the black-screen
experience but does not claim faster session startup. An earlier failed attempt
entered GNOME and `gnome-shell` segfaulted in `libmutter-18.so`; the successful
GREYWARD path later used the protected session.

Earlier 11 October keyring observation: `<development-host>`'s greetd PAM stack includes GNOME Keyring's
authentication and session hooks, and the login journal reports the daemon
starting and unlocking. The login keyring file did not exist before the reported
prompt and was created when the session first requested a secret, indicating
first-use keyring setup rather than a failed unlock of an existing keyring. It
was present and unlocked at the last check. No keyring reset, blank-password
keyring, or PAM/SELinux weakening was used. No later prompt observation is
recorded.

10 October DMS monitor configuration: `<development-host>` now uses the corrected DMS user
unit. DMS had joined the absolute `WAYLAND_DISPLAY` it inherited from UWSM to
`XDG_RUNTIME_DIR`, producing a nonexistent double-prefixed socket path. The
unit pins the relative `wayland-0` name; after installing the corrected session
RPM and restarting only DMS, logs confirmed WLR output-manager initialization
and `wlr-randr` read back 2560×1440. SELinux remained Enforcing. The ISO stager
now rejects a `greyward-session` RPM unless its packaged DMS unit matches the
fixed source unit byte for byte. See the [monitor configuration
record](architecture/DMS_MONITOR_CONFIGURATION.md).

10 October: the user accepts the R5 installation/login fix. R6 is built, hash-verified on Windows and mounted in the existing R5 VM with the output-management commit 8c130a662b047a33406c695d54adf524cc302d99 and a greeter-only CPU OpenGL renderer correction for the canonical wallpaper. Private compiled-protocol and actual embedded-greeter rendering checks pass; installed R6 greeter and DMS apply remain pending. See the candidate evidence (private development evidence).

Earlier entries below are dated evidence, not current acceptance claims.

Earlier 10 October monitor notes recorded three failures in order.
The protected Labwc global filter omitted `zwlr_output_manager_v1`; the auth
session then combined its private `XDG_RUNTIME_DIR` with an absolute
`WAYLAND_DISPLAY`; finally DMS Settings retained a stale QML backend flag even
after DMS logged a successful WLR manager bind and `wlroutput` capability. The
Labwc and socket fixes are deployed on `<development-host>`, SELinux remains Enforcing, and a
headless scale transaction passed. A reactive QML readiness patch is recorded
in the pinned DMS release manifest; exact shell assembly and a network-isolated
`greyward-dms-1.6.2-9` RPM build passed. The patched QML file is deployed as a
manifest-verified development overlay on `<development-host>`, but the DMS RPM selector remains
at `v1.6.2-6`. The prior desktop session is at the greeter; live Settings and
mode-change acceptance need a fresh interactive login. No new ISO was built. See the
[monitor configuration record](architecture/DMS_MONITOR_CONFIGURATION.md) and
[production contract](../environment/production/README.md).

10 October r5 candidate: Enrollment 5 corrects the confirmed mode-0700 program-directory login failure. The repaired r4 installation reaches the desktop (user confirmation and console evidence). R5 composition, embedded payload checks and Windows SHA-256 verification pass; fresh r5 installation, default session selection and installed security acceptance remain pending. See the candidate evidence (private development evidence).

10 October installed r4 acceptance: installation completed according to the user, but GREYWARD Labwc login fails and the greeter defaults to Hyprland. R4 is not accepted. Only the new test VM is in an approved rescue investigation; <development-host> remains the unchanged build host. See the failure evidence (private development evidence).

10 October ISO rebuild: r3 failed clean installation because private installer-origin storage was missing; it is rejected. Enrollment revision 4 is rebuilt, eleven lifecycle tests pass, and the actual packaged broker reproduces the missing-directory failure then succeeds with corrected private storage in a synthetic clean root. The r4 ISO has built, passed payload checks, and hash-matched on Windows. It is attached to the new empty test VM without runtime activation on `<development-host>`. Clean-install acceptance remains pending. See the candidate evidence (private development evidence).

10 October enrollment ISO candidate: matched installer enrollment inputs are now
packaged without activating them on `<development-host>`. The copied offline SELinux store
links successfully and the packaged compositor digest matches. The build host
remains the running development system. Candidate composition has passed;
clean-install, graphical enrollment and encrypted recovery acceptance remain
pending on the separate test VM. See the [enrollment authority](security-center/APPLICATION_SECURITY_ENROLLMENT.md).

The earlier 10 October blocker receipts below are historical snapshots; their
pre-assembly NO-GO findings are superseded only by the scoped checks recorded
above, not by production acceptance. See the candidate evidence (private development evidence).


10 October enrollment-required ISO readiness (private development evidence):
protected graphical login is observed running; dedicated build storage has 41 GiB
free. Actual authentication assembly rejects the revision-8 RPM's receipt.
Matched enrollment packaging, installer activation and encrypted repair/rollback
remain blocking. The user requires enrollment before building; no ISO was built.


10 October login routing recovery (private development evidence):
session 9 is built and installed on the development machine. It restores enrolled
protected admission after session 8 selected ordinary Labwc. Seven focused Fedora
tests and package verification pass; real graphical login retry remains pending.

10 October final ISO blocker audit (private development evidence):
DMS candidate 1.6.2-8 pins recorded Fedora Python 3.14.8 exactly; its offline RPM
rebuild and 50 upstream tested Go packages pass in the explicitly authorized
`<development-host>` build workspace.
Center 90 / Context 82 artifacts remain preserved. Production enrollment and
authenticated repair/rollback are unvalidated and incompletely packaged; ISO
construction remains NO-GO. No installed package or active session is changed.

10 October repository consolidation and ISO preparation (private development evidence):
source candidates Center 90 / Context 82, runtime 33 and DMS 1.6.2-7 have distinct
identities; the installed development tuple remains unchanged. Experimental runtime
and D-Bus overlay are excluded from the image. ISO construction is NO-GO pending
the exact package, storage and mandatory validation gates. No runtime mutation,
cleanup, ISO build, session interruption or release tag was performed.
Publication is BLOCKED by the configured SSH commit-signing key failing to
unlock. No new commit or push occurred; reviewed public changes remain staged.

Source-only targeted security truthfulness fixes (private development evidence)
correct confined ClamAV status collection and narrow portal/VPN/accepted-risk/grant
claims. Local checks are distinct from pending installed-session validation;
`<development-host>` remains on its existing package tuple with no deployment or service change.


9 October D-Bus prerequisite: **inspection correction VALIDATED on `<development-host>`**.
An explicit unpackaged development CIL overlay denies ordinary inspection of
the existing session/a11y buses; 62-domain kernel readback and actual mem-open/
invalid-FD probes pass. Messaging/FD masks, stock Flatpak chooser, Context and
Administration projections remain compatible. Remove/reapply rollback passes
without any bus/session restart. Existing native root previews reject foreign,
exited, stale and changed-object use. **Portal request-to-Flatpak recipient
binding remains NOT IMPLEMENTED; hybrid permissions remain BLOCKED.** See the
scoped receipt (private development evidence).

9 October bounded hybrid permissions: **BLOCKED** before bridge/grant integration.
The disposable Flatpak subject bootstrap and non-mutating live session-bus check
are implemented. The earlier normal same-UID user bus passed an ordinary caller's
inspection authorization check; its wider trust closure needs reassessment before
forwarded portal identities can authorize grants. Both application-specific
enforcement and first-use UX gates remain NOT DEMONSTRATED. Temporary policy,
workloads and code copies were removed; no grants or desktop/bus activation
changed. See the execution receipt (private development evidence)
and [current authority](security-center/APPLICATION_SECURITY_PLAN.md).

Previous 9 October first-use prerequisite: **BLOCKED** at the minimal-architecture
gate. Installed probes confirm sandbox-hidden paths emit no resource AVC and
the shared GTK FileChooser's denial does not identify the requesting Flatpak.
App-only grants cannot unblock that chooser; broad portal access is not an
accepted workaround. No generic grant UI, script provider, Sensitive files
provisioning, authorization or runtime changes were made in that previous probe. See the
prerequisite receipt (private development evidence)
and [current authority](security-center/APPLICATION_SECURITY_PLAN.md).

This document answers “what is true today?”. It is a status summary, not a
replacement for the domain specifications listed in [INDEX.md](INDEX.md).

## Implemented or active

- Administration console visual polish (9 October): the normal `<development-host>` desktop
  runs an explicitly assembled native UI overlay on runtime 32; package-owned
  files and Center 89 / Context 81 / session 8 remain unchanged. Risk review now
  explains credential exposure, security changes, data loss and root-shell
  lifetime. The follow-up adds obsidian grain, embedded canonical SVG branding,
  a red Administration title, silver controls and an explanation of the sudo
  handoff. Larger terminal text and readable ANSI colors preserve the continuous
  canvas instead of black default cell rectangles. Actual
  normal-seat review, fresh PAM, confined sudo/root execution and terminal output
  were visually checked. Renderer/admission and kernel checks are recorded in
  the latest visual receipt (private development evidence).
  This is development evidence, not a newly built runtime RPM or image.

- Practical SELinux administration/usability (9 October): Center 89 / Context 81 /
  runtime 32 and session package 8 installed. Approved normal-seat logout/login
  activation passes without reboot or SSH loss. Actual terminal `sudo -i`, fresh
  PAM/sysadm, nested sudo with the private Fedora helper, native lock/unlock and
  end-session checks pass. Read-only Flatpak metadata/watch, ordinary certificate
  mount preparation and DMA enumeration repair general launch failures without
  application exceptions or raw DMA access. Brave, Proton VPN's GUI, new
  Calculator, Collabora, native terminal/browser, real GTK document selection,
  development/files/network/background workflows were exercised. A fresh reviewed
  key-inspection grant commits revision 7, reuses without authentication, and
  revokes at revision 8; direct/wrong-tool/revoked execution stays denied.
  Current kernel checks pass 937 adjacent decisions. Fresh ordinary coverage
  verifies and SSH recovery remains available. Screen sharing is unavailable;
  VPN connection, whole-desktop rollback and production/offline-rescue acceptance
  remain unpassed. DMS's two prior development plugin overlays have reconciled
  root receipts, not a new reproducible DMS package.
  See the [enrollment authority](security-center/APPLICATION_SECURITY_ENROLLMENT.md)
  and normal-seat receipt (private development evidence).

- Sensitive-access Review routing deployed on `<development-host>` (9 October): Center 87 /
  Context 80 / runtime 28, plus a recorded root-owned development overlay for
  the DMS 1.6.2-6 security widget. The publisher supplies the validated resource
  reference; Center opens that registered resource, related denial history and
  existing grant controls. Native wake-up restores the same minimized window.
  The widget previously ignored its `open` action; actual desktop Review now
  navigates from Overview to the affected resource. The widget exposes only
  supported actions; Dismiss remains available in the system notification.
  Running Center binary matches the installed package (SHA-256 prefix
  `a8822aa49f4a2436`). Actual fake-key reads remain denied, exit 1; coverage is
  PROTECTED / AVAILABLE with policy revision 6. No grant or confinement change
  was made. Frontend 115 pass locally; Fedora frontend 114, shell experience 21,
  notification router 7 and shell runtime 8 pass; changed Rust file formatting,
  static and repository gates pass. Workspace formatting still finds existing
  differences in `resource_labeling.rs`. Previous Center 86 / Context 79 RPMs,
  receipt, widget preimage and validation are retained in root-only
  `resource-review-20261009` beneath the development runtime receipt directory.
  Arbitrary script/VS Code raw-key approval and restrictive temporary grants
  remain undelivered functional work. Intermittent legacy DNS/USB projection
  unavailability observed during validation is not claimed fixed by this pass.

- Normal `<development-host>` Black Box terminal paste repaired (9 October). Actual
  Ctrl+Shift+V reproduced immediate window closure with a simultaneous SELinux
  denial of Labwc writing the ordinary client's selection pipe. The canonical
  compositor policy now permits only that FIFO write; no protected-file read or
  grant-domain permission was added. Applied live without desktop restart;
  the same text pasted visibly into the real terminal and the window survived.
  The synthetic protected-key threat script still returns permission denied,
  exit 1, and broker coverage remains PROTECTED / AVAILABLE. Original module
  export and build receipts are retained in root-only `terminal-paste-20261009`
  under `/var/lib/greyward-development/application-security-live/`.

- Context 77 Update Center resolver repair deployed on `<development-host>` (9 October):
  native DNF resolution now enforces the desktop holds already shown by inventory
  and used by Apply. The former Quickshell 0.3.2 conflict is gone: live resolution
  returns RESOLVED, 535 package changes, zero removals; the installed Updates page
  shows Updates ready after refresh. Interrupted resolver startup no longer keeps
  checks blocked. Fedora focused tests: bus 26, compatibility 3, provider 12 pass;
  static/repository gates pass. No pending updates applied or reboot scheduled.
  Resolver repair initially used Center 86 / Context 77 / runtime 28. Prior Context 76 RPM
  is retained; root-only receipt backup is `update-resolver-20261009` beneath
  `/var/lib/greyward-development/application-security-live/`.

- Context 79 authenticated update handoff deployed on `<development-host>` (9 October).
  The failed post-password operation retained the ordinary confined domain,
  so Btrfs recovery inspection was denied and misleadingly reported a missing
  subvolume. A root-only socket-activated fixed worker now supplies system-service
  authority without granting ordinary applications administrative privileges.
  Live preflight from the same confined root context passes; ordinary-user helper
  and socket access remain denied. A real read-only recovery point
  `20261008T223026Z-da732756` was created and verified valid, with `ro=true`.
  Session coverage remains PROTECTED / AVAILABLE; read-only update resolution
  returns RESOLVED (535 changes, zero removals). Fedora focused tests: update bus
  30, recovery 33, provider 12 pass. Disposable old Cargo cache cleanup recovered
  space (6.4 GiB available); existing recovery points and source were retained.
  That update-worker validation used Center 86 / Context 79 / runtime 28. Context 77 RPM and
  previous policy are retained; root-only receipts are in `update-worker-20261009`
  beside the resolver receipts. A subsequent live GUI retry authenticated,
  created valid recovery point `20261008T223407Z-82f92bbc`, and reached
  PREPARING_RESTART with no error (operation `dnf5-1791498836977`). Provider
  download/preparation completion and the offline update/reboot are not yet
  claimed as passed.

- Security Center 86 sidebar deployed on `<development-host>`: shared shield emblem centered
  above branding, larger menu labels, and removed local-security footer. The menu
  uses the available height; normal and maximized layouts visually checked in the
  real desktop. Frontend UX 93/93, branding and repository gates pass.

- Normal `<development-host>` post-login resource/Flatpak failures repaired: runtime 28 with
  stable filesystem receipt reopening, canonical descendant namespace policy,
  and bounded public-IP transport retries. Broker resource coverage is PROTECTED;
  actual Brave loads HTTPS and the public IP is visible. Native/Flatpak protected
  reads and parent namespace writes remain denied. Center 85 / Context 76 retained.
  Causes, evidence and limits (private development evidence).

- Enrolled `<development-host>` greetd login recovered: ordinary UWSM startup no longer
  inherits protected-console IO; the audited plugin overlay now has its matched
  selected receipt. Real GREYWARD login reaches the visible desktop/taskbar,
  protected-seat verification passes and SSH remains available. Four focused
  Fedora descriptor checks pass. Recovery evidence and limits (private development evidence).

- Plugin/Center protection-state parity is installed on `<development-host>`: Center 85,
  Context 76 / runtime 27. The shell uses shared evaluated check states and
  accepted deviations, and the same File Security readiness as Center.
  Actual System checks shows zero findings; the flyout shows Protected and
  no spurious malware/firewall/device warning. Eight live samples remain
  Protected; mandatory desktop readback passes. Existing recorded blocks
  remain informational. Parity evidence (private development evidence).

- Security Center plugin stability receipt historically records normal `<development-host>`: Center 84,
  Context 75, runtime 27, DMS 1.6.2-6 with a backed-up development QML overlay.
  D-Bus threading initialization and separate negative-display/action leases
  correct the diagnosed crash precondition and expired-display flapping. Actual
  flyout inspection and 30 live samples show stable Review needed; real provider
  warnings remain. Context had zero restarts during this short check.
  Evidence and limitations (private development evidence).

- Security Center's main window is explicitly exempted from Labwc's forced
  server decoration in canonical session configuration and the normal `<development-host>`
  protected desktop. The GTK app ID was observed through the real Wayland
  toplevel protocol. VMConnect shows a single application-owned titlebar in
  normal and maximized states, with maximize/restore working. The titlebar receipt records
  84 / Context 72 / runtime 27; protected-desktop readback passes. Earlier
  WebKit-only chrome captures did not validate the compositor frame.

- The performance development receipt (private development evidence)
  historically records installed Center 84 / Context 72 / runtime 27 on normal `<development-host>`.
  Persistent navigation, lease-aware read scheduling, independent optional
  Overview history, Recovery-specific reads and stale-response fixes are
  implemented. Startup p95 and application-list median improved; sampled
  Center/WebKit RSS and broker idle CPU fell. Actual 220 navigation visits,
  visuals, Rust/frontend/Context tests and root desktop verification were run.
  Network deadline failures and provider long-tail latency remain unresolved;
  this is scoped development evidence, not complete performance/release acceptance.

- Integrated window chrome (private development evidence)
  historically records Center 80 / Context 72 / runtime 27 on normal `<development-host>`.
  The application owns a continuous, unbranded titlebar with canonical Labwc
  artwork and bounded native window actions. Build, focused tests and protected
  desktop verification pass. Actual normal/maximized/restored captures and
  minimum-size validation pass; physical drag/resize gestures and minimize
  remain pending. This is not release evidence.

- Security Center uses the approved silver/graphite shield-G emblem across
  launcher/running-app taskbar, the Security Center plugin and system
  notifications. [Branding](../branding/BRANDING.md#security-center-application-identity)
  owns the single SVG source and derived launcher PNG. Source/package definitions
  are updated; the normal development VM received a reversible icon-only overlay
  on 8 October, with installed SVG equality and desktop-entry validation passing.
  DMS reload reached READY. Center 80 now includes the Center branding inputs; Context remains 72.
  The separate Context 73 candidate and three-surface live branding review
  are not yet validated. This is not image or release evidence.

- The file review lifecycle receipt (private development evidence)
  historically records Center 76 / Context 72 / runtime 27 on normal `<development-host>`.
  Quarantined/deleted detections and absent-source history leave active review;
  failed actions, restored files and uncertain source status stay reviewable.
  Actual EICAR scan/quarantine clears the active list and retains history controls.
  Running-build integrity and protected-desktop verification pass; 121 frontend
  and 25 focused Python tests pass. This is scoped development validation.

- The Security Activity context receipt (private development evidence)
  historically records Center 75 / Context 71 / runtime 27 on normal `<development-host>`:
  shared contextual event rows, historical kernel PID/basename, real action,
  resource label, decision and explanation. Actual direct reads are denied and
  visible end-to-end; old attribution stays UNKNOWN. Default/minimum UI review,
  121 frontend/23 Python/two audit tests, package integrity and both repository
  gates pass. Session protection remains verified; matched rollback inputs are
  retained. This is scoped development evidence, not release acceptance.

- The focused quality/regression receipt (private development evidence)
  historically records Center 73 / Context 69 / runtime 26 on the normal `<development-host>`
  desktop: neutral graphite grain/silver depth, distinct functional glyphs,
  corrected Files fallback and compact activity/list density. All 13 screens
  were visually reviewed at default/minimum sizes, live reversible interactions
  pass, 118 focused tests and both repository gates pass. Real protection stays
  connected and verified; previous Center 72 and the receipt are recoverable.
  This is scoped development UI evidence, not production/image acceptance.

- The visual polish receipt (private development evidence)
  historically records Center 72 / Context 69 / runtime 26 on the actual `<development-host>`
  desktop. All 13 destinations pass EN capture/layout checks at 1440×900 and
  1100×700 and actual French review at the minimum size. Canonical materials,
  semantic state, readable controls and responsive Network Activity are restored.
  Native WebKit now honors the desktop locale. Fresh protection and resource
  readback, denial, revoked-grant denial, Flatpak and SSH checks pass; actual
  lease expiry still withdraws positive protection. Unsupported grant profiles,
  inventory uncertainty and deferred production validation remain explicit.

- The normal-session recheck (private development evidence)
  historically confirms Center 70 / Context 69 / runtime 26 on the real `<development-host>`
  desktop: fresh PROTECTED coverage, registered-resource readback, direct and
  revoked-grant denial, normal Flatpak compatibility and connected resource
  detail/history. Protection stayed stable through 30-second Applications and
  Protected Data observations and 15 seconds of Overview. SSH recovery remains
  available. The visual revision is delivered separately in the current receipt
  above; this older evidence does not describe Center 72.

- Security Center workspace source groups Protection, Monitor, Maintain and
  Preferences, restores dedicated Network Activity, separates Security History
  in the existing event store, and gives Backup & recovery its own route.
  The workspace receipt historically records Center 76 / Context 72 / runtime 27.
  Evidence renewal now precedes the actual lease deadline; unchanged fresh
  projections preserve the page. Root-owned GREYWARD theme/buttons are included
  in the protected Labwc closure and loaded without replacing the seat. See
  the refresh/theme receipt (private development evidence) and
  see the workspace receipt (private development evidence)
  for installed validation and limits. No enforcement authority changes.

- The normal `<development-host>` development account is deliberately enrolled, with actual
  confined greetd/user-manager/SSH execution, root-owned matched Labwc and a
  separate native DMS authentication domain. SELinux is Enforcing and Fedora
  PAM/authselect are unchanged. Fresh authoritative coverage and the real
  installed Center report PROTECTED for the enrolled scope; the actual `.ssh`
  resource is protected. Descriptor registration and tested persistent READ
  grants pass fresh owner authentication. Ordinary/direct access is denied,
  two unchanged reviewed launches succeed, and real GUI revocation removes
  the grant and denies subsequent launch. Inventory completeness remains UNKNOWN.
  Center 66 / Context 68 / runtime 25 have clean package readback; positive
  coverage survives broker restart, and final GUI revocation publishes verified
  completion. The temporary test policy/helpers are removed. See the
  normal-session receipt (private development evidence)
  for live evidence, recovery and current limits. Disk preflight had 7.1 GiB
  free; no data was deleted to make space. Root and ordinary SSH remain available.
  Automatic production lifecycle/installer/upgrade/rescue acceptance is not
  claimed. Earlier 7 October unenrolled receipts are historical.

- Historical 7 October foundation notes: Application Guard / Protected Data source includes a shared product workspace
  for Applications and Protected Data: one coverage summary, search/category
  views, contextual details/access/activity and structured tested-profile reviews
  in EN/FR. Real typed backend responses and existing operation/freshness gates
  drive it; no preview data is shipped. Source adds root-private, generation-bound
  account-origin issuance/readback; installer handoff remains unwired.
  Earlier focused checks pass: 145 runtime/domain Rust tests, fmt/Clippy, 8 Context
  workflow tests and 99 frontend tests; 21 explicit Rust integration tests remain
  ignored. The current source Center passes real private-window route/IPC/history/
  CSP checks with actual unavailable Context responses; this is presentation
  validation, not production enrollment or GUI authorization/commit evidence.
  The earlier functional foundation includes typed GUI
  descriptor/category registration, persistent native READ-grant review,
  apply/cancel/readback and reference-based revocation. Application/resource
  details and Activity use the existing identity, root policy and telemetry.
  Safe Open uses the shared runner; its standalone sandbox is retired. ELF,
  fixed interpreter scripts and bounded Type-2 AppImages support disconnected
  launches; graphical ISOLATED uses private nested Labwc/clipboard rather than
  the host display. Bounded root AVC/syscall denials enter the existing history
  and Review/Dismiss publisher with UNKNOWN process attribution.
  The earlier combined isolated-account workflow passed invocation
  `55ab0132ea12409e80a4d1e6fe6f2566` with five fresh owner authentications,
  historical generic concurrent grants and actual deny/allow/revoke, shared Safe Open, private GUI
  review/cancel and rollback. Those historical source suites passed: 296 Context tests, 94 frontend
  tests (three live-environment tests skipped), workspace Rust tests/Clippy and
  repository gates. Center 61 / Context 67 are now installed on the live desktop;
  DMS v1.6.2-6 is unchanged;
  runtime spec 19 supplies explicit installed managed workflows. The default
  broker remains read-only; the active development workflow broker permits
  isolation with UNKNOWN whole-session coverage. Flatpak document handlers, WRITE/timed grants and production
  enrollment are not represented as supported. Extended performance, hardware,
  release/image and exhaustive compatibility matrices are DEFERRED HARDENING.
  See the [current authority](security-center/APPLICATION_SECURITY_PLAN.md).
  Documentation was audited against source on 7 October; superseded receipts
  are historical (private development evidence). [Production enrollment](security-center/APPLICATION_SECURITY_ENROLLMENT.md)
  has accepted recovery/account/admin decisions and initial source for the
  existing-database enrollment journal, local-account/per-owner bindings and
  an inert offline LUKS-authenticated console. Nine focused maintenance tests
  pass, including real cryptsetup on synthetic data. Separate authentication now
  passes six enforcing-kernel cross-domain checks, two native DMS PAM cycles and
  two fresh protected GUI Polkit owner challenges on a private headless display.
  The first persistent profile permits only pinned nonexporting key inspection;
  changed code/path/arguments/revision refuse, and generic legacy grants cannot
  activate/launch. Two kernel profile reuses, direct denials and read-rule
  withdrawal pass. SSH login/signing, IDE raw access and the restrictive temporary
  fallback remain unavailable. See the scoped receipt (private development evidence).
  Activation remains BLOCKED by production seat/input, admission and lifecycle. No production gates,
  real maintenance boot, account admission or installed rollback have passed.
  Those isolated authentication checks changed no account mapping, package,
  active desktop or ISO. The subsequent Center/Context review upgrade is
  recorded separately above. The
  initial receipt (private development evidence)
  distinguishes source checks from production evidence.
  Earlier focused revalidation passed runtime Rust tests (115 passed, 21
  environment-specific tests ignored), workspace formatting, runtime all-target
  Clippy, 296 Context tests on Fedora, 89 frontend contracts and both repository
  gates. These do not pass the blocked production activation gates.

- The user rejected the October test installer. The [compatibility investigation](architecture/ISO_INSTALLER_COMPATIBILITY.md)
  identified an invalid auxiliary boot DVD introduced by the agent: stock Fedora
  branding, preseeded account/LUKS and disabled Plymouth. September and October
  product artifacts retain the same interactive Kickstart/profile and identical
  customization bytes. A composed-media guard is implemented; the product-only
  replacement `greyward-installer-20261004-interactive-6-6-53-58.iso` passed
  factory checks and was transferred with verified SHA-256. Its isolated product-only
  console shows GREYWARD branding, User Creation and an empty encryption passphrase
  prompt. The user subsequently completed installation and the isolated console
  reached the GREYWARD desktop. Greeter/desktop backgrounds regressed; fixes are
  implemented in source, with replacement-image acceptance still open. The VM's
  network was reconnected at the user's request and its public-IP lookup works.
  ClamAV's initialization projection is corrected in the Context 59 candidate;
  it shows preparation without claiming scanning readiness or suppressing actual
  protection failures. The 227 Context tests, Rust fmt/tests/Clippy and 78 frontend
  contracts pass. Session 7 packages the fresh wallpaper default; the greeter
  helper now selects the image through its actual standalone session state.
  Center 54/Context 59 build and extracted-package validation pass (227 tests;
  all 30 loaded project modules pinned to RPM bytes). Security/session cache
  reuse passes. Deployment and replacement-image acceptance remain open. The installed
  VM's supplied Secure DNS state identifies the private search-domain guard on
  Default Switch. The rejected switch workaround was reversed; the test VM remains
  there. A Hyper-V-specific prototype never shipped. Four retained ISO Context
  RPMs have a byte-identical reconciler and reproduce the same domain failure;
  no working DNS setting was lost by staging. A generic runtime split-scope
  candidate passes 239 Context tests and isolated real resolved checks for public
  encryption, local resolution and restoration on two namespaces. The installed
  user's DNS remains unaccepted. Earlier 54/59 and diagnostics-only 56/61 inputs
  are historical; the new paired candidates are Center 57/Context 62. They built
  and pass 239 extracted/installed-package tests with 31 imports pinned to RPM
  bytes. The actual <development-host> root service passes a bounded private-domain canary and
  restoration, without restarting DMS or changing profiles; no recent AVC was
  found. The paired Security packages are installed only on .149. A fresh ISO
  from DMS 6/session 7/Center 57/Context 62/branding 15 passed factory checks and
  is retained as an intermediate candidate, not an installed-image result.
  Repetition on 58/63 caught resolved retaining the removed public root domain;
  prior restoration checks did not cover that global route. Center 59/Context 64
  explicitly clear and observe it before removing the override. All 242 source
  tests and real isolated resolver restoration pass. The final packages are installed
  on <development-host> with clean integrity, 242 tests pinned to installed RPM modules, two
  complete mode/restoration cycles, unchanged DMS PID and no recent audit-log AVC.
  The fresh `greyward-installer-20261005-portable-dns-6-7-59-64.iso` passed factory
  checks (SHA-256 `736b87cefbe9ef3ed0c4b766538f9ab1d606400643d9aad673451f0f998f7a94`)
  from DMS 6/session 7/Center 59/Context 64/branding 15. The user's installation
  VM remains untouched and fresh-image acceptance is open.

- The user selected the **native DMS lock screen** as canonical on 4 October,
  superseding the migration's earlier swaylock/swayidle choice. Session RPM
  `0.1.0-6` and DMS runtime `v1.6.2-6` are installed on <development-host>: native lock routing,
  600-second idle locking, 900-second blanking, Fedora system-auth delegation and
  DMS's logind sleep inhibitor are active. The obsolete external-lock QML patch
  and idle coordinator are retired. Package integrity, backend readiness and
  source gates passed. An actual native password unlock was observed; the -6
  runtime restored a secure native surface automatically after a locked-session
  shell restart. Repeated authentication and suspend/resume remain acceptance
  gates. SSH remained available and <development-host> was not rebooted.
  See the [current migration contract](architecture/DMS_1_6_MIGRATION_PLAN.md).

- The 4 October [architecture audit](architecture/FINAL_ARCHITECTURE_AUDIT.md)
  and [build/ISO audit](architecture/BUILD_ISO_AUDIT.md) are delivered; their
  [implementation backlog](plans/PRE_RELEASE_IMPROVEMENTS.md) is in progress.
  Read-only <development-host> checks reproduced DMS rejection of a changed Quickshell RPM
  release while cached repositories offer newer Quickshell/Greeter inputs than
  the candidate's exact tuple. The solver now enforces the exact manifest tuple alongside baseline floors;
  actual closure and fresh-image validation remain in progress.
  The audit also records current-source versus installed Security Context drift,
  substantial short-sample collector CPU and repeated dependency acquisition.
  Those are assessment-time findings; the backlog now records partial package
  implementation. No fresh-image gate or production promotion has passed.

- DMS 1.6.2 migration source/package integration is implemented as an unpromoted
  candidate: immutable source/vendor pins, offline unchanged distribution backend,
  generated explicit shell, twelve patches across twenty-one upstream files, system
  plugins, restrictive state backups, explicit selected routing and production lock
  defaults. Offline Fedora package build/backend tests and source migration fixtures
  passed during development. The <development-host> candidate also passed installed integrity,
  API 34/internal sampler and first-party plugins. Earlier simulated external-lock,
  guest acceptance and old-runtime/state rollback checks are historical evidence
  for the superseded lock configuration. Native-lock restart recovery is now
  separately tested; fresh-image gates remain open. The
  dated evidence (private development evidence) records
  scope and the recovered locker-failure black-screen incident. The
  [active tracker](architecture/DMS_1_6_MIGRATION_PLAN.md) records remaining
  authentication/suspend, visual, performance, fresh-image and hardware gates.
  Matched post-cycle cgroup measurements observed lower CPU and about 32% lower
  median combined RSS; protocol startup/restart remain near the acceptance
  threshold and do not establish complete performance acceptance.
  The <development-host> 1.5.3 baseline and private backups remain recovery inputs. No 1.6 release
  acceptance is implied by the earlier ISO records below.

- Security Center shell redesign is implemented in source and running in the
  `<development-host>` development overlay: fixed identity, independent live activity,
  progressive disclosure and one shared notification projection. Real microphone
  and EICAR/quarantine transitions were exercised. Physical camera/storage,
  authenticated persistent USB trust and the rebuilt privileged scan package
  remain acceptance gaps; this is not release-image validation. See the
  dated runtime record (private development evidence)
  for tested cases and remaining build/visual gates.

- The installed-system definition is `environment/production/`.
- The ISO workflow now requires an explicit `<development-host>` runtime baseline and verified
  base-media checksum. It imports portable preferences, checks package version
  floors/Flatpak commits, rejects stale branding assets, validates the embedded
  payload, and bounds first-boot retries. It now bundles dependencies at build
  time for standalone installation, with no first-boot network fallback.
  These are implementation gates; a new
  clean graphical installation is still required for acceptance.
- The current 2026-09-18 candidate
  `output/iso/greyward-installer-20260918-installfast-anaclosure-hyperv-genericgfx.iso`
  passed ISO checksum, boot metadata, production-stage, Rock Ridge payload,
  and offline-closure checks. Its offline Flatpak installer batches the
  selected refs into one transaction while retaining per-commit verification;
  its verified Anaconda RPM closure prevents a duplicate first-boot RPM
  transaction on a fresh install. The candidate is not yet clean-installed or
  runtime-accepted in Hyper-V or on bare metal.
- Standalone dependency validation on `<development-host>` passed for 1,140 RPMs (signatures,
  baseline floors, resolution with networking absent), all five Flatpak apps
  installed into an empty offline installation, and pinned desktop/shell inputs.
  This validates the dependency workflow, not a newly composed or installed ISO.
- The 2026-09-07 offline ISO failed Anaconda dependency selection because it
  omitted the `core` group metadata and `grub2-tools-extra`. The factory now
  preserves the Fedora core group with production exclusions and verifies
  implicit installer requirements against both repositories. The corrected
  `greyward-installer-20260908-offline-fixed.iso` preserves the original baseline
  and passes embedded-payload and offline resolver checks (1,142 RPMs).
  Its test installation subsequently failed in the Plymouth `%post` rebuild:
  dracut selected the running installer's older kernel. The canonical Kickstart
  now rebuilds all installed kernels explicitly; the `offline-bootfix` candidate
  preserves the production payload and baseline. The boot-fix candidate reached its
  installed 7.1.13 kernel, then first-boot provisioning failed on CRLF line
  endings in `provision.sh`. Source staging now normalizes Linux text and checks
  shell syntax; the `offline-stagefix` candidate preserves the baseline and RPMs.
  Applying its six checksum-verified source corrections to that installed stage
  completed first-boot finalization and reached the GREYWARD greeter and desktop
  on 2026-09-09. A fresh installation of the replacement ISO and a subsequent
  reboot with the media removed remain unvalidated.
- `GREYWARD-DEV` is defined as the production definition plus the explicit
  `environment/development/` overlay.
- A reachable 2026-08-30 internal-alpha VM is available for runtime diagnosis,
  but it is development-contaminated (`example-user`, SSH and development services)
  and still carries the disposable `greyward` live account. It is evidence for
  user-session behavior only, not installed-production acceptance.
- Labwc is the canonical compositor; Hyprland remains the supported fallback.
- DMS Settings owns general desktop settings. GREYWARD Security Center owns
  GREYWARD-specific security and privacy surfaces.
- Security Center uses the Tauri frontend and Rust domain/backend workspace.
- Security Context contains the user-bus summaries and the admitted security
  service integrations.
- GREYWARD production now explicitly selects Fedora `DEFAULT:GREYWARD`, where
  the repository-owned `GREYWARD.pmod` is a small hardened layer that keeps
  RSA-2048 compatibility. This is a secure-default baseline, not a FIPS or
  release-readiness claim; compatibility validation remains part of clean-image
  acceptance. The `<development-host>` development VM remains runtime evidence only.
- Recovery V1 provides local recovery-point and Restic backup components; boot
  rollback remains a separate prototype.
- Update Center review and provider resolution remain unprivileged. Applying a
  reviewed system plan now crosses one fixed-path Polkit boundary that creates
  the Recovery V1 point and prepares DNF5, system Flatpak, and firmware work in
  one `auth_self` transaction; passwordless and cached authorization are not
  enabled. On 2026-09-06 the development VM created a valid linked recovery
  point and completed the prepared 894-package DNF5 transaction. DNF5 history
  transaction `70` reports `Ok`, Security Center matched it and reports
  `COMPLETE`, and the next boot is running kernel `7.1.13-200.fc44.x86_64`.
  This is development evidence, not clean-image or release acceptance.
- Production now includes a root-owned two-day system-update timer. It uses a
  read-only DNF5 check, the existing fixed recovery/update helper, native
  offline preparation, and a desktop notification for restart-required state;
  it does not auto-reboot or update firmware/Flatpaks without an explicit
  Update Center workflow. Clean-image runtime validation remains pending.
- Telemetry history now keeps the live OpenSnitch working set separate from a
  bounded per-user SQLite investigation store and longer-lived semantic events;
  root collectors hand off approved events through a bounded runtime spool.
- The image boundary has `environment/image/build.sh` for production staging
  and `environment/image/build-iso.sh` for an internal alpha installer ISO.
  The current source design uses Fedora boot/netinst media and starts Anaconda
  directly: there is no live desktop, temporary account, GDM hand-off, or
  `liveinst` wrapper. Anaconda owns language, storage encryption, account
  creation, and the native post-install reboot. The production stage embeds
  the current Security Center, GREYWARD session, and production applications;
  offline finalization is retryable on the installed system. The
  production stage requires a Security Center source/RPM manifest and validates
  its package-owned file contract before image construction. A fresh direct
  installer ISO and clean install still require runtime validation; no release
  ISO or release claim exists.
- The former Security Center Session 10 report is retained as dated validation
  evidence, not as a project-wide release gate. Its unfinished checks remain
  useful test targets; the Network Activity interaction cluster now has
  real-Tauri WebDriver evidence. See
  [the historical report](security-center/SESSION_10_REPORT.md).
- The project and Security Center remain under active development. This is not
  an ISO, certification, or release-readiness statement.
- The canonical DMS taskbar includes the first-party GREYWARD Network Traffic
  plugin, backed by the shared DMS `DgopService` network sampler and routed to
  Security Center Network Activity on click.
- The adjacent Network Identity pill shows distinct public and local IPs. Its
  HTTPS public lookup is fresh and memory-only, and a persistent switch loaded
  before startup timers lets the user stop every provider request until they
  manually re-enable it. The canonical DMS user service also blocks the pinned
  upstream backend's separate cleartext `ip-api.com` startup seed locally, so
  it neither phones home nor adds the former timeout delay.
- The canonical DMS taskbar now uses `AppsDock` for the merged pinned/running
  application model. DMS owns application identity, grouping, persistence and
  pin ordering; GREYWARD only seeds the initial Software pin and localizes the
  pin/unpin wording to taskbar terminology.
- Feodo threat blocking is implemented in the Security Context/OpenSnitch path:
  the package contains the fixed official-feed updater, deterministic threat
  precedence, narrow application exceptions, activity metadata, notifications,
  and the Security Center Threat Protection view. Fixture and Fedora service
  checks pass. As of 2026-09-06, `<development-host>` has the development-source iteration
  active with the updater timer running; this is development evidence, not
  packaged-release or clean-image acceptance.

## Planned or incomplete

- GREYWARD is in alpha/beta development. Most major implementation defects are
  closed; intensive bare-metal, recovery, failure-path, and edge-case testing
  still separates the current system from a public release claim.
- The previous live-account hand-off design is retired. The direct installer
  creates the only user through Anaconda, and the first-boot finalizer only
  completes local production provisioning. It masks both system
  and GNOME user Initial Setup units, verifies that a usable human account
  exists, runs production acceptance, and only then releases the greetd/DMS
  display-manager gate. The observed live v7 runtime still failed with a
  Quickshell crash and an Initial Setup `Initializing...` loop; that is
  historical failed evidence and not a validation of the direct design.
- On 2026-08-30, the alpha session's Security Context user-bus service answered
  `GetShellSummary` and reported `REVIEW NEEDED` with two review items. This
  confirms the typed service path is available; the DMS visual rendering and
  end-to-end acceptance remain open and are separate from the ISO lifecycle
  fixes. Corrective ISO v6 content was built and hash-verified on Alpha;
  clean-install, first-boot, and post-reboot runtime validation remain open.
- The internal alpha ISO path is implemented under `environment/image/`; it is
  designed for standalone installation, unsigned, hardware-unvalidated, and not a release ISO
  pipeline. The new source has not yet been proven by a clean VM installation;
  the old live-composed v7 runtime remains failed evidence only.
- A direct installer artifact was built on Alpha from the synchronized source:
  `greyward-direct-installer-20260905.iso`, SHA-256
  `c1aa51a69b7a89e82921391e8133dd619564d2b782bcbad6665be97d4a35a96d`.
  ISO content inspection passed; clean installation and first-boot runtime
  validation remain open.
- Booting or promoting a Btrfs recovery point has not been productized.
- The 2026-09-06 offline DNF5 transaction completed, but runtime observation
  found that the custom Plymouth theme stayed on `Starting GREYWARD` while DNF5
  worked. The source now enters Plymouth update mode and supplies explicit
  install/power/progress feedback. A user-run update reboot is still required to
  validate that presentation; it was intentionally not repeated while applying
  the patch. A graphical Polkit-agent observation is also still required to
  record the exact single-prompt interaction on a clean installed session;
  repository tests enforce one `pkexec` invocation and the non-cached
  `auth_self` policy in the meantime.
- GPU, Wi-Fi, Bluetooth, microphone, camera, removable-media, and other
  physical-device acceptance remain environment-dependent work.

## Status vocabulary

“Implemented” means repository code or configuration exists. “Validated” means
the named test or runtime check actually ran. “Planned” or “deferred” is not a
product capability and must not be described as shipped behavior.

## Next safe work

Normal development enrollment and core grant/denial/revocation are validated.
Automatic production lifecycle and unsupported providers remain separate work. The following broader image work is
a separate backlog, not authorization to alter an active installer VM.

1. Build and clean-install the current internal alpha installer in Hyper-V,
   then validate
   Anaconda account creation, native reboot, greetd/DMS login, portals, Polkit
   and the production acceptance contract. Repeat the minimum boot/provisioning
   gate on bare metal; VMware is not a target gate.
2. Exercise Security Center on clean installations and bare metal, prioritizing
   privilege boundaries, VPN/DNS coexistence, unavailable providers, recovery,
   failure paths, and the remaining checks in the historical Session 10 report.
3. Build a Fedora image input set and retain exact package/COPR/Flatpak/license
   artifacts before making any release-readiness claim.
