# File manager and desktop integration

## Current development proof — 14 October

### Native file icons and preview correction — candidate 16

Revision 16 is built and installed in development. It retains revision 15's
derived executable and strengthens the shared semantic icon artwork. Revision 15 compiles the pinned Strata source
with an offline Cargo vendor archive and two bounded patches. The upstream
binary remains the attested baseline; that attestation does not apply to the
derived executable. Source, Cargo.lock, vendor and patch digests are checked.

The native-icons patch uses a separate GIO/GTK theme instance for file MIME
artwork and launcher logos. Per-file customizations remain preferred. Direct
artwork is limited to root-owned, non-writable system assets; arbitrary personal
images retain isolated preview handling. Inputs are bounded, external SVG
references remain disabled, and PNGs are resized before entering the existing
bounded texture cache. Launcher metadata never executes a command or establishes
trust. Private user-only named icons and unsupported formats may use the shared
fallback; ODT content thumbnails remain unsupported.

The preview patch selects Strata's existing per-operation bubblewrap renderer.
Actual normal-window testing confirms the old PDF preview works, while SVG and
browser thumbnails encounter denied nested `/proc` mounts in reusable workers.
No generic mount allowance, unsandboxed decoder, new service or portal is added.
The normal offline RPM build passes all phases, including three Rust metadata
tests through the dedicated integration target. Twelve focused Python tests
pass on Fedora. The dependency dry run and installation replace only Files 14;
there are no scriptlets. RPM verification is clean, SELinux stays Enforcing,
SSH remains active and the matched Files 14 rollback is retained. The installed
release ELF SHA-256 is
`0206955547f80f6cc5955a28a50fb6ed3c4304670a6f1f5491eec5cbcaedc136`.

The user reconnects to the normal desktop. Real VMConnect review confirms SVG
thumbnail rendering and the shared native/Strata folder and document silhouettes.
After the user rejects washed-out accents, revision 16 colors the glyph itself,
strengthens its border and adds a tinted inset. A reopened normal Strata grid
shows blue DOCX/ODT, green XLSX/CSV, red PDF and amber archive/code marks; desktop
text-file icons show the same blue treatment. No whole-session restart occurs.
The Desktop folder in Strata also resolves the real Brave, Black Box, home and
Files launcher icons consistently with the native desktop instead of generic
document icons.
Content thumbnails retain their original appearance; ODT thumbnails in Strata
and private user-only named icons remain unsupported as stated above.

Revision 16 uses generation-checked incremental compilation with the same
source/patch/lock inputs and release ELF, not a new cold Rust build. Its normal
RPM build/check phases and three Rust checks pass after the verified prep step.
An initial 1 GiB native-build cgroup runs out of memory; its partial native
objects are discarded before the successful 2 GiB/no-swap retry (1.5 GiB peak).
The normal desktop stays active throughout this revision-16 build/install.
RPM verification is clean, SSH remains active, and SELinux remains Enforcing.
The matched revision-15 rollback is retained. Revision-16 RPM SHA-256:
`c07cc50fc2fa1a07feac84de0330ce653b245f3c573b40b07bc40434b5ac7f6c`.

A direct diagnostic launch is refused at its SELinux context transition, before
running the helper. That is not a passed or failed preview operation and prompts
no policy relaxation. Revision-15/16 automated installed helper/security checks,
PDF/video normal-window checks and full migration acceptance remain NON VÉRIFIÉ;
earlier revision-14 helper evidence below is historical. No compiler or build
safety service remains running.

### Build resource incident — historical construction failures

The ordinary session closes at 08:55:59 with guardian reason `heartbeat-age`.
At 08:57:30 the kernel reports global OOM and kills the Rust compiler. The build
unit reaches approximately 4.6 GiB memory and 7.3 GiB swap peak. This
establishes dangerous build pressure concurrent with the heartbeat failure;
it does not establish the earlier clipboard/native-lock defect as its cause.
No logout or reboot is requested and no Files 15 package is installed at that time. SSH
remains available and SELinux Enforcing. The admitted session is nevertheless
lost; it must not be reported as preserved or visually validated afterward.

The RPM environment adds full `-Cdebuginfo=2`, unlike the initial successful
source build. The candidate now appends `-C debuginfo=0` while retaining the
other Fedora compiler flags; no debug subpackage is produced. Full LTO also
reaches the bounded builder's memory limit, so the release profile uses standard
ThinLTO instead. The replacement build has a 6 GiB hard memory cap, zero permitted
swap, and stops if an ordinary graphical login appears. Do not repeat uncontrolled
memory pressure or relax guardian checks to keep a desktop alive. Remaining
source/package tests and a fresh user login are required before visual acceptance.
The isolated SDK also exposed PCManFM's exported link dependency on
`libexif-devel`; it is now an explicit build requirement. SDK correction does
not install or upgrade libraries on the running desktop system.

The whole-application test harness separately reaches the build cgroup limit,
even when only three tests are selected. The final patch separates the bounded
metadata functions into a leaf module. A standard Cargo integration target
imports that production module directly and runs its three checks without
compiling unrelated internal tests. Packaging checks that the release ELF is
preserved. A fresh normal RPM build passes after this correction; installed
desktop acceptance remains pending as recorded above.

### Resumed normal-desktop icon review

After the user unlocks the real development desktop, Strata is closed and
reopened through its desktop shortcut. The new window loads the packaged icon
overlay; its live application-bus owner is in the ordinary Guard domain. Folder
and plain-text artwork match the native desktop in the observed grid view,
and the Strata launcher/window identity uses the GREYWARD Files folder. The
admitted graphical session stays running and SELinux remains Enforcing.

This is partial visual acceptance. Two differences remain visible: Strata
represents `.desktop` launchers as generic documents whereas the native desktop
shows their application logos; the native desktop displays an ODT content
thumbnail that Strata does not support. Source inspection confirms that the
pinned Strata file-icon resolver does not resolve launcher GIcons, and its
thumbnail dispatcher does not accept ODT. Icon-resource overlays cannot add
either behavior. Do not disable useful native thumbnails or claim that matching
asset digests prove identical rendering for these cases. Native integration
would require a separately validated upstream source change and derived-build
provenance, rather than silently modifying the attested executable.

The user subsequently restores the truncated VMConnect console. The real grid
confirms the common folder, archive, spreadsheet, text and source family, and
normal-window PDF preview works. SVG preview is unavailable with enforcing
nested-mount denials, motivating candidate 15 above. Final whole-interface
acceptance remains NON VÉRIFIÉ. The later build-resource incident is separate
from the earlier console limitation; no auth/runtime activation or reboot occurs.

### Preview dependency closure

Files 14 is installed. It adds explicit RPM file dependencies for the external
programs used by the pinned sandbox helper: `magick`, `ffmpeg`, `ffprobe`,
`prlimit`, `nice`, `fc-list` and `unsquashfs`. These were already installed on
the development system but were absent from the package requirements; ELF
dependency generation only covered libraries. PDF rendering uses linked
Poppler, so no redundant `poppler-utils` requirement is added. Optional RAW
tools and the faster video-thumbnail frontend retain their upstream fallbacks.

The offline build, seven packaged requirements, single-package dependency dry
run and installed RPM verification pass. The Strata ELF and all icon assets
remain unchanged from Files 13; its matched RPM rollback is retained. No new
services, policy permissions, codecs or graphical-session restart are involved.
This fixes package metadata; full offline ISO closure and fresh installation
remain NON VÉRIFIÉ and are not inferred from the development host's packages.

The real installed helper runs under `greyward_guard_t` with the pinned bwrap
template: all namespaces unshared, read-only input, private temporary/output
storage, clean environment and bounded resources. Synthetic SVG rendering,
PDF/video thumbnails and FFprobe metadata succeed in approximately 83/59/148/161
milliseconds respectively. A registered synthetic secret remains denied with
`Permission denied` and no preview output. These are helper-level mechanism
checks, not successful GUI preview or overall performance acceptance. See the
resumed review above for actual normal-window evidence and remaining limitations.

### Icon consistency correction after user review

The user rejects Files 11's remaining mixed appearance. Its resource-count and
folder/text comparisons establish only partial coverage, not whole-interface
visual acceptance. Strata's independent extension catalog still wrapped old
Catppuccin marks, while native MIME icons used different symbols. The overlay
also omitted the embedded application icon, allowing the original Strata icon
to remain alongside the installed GREYWARD Files identity.

Revision 13 maps extension resources to complete native MIME artwork and covers
the embedded application-icon path. Common code, text, configuration, shell and
database icons share their actual SVG assets, not only an outer frame. Native
MIME aliases cover common source languages, office files, fonts and archives.
Revision 12 is an undeployed intermediate build. Interface actions remain distinct
Platinum glyphs; third-party logos and actual thumbnails retain their meaning.
The upstream executable and all non-icon resources remain unchanged. Automated
asset checks do not substitute for normal-session visual acceptance.

Files 13 was installed for the icon correction; Files 14 retains its artwork.
Six focused tests and the
repository checks pass. All 821 installed icon assets match their generated
digests; all 455 embedded icon paths are covered, including the application
identity. Every extension resource matches its selected native MIME SVG exactly.
The attested Strata ELF is unchanged and RPM verification is clean. Only the
desktop-icon user unit is refreshed; SSH, SELinux Enforcing and the admitted
graphical session remain intact. Strata is subsequently reopened after user
unlock; the resumed review above records partial visual acceptance and the
remaining differences. No claim of complete visual acceptance is made. Matched
Files 11 rollback is preserved.

Installed-profile inspection also finds an earlier migration defect: removing
an `IconThemeName` substring truncated `FallbackIconThemeName`, so PCManFM
persisted its Oxygen default. The exact fallback field is restored to Greyward
with every other preference retained, and the development migration now removes
only whole matching lines. The packaged default was already correct. This
explains another source of mixed fallback icons; visual acceptance stays pending.

The dated Files 8/11 notes below
record the earlier routing/startup proof. Native locking and broader stability
remain a blocking migration gate after the later automatic-lock closure.

### Native-lock correction candidate — not activated

The ordinary DMS profile still uses its local lock despite the compositor
reserving that protocol for protected authentication. The 00:15 journal shows
the ordinary shell's unsupported-lock error and a protected clipboard-pipe
descriptor denial, followed by guardian teardown. This establishes an actual
integration defect and a remaining clipboard path; it does not prove the final
exit cause without an instrumented normal-session retry.

The candidate uses existing native configuration rather than another locker:
enrolled ordinary DMS routes `customPowerActionLock` to the fixed
`/usr/bin/greyward-guard lock` request. Its kernel SELinux subject selects the
route; unconfined sessions retain normal local DMS locking. The session-lock
helper waits for the existing broker's root-verified `lock-status`. Surface
startup may report `SHELL_READY`, but the ordinary full check refuses to claim
protected native-lock security from its local surface or the routing setting.

The root-prepared authentication worker also supplies Qt's native
`QT_WAYLAND_DISABLED_INTERFACES` for clipboard/primary-selection/data-control
only. This complements the backend's disabled collector; it preserves `wl_seat`
and the native session-lock protocol. Installed Qt 6.11.2 registry-only probes
confirm normal clipboard bindings versus no clipboard bindings with this option,
while both retain the seat. No window or clipboard content is used in that test;
it is not a successful native-lock test. SELinux descriptor denials remain intact.

Runtime 51, Enrollment 32 and Session 18 build offline. Twelve desktop, twenty-three
DMS migration and seven readiness tests pass on Fedora. Existing-package checks,
private matched rollback copies and the three-package dependency dry run pass.
These packages have not been installed or activated. The active graphical session
and SSH remain running. Explicit user approval is required before ending that
session; real native lock/PAM unlock, clipboard and stability acceptance follow
activation. No reboot, PAM/greetd change or policy allowance is part of this fix.

During preparation, the unmodified Runtime 50 session subsequently auto-locks
without losing its protected authentication PID or admitted session. The real
VM console displays the native lock, and the existing broker's `lock-status`
returns `true` after root verification. This is an observed secure acquisition,
not a PAM-unlock pass or proof that the intermittent clipboard-dependent exit
is resolved. The pending candidate remains unactivated.

Runtime 50/Enrollment 31 disable only the private authentication backend's
clipboard collector through DMS's native configuration. The same desktop-to-Strata
paste that closed two earlier sessions now succeeds in the normal desktop, with
identical original/destination SHA-256 and the same live protected authentication
PID. No guardian closure follows. Automated drag/drop transfers nothing through
VMConnect, but the user then confirms a successful manual transfer; the real
destination, identical digest and unchanged session are verified independently.
SELinux is Enforcing; the ordinary-domain open/close regression
allows the synthetic normal file and denies the registered mock secret without
reading content. Broad stability, native-lock and Administration acceptance are
not implied by these checks. The dated investigation below explains the change.

### 13 October investigation and activation history

Further live validation: the native DMS menu replaced the old Files taskbar pin
with Strata; Brave and Terminal retained their positions. The persisted taskbar
list survives the subsequent user reconnect. The real Strata shortcut opens
normally with its new folder icon. Copying the synthetic text from Strata to
PCManFM's desktop succeeds and both files have the same SHA-256.

A later spontaneous closure during drag/drop blocked the migration's
stability acceptance. The user confirms it was not a deliberate logout. The
journal shows the guardian retiring the admitted scope while Labwc was still
alive, not an established compositor crash. An explicitly approved repeat with
read-only readiness/process-lifetime observation did not immediately reproduce
the closure; it also did not complete the file drop, so drag/drop is not passed.
The new session's initial three-minute observation records 34,383 readiness
checks without rejection. Short successful observations do not prove this
issue is fixed; a subsequent ten-minute observation records 114,233 further
checks without rejection or worker exit. Source records a bounded guardian exit
reason in the system journal, without credential/readiness contents and without
changing teardown, authentication or freshness requirements. Eleven focused
Fedora tests pass. The explicitly approved logout activates Application Security
49 and Enrollment 30, with matching protected desktop/Administration receipts,
clean RPM verification, SELinux Enforcing and SSH available. The user's subsequent
normal login succeeds. A desktop-to-Strata paste reproduces the closure before
creating the destination copy: the guardian records `readiness-io`, and concurrent
read-only observation confirms the readiness PID disappears before seat teardown.
This establishes loss of the authentication UI, not its underlying exit cause.
At that stage the issue remained blocking; a successful login was not stability acceptance.

The subsequently approved single paste captures a fatal EOF on the private DMS
backend's Wayland connection, followed by `authentication-owner-exited`. The
private backend unnecessarily binds data-control and collects ordinary clipboard
offers. Runtime 50/Enrollment 31 now seed its native `clsettings.json` with
`disabled=true` before startup, root-owned/read-only under the existing protected
runtime label. Ordinary desktop configuration is untouched. Three Fedora tests
cover the generated setting, retained lock/PAM defaults, hardlinks and dangling
aliases; offline builds and package/receipt checks pass. The real post-correction
paste passes as recorded above. No descriptor-policy allowance or guardian grace
period was added. Remaining interaction/security gates are still explicit.

At the earlier routing/startup validation, file integration was Files 8 with
Session 17. Both verified cleanly. FileManager1 selected the synthetic original in Strata on
the actual desktop; D-Bus owner/PID readback resolves the packaged Strata ELF in
`greyward_guard_t`. PCManFM retains its private desktop interface and no longer
claims FileManager1 in desktop mode. The icon service is active over the unchanged
wallpaper, and the same graphical session and DMS process remain running.

Restart validation exposed a startup-probe mistake: the full DMS check rejects
the ordinary shell's `shouldLock=true/sessionLockSecure=false` while the separate
protected authentication process reports no lock request and logind's LockedHint
is false. Icons need shell/surface readiness, not this ordinary lock assertion.
Session 17 adds `--desktop-only` to the existing probe, returning `SHELL_READY`
without a security claim. The default full lock check is unchanged and still
rejects that ordinary state. Five focused tests pass, including that distinction.
No native-lock failure is declared fixed by changing icon ordering. The same
protected authentication and guardian remain active, with no policy changes.

The initial installed baseline was DMS 1.6.2-15, Application Security 45,
Enrollment 22, Center 100 and Context 92. Earlier notes listing Enrollment 26,
Center 90 and Context 81 describe the tuple before the separately installed ISO
component update, not the baseline used for this migration.

Revision 6 of `greyward-files` was installed and verified cleanly. A real fresh
login revealed a second startup problem: DMS's simple service was active before
its QML wallpaper mapped, covering the earlier native background-layer icons.
The desktop unit uses the existing bounded DMS shell readiness check before
mapping PCManFM. Restarting only that ordinary desktop unit restores visible
icons over the unchanged wallpaper. Automatic icon startup also passes in the
approved real logout/login: one bounded readiness retry, then visible icons
without manual startup or wallpaper changes.

A spontaneous desktop closure interrupted the clipboard test. Read-only sampling
of the real protected readiness record reproduced an open descriptor with zero
links during Quickshell's atomic replacement, although its heartbeat was fresh,
Polkit registered and its process remained in the protected authentication
domain. The existing guardian rejects that snapshot and terminates its admitted
session. The correction reopens only a demonstrably replaced mutable record,
with three bounded attempts; immutable input checks, heartbeat age, ownership,
Polkit registration and the protected process context remain mandatory. It never
reuses cached readiness. Nine focused Fedora tests pass, including replacement,
hardlink/symlink refusal and fail-closed invalid readiness.

Matched DMS 17, Application Security 47 and Enrollment 28 candidates build
offline without privilege. The only changed Application Security runtime assets
are the exact DMS-release admission and the readiness reader. The original
installed RPM payloads and protected desktop/Administration trees are preserved
for rollback. The offline transaction solver selects only these three upgrades.
Following explicit approval, they are installed and the quiescent protected
runtime migration succeeded. Its session-reader digest and Administration
cross-reference match; the user logged in successfully. DMS and PCManFM run in
`greyward_guard_t`, SELinux remains Enforcing and SSH remains active. The real
taskbar creates exact installed-entry shortcuts for Brave Flatpak, native Black
Box and Strata. Full authentication failure, security and image acceptance remain
NON VÉRIFIÉ; package integrity and successful login do not substitute for them.

At the user's explicit request, these three unchanged installed-entry copies
were verified again and approved using PCManFM/libfm's native string attribute
`metadata::trust`. Their warning badges disappear on the actual desktop. Unknown
or edited launchers are not approved, and the helper still preserves first-use
review for future copies. This is desktop launcher trust, not a Protected Data
grant or administrative authorization. No global badge suppression is used.

The file-manager icon uses the canonical `branding/source/greyward-files.svg`,
an Obsidian/Platinum folder. The attested upstream ELF is unchanged. The installed
launcher selects the packaged SVG directly because the active Qt icon-name cache
retained a missing-icon entry. The real desktop renders the folder without a
badge. Other application icons, Qt/GTK themes and DMS wallpaper remain unchanged.

Strata 1.0.0 is the selected upstream candidate, source commit
`6662d8d4bd4cb3cdec3f10f918f3b4c92b18cdcc`. Its x86_64 GNU archive has SHA-256
`e15095a201165132a88032df15ecbeab795a13d6cacc4ebb943e276c35ff492e`.
The archive checksum and GitHub Actions attestation were verified before the
development installation. Installed libraries satisfy its dynamic dependencies.
Do not enable its optional portal replacement or encrypted-volume integration:
GREYWARD retains the existing portal, Polkit and storage owners.

PCManFM-Qt 2.4.1 is installed from Fedora's signed packages. Its separate
`greyward` profile uses the native transparent SVG wallpaper and
`OpenWithDefaultFileManager=true`. DMS starts first and remains the wallpaper
owner. The real desktop shows icons over the unchanged DMS background; the
existing taskbar remains visible. No compositor, PAM, greetd or policy was changed.

Both applications run as the ordinary desktop user in
`greyward_guard_u:greyward_guard_r:greyward_guard_t:s0`. Initial temporary
systemd units were supporting setup, not production startup infrastructure.
Packaged desktop icons now run in the normal user manager, and the real desktop
opens Strata through its installed launcher. The folder MIME preference is backed up before selecting
Strata. Nautilus remains installed for rollback. No file manager runs as root.

The real `FileManager1.ShowItems` probe exposed another integration failure:
PCManFM's desktop instance claimed the shared file-manager name before Strata,
and opened its own manager window. Its pinned 2.4.1 constructor registers this
name before loading settings and has no native opt-out. Revision 7 therefore
builds the exact source archive recovered from Fedora's SRPM with a three-line
desktop-mode registration guard. Only the desktop wrapper selects this binary;
the original Fedora program and native desktop-control interface remain intact.
This is a narrow routing correction, not a portal replacement or new D-Bus
broker. Installed FileManager1 routing and icon startup pass with revision 8.

## Shortcut boundary

`environment/session/greyward-desktop-shortcut` resolves an application ID only
against installed root-controlled native and system Flatpak desktop entries.
It copies the bounded original descriptor content without constructing a shell
command or deriving execution from a window title. It refuses root invocation,
unknown IDs, invalid entries and user-writable launcher locations. Unverifiable
personal/user-installed launchers remain unavailable rather than becoming trusted.

The XDG desktop directory is user-specific. Descriptor-relative exclusive
creation avoids overwriting existing files or following conflicting symlinks.
An unchanged shortcut is reused; different existing content gets a numbered
name. Native PCManFM executable-trust review is preserved. Creating a shortcut
does not grant Protected Data access or administrative authority.

The DMS menu candidate and `packaging/greyward-files/` now build offline as an
unprivileged account, using verified archives and retained upstream license
notices. The files package includes the ordinary-user wrappers, scoped style,
first-use defaults, helper, FileManager1 service and a Labwc-only user unit.
Revision 6 is installed on the development system: RPM verification is clean,
its packaged shortcut check succeeds under `greyward_guard_t`, and native ELF
and Qt style labels are supplied by the normal Fedora filesystem policy.
Revision 2 adds an explicit GREYWARD-session condition to the desktop user unit.
The user's later reconnect exposed an ordering cycle between the wanted desktop
unit, DMS and the graphical-session target. Revision 3 disables the desktop unit's
implicit target ordering, then explicitly orders it after the graphical target
and DMS. This preserves authentication and ordinary startup responsibilities.
Broader application workflows and offline ISO closure remain implementation and
validation work. Do not advertise this development installation as
an integrated release feature or remove Nautilus from the production baseline.

## Acceptance evidence

### 14 October icon-family correction

The canonical catalog is `branding/source/greyward-icon-family.json` and its
generator is `tools/generate-file-icons.py`. One Obsidian/Platinum object family
is packaged as the native Greyward icon theme and an icon-only Strata GLib
resource overlay. Folder and plain-text resources share identical source SVGs;
extension-specific marks use the same document frame and subdued palette.
Action glyphs retain distinct Lucide geometry and a common Platinum stroke.
The package retains upstream attribution and the original attested Strata ELF.
Real document/image thumbnails and third-party application brands are retained.

The first installed selection was incorrect: PCManFM 2.4.1 ignores
`IconThemeName`. Revision 10 selects QIcon's theme through the already scoped
desktop style and uses the supported fallback setting. Native GIO then exposed
the missing primary `inode-directory` alias; revision 11 adds it instead of
relying on another theme's fallback. These are integration defects, not evidence
that merely installing a theme completes visual unification. Existing layouts
and wallpaper are preserved; only the icon user unit is restarted.

Revision 11 is installed with clean RPM verification. Actual desktop and Strata
column/grid comparison passes for the synthetic folders and text files. The
installed receipt validates all 760 theme/overlay assets, and all 454 embedded
upstream action/extension SVGs are covered with no missing resource. Folder and
plain-text vectors are byte-identical across the two consumers. The unchanged
ELF digest is `aa9c9da083bfb4d8d3a72d573a93d02045228bbecb24f6bd2aed33367f999a09`.
Five focused source tests and the static/repository gates pass. Unmapped system
icons inherit Breeze/Adwaita; this does not claim to rebrand every third-party
application or to replace actual file thumbnails. Clean-image adoption remains
pending the broader migration gates.

The earlier clipboard and manual drag/drop checks remain scoped passes. A
later 14 October 00:15 automatic-lock attempt coincides with a real guardian
closure (`authentication-owner-exited`). Logind removes that graphical session;
this was not just a surviving session behind a lock screen. The ordinary shell
also reports inability to start the protected session-lock protocol. Causality
and correct native lock/unlock remain unresolved: do not present overall session
stability or locking as validated from the clipboard correction. The event
precedes icon installation. No guardian or authentication permission was relaxed.

| Check | Current evidence |
|---|---|
| Strata archive provenance | PASS: SHA-256 and GitHub Actions attestation |
| Ordinary confined Strata launch | PASS: transient unit identity and real window |
| Transparent desktop | PASS: real PCManFM icons, unchanged DMS wallpaper and taskbar |
| Synthetic folder open | PASS: confined Strata command opens the original test folder |
| Desktop double-click into Strata | PASS: VMConnect double-click opens the synthetic folder and its original Read-me.txt |
| FileManager1 routing | PASS: ordinary D-Bus ShowItems opens/selects the synthetic original in packaged confined Strata; desktop PCManFM does not capture the request |
| Shortcut verification | PASS: confined helper resolves installed Strata desktop entry |
| Desktop menus and premium application theme | PASS: native Strata custom Obsidian tokens; scoped Qt Fusion proxy style renders dark icon-free desktop menus on the real desktop |
| Synthetic folder creation and rename | PASS: real Strata New Folder action and inline rename; original document preserved |
| Synthetic text preview | PASS: original test text visibly rendered in Strata; binary/document sandbox coverage remains NON VÉRIFIÉ |
| DMS shortcut package | PASS: exact assembly, offline RPM/Go checks, matched installation and successful real login for 1.6.2-17 |
| Taskbar shortcut creation, native and Flatpak | PASS: real menu creation and original launcher hashes for Brave Flatpak, Black Box and Strata; Strata shortcut launch passes; other shortcut launches and another Flatpak case remain NON VÉRIFIÉ |
| Clipboard in both directions | PASS: real Ctrl+C/Ctrl+V, native desktop/Strata display and identical synthetic-file SHA-256; reverse paste passes after runtime 50's private clipboard correction |
| Drag/drop | PASS for the user's manual synthetic transfer, real destination SHA-256 and unchanged protected session; the VMConnect automated gesture remains inconclusive |
| Trash, binary previews, USB, SMB/SFTP | NON VÉRIFIÉ |
| Protected Data and Administration regressions | PASS only for an ordinary-domain open/close of the synthetic normal file and denial of the existing registered mock key, without content reads; Strata/Safe Open and Administration interaction regressions remain NON VÉRIFIÉ |
| Restart and reconnect | PASS only for approved matched migration, real login and automatic transparent icons; intermittent spontaneous closure remains unresolved, broader crash recovery NON VÉRIFIÉ |
| Resolution changes and multiple monitors | NON VÉRIFIÉ |
| Offline package/ISO closure and fresh installation | NON VÉRIFIÉ |

The packaged desktop user unit starts through the normal confined user manager
on the installed desktop, with both session conditions satisfied. The native
systemd graph verifier accepts the corrected unit. Global enablement and automatic
startup pass in the approved real GREYWARD login. The initial prototype did not
restart protected components; the later matched activation used the explicitly
approved logout/login. PAM and SELinux policy were not changed.
The standalone prototype binary, launcher, icon and helper were verified against
their originals and archived before switching to the RPM-owned counterparts.

Prototype observation: PCManFM used about 86 MiB after startup; Strata memory
increased while browsing. These are point observations, not performance acceptance.

The scoped menu style uses Qt's supported `QStylePlugin`/`QProxyStyle` interface,
with Fusion as the base. It preserves keyboard navigation, checkboxes and submenu
arrows, and removes only menu icons. The desktop launcher explicitly selects the
plugin: no global Qt/GTK setting or PCManFM fork is used. Its small native module
builds with warnings treated as errors. Strata uses its native custom-theme format
and keeps its upstream interface font. Menu translucency is subtle; blur is not
claimed. Native Desktop Preferences remain visible while removal of irrelevant
desktop controls is still being assessed.

VMConnect's Unicode text injection did not populate the guest rename field;
physical-key input and Enter did. This is a validation-tool limitation, not a
claim that normal user typing fails. Clipboard copy displays Strata's native
confirmation; transfer to PCManFM and drag/drop outcomes are not yet established.

## Rollback

Disable and stop only `greyward-desktop-icons.service`; close Strata normally and
remove the candidate `greyward-files` package after inspecting the DNF transaction
for unrelated removals. Restore the saved folder MIME preference. Preserve the
archived prototype files, original documents, desktop layouts,
older archived experiments and Nautilus. No session logout or policy rollback is
necessary for this prototype. A later packaged migration must preserve established
preferences and keep the normal/protected session package tuple matched.
