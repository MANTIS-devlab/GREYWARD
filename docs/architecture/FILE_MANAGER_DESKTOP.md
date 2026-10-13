# File manager and desktop integration

## Current development proof — 14 October

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

Current installed file integration is `greyward-files` 1.0.0-8 with Session 17.
Both verify cleanly. FileManager1 selects the synthetic original in Strata on
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
