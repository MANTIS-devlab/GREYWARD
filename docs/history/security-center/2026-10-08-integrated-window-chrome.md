# Integrated window chrome â€” 2026-10-08

Scoped development evidence for the normal `.149` installed application.
This is not image, production enrollment or release acceptance.
Current design: [Security Center design](../../security-center/DESIGN.md).

## Installed implementation

Center 80 / Context 72 / Application Security runtime 27. Center owns an
unbranded 38 px transparent drag area on the existing continuous canvas.
The old in-content context strip is removed. Three native HTML buttons use
byte-identical active/inactive/hover artwork from the canonical Labwc theme.
A bounded main-window command handles dragging, eight resize edges,
minimize, maximize/restore and close. GTK/Wayland owns the actual operations;
frontend security projections do not authorize window or policy operations.
Accessible EN/FR labels, native focus state and a visible keyboard focus ring
remain independent of route refresh. The fixed application viewport owns
scrolling so background refresh and navigation retain the intended behavior.

## Evidence recorded so far

- Offline Fedora RPM build succeeds; installed root package verification passes.
- 125 frontend tests pass (121 existing plus four focused chrome tests).
- Cargo formatting check passes; the native module compiles in the RPM build.
- Canonical artwork generation validation and both repository gates pass.
- Actual installed WebKit DOM reports a 1440 x 900 viewport and body, three
  accessible buttons, no titlebar branding and no redundant context strip.
- The root protected-desktop verifier reports `verified: true`.
- After authorized native PAM unlock, actual installed normal (1440 x 900),
  maximized (2560 x 1339) and restored screenshots succeed and were inspected.
  Center 80 removes the sidebar clipping seam discovered in Center 79.
- Native maximize/restore returns actual state and updates the accessible label.
  An actual temporary keyboard Space event activates the focused maximize
  control and displays its solid keyboard focus ring (Center 79).
- Native close terminates Center 79; reopening runs the installed Center 80.
- Actual minimum window resize reaches 1100 x 700, with no horizontal overflow,
  visible navigation labels and a scrollable navigation list.
- Root package verification and protected-desktop verification pass after the
  final update. Security Center remains open in its normal desktop session.
- Physical pointer dragging, edge gestures and minimize/restore remain pending;
  focused handler tests and successful compilation do not establish those
  physical interaction checks. No full Rust workspace or release suite is claimed.

## Exact inputs and recovery

- Center RPM SHA-256: `0aa53ed82425c10515535c1c72a7652e6351bb4b19fe525bfc60c606247ac941`.
- Center binary SHA-256: `d2d5e7f2ed44c953de76ba97fbfb5e01e8af9ae6ef8692d7684ec0ff3b4cadd0`.
- Center source SHA-256: `2509b61a2b0f4d6e3f816006c2ca9058b0174c66ccf4c1830e8764f78107b759`.
- Center spec SHA-256: `f494dc3c16a6ea1bfe28b06f872e969a502782a3870410cb3e8f7b5195b06ef3`.

Root-only rollback inputs and active-before receipts are retained beneath
`/var/lib/greyward-development/application-security-live/titlebar-20261008/`.
The installed live receipt selects Center 80 / Context 72 / runtime 27.
Context 73 branding remains a separate unvalidated candidate. No enrollment,
SELinux, PAM, DMS native lock or recovery policy changes accompany this update.


## Follow-up: compositor frame correction

The user exposed a double titlebar on the normal desktop after the earlier
client-surface captures. Labwc's canonical `core.decoration=server` forced a
second frame despite Tauri `decorations=false`. A real foreign-toplevel read
confirmed main-window app ID `greyward-security-center` and title
`GREYWARD Security Center`. Exact app/title rules now set serverDecoration=no;
the canonical identifier is also covered. Brave rules and auxiliary dialogs
remain unchanged.

On `.149`, root-owned protected Labwc configuration, existing local defaults
and installer skeleton were updated with restrictive ownership preserved.
Private backups of configuration/manifest/seat/active receipt are under
`/var/lib/greyward-development/application-security-live/titlebar-rule-20261008`.
Only the reviewed configuration digest and corresponding seat generation were
updated; the retained compositor process was reconfigured with SIGHUP through
a verified pidfd. Center 84 was reopened; no binary, policy, PAM, DMS, account
mapping or whole-session restart changed.

Full VMConnect console inspection shows one titlebar in normal and maximized
states; the application maximize control and restore work. Fresh root desktop
verification remains `verified: true`; SSH remains available. Desktop manifest
SHA-256 is now
`0ed95db37ce9d1148952b767f1c401afe57686620a316a510151fca214e319ae`.
This supersedes the earlier client-only claim about compositor decoration.
Physical drag/resize/minimize testing remains outside this correction.
