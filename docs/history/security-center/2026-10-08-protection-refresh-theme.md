# Protection renewal and compositor theme — 8 October 2026

Status: PASS for this scoped normal `.149` development repair. This is not
production enrollment, image, physical-seat or exhaustive release acceptance.

## Problem and correction

The installed Center 68 refreshed the visible application-security workspace
three seconds after completing its previous read. Coverage, inventory and
grants were awaited together. Read latency sometimes exhausted the five-second
provider lease before the next response. A 30-second normal-window observation
recorded seven temporary UNKNOWN intervals despite healthy enforcement.
`protection.evidence_age_ms` also changed on each response and unnecessarily
replaced the workspace DOM.

Center 70 renews against the earliest real provider deadline, reserving the
measured complete-read cost and a transport margin. Reads never overlap or
extend cached authority. The presentation key retains actual state/revision/
grant changes and evidence-age validity, without treating a valid age change
as a reason to replace the page. Overview compares parsed markup on both sides,
including normalized SVG. Authentication/operation queue exclusions remain.

The protected compositor intentionally replaces the user's XDG data directory
with its root-owned configuration. Its preparation copied `rc.xml` but omitted
the theme, so configured `Greyward` decorations fell back to built-in colors.
Runtime 26 preparation includes the packaged canonical theme and twelve SVG
buttons at `labwc/themes/Greyward/labwc/`. Inputs must be root-owned, not writable
by ordinary users, bounded and free of aliases. They enter the generated
closure manifest. User-writable themes are not introduced into the trusted
display boundary.

## Actual normal-session evidence

The real installed Tauri window and backend ran on the normal enrolled
greetd/Labwc desktop. No mock data, private display or substitute account was
used. Initial provider loading was allowed to finish before renewal measurement.

| Final Center 70 view | Observation | UNKNOWN/expired samples | Unchanged summary node replaced |
|---|---:|---:|---|
| Protected Data | 30 seconds, 120 samples | 0 | No |
| Applications | 30 seconds, 120 samples | 0 | No |
| Overview | 15 seconds, 60 samples | 0 | No |

Each observation retained one protected summary state through multiple actual
provider renewals. Earlier Center 69 startup/Flatpak completion measurements
are intermediate evidence, not the final settled-view result.

A separate live-window check paused only frontend renewal. The actual lease
expired, the UI withdrew PROTECTED and displayed UNKNOWN, and restoring real
reads restored PROTECTED. No backend response or enforcement fact was forged.
This demonstrates that steady presentation does not hide true expiry.

Root-owned assets were added to the actual admitted display closure. A retained,
verified compositor process handle received SIGHUP, without replacing the seat
or changing login mappings. A bounded root trace recorded successful reads of
`themerc` and all twelve SVGs by Labwc PID 3204550. The matched compositor's
reload path reinitializes its theme and reloads each existing window's server
decorations. The trace detached completely. Framebuffer/titlebar screenshot
capture is not claimed; the ordinary screenshot protocol remains restricted.

Session 3925, compositor PID 3204550 and authentication owner PID 3204555 were
preserved. Fresh root seat/kernel verification returns `verified:true`;
coverage is AVAILABLE / PROTECTED at policy revision 6. SELinux remains
Enforcing. DMS and Security Context user services and the workflow broker are
active. Ordinary confined SSH still receives EACCES opening the registered
private key; root and ordinary SSH recovery remain available. Inventory
completeness remains independently UNKNOWN. No grant, PAM, lock or SELinux
permission was broadened. The attempted temporary audit watch was rejected
by immutable audit mode; no audit configuration change was made.

## Installed inputs and recovery

| Package | RPM SHA-256 |
|---|---|
| `greyward-security-center-0.1.0-70.fc44.x86_64` | `e1c0044562de9cd6d0688cc7d5d55c592aa0574d5225dd6ef1a2c4926f636424` |
| `greyward-security-context-0.1.0-69.fc44.noarch` | `26680e0c9f8e8edb0da2ad2148c43b06fbc745e87e1eaf3e0e1cf08370997f72` |
| `greyward-application-security-experimental-0.1.0-26.fc44.x86_64` | `52e6a677c98ee92f48abbed3d31bdc6524a8b8dac9c1c0de360712dd5e893631` |

Center and runtime were built offline from recorded source/spec archives.
Center source archive SHA-256 is
`3ff1bb976699bc39c1f2bd28f910203f6c7bab19b1029f2fcddf3eed3526d562`;
runtime source archive is
`367b0caf4f7b1aeec162ae43969e84c5b9a6ffd96e970697c9b212508a05ef6f`.
The running Center executable and installed binary both hash to
`3dc6cfbc9e276a6eaec679bd2906e6143a31969f99886512677c4c2dd2502fd7`.
`rpm -V` for all three packages is clean. Desktop manifest SHA-256 is
`5073490e79c72dda4c26bab442f5ea38da5615600b54b00b37a7f63946be6946`.
These receipts identify inputs; fresh kernel/seat evidence remains authority.

Root-private backups and new RPMs are retained under
`/var/lib/greyward-development/application-security-live/ux-refresh-20261008/`,
including the prior desktop manifest, seat receipt and active package receipt.
Previous packages remain in the existing `ux-20261008` and enrollment receipts.
The current `active.json` records Center 70 / Context 69 / runtime 26.
No reboot, logout, disk cleanup or compositor/authentication restart occurred.
Disk preflight had 6.9 GiB free; final package installation left about 6.7 GiB.
Security Center is left open on Protected Data for review.

## Focused checks and limits

- 113 frontend tests pass, including slow complete-read renewal, genuine expiry,
  semantic state changes and reviewed-operation background exclusions.
- Three desktop-assembly tests pass: actual XDG theme layout, unsupported/missing
  inputs and rejection of user-owned privileged theme input.
- Both required repository gates pass.

Existing grant/enrollment functional evidence remains in the
[normal-session receipt](2026-10-08-application-security-normal-session.md).
Extended performance, physical-seat, suspend, fresh image/installation and
exhaustive compatibility matrices remain DEFERRED HARDENING. This repair does
not expand supported grant profiles or assert production lifecycle acceptance.
