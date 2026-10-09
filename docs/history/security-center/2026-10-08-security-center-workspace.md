# Security Center workspace — 8 October 2026

Status: PASS for scoped development delivery. This receipt records normal `.149`
development integration, not clean-image or production enrollment acceptance.

## Result and authority

[UX_SPEC.md](../../security-center/UX_SPEC.md) is the current presentation
authority. The grouped labelled navigation separates protection, monitoring,
maintenance and preferences. Files are directly discoverable; recovery has its
own destination. System checks/Devices and Network protection/threat blocking
retain contextual ownership. Overview has a compact fresh session summary.
Applications exposes actual Flatpak permissions alongside the registered native
inventory without equating provider permissions to enforced protection.

Network Activity retains route `activity`, its own live/history state, pause,
filters, narrow delta updates, details and bounded history. No application or
other security history is prepended. Security History uses route `history` and
the same telemetry database: SECURITY excludes NETWORK before pagination.
Category changes reset cursors and queries are keyed by their filters. Sensitive
denials require the existing root-kernel evidence contract; event history cannot
establish protection. Internal identity references stay in technical disclosure.

`workspace.css` owns the shell/navigation styles; conflicting earlier shell
rules were removed from `styles.css`. Existing feature components, typed
operations, confirmations, route freshness and lease expiry remain in place.
All new copy has EN/FR parity. No enforcement/authentication policy changed.

## Live validation

The actual installed Tauri window ran in the normal enrolled greetd/Labwc
desktop via the development WebDriver. No mocks, private display, separate
account or replacement event store was used.

- Center 68 / Context 69: all 13 routes render one page heading, one
  selected navigation owner and no horizontal overflow at 1440×900.
- Normal live coverage returns AVAILABLE / PROTECTED at policy revision 6.
  Protected Data shows the actual registered directory and Protected state.
  Overview settles to Protected after fresh readback; initial loading does not
  invent positive coverage. Direct key inspection in the ordinary confined SSH
  shell is denied. Root recovery, DMS and Context remain available.
- Network Activity: exclusive network workspace, pause/resume, Live/History,
  deliberately unmatched search, Clear filters and return to Live pass.
- Security History: real kernel denials and reviewed changes render. Category
  filtering/reset passes. The live dataset has no next-page cursor, so actual
  older-page navigation was not exercised; deterministic store pagination and
  renderer cursor-reset tests pass.
- Minimum real window 1100×700: labels visible, sidebar scrollable, no horizontal
  overflow. Original 1440×900 dimensions restored. Actual screenshots inspected.
- Real Flatpak collector returns six installed applications with effective
  permissions; existing settings are preserved. Recovery exposes existing Btrfs
  points and honestly reports the unavailable personal-backup destination.
- The normal-session registration, tested grant reuse and GUI revocation proof
  remains in the [enforcement receipt](2026-10-08-application-security-normal-session.md).
  This presentation change does not claim a new grant profile or re-run those
  authenticated mutations.

The first walkthrough identified an obsolete Devices title and a primary
identity-reference string. Center 68 contains their focused corrections.
The final installed tuple repeats the route/workflow/minimum-window checks,
fresh positive coverage, ordinary direct-key denial and real Brave ordinary-read /
protected-key denial. The actual window is left open on Protected Data, with
no authorization dialog pending. DMS, Context, ordinary SSH and root recovery
remain available.

## Inputs and checks

Center `0.1.0-68.fc44.x86_64` RPM SHA-256:
`48dd3217e2bba2656369ac428505a7decdf930e5bd193310834371fe346d4cc5`.
Installed Center SHA-256:
`d537f061a0af44122a0e8505badc01fec243be46227b5c56fda861652f2b9bf8`.
Center source archive SHA-256:
`4ad0bc657d5b58f3fe136f0b7f567e281ec4c94557428578df835c0dcca857ad`.
Context `0.1.0-69.fc44.noarch` RPM SHA-256:
`26680e0c9f8e8edb0da2ad2148c43b06fbc745e87e1eaf3e0e1cf08370997f72`.
Runtime remains `0.1.0-25.fc44.x86_64`, with the enforcement receipt's hash.
`rpm -V` is clean for all three packages. Root-owned `active.json` records the
same tuple and verified hashes; it remains a receipt, not enforcement evidence.

PASS: 111 focused frontend tests, 11 telemetry tests on Windows and Fedora,
Fedora workspace formatting, repository static and documentation gates. The
offline Center RPM uses `--nocheck` after focused source checks; no new full
workspace, Clippy, performance, exhaustive mutation or release acceptance is
claimed. Builds used one Cargo job and the existing package cache. Disk space
was checked before deployment (7 GiB available); no cleanup was needed.

## Recovery and limits

Previous matched packages and enrollment originals remain root-private under
`/var/lib/greyward-development/application-security-live/enrollment-20261008`.
The presentation update retains its previous active receipt and RPMs under
`/var/lib/greyward-development/application-security-live/ux-20261008`.
Only Center/Context are upgraded; root broker, enrolled mapping, protected
labels, compositor and authentication owner are unchanged. Policy revision is
still 6 and the validation grant remains revoked. No reboot, lock experiment,
ISO, LUKS or VM configuration change occurred.

The transient UI review unit has a restricted service label. Its ordinary
restart was denied. The verified old Center process was closed normally and
the installed replacement opened through the existing driver; no policy was
widened for the test tool.

DEFERRED HARDENING: exhaustive accessibility/scale/multi-user and portal/deputy
matrices, physical-seat/suspend, performance/reproducibility, clean ISO and
automatic production lifecycle. Unsupported tool/grant/provider capabilities
retain their existing unavailable state. This receipt adds no release promise.
