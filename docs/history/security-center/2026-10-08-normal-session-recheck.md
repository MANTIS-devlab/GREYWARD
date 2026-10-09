# Application Security — installed normal-session recheck

Date: 8 October 2026, final root readback 06:57:46 UTC.
Scope: the normal `.149` development desktop, not production/image acceptance.

The installed tuple remains Center 70 / Context 69 / runtime 26. No broker,
compositor, DMS, account mapping, resource label or grant change was made during
this recheck. Only Security Center was reopened to remove temporary visual
preview overrides and inspect the actual packaged application.

## Actual installed results

- PASS: root PID-1 verifier returned `{"verified":true}` twice. SELinux is
  Enforcing; ordinary SSH and the user manager use the confined Guard domain.
  The workflow broker, ordinary DMS and Security Context are active.
- PASS: live coverage is AVAILABLE / effective PROTECTED at policy revision 6.
  The actual registered `.ssh` resource reads back PROTECTED. General inventory
  completeness remains UNKNOWN; it is not inferred from session coverage.
- PASS: ordinary `open`, direct `ssh-keygen` and the revoked managed grant are
  denied on UID 1001. No key contents were printed or copied.
- PASS: existing Brave Flatpak reads `/etc/os-release` and cannot read the
  protected key. Existing overrides were retained.
- PASS: the actual installed Center shows “Your registered data is protected”,
  the resource and available folder/tool-review actions. Resource detail shows
  the new real kernel-denial events and the earlier completed GUI revocation
  in the existing telemetry history. No mocked backend responses were used.
- PASS: Protected Data and Applications each remained protected for 30 seconds;
  Overview for 15 seconds. There were zero expired coverage samples, one stable
  protection text state per route, and no replacement of the summary node.
- PASS: `rpm -V` is clean for all three packages. Installed Center SHA-256 is
  `3dc6cfbc9e276a6eaec679bd2906e6143a31969f99886512677c4c2dd2502fd7`;
  Guard SHA-256 is
  `1b7a21fc2284a9e20c7481ae7dcaa7f780859d397f6f3ce40b52527a2af2ec4a`.
- PASS: existing root SSH recovery remains available. Disk preflight: 6.9 GiB
  free; no cleanup, reboot, logout or ISO mutation occurred.

The installed-window screenshot was visually inspected. It is retained locally
at `output/application-security/20261008-ux-polish/installed-protected-final.png`;
the observations are in the guest's `flap-after.json`. Generated screenshots
are deliberately excluded from Git. Security Center is left open on Protected
Data with the validation grant revoked.

Earlier descriptor registration, freshly authenticated grant creation, two
reviewed launches without repeated authentication and GUI revocation are
documented in the [normal-session receipt](2026-10-08-application-security-normal-session.md).
This recheck does not represent a new grant-creation/revocation cycle.

## Source checks and limits

Both repository gates pass. The four focused frontend suites pass 114 tests.
The in-progress visual source revision is not part of installed Center 70.
Its Overview read waits for real coverage and its cache reuse refuses an
expired coverage projection; those source changes are not deployment evidence.
The static material check now reads the canonical tokens in `materials.css`
alongside component styling rather than assuming tokens reside in `styles.css`.

Only the tested nonexporting key-inspection profile supports persistent
sensitive READ grants. General IDE/SSH-signing, unknown-tool temporary raw
grants and WRITE/timed grants remain UNAVAILABLE. Automatic installer enrollment,
clean-image acceptance, complete offline rescue/rollback rehearsal and broader
compatibility/performance matrices remain DEFERRED HARDENING or their previously
recorded unsupported capability; none is claimed by this development recheck.
