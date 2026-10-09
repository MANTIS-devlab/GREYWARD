# Administration console visual polish — 9 October 2026

Historical scoped development evidence. Current privilege behavior belongs to
[Privilege model](../../security-center/PRIVILEGE_MODEL.md) and the
[enrollment authority](../../security-center/APPLICATION_SECURITY_ENROLLMENT.md).

## Change and delivery

The protected native Cairo/Pango/libvterm console now uses restrained graphite
and silver materials, a dedicated lock mark, bounded risk/command cards and
larger monospace text. Expanded first-use warning revision 2 explains credential
exposure, disabling protections, data loss and privileged code execution.
Returning users retain a concise reminder. Both explain that cache expiry does
not terminate an existing root shell. Argument boundaries, completeness checks,
two-minute review expiry and mandatory authentication remain enforced.

The black rectangles were libvterm's default black background painted against a
different canvas color. Defaults now match graphite. Explicit ANSI black,
blank/erased background cells, reverse video and true-color backgrounds remain
intact; the base ANSI palette is legible on the dark surface.

Installed on `.149` as an explicit assembled native UI development overlay on
runtime 32, with Center 89 / Context 81 / session 8 unchanged. No new RPM or image
was built. Package-owned inputs, SELinux rules, Fedora PAM, sudo configuration and
the active desktop closure were not changed. Root-owned source/binary hashes,
the selected manifest and previous closure are retained under
`/var/lib/greyward-development/application-security-live/administration-visual-20261009/`.
Rollback selects the saved `previous-selected` closure after ending only
Administration; it does not require logout or reboot.

## Validation

- Native compiler: `-Wall -Wextra -Werror`, PASS.
  The ordinary confined user's independently compiled binary matches the
  selected native executable byte for byte (SHA-256
  `c28a2730215d74ee0501b75fe0014e9cfaa7cb8121b9f0a54381f0a9291c22e7`).
- Native pixel regression: defaults, explicit black, blank/erased cells, SGR
  reset, reverse video, readable ANSI blue and explicit true color, PASS.
- Linux admission/descriptor tests: 6 PASS against the changed worker.
- Actual normal desktop: review and returning-user reminder inspected at
  2560×1440; protected-input verification, fresh Fedora PAM, `sudo -i`, UID 0 in
  `greyward_admin_u:sysadm_r:sysadm_t:s0`, ordinary console after root-shell exit,
  and colored directory output inspected. Default text has no black rectangles.
- Live kernel readback: 937 adjacent decisions PASS; ordinary administration
  process/descriptor/PTY access remains denied. Direct ordinary `/usr/bin/sudo`
  and the synthetic protected key read remain denied. Coverage reports
  PROTECTED / AVAILABLE at revision 8; inventory remains UNKNOWN.
- Frontend UX contracts: 93 PASS. Static and repository/documentation gates:
  PASS. No Rust implementation changed; the earlier runtime package's Cargo
  evidence is not presented as a new Cargo run in this visual pass.

Only Administration was closed/reopened with explicit approval. The graphical
session, compositor and SSH recovery stayed running; no reboot occurred. The
previous full desktop rollback and production rescue gates remain pending.
Mouse approval, additional display/scaling configurations and localization are
not claimed as live-validated by this pass.
