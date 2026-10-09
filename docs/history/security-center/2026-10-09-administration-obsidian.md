# Administration obsidian follow-up — 9 October 2026

Historical development evidence; [Privilege model](../../security-center/PRIVILEGE_MODEL.md)
owns current behavior. This supersedes the initial visual finish in the
[earlier receipt](2026-10-09-administration-visual-polish.md), without changing
its historical test evidence.

## Scoped implementation

The native console uses near-black obsidian, static fine grain, subtle material
depth, silver typography/controls, a red Administration title and the canonical
GREYWARD symbol. The review explains why a sudo request opens this protected
workflow. Existing explicit risk wording, argument boundaries, request expiry,
authentication and terminal-scoped caching remain intact. Cancel is also a
pointer target; keyboard Escape/Enter retain their behavior.

The symbol is embedded from the existing canonical SVG during packaging and
rendered using librsvg. The build input rejects active/external artwork;
the runtime does not read additional artwork files. Default terminal cells
preserve the textured canvas; explicit backgrounds and reverse video remain
supported. A real screenshot caught incorrect SVG scaling in the first
iteration; fitted ink geometry and a visible-pixel regression corrected it.

## Delivery and recovery

`.149` runs a matched root-owned UI development overlay on runtime 32, with
Center 89 / Context 81 / session 8 unchanged. No new RPM/image or SELinux,
sudoers, PAM or desktop-policy change was made. Only Administration was ended
and reopened under the user's existing approval; desktop and SSH continued.
Boot ID remained `55b23e02-a831-47ef-b6f4-8a65b299b799`.

Immutable inputs, selected manifest, receipt and previous closure are retained
under `/var/lib/greyward-development/application-security-live/administration-obsidian-20261009/`.
The native executable SHA-256 is
`1045a4ed35044b36437ed16ded9283e206d2895b2346c6949d20db45ffe74963`.
Rollback selects `previous-selected` after ending only Administration and
invalidating its tickets; resource labels/account mapping remain unchanged.
No desktop rollback or rescue boot is claimed by this follow-up.

## Evidence

- Unprivileged UID 1001 native build with `-Wall -Wextra -Werror` and librsvg
  2.62.4: PASS. Pixel checks cover visible canonical artwork, default/background
  continuity, black/blank cells, reset/erase, reverse video and true color.
- Actual installed normal seat at 2560×1440: review, sudo explanation, red title,
  logo, risk/request cards, fresh PAM prompt and colored terminal output visually
  inspected. No black rectangles around default text. Screenshots are retained
  locally under `output/admin-obsidian-20261009/`.
- Fresh authentication and `sudo -i`: UID 0 in
  `greyward_admin_u:sysadm_r:sysadm_t:s0` verified. Root shell exited; ordinary
  Administration console left open for review.
- 937 live kernel checks: PASS, including ordinary Administration process,
  descriptor/PTY denials, read-only public metadata and DMA denial. Ordinary
  `/usr/bin/sudo` execution and synthetic protected-key read remain denied.
  SELinux Enforcing; live coverage PROTECTED / AVAILABLE revision 8, inventory
  UNKNOWN.

- Linux admission tests: 6 PASS; canonical embedding/rejected SVG tests: 2 PASS
  on Fedora and Windows. Frontend UX contracts: 93 PASS. Static, repository and
  branding validation: PASS. `git diff --check`: PASS. No Rust code changed;
  no new Cargo run, full package build or image validation is claimed.

Additional mouse interaction, display/scaling and
localization coverage remain unclaimed; broader hardening remains deferred.
