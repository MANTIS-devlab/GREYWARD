# GREYWARD file integration candidate

Candidate only; production package closure and real workflow acceptance remain
pending. The owning evidence and rollout gates are in
[file manager and desktop integration](../../docs/architecture/FILE_MANAGER_DESKTOP.md).

The package reuses the attested upstream Strata 1.0.0 x86_64 archive, validates
its SHA-256 and source commit before packaging, and builds a small desktop-only
Qt style against Fedora Qt6. No upstream portal, udisks replacement or privileged
file manager is installed. Native and third-party license notices are retained;
the upstream archive includes the separately licensed UnRAR decoder.

Run `build.sh VERIFIED-INPUTS NEW-OUTPUT` on Fedora 44. Inputs are the exact
release archive and source archive recorded in `source.json`. Downloading and
attestation verification happen before this offline packaging step. Compilation
and RPM construction must run as an unprivileged builder. Do not install or
promote this package into production until the documented prototype gates pass.
Development installation is needed to validate its real packaged workflows.

Defaults are seeded only when missing. User MIME choices, Strata settings and
PCManFM layout/preferences are preserved. Only this desktop process selects the
Qt style; all other Qt/GTK applications retain their current theme. The user unit
is ordered after DMS, and its native transparent image leaves wallpaper ownership
with DMS. The existing bounded DMS shell readiness probe avoids mapping icons
before its wallpaper. Automatic startup passes in the development login;
clean-image acceptance remains pending.

`branding/source/greyward-files.svg` is the canonical Obsidian/Platinum folder
icon, packaged with the GREYWARD branding notice. The upstream attested binary
remains unchanged. Its launcher uses the root-owned SVG directly, avoiding stale
negative theme-icon cache entries in an already-running desktop.
