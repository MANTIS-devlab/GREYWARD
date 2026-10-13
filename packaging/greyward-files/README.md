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

The shared file/object family is defined by
`branding/source/greyward-icon-family.json`. `tools/generate-file-icons.py`
builds the native Greyward icon theme and matching Strata SVG resources from
the verified source archive. The desktop-only Qt style selects this native
theme through QIcon, not an unsupported PCManFM `IconThemeName` setting;
PCManFM's supported fallback setting also names Greyward. Existing profiles
and DMS icon selections require a deliberate targeted migration rather than
overwriting user preferences.

Strata's launcher selects only its root-owned icon resource subtree through
GLib's supported G_RESOURCE_OVERLAYS mechanism. The attested ELF, application
code and authentication resources are unchanged. All embedded action and
Catppuccin file SVGs receive the shared treatment; Lucide/Feather and Catppuccin
notices are retained. Third-party application logos and real content thumbnails
remain their own identity/content rather than synthetic file icons. This is an
icon-family change, not a global GTK/Qt interface theme.

`branding/source/greyward-files.svg` is the canonical Obsidian/Platinum folder
icon, packaged with the GREYWARD branding notice. The upstream attested binary
remains unchanged. Its launcher uses the root-owned SVG directly, avoiding stale
negative theme-icon cache entries in an already-running desktop.

Revision 7 also builds the pinned PCManFM-Qt 2.4.1 source archive recorded in
`source.json`. The Fedora SRPM's digests were checked; no SRPM signature is
claimed. Its three-line `pcmanfm-desktop-only.patch` prevents desktop mode from
claiming `org.freedesktop.FileManager1`, which otherwise captures requests meant
for Strata. This registration precedes PCManFM's configuration loading and has
no native opt-out. The original Fedora executable and shared translation assets
remain installed. Only the desktop wrapper selects the corrected binary; private
PCManFM desktop control, file actions and default-manager folder opening remain
native. Package build and installed D-Bus validation are separate gates.
