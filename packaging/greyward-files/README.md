# GREYWARD file integration candidate

Candidate only; production package closure and real workflow acceptance remain
pending. The owning evidence and rollout gates are in
[file manager and desktop integration](../../docs/architecture/FILE_MANAGER_DESKTOP.md).

Revision 17 retains revision 15's source-built executable and strengthens the
shared semantic icon glyphs with balanced colors and darker tinted badges;
plain-text icons remain neutral. Revision 15 builds the pinned Strata source with two bounded integration patches
and an offline Cargo vendor archive. The original attested Strata 1.0.0 archive
remains a verified baseline and supplies launcher/license assets; its Actions
attestation does not apply to the derived executable. The package also builds a
small desktop-only Qt style against Fedora Qt6. No portal, udisks replacement or privileged
file manager is installed. Native and third-party license notices are retained;
the upstream archive includes the separately licensed UnRAR decoder.

Run `build.sh VERIFIED-INPUTS NEW-OUTPUT` on Fedora 44. Inputs are the exact
release/source/desktop/vendor archives recorded in `source.json`. Fetch locked
Rust dependencies in the verified source with `cargo fetch --locked`, then run
`cargo vendor --locked --offline vendor` and
from the GREYWARD checkout,
`python3 packaging/greyward-files/prepare-vendor.py VENDOR NEW-ARCHIVE`.
The resulting digest must match the pinned vendor input; do not bypass a mismatch.
Downloading and upstream attestation verification happen before the offline
packaging step. The RPM verifies the source, Cargo.lock and patch digests and
builds with `--frozen --offline`, including Cargo's dependency file checksums.
Compilation
and RPM construction must run as an unprivileged builder. Do not install or
promote this package into production until the documented prototype gates pass.
Development installation is needed to validate its real packaged workflows.
Release compilation uses ThinLTO and omits debug information while preserving
the remaining Fedora compiler flags. This bounds the optimizer's memory demand
on small builders; it does not disable a runtime isolation mechanism.
RPM checks use a dedicated Cargo integration target importing the production
metadata module directly, without compiling Strata's unrelated internal tests.
Packaging compares the release binary with the installed image before creating
the RPM.

External preview commands are explicit RPM file dependencies: ImageMagick's
`magick`, FFmpeg/FFprobe, `prlimit`, `nice`, Fontconfig's `fc-list` and
`unsquashfs`. ELF dependency detection alone does not discover these programs.
PDF rendering uses the linked Poppler library, not `poppler-utils`; optional
RAW identification tools and `ffmpegthumbnailer` are not required because the
pinned helpers have supported fallbacks. Codec availability remains Fedora's.

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
GLib's supported G_RESOURCE_OVERLAYS mechanism. Authentication and non-icon
resources are unchanged. All embedded action and
extension SVG names resolve to the same complete semantic file artwork used by
the native MIME theme. The former Catppuccin marks are not embedded inside a
second document frame. The embedded Strata application-icon resource also uses
the canonical GREYWARD Files SVG. Lucide/Feather and upstream notices are
retained. Third-party application logos and real content thumbnails
remain their own identity/content rather than synthetic file icons. This is an
icon-family change, not a global GTK/Qt interface theme. The native-icons patch
uses a separate GIO/GTK theme instance for file MIME icons and launcher logos;
it does not change global GTK settings. Custom per-file artwork remains preferred.
Launcher fields are bounded display metadata, never proof of identity, trust or
authority, and no `Exec` field is evaluated. SVG rendering retains the existing
size limit and disabled external references; PNG dimensions and input size are
bounded. Unsupported icon formats retain the bundled fallback.
Named theme lookup is limited to administrator-owned system/theme and Flatpak
export locations. Absolute file hints bypass GTK lookup and go through the
bounded renderer directly. Direct artwork must be root-owned and not group- or
world-writable; personal image content retains isolated preview handling. Named
icons available only in a private user theme can retain the bundled fallback;
no launcher trust is inferred from an icon.

`STRATA_PREVIEW_SANDBOX=oneshot` selects Strata's existing per-operation
bubblewrap renderer. The reusable worker's nested `/proc` mount is denied by
the ordinary GREYWARD policy. This patch selects the existing isolated path;
it grants no mount permission and never enables unsandboxed parsing. Native
ODT content thumbnails remain unsupported; do not disable desktop thumbnails
to manufacture identical rendering. Installed GUI acceptance is separate from
source compilation; see the owning record for the current development state.

`branding/source/greyward-files.svg` is the canonical Obsidian/Platinum folder
icon, packaged with the GREYWARD branding notice. Its launcher uses the root-owned SVG directly, avoiding stale
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
