# GREYWARD screenshot editor

Small adaptation of Fedora 44 Swappy 1.5.1-8: native GTK minimize/maximize/close,
resizable window initialized to its content size, native Adwaita dark variant
scoped to this process, and the canonical GREYWARD screenshot icon. The editor
still handles ordinary saved PNGs. Capture authority, mouse selection, clipboard,
annotation and image coordinates are unchanged; no service or permission is added.

## Build and image integration

As an ordinary Fedora builder, with gcc, meson, scdoc, gtk3-devel,
libnotify-devel, desktop-file-utils and gpgverify installed:

```sh
python3 packaging/greyward-swappy/build.py --output /path/to/new-rpmbuild
```

Optional `--inputs DIRECTORY` reuses the two signed upstream release files.
`source.json` pins their SHA-256, the Fedora-exported public signing key and the
local patch. Both checksums and upstream detached signature verification are
mandatory. No upstream archives or build output belong in Git. The Fedora source
package URL in the manifest documents where the original spec/key came from.
MIT upstream licensing and attribution are retained.

Build Branding 19 and Session 43 with the existing builders. Supply the resulting
`swappy-1.5.1-8.greyward2.fc44.x86_64.rpm` to both image staging and the installer
builder as `--swappy-rpm FILE`. Complete staging rejects its absence, a missing
GREYWARD capability or stale source manifest. The ordinary dependency closure and
provisioner install this RPM, not Fedora's undecorated build. No ISO is built here.
Session requires `swappy(greyward-window-controls) = 1`; a Fedora rebuild cannot
silently replace this adaptation. Maintain this small patch when adopting future
Swappy releases, refreshing the pinned sources/signature/key and package revision.
This is a rebuilt editor, not a runtime resource/cache override.

The hidden `swappy.desktop` opens a supplied PNG directly. The visible Screenshot
launcher continues explaining the physical Print Screen shortcut; it does not
attempt unprivileged Grim access to the real desktop. Existing default image
associations are preserved. Branding owns the SVG and generated 24–256px PNGs,
including the `me.jtheoof.swappy` taskbar alias.

## Saving

The Save button and Ctrl+S open a local GTK Save dialog, suggesting an edited PNG
beside the source capture. An explicitly configured Swappy save directory takes
precedence. Cancellation writes nothing. Overwriting an existing chosen file
requires the native confirmation; the input capture is kept by default.
The PNG is encoded before GIO replaces the selected local file atomically with
private permissions. Actual write failure keeps the editor open and displays
an error; only success updates the header with the saved filename. Existing
settings are not rewritten and the legacy explicit `-o` command-line path is
unchanged. The chooser uses local GIO backends to avoid spawning remote volume
discovery services. Existing mounted paths remain normal local filesystem paths.
See the [GTK chooser](https://docs.gtk.org/gtk3/class.FileChooserDialog.html) and
[GIO replacement](https://docs.gtk.org/gio/method.File.replace_contents.html) APIs.

## Local validation and recovery

On 31 October 2026 the release signature verified and all three RPMs built on
`<validation-host>`. The actual packaged editor rendered a synthetic image under a separate
headless Labwc/pixman session: native controls and dark appearance were inspected.
No personal desktop was captured. Mouse clicks on titlebar controls and the
physical screenshot workflow were not separately exercised in this change;
editing/capture code is unchanged. RPM dependency preflight and installed payload
verification passed; protected-seat verification and SELinux Enforcing remained
intact. No session restart or protected-profile migration was required.

Revision `8.greyward2` was built and exercised on `<validation-host>` using the actual
packaged executable under an isolated headless compositor. A test-only GTK probe
invoked the real Save button and answered its real chooser: success produced a
pixel-identical 640×360 PNG with mode 0600 and visible confirmation; cancel wrote
nothing; a real directory-permission failure produced an error dialog and no PNG.
The source image hash stayed unchanged in all three cases. Tests ran as the
unprivileged builder; automated entry into the protected user session was
unavailable, so no physical desktop interaction is claimed. The rendered chooser,
success and error states were inspected. This does not claim a physical mouse
click or full desktop capture acceptance. No user testing was requested.

Before installation retain the prior Swappy, Branding and Session RPMs. Roll back
all three together with `dnf downgrade` against those local RPM paths. Leave user
Swappy settings and captured files untouched. No publication is authorized.
