# GREYWARD identity system

The symbol, wordmark and lockup in `source/` are canonical identity artwork. `source/greyward-security-status.svg` is the small protective emblem for Security Center shell surfaces; its package copy is generated without changing the geometry. The wallpaper source is canonical environmental artwork. Everything under `generated/` is derived; DMS and Plymouth consume the generated/installed assets directly. Designated GREYWARD identity assets are reserved branding under `LICENSE`; `PROVENANCE.md` records their repository origins and immutable hashes.

## Replace the logo everywhere

1. Update the canonical symbol and any affected wordmark/lockup geometry.
2. Run `tools\generate-branding.ps1` against a healthy GREYWARD appliance.
3. Run `tools\validate-branding.ps1`.
4. Deploy/reload DMS and capture it.
5. Build/install the branding RPM, rebuild initramfs, and complete H2 boot/unlock recovery validation.

Never paste logo geometry into QML or Plymouth scripts. Add new consumers to `manifest.json` before deploying them.

The Fedora Anaconda installer keeps its native account workflow, storage
behavior, and stage2 code. The ISO injects only the GREYWARD GTK profile,
stylesheet, and logo through a small supported `updates.img`; it does not
replace Anaconda code or hide the account page. This keeps the workflow intact
while making the GTK installer visibly GREYWARD-branded.
Plymouth/LUKS branding is applied to the installed target before its first
reboot.

The branding RPM also carries the Cockpit branding path for the installed
system and a future Web UI installer path. The Fedora 44 Everything installer
used by the current ISO is GTK, so the ISO deliberately injects the GTK profile,
stylesheet, and logo rather than relying on Cockpit CSS. The welcome, storage,
account, and error-dialog pages must still be checked visually on every
branding rebuild.

Plymouth deliberately uses a true black background with the centered GREYWARD
logo. This keeps resolution changes and bootloader letterboxing from exposing
grey side bands.

During an offline update boot, `greyward-update-status.service` is activated only
when `/system-update` exists. It switches Plymouth to `updates` mode before DNF5,
then the script theme replaces `Starting GREYWARD` with `Installing system
updates`, `Keep this computer powered on`, and a progress bar. The percentage is
rendered only from Plymouth's system-update callback; `Preparing update...` is
the explicit fallback before DNF5 reports its first progress value. Theme or
status-unit failure does not own or determine the native DNF5 result.

Additional raster wallpaper variants are available for DMS:

- `branding/wallpaper/greyward-wallpaper-black-art-4k.jpg`
- `branding/wallpaper/greyward-wallpaper-2109-4k.jpg`

The DMS wallpaper collection intentionally contains only these two supplied
3840×2160 JPG wallpapers with the canonical
`branding/source/greyward-symbol.svg` rendered as the visible GREYWARD logo;
the variants do not redraw or approximate the logo.

## Installed DMS wallpaper collection

The production provisioner installs only these two images from
`branding/wallpaper/` into `/usr/share/backgrounds/greyward/`, a standard
system background directory available to DMS. The default DMS wallpaper path
is a compatibility symlink to `greyward-wallpaper-black-art-4k.jpg`; both
images remain available through the normal DMS wallpaper workflow:

- `branding/wallpaper/greyward-wallpaper-black-art-4k.jpg`
- `branding/wallpaper/greyward-wallpaper-2109-4k.jpg`

## Greetd login background

The DMS Greeter login screen uses the Black Art desktop wallpaper
`branding/wallpaper/greyward-wallpaper-black-art-4k.jpg`, so the login and
desktop backgrounds cannot drift apart. There is no separate greeter artwork.
Provisioning atomically synchronizes the installed desktop wallpaper to
`/var/cache/dms-greeter/greeter_wallpaper_override.jpg` before every `greetd`
start. The override is persistent and is not exposed as a second desktop
wallpaper choice.

## Boot branding lifecycle

The daily GREYWARD development VM uses the reversible path below:

```powershell
.\tools\generate-branding.ps1
.\tools\validate-branding.ps1
.\tools\build-branding-rpm.ps1
.\tools\greyward-dev\install-boot-branding.ps1
.\tools\greyward-dev\verify-boot-branding.ps1
```

The installer selects the `greyward` Plymouth theme and regenerates the target
initramfs before the first encrypted-root unlock; subsequent production
provisioning repeats this selection safely. Verification confirms that a normal
kernel initramfs contains the GREYWARD script theme and logo assets, and that the
installed status unit and theme retain the update-mode command and progress
callback. Re-running it is safe.
`restore-boot-branding.ps1` restores the previously
recorded Plymouth configuration and rebuilds initramfs, including the case where
the host had no explicit prior theme configuration.

This proves controllable boot branding on the daily appliance. Encrypted-root unlock
acceptance remains a separate disposable `GREYWARD-BOOTTEST` gate and must not be
claimed from the normal initramfs inventory check alone.

## Encrypted unlock presentation

The packaged script theme is presentation only: Fedora's normal
`cryptsetup → systemd/dracut → Plymouth` request path owns the passphrase and
authentication result. The theme receives only Plymouth's masked bullet count;
it never registers a raw keyboard callback, receives characters, or uses LUKS
data in its animation. The `VERIFYING KEY` glyph field is decorative state
derived from elapsed refresh ticks, a local PRNG, and the framebuffer size.

The canonical source for its sole logo asset is
`branding/source/greyward-symbol.svg`. `tools/generate-branding.ps1` renders
the small PNG packaged in the initramfs; no Plymouth-specific logo source is
maintained. A clean image build must pass the resulting `greyward-branding`
RPM to `environment/image/build.sh --branding-rpm`; production provisioning
installs it, selects the theme, and regenerates initramfs.

Validate unlock behavior only in disposable `GREYWARD-BOOTTEST`. Before
accepting a callback as a transition signal, record the Fedora 44 sequence for
prompt display/dismissal, prompt reappearance, root progression, and splash
shutdown. Test correct and incorrect passphrases, repeated attempts, theme
absence, text-console recovery, available framebuffer resolutions, and layout
or Caps Lock indicators only when the early-boot stack exposes them reliably.
