# GREYWARD architecture

## Boundaries

GREYWARD owns shell presentation, product branding, and the Security Center product surface. DMS Settings owns general desktop/system settings; there is no separate GREYWARD Settings application. Fedora, Labwc, DMS, systemd, NetworkManager, PipeWire, BlueZ, UPower, Polkit, Plymouth, dracut, and cryptsetup remain standard upstream backends. Hyprland remains installed only as the explicit fallback compositor. No upstream fork or compositor plugin is part of H0-H2.

DMS is the sole graphical Polkit-agent owner in the canonical session. The
production DMS patch adjusts only the Polkit dialog dimensions; Security Center
keeps the privileged Recovery V1 action narrow and asks Polkit to authenticate
the active logged-in `wheel` user rather than selecting another administrator
account.

The login boundary is `greetd → dms-greeter → Fedora PAM → selected Wayland
session`. DMS Greeter runs as the unprivileged `greeter` account, reads only its
root-owned cache, and never receives or validates passwords itself. tty autologin is
disabled; `/etc/pam.d/greetd` remains the authoritative authentication policy.

Offline update boots use the standard `/system-update` marker and
`system-update.target`. The GREYWARD branding package adds a conditional Plymouth
status unit to that target. Before DNF5 begins, the unit switches Plymouth to
update mode and emits a GREYWARD-owned presentation token. The script theme then
replaces normal startup copy with `Installing system updates`, a keep-powered-on
warning, and a progress bar driven only by Plymouth's provider-reported update
fraction. Until the first fraction arrives, the same surface says `Preparing
update...`; it never invents progress. The unit is conditioned on the marker, so
update feedback appears only during an actual scheduled transaction and never on
a normal restart.

## Environment flow

`environment/production/` is the single installed-system definition. The disposable factory
applies it first, then adds the explicitly development-only overlay from
`environment/development/`. `create.ps1` is a privileged factory/maintenance path and is not a
production runtime dependency. No canonical `GREYWARD-DEV` runtime is currently registered.
A reachable internal-alpha VM is available for diagnosis, but it is development-contaminated
and is not evidence for production or Session 10 acceptance. When a canonical development VM
is available, the active path is canonical SSH plus a session-aware deploy/reload/capture loop
and does not query Hyper-V for routine application work.

The last daily development VM was unencrypted for autonomous reboot.
`GREYWARD-BOOTTEST` is a separate encrypted disposable build for graphical
LUKS presentation; neither VM is a production image.

The installed production login boundary is always `greetd → DMS Greeter →
Fedora PAM → Labwc`. The internal alpha installer boots Fedora Anaconda
directly from Everything/netinst media. It does not start a live desktop,
enable GDM autologin, or create a temporary account. Anaconda creates the
installed account; the retryable first-boot finalizer completes production
provisioning and releases the greetd gate only after the installed acceptance
contract succeeds. GNOME Initial Setup is excluded and masked so it cannot
become a second account owner.

The future image boundary is defined in
[`PRODUCTION_VS_DEVELOPMENT.md`](PRODUCTION_VS_DEVELOPMENT.md).
Packer, Hyper-V, SSH, capture, rollback, and legacy Quickshell paths are
development machinery; they are not product runtime dependencies.

## Shell flow

UWSM owns the selected graphical session: Labwc is canonical and Hyprland is fallback. A user systemd unit owns exactly one Quickshell instance. QML surfaces consume standard Wayland toplevel/workspace adapters and semantic tokens. Backend commands never live in visual components.

The bottom panel is one architectural surface: identity/workspaces/apps on the left, intentional flexible negative space in the center, and security reservation/status/tray/time/power on the right. The canonical DMS layout keeps explicit gaps between the launcher, workspace selector, and applications, uses DMS's `AppsDock` for the merged pinned/running application model, enlarges its application icons for legibility, and keeps the GREYWARD launcher mark optically smaller than them. `AppsDock` owns the native taskbar context menu, desktop-entry launch resolution, multi-window grouping, persistent `barPinnedApps` state, and pinned-icon reordering; GREYWARD does not maintain a second favorites store. GREYWARD's AppsDock patches change only the taskbar action labels, the focused-window minimize toggle, and the internal app-item gap from DMS `spacingXS` to `spacingS`; they do not change DMS identity or transaction behavior. Fresh installs seed Brave, GREYWARD Terminal, and Nautilus, while an established user's `barPinnedApps` list remains authoritative. The launcher hitbox is centered on its visual surface, so the logo-size setting changes only the mark and cannot shift its clickable target. Supporting network, audio, notification, and power icons retain the base taskbar scale.

The canonical desktop material is an AMOLED-black canvas with restrained
light-grey frosted panels, fine platinum borders, and readable high-contrast
text. DMS transparency provides the frosted treatment on Labwc; actual
background blur is enabled only where the selected compositor exposes that
capability (currently Hyprland). Every surface must remain readable without
blur.

The GREYWARD Network Traffic taskbar plugin is a thin presentation surface over
DMS's shared `DgopService` network module. The service supplies per-interface
byte counters; the plugin model selects NetworkManager's active physical
Ethernet/Wi-Fi links, excludes loopback and stacked virtual/tunnel links, and
calculates reset-safe deltas without starting another sampler. Its single click
uses the existing `greyward-security-center-route activity` path to open Network
Activity. The taskbar shows only directional throughput; interface names remain
model context and are not part of the default pill.

The adjacent GREYWARD Network Identity plugin shows separately labeled public
and local addresses. Local identity comes from local route/interface state.
Public identity uses the reviewed HTTPS providers, is always refreshed rather
than restored from an address cache, and remains in memory only. Its pill
popout owns a persistent `Public IP check` switch; the saved off state is loaded
before timers can run and prevents provider requests until manually re-enabled.
The session unit also sends non-local plain-HTTP proxy attempts to a closed
loopback port, containing the pinned DMS 1.5.3 backend's unconditional
`ip-api.com` geolocation seed without blocking the plugin's reviewed HTTPS
providers.

## Branding flow

Canonical SVG sources live under `branding/source`. `generate-branding.ps1` deterministically derives shell, raster, wallpaper, and Plymouth assets. `manifest.json` registers consumers. Generated files are never edited manually.

Logo replacement is source update -> generate -> validate -> deploy/package -> reload/rebuild initramfs -> capture/reboot acceptance.

## Recovery order

1. Reject invalid staging before activation.
2. Repoint `current` to the retained previous shell release.
3. Reinstall/remove the owned branding RPM.
4. Revert `GREYWARD-DEV` to `CLEAN-GREYWARD-DEV`.
5. Rebuild the disposable VM from verified cached inputs.
