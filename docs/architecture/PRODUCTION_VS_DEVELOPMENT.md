# Production system versus development repository

This repository contains both the GREYWARD product and the machinery used to
build and probe it. The two must not be confused.

## Future production system contract

The future installed GREYWARD system is a Fedora-based desktop image with these
runtime surfaces. This is an active-development contract, not a release claim:

- Labwc as the canonical Wayland compositor, with Hyprland retained only as a
  supported fallback where explicitly selected.
- DankMaterialShell (DMS) v1.5.3 from the independently checked archive,
  including DMS Settings as the only general desktop/system settings surface.
- Flatpak with a system Flathub remote, GTK/WLR desktop portals, and the
  pinned Bazaar-based `Software` application. Software is pinned immediately
  to the right of the DMS GREYWARD Security plugin; Update Center remains the
  canonical application-update surface.
- DMS companion capabilities `dgop` (system/process monitoring) and
  `dsearch` via the `danksearch` package (launcher file search), with image
  provisioning checks for both binaries.
- greetd plus the signed DMS Greeter package. The greeter runs as the
  unprivileged `greeter` account; Fedora PAM remains authoritative for
  authentication. tty autologin is not part of the production image.
- Fedora system services and backends: systemd/logind, NetworkManager,
  PipeWire/WirePlumber, BlueZ, UPower, Polkit, portals, firewalld, SELinux,
  Plymouth, dracut, cryptsetup, and the Fedora `DEFAULT:GREYWARD` system-wide
  cryptographic policy.
- GREYWARD branding, including the black-background Plymouth theme, centered
  logo, encrypted-root prompt handling, and the conditional
  update-mode presentation during `/system-update` boots. The presentation says
  that system updates are installing, warns the user to keep the computer powered
  on, and shows provider-reported percentage progress; before progress is
  available it truthfully reports that the update is being prepared.
- GREYWARD Security Center as the GREYWARD-specific security/privacy surface.
  Its production RPM and desktop entry are inputs to the production provisioner.
- A practical desktop baseline: Firefox as an alternate browser, Nautilus,
  Terminal (Black Box engine, GREYWARD-owned identity), GNOME Screenshot, OBS Studio, Papers, File Roller, CUPS printer
  support, and the system Flathub applications Aerion mail, Collabora Office,
  Haruna, Brave, and Proton VPN. The installed set and default handlers are defined
  by `environment/flatpak/default-applications.list` and
  `environment/flatpak/mimeapps.list`. GTK/libadwaita applications prefer
  dark Adwaita; Haruna is network-isolated by default for local playback.

The final ISO must not ship the removed standalone GREYWARD Settings
application, its RPM, its deployment script, or its dedicated backend/design
documents.

The installed production system has one official login path:
`greetd → DMS Greeter → Fedora PAM → Labwc`. DMS Greeter starts its own Labwc
compositor as the `greeter` user, so the greetd command passes a dedicated
software-renderer environment directly to that greeter process rather than
relying on the eventual user's Labwc configuration. This keeps virtual GPUs such as
VMware's vmwgfx path from presenting a black greeter when accelerated EGL or
DRM modifiers are unavailable. The installer is direct Anaconda
boot/netinst media; it does not start a live desktop, GDM autologin, or a
temporary account. Anaconda's account page creates the first installed
account; GNOME Initial Setup is excluded and masked only after Anaconda has
finished. The retryable first-boot service performs local-only production
finalization and writes the completion marker only after acceptance succeeds.
Both greetd and the tty1 getty remain gated until then. The first-boot status
service writes a clear wait message directly to tty1, and the finalizer tees
every provisioning command's stdout and stderr to both journald and tty1. Setup
status therefore remains visible without exposing a misleading terminal login
prompt or a blank screen. The installer primes the
target initramfs with the GREYWARD Plymouth theme before that first reboot, so
the first encrypted-root unlock is branded.

The installed GREYWARD Labwc session uses the same compatibility boundary after
authentication. Its session launcher detects VMware through the read-only DMI
identity or VMware DRM vendor ID and exports `WLR_RENDERER=pixman` only there,
before starting UWSM/Labwc. This prevents the VMware `vmwgfx` dma-buf close
failure from killing the user's Wayland connection when DMS starts. The launcher
does not set Pixman on physical hardware or another hypervisor, so the production
ISO remains hardware-accelerated where the compositor's normal renderer works.

### Current development boundary

The production definition is under `environment/production/`. The disposable
Hyper-V factory uses the separate development Kickstart bootstrap and then
applies the production definition plus `environment/development/`. The
bootstrap account, SSH, passwordless sudo, Hyper-V services, compiler/toolchain,
and debugging tools are therefore development-only and must not be copied into
an installed image.

This includes the Security Center build toolchain: GCC/CMake/Ninja, Rust/Cargo
with rustfmt and Clippy, RPM tooling, and the `*-devel` headers for WebKitGTK,
Nautilus, OpenSSL, AppIndicator, librsvg, and libxdo. They belong exclusively in
`environment/development/packages.txt`. The final Security Center RPM may
require the normal `webkit2gtk4.1` runtime to launch, but it must never bring
its compiler, build tools, or development headers into the installed system.

## Development-only machinery

These files support authoring, VM probing, or release engineering and are not
installed into the target user's system:

- `tools/greyward-dev/`: Hyper-V lifecycle, SSH deployment, capture, health,
  rollback, graphics gates, and compatibility probes.
- `environment/greyward.pkr.hcl`, the development Kickstart bootstrap, and
  Packer cache/state: disposable factory inputs, not runtime applications.
- `.secrets/`, repository SSH configuration, host identities, VM endpoints,
  `stendev`, and development-only passphrases. These must never be copied into
  a public ISO or production account policy.
- `GREYWARD-DEV`, `GREYWARD-BOOTTEST`, Hyper-V helpers, `output/`,
  `build/`, `state/`, screenshots, and generated capture artifacts.
- visual spikes and migration probes. The former standalone shell tree and
  service have been removed; canonical production shell ownership is DMS.
- `tests/`, `spikes/`, and source-only audit/research notes. They inform release
  acceptance but are not runtime services.

## Build boundary

`environment/production/provision.sh` is the installed-system boundary.
`environment/scripts/provision.sh` remains only a compatibility wrapper.
Anything installed there or copied into `/usr`, `/etc`, `/var`, or `/home` is a
production candidate. Anything reachable only through
`environment/development/` or `tools/greyward-dev/` is development tooling.

The shared source session tree also has a deliberate staging boundary:
`environment/session/labwc/environment` and `autostart` contain the disposable
VM's Virtual-1 behavior. The production image stager copies only the shared
Labwc compositor/theme assets; it uses `environment/production/labwc-environment`
and `labwc-autostart` for the installed session. The production environment
keeps wlroots' software-renderer fallback enabled so virtual GPUs without a
usable EGL path do not produce a black session; hardware-specific display
controls remain outside the production payload. The VM overlay may still
consume its VM-specific files directly.

`environment/image/build.sh` stages the production inputs and records source
traceability. `environment/image/build-iso.sh` embeds those inputs in the
internal alpha installer by customizing Fedora Everything/netinst media with
`mkksiso`. A Workstation/live ISO is not a valid base because its profile
delegates account creation to GNOME Initial Setup. The ISO boots directly into
Anaconda; it does not compose or start
a live desktop, does not create a temporary account, and uses the native
Anaconda account/storage workflow for the encrypted installation. The
Kickstart leaves root and normal-user credentials unspecified so the visible
account page is mandatory. The installer leaves Fedora's native Anaconda
account workflow, storage behavior, and stage2 code intact. It adds only the
GREYWARD GTK profile, stylesheet, and logo through a small supported
`updates.img`; no installer code or account-page suppression is injected.
GREYWARD branding is also applied to the installed target and its initramfs
before the first reboot. Bundled DMS and
Flatpak work is finalized locally by one retryable first-boot service after Anaconda
has rebooted into the installed target. The installer only copies and enables
that gate; it does not run DNF or systemd-dependent production provisioning in
the Anaconda target chroot. The service keeps greetd gated until
the installed-root acceptance contract passes, then removes its pending stage
and exposes the normal greetd → DMS → Labwc path. `firstboot --disable` and
package exclusions prevent GNOME Initial Setup from becoming a second account
owner. Neither the installer ISO nor the installed production path runs the
development overlay.
Use `tests/production-acceptance.sh` against an installed production system,
and use `tools/greyward-dev/health.ps1` only for the separate VM overlay.

The production provisioner records image-local trace artifacts under
`/var/lib/greyward/build-artifacts/`: installed package NEVRAs and sources,
licenses, Flatpak refs/commits, COPR build records, enabled repositories, and a
bounded component inventory. Unresolved provenance is visible in those files
and blocks public release claims; it is not silently treated as reproducibility.

When GREYWARD is ready for image work, verify from the built image—not only
from a developer VM—that:

1. greetd, DMS Greeter, PAM, and the selected Wayland session provide a real
   login/logout/recovery path;
2. Security Center and security-context are installed by the production
   provisioner, without the development deployment script;
3. no autologin, developer SSH key, plaintext development credential, or
   standalone GREYWARD Settings artifact is present; and
4. an actual offline update reboot shows the update status, while an ordinary
   reboot does not.
