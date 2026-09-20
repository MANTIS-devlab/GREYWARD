# GREYWARD production system definition

This directory is the production-side definition of the future installed
GREYWARD system. It is intentionally not an ISO builder or a release pipeline.

The intended layering is:

```text
GREYWARD production system + environment/development overlay = GREYWARD-DEV
```

`provision.sh` installs the runtime system and the GREYWARD-owned components
that the current functional VM uses. The image/factory that calls it supplies
the two Security Center RPMs in `rpms/`; the repeatable component-build step is
kept in `environment/development/build-security-center.sh` because its compiler
and packaging tools are factory-only.

`packages.txt` is the runtime package contract and `repositories.txt` lists
the small set of production sources needed by that contract.

The production cryptographic baseline is Fedora `DEFAULT` layered with the
GREYWARD-owned `GREYWARD` policy module. Provisioning installs the module and
applies `DEFAULT:GREYWARD` explicitly instead of inheriting the installer or
host default. See
[`docs/security/crypto-policy.md`](../../docs/security/crypto-policy.md) for
the rationale, compatibility cost, validation scope, and rollback command.

The runtime contract includes Fedora's `dnf5daemon-server` and
`dnf5daemon-server-polkit`. The first provides the unprivileged D-Bus
resolution backend used by Security Center; the second retains Fedora's
standard wheel authorization contract. Apply itself crosses GREYWARD's fixed
one-prompt update transaction boundary, which creates the recovery point before
delegating to native providers. This is intentional because the base Fedora
image previously supplied `dnf5` without its daemon subpackages.

The user Security Context and Update Center services are globally enabled by
the provisioner for the finished account. Their D-Bus names remain owned by
their native user services, so this startup guarantee does not add a parallel
update or security backend.

The canonical Labwc session entry starts through `greyward-start-labwc`. The
launcher selects wlroots' Pixman renderer for known VMware/Hyper-V virtual GPUs
and for systems that expose no usable DRM render node, where an accelerated
EGL/dma-buf path cannot be relied on during DMS startup. Bare-metal GPUs with a
usable render node keep hardware acceleration; the production image does not
globally disable graphics acceleration.

The baseline includes Firefox as an alternate browser, Nautilus,
`Terminal`, GNOME Screenshot, OBS Studio, Papers, Loupe, File Roller, CUPS
printer support, and the
 first-class system Flatpak applications Aerion mail, Collabora Office, Haruna,
 Brave, and Proton VPN. `environment/flatpak/default-applications.list` is the canonical
installed-app list, and `environment/flatpak/mimeapps.list` defines the
reproducible mailto, web, office-document, PDF, image, and local-video defaults.
PDFs open in Papers and common images in Loupe; neither relies on browser
registration order to select a local-file handler.

Files includes the native GVfs backends for Windows/NAS (SMB) shares, MTP
phones, cameras, and archive browsing. These are client integrations; they do
not enable an SMB server or share local files automatically.

`net-tools` is included for compatibility with the traditional `ifconfig`
command; modern scripts should continue to prefer `ip`/NetworkManager. The
`blackbox-terminal` is the Fedora-native GTK/VTE terminal engine. The
canonical override in `desktop-entry-overrides/com.raggesilver.BlackBox.desktop`
keeps Black Box's real application ID for reliable Labwc and DMS taskbar
grouping while presenting the user-facing name `Terminal`, GREYWARD geometric
icon, and `/usr/bin/zsh` login shell. The same command is used by the Labwc and
Hyprland launchers, so keyboard launch and desktop launch have one behavior.
An existing `greyward-terminal.desktop` is migrated to a hidden compatibility
entry derived from this source, preserving old pins without a duplicate launcher
or a dependency on the retired Kitty command.

The production Black Box defaults in `blackbox/schemes/` and
`dconf/50-greyward-blackbox` are the captured live `.149` state: dark theme
`Dark Pastel`, light theme `Gruvbox Light`, `Cascadia Mono NF 14`, 93% opacity,
12px terminal padding, remembered 1237x945 window size, visible header/menu,
floating controls, easy copy/paste, 1000 scrollback lines, and the login-shell
behavior. The additional `dark-pastel.json`, `paraiso-dark.json`, `seti.json`,
and `vibrant-ink.json` schemes are selectable but do not change the active
theme. Fresh installs consume this exact dconf payload.

Black Box opens directly into the captured GREYWARD Oh My Zsh/Powerlevel10k
state. The canonical shell files are `zsh/zshrc` (SHA-256
`4db86514da187b6d55f15368c3fcc8baf1591fd884170a4b8ed30ab6c080ea5a`) and
`zsh/p10k.zsh` (SHA-256
`d832b4a9ef8d8babd9e2f35dc208222263d9312cf517982c1e37bd10dce106b3`). The
prompt uses Oh My Zsh's `powerlevel10k/powerlevel10k` theme, the `git` plugin,
Nerd Font glyph mode, the current directory on the left, the current user on
the right, no icon padding, and no proactive directory shortening. Existing
Kitty or Tabby directories are user-owned historical data and are not used.

The fresh-install DMS taskbar pin set is exactly Brave (`brave-browser`),
GREYWARD Terminal (`com.raggesilver.BlackBox`), and Nautilus
(`org.gnome.Nautilus`).
The migration seeds this set only when DMS has not yet created
`barPinnedApps`; an established user's pin list remains authoritative.

The terminal's shell contract is Fedora `zsh` with Oh My Zsh and the pinned
Powerlevel10k theme from `https://github.com/romkatv/powerlevel10k`. The image
ships the canonical zsh files in `/etc/skel`; the retryable first-boot
finalizer installs the pinned upstream trees into the Anaconda-created user's
home, makes `/usr/bin/zsh` the login shell, and disables Oh My Zsh's automatic
update prompt. The production P10K file is the exact wizard-generated
`nerdfont-complete` configuration captured from the reference terminal, and
the image installs the matching Fedora Nerd Font package before first login.

Each new Black Box interactive session also renders the GREYWARD
terminal brief from `/usr/local/libexec/greyward-terminal-brief`. The renderer
reads only cheap local files and system metadata. It shows the Fedora release,
kernel, uptime, memory use, shell, and
hostname. It does not display Security Center posture, network, DNS, profile,
firewall, or update-provider details at shell startup. It never calls D-Bus,
DNF, OpenSnitch, NetworkManager, Secure DNS, or another network/provider
service during shell startup. The canonical
desktop and Labwc/Hyprland launchers set `GREYWARD_TERMINAL_BRIEF=1`, so the
first Black Box window does not depend on `TERM_PROGRAM` timing. Nested shells,
non-interactive shells, and SSH sessions do not show the brief. Every new
interactive terminal receives the full card, including terminals spawned from
an existing terminal.
Its startup card is an ASCII-safe GREYWARD wordmark and aligned local-system
summary, so no image renderer or font-dependent glyph is needed at launch.

The production desktop installs only the two supplied GREYWARD wallpapers from
`branding/wallpaper/` into `/usr/share/backgrounds/greyward/`. DMS receives a
compatibility symlink to the Black Art wallpaper, and the session applies its
real installed path so DMS opens the shared wallpaper folder when its picker
is opened.

The greetd login screen uses the same canonical desktop background as the
session: `branding/wallpaper/greyward-wallpaper-black-art-4k.jpg`. The
provisioner atomically refreshes `/var/cache/dms-greeter/greeter_wallpaper_override.jpg`
through a root-owned helper before every `greetd` start, so the setting remains
applied after restarts and cache cleanup. No separate greeter image is shipped.

DMS's production settings refer to the stable system assets in
`/usr/share/greyward/dms/`; they do not contain developer-home paths. The
per-user copies under `/etc/skel/.config/DankMaterialShell/` are still kept for
normal DMS configuration and migration compatibility. Because Anaconda creates
the first account before the retryable first-boot finalizer runs, that
finalizer also seeds the canonical DMS and Labwc files into the actual account
home while greetd remains gated; this makes the production session use the
GREYWARD defaults on the first login.

Third-party application and tray icons remain vendor-provided data. The
production DMS patches resolve the standard `hicolor` theme even when no
custom icon theme is selected, include both Flatpak's normal export tree and
the current deployment export tree, and prefer a valid StatusNotifier
`IconName` over an optional malformed `IconPixmap`. This keeps icon lookup
generic across Flatpak applications, survives app updates, and avoids copying
or hard-coding a vendor-specific icon into GREYWARD.

DMS is the single graphical Polkit-agent owner in the canonical Labwc session.
The production DMS patch keeps its authentication dialog large enough for
reliable keyboard input, while the Security Center Recovery V1 policy
authenticates the active logged-in `wheel` user. The installed Hyprland agent
is retained for that supported fallback only; a systemd condition prevents its
D-Bus activation in Labwc, where a second agent would prevent DMS from
registering.

The installed production target uses greetd, DMS Greeter, Fedora PAM, and
Labwc. GDM and GNOME Initial Setup are not part of the installer-only target;
Anaconda creates the real first user and the standard Kickstart requests the
post-install reboot. The first-boot finalizer masks any remaining Initial Setup
units, completes deferred local package work, removes any GNOME session
entry, and runs the production acceptance contract before releasing greetd.
While the pending marker exists, both greetd and the tty1 getty are gated. The
first-boot status service writes a clear wait message directly to tty1, so the
user sees setup status rather than a misleading terminal login prompt or a
blank screen.
The immutable staged production payload is copied to
`/usr/lib/greyward/installer/production` on the installed root filesystem;
only retry/status markers live under `/var/lib/greyward/installer`. This keeps
the payload visible after Fedora's automatic Btrfs layout mounts `/var`.
There is no temporary live account and no account-handoff service.

Baseline-aware installer stages import portable desktop/terminal preferences
from the selected runtime capture. First boot uses bundled RPMs, deploys captured
Flatpak app commits, and rejects packages below the captured version floors
before releasing login. It verifies the staged payload checksum and retains the
baseline provenance after setup. Retries are bounded to three starts per three
hours, with a persistent tty1/Plymouth status message and a retained diagnostic
status file. See
[`ISO_CREATION.md`](../../docs/architecture/ISO_CREATION.md) for capture scope,
build prerequisites and retry instructions. The ISO includes the RPM dependency
closure, Flatpak runtimes, DMS archive and shell source cache. Only construction
needs internet; installed setup runs without networking. The offline Flatpak
transaction temporarily disables the Flathub remote to prevent metadata refresh
attempts, then restores it for future updates. DMS's upstream What's New
changelog is disabled in the staged production patch. A clean install with the
test VM's adapter disconnected is required before accepting any new ISO.

Display Settings offers compositor include-file setup only for backends that
implement it. Labwc retains its live WLR display controls without the unsupported
Setup prompt; this does not add display persistence or change apply behavior.

Auditd is enabled in production with a moderate GREYWARD policy. It records
identity/authentication and authorization changes, login records, audit-policy
changes, privileged `sudo`/`su`/`pkexec` execution, kernel module changes, and
DNF package execution. It deliberately does not enable all-user command or
network-connection syscall auditing, which would add substantial desktop noise.
The policy is immutable at runtime (`-e 2`), so a future policy change requires
a reboot, as with Fedora's standard finalized audit profiles.

The installed DMS Greeter receives only the SELinux permission needed to query
user-unit status metadata. Two broad root-directory watch probes remain
denied and are marked `dontaudit`; GREYWARD does not grant the greeter broad
filesystem access. The production provisioner also applies a narrow UWSM
Labwc plugin fix that creates the computed reload-drop-in directory before
writing it, preserving the upstream session flow while removing the startup
error.

`/etc/greyward-production-complete` is an installed-system acceptance marker,
not a provisioning-progress flag. The first-boot finalizer writes it only
after `/usr/local/libexec/greyward-production-acceptance --pre-marker` passes;
the pending stage and display-manager gate remain in place when provisioning
fails, allowing a systemd retry without exposing a partial desktop.

Labwc routes ordinary portals to GTK and screencast/screenshot to WLR. The
GNOME portal backend remains installed for a genuine GNOME fallback session
but is conditioned away from Labwc because Mutter's service channel is not
available there. Rygel Preferences is hidden through a canonical
desktop-entry override, preserving its package dependency without presenting
an upstream utility as a GREYWARD application.

The canonical session locks after ten minutes of idle time and before
suspension through one DMS-native lock entrypoint shared by keyboard and idle
callers. DMS owns the Wayland session-lock surface, the conventional password
field, and PAM authentication, so the session and its applications remain
open. The lock uses the current canonical GREYWARD desktop wallpaper and DMS's
native lock presentation; it is distinct from the LUKS storage unlock screen.

`/etc/greyward-production-complete` is an installed-system acceptance marker,
not a provisioning-progress flag. The account hand-off writes it atomically
only after `/usr/local/libexec/greyward-production-acceptance --pre-marker`
passes for the newly created account and the disposable live account has been
removed.

GTK/libadwaita applications receive the dark Adwaita preference. Haruna is
installed with network access disabled by default for local playback; a user
can explicitly enable its network permission later if online media features
are wanted. Brave receives no GREYWARD-specific permission broadening, and
the other applications use their standard Flatpak sandbox and desktop
portals.

The Fedora Anaconda installer is co-branded by the GREYWARD branding RPM using
an automatically detected `/etc/anaconda/profile.d/greyward.conf` profile
based on Fedora's native profile and its supported GTK custom stylesheet
configuration. Fedora's native identity and installer behavior remain intact;
the canonical GREYWARD symbol is placed in Anaconda's product-logo slot and
the sidebar/navigation chrome uses a dark GREYWARD palette. A global dark GTK
theme or a fork of Anaconda is deliberately not forced.

The image stager requires a Security Center build manifest in addition to the
two RPMs. The manifest binds their filenames, hashes, NEVRAs, and source-tree
fingerprint; the production contract also verifies the package-owned provider,
D-Bus, Polkit, helper, and UI paths. This prevents a stable RPM release number
from allowing an older package payload to enter a new ISO unnoticed.

The production definition must not require the `stendev` account, a developer
password, passwordless sudo, SSH access, Hyper-V services, or developer tools.

The normal installed path uses encrypted Btrfs root. Boot rollback remains a
separate prototype and is not part of this directory.
