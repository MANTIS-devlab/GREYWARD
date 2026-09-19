# Dank Module and Trust Policy

> Decision and audit record. Dated runtime observations are historical; current
> implementation ownership is defined in `docs/REPOSITORY_MAP.md`.

Status: Policy and audit record. A component is enabled only when the production
definition and its validation evidence explicitly include it; this document is
not itself an installer.

| Component | Initial policy | Required audit |
|---|---|---|
| DMS core | Required candidate | version, source, services, Labwc behavior, logs, performance |
| dgop | Enabled production capability | dependency, daemon model, CPU/RAM, exposed telemetry, disable path |
| dsearch | Enabled production capability | local-only indexing, exclusions, watchers, paths, secrets, I/O, rebuild, disable path |
| dcal | Disabled by default | no startup network activity, explicit opt-in accounts, sync scope |
| Dank16 | Optional derived palette | GREYWARD tokens remain source of truth |
| DankGreeter | Production login surface | pinned/signed package, greetd/PAM boundary, no autologin, rollback path |
| Community plugins | Disabled/hidden | registry, arbitrary code execution, permissions, provenance |
| DMS updater | Disabled or GREYWARD-managed | privilege, source, pin enforcement, rollback |

## Objective 1 decisions

- DMS core: selected audit pin `v1.5.3`; do not install yet.
- `dgop`: enabled in the production image from the pinned GREYWARD DMS dependency repository. Provisioning fails closed if `/usr/bin/dgop` is absent.
- `dsearch`: enabled in the production image through the `danksearch` package. Provisioning fails closed if `/usr/bin/dsearch` is absent. Its index must remain local-only with explicit exclusions for secrets, browser internals, vaults, and GREYWARD-sensitive paths.
- `dcal`: disabled; no account or remote sync configuration.
- Dank16/matugen: disabled for the GREYWARD baseline. GREYWARD tokens remain canonical; dynamic wallpaper-driven application theming is not an acceptable default.
- DankGreeter: enabled as the production login surface through greetd. The greeter is
  unprivileged; authentication remains in Fedora's PAM stack. No shell-side password
  handling, tty autologin, or custom privileged authentication helper is allowed.
- Plugins: disabled/hidden for the first test. DMS source contains registry browsing and install flows, including explicit third-party risk messaging; this is an arbitrary-code and network-provenance boundary, not a harmless UI feature.
- Updater: disabled. DMS exposes `dms update`, while Fedora packaging advertises distro-package behavior; GREYWARD must verify and enforce this rather than assume it.

## Privacy defaults

Do not index `~/.ssh`, `~/.gnupg`, GREYWARD-sensitive directories, secret vaults, browser internals, or system secrets. No calendar/cloud request may occur merely because a component is installed. All startup and interaction-time network connections must be captured and classified.

## Process ownership

Before enabling any component, record who starts it, why it exists, whether it can be disabled, expected CPU/RAM, filesystem access, network access, and rollback behavior. Maintain exactly one owner for notifications, Polkit, lock/idle, wallpaper, clipboard, and generic shell services.

## Plugin policy

Allow only first-party GREYWARD plugins and explicitly audited bundled upstream plugins. Keep community discovery, automatic download, and automatic update disabled by default. Every plugin must have a pinned source, license, review status, permissions record, and removal path.

## Supply-chain finding

The inspected Fedora spec downloads a CLI from GitHub `releases/latest` during build and declares `dgop` as a required dependency. This is incompatible with GREYWARD’s reproducible-build requirement unless downstream packaging replaces the mutable URL with the selected full release asset and checksum and records the exact dgop source pin.

For the internal alpha, image traceability is enforced at the production
boundary: DMS remains pinned by version, full commit, and archive checksum;
installed RPM NEVRAs and sources, Flatpak refs/commits, licenses, and the
bounded component inventory are written to
`/var/lib/greyward/build-artifacts/`. Mutable COPR resolution is explicitly
reported until exact build records are supplied. No `latest`, `master`, or
`*-git` selector is accepted in active production/image inputs.

## Objective 2 runtime evidence — 2026-08-19

The historical reversible baseline installed DMS core only. `dgop` and
`dsearch` were absent in that probe; the production provisioner now enables
both explicitly and verifies their binaries.

During test mode, ownership was singular for the shell and notifications:
DMS/Quickshell owned `org.freedesktop.Notifications` and the ScreenSaver
names. GREYWARD’s legacy shell was stopped temporarily, not modified or
disabled permanently. On exit and after reboot, ownership returned to the
legacy GREYWARD session and no DMS helper remained.

The baseline exposed recurring conditions requiring resolution before GO:
no Wi-Fi device, BlueZ service/adapter failure, unsupported Labwc background
effect, no evdev access, missing power-profiles daemon, dummy PipeWire audio,
and graphics/portal warnings. These must be separated into VM baseline
conditions versus DMS regressions in a follow-up controlled audit; Objective 2
therefore remains FAIL/STOP despite successful startup and rollback.

## Objective 2B blocker classification — 2026-08-19

The bounded DMS run showed the warnings were startup-only rather than a
periodic crash/redamage loop. The only GREYWARD integration defect was the
manual test unit treating DMS’s expected SIGTERM exit code 143 as failure; it
was corrected with `SuccessExitStatus=143 SIGTERM` and revalidated.

No optional module was enabled to silence diagnostics in the historical probe.
Wi-Fi and Bluetooth are unavailable because the Hyper-V guest has Ethernet only
and no `/sys/class/bluetooth`; `power-profiles-daemon` remains absent. The
production image now enables `dgop` and `dsearch`; evdev access remains
restricted to avoid broadening input privileges.
Labwc blur is an explicit compositor capability warning in DMS v1.5.3, not a
reason to patch upstream logic. Direct VMConnect interaction remains the sole
acceptance gap, so Phase 2 remains FAIL and Phase 3 remains STOP.

## Canonical cutover policy — 2026-08-19

DMS v1.5.3 is now the accepted canonical GREYWARD shell foundation by explicit
product decision. The VMConnect interaction gap is waived for this promotion;
it is not evidence that physical hardware validation was completed.

Canonical DMS ownership is singular for shell, notifications, Polkit,
wallpaper, lock/idle, and tray/system surfaces. The legacy GREYWARD shell is
kept as a manually selectable rollback and is not auto-started. Optional
modules and network-connected features remain disabled by default.

## Canonical cutover evidence — 2026-08-19

The final reboot verification found one stale VM-side Labwc autostart that was
still starting `greyward-shell.service`; it was replaced with the repository’s
canonical DMS autostart. After the corrective reboot, DMS v1.5.3 remained
active and enabled, Labwc was running, the legacy service was inactive and
disabled, and DMS held the notification and ScreenSaver owners. The legacy
unit remains installed for manual rollback and was not modified. The VM was
left under DMS. Known VM capability warnings remain logged conditions and
were not hidden by enabling optional modules.
