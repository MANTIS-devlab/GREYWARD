# Dank Upstream Boundary

> Decision and audit record. Dated runtime observations are historical; current
> implementation ownership is defined in `docs/REPOSITORY_MAP.md`.

Status: Decision and audit record. DMS v1.5.3 is the current canonical pin;
the production installer records the checked archive and checksum. No visual
fork is applied.

## Candidate policy

The earlier `v1.5.2` / `74896fb` candidate review is historical. Future DMS
updates must compare a complete official release against the GREYWARD
acceptance matrix before changing the current `v1.5.3` pin.

Authoritative sources:

- [DMS releases](https://github.com/AvengeMedia/DankMaterialShell/releases)
- [DMS changelog](https://github.com/AvengeMedia/DankMaterialShell/blob/master/CHANGELOG.MD)
- [DMS source](https://github.com/AvengeMedia/DankMaterialShell)
- [DankMaterialShell installation documentation](https://github.com/AvengeMedia/DankLinux-Docs/blob/master/docs/dankmaterialshell/installation.mdx)

## Required release record

```text
AUDITED VERSIONS:
SELECTED VERSION:
SELECTED TAG:
SELECTED FULL COMMIT:
SOURCE ARCHIVE:
SOURCE CHECKSUM:
LICENSE:
RELEASE DATE:
SELECTION REASON:
KNOWN REGRESSIONS:
KNOWN FIXES:
REJECTED VERSIONS AND REASONS:
AUDIT DATE:
```

The selected commit must be recorded as a complete Git SHA. Verify the source archive checksum independently before packaging. Do not track `master`, `*-git`, mutable COPR state, or an auto-updater.

## Internal-alpha dependency traceability

The canonical input policy is `environment/production/artifact-policy.json`.
Production provisioning records installed package NEVRAs and source
repositories, exact Flatpak refs/commits, a license inventory, and a bounded
GREYWARD component inventory under `/var/lib/greyward/build-artifacts/`. An
optional `GREYWARD_COPR_BUILD_RECORD` supplies exact COPR build identifiers; if
it is not supplied, the artifact says `BUILD_ID=UNRESOLVED` and the build
remains unsuitable for a public release claim. The source image stager emits
the same artifact shape with explicit unresolved markers because it cannot
inspect the future installed image. This is traceability scaffolding, not a
release service or a complete public SBOM.

## Required audit topics

Review Labwc handling, bar and popup input masks, desktop context menus, Settings state, Network, Bluetooth, notifications/history, lock, DPMS, wallpaper, popout/modal lifecycle, blur fallback, redamage/performance, plugin execution, updater behavior, config schema, IPC/D-Bus identifiers, and packaging dependencies.

## Rebase contract

Every upstream update requires a new candidate audit, complete SHA/checksum record, changelog and issue review, source-delta report, functional regression suite, direct VMConnect interaction suite, log review, rollback test, and explicit approval. An upstream update must never silently change GREYWARD runtime behavior.

## Objective 1 selection record

Audited stable tags:

| Version | Full commit | Source archive SHA-256 | Tag commit date | Decision |
|---|---|---|---|---|
| v1.5.2 | `74896fb87cb9e4bb866dbabcfd754e3e649ad0c7` | `2fa4fccb9e3fd259fb5e2c8d6e5fe329096f893ca6b8ac9766c699061e0b347c` | 2026-07-18 | Candidate; rejected in favor of v1.5.3 |
| v1.5.3 | `069ddab041c738236a8910e4c39b65d9628d3018` | `2d665870f7019700fb38d59d043202e298e1aad1d3f1cb96360a75acbd3be9ca` | 2026-07-27 | Selected audit pin |

Selected version: `v1.5.3` / `069ddab041c738236a8910e4c39b65d9628d3018`.

Selection reason: v1.5.3 is the newest stable tag observed in the official repository and adds targeted fixes for lock-surface rejection resilience, Bluetooth adapter availability/rfkill handling, notification animation clipping, audio behavior, popout input-state reset, and wallpaper optimization. These directly overlap GREYWARD’s risk areas. The source archive checksums above were calculated from the official GitHub tag archives.

Known conditions and rejected-version reason:

- v1.5.2 is rejected as the audit pin because v1.5.3 is newer and contains relevant lock, Bluetooth, notification, popout, audio, and wallpaper fixes. It remains a comparison baseline.
- v1.5.3 still requires direct Labwc interaction testing; its source has explicit Labwc detection, logout, and DPMS paths, but no dedicated Labwc workspace-control adapter comparable to Niri/Hyprland/Mango paths.
- v1.5.3’s Fedora spec requires `dgop`, recommends `danksearch`, and downloads `dms-distropkg-${ARCH}` from a mutable `releases/latest` URL during the package build. GREYWARD must not use that supply-chain behavior unchanged.
- DMS owns `org.freedesktop.Notifications` through its user service, so it cannot run alongside a second notification owner.

Authoritative release evidence: [official releases](https://github.com/AvengeMedia/DankMaterialShell/releases), [v1.5.3 release changes](https://newreleases.io/project/github/AvengeMedia/DankMaterialShell/release/v1.5.3), and the [official source repository](https://github.com/AvengeMedia/DankMaterialShell).

## Source compatibility findings

- DMS v1.5.3 detects Labwc from the Wayland socket owner and exposes `isLabwc`; the dedicated `LabwcService` currently provides logout. Generic toplevel management and wlroots protocols are available, but workspace switching/filtering and compositor-specific keybinds are not proven for Labwc by source alone.
- DMS uses Quickshell `0.3`-era APIs, including `Quickshell.Wayland`, background-effect, idle-notify/inhibitor, shortcuts inhibitor, toplevel management, system tray, PipeWire, Bluetooth, UPower, Polkit, and notification modules. GREYWARD’s installed Quickshell package exposes those module families, but exact DMS runtime compatibility remains unvalidated until the reversible test session.
- DMS provides a user `dms.service` with `Type=dbus`, `BusName=org.freedesktop.Notifications`, and `dms run --session`; this is the intended DMS daemon/notification owner and must be isolated from `greyward-shell.service`.
- DMS source contains 573 QML files and 477 Go files; 318 QML files reference Material/theme surfaces. This is an early fork-cost warning, not a GO decision.

## Objective 2 installation evidence — 2026-08-19

The baseline used the official immutable `v1.5.3` asset
`dms-full-amd64.tar.gz`, not a mutable `latest` download. Verified asset
SHA-256:

`ed543447b98568a092845164ea9cc20538ed8efa421214fba2969ab1b90a3f53`

The extracted payload reports `v1.5.3` and was installed under the VM user’s
isolated data directory. The selected source commit remains the complete SHA
`069ddab041c738236a8910e4c39b65d9628d3018`. The disposable test used a static
user unit with explicit environment and no automatic enablement. That test
unit was later replaced by the explicitly approved canonical
`greyward-dms.service` cutover described below.

The official sibling asset `dms-qml.tar.gz` has SHA-256
`db9d4955a8155d4c6f157027a7f3d61173546afe71eff439f74cf7b918b27f2b`.
The Inter Variable and Material Symbols Rounded binaries bundled by GREYWARD
are byte-identical to the font paths in that archive; exact paths, hashes, and
retained license files are recorded in
`security-center/THIRD_PARTY_NOTICES.md`.

## Objective 2B runtime review — 2026-08-19

The v1.5.3 source review was repeated against the bounded GREYWARD test
window. `backend_networkmanager_wifi.go` intentionally returns
`no WiFi device available` when NetworkManager exposes no wireless device;
the VM exposes Ethernet only. `BlurService.qml` and `dms doctor` treat
`ext-background-effect-v1` as compositor capability-dependent. The official
DMS repository documents Labwc support but does not promise every blur or
workspace-specific capability on every Labwc build. The official issue/release
review found no relevant v1.5.3 fix that would justify a downstream core patch
for these VM capability warnings.

The only correction made in Objective 2B was outside DMS: the disposable test
unit now classifies its expected SIGTERM exit (`143`) as successful. The DMS
payload, source pin, and QML/Go files were not modified.

## Canonical cutover decision — 2026-08-19

The product owner accepted DMS `v1.5.3` / full commit
`069ddab041c738236a8910e4c39b65d9628d3018` as the GREYWARD generic shell
foundation. The direct VMConnect interaction gate was explicitly waived for
this promotion. The source pin and verified archive checksum remain unchanged;
no mutable release, `*-git` dependency, self-update, or upstream source patch
is introduced by the cutover.

## Canonical cutover evidence — 2026-08-19

The pinned payload was installed under `/usr/local/share/greyward-dms/v1.5.3`
with commit `069ddab041c738236a8910e4c39b65d9628d3018` and archive checksum
`ed543447b98568a092845164ea9cc20538ed8efa421214fba2969ab1b90a3f53`.
After the corrective autostart deployment and reboot, `labwc` was running,
`greyward-dms.service` was active and enabled, and `greyward-shell.service`
was inactive and disabled. DMS owned the notification and ScreenSaver bus
names. That historical DMS-core audit made no PAM, greetd, authentication,
bootloader, or STENOS changes. The production image now adds the separately
packaged DMS Greeter through greetd while retaining Fedora PAM as the authority.
The VM was intentionally left under DMS; no rollback was performed
after the final verification.

## Objective 3 visual fork-cost spike — 2026-08-19

Inspection of the pinned v1.5.3 source found that the bar, launcher, Control
Center, Settings, and notification surfaces consume the shared
`qs.Common.Theme` singleton. The upstream release documents a custom JSON theme
loaded through `settings.json` / `customThemeFile`. GREYWARD tested this
supported extension point with `spikes/dms-v1.5.3/greyward-obsidian.json`.

The result modified zero upstream files, zero DMS QML files, and zero
functional/backend paths. It added only GREYWARD-owned theme metadata,
reversible settings, documentation, and the VM spike workflow. Real VM
captures in `output/greyward-runtime/dms-visual-spike/` show the shared palette
across all five representative surfaces. The test was exited cleanly and the
canonical DMS settings were restored.

```text
UPSTREAM FILES MODIFIED: 0
GREYWARD FILES ADDED: spike theme/settings/readme and reversible workflow
SURFACE-SPECIFIC PATCHES: 0
FUNCTIONAL LOGIC MODIFIED: 0
MATERIAL ASSUMPTIONS: supported Material 3 color schema only
REBASE RISK: LOW
FORK COST: LOW for the shared-theme route
```

The supported theme route is recommended for the next full-migration design
pass, with a condition that GREYWARD typography, spacing, iconography, bar
composition, and content hierarchy be specified before accepting a product
theme. `GO/NO-GO: GO WITH CONDITIONS`. No DMS source fork is justified by this
spike.
