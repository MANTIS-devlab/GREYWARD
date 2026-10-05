# DMS 1.6.2 migration implementation and acceptance

Status: **IMPLEMENTED candidate packaging and source integration; NOT PROMOTED.**
This is the active tracker for the user-approved migration of 4 October 2026.
It does not convert development-VM observations into release acceptance.

## Fixed decision

Use an unchanged upstream distribution backend with embedded vanilla diagnostics,
mostly upstream QML, GREYWARD defaults and first-party plugins, and a small audited
patchset assembled into a complete explicit shell override. Never track a complete
upstream shell fork, patch runtime extraction, or infer per-file overlays from `-c`.

The canonical input is [dms-release.json](../../environment/production/dms-release.json).
It binds DMS v1.6.2 / `2db7646fe3ab47fddfdb8723f2da07d61a0d47ac`,
DankCommon `26396ce432d6c71c3f5367438f96f4a8d667e160`, and dankgo
`v1.6.1-0.20260908011626-07e1ef7caaea` to both checked archives, ordered patch
digests/preimages, shell digest, build inputs, and the development compatibility tuple.
The backend API is 34; the release changelog's older API number is not authoritative.

Keep Labwc/UWSM, Security Context's `greyward.security.experience/v1` contract,
typed actions, freshness and route allowlists, Update Center/recovery authority,
branding and the exact GREYWARD desktop interactions. No new generic command API.
Do not enable Island, dynamic theming, community downloads, cloud calendars or new
default external requests. Keep explicit cleartext geolocation contained by the
closed-loopback HTTP proxy. Do not run `dms auth sync` or rewrite Fedora PAM/authselect.

The user's 4 October correction supersedes the original external-lock decision:
**the native DMS lock screen is canonical**. DMS owns idle locking, display power
and its logind sleep inhibitor; the separate swayidle unit and swaylock default
are retired. AC/battery settings lock at 600 seconds, blank at 900 seconds, and
blank after 300 seconds of inactivity while locked. Automatic suspend and startup
locking remain disabled; `lockBeforeSuspend=true`, `loginctlLockIntegration=true`
and `customPowerActionLock=""`. Keyboard callers use the fixed GREYWARD wrapper,
which requests native locking and confirms `lock.isLocked` before returning success.
The package-owned `/etc/pam.d/greyward-dms-lock` delegates authentication and account
checks to Fedora's existing `system-auth` stack. It does not rewrite authselect,
login, greeter PAM or enable authentication synchronization. An actual native password unlock was observed on .149. The 1.6.2-6 candidate
also restored a secure native surface automatically after a shell restart while
the logind session remained locked. Repeated authenticated cycles, failed-password
behaviour and suspend/resume remain acceptance gates; .149 is not rebooted.

## Package and runtime contract

[packaging/greyward-dms](../../packaging/greyward-dms/) consumes immutable local
source and vendored CLI archives. It builds offline with `distro_binary withshell`,
`GOPROXY=off`, `GOSUMDB=off`, `GOTOOLCHAIN=local` and vendor module resolution.
The Fedora toolchain NEVRAs are pinned in the manifest. A build with network
interfaces beyond loopback is refused. Upstream `sync-shell` generates the embedded
vanilla UI and `.dankrev`. Precreating its empty generated input removes an upstream
file-enumeration race; the unchanged generator computes the final key. `.dankrev`
remains a cache key, never authenticity evidence.
Upstream backend tests run without `withshell`, as their shell-embedding test requires.
The tagged distribution binary is built and its CLI checked separately.

The RPM owns `/usr/bin/dms`, the manifest-selected versioned runtime, the verifier and
`/etc/xdg/quickshell/dms-plugins`. The installed receipt also records binary and
first-party file hashes, exact build NEVRAs, Go version, and the shell file inventory.
The package carries upstream/common licenses, vendored module inventory and license
texts. Complete license/SBOM review remains a promotion gate.

The root-owned `/etc/greyward/dms-release` selects a paired runtime. The wrapper
verifies ownership, non-writable ancestors, inventories/digests and the runtime
tuple at startup and during health checks. IPC uses selection/ownership/tuple
verification to reach the running shell without rehashing its complete payload
on every interaction. Only `run` receives `-c`; other commands receive
`DMS_SHELL_DIR`. Caller shell overrides are refused. XDG data paths serve icons/apps,
not shell selection. `greyward-dms.service` is the one service owner; `dms.service`
is an alias for upstream managed restart. The GREYWARD wrapper also routes `restart`
to that owner.

DMS Greeter remains separately packaged at the candidate manifest's exact NEVRA.
Numeric version agreement alone is not compatibility evidence. The old 1.5.3
payload, wrappers and state backups remain recoverable during candidate testing.

## Customization and adoption ledger

The candidate has eleven patch files touching **twenty** upstream files. The original
target was eighteen. The SystemUpdateService hunk routes native update execution
to Update Center. The external-lock handoff patch was removed when the user
selected native DMS locking. A demonstrated restart regression requires a narrow
`Modules/Lock/Lock.qml` startup reconciliation: recreate the native lock surface
when async loading missed the initial logind locked-state signal. Without it the
compositor remains locked with a black display after shell replacement. The
readiness check rejects a locked hint without a secure native surface.
Counts and hashes are
measured by assembly rather than manually maintained expectations.

| Surface | Result / pending acceptance |
|---|---|
| Palette, typography, logo, wallpaper and bottom bar | Supported defaults retained; visual/scaling parity pending |
| Launcher target and blank-bar clicks | Narrow BasePill/launcher/BarCanvas patch; interaction gate pending |
| AppsDock | Native pins/model; labels/spacing retained; only grouped focused-minimize patch remains |
| RunningApps alternate sizing | Obsolete patch removed; canonical desktop uses AppsDock |
| Authentication surfaces | 720x420 Polkit geometry retained; long-text/scaling gate pending |
| Settings and displays | Desktop/local-wallpaper wording, Labwc curation and config-path guard retained |
| Closed popouts | Guarded 30-second Labwc reclamation retained; reference/memory cycling gate pending |
| Changelog | Source patch removed; asserted upstream `.changelog-1.6` marker adapter after backup |
| Icons/tray | Upstream theme/XDG/loose-icon handling retained; actual active Flatpak roots discovered safely; tray fallback retained |
| Notifications | Severity presentation and quiet replacement retained without replacing upstream DND policy |
| Four first-party plugins | Same typed/security, traffic, identity/opt-out and software contracts; system delivery/receipts, exact 1.6.2 declarations, root-scoped async security callbacks |
| Internal dgop | Runtime capability/data gate replaces executable check; legacy VM package retained for rollback |
| Updates | Native execution opens the existing typed Update Center route; DMS self-updater absent in distro binary |
| Screenshots | Upstream CLI/JSON available; automated evidence keeps grim; region/cancel/HiDPI/hardware acceptance pending |
| State/config | Back up config/state/cache separately; preserve established pins, malformed state and modified plugins |
| Search/clipboard/network/audio/Bluetooth/battery | Upstream fixes retained; privacy and truthful unavailable/failure states remain required |
| Plugin catalogs/lockfiles and diagnostic UX | First-party receipt pins implemented; EN/FR catalogs and broader diagnostic adoption deferred |

No security collector, notification router, recovery implementation or Update Center
workflow is redundant simply because upstream names a similar surface.

## Phases and gates

The [4 October development evidence](../history/migrations/2026-10-04-dms-1.6.2-candidate.md)
records package/session tests and the actual rollback rehearsal. It does not
replace outstanding promotion gates or establish graphical authentication success.

| Phase | Required work and exit gate |
|---|---|
| 0: recoverable baselines | Preserve dirty-tree inventory/hashes and branch; checkpoint when host identifiable; restrictive runtime/config/state/cache/unit/greeter backups; restore rehearsal; original and normalized 1.5.3 captures/performance |
| 1: vanilla 1.6.2 | Verify inputs; offline unchanged backend build/tests; RPM ownership/licenses/dependencies; isolated fresh-config session, single notification/Polkit owner; startup/IPC/portals/displays/shutdown/SELinux |
| 2: deterministic customization | Exact preimages/hunks/no fuzz; explicit paired routing; system plugins/user reconciliation; embedded-vs-override diagnostics; actual service restart; reversible selector/state |
| 3: desktop parity | Theme/bar/settings/launcher/AppsDock/Polkit/popouts; delete obsolete hunks; equal-resolution/scaling captures and direct interaction |
| 4: authoritative integration | Four plugins/reload/freshness/routes/USB/privacy/notifications; every lock entrypoint; repeated lock/unlock, failed locker, suspend/resume; Update Center only |
| 5: upstream benefits | Internal dgop, screenshot metadata, state migration, narrower icons, lazy geolocation, no duplicate delivery/discovery assumptions or new default requests |
| 6: regression/performance | Full matrices below on .149, then fresh installation and applicable hardware; no unresolved mandatory failure; demonstrated rollback |
| 7: promotion | Change tested production/image inputs and current docs together only after upstream-review contract and all applicable gates; retain previous artifacts through login/reboot/rollback |

Working-tree edits never reset or silently include unrelated changes. The migration
branch is `codex/dms-1.6-migration`. Generated trees/RPMs and private measurements
live under ignored `output/`/`cache/`, not canonical Git source.

## Acceptance matrix

| Area | Mandatory cases |
|---|---|
| Session | Fresh/repeated login, UWSM environment, compositor-first startup, IPC readiness, restart, logout, reboot |
| Lock | Keyboard/power/launcher/loginctl, repeated unlock/relock, idle/before-sleep/resume, wrong password, missing/failed locker, one surface |
| Taskbar | Widget order, centered/edge/blank clicks, shortcuts, launch, pins/reorder, minimize/grouping/overflow |
| Surfaces/displays | Settings/launcher/Overview/popouts/tray/wallpaper; Escape/focus; hotplug/removal/fullscreen; 100/125/150/200%, mixed scaling and readable no-blur fallback |
| Security/notifications | Fresh/stale/collector failure, typed USB/privacy readback, disconnect/subscription loss; DND/critical/quiet replacement/actions/default click/expiry/history/restart, no duplicate success |
| Network | Physical links, aggregate/reset/wrap, absent adapter, tunnel exclusion, local/public distinction, opt-out before startup and after restart |
| Updates/screenshots | Existing recovery-linked one-authorization transaction; no alternate executor; region/screen/cancel/file/clipboard/JSON geometry/cursor/HiDPI/multi-output; touch/stylus where hardware exists |
| Failure/rollback | Backend/socket/config/state/dependency/plugin/tuple/hardware failures show UNKNOWN/UNAVAILABLE/DEGRADED, never success; restore old runtime/state/preferences/greeter/lock/notification owner/Security Center |

Run both repository gates, `python3 -m unittest discover -s tests -p 'test_image*.py'`,
and `test_dms*.py`, plus Fedora runtime/package gates. Run installed-package
ownership fixtures with sudo on Fedora; Windows skips those fixtures. If Security Center
implementation changes, run its README's Rust fmt/test/clippy, frontend contract,
Python/D-Bus and real-window suites. This migration does not replace those services.

Compare original 1.5.3, normalized 1.5.3, vanilla 1.6.2 and customized 1.6.2 with
identical resources, renderer, resolution, package tuple and security workload:
10 starts, 30 first-open/revisit samples per applicable panel, 10 restarts, 10-minute
idle and repeated closed-panel cycles. Report median/p95/spread and warm/fresh scope.
Use cgroup-v2 CPU accounting, including helpers that exit between samples;
refuse inactive services or process restarts during an idle run. RSS sums live
service processes and therefore includes shared pages in each process.
Opening/startup/restart p95 may grow by at most max(10%, 50ms); idle CPU by 0.5 points
of one core; combined steady memory by 10%. Continuing memory/reference growth or
budget failure blocks promotion. Repeat old/new/old on regression. CLI completion
latency is not rendered-frame latency; source improvements are not measured savings.

Review root ownership, socket 0600/session routing, first-party user authority,
fixed Polkit actions, SELinux AVCs without broad grants, private backups/diagnostics,
and single update/lock/notification/Polkit owners. Physical hardware and human visual
interaction may be handed off explicitly; missing evidence stays unvalidated.
