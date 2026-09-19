# GREYWARD DMS Migration Plan

> Historical migration and runtime audit record. It is not a current
> architecture or execution guide; use `docs/architecture/` and `docs/STATUS.md`.

Status: historical migration/audit record. The canonical DMS cutover is complete;
the former standalone GREYWARD Settings application described in older evidence is
removed. Current production surfaces are DMS Settings for general settings and
GREYWARD Security Center for GREYWARD security/privacy workflows.

## Scope and invariants

GREYWARD remains the user-facing product. Labwc remains the canonical compositor unless a genuine blocker is demonstrated. The retained GREYWARD shell and `greyward-shell.service` are rollback-era code; custom standalone Settings work is removed. Authentication, PAM, greetd, boot, disk unlock, and greeter remain separate concerns. Security Center is the production GREYWARD-specific security/privacy surface.

The purpose of DMS is reuse of generic desktop functionality, not adoption of Dank branding or an uncontrolled second shell. Product decision: DMS v1.5.3 is accepted as the canonical generic desktop-shell foundation for GREYWARD. The prior direct VMConnect interaction requirement was explicitly waived by the product owner and no longer blocks this cutover.

## Phase 0: hard VM and state gate

The canonical endpoint is:

```text
stendev@<historical-private-address>:22
identity: $env:USERPROFILE\.ssh\greyward-dev_ed25519
```

No runtime migration, DMS installation, or DMS test session may begin until direct SSH access succeeds and the guest is verified as the expected GREYWARD VM. Historical private endpoints are redacted; do not infer runtime state from old handoff metadata.

The first read-only verification must record hostname, Fedora release, kernel, Labwc version, Quickshell version/build, GREYWARD marker/state, active compositor/session, systemd user services, shell processes, and current owners for notifications, Polkit, lock/idle, wallpaper, display, network, Bluetooth, audio, and power.

Before starting DMS, record the existing GREYWARD baseline under equivalent conditions: Labwc CPU/RSS, Quickshell CPU/RSS, total shell RSS, idle system CPU, persistent shell processes, startup time where measurable, and relevant journal warnings/errors. Compare `CURRENT GREYWARD`, `DMS UNSTYLED BASELINE`, and `DMS + GREYWARD THEME` using relative rather than absolute Hyper-V thresholds.

## DMS selection gate

`v1.5.2` / commit `74896fb` is an audit candidate only. Before Phase 1, inspect the current official stable releases, the newest stable release, full commits, source checksums, changelog, and relevant open/closed issues. Compare at minimum v1.5.2 with the newest stable release for Labwc, input masks, context menus, Settings, Network, Bluetooth, notifications, lock, DPMS, wallpaper, popouts/modals, blur, performance, and redamage.

Select the safest stable release for GREYWARD. Record the result in `DANK_UPSTREAM.md` with the complete SHA and verified source checksum. Never use an abbreviated commit as the reproducibility pin.

## Source and compatibility audit

Audit selected DMS source, Quickshell requirements/features, Labwc adapters, DMS core services, optional modules, plugins, config/state paths, IPC/D-Bus identifiers, and packaging. Produce compatibility, capability, regression, process-ownership, privacy/network, plugin, updater, config-migration, branding, and supply-chain matrices.

Keep functional logic upstream wherever possible. GREYWARD owns branding, visual tokens, privacy defaults, recovery, security policy, and product-specific extensions. Preserve DMS internal identifiers and config paths initially; change them only with an explicit migration cost and compatibility plan.

## Parallel DMS test environment

`greyward-shell.service` remains available and unchanged as the known-good rollback path. Do not solve conflicts by deleting or permanently disabling GREYWARD components. If simultaneous ownership is unsafe, define an explicit test-session/service switch with exact commands for:

```text
LEGACY GREYWARD -> DMS TEST
DMS TEST -> LEGACY GREYWARD
```

The switch must document service/session configuration, process order, environment, active notification and Polkit owners, verification, failure recovery, and restoration. DMS test mode must not become canonical or modify legacy defaults.

## Interaction and logging acceptance

Every capability is classified as `AUTOMATED VALIDATION`, `DIRECT VMCONNECT VALIDATION`, or `PHYSICAL HARDWARE VALIDATION`. `IMPLEMENTED` is not `VALIDATED`.

No PASS is recorded for desktop right-click, taskbar, tray menus, launcher, Control Center, window interaction, display confirmation, lock/unlock, or context-menu dismissal without direct pointer/keyboard exercise in VMConnect or on physical hardware.

During every runtime phase inspect `journalctl --user`, DMS, Quickshell, Labwc, NetworkManager, PipeWire, BlueZ, Polkit, and logind logs. Track new and repeated warnings/errors. Record implementation mistakes as:

```text
SELF-DETECTED ISSUE:
ROOT CAUSE:
CORRECTION:
VALIDATION:
```

## Functional audit

Test panel/taskbar, workspaces, windows, launcher/search, Control Center, network, Bluetooth, audio, displays, notifications/history/DND/actions, tray, wallpaper, OSD, clipboard, screenshots, power, lock, idle, suspend, DPMS, Settings persistence, Labwc context input, crash/restart/reboot recovery, and repeated lifecycle use. Repeat launcher, Control Center, Settings, notifications, wallpaper, and lock interactions. Measure CPU/RSS/redamage in all three comparison states.

## Isolated fork-cost spike

The visual spike is exploratory and must remain in an isolated branch/worktree or equivalent disposable boundary until GO. It covers representative bar, Control Center, launcher, Settings, and notification surfaces.

Record:

```text
UPSTREAM FILES MODIFIED:
GREYWARD FILES ADDED:
GO FILES MODIFIED:
QML FILES MODIFIED:
COMMON/THEME FILES MODIFIED:
CORE LOGIC MODIFIED:
SURFACE-SPECIFIC PATCHES:
HARDCODED MATERIAL ASSUMPTIONS:
ESTIMATED REBASE CONFLICT SURFACE:
```

Identify every patch that modifies functional upstream logic. Screenshots alone cannot justify GO.

## GO / NO-GO

GO requires a verified full-SHA/checksum pin, reachable and verified VM, successful Labwc/Quickshell audit, reversible test switching, singular ownership, preserved display safety, classified network activity, acceptable privacy/plugin/updater/search/calendar/Polkit/lock policy, limited functional fork delta, direct interaction validation, clean recurring logs, and tested rollback.

NO-GO includes an unreachable/unverified VM, irreversible shell switching, large functional/core fork delta, duplicate owners, weaker display safety, unexplained network activity, uncontrolled indexing/plugins, self-updating or unpinned DMS, unvalidated pointer/display/lock behavior, or recurring hidden runtime errors.

## Required future phases

1. Freeze verified baseline and performance.
2. Select and pin the safest audited DMS release.
3. Audit source, compatibility, ownership, privacy, and packaging.
4. Establish reversible parallel DMS test mode.
5. Perform deep functional and interaction audit.
6. Run isolated fork-cost spike.
7. Make GO/NO-GO decision.
8. Only after GO, build GREYWARD visual adaptation incrementally.
9. Complete reboot, crash, lock, privacy, security, physical-hardware, and rollback acceptance.
10. Cut over canonically only after all gates pass; defer legacy cleanup.

## Objective 1 evidence — 2026-08-19

### Phase 0 result

`PASS`: the canonical VM was reachable through the managed alias with the host-owned identity and was verified as GREYWARD-DEV. The historical private endpoint is intentionally redacted.

Runtime evidence collected over read-only SSH:

- hostname: `fedora.local`;
- Fedora: `44`;
- kernel: `7.1.8-200.fc44.x86_64`;
- Labwc: Fedora package `0.9.6-1.fc44`, Fedora Project build;
- Quickshell: Fedora COPR `errornointernet/quickshell`, `0.3.0-3.fc44`, revision unavailable in the binary;
- UWSM: `0.24.3-1.fc44` from COPR `sdegler/uwsm`;
- historical GREYWARD marker: `/etc/greyward-h0-complete` contained `GREYWARD H0 PROVISIONING COMPLETE`;
- active shell: `greyward-shell.service` → `/usr/bin/qs -c greyward`;
- active compositor: `labwc`;
- settings process: historical `/usr/bin/greyward-settings` (removed; current production settings are provided by DMS);
- DMS, `dgop`, `dsearch`, and `dcal`: not installed;
- current screenshot: `output/greyward-runtime/baseline-current.png` (historical read-only capture; representative state contains the removed GREYWARD Settings prototype, Kitty, Labwc desktop menu, and panel).

Current user services include `greyward-shell.service`, `wayland-wm@labwc.service`, PipeWire/WirePlumber, portals, D-Bus, and GVFS. No separate notification daemon or `hyprpolkitagent` process was observed. The historical Settings application owned the `systems.mantis.greyward.settings` D-Bus name; that application is removed. NetworkManager, BlueZ, PipeWire/WirePlumber, UPower, Polkit, and `sshd` are active system services.

The graphical session was not pointer-tested through VMConnect in this objective. Therefore desktop right-click, taskbar, tray, launcher, Settings controls, display confirmation, and lock/unlock remain `DIRECT VMCONNECT VALIDATION: PENDING`, even though a screenshot proves visible presence only.

### GREYWARD baseline

At capture time the VM had been up for about one hour. `labwc` used approximately `84,500 KiB RSS`, Quickshell approximately `337,840 KiB RSS`, and the removed GREYWARD Settings prototype approximately `296,288 KiB RSS`; all reported `0.0% CPU` in the instantaneous sample. The idle load average was `0.00, 0.00, 0.00`. `greyward-shell.service` had `MainPID=921`, `NRestarts=0`, and started at `2026-08-19 01:43:11 CEST`.

Startup warnings recorded before any DMS activity:

- UWSM Labwc plugin could not create `55_reload.conf` because the drop-in directory was absent;
- WirePlumber reported that the BlueZ system service was unavailable;
- Quickshell reported Mesa/Zink device discovery failures in the VM and a portal app-ID registration warning.

These are baseline conditions and must be compared against DMS logs rather than silently attributed to DMS.

### Phase 1 result

`PASS WITH CONDITIONS`: source, packaging, process, module, privacy, and compatibility evidence is sufficient to design a reversible parallel test. It is not evidence that DMS functionality is accepted. Phase 2 must remain blocked until the explicit service/session switch and direct VMConnect validation exist.

## Objective 2 evidence — 2026-08-19 — reversible DMS baseline

### INSTALL

The selected release was installed from the immutable official `v1.5.3`
`dms-full-amd64.tar.gz` asset. Verified archive SHA-256:

`ed543447b98568a092845164ea9cc20538ed8efa421214fba2969ab1b90a3f53`

The source pin is the complete SHA
`069ddab041c738236a8910e4c39b65d9628d3018`. The payload is isolated at
`~/.local/share/greyward-dms-test/v1.5.3`; no system DMS package, mutable
`latest` asset, `*-git` package, updater, DankGreeter, PAM, or authentication
change was used. `dgop`, `dsearch`, `dcal`, matugen, Dank16, and plugins remain
absent/disabled.

### DMS TEST MODE / SAFE SWITCH

The historical VM helper referenced here was later removed; no current
`tools/greyward-dev/dms-test-guest.sh` exists. The replacement development
switch is `~/.local/bin/greyward-dms-test-switch`. It creates only the static manual
user unit `greyward-dms-test.service` and never enables it.

```text
~/.local/bin/greyward-dms-test-switch install
~/.local/bin/greyward-dms-test-switch enter
~/.local/bin/greyward-dms-test-switch exit
~/.local/bin/greyward-dms-test-switch status
```

`enter` stops `greyward-shell.service`, verifies it is inactive, and starts
DMS. On failed startup it restores the legacy service. `exit` stops DMS,
verifies it is stopped, and starts GREYWARD. The legacy unit was not edited,
disabled, masked, or replaced.

### LABWC / CORE SURFACES

DMS v1.5.3 started under Labwc `0.9.6` with Quickshell `0.3.0-3.fc44` and
reported Labwc detection from the Wayland socket. Gamma, WlrOutput management,
clipboard, wallpaper, NetworkManager, logind, Polkit, and tray recovery paths
initialized. Automated IPC checks succeeded for launcher, Control Center,
Settings, notification modal, wallpaper query, lock status, and power menu.
The captured baseline is `output/greyward-runtime/dms-test-baseline.png`.

Pointer behavior for bar, launcher, tray, Control Center, Settings, context
menus, lock/unlock, and display confirmation remains
`DIRECT VMCONNECT VALIDATION: PENDING`; visible presence is not acceptance.

### PROCESS OWNERSHIP

During test mode there was one shell owner: DMS and its child Quickshell. DMS
Quickshell owned `org.freedesktop.Notifications`; DMS also claimed the
ScreenSaver names and initialized Polkit. The historical GREYWARD Settings
application remained separate and was not changed in that test. After rollback, DMS owners
disappeared and the legacy shell returned. No dgop/dsearch/dcal/plugin helper
ran.

### LOG REVIEW / SELF-DETECTED ISSUES

The first wrapper omitted the isolated DMS `bin` directory from `PATH` and did
not create DMS state directories. This caused artificial `dms blur`, `dms
auth`, and config-watch warnings.

```text
SELF-DETECTED ISSUE: isolated wrapper PATH/state setup was incomplete.
ROOT CAUSE: wrapper exported only XDG_CONFIG_HOME and not the DMS bin path.
CORRECTION: add ROOT/bin to PATH and create isolated config/state/cache dirs.
VALIDATION: second DMS start no longer emitted those artificial warnings.
```

Real recurring conditions remained: no VM Wi-Fi device, BlueZ activation
failure, missing optional dgop, absent power-profiles daemon, no CUPS daemon,
unsupported Labwc background effect, no evdev permission, dummy PipeWire
audio, portal app-ID collision, and Mesa/Zink warnings. Some overlap the
accepted GREYWARD baseline, but the DMS session still emitted recurring
warnings/errors and therefore does not meet the clean-log gate.

### PERFORMANCE

Existing baseline: Labwc approximately `84,500 KiB RSS`, Quickshell
`337,840 KiB RSS`, Settings `296,288 KiB RSS`, instantaneous CPU `0.0%`.
DMS test sample: Labwc `105,432 KiB RSS`, DMS CLI `35,040 KiB RSS`, DMS
Quickshell `663,872 KiB RSS` and `10.4% CPU`; the corrected short restart
reached `471,976 KiB RSS` and `43.1% CPU` during startup. These are comparative
Hyper-V observations, not absolute thresholds; the elevated DMS sample needs
a longer controlled idle retest.

### LEGACY ROLLBACK / REBOOT

`DMS TEST → LEGACY GREYWARD` succeeded: the legacy unit returned active with
`/usr/bin/qs -c greyward`, and no DMS process remained. A full reboot then
returned automatically to the enabled/active legacy service. The DMS unit was
static/inactive after reboot; no repair or VM recreation was required.

### FINAL REPORT

```text
INSTALL: PASS — pinned v1.5.3 archive and verified checksum.
DMS TEST MODE: PASS — deterministic manual switch; legacy unchanged.
LABWC: PASS WITH CONDITIONS — ran under Labwc 0.9.6.
CORE SURFACES: AUTOMATED PARTIAL PASS; DIRECT VMCONNECT PENDING.
PROCESS OWNERSHIP: PASS during test; restored to legacy.
LEGACY ROLLBACK: PASS.
REBOOT: PASS.
LOG REVIEW: FAIL — recurring environment/DMS warnings remain.
PERFORMANCE: RECORDED; elevated DMS Quickshell sample needs retest.
SELF-DETECTED ISSUES: wrapper PATH/state issue corrected and revalidated.
BLOCKERS: recurring runtime warnings/errors and missing direct VMConnect evidence.
PHASE 2: FAIL — runnable baseline, acceptance gate not met.
PHASE 3 RECOMMENDATION: STOP until blockers are resolved and interaction is validated.
```

No visual customization, canonical cutover, fork-cost spike, or Phase 3 work
was started.

## Objective 2B evidence — 2026-08-19 — runtime blocker resolution

### CLEAN TEST BOUNDARY

The clean boundary began at `2026-08-19T19:15:56+02:00` with
`greyward-shell.service` active and the DMS test unit inactive. DMS TEST was
entered through the existing switch and ran for approximately 48 seconds
before the legacy shell was restored. The VM ended with GREYWARD active,
DMS inactive, and no DMS process or D-Bus owner.

### RUNTIME ISSUES FOUND

| Issue | Exact message | Frequency in bounded window | Classification / effect |
|---|---|---:|---|
| Wi-Fi absent | `Failed to get initial networks: no WiFi device available`; `DMS API Error ... no WiFi device available`; `WiFi scan failed: no WiFi device available` | once each at startup | VM environment: `nmcli` exposes only connected Ethernet and no Wi-Fi device. Network Wi-Fi UI has no device; no DMS crash. v1.5.3 source explicitly returns this error when `wifiDevice == nil`. |
| Bluetooth absent | `Failed to initialize bluez manager: no bluetooth adapter found: Could not activate remote peer 'org.bluez'` | once per startup path | VM environment: BlueZ is installed/enabled but systemd skips it because `/sys/class/bluetooth` does not exist. No adapter is present. |
| Power profiles absent | `Could not launch service org.freedesktop.UPower.PowerProfiles`; `The PowerProfiles service will not work.` | once each | Optional dependency: `power-profiles-daemon` is not installed; DMS doctor labels it optional. No power-profile surface can be validated in this VM. |
| Input access absent | `Failed to initialize evdev manager: insufficient permissions to access input devices` | once | VM permission boundary: `/dev/input/event*` is `root:input 0660`; `stendev` is not in `input`. It affects Caps Lock state/OSD, not pointer input. Adding the broad `input` group was not performed. |
| Blur capability absent | `Cannot enable background effect as ext-background-effect-v1 is not supported by the current compositor.` | startup/surface capability warning | Labwc capability gap. v1.5.3 doctor and `BlurService.qml` explicitly treat `ext-background-effect-v1` as optional compositor support and provide a non-blur path. No DMS core patch was made. |
| Graphics/portal/audio | Mesa/Zink device discovery, portal app-ID collision, and PipeWire dummy-output warnings | once at startup | Existing Hyper-V/GREYWARD environment conditions; no new Labwc crash or shell restart. |
| Compositor adapters | unset `I3SOCK`/`SWAYSOCK` and `HYPRLAND_INSTANCE_SIGNATURE` | once at startup | Expected v1.5.3 generic adapter probes while running Labwc; not a shell failure. |
| Optional monitoring | `dgop is not installed or not in PATH` | once | Intentional policy: dgop is not enabled or installed for this baseline. |

No issue above repeated periodically during the 48-second bounded window after
startup. The earlier artificial `dms blur`, `dms auth`, config-watch, and
unit-failed messages were corrected: the wrapper now exports the isolated
`bin` directory, creates isolated state directories, and marks normal SIGTERM
stop (`143`) successful.

### ROOT CAUSES / UPSTREAM CHECK

The selected v1.5.3 source confirms the Wi-Fi behavior in
`core/internal/server/network/backend_networkmanager_wifi.go`: scanning
returns `no WiFi device available` when NetworkManager reports no wireless
device. The source and official DMS documentation describe Labwc as supported
but treat blur and several integrations as capability-dependent. The official
release/issues review also shows unsupported blur and missing optional
power-profile services as documented doctor warnings, not required baseline
dependencies. No evidence justified patching DMS core or installing optional
network-connected modules. The upstream Labwc workspace/control limitations
remain an audit condition, not a Phase-2 integration fix.

### CORRECTIONS

```text
ISSUE: normal test-service stop was recorded as failed (status 143).
ROOT CAUSE: systemd did not classify the expected SIGTERM exit as successful.
CORRECTION: add SuccessExitStatus=143 SIGTERM to greyward-dms-test.service.
VALIDATION: after the corrected run, DMS test was inactive (not failed), and
greyward-shell.service was active.
```

### DMS CORE SURFACES

Automated validation after the correction:

- DMS starts and its Quickshell child runs under Labwc;
- the bar is visible in `output/greyward-runtime/dms-2b-final.png`;
- launcher, Control Center, Settings, notification modal, lock status, and
  power menu IPC calls succeeded;
- tray IPC is present and correctly reports no tray items in the VM;
- wallpaper IPC is present, but no DMS-selected wallpaper is configured;
- DMS owns `org.freedesktop.Notifications` only during test mode;
- rollback returns ownership to GREYWARD and leaves no DMS process.

### DIRECT VM VALIDATION

`AUTOMATED VALIDATION`: completed as above.

`DIRECT VMCONNECT VALIDATION`: not performed by Codex. The screenshot proves
visible rendering only; it does not prove pointer behavior, popup dismissal,
click-through, or keyboard interaction.

`PHYSICAL HARDWARE VALIDATION`: not performed.

### MANUAL VMCONNECT ITEMS

The remaining minimal checklist is intentionally limited to items Codex could
not honestly mark PASS:

1. In VMConnect, verify the DMS bar accepts pointer input and does not leave
   an invisible click-blocking layer.
2. Click launcher, Control Center, Settings, and the tray area; verify each
   opens, accepts input, and dismisses cleanly.
3. Send a desktop notification and verify popup display and dismissal.
4. Verify the Labwc desktop/application remains usable behind and after each
   popup.

### FINAL REPORT

```text
RUNTIME ISSUES FOUND: startup-only Wi-Fi, BlueZ, power-profile, evdev, blur,
graphics/portal/audio, compositor-probe, and intentional dgop warnings.
ROOT CAUSES: VM hardware/capability state, optional dependencies, and Labwc
capability differences; one GREYWARD test-unit stop-status defect.
UPSTREAM ISSUES: no confirmed v1.5.3 core defect causing periodic failure;
Labwc blur/workspace capability remains a compatibility condition.
CORRECTIONS: isolated wrapper PATH/state correction previously applied;
SuccessExitStatus=143 SIGTERM added and validated.
DMS CORE SURFACES: automated partial PASS; bar rendered, IPC surfaces work.
DIRECT VM VALIDATION: NOT VALIDATED.
MANUAL VMCONNECT ITEMS: four-item checklist above remains.
PROCESS OWNERSHIP: singular during DMS test; restored to GREYWARD afterward.
ROLLBACK: PASS; service active, DMS inactive, no process or D-Bus owner.
LOG REVIEW: startup warnings are now classified and non-recurring in the
bounded window; capability limitations remain.
PHASE 2: FAIL — direct VMConnect acceptance is still missing.
PHASE 3: STOP.
```

Objective 2B stops here. No visual customization, canonical cutover, or
fork-cost work was started.

## Canonical cutover — 2026-08-19

The product owner accepted DMS v1.5.3 as the canonical GREYWARD generic shell
and explicitly waived the remaining direct VMConnect interaction gate. This
waiver changes the acceptance decision only; privacy, pinning, rollback, Labwc,
authentication, and ownership constraints remain unchanged.

Canonical runtime contract:

- `greyward-dms.service` is the normal user shell under Labwc/UWSM;
- `greyward-shell.service` remains installed and unchanged as rollback, but is
  not globally enabled;
- the two services have an explicit conflict relationship and must not run
  together;
- rollback disables the DMS unit, enables the legacy unit, stops DMS, then
  starts `greyward-shell.service`;
- DMS uses only the pinned v1.5.3 payload and does not self-update;
- dgop, dsearch, dcal, Dank16, matugen, plugins, calendar/cloud integrations,
  and updater functionality remain disabled.

The visual/fork-cost spike is the next milestone and is not started here.

### Cutover verification

The first reboot exposed a stale VM-side Labwc autostart that relaunched the
legacy service; this was a self-detected integration issue, not a DMS source
change. The autostart was replaced with the canonical DMS start command, the
legacy service was stopped, and a corrective reboot was completed.

```text
SELF-DETECTED ISSUE: stale VM autostart started greyward-shell.service after reboot.
ROOT CAUSE: the VM’s deployed ~/.config/labwc/autostart predated the canonical cutover.
CORRECTION: install the repository autostart, stop legacy, start greyward-dms.service.
VALIDATION: after corrective reboot, Labwc=running, DMS=active/enabled,
legacy=inactive/disabled, DMS commit=069ddab041c738236a8910e4c39b65d9628d3018.
```

The VM remains under DMS. No automatic rollback was performed after the final
verification. The legacy unit remains installed as a manual rollback path.

## Objective 3 — isolated visual fork-cost spike — 2026-08-19

The v1.5.3 source architecture was inspected from the verified release asset.
The five representative surfaces consume the shared `qs.Common.Theme`
singleton and its Material 3 token properties. DMS also documents a supported
custom JSON theme through `settings.json` and `customThemeFile`.

The spike therefore used only that supported mechanism. The disposable theme
is `spikes/dms-v1.5.3/greyward-obsidian.json`; the VM workflow is
`tools/greyward-dev/dms-visual-spike.ps1`. Entry backs up the user settings,
applies the theme, and restarts only `greyward-dms.service`; exit restores the
settings and removes the disposable state. The canonical service, DMS payload,
legacy shell, DMS source, plugins, updater, and backend ownership were not
modified.

Representative VM captures are stored in
`output/greyward-runtime/dms-visual-spike/`:

- `launcher.png`
- `control-center.png`
- `settings.png`
- `notification.png`
- `../dms-visual-spike-obsidian.png` for the bar/background state

The captures show the GREYWARD obsidian/graphite base, silver hierarchy,
restrained contrast, and consistent shared surfaces. No surface-specific QML
patch was needed. Settings were restored afterward; the VM remains on the
canonical DMS theme state with DMS active and the legacy service inactive.

### Objective 3 cost report

```text
UPSTREAM FILES MODIFIED: 0
GREYWARD FILES ADDED: 4 spike artifacts plus reversible VM workflow
SHARED THEME/COMPONENT MODIFICATIONS: 1 supported custom theme JSON
SURFACE-SPECIFIC PATCHES: 0
FUNCTIONAL/BACKEND MODIFICATIONS: 0
HARDCODED MATERIAL ASSUMPTIONS: DMS exposes a Material 3 JSON schema and
shared Theme token names; the spike consumes that contract without patching it.
ESTIMATED REBASE CONFLICT SURFACE: none for the spike artifacts
```

The first spike-script run exposed a PowerShell quoting defect before the VM
theme was applied. It was corrected by removing local `$()` interpolation and
using a remote `systemctl | grep` check; the corrected enter/capture/exit
workflow passed. This is recorded as a tooling issue, not a DMS runtime issue.

The supported theme route is a low-maintenance candidate for full migration.
It is not yet a complete GREYWARD product theme: typography, spacing, icon
language, bar layout, wallpaper, and Settings-specific content still require a
separate approved design pass. No full migration was started automatically.

`GO/NO-GO: GO WITH CONDITIONS` — proceed to a deliberate full visual design
pass using the supported shared theme route, while keeping the spike artifacts
disposable until typography, spacing, iconography, and content hierarchy are
approved.
DMS OBJECTIVE 4 EVIDENCE — 2026-08-19

The focused runtime audit found two obsolete GREYWARD-owned Labwc references:
the Root right-click binding to `root-menu`/`menu.xml`, and the `W-Space`
binding to `qs ipc -c greyward`. The legacy service itself was already
disabled/inactive and no legacy shell process or duplicate notification,
Polkit, or ScreenSaver owner was present.

The repository now removes the Root menu binding and menu deployment, and maps
`W-Space` to DMS `spotlight toggle`. DMS v1.5.3 source inspection showed that
its default bar uses `focusedWindow`; the supported `RunningApps` widget uses
the native `ToplevelManager`/`CompositorService` model and calls each toplevel’s
`activate()` method. A complete DMS bar settings record was added with
`runningApps` enabled; no DMS QML or backend was changed.

The first minimal `barConfigs` experiment made the bar disappear because
required bar fields such as `enabled` were omitted. It was immediately restored
and replaced with a complete upstream-shaped record. This is a self-detected
configuration issue, not an upstream defect.

After deployment and reboot, Labwc was running, DMS was active/enabled, the
legacy service was inactive, `menu.xml` was absent, and the Root binding was
gone. Kitty and Firefox were both represented in the DMS bar after reboot.
Automated close/reopen validation passed: Kitty was closed and relaunched while
Firefox remained running. No critical user-journal entries were present.

```text
RIGHT-CLICK ROOT CAUSE: legacy Labwc Root binding and root-menu deployment.
RIGHT-CLICK RESULT: removed from repository deployment and VM runtime.
TASKBAR ROOT CAUSE: DMS default focusedWindow widget, not legacy shell ownership.
TASKBAR RESULT: complete DMS RunningApps configuration; two apps represented.
UPSTREAM DMS CHANGES: 0
ROLLBACK-ONLY: greyward-shell.service and legacy Quickshell source/configuration.
REMOVED/DISABLED: root-menu binding/deployment and legacy launcher keybind.
REBOOT: PASS; DMS canonical, Labwc running, legacy inactive.
LOG REVIEW: no critical entries; known VM capability warnings remain classified.
MINIMIZE/RESTORE: DIRECT POINTER VALIDATION PENDING.
DMS CLEAN BASELINE: PASS WITH MANUAL INTERACTION CONDITION.
```

Final post-reboot evidence (2026-08-19):

- `greyward-dms.service`: active and enabled; `greyward-shell.service`: inactive.
- Labwc and DMS are the only shell processes; no legacy `qs -c greyward` process
  is running.
- Notification ownership is DMS Quickshell; ScreenSaver ownership is DMS. No
  duplicate owner was observed.
- `journalctl --user -b -p crit` contains no entries.
- Repeated non-critical VM capability warnings remain: software rendering/
  missing EDID, no Wi-Fi adapter, no Bluetooth adapter, missing `dgop`, and
  unavailable input-device access. These are environment limitations and were
  not silently classified as feature passes.
- Direct pointer validation remains pending. VMConnect exposes the guest child
  surface off-screen in the host session, so right-click and minimize/restore
  are not marked PASS from automation.

User-provided direct interaction evidence (2026-08-19): application minimize and
restore from the DMS taskbar are confirmed OK. The desktop right-click still
showed the former GREYWARD artifact, which identified a retained staged release
as the remaining residue. The exact old release files were removed from the VM,
Labwc was reconfigured, and the VM was rebooted. Post-reboot checks show only the
active `~/.config/labwc/rc.xml`, no `menu.xml`, no `Root` binding, DMS active and
enabled, legacy inactive, and no critical user-journal entries.

DMS v1.5.3 source inspection confirms that it has no desktop-wide background
context menu. Its default empty-desktop behavior is therefore no menu; context
menus remain available on DMS-owned surfaces such as launcher entries, running
applications, tray items, and popouts. The previous GREYWARD desktop menu is not
part of the canonical DMS behavior.

Follow-up direct reports identified a second layer: with no custom `menu.xml`,
Labwc's own default `Root` bindings displayed its built-in `Terminal / Reconfigure /
Exit` menu on the desktop. The active repository `rc.xml` now explicitly overrides
both the left- and right-button `Root` bindings with `None`, while retaining the
other Labwc default mouse bindings. The rules were installed on GREYWARD-DEV and
successfully reloaded with the running compositor PID; DMS remains active and the
legacy service remains inactive.

DMS VISUAL IDENTITY IMPLEMENTATION — 2026-08-19

The canonical DMS v1.5.3 shell now uses the supported native customization route:

```text
UPSTREAM FILES MODIFIED: 0
GREYWARD FILES ADDED/MODIFIED: native DMS settings, GREYWARD Obsidian theme,
  existing GREYWARD symbol SVG, and provisioning/deployment paths
QML PATCHES: 0
FUNCTIONAL/BACKEND LOGIC MODIFIED: 0
SURFACE-SPECIFIC PATCHES: 0
ESTIMATED REBASE CONFLICT SURFACE: low
```

The applied configuration provides a full-width bottom GREYWARD taskbar, numbered
workspaces, native running-app management, centered clock, status/tray controls,
custom GREYWARD launcher symbol, dark obsidian/graphite surfaces, restrained silver
accents, and shared native DMS theme tokens. Launcher, Control Center, Settings,
notification, and power/session surfaces were captured from the running VM. The
notification and power captures are stored at
`output/greyward-runtime/objective5-notification.png` and
`output/greyward-runtime/objective5-power.png`.

The first visual pass exposed a self-detected issue: the initial bar was too close
to the stock DMS density. `innerPadding`, spacing, widget padding, and icon scale
were increased using native settings; the resulting taskbar is visibly taller and
more deliberate without changing DMS QML or task-management logic.

The theme and logo now use stable per-user paths under
`~/.config/DankMaterialShell/`, and the Packer provisioning path installs those
assets for fresh GREYWARD images. The VM was updated with the targeted files and
DMS was restarted successfully. Labwc's left and right desktop Root bindings were
also reloaded with explicit `None` actions, removing the former
`Terminal / Reconfigure / Exit` artifact while leaving DMS-owned context menus
available on DMS surfaces.

Runtime evidence: `greyward-dms.service` and Labwc are active; no legacy
`qs -c greyward` process is running; no critical user-journal entries were found;
the only observed warnings are known Hyper-V capability limitations such as
software rendering, absent Wi-Fi/Bluetooth adapters, missing `dgop`, and portal/
input limitations. The installed wrapper does not expose `dms` as a bare PATH
command in the SSH shell, so diagnostics must use `/usr/local/bin/greyward-dms`.

SELF-DETECTED ISSUE:
Running `/usr/local/bin/greyward-dms doctor -v` from a non-graphical SSH shell
created a diagnostic Quickshell child without the active Wayland environment;
that child dumped core at 21:07 while the canonical `greyward-dms.service`
remained active and healthy.

ROOT CAUSE:
The remote SSH command lacked the session's `XDG_RUNTIME_DIR` and
`WAYLAND_DISPLAY`; this was a diagnostic invocation error, not a DMS service
restart or visual-theme failure.

CORRECTION:
Treat `doctor` as a session-scoped diagnostic and run it only with the active
graphical environment. Do not use the bare SSH shell as a GUI acceptance path.

VALIDATION:
After the event, `greyward-dms.service` remained active, DMS/Quickshell and
Labwc remained the sole shell processes, and subsequent service logs showed only
the known VM capability warnings. No repeated DMS crash loop was observed.

```text
VISUAL RESULT: PASS WITH CONDITIONS
LEGACY ROLLBACK: PRESERVED AND NOT STARTED AUTOMATICALLY
CANONICAL SHELL: DMS v1.5.3
PHASE 3: NOT STARTED
```

The remaining acceptance captures were completed and visually inspected:

- `output/greyward-runtime/objective5-launcher-search.png`
- `output/greyward-runtime/objective5-files.png`

The launcher capture shows a real Firefox search result with its selected state;
the Files capture shows the native file manager alongside the GREYWARD taskbar
and running-app indicator.

SESSION OBJECTIVE REVIEW

THIS SESSION WAS SUPPOSED TO:
- transform canonical DMS visually into GREYWARD;
- establish the GREYWARD DMS visual foundation;
- restore the GREYWARD launcher SVG;
- enlarge and redesign the taskbar;
- restore the intended GREYWARD shell/system icon direction;
- adapt launcher, Control Center, Settings, notifications and shared shell
  surfaces;
- preserve native DMS functionality and low fork cost.

RESULT: PASS WITH CONDITIONS

NOT COMPLETED FROM THIS SESSION:
- Direct physical-hardware validation is outside the VM objective.
- DMS blur remains unavailable under the current Labwc/Hyper-V capability set;
  the theme uses a dark opaque fallback.

VISUAL RESULT

TASKBAR: Native DMS full-width bottom bar, enlarged through supported spacing,
padding, icon scale, and border settings; numbered workspaces, running apps,
centered clock, tray, notification, network/audio, and power controls present.

LAUNCHER LOGO: Existing GREYWARD SVG restored through DMS custom logo settings.

ICONS: DMS system icons remain coherent and restrained; third-party application
icons are preserved rather than unnecessarily replaced.

LAUNCHER: Native DMS launcher and real Firefox search-result state captured.

CONTROL CENTER: Native DMS surface captured with dark shared theme.

SETTINGS: Native DMS Settings retained and captured; no second Settings app.

NOTIFICATIONS / MENUS: Native notification and power/session surfaces captured;
Labwc desktop artifact removed while DMS-owned menus remain available.

TYPOGRAPHY / MATERIAL: Dark obsidian hierarchy, restrained silver accents,
controlled transparency, fine borders, and opaque fallback where blur is absent.

IMPLEMENTATION DELTA

NATIVE DMS CUSTOMIZATION: Custom theme, launcher logo, bar composition,
workspace indices, spacing, padding, transparency, borders, and native widget
placement.

GREYWARD-THEME/ASSETS: `environment/session/dankmaterialshell/greyward-obsidian.json`,
`settings.json`, and the existing canonical GREYWARD SVG symbol.

SHARED QML MODIFICATIONS: None.

SURFACE-SPECIFIC QML MODIFICATIONS: None.

FUNCTIONAL/BACKEND MODIFICATIONS: None.

UPSTREAM FILES MODIFIED: 0.

QML PATCHES: 0.

REBASE RISK: LOW.

REMAINING WORK

SESSIONS REMAINING: 0 for this visual-identity objective. A later migration
objective may separately evaluate direct pointer interaction and physical
hardware behavior; it is not started here.

CURRENT OVERALL PROGRESS: Visual identity implementation complete with native
DMS customization, stable provisioning paths, real-state captures, and the VM
left under canonical DMS.

NEXT SESSION: Only begin the next explicitly approved migration objective.

## Taskbar geometry correction — 2026-08-19

SESSION OBJECTIVE REVIEW

THIS SESSION WAS SUPPOSED TO:
- add deliberate internal spacing between taskbar content and both physical
  screen edges;
- make the actual rendered GREYWARD launcher SVG substantially larger;
- preserve the accepted application/task area and the rest of the taskbar.

RESULT: PASS

LEFT EDGE INSET: Native DMS `barInsetPadding=20` creates a visible 20 px
internal gap between the full-width background edge and the launcher content.

RIGHT EDGE INSET: The same shared native inset creates a visible 20 px gap
between the power control and the right screen edge.

LAUNCHER CONTAINER SIZE: Unchanged native DMS bar geometry; the launcher
interaction pill remains inside the existing approximately 36 px bar content
height.

ACTUAL SVG RENDERED SIZE: Native DMS image box increased from approximately
25 px (`launcherLogoSizeOffset=10`) to approximately 40 px
(`launcherLogoSizeOffset=30`). The visible mark is correspondingly larger
while remaining optically centered and visually contained.

SVG SIZE BEFORE: Approximately 25 px rendered image box; the visible symbol
was a small supporting icon.

SVG SIZE AFTER: Approximately 40 px rendered image box; the visible symbol is
now a strong left-side anchor without clipping.

IMPLEMENTATION METHOD: Native DMS configuration only.

VISUAL CAPTURE: `output/greyward-runtime/taskbar-geometry-after.png`, captured
at the VM's native 2560x1440 resolution and visually inspected. Both outer
insets are visible, the launcher is substantially larger, and the application
area, clock, right controls, wallpaper, and taskbar height remain unchanged.

SELF-DETECTED ISSUES: The prior `barInsetPadding=0` left content edge-to-edge,
and `launcherLogoSizeOffset=10` was insufficient. Both were corrected in one
native iteration; no QML or functional logic changes were required.

REMAINING PLAN

SESSIONS REMAINING: 0 for the current GREYWARD DMS desktop milestone.

NEXT SESSION: Only begin the next explicitly approved migration objective.

## Targeted visual correction — 2026-08-19

SESSION OBJECTIVE REVIEW

THIS SESSION WAS SUPPOSED TO:
- fix launcher and right-side taskbar containment;
- enlarge the GREYWARD launcher SVG without enlarging the whole bar;
- preserve the accepted application-area scale;
- reduce right-side system-control weight;
- strengthen the central clock;
- restore the canonical pre-DMS wallpaper and add the existing GREYWARD SVG
  identity as static branding;
- remove the residual Labwc `Terminal / Reconfigure / Exit` desktop menu.

RESULT: PASS WITH CONDITIONS

VISUAL CORRECTIONS

TASKBAR CONTAINMENT: Native DMS geometry was adjusted with spacing 7,
widget padding 8, icon scale 1.0, and unchanged inner padding 16. The
full-width bar remains contained and the right controls are visibly more
compact in `output/greyward-runtime/visual-corrected.png`.

LAUNCHER SVG: The existing SVG remains the launcher source; native
`launcherLogoSizeOffset` is 10. No launcher QML or SVG redraw was introduced.

APPLICATION AREA: The running-app area remains native DMS and was not globally
resized.

RIGHT SYSTEM CONTROLS: Native global icon scale and widget padding reduce the
supporting controls while keeping their pointer surfaces usable.

CENTRAL CLOCK: Native font scale is 1.10, preserving the central clock’s
position and increasing its hierarchy relative to the system controls.

WALLPAPER RESTORED: The canonical `branding/wallpaper/greyward-wallpaper.svg`
was preserved unchanged as the source composition. DMS uses the generated
3840x2160 PNG at `~/.config/DankMaterialShell/greyward-wallpaper.png`.

WALLPAPER GREYWARD LOGO: The existing canonical `branding/source/greyward-symbol.svg`
was rendered into the static PNG at restrained opacity and lower-left placement.
The source SVG was not replaced or redrawn.

IMPLEMENTATION

NATIVE DMS CUSTOMIZATION USED: `settings.json` only for taskbar geometry and
font/icon hierarchy; DMS wallpaper IPC for explicit ownership.

GREYWARD ASSETS USED: Canonical wallpaper SVG, canonical GREYWARD symbol SVG,
and the generated DMS raster wallpaper.

QML MODIFICATIONS: None.

FUNCTIONAL LOGIC MODIFIED: None.

UPSTREAM FILES MODIFIED: 0.

VALIDATION

VISUAL REVIEW: Captured and inspected `output/greyward-runtime/visual-corrected.png`;
it shows DMS, multiple open applications, contained taskbar, compact right
controls, and the restored wallpaper with GREYWARD logo. The post-reload
`output/greyward-runtime/artifact-check.png` contains no residual Labwc menu.

PERSISTENCE: DMS session state records the explicit wallpaper path with cycling,
per-monitor, and per-mode wallpaper disabled. Deployment and fresh-session
provisioning now install the asset and reapply it after DMS becomes IPC-ready.

LOG REVIEW: `greyward-dms.service` and Labwc remained active after the restart;
no new repeated service errors were observed in the targeted review.

SELF-DETECTED ISSUES FIXED:

SELF-DETECTED ISSUE: The first generated PNG did not contain the logo because
the SVG renderer did not resolve the external `<image>` reference.

CORRECTION: Kept the canonical wallpaper SVG unchanged and composed the
existing canonical logo into the final raster using the VM’s SVG renderer and
ImageMagick.

VALIDATION: The regenerated PNG visibly contains the monochrome GREYWARD logo,
and the same asset is selected by DMS on the VM.

REMAINING PLAN

SESSIONS REMAINING: 0 for this targeted visual correction milestone.

CURRENT OVERALL PROGRESS: Corrected native DMS geometry, static GREYWARD
wallpaper ownership, and the Labwc desktop-menu residue without QML or
functional fork changes.

NEXT SESSION: Only begin the next explicitly approved migration objective.
