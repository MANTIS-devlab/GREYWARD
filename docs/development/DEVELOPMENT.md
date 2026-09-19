# GREYWARD development

The Windows repository is authoritative. The disposable `GREYWARD-DEV` runtime
must be recreated from the factory when needed; `STENOS-DEV` is out of scope and
protected by explicit name guards.

The future installed system is defined in `environment/production/`. The Hyper-V factory
stages that definition and then applies `environment/development/` for the disposable VM's
SSH, credentials, Hyper-V support, and development tools. Keep changes to the installed OS in
the production definition; use the overlay only for VM access and authoring support.

Production-surface rule: use DMS Settings for general desktop/system settings and
GREYWARD Security Center for GREYWARD security/privacy workflows. The removed standalone
GREYWARD Settings application has no supported build or deployment path.

The login path is greetd with DMS Greeter. Test login failure, lockout/rate limiting,
session selection, logout, and recovery through the guest console; do not add an
autologin shortcut or handle credentials in QML/Quickshell.

The development overlay intentionally grants the bootstrap developer account
passwordless administrative access through `/etc/sudoers.d/90-greyward-dev`
(and a host may add an equivalent maintenance rule). This is an access aid for
the disposable VM only; it is not an OS feature and must never enter the
production image. Production account creation and privilege policy are owned
by the normal installer and the installed wheel/polkit rules.

The VM and production definition should otherwise agree on the security
baseline: SELinux targeted policy stays `Enforcing`, and the GREYWARD Plymouth
theme remains selected. A VM may lack hardware-only evidence such as TPM,
Secure Boot, or fwupd HSI; those differences must be reported as environment
limitations rather than silently changed in the development overlay.

The complete production/development boundary is documented in
[`../architecture/PRODUCTION_VS_DEVELOPMENT.md`](../architecture/PRODUCTION_VS_DEVELOPMENT.md). A healthy
GREYWARD-DEV VM is evidence for development only; it is not proof that the final
ISO contains Security Center, production account policy, or release-complete
hardware support.

## Stable interface

```powershell
.\tools\greyward-dev\create.ps1          # zero-to-ready factory
.\tools\greyward-dev\start.ps1
.\tools\greyward-dev\stop.ps1
.\tools\greyward-dev\health.ps1
.\tools\greyward-dev\deploy.ps1
.\tools\greyward-dev\reload.ps1
.\tools\greyward-dev\capture.ps1
.\tools\greyward-dev\checkpoint.ps1
.\tools\greyward-dev\revert.ps1
```

Canonical guest access uses the GREYWARD-owned SSH config and the host-account-owned identity:
`ssh -F .secrets\ssh\config greyward-dev`. The bootstrap private key is owned by the
authorized interactive host account and provisioning receives only its public key. Do not
cache or document a DHCP address.

The one-time `create.ps1` bootstrap is a host-privileged maintenance operation. Run it from an
elevated PowerShell session with effective Hyper-V Administrators access; the factory also needs
to manage the temporary `greyward-build` host mapping. With the managed SSH alias
operational, `deploy.ps1`, `reload.ps1`, `capture.ps1`, and `health.ps1` use `ssh greyward-dev`
and establish the active Wayland session environment themselves, whether the selected compositor
is canonical Labwc or the retained Hyprland fallback.
Host lifecycle commands (`start.ps1`, `stop.ps1`, `checkpoint.ps1`, and `revert.ps1`)
remain privileged lifecycle operations and are not part of the routine SSH-only loop.
`create.ps1` and `start.ps1` also ensure Hyper-V console HID support before boot. If that support
is added to an already-open VM, reconnect VMConnect before treating console keyboard/pointer
input as a runtime result.

## VMware production-candidate test VM

`GREYWARD -VMWARE- DEV` is the separate VMware Workstation clean-install and
runtime-validation bench. It is not `GREYWARD-DEV`, is not the `.149` Hyper-V
development VM, and is not a production image. The following configuration was
verified on 2026-09-16; the current IP and attached ISO can change between tests:

| Property | Verified value |
|---|---|
| VMware Workstation | 26.0.0 (build 25388281) |
| VMX | Local VMware workspace (machine-specific, not recorded in Git) |
| Guest | Fedora 44, x86_64; hostname `greyward` |
| Firmware / boot | EFI; HDD first, `nvme0:0` first in HDD order |
| CPU / memory | 4 vCPU, 8 GiB RAM |
| System disk | Fresh NVMe VMDK in the local VMware workspace, not a Hyper-V disk |
| Installer media | Candidate ISO attached to the SATA CD/DVD device and connected |
| Graphics | VMware 3D enabled; VMX caps are 2560x1440, but this is not a DRM-mode guarantee; see the VMware Wayland diagnostic |
| Network | Bridged `vmxnet3`; DHCP address resolved through the managed alias |
| Guest access | `stendev`, SSH public-key authentication only; password SSH disabled |
| VMware Tools | `vmrun checkToolsState` currently reports `unknown`; do not assume guest operations are available |

### Short SSH protocol for an agent

From the Windows repository host, use the managed alias and do not invent a
second key or store the guest password:

```powershell
ssh -F .secrets\ssh\config greyward-vmware
```

The alias resolves to the current VMware guest address and the host-owned key
`$env:USERPROFILE\.ssh\greyward-dev_ed25519`. The corresponding private key is
not part of the repository. For a one-shot command:

```powershell
ssh -F .secrets\ssh\config greyward-vmware "command"
```

The current address is DHCP-derived and may change after a VMware network
restart; update the managed alias after verifying the address rather than
adding a new ad-hoc host entry. SSH is a temporary test-VM access aid and must
not be copied into the production ISO or its provisioner. The VM currently
uses bridged networking, so disable `sshd` or move the adapter to host-only
when the access window closes.

For the distinct Workstation → VMware Tools → `vmwgfx` → DRM → wlroots/Labwc
→ DMS investigation and its read-only capture gate, see
[VMware Wayland display diagnostic](VMWARE_WAYLAND_DISPLAY_DIAGNOSTIC.md).

## Normal shell loop

```text
EDIT QML/SVG
 -> validate-branding.ps1
 -> deploy.ps1
 -> reload.ps1
 -> capture.ps1
 -> inspect output/greyward-runtime/current.png
```

Deployment stages a complete release under `~/.local/share/greyward/releases`, validates it in the guest, then atomically changes the `current` symlink. The previous release is retained for rollback.

## Fast Security Center iteration

Security Center source should remain persistent in the guest during an iteration session. Use
`tools/greyward-dev/iterate-security-center.ps1` for component-scoped edits:

```powershell
.\tools\greyward-dev\iterate-security-center.ps1 -Component Python
.\tools\greyward-dev\iterate-security-center.ps1 -Component Frontend
.\tools\greyward-dev\iterate-security-center.ps1 -Component Rust
.\tools\greyward-dev\iterate-security-center.ps1 -Component Dms
```

The Python and DMS paths sync only their component and restart only the affected user service;
the frontend path uses a persistent Cargo target directory and the Rust path runs `cargo check`
without rebuilding an RPM. `-Component Service` is reserved for unit-file changes. Use
`-Reset` explicitly to remove the disposable guest-side development source and Cargo cache, then
recreate them on the next iteration.

Run the complete package deployment once the focused loop is stable:
`tools/greyward-dev/deploy-security-center.ps1`. It still stages a clean source tree, builds both
RPMs, installs them, runs packaged checks, launches the installed application, and runs the health
gate. To reduce repeated Rust compilation, the deployment first runs
`cargo test --workspace --locked` against the exact persistent guest-side staged source, then
passes that successful result to `environment/development/build-security-center.sh`. The RPM build
reuses `~/.cache/greyward/package-cargo-target` and skips only the redundant RPM `%check` Rust test
when that pre-build test has succeeded; standalone invocations of the build script keep their
normal `%check`. Deployment output includes `GREYWARD_TIMING` markers for source sync, Rust tests,
the Tauri build, each RPM build, package total, installation, packaged checks, launch, and health.
Those markers are the comparison baseline for future package-workflow changes.

The full desktop deployment also installs the production `Terminal` desktop entry and its
GREYWARD geometric icon, clears the stale DMS launcher cache, then refreshes the local
desktop-entry cache before restarting DMS. For a fresh development account it also seeds the
GREYWARD Black Box configuration while preserving the existing Oh My Zsh/Powerlevel10k shell setup.

## Real Tauri interaction automation

The canonical real-UI path is `tools/greyward-dev/run-security-center-interaction.ps1`.
It syncs Security Center source to the disposable guest, builds the development Tauri binary,
starts `tauri-driver` with Fedora's `/usr/bin/WebKitWebDriver` under the active Wayland user
session, and runs `security-center/tauri/frontend/interaction.test.mjs` entirely inside the
guest. The host retrieves the bounded result after the guest restores connectivity; this is
required for tests that intentionally change firewall/privacy state. The Privacy interaction
also arms `security-center/tauri/dev/privacy-network-watchdog.sh` before its first mutation;
future network-mutating tests may reuse that guard with `arm STANDARD` and `cancel`. It does
not rebuild an RPM. The runner syncs the locked `security-center/tauri/package.json` and
`package-lock.json` and installs the guest-only WebDriver dependency set with `npm ci` before
the test starts.

Install the guest-only driver once with `cargo install tauri-driver --locked` and ensure the
Fedora WebKitWebDriver runtime/development packages are installed. The test uses WebDriver
semantic selectors and DOM event execution for controls because this WebKitWebDriver build does
not implement native element-click; it never uses coordinates or a custom input layer.

VMConnect is a visual observation surface only for GREYWARD-DEV automation; its guest display
must not be used as a click or keyboard transport. The harness has no CDP endpoint requirement
and does not enable a production debug surface.

## Safety

- VM lifecycle wrappers protect GREYWARD names and never target `STENOS-DEV`.
- Factory creation and `-Resume` are maintenance paths; they are not part of the normal UI development loop.
- Host bootstrap uses the existing Hyper-V `Default Switch` and DHCP, matching the proven STENOS path. GREYWARD does not create or mutate a host NAT or host IP configuration.
- `destroy.ps1` requires `-VmName GREYWARD-DEV -ConfirmVmName GREYWARD-DEV`.
- Runtime captures, ISOs, Packer output, state, RPMs, and audit scratch files
  remain ignored. Hyper-V disks/checkpoints under `.vmtest/` are deliberately
  retained and must be managed through the VM lifecycle tools.
- Clipboard commands are text-only and must never transport secrets.

## Current phase: H2 visual refinement and branding

The existing development appliance is H2-active. Verified H2 slices are recorded in
`tools/greyward-dev/state/handoff.json`: canonical branding consumers, GREYWARD material
tokens and panel treatment, restrained hover/active motion, Fluent app-tile gloss, and the
installed GREYWARD Plymouth theme with normal initramfs inventory verification. The daily VM
was not rebooted as part of this pass; encrypted unlock validation remains a disposable
`GREYWARD-BOOTTEST` gate.

## Human gates

1. Run the one-time host bootstrap from the authorized execution context with effective Hyper-V access.
2. H0 runtime acceptance confirms the active repository shell, capture, workspace state change, and pointer/keyboard behavior in VMConnect.
3. In H2, enter the disposable boot-test LUKS passphrase and verify text recovery.

## Deferred H1 review

Labwc supplies the canonical native move, resize, minimize, maximize, and fullscreen behavior
through its server-side decorations and standard mouse/key bindings. Hyprland remains available
for fallback comparison; its prior edge/corner-resize limitation and minimized-window helper are
fallback-specific and do not define the Labwc path.

## Upstream-constrained window semantics

The Labwc task list consumes Quickshell's standard Wayland toplevel manager and uses compositor
activation/minimized state; it does not fabricate titlebars or move windows off-screen. Native
GTK, Firefox, and Black Box client chrome remains intact beneath Labwc's one server-side decoration.
Brave's Wayland decoration feature is seeded through its per-user Flatpak `brave-flags.conf`,
so its minimize, maximize, and close controls remain available after Flatpak updates. Labwc
retains its native titlebar for maximized Brave windows because server-side controls cannot be
merged into Brave's tab strip by the Wayland decoration protocol.
The installed Hyprbars binary is ABI-incompatible with Hyprland 0.56.2 and remains disabled on
the fallback path.
