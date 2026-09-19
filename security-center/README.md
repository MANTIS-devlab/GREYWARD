# GREYWARD Security Center

GREYWARD Security Center is the canonical Tauri 2 desktop application. The
frontend is presentation-only; the existing Rust domain and backend crates
remain responsible for collection, evaluation, evidence, privacy state, and
network controls.

## Workspace

- `crates/greyward-security-domain`: backend-independent posture contract.
- `crates/greyward-security-backends`: real local collectors, evaluator,
  privacy state, and validated controls.
- `tauri/src-tauri`: thin Tauri command facade and application entry point.
- `tauri/frontend`: vanilla JavaScript/CSS UI, bundled GREYWARD SVG and Inter.
- `file-context`: focused GTK4 file-evidence window and scan launcher; it uses
  the existing typed Security Context API and owns no security policy.
- `nautilus`: the file-manager menu bridge for Safe Open, scanning, and file
  context.
- `security-context`: packaged user/system D-Bus services and fixed privileged
  helpers described by the Security Context documentation.

The old general-purpose GTK presentation crate is no longer a workspace member
or canonical application. The narrowly scoped GTK file-context helper remains
an intentional packaged companion to the Tauri application.

## Fedora 44 build dependencies

Install the normal Fedora packages:

```bash
sudo dnf install cargo rust rustfmt clippy webkit2gtk4.1-devel nautilus-devel openssl-devel libappindicator-gtk3-devel librsvg2-devel libxdo-devel desktop-file-utils rpm-build
```

Build and validate:

```bash
cargo fmt --all -- --check
cargo build --workspace --release --locked --features greyward-security-center/custom-protocol
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
desktop-file-validate data/systems.mantis.greyward.securitycenter.desktop
```

The source-only frontend contract does not need browser-driver dependencies:

```bash
node --test tauri/frontend/ux-contract.test.mjs
```

The real-window interaction, startup, and performance suites do. Install their
locked dependencies from the Tauri tooling directory before running them in the
documented Fedora desktop session:

```bash
cd tauri
npm ci --ignore-scripts --no-audit --no-fund
npm run test:interaction
node --test frontend/startup.test.mjs frontend/performance.test.mjs
```

Run as the logged-in desktop user:

```bash
cargo run --locked -p greyward-security-center --features custom-protocol
```

The RPM spec is `packaging/greyward-security-center.spec`. It retains the
existing package name, desktop entry, launcher path, icon identity, and
single-instance expectation.

## IPC boundary

The webview can invoke only typed commands registered in
`tauri/src-tauri/src/lib.rs`: page reads, verified NetworkManager/firewalld
trust-zone changes, safe posture export, and bounded activity clearing. It has
no arbitrary shell, filesystem, D-Bus, sudo, or generic command API.

## System checks workflow

**System security** opens **System checks** directly, with contextual access to
File security, Application access, and Devices & recovery. It covers
OS security updates together with core posture checks such as
encryption, firmware, SELinux, and recovery readiness. Application versions
remain owned by Update Center and the Application Access view. Its detail page
leads with findings and their relevant typed page actions; the recorded reason and complete
technical evidence remains available behind the All checks disclosure.
Privileged recovery-point creation depends on the DMS-owned session Polkit
agent and the packaged `org.greyward.RecoveryPoint` fixed-path policy. The
authenticated `wheel` user supplies their own password; the policy does not
silently select another administrator account. The update worker runs as a
user systemd service, so its `pkexec` child cannot be required to carry the
window's active logind-session flag. A graphical Polkit agent is still
required; opening the window through an SSH escape hatch does not provide one.

The Update Center prefers Fedora's `dnf5daemon-server` D-Bus provider for
unprivileged resolution. It is
declared by both the Security Context RPM and the production package contract,
along with `dnf5daemon-server-polkit`, so future installed images include the
daemon and its standard wheel authorization rule. Already-installed systems
without the daemon retain a fixed-path `dnf5` CLI fallback for checking. Apply
uses `/usr/libexec/greyward-update-action`: one fixed Polkit helper creates the
pre-update recovery point and runs only the reviewed DNF5, system Flatpak, and
fwupd flags. It authenticates the invoking `wheel` user once; user Flatpak is
unprivileged. The helper schedules the stored DNF5 transaction through
`/system-update` without rebooting immediately, and the later visible restart
delegates to logind. After the new boot, the Update Center matches the prepared
operation to a successful DNF5 history record before reporting completion.
GREYWARD does not install a passwordless or cached authorization rule.
If Fedora's optional OpenH264 repository is unavailable while it is replacing
the installed `noopenh264` placeholder, the helper retries with that optional
repository disabled. The system and security update continues, while the
transaction records that the codec packages were deferred for a later retry.
Other repository or package failures remain hard failures.

Production also includes a root-owned, two-day `greyward-auto-update.timer`
for the Fedora system provider. It checks with DNF5, applies available system
updates through the fixed native update helper without a prompt, creates the
same pre-update recovery point, prepares the native offline transaction, and
notifies the logged-in desktop that a restart is required. It does not reboot
automatically, and it does not silently update firmware, system Flatpaks, or
user-scope applications.

This native-provider apply/restart path is a separately admitted post-V0
Update Center capability. The visible Check action is resolve-only; provider
application is explicit, bounded, and followed by a fresh provider snapshot so
completion cannot be reported without readback.

## Reliable VM launch path

Build/install from GREYWARD-DEV when its Fedora repositories are available:

```powershell
.\tools\greyward-dev\deploy-security-center.ps1
```

From the Windows workspace, open the last installed version:

```powershell
.\tools\greyward-dev\open-security-center.ps1
```

This opens the last installed package through the durable desktop launcher.

## Performance validation

Page reads and privacy profile changes use asynchronous Tauri command dispatch so
blocking service reads do not occupy the window thread. Frontend refreshes retain
open disclosures and focus; shared confirmation dialogs remain mounted outside
page replacement. These interaction contracts are covered by the frontend tests.

The real runtime benchmarks are `tauri/frontend/startup.test.mjs` for launch
phase measurements and `tauri/frontend/performance.test.mjs` for the broader
route/action regression pass. Run them
inside the logged-in GREYWARD-DEV Fedora session with guest-local
`tauri-driver` and `WebKitWebDriver`; set `GREYWARD_TAURI_WEBDRIVER_URL` and
`GREYWARD_TAURI_APPLICATION` to the local driver endpoint and binary. It
reports launch phases, startup, route readiness, command activity, revisit
behavior, and idle CPU/RSS. Harness-only timings are not runtime evidence; the
measured before/after record is [PERFORMANCE.md](../docs/security-center/PERFORMANCE.md).
