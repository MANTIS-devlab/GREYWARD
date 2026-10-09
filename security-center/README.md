# GREYWARD Security Center

GREYWARD Security Center is the canonical Tauri 2 desktop application. The
frontend is presentation-only; the existing Rust domain and backend crates
remain responsible for collection, evaluation, evidence, privacy state, and
network controls.

## Workspace

Sensitive-access notification **Review** routes to the affected registered resource
in Protected Data, with its access history and reviewed-grant controls. Review is
not permission approval. The current tested grant provider supports restricted
SSH-key inspection only; arbitrary script and IDE raw-key access remains
unavailable. The normal-user test scripts exercise the deny path and must not be
reported as a completed VS Code access workflow.

Launcher, running-app taskbar, plugin and system notifications share the
[Security Center shield-G identity](../branding/BRANDING.md#security-center-application-identity).
The canonical SVG generates both packaged icon names and the PNG fallback.

Current development status, 8 October: the normal `.149` account is deliberately
confined and the real installed broker/Context/Center expose actual protected
resources and tested key-inspection grants. Ordinary/direct access is denied;
reviewed launches and GUI revocation use native protected Fedora authentication.
See the [normal-session receipt](../docs/history/security-center/2026-10-08-application-security-normal-session.md)
for the baseline Center 66 / Context 68 / runtime 25 enforcement validation.
The subsequent [workspace receipt](../docs/history/security-center/2026-10-08-security-center-workspace.md)
records the Center 68 / Context 69 / runtime 25 presentation update, dedicated
Network Activity and separate Security History. The subsequent
[refresh/theme receipt](../docs/history/security-center/2026-10-08-protection-refresh-theme.md)
records Center 70 / Context 69 / runtime 26: visible lease renewal,
stable views and canonical decorations in the root-owned compositor closure. This does not
claim automatic production/image enrollment. The older private-account and
unenrolled package observations in the detailed foundation notes below are
historical where superseded by that receipt. The earlier
[visual polish receipt](../docs/history/security-center/2026-10-08-security-center-visual-polish.md)
records installed Center 72 / Context 69 / runtime 26, coherent materials and
semantic state, real EN/FR route review, native locale handoff and actual
deny/expiry/readback checks. This remains development evidence, with unsupported
grant profiles and production lifecycle limits stated explicitly.
The previous [focused quality/regression receipt](../docs/history/security-center/2026-10-08-security-center-quality-regressions.md)
records installed Center 73 / Context 69 / runtime 26, restored graphite finish,
intentional icons, compact lists and actual default/minimum desktop review.

The [Security Activity context receipt](../docs/history/security-center/2026-10-08-security-activity-context.md)
records the previous Center 75 / Context 71 / runtime 27 development tuple:
shared actor/action/resource/decision rows, bounded historical kernel process
metadata, real denial proof and normal-desktop validation. Historical identities
stay unknown when unrecorded; history cannot establish current protection.
The [file review lifecycle receipt](../docs/history/security-center/2026-10-08-file-review-lifecycle.md)
records the scoped active-review/history fix. The current behavior is defined
in [File Security](../docs/security-center/FILE_SECURITY.md).

The [integrated window chrome receipt](../docs/history/security-center/2026-10-08-integrated-window-chrome.md)
records installed Center 80 / Context 72 / runtime 27, application-owned
unbranded chrome and bounded native operations. Actual normal/maximized/restored visual review and minimum-size checks pass;
physical drag/resize gestures and minimize remain pending.

- `crates/greyward-security-domain`: backend-independent posture contract.
- `crates/greyward-security-backends`: real local collectors, evaluator,
  privacy state, and validated controls.
- `crates/greyward-application-security`: experimental root-runtime foundation,
  identity registry, policy storage, operations, kernel-bound peer evidence and
  typed read broker, explicit development workflow and Guard CLI. The
  experimental package is excluded from image inputs.
  The installed public workflow broker is active on `.149`; no production
  application-protection release is provided yet. See
  the [approved implementation authority](../docs/security-center/APPLICATION_SECURITY_PLAN.md).

  Descriptor-bound directory review leases reject unsafe resolution and changed
  objects. The separate-account provider now applies labels through retained
  descriptors, journals original metadata in the shared policy database, and verifies
  live kernel decisions. Its reviewed read-only grants pass deny/allow/revoke
  checks after fresh authentication. Stored metadata remains UNKNOWN.
  `native_restrictions.rs` supplies descriptor-bound
  disconnected/headless Landlock and seccomp restrictions. Its fixed test driver
  under `tests/support/` replaces the independent native-worker prototype.
  `isolated_launch.rs` and `bin/greyward-native-worker.rs` connect that core to
  held-code ELF preparation, private namespaces/home, standard-stream-only
  delivery and worker readiness before exec. The unknown ELF public-file control
  and inaccessible host-resource check pass through the real bus. `payload.rs`
  adds fixed interpreter scripts and bounded Type-2 AppImage extraction;
  `private_display.rs` and `bin/support/graphical.rs` supply private nested
  Labwc/clipboard and disconnected graphical payloads. Production activation
  remains open.
  The fixed test driver is not installed by the package.

  The immutable `policy.rs` index prepares desired resource rules by policy
  revision, installation/content generation and exact run membership. Reviewed
  candidates are not effective access decisions. Shared policy storage retains
  metadata-only resource intentions and persistent grant proposals through
  revision-checked, freshly authorized owner reviews. Pending intentions stay
  UNKNOWN; persistence alone does not activate grants. `policy_execution.rs`
  connects reviewed intentions to the fixed development kernel provider and
  authoritative readback. `reviewed_launch.rs` prepares an
  immutable root copy of the reviewed generation and a bounded private unit.
  `workflow.rs`, `development_bus.rs` and `guard_client.rs` provide typed
  registration, grant/revoke, operation and launch dispatch on the separate
  development bus. The actual bus deny/allow/revoke sequence passes with fresh
  owner authentication. Safe Open now uses this shared runner without a legacy
  sandbox fallback. Configured Flatpak document handlers stay unavailable until
  a provider preserves their native semantics. Public activation and production
  enrollment remain separate work.

  `access_events.rs` joins root audit AVC/syscall evidence for registered
  resource denials. The Context ingestion adapter writes existing telemetry,
  and the existing notification publisher aggregates Review/Dismiss items.
  Attribution and global coverage stay UNKNOWN where unproven. The source GUI
  has descriptor/category registration, native READ grant review and verified
  apply/cancel/revoke, isolated graphical launch and related resource/app
  Activity. The source runtime spec is revision 33; installed development runtime
  32 and its explicit overlays remain unchanged. Older revision-13/20 notes below
  are historical. See the authority for live receipts and DEFERRED HARDENING.

  `resource_policy.rs` generates development-only denial policy;
  `selinux_readback.rs` verifies live kernel type decisions, enforcing state and
  policy sequence. Actual absence/removal and held-descriptor denial tests pass.
  These type-policy receipts alone establish neither object registration nor
  whole-session coverage; the separate critical provider verifies those inputs.

  Production-enrollment source now adds schema-four lifecycle/CAS records and
  per-owner provider/workload bindings. Ordinary production broker opening
  refuses older schemas until an offline snapshot/migration coordinator exists.
  The default public service remains read-only. The explicit `--workflows`
  service exposes the shared dispatcher on `.149`, with managed isolation for
  normal local accounts and policy mutations requiring enrolled-owner checks.
  Context 67 / Center 64 validate separate capability flags; missing legacy
  flags default false. PID 1 creates the private home in the workload namespace,
  scratch-root modes are explicit under umask 0077, and the private display
  helper binds the actual workload UID. See the
  [live development receipt](../docs/history/security-center/2026-10-07-application-security-live-development.md).
  The [live integration receipt](../docs/history/security-center/2026-10-07-application-security-live-integration.md)
  records installed Center 64 / Context 67 / runtime 20: normal desktop reads,
  route refresh, actual broker loss/recovery and accurate negative coverage in
  Overview and Applications. That dated receipt predates deliberate normal-account
  enrollment; it does not establish current protection. See the enrollment
  authority for current development enrollment/readback. Generic sensitive
  grants and automatic production lifecycle remain incomplete.
  An inert maintenance console uses
  explicit offline boot and fresh LUKS authentication without a recovery account;
  it is not included in the experimental package. Separate authentication now
  passes private-seat native PAM, two fresh GUI Polkit challenges and same-UID
  cross-domain denials. Persistent grant reuse now requires an exact tested
  profile; legacy generic grants cannot activate/launch. Only pinned nonexporting
  key inspection is profiled; IDE, SSH login/signing and temporary grants remain
  unavailable. Activation remains BLOCKED by production input/admission/lifecycle, with no passed
  production gates. See the [enrollment authority](../docs/security-center/APPLICATION_SECURITY_ENROLLMENT.md).

Flatpak compatibility reads summarize the provider's effective context for the
exact architecture/branch. Local override records never override that result;
failed reads stay unavailable and environment values are excluded. Fixed
provider commands use nonblocking bounded output and process-group cleanup,
including descendants retaining a pipe. This read runner is not the privileged
isolation worker or a claim of workload confinement.
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
sudo dnf install cargo rust rustfmt clippy webkit2gtk4.1-devel nautilus-devel openssl-devel libappindicator-gtk3-devel librsvg2-devel libxdo-devel sqlite-devel dbus-devel libseccomp-devel desktop-file-utils rpm-build
```

Build and validate:

```bash
cargo fmt --all -- --check
cargo build --workspace --release --locked --features greyward-security-center/custom-protocol
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
desktop-file-validate data/systems.mantis.greyward.securitycenter.desktop
```

The Ubuntu source CI job pins Rust 1.98.1 and explicitly excludes ten tests
requiring a live SELinux execution context plus the installed-Fedora-RPM
identity control. Their names remain visible in
[`source-validation.yml`](../.github/workflows/source-validation.yml). This is
a portable source gate, not a full Fedora acceptance pass. Run the full
workspace command above on the compatible Fedora test host; never supply forged
contexts or relax runtime validation to make an Ubuntu fixture pass.

For scoped Administration rendering changes, compile the native regression as
an ordinary user on Fedora (Wayland protocols, Pango/Cairo, xkbcommon, libvterm
SELinux and librsvg development headers are required). From `security-center/`:

```bash
admin_render_dir=$(mktemp -d)
wayland-scanner client-header /usr/share/wayland-protocols/staging/ext-session-lock/ext-session-lock-v1.xml "$admin_render_dir/ext-session-lock-v1-client-protocol.h"
wayland-scanner private-code /usr/share/wayland-protocols/staging/ext-session-lock/ext-session-lock-v1.xml "$admin_render_dir/protocol.c"
python3 -I packaging/application-security/administration/embed-logo.py data/greyward-symbol.svg "$admin_render_dir/greyward-admin-logo.h"
gcc -O2 -Wall -Wextra -Werror -I"$admin_render_dir" ../tests/test_administration_render.c "$admin_render_dir/protocol.c" $(pkg-config --cflags --libs wayland-client pangocairo xkbcommon vterm libselinux librsvg-2.0) -lutil -o "$admin_render_dir/render-test"
"$admin_render_dir/render-test"
python3 ../tests/test_administration.py
python3 ../tests/test_administration_branding.py
```

This tests actual cell colors and admission contracts without opening a seat or
changing policy. Actual Administration review and terminal visual checks remain
necessary. The [privilege model](../docs/security-center/PRIVILEGE_MODEL.md)
defines warning, authentication and handoff behavior.

Use an isolated builder for dependency acquisition. Do not upgrade the active
desktop's runtime libraries just to obtain headers. The experimental peer
tests require Fedora's real system bus with `ProcessFD` credentials and run
separately from ordinary source tests:

```bash
cargo test --locked -p greyward-application-security --test system_bus_peer -- --ignored --skip unprivileged_calls_cannot_supply_authorization_details --skip root_broker_checks_do_not_authorize_an_unauthenticated_subject
```

These establish kernel-bound peer identity, not whole-session enforcement. The
separate Polkit/root-storage tests require bounded development fixtures; never
run the build system as root. Separate-account SELinux/session/portal probes are documented in
[the development spike](../spikes/application-security/README.md).

The source-only frontend contract does not need browser-driver dependencies:

```bash
node --test tauri/frontend/ux-contract.test.mjs tauri/frontend/application-workflows.test.mjs tauri/frontend/application-view.test.mjs tauri/frontend/security-history.test.mjs
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
unprivileged. A root-only socket-activated worker executes that validated plan
in system-service authority, verifying the kernel peer UID; ordinary confined
applications cannot access the socket or acquire administrative service control.
The helper schedules the stored DNF5 transaction through
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

For the current installed-desktop measurement record, see
[PERFORMANCE.md](../docs/security-center/PERFORMANCE.md). The development-only
`tools/greyward-dev/security-center-benchmark.py` profiles the existing native
WebKit session: route readiness, real command latency, render counts, idle reads
and browser errors. It changes no security policy and removes its instrumentation
on completion. It requires an already connected native desktop driver/session;
do not run a second shell or move the application to a private display.

Overview exposes posture and fresh Guard coverage before its independent recent
history read finishes. Loading/unavailable history is explicit; background
renewal preserves the actual evidence deadline. Navigation chrome remains mounted.

The packaged `/usr/libexec/greyward-security-posture` command collects the core
snapshot and emits the same `greyward.security.posture/v1` digest used by the
Security Center. Security Context uses this headless backend command instead of
starting the graphical executable for each posture read. Missing or failed reads
retain the existing unavailable state and freshness limits. Bursts of provider
signals share one pending idle callback; subsequent changes still trigger a read.

Component builds retain external Cargo dependencies while cleaning first-party
crates whose content digest changed. This prevents normalized source timestamps
from hiding changed code. `environment/image/build-components.py` reuses only
hash-verified receipts and rejects changed inputs under a previously built package
identity; increment the affected RPM release before building changed inputs.

Endpoint-country hints use optional local MMDB/geofeed data. No country database
or remote lookup is required. API/UI metadata reports source availability and
file age; data older than 180 days is marked stale with very low confidence.
Legacy DAT input requires an explicit `GREYWARD_GEOIP_LEGACY_DB` path.

Page reads and privacy profile changes use asynchronous Tauri command dispatch so
blocking service reads do not occupy the window thread. Frontend refreshes retain
open disclosures and focus; shared confirmation dialogs remain mounted outside
page replacement. These interaction contracts are covered by the frontend tests.

Bundled startup/request modules remove inline document scripting. The script CSP
has no inline exception; existing typed native IPC remains available. Request
wait expiry does not cancel backend work and says so in EN/FR. Timers also clear
after synchronous transport failures, and stale Updates reads cannot replace a
later visit. Source contracts and a private headless WebKit/Tauri smoke test pass;
new package, complete interaction and performance acceptance remain pending.

The experimental Application Security source boundary contains five typed reads
plus descriptor registration, reviewed native READ-grant apply/cancel/revoke,
operations and prepared launch workflows. Context pins the root peer; Tauri
exposes only fixed commands. Source GUI includes Applications/Protected Data,
related grants and Activity, retaining legacy Flatpak observations. Current
public snapshots use fresh negative enrollment prerequisites; absent enrollment or an unconfined caller is UNAVAILABLE with no effective profile; absent/invalid
providers are Unavailable. Kernel-grant operation readback does not make an
unverified whole-session snapshot PROTECTED.

Latest scoped receipt is `55ab0132ea12409e80a4d1e6fe6f2566`: actual kernel
registration/grants/revocation, shared Safe Open and ELF/script/AppImage/private
graphical execution, plus private GUI review/cancel. A full GUI password/commit
walkthrough and matching installed runtime/Center/Context acceptance remain
open. Installed Center 59/Context 64 are unchanged. See the
[current authority](../docs/security-center/APPLICATION_SECURITY_PLAN.md) and
[planned production enrollment](../docs/security-center/APPLICATION_SECURITY_ENROLLMENT.md).

The real runtime benchmarks are `tauri/frontend/startup.test.mjs` for launch
phase measurements and `tauri/frontend/performance.test.mjs` for the broader
route/action regression pass. Run them
inside the logged-in GREYWARD-DEV Fedora session with guest-local
`tauri-driver` and `WebKitWebDriver`; set `GREYWARD_TAURI_WEBDRIVER_URL` and
`GREYWARD_TAURI_APPLICATION` to the local driver endpoint and binary. It
reports launch phases, startup, route readiness, command activity, revisit
behavior, and idle CPU/RSS. Harness-only timings are not runtime evidence; the
measured before/after record is [PERFORMANCE.md](../docs/security-center/PERFORMANCE.md).
