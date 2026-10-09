# GREYWARD current status

10 October [repository consolidation and ISO preparation](history/migrations/2026-10-10-release-preparation.md):
source candidates Center 90 / Context 82, runtime 33 and DMS 1.6.2-7 have distinct
identities; the installed development tuple remains unchanged. Experimental runtime
and D-Bus overlay are excluded from the image. ISO construction is NO-GO pending
the exact package, storage and mandatory validation gates. No runtime mutation,
cleanup, ISO build, session interruption or release tag was performed.
Publication is BLOCKED by the configured SSH commit-signing key failing to
unlock. No new commit or push occurred; reviewed public changes remain staged.

Source-only [targeted security truthfulness fixes](history/security-center/2026-10-09-security-truthfulness.md)
correct confined ClamAV status collection and narrow portal/VPN/accepted-risk/grant
claims. Local checks are distinct from pending installed-session validation;
`.149` remains on its existing package tuple with no deployment or service change.


9 October D-Bus prerequisite: **inspection correction VALIDATED on `.149`**.
An explicit unpackaged development CIL overlay denies ordinary inspection of
the existing session/a11y buses; 62-domain kernel readback and actual mem-open/
invalid-FD probes pass. Messaging/FD masks, stock Flatpak chooser, Context and
Administration projections remain compatible. Remove/reapply rollback passes
without any bus/session restart. Existing native root previews reject foreign,
exited, stale and changed-object use. **Portal request-to-Flatpak recipient
binding remains NOT IMPLEMENTED; hybrid permissions remain BLOCKED.** See the
[scoped receipt](history/security-center/2026-10-09-dbus-boundary-proof.md).

9 October bounded hybrid permissions: **BLOCKED** before bridge/grant integration.
The disposable Flatpak subject bootstrap and non-mutating live session-bus check
are implemented. The earlier normal same-UID user bus passed an ordinary caller's
inspection authorization check; its wider trust closure needs reassessment before
forwarded portal identities can authorize grants. Both application-specific
enforcement and first-use UX gates remain NOT DEMONSTRATED. Temporary policy,
workloads and code copies were removed; no grants or desktop/bus activation
changed. See the [execution receipt](history/security-center/2026-10-09-hybrid-flatpak-bootstrap.md)
and [current authority](security-center/APPLICATION_SECURITY_PLAN.md).

Previous 9 October first-use prerequisite: **BLOCKED** at the minimal-architecture
gate. Installed probes confirm sandbox-hidden paths emit no resource AVC and
the shared GTK FileChooser's denial does not identify the requesting Flatpak.
App-only grants cannot unblock that chooser; broad portal access is not an
accepted workaround. No generic grant UI, script provider, Sensitive files
provisioning, authorization or runtime changes were made in that previous probe. See the
[prerequisite receipt](history/security-center/2026-10-09-first-use-permission-proof.md)
and [current authority](security-center/APPLICATION_SECURITY_PLAN.md).

This document answers “what is true today?”. It is a status summary, not a
replacement for the domain specifications listed in [INDEX.md](INDEX.md).

## Implemented or active

- Administration console visual polish (9 October): the normal `.149` desktop
  runs an explicitly assembled native UI overlay on runtime 32; package-owned
  files and Center 89 / Context 81 / session 8 remain unchanged. Risk review now
  explains credential exposure, security changes, data loss and root-shell
  lifetime. The follow-up adds obsidian grain, embedded canonical SVG branding,
  a red Administration title, silver controls and an explanation of the sudo
  handoff. Larger terminal text and readable ANSI colors preserve the continuous
  canvas instead of black default cell rectangles. Actual
  normal-seat review, fresh PAM, confined sudo/root execution and terminal output
  were visually checked. Renderer/admission and kernel checks are recorded in
  the [latest visual receipt](history/security-center/2026-10-09-administration-obsidian.md).
  This is development evidence, not a newly built runtime RPM or image.

- Practical SELinux administration/usability (9 October): Center 89 / Context 81 /
  runtime 32 and session package 8 installed. Approved normal-seat logout/login
  activation passes without reboot or SSH loss. Actual terminal `sudo -i`, fresh
  PAM/sysadm, nested sudo with the private Fedora helper, native lock/unlock and
  end-session checks pass. Read-only Flatpak metadata/watch, ordinary certificate
  mount preparation and DMA enumeration repair general launch failures without
  application exceptions or raw DMA access. Brave, Proton VPN's GUI, new
  Calculator, Collabora, native terminal/browser, real GTK document selection,
  development/files/network/background workflows were exercised. A fresh reviewed
  key-inspection grant commits revision 7, reuses without authentication, and
  revokes at revision 8; direct/wrong-tool/revoked execution stays denied.
  Current kernel checks pass 937 adjacent decisions. Fresh ordinary coverage
  verifies and SSH recovery remains available. Screen sharing is unavailable;
  VPN connection, whole-desktop rollback and production/offline-rescue acceptance
  remain unpassed. DMS's two prior development plugin overlays have reconciled
  root receipts, not a new reproducible DMS package.
  See the [enrollment authority](security-center/APPLICATION_SECURITY_ENROLLMENT.md)
  and [normal-seat receipt](history/security-center/2026-10-09-desktop-compatibility.md).

- Sensitive-access Review routing deployed on `.149` (9 October): Center 87 /
  Context 80 / runtime 28, plus a recorded root-owned development overlay for
  the DMS 1.6.2-6 security widget. The publisher supplies the validated resource
  reference; Center opens that registered resource, related denial history and
  existing grant controls. Native wake-up restores the same minimized window.
  The widget previously ignored its `open` action; actual desktop Review now
  navigates from Overview to the affected resource. The widget exposes only
  supported actions; Dismiss remains available in the system notification.
  Running Center binary matches the installed package (SHA-256 prefix
  `a8822aa49f4a2436`). Actual fake-key reads remain denied, exit 1; coverage is
  PROTECTED / AVAILABLE with policy revision 6. No grant or confinement change
  was made. Frontend 115 pass locally; Fedora frontend 114, shell experience 21,
  notification router 7 and shell runtime 8 pass; changed Rust file formatting,
  static and repository gates pass. Workspace formatting still finds existing
  differences in `resource_labeling.rs`. Previous Center 86 / Context 79 RPMs,
  receipt, widget preimage and validation are retained in root-only
  `resource-review-20261009` beneath the development runtime receipt directory.
  Arbitrary script/VS Code raw-key approval and restrictive temporary grants
  remain undelivered functional work. Intermittent legacy DNS/USB projection
  unavailability observed during validation is not claimed fixed by this pass.

- Normal `.149` Black Box terminal paste repaired (9 October). Actual
  Ctrl+Shift+V reproduced immediate window closure with a simultaneous SELinux
  denial of Labwc writing the ordinary client's selection pipe. The canonical
  compositor policy now permits only that FIFO write; no protected-file read or
  grant-domain permission was added. Applied live without desktop restart;
  the same text pasted visibly into the real terminal and the window survived.
  The synthetic protected-key threat script still returns permission denied,
  exit 1, and broker coverage remains PROTECTED / AVAILABLE. Original module
  export and build receipts are retained in root-only `terminal-paste-20261009`
  under `/var/lib/greyward-development/application-security-live/`.

- Context 77 Update Center resolver repair deployed on `.149` (9 October):
  native DNF resolution now enforces the desktop holds already shown by inventory
  and used by Apply. The former Quickshell 0.3.2 conflict is gone: live resolution
  returns RESOLVED, 535 package changes, zero removals; the installed Updates page
  shows Updates ready after refresh. Interrupted resolver startup no longer keeps
  checks blocked. Fedora focused tests: bus 26, compatibility 3, provider 12 pass;
  static/repository gates pass. No pending updates applied or reboot scheduled.
  Resolver repair initially used Center 86 / Context 77 / runtime 28. Prior Context 76 RPM
  is retained; root-only receipt backup is `update-resolver-20261009` beneath
  `/var/lib/greyward-development/application-security-live/`.

- Context 79 authenticated update handoff deployed on `.149` (9 October).
  The failed post-password operation retained the ordinary confined domain,
  so Btrfs recovery inspection was denied and misleadingly reported a missing
  subvolume. A root-only socket-activated fixed worker now supplies system-service
  authority without granting ordinary applications administrative privileges.
  Live preflight from the same confined root context passes; ordinary-user helper
  and socket access remain denied. A real read-only recovery point
  `20261008T223026Z-da732756` was created and verified valid, with `ro=true`.
  Session coverage remains PROTECTED / AVAILABLE; read-only update resolution
  returns RESOLVED (535 changes, zero removals). Fedora focused tests: update bus
  30, recovery 33, provider 12 pass. Disposable old Cargo cache cleanup recovered
  space (6.4 GiB available); existing recovery points and source were retained.
  That update-worker validation used Center 86 / Context 79 / runtime 28. Context 77 RPM and
  previous policy are retained; root-only receipts are in `update-worker-20261009`
  beside the resolver receipts. A subsequent live GUI retry authenticated,
  created valid recovery point `20261008T223407Z-82f92bbc`, and reached
  PREPARING_RESTART with no error (operation `dnf5-1791498836977`). Provider
  download/preparation completion and the offline update/reboot are not yet
  claimed as passed.

- Security Center 86 sidebar deployed on `.149`: shared shield emblem centered
  above branding, larger menu labels, and removed local-security footer. The menu
  uses the available height; normal and maximized layouts visually checked in the
  real desktop. Frontend UX 93/93, branding and repository gates pass.

- Normal `.149` post-login resource/Flatpak failures repaired: runtime 28 with
  stable filesystem receipt reopening, canonical descendant namespace policy,
  and bounded public-IP transport retries. Broker resource coverage is PROTECTED;
  actual Brave loads HTTPS and the public IP is visible. Native/Flatpak protected
  reads and parent namespace writes remain denied. Center 85 / Context 76 retained.
  [Causes, evidence and limits](history/security-center/2026-10-08-session-resource-flatpak-recovery.md).

- Enrolled `.149` greetd login recovered: ordinary UWSM startup no longer
  inherits protected-console IO; the audited plugin overlay now has its matched
  selected receipt. Real GREYWARD login reaches the visible desktop/taskbar,
  protected-seat verification passes and SSH remains available. Four focused
  Fedora descriptor checks pass. [Recovery evidence and limits](history/security-center/2026-10-08-enrolled-login-recovery.md).

- Plugin/Center protection-state parity is installed on `.149`: Center 85,
  Context 76 / runtime 27. The shell uses shared evaluated check states and
  accepted deviations, and the same File Security readiness as Center.
  Actual System checks shows zero findings; the flyout shows Protected and
  no spurious malware/firewall/device warning. Eight live samples remain
  Protected; mandatory desktop readback passes. Existing recorded blocks
  remain informational. [Parity evidence](history/security-center/2026-10-08-security-plugin-parity.md).

- Security Center plugin stability receipt historically records normal `.149`: Center 84,
  Context 75, runtime 27, DMS 1.6.2-6 with a backed-up development QML overlay.
  D-Bus threading initialization and separate negative-display/action leases
  correct the diagnosed crash precondition and expired-display flapping. Actual
  flyout inspection and 30 live samples show stable Review needed; real provider
  warnings remain. Context had zero restarts during this short check.
  [Evidence and limitations](history/security-center/2026-10-08-security-plugin-stability.md).

- Security Center's main window is explicitly exempted from Labwc's forced
  server decoration in canonical session configuration and the normal `.149`
  protected desktop. The GTK app ID was observed through the real Wayland
  toplevel protocol. VMConnect shows a single application-owned titlebar in
  normal and maximized states, with maximize/restore working. The titlebar receipt records
  84 / Context 72 / runtime 27; protected-desktop readback passes. Earlier
  WebKit-only chrome captures did not validate the compositor frame.

- The [performance development receipt](history/security-center/2026-10-08-security-center-performance.md)
  historically records installed Center 84 / Context 72 / runtime 27 on normal `.149`.
  Persistent navigation, lease-aware read scheduling, independent optional
  Overview history, Recovery-specific reads and stale-response fixes are
  implemented. Startup p95 and application-list median improved; sampled
  Center/WebKit RSS and broker idle CPU fell. Actual 220 navigation visits,
  visuals, Rust/frontend/Context tests and root desktop verification were run.
  Network deadline failures and provider long-tail latency remain unresolved;
  this is scoped development evidence, not complete performance/release acceptance.

- [Integrated window chrome](history/security-center/2026-10-08-integrated-window-chrome.md)
  historically records Center 80 / Context 72 / runtime 27 on normal `.149`.
  The application owns a continuous, unbranded titlebar with canonical Labwc
  artwork and bounded native window actions. Build, focused tests and protected
  desktop verification pass. Actual normal/maximized/restored captures and
  minimum-size validation pass; physical drag/resize gestures and minimize
  remain pending. This is not release evidence.

- Security Center uses the approved silver/graphite shield-G emblem across
  launcher/running-app taskbar, the Security Center plugin and system
  notifications. [Branding](../branding/BRANDING.md#security-center-application-identity)
  owns the single SVG source and derived launcher PNG. Source/package definitions
  are updated; the normal development VM received a reversible icon-only overlay
  on 8 October, with installed SVG equality and desktop-entry validation passing.
  DMS reload reached READY. Center 80 now includes the Center branding inputs; Context remains 72.
  The separate Context 73 candidate and three-surface live branding review
  are not yet validated. This is not image or release evidence.

- The [file review lifecycle receipt](history/security-center/2026-10-08-file-review-lifecycle.md)
  historically records Center 76 / Context 72 / runtime 27 on normal `.149`.
  Quarantined/deleted detections and absent-source history leave active review;
  failed actions, restored files and uncertain source status stay reviewable.
  Actual EICAR scan/quarantine clears the active list and retains history controls.
  Running-build integrity and protected-desktop verification pass; 121 frontend
  and 25 focused Python tests pass. This is scoped development validation.

- The [Security Activity context receipt](history/security-center/2026-10-08-security-activity-context.md)
  historically records Center 75 / Context 71 / runtime 27 on normal `.149`:
  shared contextual event rows, historical kernel PID/basename, real action,
  resource label, decision and explanation. Actual direct reads are denied and
  visible end-to-end; old attribution stays UNKNOWN. Default/minimum UI review,
  121 frontend/23 Python/two audit tests, package integrity and both repository
  gates pass. Session protection remains verified; matched rollback inputs are
  retained. This is scoped development evidence, not release acceptance.

- The [focused quality/regression receipt](history/security-center/2026-10-08-security-center-quality-regressions.md)
  historically records Center 73 / Context 69 / runtime 26 on the normal `.149`
  desktop: neutral graphite grain/silver depth, distinct functional glyphs,
  corrected Files fallback and compact activity/list density. All 13 screens
  were visually reviewed at default/minimum sizes, live reversible interactions
  pass, 118 focused tests and both repository gates pass. Real protection stays
  connected and verified; previous Center 72 and the receipt are recoverable.
  This is scoped development UI evidence, not production/image acceptance.

- The [visual polish receipt](history/security-center/2026-10-08-security-center-visual-polish.md)
  historically records Center 72 / Context 69 / runtime 26 on the actual `.149`
  desktop. All 13 destinations pass EN capture/layout checks at 1440×900 and
  1100×700 and actual French review at the minimum size. Canonical materials,
  semantic state, readable controls and responsive Network Activity are restored.
  Native WebKit now honors the desktop locale. Fresh protection and resource
  readback, denial, revoked-grant denial, Flatpak and SSH checks pass; actual
  lease expiry still withdraws positive protection. Unsupported grant profiles,
  inventory uncertainty and deferred production validation remain explicit.

- The [normal-session recheck](history/security-center/2026-10-08-normal-session-recheck.md)
  historically confirms Center 70 / Context 69 / runtime 26 on the real `.149`
  desktop: fresh PROTECTED coverage, registered-resource readback, direct and
  revoked-grant denial, normal Flatpak compatibility and connected resource
  detail/history. Protection stayed stable through 30-second Applications and
  Protected Data observations and 15 seconds of Overview. SSH recovery remains
  available. The visual revision is delivered separately in the current receipt
  above; this older evidence does not describe Center 72.

- Security Center workspace source groups Protection, Monitor, Maintain and
  Preferences, restores dedicated Network Activity, separates Security History
  in the existing event store, and gives Backup & recovery its own route.
  The workspace receipt historically records Center 76 / Context 72 / runtime 27.
  Evidence renewal now precedes the actual lease deadline; unchanged fresh
  projections preserve the page. Root-owned GREYWARD theme/buttons are included
  in the protected Labwc closure and loaded without replacing the seat. See
  the [refresh/theme receipt](history/security-center/2026-10-08-protection-refresh-theme.md) and
  see the [workspace receipt](history/security-center/2026-10-08-security-center-workspace.md)
  for installed validation and limits. No enforcement authority changes.

- The normal `.149` development account is deliberately enrolled, with actual
  confined greetd/user-manager/SSH execution, root-owned matched Labwc and a
  separate native DMS authentication domain. SELinux is Enforcing and Fedora
  PAM/authselect are unchanged. Fresh authoritative coverage and the real
  installed Center report PROTECTED for the enrolled scope; the actual `.ssh`
  resource is protected. Descriptor registration and tested persistent READ
  grants pass fresh owner authentication. Ordinary/direct access is denied,
  two unchanged reviewed launches succeed, and real GUI revocation removes
  the grant and denies subsequent launch. Inventory completeness remains UNKNOWN.
  Center 66 / Context 68 / runtime 25 have clean package readback; positive
  coverage survives broker restart, and final GUI revocation publishes verified
  completion. The temporary test policy/helpers are removed. See the
  [normal-session receipt](history/security-center/2026-10-08-application-security-normal-session.md)
  for live evidence, recovery and current limits. Disk preflight had 7.1 GiB
  free; no data was deleted to make space. Root and ordinary SSH remain available.
  Automatic production lifecycle/installer/upgrade/rescue acceptance is not
  claimed. Earlier 7 October unenrolled receipts are historical.

- Historical 7 October foundation notes: Application Guard / Protected Data source includes a shared product workspace
  for Applications and Protected Data: one coverage summary, search/category
  views, contextual details/access/activity and structured tested-profile reviews
  in EN/FR. Real typed backend responses and existing operation/freshness gates
  drive it; no preview data is shipped. Source adds root-private, generation-bound
  account-origin issuance/readback; installer handoff remains unwired.
  Earlier focused checks pass: 145 runtime/domain Rust tests, fmt/Clippy, 8 Context
  workflow tests and 99 frontend tests; 21 explicit Rust integration tests remain
  ignored. The current source Center passes real private-window route/IPC/history/
  CSP checks with actual unavailable Context responses; this is presentation
  validation, not production enrollment or GUI authorization/commit evidence.
  The earlier functional foundation includes typed GUI
  descriptor/category registration, persistent native READ-grant review,
  apply/cancel/readback and reference-based revocation. Application/resource
  details and Activity use the existing identity, root policy and telemetry.
  Safe Open uses the shared runner; its standalone sandbox is retired. ELF,
  fixed interpreter scripts and bounded Type-2 AppImages support disconnected
  launches; graphical ISOLATED uses private nested Labwc/clipboard rather than
  the host display. Bounded root AVC/syscall denials enter the existing history
  and Review/Dismiss publisher with UNKNOWN process attribution.
  The earlier combined isolated-account workflow passed invocation
  `55ab0132ea12409e80a4d1e6fe6f2566` with five fresh owner authentications,
  historical generic concurrent grants and actual deny/allow/revoke, shared Safe Open, private GUI
  review/cancel and rollback. Those historical source suites passed: 296 Context tests, 94 frontend
  tests (three live-environment tests skipped), workspace Rust tests/Clippy and
  repository gates. Center 61 / Context 67 are now installed on the live desktop;
  DMS v1.6.2-6 is unchanged;
  runtime spec 19 supplies explicit installed managed workflows. The default
  broker remains read-only; the active development workflow broker permits
  isolation with UNKNOWN whole-session coverage. Flatpak document handlers, WRITE/timed grants and production
  enrollment are not represented as supported. Extended performance, hardware,
  release/image and exhaustive compatibility matrices are DEFERRED HARDENING.
  See the [current authority](security-center/APPLICATION_SECURITY_PLAN.md).
  Documentation was audited against source on 7 October; superseded receipts
  are [historical](history/security-center/2026-10-07-application-security-status.md). [Production enrollment](security-center/APPLICATION_SECURITY_ENROLLMENT.md)
  has accepted recovery/account/admin decisions and initial source for the
  existing-database enrollment journal, local-account/per-owner bindings and
  an inert offline LUKS-authenticated console. Nine focused maintenance tests
  pass, including real cryptsetup on synthetic data. Separate authentication now
  passes six enforcing-kernel cross-domain checks, two native DMS PAM cycles and
  two fresh protected GUI Polkit owner challenges on a private headless display.
  The first persistent profile permits only pinned nonexporting key inspection;
  changed code/path/arguments/revision refuse, and generic legacy grants cannot
  activate/launch. Two kernel profile reuses, direct denials and read-rule
  withdrawal pass. SSH login/signing, IDE raw access and the restrictive temporary
  fallback remain unavailable. See the [scoped receipt](history/security-center/2026-10-07-application-security-authentication.md).
  Activation remains BLOCKED by production seat/input, admission and lifecycle. No production gates,
  real maintenance boot, account admission or installed rollback have passed.
  Those isolated authentication checks changed no account mapping, package,
  active desktop or ISO. The subsequent Center/Context review upgrade is
  recorded separately above. The
  [initial receipt](history/security-center/2026-10-07-application-security-enrollment-initial.md)
  distinguishes source checks from production evidence.
  Earlier focused revalidation passed runtime Rust tests (115 passed, 21
  environment-specific tests ignored), workspace formatting, runtime all-target
  Clippy, 296 Context tests on Fedora, 89 frontend contracts and both repository
  gates. These do not pass the blocked production activation gates.

- The user rejected the October test installer. The [compatibility investigation](architecture/ISO_INSTALLER_COMPATIBILITY.md)
  identified an invalid auxiliary boot DVD introduced by the agent: stock Fedora
  branding, preseeded account/LUKS and disabled Plymouth. September and October
  product artifacts retain the same interactive Kickstart/profile and identical
  customization bytes. A composed-media guard is implemented; the product-only
  replacement `greyward-installer-20261004-interactive-6-6-53-58.iso` passed
  factory checks and was transferred with verified SHA-256. Its isolated product-only
  console shows GREYWARD branding, User Creation and an empty encryption passphrase
  prompt. The user subsequently completed installation and the isolated console
  reached the GREYWARD desktop. Greeter/desktop backgrounds regressed; fixes are
  implemented in source, with replacement-image acceptance still open. The VM's
  network was reconnected at the user's request and its public-IP lookup works.
  ClamAV's initialization projection is corrected in the Context 59 candidate;
  it shows preparation without claiming scanning readiness or suppressing actual
  protection failures. The 227 Context tests, Rust fmt/tests/Clippy and 78 frontend
  contracts pass. Session 7 packages the fresh wallpaper default; the greeter
  helper now selects the image through its actual standalone session state.
  Center 54/Context 59 build and extracted-package validation pass (227 tests;
  all 30 loaded project modules pinned to RPM bytes). Security/session cache
  reuse passes. Deployment and replacement-image acceptance remain open. The installed
  VM's supplied Secure DNS state identifies the private search-domain guard on
  Default Switch. The rejected switch workaround was reversed; the test VM remains
  there. A Hyper-V-specific prototype never shipped. Four retained ISO Context
  RPMs have a byte-identical reconciler and reproduce the same domain failure;
  no working DNS setting was lost by staging. A generic runtime split-scope
  candidate passes 239 Context tests and isolated real resolved checks for public
  encryption, local resolution and restoration on two namespaces. The installed
  user's DNS remains unaccepted. Earlier 54/59 and diagnostics-only 56/61 inputs
  are historical; the new paired candidates are Center 57/Context 62. They built
  and pass 239 extracted/installed-package tests with 31 imports pinned to RPM
  bytes. The actual .149 root service passes a bounded private-domain canary and
  restoration, without restarting DMS or changing profiles; no recent AVC was
  found. The paired Security packages are installed only on .149. A fresh ISO
  from DMS 6/session 7/Center 57/Context 62/branding 15 passed factory checks and
  is retained as an intermediate candidate, not an installed-image result.
  Repetition on 58/63 caught resolved retaining the removed public root domain;
  prior restoration checks did not cover that global route. Center 59/Context 64
  explicitly clear and observe it before removing the override. All 242 source
  tests and real isolated resolver restoration pass. The final packages are installed
  on .149 with clean integrity, 242 tests pinned to installed RPM modules, two
  complete mode/restoration cycles, unchanged DMS PID and no recent audit-log AVC.
  The fresh `greyward-installer-20261005-portable-dns-6-7-59-64.iso` passed factory
  checks (SHA-256 `736b87cefbe9ef3ed0c4b766538f9ab1d606400643d9aad673451f0f998f7a94`)
  from DMS 6/session 7/Center 59/Context 64/branding 15. The user's installation
  VM remains untouched and fresh-image acceptance is open.

- The user selected the **native DMS lock screen** as canonical on 4 October,
  superseding the migration's earlier swaylock/swayidle choice. Session RPM
  `0.1.0-6` and DMS runtime `v1.6.2-6` are installed on .149: native lock routing,
  600-second idle locking, 900-second blanking, Fedora system-auth delegation and
  DMS's logind sleep inhibitor are active. The obsolete external-lock QML patch
  and idle coordinator are retired. Package integrity, backend readiness and
  source gates passed. An actual native password unlock was observed; the -6
  runtime restored a secure native surface automatically after a locked-session
  shell restart. Repeated authentication and suspend/resume remain acceptance
  gates. SSH remained available and .149 was not rebooted.
  See the [current migration contract](architecture/DMS_1_6_MIGRATION_PLAN.md).

- The 4 October [architecture audit](architecture/FINAL_ARCHITECTURE_AUDIT.md)
  and [build/ISO audit](architecture/BUILD_ISO_AUDIT.md) are delivered; their
  [implementation backlog](plans/PRE_RELEASE_IMPROVEMENTS.md) is in progress.
  Read-only .149 checks reproduced DMS rejection of a changed Quickshell RPM
  release while cached repositories offer newer Quickshell/Greeter inputs than
  the candidate's exact tuple. The solver now enforces the exact manifest tuple alongside baseline floors;
  actual closure and fresh-image validation remain in progress.
  The audit also records current-source versus installed Security Context drift,
  substantial short-sample collector CPU and repeated dependency acquisition.
  Those are assessment-time findings; the backlog now records partial package
  implementation. No fresh-image gate or production promotion has passed.

- DMS 1.6.2 migration source/package integration is implemented as an unpromoted
  candidate: immutable source/vendor pins, offline unchanged distribution backend,
  generated explicit shell, eleven patches across twenty upstream files, system
  plugins, restrictive state backups, explicit selected routing and production lock
  defaults. Offline Fedora package build/backend tests and source migration fixtures
  passed during development. The .149 candidate also passed installed integrity,
  API 34/internal sampler and first-party plugins. Earlier simulated external-lock,
  guest acceptance and old-runtime/state rollback checks are historical evidence
  for the superseded lock configuration. Native-lock restart recovery is now
  separately tested; fresh-image gates remain open. The
  [dated evidence](history/migrations/2026-10-04-dms-1.6.2-candidate.md) records
  scope and the recovered locker-failure black-screen incident. The
  [active tracker](architecture/DMS_1_6_MIGRATION_PLAN.md) records remaining
  authentication/suspend, visual, performance, fresh-image and hardware gates.
  Matched post-cycle cgroup measurements observed lower CPU and about 32% lower
  median combined RSS; protocol startup/restart remain near the acceptance
  threshold and do not establish complete performance acceptance.
  The .149 1.5.3 baseline and private backups remain recovery inputs. No 1.6 release
  acceptance is implied by the earlier ISO records below.

- Security Center shell redesign is implemented in source and running in the
  `.149` development overlay: fixed identity, independent live activity,
  progressive disclosure and one shared notification projection. Real microphone
  and EICAR/quarantine transitions were exercised. Physical camera/storage,
  authenticated persistent USB trust and the rebuilt privileged scan package
  remain acceptance gaps; this is not release-image validation. See the
  [dated runtime record](history/security-center/2026-09-16-security-shell-runtime.md)
  for tested cases and remaining build/visual gates.

- The installed-system definition is `environment/production/`.
- The ISO workflow now requires an explicit `.149` runtime baseline and verified
  base-media checksum. It imports portable preferences, checks package version
  floors/Flatpak commits, rejects stale branding assets, validates the embedded
  payload, and bounds first-boot retries. It now bundles dependencies at build
  time for standalone installation, with no first-boot network fallback.
  These are implementation gates; a new
  clean graphical installation is still required for acceptance.
- The current 2026-09-18 candidate
  `output/iso/greyward-installer-20260918-installfast-anaclosure-hyperv-genericgfx.iso`
  passed ISO checksum, boot metadata, production-stage, Rock Ridge payload,
  and offline-closure checks. Its offline Flatpak installer batches the
  selected refs into one transaction while retaining per-commit verification;
  its verified Anaconda RPM closure prevents a duplicate first-boot RPM
  transaction on a fresh install. The candidate is not yet clean-installed or
  runtime-accepted in Hyper-V or on bare metal.
- Standalone dependency validation on `.149` passed for 1,140 RPMs (signatures,
  baseline floors, resolution with networking absent), all five Flatpak apps
  installed into an empty offline installation, and pinned desktop/shell inputs.
  This validates the dependency workflow, not a newly composed or installed ISO.
- The 2026-09-07 offline ISO failed Anaconda dependency selection because it
  omitted the `core` group metadata and `grub2-tools-extra`. The factory now
  preserves the Fedora core group with production exclusions and verifies
  implicit installer requirements against both repositories. The corrected
  `greyward-installer-20260908-offline-fixed.iso` preserves the original baseline
  and passes embedded-payload and offline resolver checks (1,142 RPMs).
  Its test installation subsequently failed in the Plymouth `%post` rebuild:
  dracut selected the running installer's older kernel. The canonical Kickstart
  now rebuilds all installed kernels explicitly; the `offline-bootfix` candidate
  preserves the production payload and baseline. The boot-fix candidate reached its
  installed 7.1.13 kernel, then first-boot provisioning failed on CRLF line
  endings in `provision.sh`. Source staging now normalizes Linux text and checks
  shell syntax; the `offline-stagefix` candidate preserves the baseline and RPMs.
  Applying its six checksum-verified source corrections to that installed stage
  completed first-boot finalization and reached the GREYWARD greeter and desktop
  on 2026-09-09. A fresh installation of the replacement ISO and a subsequent
  reboot with the media removed remain unvalidated.
- `GREYWARD-DEV` is defined as the production definition plus the explicit
  `environment/development/` overlay.
- A reachable 2026-08-30 internal-alpha VM is available for runtime diagnosis,
  but it is development-contaminated (`development-user`, SSH and development services)
  and still carries the disposable `greyward` live account. It is evidence for
  user-session behavior only, not installed-production acceptance.
- Labwc is the canonical compositor; Hyprland remains the supported fallback.
- DMS Settings owns general desktop settings. GREYWARD Security Center owns
  GREYWARD-specific security and privacy surfaces.
- Security Center uses the Tauri frontend and Rust domain/backend workspace.
- Security Context contains the user-bus summaries and the admitted security
  service integrations.
- GREYWARD production now explicitly selects Fedora `DEFAULT:GREYWARD`, where
  the repository-owned `GREYWARD.pmod` is a small hardened layer that keeps
  RSA-2048 compatibility. This is a secure-default baseline, not a FIPS or
  release-readiness claim; compatibility validation remains part of clean-image
  acceptance. The `.149` development VM remains runtime evidence only.
- Recovery V1 provides local recovery-point and Restic backup components; boot
  rollback remains a separate prototype.
- Update Center review and provider resolution remain unprivileged. Applying a
  reviewed system plan now crosses one fixed-path Polkit boundary that creates
  the Recovery V1 point and prepares DNF5, system Flatpak, and firmware work in
  one `auth_self` transaction; passwordless and cached authorization are not
  enabled. On 2026-09-06 the development VM created a valid linked recovery
  point and completed the prepared 894-package DNF5 transaction. DNF5 history
  transaction `70` reports `Ok`, Security Center matched it and reports
  `COMPLETE`, and the next boot is running kernel `7.1.13-200.fc44.x86_64`.
  This is development evidence, not clean-image or release acceptance.
- Production now includes a root-owned two-day system-update timer. It uses a
  read-only DNF5 check, the existing fixed recovery/update helper, native
  offline preparation, and a desktop notification for restart-required state;
  it does not auto-reboot or update firmware/Flatpaks without an explicit
  Update Center workflow. Clean-image runtime validation remains pending.
- Telemetry history now keeps the live OpenSnitch working set separate from a
  bounded per-user SQLite investigation store and longer-lived semantic events;
  root collectors hand off approved events through a bounded runtime spool.
- The image boundary has `environment/image/build.sh` for production staging
  and `environment/image/build-iso.sh` for an internal alpha installer ISO.
  The current source design uses Fedora boot/netinst media and starts Anaconda
  directly: there is no live desktop, temporary account, GDM hand-off, or
  `liveinst` wrapper. Anaconda owns language, storage encryption, account
  creation, and the native post-install reboot. The production stage embeds
  the current Security Center, GREYWARD session, and production applications;
  offline finalization is retryable on the installed system. The
  production stage requires a Security Center source/RPM manifest and validates
  its package-owned file contract before image construction. A fresh direct
  installer ISO and clean install still require runtime validation; no release
  ISO or release claim exists.
- The former Security Center Session 10 report is retained as dated validation
  evidence, not as a project-wide release gate. Its unfinished checks remain
  useful test targets; the Network Activity interaction cluster now has
  real-Tauri WebDriver evidence. See
  [the historical report](security-center/SESSION_10_REPORT.md).
- The project and Security Center remain under active development. This is not
  an ISO, certification, or release-readiness statement.
- The canonical DMS taskbar includes the first-party GREYWARD Network Traffic
  plugin, backed by the shared DMS `DgopService` network sampler and routed to
  Security Center Network Activity on click.
- The adjacent Network Identity pill shows distinct public and local IPs. Its
  HTTPS public lookup is fresh and memory-only, and a persistent switch loaded
  before startup timers lets the user stop every provider request until they
  manually re-enable it. The canonical DMS user service also blocks the pinned
  upstream backend's separate cleartext `ip-api.com` startup seed locally, so
  it neither phones home nor adds the former timeout delay.
- The canonical DMS taskbar now uses `AppsDock` for the merged pinned/running
  application model. DMS owns application identity, grouping, persistence and
  pin ordering; GREYWARD only seeds the initial Software pin and localizes the
  pin/unpin wording to taskbar terminology.
- Feodo threat blocking is implemented in the Security Context/OpenSnitch path:
  the package contains the fixed official-feed updater, deterministic threat
  precedence, narrow application exceptions, activity metadata, notifications,
  and the Security Center Threat Protection view. Fixture and Fedora service
  checks pass. As of 2026-09-06, `.149` has the development-source iteration
  active with the updater timer running; this is development evidence, not
  packaged-release or clean-image acceptance.

## Planned or incomplete

- GREYWARD is in alpha/beta development. Most major implementation defects are
  closed; intensive bare-metal, recovery, failure-path, and edge-case testing
  still separates the current system from a public release claim.
- The previous live-account hand-off design is retired. The direct installer
  creates the only user through Anaconda, and the first-boot finalizer only
  completes local production provisioning. It masks both system
  and GNOME user Initial Setup units, verifies that a usable human account
  exists, runs production acceptance, and only then releases the greetd/DMS
  display-manager gate. The observed live v7 runtime still failed with a
  Quickshell crash and an Initial Setup `Initializing...` loop; that is
  historical failed evidence and not a validation of the direct design.
- On 2026-08-30, the alpha session's Security Context user-bus service answered
  `GetShellSummary` and reported `REVIEW NEEDED` with two review items. This
  confirms the typed service path is available; the DMS visual rendering and
  end-to-end acceptance remain open and are separate from the ISO lifecycle
  fixes. Corrective ISO v6 content was built and hash-verified on Alpha;
  clean-install, first-boot, and post-reboot runtime validation remain open.
- The internal alpha ISO path is implemented under `environment/image/`; it is
  designed for standalone installation, unsigned, hardware-unvalidated, and not a release ISO
  pipeline. The new source has not yet been proven by a clean VM installation;
  the old live-composed v7 runtime remains failed evidence only.
- A direct installer artifact was built on Alpha from the synchronized source:
  `greyward-direct-installer-20260905.iso`, SHA-256
  `c1aa51a69b7a89e82921391e8133dd619564d2b782bcbad6665be97d4a35a96d`.
  ISO content inspection passed; clean installation and first-boot runtime
  validation remain open.
- Booting or promoting a Btrfs recovery point has not been productized.
- The 2026-09-06 offline DNF5 transaction completed, but runtime observation
  found that the custom Plymouth theme stayed on `Starting GREYWARD` while DNF5
  worked. The source now enters Plymouth update mode and supplies explicit
  install/power/progress feedback. A user-run update reboot is still required to
  validate that presentation; it was intentionally not repeated while applying
  the patch. A graphical Polkit-agent observation is also still required to
  record the exact single-prompt interaction on a clean installed session;
  repository tests enforce one `pkexec` invocation and the non-cached
  `auth_self` policy in the meantime.
- GPU, Wi-Fi, Bluetooth, microphone, camera, removable-media, and other
  physical-device acceptance remain environment-dependent work.

## Status vocabulary

“Implemented” means repository code or configuration exists. “Validated” means
the named test or runtime check actually ran. “Planned” or “deferred” is not a
product capability and must not be described as shipped behavior.

## Next safe work

Normal development enrollment and core grant/denial/revocation are validated.
Automatic production lifecycle and unsupported providers remain separate work. The following broader image work is
a separate backlog, not authorization to alter an active installer VM.

1. Build and clean-install the current internal alpha installer in Hyper-V,
   then validate
   Anaconda account creation, native reboot, greetd/DMS login, portals, Polkit
   and the production acceptance contract. Repeat the minimum boot/provisioning
   gate on bare metal; VMware is not a target gate.
2. Exercise Security Center on clean installations and bare metal, prioritizing
   privilege boundaries, VPN/DNS coexistence, unavailable providers, recovery,
   failure paths, and the remaining checks in the historical Session 10 report.
3. Build a Fedora image input set and retain exact package/COPR/Flatpak/license
   artifacts before making any release-readiness claim.
