# GREYWARD current status

This document answers “what is true today?”. It is a status summary, not a
replacement for the domain specifications listed in [INDEX.md](INDEX.md).

## Implemented or active

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
  but it is development-contaminated (`stendev`, SSH and development services)
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
