# GREYWARD repository map

The current publication artifact contract is
[`patch-notes/0.5.0-dms2-rc3.md`](patch-notes/0.5.0-dms2-rc3.md): exact ISO
identity, package tuple, validation limits and later-source differences.
`tools/public-export.py` also masks Windows paths written with either separator;
`tests/test_public_export.py` covers this. `.gitleaks.toml` permits only the
exact pinned upstream Polkit preimage hash, not arbitrary credentials.
Path-scoped scanner exceptions target named rules and combine path/content with
AND; the publication tests prevent whole-file exclusions. The public ISO guide
templates document explicit DMS 2.0 selection without changing the active
validated manifest.

Security/privacy notification transitions: `security-center/security-context/greyward_security_context/security_notices.py`
owns verified Update Center notices and optional per-application sensor starts. `shell_runtime.py` composes
them, `notification_router.py` owns deduplication/daily delivery, and the existing
Security Center Privacy page owns the boolean preference through typed Rust and
session-bus calls. The canonical contract is
[`LIVE_PRIVACY_CAPSULE.md`](security-context/LIVE_PRIVACY_CAPSULE.md#security-and-privacy-notifications);
tests are `test_security_notices.py`, `test_notification_router.py`,
`test_shell_runtime.py` and `tauri/frontend/ux-contract.test.mjs`.
`environment/production/security-center-contract.tsv` requires the new session
notification module in imported RPMs, image composition and installed acceptance.

Offline firewall health is collected in the Rust backend `adapters.rs` through
the fixed `GetFirewallState` read in `security-center/security-context/greyward_security_context/network_policy_service.py`.
The existing system-bus policy permits that read for ordinary callers; mutations
still require the existing administrator review and Polkit path.
`security-context/tests/test_network_authorization.py` covers the bounded read
and provider failures; Rust network collector tests cover absent/failed links
without calling the authorization-triggering desktop state command. The
contract is in `docs/security-context/LIVE_PRIVACY_CAPSULE.md`.
The explicit Fedora `tests/test_offline_firewall_boundary.py` runs an extracted
posture executable as an ordinary user in a network namespace, with a private
bus forwarding the packaged read method to the real host firewall. It samples
four refreshes and provider loss without altering the installed desktop.

Protected lock wallpaper and native styling are selected by
`security-center/packaging/application-security/desktop/materialize.py`.
The authentication assembler pins and adapts the 2.0 settings/theme loaders to
read one immutable profile, and bypasses the native GPU blur layer only for
software rendering. `tests/test_lock_wallpaper.py` exercises the actual native
lock against an unavailable folder worker; `test_authentication_input_focus.py`
provides its isolated display/profile fixture. The contract and evidence limits
are in `docs/security-center/PRIVILEGE_MODEL.md` and `docs/STATUS.md`; the native
command is in `security-center/README.md`. Existing source-aware image checks
bind both packaged Python inputs, preventing JSON-only or stale-assembler fixes.

Protected Polkit presentation is owned by
`security-center/packaging/application-security/authentication/assemble.py`:
one Obsidian/Platinum card, canonical SVG paths compiled into synchronous shapes,
scrollable plain-text requests and keyboard/mouse actions for input and mirrored
outputs. Mirrors cancel the shared flow without needing the input controller.
The contract is
in `docs/security-center/PRIVILEGE_MODEL.md`; the explicit native checks are
`tests/test_authentication_input_focus.py` and
`tests/test_authentication_presentation.py` (commands in `security-center/README.md`).
`environment/image/verify-usbguard-inputs.py` also refuses a missing or stale
authentication emblem; the existing per-file negative controls in
`tests/test_usbguard_release_inputs.py` cover that input. See status for the
distinction between isolated rendering, prepared packages and live activation.

DMS 2.0 migration authority: `docs/architecture/DMS_2_0_MIGRATION.md`.
The RC3 composition and Windows media evidence are recorded in `docs/STATUS.md`;
that candidate does not establish fresh-install or hardware acceptance. RC2's
offline failure is retained there as historical diagnosis.
`environment/image/build-iso.sh` and `build.sh` own explicit `--dms-candidate`
composition: candidate receipt and plugin sources are selected together, while
`verify-usbguard-inputs.py` checks the selected receipt and helper sources.
`tests/test_usbguard_release_inputs.py` covers explicit candidate receipt selection
and stale-input refusal. The default validated release is not implicitly promoted.
`test_image_offline.py` also executes the stager's package-contract reader with
CRLF input and a missing-payload negative control; inventory readers normalize
Windows line endings before comparing Linux package paths.
`tools/greyward-dev/desktop-baseline.py` owns metadata/private recovery capture;
`desktop-performance-gate.py` owns comparable-evidence regression decisions.
Tests: `python -m unittest discover -s tests -p 'test_desktop_migration_evidence.py'`.
These tools do not activate a desktop or establish release acceptance.
The separate `environment/production/dms-2.0-candidate.json`,
`environment/patches/dms-2.0/`, `environment/session/dms-2.0/` and
`packaging/greyward-dms/toolchain.py` own candidate source, managed settings and
pinned build tooling. `tests/test_dms_candidate.py` guards incomplete-selection
refusal/toolchain inputs; explicit Linux `test_dms20_shell.py` and
`test_authentication_input_focus.py` use private headless displays. The protected
adapter remains in the canonical authentication assembler; its 2.0 pins and
native-control adapter do not establish installed-session acceptance.
`desktop/materialize.py` owns the versioned protected profile and schema;
`packaging/greyward-dms/assemble.py` binds the candidate manifest schema to the
pinned native settings declaration. `test_dms20_shell.py` additionally compares
the actual shell declaration against the protected profile, closing constant-only
fixture agreement. The schema-corrected revision-7 successor is active with fresh
seat/schema readback passing; physical acceptance remains pending (see current status).
`desktop/session.py` and `prepare.py` consume it using the verified generation.
The clipboard/profile and desktop fixtures cover both generations, alias
refusal and preservation of legacy input.
Candidate first-party surfaces live in `environment/session/dms-2.0-plugins/`;
`greywardSecure/SecurityClient.qml` is the single ordinary observer/action owner,
with native taskbar, dashboard and launcher adapters.
`greywardSecure/StatusModel.js` owns conservative read-only card rendering and
`StatusCard.qml` owns responsive layouts; `StatePalette.js` is generated by the
canonical desktop palette tool. Tests: `node --test tests/dms-security-cards.test.mjs`,
`test_desktop_palette.py` and the explicit native `test_dms20_plugins.py`.
`SecureWidget.qml` sizes its taskbar emblem four pixels above the native bar
icon size; content measurement accommodates it without another pill layer.
The client preserves rich evidence only within its original lease on positive
aggregate fallback; negative findings remain immediate. The native fallback
fixture covers expiry, pending actions and aggregate-only card rendering.
`docs/STATUS.md` distinguishes the supplied R6 session presentation from its
separate root-fallback capture: no visible flapping is now user-reported, but
the status paths have not been shown to agree. This is RC1 installed evidence,
not acceptance of the undeployed follow-up packages.
The same native suite also loads the generated theme through DMS's actual
custom-theme loader and checks the resolved reference dark surface roles.
The card model keeps filtering status primary and projects VPN as optional,
secondary information. `shell_summary.py` owns the bounded VPN projection from
fresh existing root DNS/link observations; `shell_experience.py` exposes the
closed state vocabulary without interface names. Their Python fixtures cover
split VPN, observed absence, stale/malformed data and protection independence.
`greyward-security-backends/src/adapters.rs` owns known-disconnected collection
and independent live-firewall readback; `facts.rs` defaults legacy absence to
unconfirmed and `policy.rs` evaluates that typed evidence. Rust collector and
policy fixtures distinguish offline from failed providers. The overall posture
evaluator remains unchanged.
The Center/AppSec RPM specs rebuild first-party release artifacts explicitly
while retaining third-party dependency caches. `test_security_package_builds.py`
executes their Cargo directives against intentionally stale executable outputs;
installed payload/compiled-helper canaries remain separate acceptance evidence.

Package-only DMS revisions are declared by `build.rpmRelease`; the DMS builder,
Enrollment dependency and image component identity guard consume that same pin.
`test_dms_build_inputs.py` executes the actual spec/dependency generators.
`environment/session/greyward-dms` keys the ordinary QML disk cache by the
verified receipt digest, preventing old compiled plugins surviving fixed RPM
timestamps. `tests/test_dms_qml_cache.py` executes the wrapper through the kernel
and checks same-mtime upgrades, warm reuse and preservation. Its optional
`GREYWARD_QML_CACHE_NATIVE=1` private Quickshell replay reports unavailable cache
generation explicitly; installed cache mappings are separate evidence. Session
owns this ordinary wrapper; protected authentication is unchanged.
The visual successor is activated for physical review and remains a release candidate. Candidate presets live in
`environment/session/dms-2.0-defaults/`, installed by the matched candidate Session RPM. The existing
state/session migration scripts own four-root backup/readback, previous-copy
reconciliation and preference preservation. `test_dms20_plugins.py` and
`test_dms20_state.py` cover isolated native views and the real unprivileged CLI.
`experience.json` also owns the portable physical appearance preset, applied
only to new accounts. `greyward-native-plugin-appearance.patch` forwards the
native widget Background option into both PluginComponent pills and selects
the standalone gear in `environment/session/dms-2.0/assets/` for Settings.
The native plugin fixture exercises both background states and retention of
last-known network identity during refresh; the state fixture covers exact
factory geometry/options and preservation of established user layouts.
`greyward-dms-session-migrate` seeds the native `dms_settings` taskbar pin only
for fresh DMS 2.0 lists; Session 34 owns the helper. Existing lists and legacy
generation defaults are preserved. The Bash/jq state fixture checks both
generations; image staging compares the actual packaged helper to source.
`desktop/materialize.py` owns the protected lock wallpaper selection, covered
by `test_application_authentication.py`; ordinary preferences cannot override it.
`production/packages.txt`, `flatpak/default-applications.list`, `baseline.py`
and `build-offline.py` define the reduced application selection and prevent
retired packages from re-entering through captured floors or installer groups.
These candidate source paths do not change the active 1.6 profile or authorize
publication, installation, session changes or ISO composition.
The separate physical-trial manifest explicitly retains incomplete release
acceptance. `packaging/greyward-dms/verify.py` validates that classification and
the installed dependency tuple; it does not authorize the activation window.
Strata security actions use the native literal-argv manifests under
`environment/session/desktop/actions`, seeded without overwriting preferences
by `greyward-files-seed`. The existing file-context companion owns bounded
Safe Open/scan dispatch. Tests: `tests/test_strata_file_actions.py`.
`packaging/greyward-files/pcmanfm-strata-routing.patch` keeps the desktop private,
routes folder opens to Strata and packages only private Qt translations; it
does not generate a second public file-browser launcher. The RPM/build helper
share one explicit Cargo target. `tests/run_desktop_outputs.py` and its linked
native driver test routing and output ownership in a private Wayland seat.
Equivalent GIO/Qt URI encodings must resolve to the exact synthetic destination.
`environment/session/desktop/strata-launcher` is the canonical public wrapper.
Its LF checkout attribute and Files RPM normalization prevent a Windows CR from
entering the kernel interpreter path. `tests/test_files_launchers.py` exercises
the source and packaged wrapper with literal argv and a CRLF negative control;
the Files spec runs it against the staged payload before accepting the RPM.

Public source validation: `.github/workflows/source-validation.yml` owns the
repository, frontend, Python, Rust and secret-scan gates. The migration fixture
in `tests/test_dms_shell_migration.py` retains real label copying on SELinux
hosts and emulates only that boundary on non-SELinux CI; a failed-copy test
requires the original file to remain unchanged. Production label enforcement
is unchanged. `tools/public-export.py` and `tests/test_public_export.py` own
private-host redaction and byte-preserving source export.

Corrected 0.4.5 candidate inputs: the Application Security and Enrollment specs
own the candidate matched 70/61 dependency pair; Files 18 owns the multi-output
desktop. Session 23 rebuilds canonical LF defaults for exact image staging.
`environment/image/verify-usbguard-inputs.py` accepts exact LF/CRLF
representations of canonical Go source in reviewed helper receipts, while
rejecting missing or changed source evidence. Validate with
`tests/test_usbguard_release_inputs.py` and `tests/test_image_offline.py`.
The 0.4.5 media gate passes. The same Files 18 RPM was installed on `<validation-host>`
with clean RPM verification before the later Files 19 migration trial; physical
placement remains a separate check. Installed/physical acceptance remains tracked in
[current status](STATUS.md) and [ISO creation](architecture/ISO_CREATION.md).

ISO package provenance and the explicitly non-source-rebuilt `<validation-host>` test import
are owned by `environment/image/build.sh` and
`environment/image/validate-installed-rpm-import.py`; installed header checks
live in `environment/production/production-acceptance.sh`. Validate with
`tests/test_installed_rpm_import.py`, `tests/static.ps1`, and
`tools/validate-repository.ps1`. Contract: [ISO creation](architecture/ISO_CREATION.md).

The first-boot login boundary and account preparation order are owned by
`environment/image/installer.ks.tmpl`,
`environment/production/provision-firstboot.sh` and
`environment/production/provision.sh`, with final checks in
`environment/production/production-acceptance.sh`. The account's final shell
is selected before enrollment without starting user processes; enrollment is
prepared while the account is quiescent, then `configure-zsh.sh` performs the
user-owned Git setup. Greetd, Fedora's display manager/GDM, GNOME Initial Setup
and the per-user systemd manager stay gated until enrollment and acceptance
complete. Unit ordering alone does not keep a failed installation private.

The [post-0.3.8 bare-metal follow-up](patch-notes/post-0.3.8-bare-metal-follow-up.md)
records the physical test configuration, confirmed results, and next-ISO
acceptance gaps. Canonical source ownership remains with the paths below.

Security Center status and firmware HSI presentation: `security-center/security-context/greyward_security_context/shell_experience.py` gives the ordinary-session DMS widget a bounded display-only refresh grace without extending `fresh_until`; `environment/session/dankmaterialshell/plugins/greywardSecure/SecureWidget.qml` uses the read-only `ApplicationSecurity1.GetSystemPosture()` aggregate when the protected compositor's private session bus has no Context owner, and labels stale evidence as refreshing without attention/actions. `security-center/crates/greyward-application-security/src/development_bus.rs` owns the bounded system-bus projection; `security-center/crates/greyward-security-backends/src/adapters.rs` reads current `SecurityAttributes` only (not historical `SecurityEvents`), `src/presentation.rs` carries measured HSI differences into `security-center/tauri/frontend/app.js`, and firmware settings remain user-controlled. The pre-migration `<validation-host>` deployment was Security Center 115 / Context 108 / DMS 1.6.2-26 / Application Security 69 / Enrollment 60; current trial versions are in [status](STATUS.md). HSI live presentation and ISO validation remain pending. Validate with the broker tests, `security-center/tauri/frontend/ux-contract.test.mjs`, `tests/static.ps1`, and `tools/validate-repository.ps1`. See [live taskbar presentation](security-context/LIVE_PRIVACY_CAPSULE.md), [backend contract](security-center/BACKENDS.md) and [current status](STATUS.md).

Login display and Polkit input ownership: environment/production/dms-greeter-ui is the pinned DMS Greeter shell selected by environment/production/provision.sh; it renders one surface per Wayland output and exposes a keyboard-accessible username correction action. environment/production/greyward-start-dms-greeter explicitly selects GLES2 on physical systems to match the protected compositor's validated cross-GPU path, retaining Pixman only for known virtual GPUs or missing DRM render nodes. security-center/packaging/application-security/authentication/assemble.py styles the protected authorization prompt and keeps one real password field while mirroring masked input feedback across protected outputs. Production acceptance and tests/test_dms_greeter.py / tests/test_application_authentication.py guard the selected UI, renderer boundary and input ownership. The source UI and launcher are now deployed on <validation-host>; the greeter loaded the external shell, but the latest DRM snapshot exposed only the built-in panel, so three-screen behavior still requires a connected-output check. See [desktop architecture](architecture/ARCHITECTURE.md) and [current status](STATUS.md).

Protected Polkit multi-display entry: `security-center/packaging/application-security/authentication/assemble.py` gives one protected field ownership of the password and mirrors the same bounded GREYWARD card, masked character count, request summary and actions across the other protected outputs. `desktop/session.py` applies the layout selected during installation to the protected compositor without displaying the layout in Polkit. `tests/test_application_authentication.py` and `tests/test_protected_keyboard_layout.py` guard the display and input contracts. The earlier `<validation-host>` baseline installed Application Security 69 / Enrollment 60 with DMS 1.6.2-26; the later physical trial is tracked in [status](STATUS.md). Physical three-screen visual confirmation remains pending. See [current status](STATUS.md).

Wi-Fi/Bluetooth firmware ownership: `environment/production/packages.txt` is
the single package-selection source; `environment/image/build-offline.py`
resolves its Fedora-signed dependency closure; `environment/image/validate-production-stage.sh`
rejects declared firmware missing from Anaconda's selection;
`environment/production/production-acceptance.sh` checks the same installed
manifest; `tests/test_image_offline.py` locks the supported family set. See
[production setup](../environment/production/README.md),
[hardware testing](../HARDWARE_TESTING.md) and [current status](STATUS.md).

Protected-seat verification ownership: `security-center/packaging/application-security/desktop/verify.py` compares the installed confined role with the saved enrollment receipt. It allows only the reviewed `greyward_usbguard_approval_t` helper outside ordinary coverage, and only admits its exact executable, SELinux context, UID and active session cgroup. `desktop/ordinary-policy.py` owns fresh-enrollment attribute generation and excludes that helper and the display domain from ordinary applications. `tests/test_application_security_verification.py` covers the generated CIL/JSON against the verifier, additions/removals and helper identity boundaries. `environment/image/verify-usbguard-inputs.py` checks the generator/verifier RPM payload on source-built and imported image paths; `tests/test_usbguard_release_inputs.py` guards stale payload rejection. The `<validation-host>` verifier passed against the active kernel policy; R6's offline policy/receipt repair now passes six live verifier readbacks with SELinux Enforcing. Clean-install acceptance remains separate. The exact installed evidence is recorded in [status](STATUS.md).

Network Rules presentation and provider ownership are defined below. Current
installed evidence and acceptance limits are maintained in
[network rules](security-context/NETWORK_RULES.md).

Network idle/heartbeat health belongs to
`security-center/security-context/greyward_security_context/user_bus.py`:
it distinguishes a quiet event stream from a disconnected OpenSnitch daemon by
checking the root-only GREYWARD control socket's established peer and the two
system services. `test_network_protection.py` and `test_user_bus.py` guard both
the idle and disconnected states. The RPM declares `iproute` for the `ss`
socket probe. See [OpenSnitch](security-context/OPENSNITCH.md).

Protected Data status wording belongs to
`security-center/tauri/frontend/application-view.js` and `i18n.js`: only a
verified required baseline receives the portal/deputy limitation; degraded
coverage names the missing required checks. The UI contract is
`application-view.test.mjs`; current rules are in the
[UX specification](security-center/UX_SPEC.md).

Network-rule ownership: Context `network_rules.py` defines normalization,
matching and storage; `network_rule_transactions.py` owns reviews/lifecycle;
`network_firewall.py` owns native readback/rollback and lazy, name-owner-following
firewalld D-Bus proxies, so an early boot race or daemon restart does not leave
the incoming provider permanently unavailable. The unprivileged
`network_applications.py`, called by `user_bus.py`, owns the installed desktop
name/icon catalog; it grants no authority and never launches entries. `network_policy_service.py`,
`user_bus.py` and named Tauri commands preserve the root boundary. Frontend
`network-rules.js`/`.css` own presentation. The Center launcher in
`security-center/data/greyward-security-center-launch` owns display-only Hyper-V
renderer selection; `test_network_packaging.py` covers the driver decision.
It changes this application's paint path, not the compositor or permissions.
The Context RPM installs
`org.greyward.NetworkRules1.policy`. Validation: Context `test_network*.py`,
frontend `network-rules.test.mjs` (including complete HTML-order bootstrap) and
UX contracts. Executable-line normalization
belongs to the two Security Center/Context specs and spec-copy normalization to
`environment/development/build-security-center.sh`; `test_network_packaging.py`
protects scripts without corrupting binary assets. The Context spec defers
coupled engine activation. The installed `<validation-host>` packages are Center 115 / Context
108; Center 111 / Context 105 is historical. RPM verification and package/source
tests pass, and the Network Rules catalog was read back on `<validation-host>`. Authority:
[network rules](security-context/NETWORK_RULES.md).

Security Center taskbar multi-display ownership: `environment/session/dankmaterialshell/plugins/greywardSecure/SecureWidget.qml` scopes every `Proc.runCommand` callback ID to `parentScreen.name` and a per-widget token because the DMS process service is shared across output bars. Each display keeps its own status completion and action feedback while using the same Security Context service. `tests/test_application_authentication.py` and `tests/static.ps1` reject fixed cross-display IDs. The user confirmed Security Center and Network Identity widgets work across the external displays after the DMS migration. See [live taskbar presentation](security-context/LIVE_PRIVACY_CAPSULE.md) and the [bare-metal follow-up](patch-notes/post-0.3.8-bare-metal-follow-up.md).

Native window-placement ownership: `environment/session/labwc/rc.xml`, packaged
by `packaging/greyward-session/` and copied into enrolled compositor inputs by
`security-center/packaging/application-security/desktop/prepare.py`. Validation:
`pwsh -NoProfile -File tests/static.ps1`, the Session RPM source comparison in
`environment/image/build.sh`, and separate installed gesture acceptance.
Authority: [native window placement](architecture/WINDOW_MANAGEMENT.md).

Native file-icon integration ownership: `packaging/greyward-files/strata-native-icons.patch`,
`strata-preview-mode.patch`, pinned `source.json`, offline `prepare-vendor.py`
and `environment/session/desktop/strata-launcher`. Shared semantic artwork is
owned by `branding/source/greyward-icon-family.json` and
`tools/generate-file-icons.py`. The derived executable uses native MIME/launcher
artwork and the existing isolated per-operation renderer. Validation:
`python -m unittest discover -s tests -p 'test_file_icon_family.py'`, offline
RPM `%check` and separate installed desktop acceptance. Files 17 is installed;
normal-window icon/preview and synthetic file/Trash checks pass, as do installed
helper/registered-secret denials. Remaining migration/image gates stay explicit. Authority: [file manager integration](architecture/FILE_MANAGER_DESKTOP.md).

Preview runtime dependency ownership: `packaging/greyward-files/greyward-files.spec`
declares the pinned upstream helper's external commands as RPM file requirements.
Validation combines offline RPM construction/readback, installed sandbox-helper
operations and the separate pending normal-window acceptance. No new parser,
daemon or policy allowance is introduced. Authority:
[file manager desktop integration](architecture/FILE_MANAGER_DESKTOP.md).

Icon consistency correction ownership remains the canonical family catalog,
`tools/generate-file-icons.py` and `packaging/greyward-files/`. Extension names
map to whole native MIME assets; the icon-only overlay includes the embedded
application icon. `test_file_icon_family.py` checks exact cross-consumer artwork
and removal of legacy extension marks. Files 14 retains those assets. Reopened
normal-window folder/text comparison passes; launcher GIcon resolution and ODT
thumbnails are outside the icon-only overlay and remain unsupported by the
pinned Strata renderer. Whole-interface acceptance is pending. Authority:
[file manager desktop integration](architecture/FILE_MANAGER_DESKTOP.md).

Native lock handoff ownership: `environment/session/greyward-dms-state-migrate`,
`greyward-session-lock`, `greyward-dms-runtime-check` and `packaging/greyward-session/`.
The kernel subject selects the existing broker handoff; surface ordering never
claims private lock security. Private Qt clipboard suppression belongs to
`security-center/packaging/application-security/desktop/session.py`. Validation:
`python -m unittest discover -s tests -p 'test_dms_migration.py'`,
`test_dms_runtime.py`, `test_application_desktop.py`, installed Qt registry probes
and the pending real lock/PAM retry. Authority:
[file manager desktop integration](architecture/FILE_MANAGER_DESKTOP.md).
The matched candidate is installed and its protected runtime refreshed after
approved session closure. New-session lock/PAM and stability acceptance remain
pending. No new locker, daemon or policy allowance is introduced.

Candidate desktop-only routing is the pinned third native patch in
`packaging/greyward-files/pcmanfm-strata-routing.patch`. It rejects public browsing
arguments, routes folders to literal Strata URI argv and installs translations
privately. Native routing/output acceptance is being built; the installed
reference still retains its validated packages. Enrollment candidate dependency
selection is explicit in `packaging/greyward-enrollment/build.sh`; its default
continues to use the production DMS receipt.

Shared desktop palette ownership: `branding/source/greyward-desktop-palette.json`
and `tools/generate-desktop-theme.py` generate the DMS dark/light roles, Strata
Obsidian/Silver themes, private desktop Qt palette and Security Center dark
`security-center/tauri/frontend/theme-tokens.css`. Material/interaction treatment
remains in `materials.css`; this does not add a Security Center light mode.
The palette's closed `dms.dark` role overrides retain the observed reference's
darker native shell surfaces without changing application surfaces. Session owns
the actual `/usr/share/greyward/dms/greyward-obsidian.json`, its factory copy and
the reference Overview grid. Candidate image staging checks all three payloads;
the explicit `GREYWARD_SESSION_RPM` fixture tests real RPM readback and stale
theme/preset refusal in `test_image_offline.py`. It reads the closed set together
so identical RPM hard-link members are verified correctly.
Validation: `python tools/generate-desktop-theme.py --check`,
`python -m unittest discover -s tests -p 'test_desktop_palette.py'` and
`test_desktop_defaults.py`. Migration/installed visual acceptance remains
explicit in [DMS 2.0 migration](architecture/DMS_2_0_MIGRATION.md).

Shared icon-family ownership: `branding/source/greyward-icon-family.json`,
`tools/generate-file-icons.py`, desktop-only QIcon selection in
`environment/session/desktop/style/obsidian.cpp`, and the icon-only Strata
resource overlay selected by its existing launcher. `packaging/greyward-files/`
generates/packages assets and their ISC/MIT notices. Validation:
`python -m unittest discover -s tests -p 'test_file_icon_family.py'`, offline
package/installed-resource checks and real desktop/column/grid comparison.
Authority: [file manager desktop integration](architecture/FILE_MANAGER_DESKTOP.md).
Revision 11 corrects native theme selection and GIO folder naming. Overall
session/lock stability remains unresolved after the later 00:15 closure.

File manager/desktop migration ownership: `environment/session/desktop/`,
`environment/session/greyward-desktop-shortcut`, `greyward-files-seed`,
`greyward-desktop-icons.service` and `packaging/greyward-files/`;
`python -m unittest discover -s tests -p 'test_desktop_*.py'` and
[file manager desktop integration](architecture/FILE_MANAGER_DESKTOP.md).
The current ordinary-user Strata/PCManFM proof is separate from the earlier rolled-back
experiment below. Packaged startup and real DMS shortcut creation pass. The
0.4.0 candidate now includes Files 17, and composition plus independent media
closure checks pass; fresh-install behavior remains pending. The canonical file-manager icon is
`branding/source/greyward-files.svg`, owned by `packaging/greyward-files/` and
registered in `branding/manifest.json`. Earlier entries below are historical.

Multi-output icon placement ownership: `environment/session/desktop/output-layout.h`
and `packaging/greyward-files/pcmanfm-multi-output.patch`, pinned through
`source.json` and applied by the Files 18 spec. It owns one entry per named
output, native drag/menu placement, disconnected-screen fallback and restoration,
and Bottom-layer surface reconciliation above DMS wallpaper. Validation:
`tests/test_desktop_output_layout.cpp` in RPM `%check` and explicit
`tests/run_desktop_outputs.py` / `test_desktop_outputs.cpp` on a private headless
three-output seat, with PIE and Qt signal-binding gates. `environment/image/build.sh` checks the installed source
manifest against canonical input, including the layout header digest. `<validation-host>` has
a scoped native update over Files 17; the full Files 18 RPM and physical
acceptance remain pending.
Authority: [file manager integration](architecture/FILE_MANAGER_DESKTOP.md).

Desktop-only FileManager1 routing is scoped by
`packaging/greyward-files/pcmanfm-desktop-only.patch` and the pinned source
preimage in `source.json`. The existing `greyward-dms-runtime-check
--desktop-only` orders surfaces without asserting native-lock security;
`tests/test_dms_runtime.py` preserves the separate full-check contract.
Guardian exit diagnostics belong to the existing protected `desktop/session.py`
and `tests/test_application_desktop.py`; runtime 49/Enrollment 30 activate them
after the approved logout. Real paste reproduces an authentication-UI exit,
so the migration's stability acceptance remains pending. The subsequent native
private-clipboard configuration correction belongs to `desktop/materialize.py`
and `tests/test_authentication_clipboard.py`; ordinary clipboard settings and
mandatory guardian teardown remain unchanged. Runtime 50/Enrollment 31 activate
the configuration; real reverse paste passes without losing authentication.
Manual drag/drop passes with user confirmation and real-file/session checks;
the automated gesture is inconclusive and broader acceptance is pending.

13 October historical `<development-host>` plugin recovery: DMS 1.6.2-15, Application Security 45 and Enrollment 26 were installed as a matched tuple; Security Center 90, Security Context 81 and Session 16 remained installed. The DMS integrity check passed, the fixed `greywardSecure` plugin was loaded, its taskbar button had opening/success/failure feedback, and SELinux remained Enforcing. Only DMS was restarted; Labwc and the VM were not. DMS 14 restored the broken plugin; installed Enrollment 16 required exact DMS 14. This snapshot is superseded by the 14 October ISO candidate recorded in [status](STATUS.md) and [ISO build evidence](architecture/ISO_CREATION.md). The desktop-icon experiment remained rolled back.

12 October historical: R6 still started at 1024×768 with the previous 0.3.5 Dawn image
because its mode request was absent from the root-owned protected-compositor
autostart. A replacement candidate now includes that request for VM output
`Virtual-1`; Center 100, Context 92, Application Security 45 and Enrollment 22
were built as one matched set. Build and media checks pass; installed resolution
acceptance remains pending. See [current status](STATUS.md), the [monitor
configuration record](architecture/DMS_MONITOR_CONFIGURATION.md) and [ISO
build evidence](architecture/ISO_CREATION.md).

10 October: the user accepts the R5 installation/login fix. R6 is built, hash-verified on Windows and mounted in the existing R5 VM with the output-management commit 8c130a662b047a33406c695d54adf524cc302d99 and a greeter-only CPU OpenGL renderer correction for the canonical wallpaper. Private compiled-protocol and actual embedded-greeter rendering checks pass; installed R6 greeter and DMS apply remain pending. See the candidate evidence (private development evidence).

Earlier entries below are dated evidence, not current acceptance claims.

10 October r5 candidate: Enrollment 5 corrects the confirmed mode-0700 program-directory login failure. The repaired r4 installation reaches the desktop (user confirmation and console evidence). R5 composition, embedded payload checks and Windows SHA-256 verification pass; fresh r5 installation, default session selection and installed security acceptance remain pending. See the candidate evidence (private development evidence).

10 October installed r4 acceptance: installation completed according to the user, but GREYWARD Labwc login fails and the greeter defaults to Hyprland. R4 is not accepted. Only the new test VM is in an approved rescue investigation; <development-host> remains the unchanged build host. See the failure evidence (private development evidence).

10 October ISO rebuild: r3 failed clean installation because private installer-origin storage was missing; it is rejected. Enrollment revision 4 is rebuilt, eleven lifecycle tests pass, and the actual packaged broker reproduces the missing-directory failure then succeeds with corrected private storage in a synthetic clean root. The r4 ISO has built, passed payload checks, and hash-matched on Windows. It is attached to the new empty test VM without runtime activation on `<development-host>`. Clean-install acceptance remains pending. See the candidate evidence (private development evidence).

10 October enrollment ISO candidate: matched installer enrollment inputs are now
packaged without activating them on `<development-host>`. The copied offline SELinux store
links successfully and the packaged compositor digest matches. The build host
remains the running development system. Candidate composition has passed;
clean-install, graphical enrollment and encrypted recovery acceptance remain
pending on the separate test VM. See the [enrollment authority](security-center/APPLICATION_SECURITY_ENROLLMENT.md).

The earlier 10 October blocker receipts below are historical snapshots; their
pre-assembly NO-GO findings are superseded only by the scoped checks recorded
above, not by production acceptance. See the candidate evidence (private development evidence).


The enrollment-required readiness receipt (private development evidence)
traces authentication assembly and installer/recovery packaging gaps. Existing
Application Security and image owners remain canonical; no new activation path
is introduced.


Enrolled session admission is routed by `environment/production/greyward-start-labwc`
through the existing protected login selector; `tests/test_session_admission_route.py`
checks the route and no-fallback failure contract. The `greyward-session` RPM
normalizes this executable to LF at install time so a Windows-built source archive
cannot break the kernel shebang. See the
session-9 recovery receipt (private development evidence).

The final ISO blocker audit (private development evidence)
owns the current DMS toolchain correction and release integration evidence;
`tests/test_dms_build_inputs.py` checks receipt drift and upstream checksum refusal.

The 10 October preparation receipt (private development evidence)
records publication filtering, source candidate revisions, local policy compilation
and the ISO storage/acceptance decision. Current build ownership remains in the
existing image/package rows; experimental enrollment is not promoted.

The source-only truthfulness receipt (private development evidence)
records the narrow ClamAV provider and coverage/VPN/accepted-limitation/grant
presentation correction. Ownership remains in the existing File Security,
Application Security, posture and Secure DNS rows below.


Use this table to find the first file to read for a scoped change. Paths in the
implementation, configuration, tests, and validation columns are checked by
the repository validator. If a task does not fit a row, update the nearest
canonical row or add one before creating a new implementation boundary.

| Feature | Implementation | Canonical documentation | Configuration/assets | Tests | Validation | Related |
|---|---|---|---|---|---|---|
| Product overview and README text | `README.md` | `docs/DOCUMENTATION_POLICY.md`; `docs/STATUS.md` | Existing README images, GIF, SVG and published-image links remain unchanged during text-only revisions | `tests/static.ps1`; `tools/validate-repository.ps1` | Repository gates; public-export review; check image tags/assets and download links against the prior version | `docs/INDEX.md`; `CONTRIBUTING.md`; `SECURITY.md` |
| Protected DMS authentication-shell compatibility | `security-center/packaging/application-security/authentication/assemble.py`; `security-center/packaging/application-security/greyward-application-security-experimental.spec`; `packaging/greyward-enrollment/greyward-enrollment.spec` | `docs/security-center/APPLICATION_SECURITY_ENROLLMENT.md`; `docs/architecture/ISO_CREATION.md` | Exact DMS receipt/file-map/shell-digest checks pin lock, PAM and Polkit; active Polkit authorization forces the native lock during Administration or lock retry; one protected field owns password entry, while all protected outputs mirror the same bounded card, masked length, request and actions; hotplug retargets the authoritative field; the installed XKB selection remains applied without being displayed; Enrollment requires the exact Application Security RPM | `tests/test_application_authentication.py`; `tests/test_protected_keyboard_layout.py` | Application Security 69 / Enrollment 60 installed on `<validation-host>`; focused tests and repository gates pass; protected migration to DMS 1.6.2-26 completed; physical three-screen visual acceptance and ISO validation remain pending | `docs/STATUS.md`; `environment/production/dms-release.json` |
| Security update availability in System checks | `security-center/crates/greyward-security-backends/src/adapters.rs` | `security-center/README.md`; `docs/STATUS.md` | A successful DNF5 security-only query returning `{}` means zero available security updates; malformed/unknown output and nonzero exits remain unverified | Parser unit tests in `adapters.rs` | DNF5 live readback on `<validation-host>` returned `{}` with exit 0; Security Center 115 installed; Fedora workspace tests and both repository gates pass | `security-center/crates/greyward-security-backends/src/presentation.rs`; `security-center/tauri/frontend/` |
| Public-source boundary, local Git maintenance and approval-gated publication | `tools/public-export.py`; `tools/export-public-repository.ps1` | `docs/PUBLICATION.md`; `AGENTS.md` | `tools/publication-policy.json`; `tools/publication-templates/` | `tests/test_public_export.py` | Publication boundary tests; static/repository gates; public CI and secret scan | Private originals/history must never be published or deleted by export |
| Protected Labwc renderer selection | `security-center/packaging/application-security/desktop/session.py`; `security-center/packaging/application-security/greyward-application-security-experimental.spec`; `packaging/greyward-enrollment/greyward-enrollment.spec` | `docs/architecture/DMS_MONITOR_CONFIGURATION.md` | GLES2 for capable physical systems; Pixman retained for authentication, known VMware/Hyper-V and systems without DRM render nodes; no user-controlled environment or SELinux-policy change | `tests/test_application_desktop.py`, `tests/test_protected_compositor_display.py`, `tests/test_dms_build_inputs.py` | Focused renderer-policy tests, package-pair checks, both repository gates, installed multi-GPU session validation | `environment/image/`, `docs/STATUS.md` |
| Installer-selected keyboard layout | `security-center/packaging/application-security/desktop/keyboard_config.py`; `desktop/prepare.py`; `desktop/session.py`; `environment/production/provision.sh`; `production-acceptance.sh`; `packaging/greyward-enrollment/migrate-dms-shell.py` | `environment/production/README.md`; `docs/security-center/APPLICATION_SECURITY_ENROLLMENT.md` | Validate Anaconda/systemd-localed's root-owned XKB record once at first boot; share its model/layout/variant/options with greetd, `/etc/skel`, the installed user's Labwc environment and the immutable protected-session receipt; never source user-writable Labwc environment files for protected defaults | `tests/test_protected_keyboard_layout.py`; `tests/test_dms_shell_migration.py`; `tests/test_image_offline.py`; `tests/static.ps1` | Keyboard parser and injection tests, migration receipt tests, both repository gates, fresh-install typed-layout acceptance | `environment/image/installer.ks.tmpl`; `<validation-host>` remains on its already-working French layout until a future provisioning/migration applies the generated settings |
| Bounded D-Bus inspection and root-review prerequisite | `tools/greyward-dev/application-security-bus-kernel-check.py`; `tools/greyward-dev/application-security-bus-compatibility.py`; `tools/greyward-dev/application-security-bus-review-check.py`; existing hybrid bus check | `docs/security-center/APPLICATION_SECURITY_PLAN.md`; `docs/history/security-center/2026-10-09-dbus-boundary-proof.md` | `spikes/application-security/selinux/greyward_session_bus_boundary.cil`; explicit reversible development module only | Live 62-domain kernel readback, ordinary mem-open/invalid-FD checks, native preview actor/stale/changed-object checks and installed Flatpak chooser | Python syntax, installed scoped probes, both repository gates; remove/reapply without restart | Portal request recipient binding remains NOT IMPLEMENTED; no grants or production activation |
| Bounded hybrid Flatpak proof (BLOCKED before grant/bridge integration) | `tools/greyward-dev/application-security-hybrid-bootstrap.py`; `tools/greyward-dev/application-security-hybrid-bus-check.py` | `docs/security-center/APPLICATION_SECURITY_PLAN.md`; `docs/history/security-center/2026-10-09-hybrid-flatpak-bootstrap.md` | `spikes/application-security/selinux/greyward_hybrid_flatpak_probe.te`; disposable separate-account root launch, no resource grant | Actual Fedora policy compilation/bootstrap and non-mutating normal-session bus inspection check | Syntax checks; repository gates; exact installed observations in receipt | Existing broker/grant/portal boundaries; no product provider or UI delivered |
| First-use Flatpak permission prerequisite (BLOCKED; no product grant provider) | `tools/greyward-dev/application-security-first-use-proof.py` | `docs/security-center/APPLICATION_SECURITY_PLAN.md`; `docs/history/security-center/2026-10-09-first-use-permission-proof.md` | Existing registered directory/system Flatpak; launch-local exposure; stock portal request closes itself | Actual enrolled negative namespace/resource/portal probes; no secret content reads or approvals | Run the documented probe as the enrolled user; repository gates | Existing root audit, reviewed grants and notifications; both end-to-end gates remain unpassed |
| Installer enrollment and first-boot handoff | `packaging/greyward-enrollment/enroll.py`; `packaging/greyward-enrollment/`; `environment/production/provision-firstboot.sh`; `environment/production/configure-zsh.sh`; `environment/production/provision.sh`; `environment/image/installer.ks.tmpl` | `docs/security-center/APPLICATION_SECURITY_ENROLLMENT.md`; `packaging/greyward-enrollment/README.md`; `docs/architecture/ISO_CREATION.md` | Six production SELinux modules and matched compositor receipt; root-owned installer account origin; choose the final shell as root, defer user-owned zsh/Git setup until enrollment prepare succeeds, verify no logind session and stop only an idle user manager, then recheck enrollment after zsh/Git setup; validate read-only `PENDING_SESSION` retries before the quiescence gate while keeping `PREPARING` and `PREPARED_INPUTS` quiescent; preserve schema/account/mapping/digest/enforcement/service readbacks on that retry; keep installed boot text-only until acceptance passes; log PID/process if enrollment refuses quiescence; first-boot readiness checks greeter-owned Labwc/Quickshell after the launcher exec and requires the existing seat verifier for a user handoff | `tests/test_installer_enrollment.py`; `tests/test_image_offline.py`; `tests/test_firstboot_login_boundary.py` | Focused lifecycle and image-path tests, RPM checks and copied offline policy linking; clean-install/recovery acceptance remains pending | Existing broker, protected authentication and Administration |
| Persistent protected-resource and graphical Flatpak recovery | `security-center/crates/greyward-application-security/src/resource_labeling.rs`; `environment/production/selinux/greyward-application-session.te`; `environment/session/dankmaterialshell/plugins/greywardPublicIp/PublicIpWidget.qml` | `docs/history/security-center/2026-10-08-session-resource-flatpak-recovery.md` | Resource label journal filesystem identity; descendant namespace policy; HTTPS retry cooldown | Resource-labeling filesystem reopen unit tests; `tests/static.ps1` | Fedora runtime package tests and actual normal desktop browser/coverage/denial checks | `security-center/packaging/application-security/greyward-application-security-experimental.spec` |
| Enrolled desktop clipboard transfer | `environment/production/selinux/greyward-application-display.te` | `docs/STATUS.md` (9 October terminal paste repair) | Compositor write to ordinary client FIFO only; no protected-file or grant-domain access | Actual Black Box Ctrl+Shift+V before/after; synthetic protected-key denial | Fedora SELinux policy compile/install; real VMConnect paste and surviving window; broker coverage | `docs/security-center/APPLICATION_SECURITY_ENROLLMENT.md` |
| Enrolled graphical login descriptor handoff | `security-center/packaging/application-security/desktop/login.py` | `docs/history/security-center/2026-10-08-enrolled-login-recovery.md`; `docs/security-center/APPLICATION_SECURITY_ENROLLMENT.md` | Protected authentication seat and selected root-owned DMS receipt | `tests/test_guard_login.py` | `python3 tests/test_guard_login.py` on Fedora; actual greetd login and protected-seat verifier | `packaging/greyward-dms/verify.py` |
| Application Guard and Protected Data user acceptance | `security-center/tauri/frontend/application-security.js`, `application-view.js`, `app.js` | `docs/security-center/USER_ACCEPTANCE_APPLICATION_GUARD.md`; `docs/security-center/APPLICATION_SECURITY_PLAN.md` | Prepared normal-user launcher fixtures on `<development-host>`; synthetic note and existing kernel-protected test key | User-run desktop scenarios in the guide; no harness | User checks Security Center state and kernel SELinux denial evidence; allowed reviewed-tool execution is limited by the missing Center launch action | Normal `<development-host>` enrollment receipt; production lifecycle remains unvalidated |
| Application Guard and Protected Data (normal development session enrolled; production lifecycle unvalidated) | `security-center/crates/greyward-security-domain/src/application_security.rs`, `security-center/crates/greyward-application-security/`, `security-center/security-context/`, `spikes/application-security/portal/`, `spikes/application-security/wayland/`, `security-center/crates/greyward-application-security/src/resource_selection.rs`, `resource_catalogue.rs`, `rpm_identity.rs`, `installed_content.rs`, `provider_inventory.rs`, `read_worker.rs`, `policy.rs`, `policy_intent.rs`, `store_intent.rs`, `resource_policy.rs`, `resource_registration.rs`, `resource_labeling.rs`, `managed_grant.rs`, `reviewed_launch.rs`, `policy_execution.rs`, `workflow.rs`, `development_bus.rs`, `guard_client.rs`, `isolated_launch.rs`, `bin/greyward-native-worker.rs`, `bin/greyward-guard.rs`, `bin/greyward-application-security-development.rs`, `selinux_readback.rs`, `native_restrictions.rs`, `payload.rs`, `private_display.rs`, `access_events.rs`, `bin/support/graphical.rs` in the same runtime source directory, `security-center/security-context/greyward_security_context/application_workflows.py`, `security-center/tauri/frontend/application-security.js`, `security-center/tauri/frontend/application-view.js`, `security-center/packaging/application-security/desktop/`, `security-center/packaging/application-security/authentication/assemble.py`, `security-center/crates/greyward-security-backends/src/rpm_metadata.rs`, `security-center/crates/greyward-security-backends/src/provider_process.rs`, `security-center/crates/greyward-security-backends/src/application_reads.rs`, `security-center/crates/greyward-security-backends/src/flatpak_permissions.rs`, `security-center/crates/greyward-security-backends/src/flatpak_inventory.rs` | `docs/security-center/APPLICATION_SECURITY_PLAN.md` (current implementation audit); `docs/security-center/APPLICATION_SECURITY_ENROLLMENT.md` (normal development enrollment validated; production lifecycle unvalidated) | `spikes/application-security/selinux/greyward_guard_probe.te`, `spikes/application-security/selinux/greyward_application_broker_probe.te`, `spikes/application-security/selinux/greyward_resource_grant_probe.te`, `spikes/application-security/selinux/greyward_managed_grant_probe.te`, `spikes/application-security/selinux/greyward_ui_probe.te`, `security-center/packaging/application-security/`, `environment/development/greyward-guard-isolation-host.cil`; installed public workflow broker on <development-host>, restrictive isolation for normal local users; protected policy changes require confined enrollment; policy/admission/upgrade/recovery design gates E0–E5 unpassed | `tools/greyward-dev/application-security-live-enable.sh`, `tools/greyward-dev/application-security-live-rollback.sh`, `tools/greyward-dev/application-security-feasibility.sh`, `application-security-probe.py`, `application-security-routes.sh`, `application-security-tty.py`, `application-security-headless.sh`, `application-security-session-check.ps1`, `application-security-portal-probe.py`, `application-security-authorization.py`, `application-security-flatpak.py`, `application-security-broker-mac.sh`, `application-security-native-worker.sh`, `application-security-resource-selection.sh`, `application-security-installed-content.sh`, `application-security-grant-scope.sh`, `application-security-grant-probe.py`, `application-security-grant-lifetime.py`, `application-security-deputies.sh`, `application-security-deputy-probe.py`, `application-security-keyring.sh`, `application-security-keyring-session.sh`, `application-security-wtype-input.sh`, `application-security-lock.sh`, `application-security-lock-session.sh`, `application-security-lock.py`, `application-security-read-transport.sh`, `application-security-wayland.sh`, `application-security-wayland-session.sh`, `application-security-policy-profile.sh`, `application-security-policy-intent.sh`, `application-security-registration-guard.sh`, `application-security-critical-session.py`, `application-security-critical-headless.sh`, `application-security-resource-policy.sh`, `application-security-resource-policy.py`, `application-security-safe-open.sh`, `application-security-safe-open.py`, `application-security-task-probe.py`, `application-security-pip-input.sh`, `application-security-pip-launch.py`, `application-security-pip-backend.py`, `application-security-ui-check.sh`, `application-security-ui-session.sh`, `application-security-ui-probe.mjs`, `application-security-ui-context.py`, `application-security-product-context.py`, `application-security-product-fixtures.py`, `build-application-security-experimental.sh` in the same tool directory | domain/runtime Rust suites and explicit ignored Fedora system-bus/authentication tests; `security-center/security-context/tests/test_application_workflows.py`, `security-center/tauri/frontend/application-workflows.test.mjs`, `security-center/tauri/frontend/application-view.test.mjs`; `security-center/crates/greyward-security-backends/tests/flatpak_provider.rs`, `security-center/crates/greyward-security-backends/tests/application_reads.rs`; isolated subject/session/portal/rollback gates; repository static/documentation checks | `spikes/application-security/README.md`, `docs/STATUS.md` |
| Installed Application Guard live UI connection | `security-center/tauri/frontend/application-security.js`, `application-view.js`, `app.js` in the same frontend directory; runtime `broker.rs`, `enrollment.rs`, `selinux_readback.rs` | `docs/security-center/APPLICATION_SECURITY_PLAN.md`; installed receipts `docs/history/security-center/2026-10-08-application-security-normal-session.md`, `docs/history/security-center/2026-10-08-security-center-workspace.md` | Center 73 / Context 69 / runtime 26 installed on deliberately enrolled `<development-host>`; automatic production lifecycle unvalidated | `security-center/tauri/frontend/application-workflows.test.mjs`, `application-view.test.mjs` in the same directory; runtime broker/enrollment tests | Focused Node tests, Cargo broker/enrollment tests; actual normal-desktop native UI refresh and broker loss/recovery | `docs/STATUS.md`, existing Context freshness and operations |
| Application Security enrollment (normal development enrollment; automatic production lifecycle unvalidated) | `security-center/crates/greyward-application-security/src/enrollment.rs`, `store.rs`, `workflow.rs`, `development_bus.rs`, `selinux_readback.rs` in the same runtime source directory; `security-center/packaging/application-security/maintenance.py` | `docs/security-center/APPLICATION_SECURITY_ENROLLMENT.md`; scoped receipt `docs/history/security-center/2026-10-07-application-security-enrollment-initial.md` | `security-center/packaging/application-security/greyward-maintenance.target`, `security-center/packaging/application-security/greyward-maintenance-console.service`; offline maintenance remains inactive; deliberate normal development enrollment is recorded in the authority | `tests/test_application_enrollment.py`, `tools/greyward-dev/application-security-enrollment-boundary.py`; incompatible fixture `spikes/application-security/selinux/greyward_enrollment_boundary_probe.te`, `spikes/application-security/selinux/greyward_enrollment_boundary_deny.cil` | `python -m unittest discover -s tests -p test_application_enrollment.py`; explicit Linux/root synthetic LUKS fixture; runtime Cargo tests/Clippy; E0–E5 unpassed | `environment/production/`, existing Fedora PAM/UWSM/DMS and update/recovery owners |
| Protected authentication and tested persistent tool profiles (scoped source; no production activation) | `security-center/crates/greyward-application-security/src/tool_profile.rs`, `policy_intent.rs`, `managed_grant.rs`, `reviewed_launch.rs`, `workflow.rs`, `selinux_readback.rs` in the same runtime source directory; `security-center/packaging/application-security/authentication/assemble.py` | `docs/security-center/APPLICATION_SECURITY_ENROLLMENT.md`; scoped receipt `docs/history/security-center/2026-10-07-application-security-authentication.md` | `environment/production/selinux/greyward-application-auth.te`, `environment/production/selinux/greyward-application-auth.cil`, `environment/production/selinux/greyward-application-grants.te`; excluded from experimental RPM and image activation | `tests/test_application_authentication.py`, `tests/test_application_desktop.py`, `tools/greyward-dev/application-security-authentication-check.sh`, `tools/greyward-dev/application-security-authentication-boundary.py`, `tools/greyward-dev/application-security-authentication-session.py`, `tools/greyward-dev/application-security-lock.py`, `spikes/application-security/selinux/greyward_authentication_boundary_probe.te` | Pinned shell assembly; separate UID-1002 enforcing cross-domain, native PAM, fresh GUI Polkit and tool reuse/withdrawal probes; runtime tests/Clippy | `docs/STATUS.md`, installed DMS native lock remains canonical |
| Protected login startup and readiness | security-center/packaging/application-security/desktop/materialize.py, authentication.py, and session.py, plus packaging/greyward-enrollment/migrate-dms-shell.py | docs/architecture/ARCHITECTURE.md; docs/security-center/APPLICATION_SECURITY_PLAN.md; docs/security-center/APPLICATION_SECURITY_ENROLLMENT.md; packaging/greyward-enrollment/README.md | Seed private authentication settings at DMS schema v18; pass the private compositor socket through a broker-created relative `wayland-0` alias; preserve broker admission until protected Polkit registration; refresh the profile helper, authentication worker and session worker plus receipts only through quiescent rollback-capable migration; start a minimal noninteractive backdrop before the full protected DMS shell starts | tests/test_application_authentication.py; tests/test_dms_shell_migration.py | Five migration and nine authentication tests pass with static/repository validation. After packages 40/15 were installed, the user observed about 3 s black then 3 s backdrop; the protected-session worker took 2.37 s. Application Security 41 and Enrollment 16 both build successfully and are installed on `<development-host>`; migration refreshed and verified the protected desktop receipt and shell inputs with SELinux Enforcing. The user visually confirmed the new splash appears early; normal DMS is active afterward | security-center/packaging/application-security/greyward-application-security-experimental.spec, protected desktop preparation in prepare.py
| Installed GREYWARD system | `environment/production/` | `ARCHITECTURE.md`, `docs/architecture/PRODUCTION_VS_DEVELOPMENT.md`, `environment/production/README.md`, `docs/security/crypto-policy.md` | `environment/production/manifest.json`, `environment/production/packages.txt`, `environment/production/external-rpms.txt`, `environment/production/desktop-entry-overrides/`, `environment/production/blackbox/`, `environment/production/dconf/`, `environment/production/configure-zsh.sh`, `environment/production/zsh/`, `environment/session/`, `branding/` | `tests/guest-acceptance.sh` | `tests/static.ps1`, `tools/validate-repository.ps1` | `environment/development/`, `packaging/` |
| Development VM overlay | `environment/development/`, `tools/greyward-dev/` | `docs/architecture/PRODUCTION_VS_DEVELOPMENT.md`, `docs/development/DEVELOPMENT.md`, `docs/development/VMWARE_WAYLAND_DISPLAY_DIAGNOSTIC.md` | `environment/http/greyward-dev-bootstrap.ks.tmpl`, `.secrets/` | `tests/guest-acceptance.sh` | `tools/greyward-dev/health.ps1`, `tools/greyward-dev/graphics-gate.ps1`, `tools/greyward-dev/iterate-security-center.ps1`, `tools/greyward-dev/run-security-center-interaction.ps1`, `tools/greyward-dev/deploy-security-center.ps1` | `environment/greyward.pkr.hcl` |
| Image/install boundary (including target-kernel initramfs branding, final ISO closure validation, Hyper-V-first candidate workflow, direct Rock Ridge ISO inspection, and fabrication incident ledger) | `environment/image/build.sh`, `environment/image/build-iso.sh`, `environment/image/validate-production-stage.sh`, `environment/image/baseline.py`, `environment/image/build-offline.py`, `environment/image/build-components.py`, `environment/image/stage-text.py`, `environment/image/installer-contract.py`, `environment/production/install-offline-flatpaks.sh`, `tools/greyward-dev/capture-image-baseline.ps1`, `tools/greyward-dev/validate-vmware-iso.py` (legacy filename; hardware-neutral), `environment/image/installer.ks.tmpl`, `environment/production/provision-firstboot.sh`, `environment/production/provision-firstboot.service`, `environment/production/firstboot-status.sh`, `environment/production/firstboot-status.service` | `docs/architecture/ISO_CREATION.md`, `docs/architecture/ISO_REBUILD_QUICKSTART.md`, `docs/architecture/ISO_INSTALLER_COMPATIBILITY.md`, `docs/architecture/PRODUCTION_VS_DEVELOPMENT.md`, `environment/production/README.md` | `environment/production/production-acceptance.sh`, `environment/production/audit/greyward.rules`, `environment/production/selinux/greyward-dms-greeter.cil`, `environment/production/greyward-start-labwc`, `environment/production/greyward-sync-greeter-wallpaper`, `environment/production/manifest.json`, `environment/production/external-rpms.txt`, `environment/production/artifact-policy.json` | `tests/production-acceptance.sh`, `tests/static.ps1`, `tests/test_image_baseline.py`, `tests/test_image_offline.py`, `tests/test_image_stage_text.py`, `tests/test_image_installer_contract.py`, `tests/test_image_greeter_wallpaper.py`, `tests/test_component_cache.py`, `tests/test_session_policy.py` | `tools/validate-repository.ps1`, `tests/static.ps1`, `environment/image/build.sh`, `environment/image/build-iso.sh`, `environment/image/validate-production-stage.sh`, `tools/greyward-dev/validate-vmware-iso.py`, `python3 -m unittest discover -s tests -p "test_image_*.py"` | `environment/greyward.pkr.hcl` |

The offline image builder may receive `GREYWARD_FLATHUB_REPO_FILE` when its
network cannot reach Flathub. It validates the canonical repository URL and
pinned signing-key digest before staging the descriptor.
| DMS release assembly and reversible migration | `packaging/greyward-dms/`, `environment/session/greyward-dms`, `environment/session/greyward-dms-state-migrate`, `environment/session/greyward-dms-runtime-check`, `tools/greyward-dev/dms-candidate-guest.sh`, `tools/greyward-dev/dms-measure.py`, `tools/greyward-dev/dms-benchmark-session.py`, `tools/greyward-dev/dms-diagnostics.py` | `docs/architecture/DMS_1_6_MIGRATION_PLAN.md` | `environment/production/dms-release.json`, `environment/patches/dms/`, `environment/session/greyward-dms.service`, `environment/production/install-dms.sh` | `tests/test_dms_migration.py`, `tests/test_dms_package_verify.py`, `tests/test_dms_runtime.py`, `tests/dms-native-lock.test.mjs`, `tests/dms-network.test.mjs`, `tests/test_image_offline.py`, `tests/guest-acceptance.sh` | `tests/static.ps1`, `tools/validate-repository.ps1`, `python3 -m unittest discover -s tests -p "test_dms*.py"`, `node --test tests/dms-network.test.mjs`, offline Fedora RPM build and session acceptance | `docs/decisions/DANK_UPSTREAM.md`, `docs/decisions/DANK_MODULES.md` |
| Desktop session and Labwc/DMS | `environment/session/`, including the DMS-owned `AppsDock` taskbar configuration, session migration and compositor-aware display setup visibility | `docs/architecture/ARCHITECTURE.md`, `environment/production/README.md` | `environment/session/labwc/`, `environment/session/dankmaterialshell/`, `environment/session/greyward-dms-session-migrate`, `environment/patches/dms/`, `environment/production/greyward-start-labwc` | `tests/static.ps1`, `tests/guest-acceptance.sh`, GREYWARD-DEV AppsDock and display-settings runtime scenarios | `pwsh -NoProfile -File .\\tests\\static.ps1`, `tools/greyward-dev/deploy.ps1`, `tools/greyward-dev/reload.ps1` | `environment/production/` |
| Protected DMS monitor configuration | `security-center/packaging/application-security/desktop/prepare.py`; `security-center/packaging/application-security/desktop/session.py`; `security-center/packaging/application-security/desktop/labwc-protected-input.patch`; `security-center/packaging/application-security/authentication/assemble.py`; `environment/session/greyward-dms.service`; `environment/session/greyward-dms-state-migrate`; `environment/session/dankmaterialshell/monitors.json`; `environment/session/labwc/rc.xml`; `environment/production/labwc-autostart`; `environment/production/packages.txt`; `environment/production/production-acceptance.sh`; `environment/image/build.sh`; `environment/patches/dms/greyward-wlr-output-readiness.patch`; `environment/production/dms-release.json`; `packaging/greyward-session/greyward-session.spec`; `packaging/greyward-enrollment/greyward-enrollment.spec`; `packaging/greyward-enrollment/migrate-dms-shell.py` | `docs/architecture/DMS_MONITOR_CONFIGURATION.md`; `environment/production/README.md`; `environment/image/README.md` | Expose only `zwlr_output_manager_v1` to ordinary clients; preserve the private auth runtime and broker socket alias; keep the protected Polkit admission gate while polling readiness quickly at startup; pin the DMS unit's relative `WAYLAND_DISPLAY=wayland-0`; seed a first-session 1920×1080 profile; put the fixed mode request in the root-owned protected-compositor autostart because it ignores the account's writable Labwc autostart; target only `Virtual-1` and preserve physical modes and existing profiles; reuse the active Labwc output mode; require wlr-randr at runtime; require Enrollment's exact DMS dependency to match the selected shell RPM; reject a session RPM whose DMS unit, migration, monitor profile or virtual-output autostart differ from source; reject DMS plugin payload drift after CRLF normalization; make Settings readiness depend on a valid `wlroutput.getState` response with bounded retry and logs; refresh enrolled DMS copies through a root-only, quiescent migration | `tests/test_protected_compositor_display.py`; `tests/test_dms_wayland_runtime.py`; `tests/test_dms_shell_migration.py`; `tests/test_dms_migration.py`; `tests/test_dms_build_inputs.py`; `tests/test_image_offline.py`; `tests/test_application_authentication.py`; exact pinned DMS shell assembly receipt | `<development-host>` current installed DMS 1.6.2-17, Application Security 51, Enrollment 32, Session 18, Security Center 100 and Security Context 92; `wlr-randr` reads 2560×1440 with SELinux Enforcing. Session 21 is a build-only RPM in the 0.4.0 candidate; its fresh taskbar default is not installed on `<development-host>`. Candidate composition and 39-path Windows media validation pass; installed display and fresh-install behavior remain unverified | Higher-risk input, capture, output-power and session-lock globals |
| GREYWARD Network Traffic taskbar | `environment/session/dankmaterialshell/plugins/greywardNetworkTraffic/NetworkTrafficWidget.qml`, `environment/session/dankmaterialshell/plugins/greywardNetworkTraffic/NetworkTrafficModel.qml`, `environment/session/dankmaterialshell/plugins/greywardNetworkTraffic/NetworkTrafficMath.js` | `docs/architecture/ARCHITECTURE.md` | `environment/session/dankmaterialshell/settings.json`, `environment/session/dankmaterialshell/plugin_settings.json`, `environment/session/dankmaterialshell/plugins/greywardNetworkTraffic/plugin.json`, `tools/greyward-dev/deploy.ps1` | `tests/static.ps1`, GREYWARD-DEV runtime scenarios | `pwsh -NoProfile -File .\\tests\\static.ps1`, `tools/greyward-dev/deploy.ps1`, `tools/greyward-dev/reload.ps1` | DMS `DgopService`, Security Center Network Activity |
| GREYWARD Network Identity taskbar | `environment/session/dankmaterialshell/plugins/greywardPublicIp/PublicIpWidget.qml` | `docs/architecture/ARCHITECTURE.md`, `docs/security-center/PRIVACY.md` | `environment/session/dankmaterialshell/settings.json`, `environment/session/dankmaterialshell/plugin_settings.json`, `environment/session/dankmaterialshell/plugins/greywardPublicIp/plugin.json` | `tests/static.ps1`, `security-center/crates/greyward-security-backends/src/privacy.rs` tests, GREYWARD-DEV multi-screen/opt-out/restart runtime scenario | `pwsh -NoProfile -File .\\tests\\static.ps1`, `tools/greyward-dev/deploy.ps1`, `tools/greyward-dev/reload.ps1` | Per-screen process IDs; one DMS PluginService owner shares current addresses through memory-only global variables, including ownership handoff on screen removal; locally drawn flags for a broad country set with an ISO-code fallback; no duplicate provider lookup; Security Center external-service disclosure |
| Boot and offline-update branding | `packaging/greyward-branding/SOURCES/greyward.script`, `packaging/greyward-branding/SOURCES/greyward-update-status.service`, `packaging/greyward-branding/SPECS/greyward-branding.spec` | `branding/BRANDING.md`, `docs/architecture/ARCHITECTURE.md` | `branding/source/greyward-symbol.svg`, `branding/generated/boot/`, `packaging/greyward-branding/SOURCES/greyward.plymouth` | `tests/static.ps1` | `tools/validate-branding.ps1`, `tools/build-branding-rpm.ps1`, `tools/greyward-dev/verify-boot-branding.ps1`, user-run offline update/reboot observation | `system-update.target`, DNF5 offline transaction, Security Center Updates workflow |
| Security Center UI/domain and integrated window chrome | `security-center/tauri/`, `security-center/crates/`, `security-center/security-context/greyward_security_context/network_location.py` | `docs/security-center/ARCHITECTURE.md`, `docs/security-center/UX_SPEC.md`, `docs/security-center/DATA_MODEL.md`, `docs/security-center/BACKENDS.md`, `docs/security-center/FILE_SECURITY.md`, `docs/security-center/PERFORMANCE.md`, `docs/security-center/remediation/` | `security-center/tauri/frontend/` (including bundled `startup.js`/`request-adapter.js`/`application-security.js`/`security-history.js` (shared contextual actor/action/resource/decision rows and evidence disclosures), `environment/session/labwc/rc.xml` exact main-window decoration exception, persistent `window-chrome.js`/`window-chrome.css` and `src-tauri/src/window_chrome.rs` native actions, canonical Labwc control artwork copied by `tools/generate-security-center-window-controls.ps1`, persistent route shell/navigation and optional Overview activity/Recovery read scheduling in `app.js`/`src-tauri/src/lib.rs`, canonical `workspace.css` shell/navigation with centered shared Security Center emblem and enlarged menu text, canonical `materials.css` neutral graphite grain/silver materials, intentional shared `app.js` glyphs and native WebKit EN/FR handoff, self-origin script CSP, stale-route read protection, semantic EN/FR catalog, silver frosted-glass surfaces, shared keyboard-accessible confirmations, refresh continuity, asynchronous page-read and privacy dispatch, direct System checks navigation, explained privacy profiles, action-first recovery and file workflows, and progressive activity/update history), optional age-aware local endpoint-country resolver via MMDB/geofeed data, `GREYWARD_GEOIP_DB`, optional `GREYWARD_GEOIP_DB_SECONDARY`, and optional `GREYWARD_GEOFEED_DB`, `security-center/crates/greyward-security-backends/src/presentation.rs` (typed evidence presentation), `security-center/data/` | `security-center/crates/greyward-security-domain/tests/`, `security-center/tauri/frontend/ux-contract.test.mjs`, `security-center/tauri/frontend/security-history.test.mjs`, `security-center/tauri/frontend/window-chrome.test.mjs`, `security-center/tauri/frontend/interaction.test.mjs`, `security-center/tauri/frontend/performance.test.mjs`, `security-center/tauri/frontend/performance-contract.test.mjs`, `tools/greyward-dev/security-center-benchmark.py` (read-only actual native desktop measurements), `security-center/tauri/frontend/startup.test.mjs`, `security-center/security-context/tests/test_network_protection.py`, `security-center/security-context/tests/test_network_location.py`, `tests/country-metadata.test.mjs`, `security-center/security-context/tests/test_file_security.py`, `security-center/security-context/tests/test_user_bus.py` | `cargo test --workspace --locked`, `node --test tauri/frontend/ux-contract.test.mjs`, `node --test tauri/frontend/interaction.test.mjs`, `node --test tauri/frontend/performance.test.mjs` and `node --test tauri/frontend/startup.test.mjs` in GREYWARD-DEV, `python3 -m unittest discover -s security-context/tests -p 'test_*.py'` | `security-center/security-context/`, `environment/session/dankmaterialshell/plugins/greywardSecure/` |
| GREYWARD Update Center workflow | `security-center/crates/greyward-security-backends/src/adapters.rs`, `security-center/security-context/greyward_security_context/update_center.py`, `update_center_bus.py`, `security-center/security-context/bin/greyward-update-action`, `security-center/security-context/systemd/greyward-update-worker.socket`, `greyward-update-worker@.service`, `packaging/greyward-enrollment/enroll.py`, `environment/production/selinux/greyward-application-session.te`, `.fc`, `security-center/tauri/frontend/app.js` | `docs/architecture/UPDATE_CENTER_ARCHITECTURE.md`, `docs/security-center/remediation/2026-09-01-updates-workflow.md`, `docs/security-center/remediation/2026-09-02-essential-pci-driver-support.md` | `security-center/security-context/dbus/`, `security-center/security-context/systemd/`, `security-center/security-context/polkit/`, `security-center/tauri/src-tauri/src/lib.rs` | `security-center/security-context/tests/test_update_center.py`, `test_update_center_bus.py`, `test_recovery.py`, `tests/test_installer_enrollment.py`, `security-center/tauri/frontend/ux-contract.test.mjs`, `interaction.test.mjs` | `PYTHONPATH=security-center/security-context python3 -m unittest test_update_center.py test_update_center_bus.py`, `python -m unittest tests.test_installer_enrollment`, `node --test security-center/tauri/frontend/ux-contract.test.mjs`, `tools/greyward-dev/run-security-center-interaction.ps1` | `security-center/packaging/`, `environment/production/` |
| GREYWARD Privacy workflow | `security-center/crates/greyward-security-backends/src/profiles.rs`, `src/bin/greyward-security-profile.rs`, `security-center/security-context/greyward_security_context/user_bus.py`, `security-center/tauri/src-tauri/src/lib.rs`, `security-center/tauri/frontend/app.js`, `environment/session/dankmaterialshell/plugins/greywardSecure/SecureWidget.qml` | `docs/security-center/PRIVACY.md`, `docs/security-center/remediation/2026-09-01-privacy-workflow.md` | `security-center/tauri/frontend/i18n.js`, `security-center/tauri/frontend/ux-contract.test.mjs`, `security-center/tauri/frontend/security-history.test.mjs`, `security-center/tauri/frontend/window-chrome.test.mjs`, `security-center/tauri/frontend/interaction.test.mjs` | `security-center/security-context/tests/test_shell_summary.py`, `security-center/crates/greyward-security-backends/src/profiles.rs` tests | `PYTHONPATH=security-center/security-context python3 -m unittest discover -s security-center/security-context/tests -p 'test_*.py'`, `node --test security-center/tauri/frontend/ux-contract.test.mjs`, `tools/greyward-dev/run-security-center-interaction.ps1` | `security-center/packaging/`, `environment/production/` |
| GREYWARD File Security core workflow (trusted system scanner metadata; active review versus handled history; fresh source availability) | `security-center/security-context/greyward_security_context/clamav.py`, `file_security.py`, `safe_open.py`, `user_bus.py`, `clamav_service.py`, `session10_bus.py`, `security-center/tauri/frontend/app.js` | `docs/security-center/FILE_SECURITY.md`, `docs/security-center/BACKENDS.md`, `docs/security-center/PRIVILEGE_MODEL.md`, `docs/security-center/remediation/2026-08-31-file-security-core.md` | `security-center/security-context/systemd/greyward-clamav-scan.service`, `security-center/security-context/dbus/`, `environment/production/` | `security-center/security-context/tests/test_file_security.py`, `test_clamav.py`, `test_safe_open.py`, `security-center/tauri/frontend/ux-contract.test.mjs` | `PYTHONPATH=security-center/security-context python3 -m unittest discover -s security-center/security-context/tests -p 'test_*.py'`, `node --test security-center/tauri/frontend/ux-contract.test.mjs`, Fedora GREYWARD-DEV D-Bus E2E | `security-center/security-context/`, `security-center/tauri/frontend/`, `environment/production/` |
| Security Center validation backlog | `security-center/tests/session10-gate.sh` | `docs/security-center/ACCEPTANCE.md`, `TESTING.md`, `docs/security-center/SESSION_10_REPORT.md` | Fedora/VM evidence and runtime command hooks | `security-center/tests/session10-gate.sh` | `bash security-center/tests/session10-gate.sh --report /path/to/session-10-run.md` | `tests/static.ps1` |
| Security Center packaging | `security-center/packaging/`, `environment/development/build-security-center.sh`, `tools/greyward-dev/deploy-security-center.ps1` | `docs/security-center/README.md`, `docs/development/DEVELOPMENT.md`, `docs/security-center/remediation/` | `security-center/packaging/`, `security-center/data/` | `security-center/` package checks | `cargo test --workspace --locked`, `cargo build --workspace --release --locked`, `desktop-file-validate`, packaged RPM checks | `environment/production/` |
| Security Context | `security-center/security-context/` | `docs/security-context/README.md`, `docs/security-context/ARCHITECTURE.md`, `docs/security-context/LIVE_PRIVACY_CAPSULE.md`, `docs/architecture/UPDATE_CENTER_ARCHITECTURE.md`, `docs/security/privilege-model.md` | `security-center/security-context/systemd/`, `security-center/security-context/dbus/`, `security-center/security-context/polkit/`, `environment/production/packages.txt` | `security-center/security-context/tests/` | `python3 -m unittest discover -s security-context/tests -p 'test_*.py'` | `docs/security/`, `docs/recovery/`, `environment/session/dankmaterialshell/plugins/greywardSecure/` |
| Security Center launcher, shell presentation and notifications | `security-center/security-context/greyward_security_context/shell_summary.py`, `security-center/security-context/greyward_security_context/shell_experience.py`, `security-center/security-context/greyward_security_context/shell_runtime.py`, `security-center/security-context/greyward_security_context/usbguard_session.py`, `security-center/security-context/greyward_security_context/notification_router.py`, `environment/session/dankmaterialshell/plugins/greywardSecure/SecureWidget.qml`, `environment/production/selinux/greyward-application-auth.te`, `environment/production/selinux/greyward-application-usbguard-approval.te`/`.fc`, `packaging/greyward-dms/usbguard-approval.go`, and `packaging/greyward-dms/greyward-dms.spec` | `docs/security-context/LIVE_PRIVACY_CAPSULE.md`, `docs/security-context/ARCHITECTURE.md`, `branding/BRANDING.md` | `branding/source/greyward-security-status.svg`, `security-center/data/greyward-security-center.svg`, `security-center/data/greyward-security-center.png`, `environment/patches/dms/greyward-security-notifications.patch`; one server-filtered `notification_items` list drives both taskbar alerts and native desktop notifications; live posture remains immediate, transient Secure DNS/firewall/device warnings wait 30 seconds, critical events remain immediate; USB approval uses the distinct taskbar client, protected authentication and auth-only USBGuard executor detailed below; DMS parents and ordinary apps receive no USBGuard write permission; native USB notifications remain review-only; the taskbar launch button uses DMS desktop-entry routing and displays opening, success, and failure feedback | `security-center/security-context/tests/test_shell_summary.py`, `security-center/security-context/tests/test_shell_experience.py`, `security-center/security-context/tests/test_notification_router.py`, `security-center/security-context/tests/test_shell_runtime.py`, `security-center/security-context/tests/test_usbguard_lifecycle.py`, `security-center/security-context/tests/test_usbguard_session_action.py`, `tests/test_installer_enrollment.py`, `tests/static.ps1` | Python lifecycle tests on Fedora (D-Bus startup order, display/evidence leases, revision renewal, shared alert projection, missing detections, shared evaluated-check/accepted-deviation parity and validated Protected Data resource Review routing); USB action/readback and notification routing tests; Enrollment policy compile and exact protected-DMS helper transition/map/read-execute test; frontend UX contracts; `tools/greyward-dev/security-shell-state-sheet.py`; actual Polkit prompt acceptance on `<validation-host>` remains pending | `security-center/packaging/greyward-security-context.spec`, `security-center/packaging/greyward-security-center.spec`, `packaging/greyward-enrollment/greyward-enrollment.spec`, `tools/validate-branding.ps1` |
| USBGuard taskbar approval completion | `packaging/greyward-dms/usbguard-approval.go`, `usbguard-approval-execute.go`, `verify.py`; `environment/production/selinux/greyward-application-usbguard-approval.te`/`.fc`; protected `authentication/assemble.py`, `desktop/materialize.py`; `packaging/greyward-enrollment/migrate-dms-shell.py`; Context `usbguard.py`/`usbguard_session.py`; `SecureWidget.qml` | `docs/security-context/ARCHITECTURE.md`, `docs/security-center/USB_APPROVAL.md`, `docs/STATUS.md` | Atomic typed availability projection; distinct taskbar/auth-executor domains; no cgroup or general auth-runtime read; upstream interactive Polkit; explicit isolated Python CLI entrypoint; private Qt buffers; own device hash; no manually created trust | `usbguard-approval_test.go`, `tests/test_application_authentication.py`, explicit offscreen `tests/test_authentication_input_focus.py`, `tests/test_dms_shell_migration.py`, `tests/test_installer_enrollment.py`, Context `test_usbguard_lifecycle.py`, `test_usbguard_session_action.py`, `test_shell_experience.py` | Go tests; Fedora Python tests; both repository gates; `environment/image/verify-usbguard-inputs.py` and `tests/test_usbguard_release_inputs.py` refuse stale complete-stage RPMs; installed kernel decisions and atomic FileView label proof; late Qt window-entry regression; installed taskbar/Polkit/device/kernel/persistent-rule readback and user-confirmed keyboard/alert clearance; reconnect/reboot persistence untested | Installed <validation-host> tuple: DMS 26 / Context 108 / Application Security 69 / Enrollment 60; the earlier 26/107/64/55 row is historical candidate evidence; ISO validation is separate |
| Wayland session lock | `environment/session/greyward-session-lock`, `environment/session/greyward-dms-state-migrate`, `packaging/greyward-session/` | `environment/production/README.md` | `environment/session/labwc/rc.xml`, `environment/session/dankmaterialshell/settings.json`, `environment/session/greyward-dms-lock.pam` | `tests/test_dms_migration.py`, `tests/static.ps1` | Fedora native DMS lock/suspend validation | `environment/production/provision.sh` |
| GREYWARD telemetry history and Security Center projections | `security-center/security-context/greyward_security_context/telemetry.py`, `findings.py`, `aggregation.py`, `local_activity.py`, `user_bus.py`, `shell_runtime.py` | `docs/telemetry/README.md`, `EVENT_MODEL.md`, `PRIVACY_STORAGE.md`, `CORRELATION_QUERY.md` | per-user `$XDG_STATE_HOME/greyward/telemetry/events.sqlite3`, root spool under `/run/greyward-security-context/`, plus user-owned HMAC device key at runtime | `security-center/security-context/tests/test_telemetry.py`, `test_aggregation.py`, `test_local_activity.py`; typed Rust history adapter in `security-center/crates/greyward-security-backends/src/privacy.rs` | `PYTHONPATH=security-center/security-context python3 -m unittest discover -s security-center/security-context/tests -p 'test_*.py'` | `docs/security-center/DATA_MODEL.md`, `security-center/tauri/frontend/app.js`, `environment/session/dankmaterialshell/plugins/greywardSecure/SecureWidget.qml` |
| Recovery V1 | `security-center/security-context/greyward_security_context/recovery.py`, `restic_backup.py` | `docs/recovery/RECOVERY_V1.md` | `security-center/security-context/bin/`, `systemd/` | `security-center/security-context/tests/test_recovery.py` | Python unit tests and Security Center package validation | `docs/recovery/BOOT_ROLLBACK_PROTOTYPE.md` |
| Secure DNS/network protection and Feodo threat blocking | `security-center/security-context/greyward_security_context/secure_dns_reconciler.py`, `security-center/security-context/greyward_security_context/secure_dns_split.py`, `security-center/security-context/greyward_security_context/network_policy_service.py`, `security-center/security-context/greyward_security_context/control_plane.py`, `security-center/security-context/greyward_security_context/feodo.py`, `security-center/security-context/greyward_security_context/user_bus.py`, `security-center/security-context/greyward_security_context/notification_router.py` | `docs/security/SECURE_DNS_IMPLEMENTATION_PLAN.md`, `docs/security-context/OPENSNITCH.md` | `security-center/security-context/bin/greyward-feodo-update`, `security-center/security-context/systemd/greyward-feodo-update.service`, `security-center/security-context/systemd/greyward-feodo-update.timer`, `security-center/security-context/dbus/`, `security-center/security-context/config/`, `security-center/data/`, `security-center/tauri/frontend/` | `security-center/security-context/tests/test_secure_dns.py`, `security-center/security-context/tests/test_secure_dns_split.py`, `tests/fedora-secure-dns-split.py`, `tests/fedora-secure-dns-service.py`, `test_network_protection.py`, `test_feodo_threat_intel.py`, `security-center/tauri/frontend/ux-contract.test.mjs` | Python unit tests, frontend contract tests, Fedora systemd/D-Bus checks, Rust workspace tests | `docs/security-context/PORTMASTER.md` |
| Software and default file handlers | `environment/flatpak/`, including `seed-system-permissions.py`, native viewers, GVfs file backends and terminal compatibility migration in `environment/production/` | `docs/software/FLATPAK_BAZAAR_INTEGRATION_PLAN.md`, `environment/production/README.md` | `environment/flatpak/default-applications.list`, `environment/flatpak/mimeapps.list`, `environment/production/packages.txt`, `environment/production/desktop-entry-overrides/`, `branding/` | `tests/static.ps1`, `tests/test_flatpak_default_policy.py` | `tests/static.ps1`, Python default-policy tests, isolated Flatpak provider checks, guest acceptance, live file opening, archive browsing, SMB backend recognition and launcher search | `tools/greyward-dev/deploy.ps1` |
| Branding and boot visuals | `branding/`, `packaging/greyward-branding/` | `branding/BRANDING.md`, `branding/LICENSE`, `branding/PROVENANCE.md`, `LICENSING.md` | `branding/source/`, `branding/generated/`, `branding/wallpaper/`, `packaging/greyward-branding/SOURCES/` | `tests/static.ps1` | `tools/validate-branding.ps1`, `tools/build-branding-rpm.ps1` | `environment/session/` |
| Prototypes and upstream research | `spikes/` | `docs/security-context/README.md`, `docs/security-center/RESEARCH.md` | `spikes/dms-v1.5.3/`, `spikes/opensnitch-control-plane/` | prototype-local README/test instructions | read-only research; never production provisioning | `docs/history/` |
| Repository validation | `tools/validate-repository.ps1`, `tests/static.ps1` | `docs/DOCUMENTATION_POLICY.md` | `docs/INDEX.md`, `docs/REPOSITORY_MAP.md` | `tests/static.ps1` | `pwsh -NoProfile -File .\\tools\\validate-repository.ps1` | `AGENTS.md` |
| Pre-release architecture and build audit with approved execution backlog | `environment/production/`, `environment/image/`, `packaging/`, `security-center/` | `docs/architecture/FINAL_ARCHITECTURE_AUDIT.md`, `docs/architecture/BUILD_ISO_AUDIT.md`, `docs/plans/PRE_RELEASE_IMPROVEMENTS.md` | `environment/production/dms-release.json`, `versions.json` | `tests/static.ps1` | `tests/static.ps1`, `tools/validate-repository.ps1`; read-only Fedora runtime/package inspection | `docs/STATUS.md`, `docs/architecture/ISO_CREATION.md` |
| Publication licensing, clean history, and third-party provenance | `tools/export-public-repository.ps1`, repository root, and vendored asset directories | `docs/PUBLICATION.md`, `LICENSING.md`, `THIRD_PARTY_NOTICES.md`, `branding/PROVENANCE.md` | `branding/`, `security-center/data/fonts/`, `security-center/tauri/frontend/assets/network-icons/`, `security-center/vendor/` | `tests/static.ps1`, manual license/provenance review, external secret scan of the publication candidate | Run both repository gates; initially export one unrelated root commit, then update the existing clean public checkout with reviewed current-tree changes. Verify receipts, checksums, license texts and secret-scan results before publication. | `README.md`, `branding/BRANDING.md`, `docs/decisions/DANK_UPSTREAM.md` |
| Public contribution and vulnerability reporting | Repository root | `CONTRIBUTING.md`, `SECURITY.md` | `LICENSE`, `LICENSING.md` | Documentation-link validation | `pwsh -NoProfile -File .\\tools\\validate-repository.ps1` | `README.md`, `docs/STATUS.md`, `security-center/README.md` |
| GREYWARD unattended system updates | `security-center/security-context/bin/greyward-auto-update`, `security-center/security-context/systemd/greyward-auto-update.service`, `security-center/security-context/systemd/greyward-auto-update.timer` | `docs/architecture/UPDATE_CENTER_ARCHITECTURE.md`, `security-center/README.md` | `security-center/packaging/greyward-security-context.spec`, `environment/production/provision.sh` | `security-center/security-context/tests/test_auto_update.py`, `tests/static.ps1` | `pwsh -NoProfile -File .\\tests\\static.ps1`, `PYTHONPATH=security-center/security-context python3 -m unittest test_auto_update.py` | `security-center/security-context/bin/greyward-update-action` |

| Protected desktop Administration and targeted SELinux usability | `security-center/crates/greyward-application-security/src/administration.rs`, `security-center/packaging/application-security/administration/`, build-time canonical SVG embedder and protected desktop/authentication assembly, Context `application_workflows.py`/`usbguard.py`, Tauri facade/frontend | `docs/security-center/APPLICATION_SECURITY_ENROLLMENT.md`, `docs/security-center/PRIVILEGE_MODEL.md` | `environment/production/selinux/greyward-administration.te`, `greyward-administration.cil`, `greyward-application-metadata.te`/`.fc`; experimental package, no automatic image enrollment | `tests/test_administration.py`, `tests/test_administration_branding.py` (closed SVG inputs and LF-only sudo-handoff shebang), `tests/test_administration_render.c` (native artwork/cell pixels), `test_application_authentication.py`, Context workflow/USB tests, frontend UX contracts | Focused native renderer compile/run (Security Center README), Cargo/Python/Node and both repository gates; `tools/greyward-dev/administration-kernel-check.py`, `administration-visual-check.py`; normal-seat activation passed; full desktop rollback acceptance still required | `docs/history/security-center/2026-10-09-practical-administration.md`, existing DMS/PAM/typed Polkit/recovery owners |

The administration row also owns `greyward-flatpak-metadata.service`/`.path` in
the experimental package: event-driven public export reconciliation, validated
by `tests/test_application_metadata.py` and actual installed path events.
The same authority owns the read-only closure rules in
`environment/production/selinux/greyward-application-metadata.cil`, the session
package's `environment/flatpak/greyward-portal-backends.conf` backend selection,
and normal-seat evidence in
`docs/history/security-center/2026-10-09-desktop-compatibility.md`.
Approved normal-seat activation passes; full desktop rollback remains pending
at the user's request to retain the running session. Ordinary transient-job
control belongs to `greyward-application-session.te`, with actual user-job and
unauthenticated system-control checks in the normal-seat receipt.
`greyward-application-display.fc` and desktop preparation own immutable Labwc
configuration/theme labels; the display reads static assets without broad state
access. Center's native main-window setup and explicit navigation wake-up retain
application-owned chrome and covered-window handoff behavior.
`tools/greyward-dev/desktop-compatibility-kernel-check.py` reads current kernel
boundaries; `flatpak-cache-label-repair.py` is an explicit development-only
public-icon migration with alias/protected-label tests in
`tests/test_flatpak_cache_label_repair.py`. Run these focused Linux fixtures,
the trusted guest kernel check and both repository gates. Normal-seat activation
passes; full desktop rollback and authenticated production rescue remain pending.

The Packer file, development bootstrap Kickstarts, and account-provisioning
overlay remain tracked locally but are omitted from public exports by
`tools/export-public-repository.ps1`.

Generated directories (`build/`, `cache/`, `output/`, `environment/packer_cache/`,
`tmp/`, `.greyward-iso-stage.*`, and `.greyward-iso-tree.*`) are local artifacts;
`.secrets/` contains credentials. None is source of truth. `.vmtest/` is
different: it contains Hyper-V VM disks and checkpoints and must be managed by
the VM lifecycle tools, not routine repository cleanup.
