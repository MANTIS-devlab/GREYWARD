# Historical Application Security experiments

Status: HISTORICAL. These recipes/receipts describe chronological prototypes,
including retired standalone Safe Open. Do not use them as a current package
or production enrollment recipe. See the
[current plan](../../security-center/APPLICATION_SECURITY_PLAN.md).

# Application Security feasibility

The active priority is the fixed combined blocking flow, rather than expansion
of the older matrices below. Stage `application-security-registration-guard.sh`,
`application-security-policy-intent.sh`, `application-security-authorization.py`,
`application-security-tty.py`, `application-security-critical-session.py` and
`application-security-critical-headless.sh` in the existing probe directory,
plus `greyward_managed_grant_probe.te` and the current runtime source. Run
`bash /var/tmp/greyward-application-security-probe/application-security-registration-guard.sh --end-to-end`
as the development user. This fixed workflow owns only UID 1002, its synthetic
resource tree, private policy database and its named temporary modules/units.
It requires three fresh owner authentications, actual denial/allow/revocation,
an enrolled private PAM session, minimum Flatpak/DMS/Labwc startup and rollback.
The coordinator restores the probe password even on failure. The archived
experimental RPM is not activated or changed by this source test.

This sequence passed on 7 October 2026; concrete receipts are in the
[active plan](../../security-center/APPLICATION_SECURITY_PLAN.md). Additional
portal/deputy matrices, performance/reproducibility, physical-seat/suspend and
release/image hardening are DEFERRED HARDENING. Historic matrix receipts below
retain their original scope and do not establish production protection.

The source policy-intention fixture is
`tools/greyward-dev/application-security-policy-intent.sh`. Stage it and the
existing authorization coordinator in `/var/tmp/greyward-application-security-probe`
after staging the reviewed source runtime and fixed policy action. It builds
tests unprivileged, verifies root/private storage roundtrip and concurrency,
rejects unauthenticated commit, then performs two fresh owner authentications
for separate in-memory intentions. No active grants, labels or production DB
are created. Its cleanup restores only the owned probe account's password,
removes the temporary action and verifies unchanged active DMS/Enforcing state.

The existing Safe Open runner now holds a descriptor through classification and
bubblewrap setup. To repeat its scoped compatibility fixture, stage
`application-security-safe-open.sh` and `.py` alongside the feasibility script in
`/var/tmp/greyward-application-security-probe`, and stage reviewed `safe_open.py`
in the existing source build tree. Run the shell fixture as the development
user. It copies the reviewed Python input to a fixed root-owned development
path, uses only the owned probe account and synthetic headless viewer, then
rolls back enrollment/labels. Normal viewing, replacement refusal, read-only
exposure and parent descriptor closure pass on bubblewrap 0.12 (134 ms,
11.4 MiB, no swap). Shared Guard runner integration remains open. No production
Safe Open package, active handler preference or desktop session is changed.

The private pinned Labwc Wayland security-context test passes ordinary client
controls, suppression of twelve advertised privileged interfaces and rejection
of an explicit forged manager bind. Ordinary data-device access remains;
clipboard isolation, native broker connection creation and managed denial of
the unrestricted socket remain open. The pinned XML input and retained MIT
license are recorded in `wayland/source.json`; no upstream protocol source is
independently maintained. Account/module rollback preserves the active desktop.

The separate-account native DMS PAM fixture passes a wrong-password secure-lock
check and two actual password-authenticated unlock cycles on a private headless
display. Its original password hash/change date and enrollment are restored;
the active DMS process stays unchanged. No IPC unlock, host keyboard injection,
Fedora PAM change or active-session lock is used. Logind, real-seat and suspend
acceptance remain open. The signed extracted wtype input is development-only.

Source broker reads now run in one fixed verification worker with eight
outstanding slots. Two timeout/admission/failure tests and all 67 ordinary
runtime tests pass, along with Clippy and actual system-bus owner/revision/query
checks. Revision 11 does not contain this later source change. Launch/resource
preparation and service initialization bounds remain separate gates.

`tools/greyward-dev/application-security-keyring.sh` exercises the installed
GNOME Keyring/libsecret deputy in a separate UID-1002 private bus/HOME. A
fresh synthetic store/read succeeds before confinement. The enrolled service's
live bus peer then matches `greyward_guard_gkeyringd_t`; protected collection
retrieval and direct file reads fail. Service presence does not imply usable
grants or a protected badge: the collection is unavailable. Correct private
runtime/user labels were required; no SELinux allow rule was added. Earlier
missing-service runs are not acceptance. Cleanup retains the active desktop.
Reviewed Secret Service compatibility and grant semantics remain open.

Provider startup now has four fixed workers and eight outstanding job slots.
Ten focused tests pass: a held worker cannot prolong the caller deadline or
release its admission early, expired queued work never starts, and actual
child/pipe cleanup remains bounded. Workspace Clippy passes. This corrects the
startup gap recorded in earlier receipts below; independent filesystem
verification and production launch containment remain open. Kernel-stalled
storage was not injected. Experimental RPM revision 11 builds offline and
passes extracted MAC/read/FD checks. Its SHA-256 is
`50aa9c27b75da5fcd8e607f79f1030e548b562a9d2cb2ced8c9dfa154c34bc70`;
the production database remains absent and the fixture rolls back. Full
package-only Center/Context and release acceptance remain open.

The latest source continuation replaces Security Center's local JSON writer
with the existing telemetry store through three fixed presentation-only Context
methods. Nine migration tests and all 284 Context source tests pass. The private
confined Tauri smoke passes export, shared-history read, clear and empty
readback; missing broker reads remain Unavailable and inline scripts remain
blocked. The latest matching source binary also passes in 15.397 seconds with
831.8 MiB peak fixture memory; its build used 295.3 MiB swap. These are not
performance measurements. Temporary
modules/mapping are removed, SELinux stays Enforcing and DMS PID 4888 is
unchanged. Earlier source/RPM counts and receipts below are historical to their
stated scope; revision 10 does not cover this history replacement. Storage,
redaction and retained-backup semantics are defined in
[the telemetry contract](../../telemetry/PRIVACY_STORAGE.md).

Status: experimental, Phase 0. Authority:
[approved plan](../../security-center/APPLICATION_SECURITY_PLAN.md).

The SELinux module is development-only. It defines a separate login domain and
an independently selected, dedicated resource-owner domain, with a synthetic protected
type deliberately excluded from ordinary home-content attributes. It is not
the production application policy and proves neither desktop compatibility nor
portal/deputy resistance by itself.

Build on Fedora with `make -f /usr/share/selinux/devel/Makefile
greyward_guard_probe.pp`. Install only using the bounded development probe
tool, on a separate test account. Never add this module to the production
manifest, change the default login mapping, disable SELinux or map `development-user`.

Copy the policy, probe Python file and
`tools/greyward-dev/application-security-feasibility.sh` into a private staging
directory. With SELinux development tools already installed, run the lifecycle
as root: `setup /path/to/staging`, `run`, then `rollback` to rehearse restoration.
`aliases` checks an inode-matched bind in a transient unit's private namespace.
`namespace` repeats the live owner/deputy suite as root inside a new user,
mount and network namespace, mapping only UID 1002. The helper rejects actual
root and every other UID map; owner processes remain visible for bypass tests.
Setup refuses to adopt an existing unowned account; ownership is recorded in a
root-only development receipt. Rollback retains synthetic fixtures but removes
the login mapping, module and public-key access. No other account is remapped.
Actual SSH and user-manager checks are separate from the root-selected context
probe and must be recorded separately. A headless shell startup is not proof
of interactive desktop, authentication, portal or whole-session acceptance.

The current [evidence table](../../security-center/APPLICATION_SECURITY_PLAN.md#development-evidence-6-october-2026)
records scoped results and remaining gates. The generic development subject
cannot become the separate owner context, including through its own user
manager. No production account is enrolled or shown as Protected.

The owner deliberately does not use Fedora's general user-domain template:
its inherited NSS rules permitted ordinary subjects to connect to its Unix
socket in the first probe. The dedicated domain now denies that connection,
with a kernel audit record and a working ordinary-socket positive control.
Its fixed Python fixture runs with `-I`; granting an interpreter a domain while
allowing user-site startup code would invalidate that boundary. This minimal
fixture is not yet a compatible grant profile for a graphical tool.

Rename preserves the source inode label. The expanded owner probe reproduced
an ordinary inode moving into the protected tree with its ordinary label. The
fixed fixture now denies ordinary-file rename/link in the owner domain while
allowing its metadata writes and properly labelled in-directory replacement.
This is a narrow experimental restriction, not a claim that arbitrary IDE or
browser import workflows are supported. Compatible tool profiles and supported
replacement paths must be proven before resource coverage can be advertised.

While the separate account is enrolled, execute
`tools/greyward-dev/application-security-routes.sh` through its SSH connection.
It exercises actual SSH, user-service and scheduled timer routes and tests a
forbidden owner-domain request through the user manager. It does not use cron
or install another scheduling service. Copy `application-security-tty.py` to
a root-owned development libexec path and run it in a fresh bounded root unit:

```bash
sudo systemd-run --quiet --collect --wait --pipe \
  --property=RuntimeMaxSec=30 --property=MemoryMax=64M \
  --property=SELinuxContext=unconfined_u:unconfined_r:unconfined_t:s0 \
  /usr/bin/python3 -I /usr/local/libexec/greyward-application-security-tty.py
```

The root helper is outside the application boundary. It creates only a private
PTY and selects `local_login_t` for its fixed login child; the enrolled shell
must enter the confined subject. A fresh unit avoids inheriting SSH's immutable
audit login UID. `login -f` skips password authentication, so a passing result
proves session mapping and access checks, not authentication or physical-seat
login. Neither login/PAM configuration nor an existing terminal is modified.

### Document provider experiment

The stock 1.22.1 provider rejects protected file descriptors but permits a
named export of an existing protected hardlink in an ordinary parent. FUSE
reads stay denied. This fails the selected export gate. The experimental
`portal/protected-named-export.patch` checks an existing named target through
an O_PATH descriptor and kernel access checks without reading content.
`portal/source.json` pins archive, preimage, patch and output digests; the patch
is the only maintained provider code. Neither a complete provider fork nor a
production provider replacement is committed.

With the recorded source archive already obtained, run as an unprivileged
builder:

```bash
python3 portal/prepare-provider.py source.tar.xz /private/new-output
meson setup build /private/new-output/xdg-desktop-portal-1.22.1 \
  --wrap-mode=nodownload -Dtests=disabled -Ddocumentation=disabled \
  -Dman-pages=disabled -Dgeoclue=disabled -Dgudev=disabled \
  -Dflatpak-interfaces=disabled
ninja -C build -j1 document-portal/xdg-document-portal
```

These are prototype build flags, not release acceptance. Supply dependencies
from an isolated builder or a private matching header sysroot. Do not install
floating development dependencies onto the active desktop. The October probe
accidentally upgraded 19 runtime packages while obtaining headers; all 19
original runtime NEVRAs were restored without restarting DMS. Receipts are
retained privately. Subsequent headers were downloaded/extracted only.

Select the prototype binary only in the fixed probe account's
`xdg-document-portal.service.d/greyward-feasibility.conf`. The headless startup
hook `tools/greyward-dev/application-security-headless.sh` exercises that
account's actual UWSM graphical target, document methods and DMS readiness.
`application-security-portal-probe.py` verifies ordinary exports/save-as,
protected file/directory/hardlink rejection and existing-export symlink
replacement. The kernel remains responsible for every later FUSE access;
the named check does not permanently bind a pathname export to an inode.
Existing named symlinks/nonregular files are currently unsupported by the
prototype. Full Flatpak/FileChooser/persistent-export/provider compatibility
and replacement races remain production gates.

The latest scoped result is 36 portal checks plus a READY DMS session against
the same account's private bus. A real Flatpak runtime reads an ordinary
selected-document FUSE export while synthetic credential reads fail; its
confined domain and zero effective capabilities are checked. No browser GUI,
persisted override or production account is changed. The earlier documented
23-check count was incorrect: the native suite contains 21 checks; the expanded
Flatpak suite brings the current total to 36. Grant/revoke readback and new
FUSE opens are checked; broad-home original-path access remains after portal
revocation. A persistent ordinary-document grant survives a restart of only
this account's provider. Exports are deleted after the probe. This does not
prove FileChooser, retained-FD revocation or persistence across a full login.

With the pinned private provider already built, run the fixed coordinator:

```powershell
pwsh -NoProfile -File tools/greyward-dev/application-security-session-check.ps1
```

It stages the reviewed helpers, enrolls only the owned probe account, exercises
actual SSH/service/timer routes, and creates a separate headless UWSM session.
The SSH session ID and an explicit synthetic seat avoid UWSM's physical-VT
lookup; this is not real-seat login acceptance. It verifies fresh portal and
shell JSON and always attempts mapping/label/provider/module rollback, then
checks SELinux enforcing and the unchanged recovery desktop PID. Probe-account
quiescence is bounded because logind termination is asynchronous. Rollback is
idempotent. UWSM's successful exit alone is insufficient evidence.

The lifecycle rollback removes the probe's provider drop-in as well as its
mapping, labels and public-key access. Prototype binaries and synthetic
diagnostic fixtures are retained for inspection but are not selected.

Before removing the module, restore the test account mapping and synthetic
object labels. Keep the existing recovery account and its SSH access intact.

### Root-runtime boundary probes

The new Rust runtime contains a foundation and a typed read broker; there is
no installed production broker.
Its ordinary tests cover registry/storage/operations, pidfd binding and private
authorization-ticket matching. The explicit `system_bus_peer` tests additionally
exercise Fedora's actual system bus and Polkit. The fixed experimental actions
are in `security-center/packaging/application-security/`; existing Security RPMs
do not install them. Detailed Polkit requests require a trusted root client.
The root test uses a fixed UID 1002 bus peer and proves owner/system requests
without authentication do not acquire a ticket. It uses no interactive prompt.
A separate process-bound private-terminal fixture passes two actual owner
authentications and separate in-memory intention transactions; effective grant
apply and kernel readback remain unimplemented.

The root storage unit test refuses unsafe owner/mode/link/corrupt cases under
the private development receipt directory; it never opens production storage.
Build all test executables as the unprivileged builder, copy only the reviewed
artifacts to root-owned development libexec paths, and run the exact root tests
in bounded transient units. Do not run Cargo or dependency build scripts as root.
Remove the temporary Polkit action file after the test. The fixed probe account,
policy module and provider selection use the lifecycle rollback above.

The ignored `system_bus_authorization` fixture tests fresh owner authentication
without a desktop agent. Build it unprivileged and copy its executable to
root-owned `/usr/local/libexec/greyward-application-security-fresh-auth-test`.
Copy `tools/greyward-dev/application-security-authorization.py` to the matching
root-owned libexec helper path. Install only the reviewed experimental action
file temporarily, then run the helper with `python3 -I` in a bounded root unit
named `greyward-application-security-auth-probe` (60 seconds, 128 MiB).
Its private terminal agent registers against the kernel-validated PID/start
time. The broker still checks the actual system-bus subject. Two operations
must produce two password challenges for separate register/remove intentions;
no effective grant or protection label is created. Only the owned
UID 1002 account receives a random temporary password, never printed or saved.
The original locked hash/change date is saved in a root-only recovery receipt
and restored on exit. An outer cleanup trap must also run the helper's
`--restore` command and remove the temporary action file. The lifecycle rollback
handles interrupted receipts before removing enrollment. Never target the
development user's password or desktop authentication agent.

The managed-code root test uses the private receipt directory, not production
storage. It proves a root-owned copy stays unchanged after a retained source
writer mutates the original, and rejects cache symlinks/hardlinks/corruption,
expired work, concurrent writers and the cache budget. No writable cache
descriptor remains after publication. This is content identity, not verified
provenance or effective confinement. A confined import worker with an external
hard deadline and protected-resource denial is still required before public
launch APIs can use it.

The `system_bus_broker` integration fixture additionally checks a real root
read server and its UID 1002 client. Run only the exact
`root_read_transport_enforces_scope_without_enforcement_claims` test in a
bounded root unit; it invokes the exact child test under the owned probe account.
The executable must first be built unprivileged and copied to root-owned
`/usr/local/libexec/greyward-application-security-broker-test`. Temporarily
install only the reviewed read policy, reload bus configuration, and remove it
afterward. Do not replace an existing broker or restart the bus. The fixture
uses an in-memory registry, returns UNKNOWN and leaves no active bus name.

The [experimental package](../../../security-center/packaging/application-security/README.md)
has also been built offline and its extracted binary tested under the packaged
service restrictions in a private filesystem namespace. Map only a root-owned
0700 development storage fixture onto the fixed database directory there;
clear `StateDirectory` for this probe so the host production path is not created.
Stop/remove the temporary unit and bus policy afterward. This scoped check is
separate from installed-package, production SELinux, provider and image gates.

The root MAC continuation uses the reviewed
`selinux/greyward_application_broker_probe.te` and
`tools/greyward-dev/application-security-broker-mac.sh`. Build the ignored
`broker_mac` test unprivileged, copy it to the fixed root-owned
`/usr/local/libexec/greyward-application-security-mac-test`, and stage the
policy/lifecycle scripts in the private development probe directory. Run the
script as the development user with the privately extracted experimental RPM
directory. It compiles policy without root, temporarily installs the synthetic
subject and broker modules, and preserves the packaged service restrictions.
The service gets a private namespace mapping of an owned 0700 storage fixture;
the host production database must remain absent. The actual domain is checked,
not selected by a test-only `SELinuxContext` override. Cleanup removes both
modules, the temporary unit/bus policy and separate-account enrollment.

On 7 October, extracted broker revision 3 passed `GetCoverage` and an empty
`ListApplications` under `greyward_application_broker_t`. Both responses retain
UNKNOWN health. SQLite is root-owned, mode 0600 and has the private state type.
The exact ignored root test also passed: process metadata is readable and the
synthetic credential is denied despite UID 0 and its mode 0644. DMS PID 4888
remained unchanged with SELinux enforcing. The initial policy failed service
name acquisition and caller proc metadata opens; reviewed server-name and
process-metadata permissions correct those boundaries without credential reads.
This proves the fixed read daemon boundary, not production whole-session
coverage, authorized mutations or import/launch worker confinement.

The same script additionally exercises a pre-opened synthetic credential FD.
Systemd and the system bus both reject transporting that FD; their policy was
not widened. A separate fixed synthetic producer domain opens it, then
automatically transitions its child to the broker domain with NoNewPrivileges
retained. Only the test producer can read the synthetic credential; it has no
ordinary application entry path and is never packaged as a production service.
The child verifies the credential is unreadable: this kernel sanitizes the FD
to its internal null character device during exec. The ordinary `/usr/bin/cat`
descriptor stays readable as a positive control. All three ignored FD fixture
tests pass; the child checks its actual domain and the selected descriptor.
The internal null inode need not share `/dev/null`'s filesystem/inode; the test
requires the null character-device number and EOF. This matches
[the pinned kernel's inherited-file revalidation](https://github.com/torvalds/linux/blob/v7.1/security/selinux/hooks.c).
It is an execution-boundary fixture, not a public import worker or a claim that
data previously read by an authorized application can be revoked.

### Flatpak read compatibility

The bounded pure-policy benchmark is
`tools/greyward-dev/application-security-policy-profile.sh`. It measures ten
index preparations and thirty warm passes over 2,000 synthetic records using
the exact current Cargo test artifact. It creates no enrollment or policy
database. See the approved plan for measured distributions and open enforcement
gates; source lookup time is not installed launch latency.

`tools/greyward-dev/application-security-flatpak.py` runs as the unprivileged
builder against an already installed system application. A disposable
`FLATPAK_USER_DIR` tests user-global/app override precedence and verifies that
removing `home` preserves an explicit path grant. Fourteen live checks pass against
Flatpak 1.18.4, including fresh default seeding and byte-identical retention
of existing global/app overrides. Stage the shared
`environment/flatpak/seed-system-permissions.py` beneath the fixture's fixed
`/var/tmp/greyward-application-security-build/environment/flatpak/` directory.
Installed applications and active user overrides are untouched.
The existing compatibility collector now uses the provider's canonical
effective context, not a second local-override merge. Read failures and
unsupported/oversized serialization remain unavailable/partial. Access
projections exclude environment values. Full layer attribution, portal grants,
permission mutation/readback and mandatory Protected Data remain open gates.

The explicit backend integration test `flatpak_provider` also passes an actual
read of the installed applications. The compatibility collector parses bounded
JSON rather than dropping malformed TSV rows, obtains full 64-character commits
from `info --show-commit` before/after permission inspection, and invalidates
permissions if the generation changes or cannot be read. Short hashes from
`list` are unsuitable generation bindings. Flatpak 1.18.4's successful empty
scope emits no bytes; that case is accepted only after command success, while
malformed JSON, duplicate refs and unsupported identity components fail.
Run `cargo test -p greyward-security-backends --test flatpak_provider --locked
--offline -- --ignored` as the unprivileged builder in the bounded development
unit. This checks read-only deployment evidence; it does not populate the root
registry, validate publisher provenance or establish protected-resource access.

### Fixed native worker

The canonical restriction core is now
`security-center/crates/greyward-application-security/src/native_restrictions.rs`.
The independent native-worker workspace has been retired after equivalent
private kernel checks passed against this runtime. Landlock 0.4.7 and libseccomp
0.4.0 are pinned in the product Cargo lock; libseccomp/libseccomp-devel on the
builder are 2.6.1-2.fc44. Missing dependencies or restrictions fail closed.

Stage the runtime sources, Cargo lock and its fixed
`tests/support/native_restriction_check.rs` driver beneath
`/var/tmp/greyward-application-security-build/security-center/`, then run
`tools/greyward-dev/application-security-native-worker.sh` as the ordinary
builder. The script resolves Cargo's exact current example artifact, copies it
into root-owned libexec and runs only its fixed separate-account fixture.
It accepts only `--fixed-probe`, UID 1002, the actual ordinary SELinux domain
and synthetic paths. It has no generic launch interface. The fixture temporarily
enrolls only the owned test account, uses a private namespace root and touches
no real credentials, production database or active desktop. Cleanup restores
mapping/labels/policy. The test driver is excluded from RPM installation.

The 7 October probe passes: PID 1 and user/mount/network/PID namespace identities
are checked against host identities; effective capabilities are empty. Fully
enforced Landlock rules permit the selected document and scratch only outside
`/usr` and the null device. Seccomp denies socket creation and a fixed set of
dangerous syscalls, with NoNewPrivileges verified. Fixed child `cat` executions
read the selected document and fail on ordinary outside/protected files. Removing
the required selected-document mount refuses execution before the synthetic
launch marker exists. The result explicitly says `profile_claimed:false` and
reports the requested ABI, not an unqueried actual ABI. There is no broad home
allow followed by negative path rules. This does not prove a production syscall
profile, descriptor sanitation for arbitrary workloads, restricted Wayland,
nested display, AppImage extraction, grant handling or a production runner.

The initial custom tmpfs label was denied to systemd during namespace setup;
that policy was not widened. A private scratch bind replaces it. Repeat testing
caught stale scratch labels after cleanup; fixture relabeling now covers only
that private synthetic tree. Cleanup quiesces/removes probe enrollment before
restoring labels, verifies SELinux enforcing and preserves the main DMS PID.

During initial acquisition/build, invoking the user's rustup shim upgraded its
stable toolchain to 1.99.0. This remains a development-tooling side effect; the
Fedora Rust/Cargo RPMs remain 1.98.0. Subsequent builds use the explicit Fedora
paths above. Earlier experimental RPM compiler receipts did not distinguish the
shim from Fedora and are insufficient as a pinned production build tuple.

### Directory catalogue and native RPM evidence

The runtime's metadata-only catalogue checks 13 fixed credential, cloud and
browser locations under an authenticated home descriptor. It never lists the
home recursively or reads secret contents. Supported directories remain
UNKNOWN; absence is Not present, aliases/unsupported files are Unavailable.
Three catalogue tests cover unreadable contents, aliases, owner checks, expiry
and review invalidation. Directory registration, labels, replacement safety,
custom resources and category presentation are still unimplemented.

`rpm_identity.rs` compares a held ELF digest/root mode with exact RPM file
metadata collected before and after hashing. Three ordinary tests and one
explicit read-only Fedora test pass. Weak/missing digests, duplicate owners,
configuration/ghost files, unsafe modes and ordinary-owned copies are refused.
The installed `/usr/bin/cat` fixture uses the fixed query format in that module;
run its ignored test in a hard-bounded development unit. RPM header/file
digests establish metadata/content coherence, not approved source provenance
or grant authority. That historical receipt/hash fixture predates the held
ancestry implementation below. Signatures/source approval, complete native
inventory and prepared launch binding remain open gates. See the
[RPM digest contract](https://rpm.org/docs/4.20.x/manual/signatures_digests.html).

The subsequent `installed_content.rs` proof holds each root-owned,
non-writable ancestor, opens the executable without aliases/mount crossings
and verifies path membership against the held objects. Run
`application-security-installed-content.sh` with its root-owned source test
binary staged as `/usr/local/libexec/greyward-application-security-installed-test`.
Three explicit root tests pass: replacement/ancestor changes, exact ordinary
copies/symlinks and a private bind alias. They create only synthetic fixtures
under fixed private development storage, with no enrollment or host mount.
The actual ignored Fedora RPM test passes using the fixed bounded metadata
collector and one shared deadline. Two backend tests verify environment
clearing and expired-query failure. No generic provider command is exported.
Separate `/usr` mounts/symlink paths are unsupported; provenance, complete
inventory and an independently bounded verification worker remain open.

The revision-9 offline experimental RPM build/check and extracted MAC/read/FD
fixture pass. The additional exact root test
`root_broker_installed_metadata_collection_retains_credential_denial` uses the
actual collector in `greyward_application_broker_t`, reads installed metadata
and still fails on synthetic credential content. RPM execute-without-transition,
read-only RPM database/code interfaces and self process-group lifetime
permissions belong only to the temporary broker policy. No credential grant,
RPM transaction or ordinary entry is enabled. Its helper test binary is built
separately; the revision-9 archive predates that ignored test, not the collector.
Current domain/runtime source counts are 81 ordinary and 19 explicit
Fedora/root fixtures; backend source adds 24 provider/read checks. Full workspace
formatter/Clippy, repository gates and cleanup pass. Exact artifact receipts
are in the [implementation authority](../../security-center/APPLICATION_SECURITY_PLAN.md).

### Disjoint grants and workload expiry

Stage `selinux/greyward_resource_grant_probe.te` and the three
`application-security-grant-*` tools under the fixed probe directory, then run
`application-security-grant-scope.sh` as the development user. This temporarily
enrolls only the synthetic account and removes both modules/mapping afterward.
The latest 7 October run passes 34 checks: ordinary 9 with NoNewPrivileges,
ordinary 9 without it, synthetic tool 8 and browser 8.
Only the tool reads its synthetic SSH resource; only the browser reads its
synthetic profile. Cross-resource reads and ordinary entry to grant domains
fail. Fixed exec children establish the no-credential type, read an ordinary
positive control and lose inherited raw credential descriptors.

The initial automatic transition lacked `nnp_transition` and retained the
grant type. A later attempt to change role was denied by Fedora's role-change
constraint. The final fixture keeps the role, drops the process type and grants
only the specific NNP transition into the ordinary baseline. It adds no
role-change exemption. Actual destination checks are mandatory; a failed child
command alone does not prove the transition.

The lifetime fixture starts a root-controlled system unit with an eight-second
runtime limit, one-second stop limit and whole-cgroup SIGKILL fallback. A parent
and forked child hold a synthetic raw grant and ignore SIGTERM. The independent
root observer verifies UID/domain/cgroup and holds both pidfds. Both terminate,
and the unit result is `timeout`, after the initiating launcher has exited.
This establishes the fixed lifetime mechanism, not a production this-run grant,
broker-crash integration, authorization transaction or revocation API. Real
SSH/browser/IDE profiles, in-process extension risks, helper compatibility,
policy compilation/cache and grant readback remain open. DMS PID 4888 and
SELinux enforcing are preserved; the account enrollment is rolled back.

### Bundled UI and source read profiling

The private source-binary WebKit/Tauri check passes using
`application-security-ui-check.sh`, `application-security-ui-session.sh` and
`application-security-ui-probe.mjs`. It runs only UID 1002 with a private
headless compositor, private network/runtime/home/config and a session bus
without activation directories. It does not attach to the active display or
launch installed session providers. The earlier UI smoke fixture used an
unconfined test subject and proved no confinement. The subsequent `--confined`
check positively matches the root-owned Tauri executable by device/inode in the
private cgroup and reads its live `greyward_guard_t` context. WebDriver
infrastructure runs in the separate temporary `greyward_ui_probe_driver_t`
domain without credential grants; only the root unit selects it. No
ordinary-subject entry to that driver is allowed. Both modules/mapping are
removed afterward. This validates a private window path, not complete enrolled
desktop/provider/grant compatibility. Whole-cgroup cleanup belongs to the fixed root unit, avoiding
numerical-PID cleanup races. The wrapper refuses an already busy test account.

The earlier debug binary SHA-256 is
`114e65cb3fb739f1f9149ac656eea94f194561e3fb9a93a1e8661aa534393b10`.
Bundled startup/request scripts load, existing allowlisted native IPC responds,
and WebKit reports a CSP violation while refusing an injected inline script.
All 85 frontend contracts pass, including synchronous transport timer cleanup,
truthful timeout semantics and a stale Updates response after leave/revisit.
Full page interaction, localization/accessibility, packaged UI and performance
protocols remain open.

The confined continuation first failed on infrastructure shell entry, private
bus AVC initialization, wlroots shared memory, nested Xwayland startup and
OpenSSL configuration reads. Those permissions belong only to the temporary
automation domain; the ordinary application policy was not widened to admit
them. The driver requires a positively matched live Tauri executable and does
not infer identity from process names. Unreadable unrelated Fedora collector
helpers are not attribution evidence. The final private unit completes in
2.898 seconds, with bundled scripts, native IPC and inline-CSP checks passing.
This single sample is not a performance acceptance measurement.

### Offline file deputies and package tasks

Stage `application-security-deputies.sh`, `application-security-deputy-probe.py`,
`application-security-task-probe.py`, `application-security-pip-input.sh`,
`application-security-pip-launch.py` and `application-security-pip-backend.py`
in the same fixed development stage as the feasibility helper and policy.
Run the unprivileged `application-security-pip-input.sh acquire` once to obtain
and verify the exact Fedora input. It extracts without RPM installation and
refuses an existing payload rather than replacing it. The root-owned receipt
records `python3-pip-26.0.1-3.fc44.noarch` and SHA-256
`5715def217cfaa500123a0461c607c580400780012fa8d6b004a4a073879f291`.
The development-only package resides under
`/usr/local/lib/greyward-development/pip-probe`; no production component uses it.

Then run `bash /var/tmp/greyward-application-security-probe/application-security-deputies.sh`
as the recovery user. The fixed transient unit runs only UID 1002, private
network/tmp, an enforcing subject domain and whole-unit runtime/resource limits.
All seven scenarios pass: real cp/rsync/tar/GPG export attempts, offline npm
preinstall/pip PEP 517 hooks and the real Flatpak runtime. Each has an ordinary positive control and a
synthetic credential denial. GPG actually enters Fedora's `gpg_t`; audit shows
its credential-directory denial. Task interpreters stay in `greyward_guard_t`.
The test skips neither package hook nor permission readback. No dependency is
downloaded by either task, no credential contents/command/environment telemetry
is stored, and enrollment/modules are removed afterward. DMS PID 4888 remains.

The first npm fixture used one `/dev/null` pathname for two configuration
scopes, which npm rejects. Separate empty files fix that fixture; no io_uring
workaround or broader SELinux permission is applied. Single-unit runtime
1.986 s/72 MiB/no swap is scoped fixture evidence, not a performance budget.
These probes do not complete all production service deputies, tool profiles,
portal grants, approved IDE tasks or whole-session coverage.

The seventh scenario runs the existing system Brave deployment's runtime shell
through real Flatpak 1.18.4, with explicit broad `home` access. It starts no
browser window and changes no installed application/override. Display, device,
session-bus proxy and document-portal access are disabled for this file probe;
the manifest's filtered system-bus proxy still starts. Ordinary input and
protected target/aliases are present; direct, symlink and hardlink reads fail.
The workload retains `greyward_guard_t` and zero effective capabilities. The
wrapper independently requires an AVC matching the synthetic credential inode,
reader and subject, not just a failed command. The final seven-case unit reports
2.014 seconds, 61.4 MiB peak and no swap; this is not a launch benchmark.

Flatpak initially failed in namespace setup before executing the test command.
The development policy now permits namespace loopback setup, tmpfs/proc/private
devpts creation, read-only bind remounts, scratch/deployment mount targets and
ordinary execution of the observed `var_lib_t` runtime. Recursive read-only
remount uses the filesystem interface instead of an incidental host-mount list;
it grants neither mounting every filesystem nor file/device access. Namespace
`CAP_SYS_RESOURCE` plus sysctl open/write permits bubblewrap's descendant limit
hardening. Host capabilities, DAC override, credential reads and grant-bearing
transitions remain denied. Parent-network changes, parent `/tmp` remount and
host namespace-limit write-open all fail; the host limit is unchanged afterward.
The exact final module also passes 33 subject/deputy/ptrace checks, the same 33
checks as namespace root, and 26 private bind-alias checks. The namespace
receipt confirms its restricted UID map rather than treating it as host root.
Cleanup restores mapping/labels/module and keeps
SELinux enforcing and the same active DMS PID. Full graphical Flatpak, portal
grants and other filesystem tuples still require separate acceptance.

Three source tests of `provider_inventory.rs` also pass: installation/channel/
repository/owner separation, partial or missing-generation preservation,
stale revisions and invalid batches. Intake is an internal registry transaction,
not provenance, a public mutation or a production provider enrollment.

### Typed Context continuation

Revision 10 includes Flatpak intake and bounded provider cleanup. Its offline
build/check and extracted MAC/Context/read/FD fixture pass. RPM SHA-256
`76057e7647b1e433f7b5fb24a9deac6126edd62b7e7b5301d20659efbed50e9e`,
source SHA-256
`810561cbde379f598273d04eba15144344fc6c344320eca0b4b73e0c37351ab0`.
The lock/compiler/runtime tuple is unchanged from revision 9. Subsequent
native observed per-member intake has two passing source tests and remains
outside this archive. It always uses partial refresh, preserves other members/
providers, and does not approve RPM signer/repository or updated grants.

Eight provider-runner tests pass, including admission retention/release and
actual child reaping. One background reaper retains at most 32 running/pending
children and their admission slots; request cleanup does not block on wait.
Kernel-uninterruptible I/O was not injected. Synchronous spawn/filesystem
verification and hostile process-group escape still need independent workers.
Missing or saturated providers are failures, not empty safe inventories.

`application_security.py` forwards only the three fixed broker reads through
the root system-bus socket. It verifies the root unique owner before calling it
and checks that ownership remains unchanged afterward. Closed JSON validation
rejects cross-user records, malformed generations, duplicates, stale pages,
contradictory protection, old evidence and oversized replies. Unknown inventory
does not become protection. The projection lease is at most five seconds and
cannot exceed remaining enforcement freshness. Missing providers have no
projection and an immediately expired unavailable state.

The 266 Context tests pass on Fedora, including 15 wire/transport tests and the
typed session-method adapter test. `application-security-broker-mac.sh` also
passes actual Context adapter reads against the revision-6 extracted RPM under
its temporary root MAC domain. Coverage remains UNKNOWN; the private database
stays root/0600 and host production storage is absent. Cleanup releases the bus
name, removes test units/modules/mapping and leaves DMS PID 4888 unchanged.
No Context package or production broker was installed for this continuation.

The subsequent shared-contract/facade debug binary SHA-256 is
`78acbbb6f90ad39a8bdce1d9ccdd7fab456f17d2204842bc274dd2a4ad8977b7`.
Its three asynchronous read commands share domain wire types with the runtime
and use seven tested backend decoders. The complete Rust workspace, formatter,
Clippy and 85 frontend contracts pass. Vendored Tao emits its six existing
dependency warnings; first-party Clippy passes with `-D warnings`.

The private window now starts `application-security-ui-context.py`, exporting
only the three source read methods, with no installed-provider activation or
mutating interface. The wrapper requires the host broker name to be absent
before this failure-path test. Actual facade/Context reads all return Unavailable
with no projection and an expired lease, while excessive pages/path selectors
are rejected. Native IPC and CSP tests still pass in `greyward_guard_t`.
The 5.136-second single run is not a performance budget measurement.
Source Python modules are copied into a root-owned read-only fixture outside
the private builder directory; its contents are not package acceptance evidence.
Private-bus messaging/ownership and logind metadata permissions are limited to
the temporary automation domain. Both modules/mapping are removed afterward.

The explicit ignored `reads` test
`profile_two_thousand_records_without_protection_claims` measures 30 warm
source samples with 2,000 synthetic records on .149. Median/p95/spread:
in-memory lookup 2/6/1–46 microseconds; list with serialization
26.088/29.624/24.564–30.540 ms; detail with serialization
23.407/25.044/21.960–25.358 ms. It includes caller revalidation but not D-Bus
transport, provider collection, production disk storage or launch. Every
projection stays UNKNOWN; this is not production/cold-start acceptance and
does not complete the full performance budgets.

`tools/greyward-dev/application-security-resource-policy.sh` tests the runtime's
generated denial CIL against synthetic objects in a separate confined account.
It requires the reviewed staged source and existing owned probe account, never
enrolls the development user and rolls back its modules/labels/mapping. Eighteen
alias/access/tampering checks and held-FD read/mmap positive/negative controls
pass. Compiler assertions are checked with a private root configuration; the
host's settings stay unchanged. Detailed hashes, failures, timings and remaining
registration/portal/session gates are in the approved plan's dated receipt.
