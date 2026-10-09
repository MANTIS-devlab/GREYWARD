# Application Security development evidence through 7 October 2026

Status: HISTORICAL. Chronological receipts retain their original scope and
may describe superseded source. This is not a current install recipe or a
production guarantee. See the [current plan](../../security-center/APPLICATION_SECURITY_PLAN.md).
The latest scoped receipt is invocation `55ab0132ea12409e80a4d1e6fe6f2566`;
earlier 285/89-test and revision-13 statements predate the latest continuation.

### Active priority: functional critical gates (7 October 2026)

The user's priority change limits the immediate acceptance sequence to these
five gates. Passing a source test or a synthetic policy spike alone does not
close a gate.

| Blocking gate | Status | Remaining proof |
|---|---|---|
| Descriptor-based resource registration | VALIDATED | Fixed separate-account flow: fresh owner authentication, held directory, schema-three journal and actual readback for four synthetic objects. |
| Reviewed kernel grants | VALIDATED | Generation-validated root-owned tool receives a disjoint read-only kernel context after a second fresh review; access withdrawal is verified after a third fresh review. |
| Isolated-account whole-session enrollment | VALIDATED | Real private PAM login and its user manager, direct interpreter/executable, user service and headless graphical processes are confined against the registered synthetic resources. Production enrollment remains separate. |
| End-to-end deny/allow/revoke and truthful state | VALIDATED | Ordinary/unknown direct workloads denied, reviewed tool allowed, explicit context bypass and spawned child denied, held-descriptor/new-open reads denied after revocation; public coverage remains UNKNOWN. |
| Minimum regression and rollback | VALIDATED | Private DMS/Labwc readiness and contexts, actual broad-home Flatpak ordinary control/protected denial, SSH recovery, unchanged active DMS PID 4888, Enforcing, password/labels/mapping/module restoration. |

Extra compatibility matrices, exhaustive portal/deputy and alias tests,
performance/reproducibility measurements, physical-seat/suspend tests, clean
image acceptance and release hardening are **DEFERRED HARDENING**. Existing
evidence remains scoped to what actually ran. These deferred tasks are not
blockers for continuing functional implementation; no release acceptance is
claimed. Immediately after the critical gates pass, resume the implementation
phases below without expanding the matrix. Fix bypasses, incorrect grants,
policy corruption, false PROTECTED results and core blockers immediately.

Critical acceptance evidence: `.149`, 7 October 2026, fixed
`application-security-registration-guard.sh --end-to-end`. Authentication unit
invocation `93a4ba7ef71f4eaeb04fcaa9914d7425` passed in 41.100 seconds with three
fresh owner challenges. Test artifact SHA-256
`70dc5b31a7a777c618d618e9377c161fca7f78e3ee44d632a19697530fb40e25`;
reviewed tool SHA-256
`96601026baf70d9374598587e357a72fea0fed1145e4889fe92888b6019ab8c9`.
The same sequence includes actual resource registration, kernel grants,
revocation, private PAM/user-manager/graphical startup and Flatpak checks.
All are development gates using synthetic data, not a production deployment.
The test tool and policy/compiler helpers are excluded from the archived RPM.

The resolved pipe failure was a missing descriptor/pipe permission from the
development root coordinator to its grant subject. Only standard pipe transport
was added; no unconfined socket, file-read or process-memory permission was
introduced. The tool's exact success marker and the held-descriptor exchange
are both required by the passing fixture. Files with symlinks, special objects,
unsupported mounts or over-budget trees remain unavailable; label registration
does not pretend to support them. The SQLite journal is operational state;
loading VERIFIED metadata after a restart cannot establish live protection.

Critical validation is closed for this fixed provider. The functional continuation
now exposes descriptor registration, native RPM grant review, immutable reviewed
launch, operation readback and revocation through the explicitly selected
development system bus and `greyward-guard`. Public activation, restart recovery
and production enrollment remain
implementation work, not passed features. Do not reopen the closed matrix unless
a subsequent functional change invalidates its evidence.

Functional transport evidence: `.149`, 7 October 2026,
`application-security-registration-guard.sh --workflow`, authentication invocation
`8d394822cb9a4baba6b3556f169adf6b`, PASS in 40.979 seconds with three fresh owner
challenges. Authentication artifact SHA-256
`eb795ee2d587ac69cc7e61f04d679341dd3413eaf4b3822ca75881df2d56e934`.
An actual confined client transfers its held directory over D-Bus, registers it,
reviews the installed `/usr/bin/cat` RPM generation, reads synthetic data through
the root-prepared immutable launch, then revokes access. Ordinary and unknown
direct execution, explicit context bypass and held/new descriptors after
revocation remain denied. The same run verifies private PAM/user-manager,
DMS/Labwc, broad-home Flatpak ordinary control/protected denial and restoration.
Active DMS PID 4888, SSH recovery and SELinux Enforcing are preserved. Global
coverage remains UNKNOWN; verified operation completion is a narrower fact.

The transport fixes preserve the incoming D-Bus call serial when queueing a
reply, permit only the kernel's metadata-only O_PATH descriptor receive check,
and add the typed launch-handle namespace. No content-read permission was added
to the system bus. Native grant identity now separately binds the composite RPM
installation generation and the raw immutable executable digest. Retired grant
subjects retain their types without access rules while live workloads exit.
The unchanged critical provider also passed invocation
`35f11aa839b24c7cbf061e9dd16e6b3e` in 41.375 seconds after extraction of the typed
kernel continuation; artifact
`7d3b02c7339c8831f8c9f1193db4ea3cb0899c7d6c4acdc241e46a96f639d517`.

The default installed broker remains read-only. The separate development bus
name is `systems.mantis.greyward.ApplicationSecurityDevelopment1`; mutation and
launch handling is limited to the enrolled UID 1002 provider and fixed private
storage. Revision-13 packaging source includes the explicit development binary
and CLI, with no service preset, automatic enrollment or image inclusion. It
does not replace the archived revision-12 package receipt.

Functional isolated runner continuation: `.149`, 7 October 2026, workflow
invocation `7db1d3dc20244e2788f0677d1552c339`, PASS in 40.653 seconds; authentication
artifact `f44a36e74d14deb76d5de0daca029acaa73373cc19a98c5e47b05440607782fb`.
In addition to the closed critical sequence, an unknown ELF selected through
O_PATH ran from an immutable root copy in private PID/user/network/mount
namespaces. Its disposable worker verifies those namespaces, equal non-root
UIDs, absent capabilities, Landlock ABI 9, seccomp and no-new-privileges before
exec. A public `/usr/lib/os-release` control succeeds; the host synthetic
resource is inaccessible. Candidate copying rejects registered-resource labels;
it is not a protected-file export API. The worker uses a private scratch/home,
no host display or session bus, and network off. Streams are transferred only
after its bounded readiness handshake, without recording application contents.
`greyward-guard --development run -- FILE [ARGS]` selects this experimental
disconnected path. This dated ELF receipt predates the graphical, script,
AppImage and shared Safe Open implementation described below.

### Functional product continuation — 7 October 2026

IMPLEMENTED in source: typed Center/Context registration, native tool READ grant
review, apply/poll/cancel and reference-based revocation; application/resource
details share grant records and the existing Activity history. EN/FR review
copy discloses raw credentials, in-process extensions and restart requirements.
The real peer UID/PID/start time owns bounded reviews; a frontend timeout is
never reported as backend cancellation or verified completion. Revocation needs
the existing grant reference, not the old executable remaining present.

The fixed kernel provider supports up to sixteen concurrent reviewed READ
grants. Updating one context preserves only other grants verified active in the
kernel; failed desired proposals cannot become access rules. Retired subjects
keep their labels with no access, bounded to thirty-two cached contexts. WRITE
and timed raw-access grants remain UNAVAILABLE.

The shared runner now supports ELF, validated fixed Python/shell interpreter
scripts and bounded x86_64 Type-2 AppImage extraction. It never executes a
downloaded AppImage runtime or uses an unrestricted fallback. Graphical ISOLATED
uses a broker-created Wayland security-context connection, a private nested
Labwc and separate clipboard. Payloads receive only the private display,
disposable home and disconnected namespace; private Xwayland is separate from
the host X server. The worker verifies capabilities, namespaces, SELinux,
Landlock ABI 9, seccomp and descriptor cleanup before announcing readiness.
ISOLATED environment lifetime is bounded to one hour.

Safe Open retains the selected descriptor through classification and shares the
same prepared-code/document runner and lifetime handle. The standalone
`build_command` sandbox was removed; its development test entry point redirects
to the combined workflow. A configured Flatpak document handler is explicitly
UNAVAILABLE until a Flatpak-preserving document provider exists; no alternate
handler or wrapper silently replaces the user's choice. Existing Flatpak
permissions and launches remain intact. The native document viewer path is
exercised through the actual Context adapter.
The native worker cannot preserve a Flatpak handler's document-portal and
sandbox contracts. A provider must integrate those contracts before this path
can be enabled; resetting overrides or silently selecting another viewer is
not an acceptable replacement.

`access_events.rs` reads a bounded root-owned audit tail and joins enforcing
SELinux AVCs to failed syscall UID evidence and registered resource types. Only
confirmed READ/WRITE/OPEN denials enter existing telemetry. No paths, process
titles, command arguments or content are exported, and attribution stays UNKNOWN.
Rotation, backlog and retained-event gaps are explicit. The existing shell
runtime performs ingestion before projection; its existing notification router
aggregates recent blocks with Review/Dismiss, quiet replacement and no Allow.
A denied attempt does not become a malware finding or certify coverage.

The installed guest compatibility tuple remains Center 59 / Context 64 /
DMS v1.6.2-6 on the active guest. The runtime spec is revision 14; the archived
revision-13 RPM is historical and does not contain this continuation. Production
enrollment, live whole-session coverage and package/image promotion are not
claimed. The isolated UID-1002 development opt-in does not change the active
desktop account; public snapshots remain UNKNOWN unless separately proven.

VALIDATED focused source evidence: `.149`, combined
`application-security-registration-guard.sh --workflow`, authentication unit
invocation `55ab0132ea12409e80a4d1e6fe6f2566`, outer exit 0 and inner PASS in
90.606 seconds with five fresh owner authentications. Authentication artifact SHA-256:
`d37c08add6b012571c3fc7a325141944570300cece67fed234eda5e57c3adc0f`;
the private GUI binary is
`ee9a8b49ec1012077cf085705373786ad9b078a51229fcbb3828a7dc3a072a9d`.
The real Context adapter
imports an actual enforcing resource denial, views an ordinary document through
shared Safe Open and refuses a protected selection. Native `cat` and `head`
grants coexist; revoking `head` preserves the live `cat` grant, and final
revocation denies existing/new reads. The same sequence executes isolated ELF,
script, Type-2 AppImage and graphical payloads; private WebKit/Tauri invokes the
real typed provider, renders the resource/grant and cancels a revocation review.
That GUI receipt verifies review/cancel, not a GUI password/commit walkthrough.
Rollback restores the probe password, labels, mapping and modules, removes the
opt-in, leaves UID 1002 idle and retains active DMS PID 4888 and SSH/Enforcing.

Focused validation also passes workspace Cargo tests and all-target Clippy
against Fedora's pinned `/usr/bin` toolchain, 296 Context tests, 94 frontend
contracts (three environment-dependent live tests skipped), and both repository
gates. Debug GUI compilation passes; no revision-14 RPM/image claim is made.

DEFERRED HARDENING: extended portal/deputy and hardware matrices, cache/performance
budgets, policy-context cache reclamation, document-cache retention, restart and
release/image reproducibility. Remaining functional limitations are the
Flatpak-native selected-document provider, WRITE/timed grants, automatic full
inventory population and production enrollment/coverage; these are not silently
classified as successful features or confused with the deferred test matrices.

Source regression after this continuation: workspace Rust tests and all-target
Clippy pass on Fedora with the pinned `/usr/bin` toolchain; all 285 Security
Context tests pass there. The 89 frontend contracts and both repository gates
pass on the host. The full Context suite is Linux-specific (O_PATH and POSIX
filesystem semantics); a Windows invocation is not acceptance evidence. No
additional performance, physical-seat, suspend, image or exhaustive deputy
matrix was opened.

Functional package checkpoint: experimental runtime
`greyward-application-security-experimental-0.1.0-13.fc44.x86_64` builds offline
with its ordinary `%check` suites passing. RPM SHA-256
`6cdf9d26c887090710d6099b04f0cd54bc70f6681c6738e94544cf84e599e27e`;
source archive `6978e2cc33f66660c34cb3b10354f534dc413f9aad971e72daad3945ef03ae8b`;
spec `8efb1e81b89f4512b45de72c15da164307b09c6613140b2bab1c55f0e98e5748`.
File ownership is root/root; the empty mount target is 0555, no scriptlets or
automatic activation are present. Extracted packaged CLI and worker correctly
refuse an absent broker and an unprepared UID-1001 invocation. These are package
build/refusal checks, not a claim that the release binary repeated the enrolled
kernel flow. The archived revision-12 receipt remains intact. Local artifact
and toolchain inputs are retained under ignored
`output/application-security/20261007-runtime13/`.

The package build exposed full host storage: Hyper-V paused the development VM
on Disk Full with only about 8 MB free on F:. The confinement flow and rollback
had already completed. An unused, unmounted generated September ISO was copied
and hash-verified on D:, then reversibly archived there to free about 5 GB.
Windows denied creating a symbolic link, so that old artifact's original F:
path is absent; its two preserved copies and receipt are in
`D:\GREYWARD-generated-artifact-archive\20261007-space-recovery\`.
The mapped development VM was resumed from its paused state, preserving active
DMS PID 4888, SSH recovery and SELinux Enforcing. No reset/reboot, mounted
installer mutation or image rebuild occurred. The package build then completed.
The host recovery receipt is retained in ignored
`output/application-security/20261007-host-storage-recovery.json`.


### Development evidence, 6 October 2026

The fixed `greyward-guard-probe` account on .149 is independent of `development-user`.
The development module and login mapping are never production inputs.
Installing Fedora SELinux development tools upgraded the test machine's policy
from 44.8 to **44.11-1.fc44**; this is the tested development tuple, not a
promoted production receipt. Portal package: **1.22.1-1.fc44**. Main DMS PID
4888 remained active and SSH/enforcing mode remained available during probes.

| Check | Actual result and scope |
|---|---|
| Synthetic subject suite | `application-security-feasibility.sh run`: 33 PASS, including native/copied/interpreter/shell reads, aliases, replacement/child labels, forbidden transitions and same-UID descriptor/memory/ptrace/signal/socket access. A real owner-domain SSH agent loads a synthetic private key; the ordinary subject cannot contact it. No real credentials are used. Ordinary files and sockets have positive controls. Fedora's user-domain template initially permitted socket connection to the owner; a dedicated non-userdomain fixes it, with an enforcing kernel `connectto` denial. An ordinary inode imported by rename initially retained its ordinary label; the narrow fixture now denies that import while preserving replacement created inside the protected tree. This fixed fixture is not arbitrary resource registration or a compatible production tool profile. |
| Session routes | `application-security-routes.sh`: actual SSH, user service and scheduled systemd timer each passed 24 checks in `greyward_guard_t`. The user manager's owner-context request failed with exec status 203. `application-security-tty.py`: private PTY, real login/PAM-session mapping and 24 checks passed; root's fixed `login -f` skips password authentication. Root helper uses a fresh transient service and explicitly selects the normal login execution context for its child. Physical TTY, greetd and authentication acceptance remain open. |
| Bind alias | `application-security-feasibility.sh aliases`: 26 PASS. The private transient unit's bind alias has the same device/inode and a kernel mount-table entry; its read is denied. No host or active-session mount is changed. |
| Headless desktop | Actual UWSM graphical target started Labwc and DMS API 34 on a private headless output/user bus. Configuration/plugins loaded. This does not establish real-seat login, native-lock or real-window acceptance. Dedicated production service domains remain required; USBGuard authority was not widened to ordinary applications. |
| Portal | Stock 1.22.1 **FAIL:** AddNamed/AddNamedFull exported a protected hardlink in an ordinary parent, though FUSE reads were denied. The pinned, private provider patch now passes 36 actual portal checks: ordinary four-method exports, new save-as, protected file/directory/hardlink rejection, existing-export symlink replacement and a real Flatpak runtime selected-document flow. The earlier 23-check count was incorrect: 21 native checks plus 15 Flatpak grant/revoke/persistent-provider checks gives 36. It is selected only for the probe account and is not a production replacement. Full Flatpak/FileChooser/login persistence and replacement races remain gates; no complete export-containment claim is permitted. |
| Scoped rollback | Probe login mapping/module/user context removed, fixture home labels restored and probe public-key access removed; original desktop/SSH stayed available. Re-enrollment and synthetic tests passed. Package rollback and production account migration remain unvalidated. |
| Rust foundation | 15 domain and 42 runtime tests PASS: 2,000 records/pagination, owner-scoped detail, generation/revision/corruption, stale previews, cancellation/readback, enforcement lease, live pidfd identity and exec/exit/forged credentials, candidate descriptor replacement/shared-offset/retained-writer cases, wire validation and bounded admission. Candidate hashing does not make mutable code immutable or authorize a launch. Two actual peer tests PASS against dbus-broker 37-8.fc44: ProcessFD credentials/disconnected-name rejection and fixed authority despite environment overrides. Pure operation tests do not establish worker cancellation; no production broker or grants exist. |
| Authorization boundary | Four unit tests bind a non-serializable, single-use five-second ticket to execution, bus sender, operation, purpose and revision; deadline/expiry and owner-to-system reuse are rejected. Two actual Polkit tests PASS: an unprivileged detailed check is rejected by the authority; a root client checking the separate UID 1002 subject cannot acquire an owner/system weakening ticket without authentication. Fixed auth_self/auth_admin actions are installed only during the test and then removed. A separate root/private-terminal fixture also passes two fresh owner password challenges against Polkit 127-2.fc44.2; it binds the agent to the actual PID/start time, uses a temporary random probe password and restores the original locked hash/change date. The agent never attaches to the active desktop. No policy change or grant is claimed. |
| Root filesystem storage | Explicit root-only test PASS in the private development directory: 0700 directory/0600 database creation, persistence, and rejection of wrong UID, writable mode/parent, hardlink, file/parent symlink and corrupt bytes. An existing zero-byte/schema-less database is rejected rather than silently initialized. It uses the same private constructor as the fixed production path without creating the production database or a daemon. |
| Typed read transport | Two explicit real-bus tests PASS: bounded root server and confined UID 1002 client. Own record is visible; foreign record is indistinguishable from absence. Claimed UID/extra fields, stale revision, oversized page, bus-name takeover and mutation calls fail. Coverage and inventory stay UNKNOWN. Temporary policy is removed and the bus name released; the in-memory fixture never creates production storage. |
| Experimental package | `greyward-application-security-experimental-0.1.0-1.fc44.x86_64` built offline with the pinned Cargo lock; RPM SHA-256 `761c96fb0e0321a11b7a954a356f88c954e0a7ac6941e4cd9acaf8f06d55a105`. Ownership/dependencies, no scriptlets/preset/activation, extracted non-root/argument refusal pass. Extracted binary with packaged service restrictions passes actual system-bus reads in a private filesystem namespace: database 0600/root in a 0700/root development fixture, fixed production path mapped only inside the unit. The host production database is absent. Source unit verifies; NoNewPrivileges, strict filesystem protection, limited capabilities and 128 MiB cap are observed. This is not installed-package, production SELinux, cold/warm performance or release acceptance. The RPM is excluded from production/image inputs. |

### Read compatibility continuation, 7 October 2026

Eleven new backend tests pass for bounded provider output/deadlines, canonical
Flatpak permission handling, unavailable reads, explicit paths, bus denials and
excluded environment values. The live disposable-override probe passes nine
checks against Flatpak 1.18.4 without changing installed applications or active
user overrides. The frontend suite passes 79 checks, including EN/FR unavailable
application rendering. Flatpak collection shares an eight-second backend
budget; named installations not covered by the compatibility adapter are
reported as partial. Full provider layer attribution, portal grants and
permission mutation remain pending. These are source compatibility corrections,
not installed Security Center or Protected Data acceptance.

The experimental broker also builds offline as `0.1.0-3.fc44`; its RPM SHA-256
is `86c8e837ff6c7bb28d05fb5c1ee160f941ef44aa60b1081404d6081d568d86c0`
and source archive SHA-256 is
`94b1e286e9c2437a7953c099adfaeb1dd02ef53e7723274762e232e4bce3e4e6`.
It includes the managed-content/authentication foundation. The extracted-service
check in the preceding table was performed on revision 1. A separate 7 October
revision-3 check passes actual typed reads under the experimental root SELinux
domain, retaining the package's service restrictions and UNKNOWN responses.
Its database has the private state label, root owner and mode 0600; no host
production database is created. The same domain is denied synthetic credential
content. Cleanup removes both probe policies, the temporary bus configuration
and unit, and restores separate-account mapping/labels. DMS PID 4888 and SELinux
enforcing remain unchanged. This is scoped MAC/read compatibility, not whole
session, mutation, worker, installed production package or image acceptance.
None of these packages is installed, activated or a final release input set.

The next source checkpoint, `0.1.0-4.fc44`, builds offline and passes its ordinary
runtime/domain `%check`. RPM SHA-256:
`ebf975b4d63505fe22cf1431010d653eebc198f669a458d65a14d259fe1e285f`;
source archive SHA-256:
`89f5de33caae48b5308d9e176e55397b9b3e6315ad8f27c00c726b8b3ec45eac`.
Ownership/dependency inspection and the revision-4 extracted MAC/read/FD
fixture pass. It contains provider-scoped reconciliation and the new ignored
root fixtures; those root fixtures were explicitly executed separately, not
counted as ordinary RPM tests. It ships no SELinux producer/probe policy,
activation or package scriptlets. This remains an experimental package outside
the production tuple; root providers, enrollment and mutations are incomplete.

Provider-scoped registry reconciliation now preserves other providers. Partial
discovery can update observed generations but cannot infer uninstall from
missing records. Complete discovery removes only its own provider records;
cross-provider identity collisions and stale SQLite revisions are rejected
atomically. Three additional ordinary Rust tests pass (60 foundation tests
in total). Live collectors and their completeness/readback evidence remain
unimplemented; revision 3 predates this reconciliation source change.

The existing Flatpak read adapter now carries full deployment generations and
an independent identity-read state. Bounded JSON rejects malformed/duplicate
refs; commits are read before and after permissions, and a changed/unreadable
generation invalidates those permissions. Two further ordinary backend tests
pass (13 new compatibility tests total), and the explicit installed-provider
test passes on the six system applications. Empty user-scope output is verified
as a successful empty inventory, not a failed read. No root-registry import,
publisher verification, permission mutation or Protected Data claim follows
from these observations. The frontend compatibility suite remains 79 PASS.

The inherited-FD continuation passes three additional explicit Rust fixtures.
A fixed synthetic producer domain opens the credential, then its child makes
the real automatic broker-domain transition with NoNewPrivileges retained.
The child receives SELinux's internal null device instead of the protected FD
and verifies EOF; an ordinary executable FD remains readable. The producer
alone is permitted synthetic credential access and is excluded from production
packaging. Systemd/system D-Bus credential-FD transport is also denied; those
services were not widened. This follows
[kernel 7.1's inherited-file revalidation](https://github.com/torvalds/linux/blob/v7.1/security/selinux/hooks.c)
and does not establish a public import worker or revocation of already-read data.

The read API source and experimental package boundary are documented in
[`security-center/packaging/application-security/README.md`](../../../security-center/packaging/application-security/README.md).
List pagination uses a bounded limit, expected inventory revision and opaque
installation cursor. The real peer supplies ownership; the API accepts no UID,
path or command. Mutations, enrollment and launch operations remain unavailable.
The latest probe rollback removed its login mapping/module, restored synthetic
labels and revoked probe public-key access. The existing DMS PID remains 4888;
SELinux stays enforcing. No active desktop or installation VM was restarted.

Reproducible sources are in `spikes/application-security/` and
`tools/greyward-dev/application-security-*`. Raw synthetic probe JSON and the
restricted source inventory are retained under ignored
`output/application-security/`; no secret contents or recovery private keys
are collected. Source gates, package-only checks, performance, ISO and clean
installation must be recorded separately when run against the resulting code.

### Descriptor and native-worker continuation, 7 October 2026

Seven new ordinary Rust resource-selection tests pass (67 foundation tests in
total). `DirectorySelection` holds an O_PATH directory descriptor, exposes no
content/launch descriptor and reads metadata only. `openat2` beneath the trusted
base refuses traversal, symlinks and mount crossings. Owner mismatch, expired
review, changed metadata, individual files and unsupported filesystems fail
closed. A directory lease is not persistent resource identity or verified
coverage; labeling, inheritance, atomic replacement and authorized registration
remain unimplemented. The first test run correctly rejected Fedora's tmpfs
`/tmp`; positive fixtures now use Btrfs `/var/tmp`, without widening eligibility.
An additional explicitly executed root test verifies a private bind alias has
the same inode as the selected directory but returns EXDEV through this selector
(14 explicit Fedora/root fixtures total). No host mount or user resource changes.

Historical prototype evidence: the independent native-worker workspace (now retired) and fixed
`application-security-native-worker.sh` pass synthetic runtime checks on the
separate account. Actual UID/domain, PID 1, distinct mount/PID/network/user
namespaces, narrow UID mappings and empty effective capabilities are verified.
Landlock rules must be fully enforced; the worker verifies NoNewPrivileges and
seccomp filter mode, selected-document/private-scratch access, denied outside
and protected reads, socket-creation denial and inherited child-exec denial.
Missing selected input refuses before the synthetic launch marker. Output
claims no profile and identifies the requested ABI only. This is not arbitrary
workload sanitation, graphical isolation, an AppImage provider or production
Guard. Root-owned private fixtures and bounded units preserve the active DMS
PID 4888; enrollment/mapping/labels are rolled back after each probe.

An initial custom tmpfs label was denied to systemd; no permission was widened.
A private scratch bind replaces it. Repeat testing also caught restored labels
on old synthetic scratch files; only that private tree is relabeled for a run.

Initial standalone compilation invoked the development rustup stable shim,
which upgraded it to 1.99.0. The Fedora Rust/Cargo RPMs remain 1.98.0-1.fc44.
Subsequent builds explicitly select `/usr/bin/cargo`, `RUSTC=/usr/bin/rustc` and
`RUSTDOC=/usr/bin/rustdoc`. Earlier experimental package receipts recorded the
installed RPMs, not a proven compiler path, and are not an exact production
toolchain receipt. The revision-5 experimental spec fixes those compiler paths;
its build validation must be recorded independently when run. No existing
working tree, active desktop or installer VM was reset or restarted.

The complete Rust workspace tests pass using Fedora's explicit compiler, and
the direct Fedora formatter passes. Validation must invoke
`/usr/bin/cargo-clippy clippy` and `/usr/bin/cargo-fmt fmt` directly, with
`CARGO=/usr/bin/cargo`: Cargo's external-command lookup selected the home
Clippy shim even with a fixed PATH and exposed a 1.98/1.99 mismatch. That failed
lint run is not a passing check; the direct Fedora rerun is recorded separately.

The direct Fedora Clippy rerun passes the full workspace/all targets with
warnings denied for project code. Existing vendored Tao warnings remain capped
as dependency warnings. The revision-5 experimental RPM now builds offline
through `tools/greyward-dev/build-application-security-experimental.sh`, including
ordinary runtime/domain tests. Source SHA-256:
`55dc48faa1d150e8ea42b1e0f78927d6cb6e92e9588852f6ddf365460b57a743`;
RPM SHA-256:
`d823000ed4aff329aca40d8723785d3c19efb406ee95b670c1ce67785090df20`.
Recorded tools are Fedora Rust/Cargo 1.98.0, Clippy 0.1.98 and rustfmt 1.9.0;
SQLite 3.51.2-2.fc44, dbus-libs 1.16.2-1.fc44, systemd 259.8-1.fc44 and SELinux
policy 44.11-1.fc44 are development inputs. Root ownership, no scriptlets and
the exact extracted revision-5 MAC/read/inherited-FD fixture pass. The host
production DB remains absent; temporary policies/mapping are removed and DMS
PID 4888 stays active. This is a development receipt, not production enrollment,
an installed package, a final release tuple or image acceptance.

Eight new Context tests pass (250 total on Fedora) for read-only history/digest
projection, ingestion-owned findings, duplicate-import resolution preservation,
device review/disconnect, unavailable/corrupt history, resumable backfill across
VACUUM, interrupted migration and background ingestion ordering. Existing
history stays in the same store. The background shell collector imports the
root spool and backfills at most 64 existing events per cycle; history reads
do neither. A stable event-ID cursor and derived findings commit atomically,
preserving resolved findings. Live provider reads can still reconcile device
observations; this does not yet complete all Phase-6 projection/controller work.
The new source is not deployed or accepted as a new Context package. Phases
0–1 remain in progress; preparatory debt corrections are not later-phase gates.

### 7 October continuation: native evidence and resource grants

The foundation now has 73 passing ordinary Rust tests and 15 explicitly run
Fedora/root tests. The six added ordinary tests cover RPM serialization/object
eligibility and metadata-only catalogue discovery; the additional explicit
Fedora test compares the held `/usr/bin/cat` SHA-256/root mode against installed
RPM receipts before/after verification. Root-owned copies and RPM digest
coherence are not a publisher/source approval, grant or launch authority. No
complete native inventory or installed provider has been added.

The catalogue checks 13 fixed locations without reading contents or crawling
the home. Directories are UNKNOWN, missing locations Not present and unsupported
objects/aliases Unavailable. Its held review leases do not establish labels,
atomic-replacement safety or registration. Phase 2 is preparatory only.

The separate-account grant fixture passes 34 checks across ordinary/tool/browser
subjects, disjoint resources, restricted child types and inherited descriptor
sanitation. Initial NNP and role-transition attempts failed; the tested policy
keeps the role and permits only the specific NNP transition to the no-credential
type. It adds no role-change exemption. A separate root-owned eight-second
workload limit terminates the grant holder and its forked child even while they
ignore SIGTERM; the observer verifies their identities/membership with pidfds
and the unit timeout result. This is not production grant authorization,
revocation or broker-crash acceptance. Temporary modules and account mappings
are removed, SELinux stays enforcing and DMS PID 4888 is unchanged.

The runtime's direct Fedora Clippy check passes after these source additions.
The revision-5 RPM receipt above remains a historical checkpoint of its exact
source input; it does not package these newer source additions. No production
tuple, installed-package acceptance or clean-image result is claimed.

### Read adapter and confined UI continuation, 7 October 2026

The source Context adds only typed `GetApplicationCoverage`,
`ListApplications(ubts)` and `GetApplication(s)` reads. It pins the root broker's
unique system-bus destination, verifies root UID and rejects owner changes.
Closed validation covers caller ownership, generations, revision/cursor order,
protection/isolation gates and freshness. No arbitrary operation, claimed UID,
path, launch or mutation is forwarded. An absent provider is Unavailable with
no projection; valid transport does not change UNKNOWN inventory/protection.
Leases last at most five seconds and never outlive enforcement evidence.

All 266 Context source tests pass on Fedora, including 15 wire/transport checks
and the typed session-method adapter check. Actual adapter reads also pass in
`application-security-broker-mac.sh` against extracted revision 6, retaining the
root/0600 private database, UNKNOWN coverage and synthetic credential/FD denials.
Context 64 remains installed; these source additions are not package acceptance.

The revision-6 offline experimental RPM/check/ownership inspection passes.
RPM SHA-256: `8718279d387b2f2c7c7c59c1a8b6d419f660b7337f975ad10fdcc0efcc020ef9`;
source archive SHA-256:
`29c816ae0be2e3c619d5ad303ad17af4d0e87670072d94033aa204e4e8762689`;
Cargo lock SHA-256:
`150c99e035f309706fe1426e4600b6ed681d863e2d2e0b609d5928108663946f`.
It uses explicit Fedora Rust/Cargo 1.98.0 with SQLite 3.51.2-2, D-Bus 1.16.2-1,
systemd 259.8-1 and development SELinux policy 44.11-1. It has no scriptlets,
activation or production/image input. This immutable archive predates the
new Context adapter and source read benchmark; it is not the current complete
Security Center/Context package tuple.

`application-security-ui-check.sh --confined` passes with the root-owned Tauri
executable positively matched by device/inode in the private unit and observed
in `greyward_guard_t`. Temporary WebDriver infrastructure has its own
`greyward_ui_probe_driver_t` domain and no credential grants; root alone selects
it. Bundled scripts, allowlisted native IPC and authoritative inline-CSP denial
pass. The 2.898-second single run is not a performance measurement. Both modules,
probe mapping and private services are removed afterward; SELinux remains
enforcing and main DMS PID 4888 is preserved. This is a private window path,
not complete enrolled desktop, provider, grants or real-seat acceptance.

The 30-warm-sample/2,000-synthetic-record source read fixture passes: median/p95
lookup 2/6 microseconds, list 26.088/29.624 ms, detail 23.407/25.044 ms. It includes
caller revalidation and serialization, excludes D-Bus/providers/production disk
and launch, and preserves UNKNOWN. Cold, packaged and full budgets remain open.

### Shared facade and installed identity continuation, 7 October 2026

Shared inventory/coverage wire types now serve the runtime, Context validation
and three asynchronous Tauri read commands. Seven backend decoder tests pass.
The private confined Tauri binary
`78acbbb6f90ad39a8bdce1d9ccdd7fab456f17d2204842bc274dd2a4ad8977b7`
passes all three facade reads through the source Context methods: absent broker
means Unavailable, no projection and an expired lease. Invalid page/path
selectors are rejected, and native IPC/bundled scripts/inline-CSP checks pass.
The unit's single 5.136-second run is not performance acceptance. It removes
its temporary modules/mapping and preserves DMS PID 4888.

The revision-7 offline experimental package passes its package checks and the
extracted root MAC/Context-read/credential-FD fixture. RPM SHA-256:
`62f521e092a77de9e6430ab21d049158ce90ae78fc1c496736af9ccf554c9198`;
source SHA-256:
`ba654df849c754bab3d8b9a32197f01e7684dc87b8fe285205b53519006d2aeb`.
Revision 8 subsequently passes its offline build/check with installed ancestry
groundwork, but was not separately run as a service. RPM SHA-256:
`81b3b92a0d2be968d0e3ebbb218618e250c41acae0161589f337c482fa8809df`;
source SHA-256:
`369f200f10b03b678fbe04e07000f617605385074d9fc16a1a4fe459b0f36f7b`.
Both use the earlier lock receipt and explicit Fedora tuple above. Neither
contains the following collector changes or establishes a promoted Center/Context tuple.

The installed-file proof holds each root-owned, non-writable ancestor and a
read-only ELF descriptor, checking continued path membership and metadata.
Symlinks, magic links, mount crossings, writable ancestry and replacement
invalidate it. Root-private tests cover identical ordinary-owned copies,
ancestor replacement and a real bind alias. The provider uses one canonical
domain path selector, a fixed RPM query, a clean environment, bounded output
and one shared metadata/hash deadline. Changed receipts or a different path
cannot acquire the binding; `/usr/bin/cat` passes the actual Fedora collector.
This is content/metadata coherence, not publisher approval, immutable launch
code, full inventory or grant authority. It assumes the broker's trusted
filesystem namespace and still needs an independent verifier worker deadline
for stalled filesystem calls. Separate `/usr` mounts and symlink paths are
currently unsupported, not accepted through a weaker fallback.

At the revision-9 checkpoint: 76 ordinary tests; 19 explicitly run Fedora/root
fixtures. Backends add two clean-environment/deadline tests to their existing
20 new provider/read checks. Scoped Rust tests and the complete workspace
formatter/Clippy pass; no dependency version was refreshed. The experimental
revision-9 offline package build/check passes. RPM SHA-256:
`58b1c99826a3e7269251147faec61454754028e01a7e673dbf14c87cdb9cd9c8`;
source SHA-256:
`817aaf448712a82f8f1888e81e1778d5d3ba574f86e7836bb4a1cfca214ee22f`;
lock SHA-256:
`9521e9de23dbd6c4bf64844b7e00c46a8393e2434dd4ae302e6d9156df506d3a`.
The only additional lock change is the existing backend workspace dependency;
no external dependency version changed. The archive predates the new ignored
MAC collector fixture, not the collector implementation.

Its extracted service passes typed Context/root reads and the separately built
MAC fixture. The root broker collects `/usr/bin/cat` under its dedicated domain
while synthetic credential content/FD access remains denied. Temporary policy
uses RPM execution without the RPM package-domain transition, read-only
database/code interfaces and self process-group/lifetime permissions; it adds
no credential permission or ordinary-subject entry. Cleanup verifies Enforcing,
unchanged DMS PID 4888, no broker bus owner, no probe mapping/module and no
production database. Both repository gates pass. This is still an experimental
read broker, not installed production enforcement or a promoted Center/Context
tuple. Full inventory, source provenance, worker/session policy and every later
phase gate remain open. No reboot, active desktop restart or image change occurred.

### Offline task/deputy and inventory continuation, 7 October

The fixed separate-account `application-security-deputies.sh` passes six
positive/negative scenarios: cp, rsync, tar, GPG store, an actual offline npm
preinstall hook and an actual offline pip PEP 517 build hook. Ordinary input
works; synthetic credential reading/export does not. Kernel AVCs identify
GPG's actual `gpg_t` transition and the task interpreters in `greyward_guard_t`.
No raw secret contents, command lines or environment values are recorded.
The npm fixture initially failed because it loaded `/dev/null` as both user
and global configuration. Separate empty files correct the fixture without
widening policy; the attempted `UV_USE_IO_URING` workaround was removed.
Observed io_uring denials were not evidence that the task had run.

Pip is not installed on the guest. Its signature-checked Fedora input is
`python3-pip-26.0.1-3.fc44.noarch`, SHA-256
`5715def217cfaa500123a0461c607c580400780012fa8d6b004a4a073879f291`.
The acquisition/extraction tool retains a root-owned receipt and exposes only
the Python package under a development-only root-owned read-only directory.
No RPM scriptlets, runtime installation or production input change occurs.
Both package tasks have private networking and no dependency downloads.
The six-case unit reports 1.986 seconds and 72 MiB peak/no swap; this single
fixture is not launch/performance acceptance. Mapping/module cleanup,
SELinux enforcing and unchanged DMS PID 4888 are verified.
Other service deputies, production tool profiles, real-seat login, portals,
grant/workload lifetimes and the mandatory full-session gate remain open.

The subsequent real Flatpak broad-home case passes against the existing system
Brave deployment/runtime, without launching its GUI or changing any override.
Ordinary input works, protected direct/symlink/hardlink targets are present but
unreadable, the runtime stays in `greyward_guard_t` with no effective capabilities,
and an exact synthetic-inode kernel AVC is required by the wrapper. It disables
display/device/session proxy/document portal for this scoped file probe; the
manifest's filtered system proxy remains. Initial setup failures are recorded
as Unavailable, not successful protection. The pinned bubblewrap setup needs
descendant namespace network/limit capabilities, scratch/deployment mount
targets and ordinary runtime execution. Recursive read-only remount is allowed
without granting arbitrary filesystem mounts or data/device access. No host
capability, DAC override or grant transition is added. The same module passes
33 subject/deputy/ptrace, another 33 checks as namespace root, and 26 private
bind-alias checks. The namespace maps only UID 1002 and retains visibility of
the live owner for process/socket/agent bypass attempts; actual root and other
UID maps are refused by the helper. Parent network/mount
changes and host namespace-limit write-open are rejected; the host limit stays
unchanged. The seven-case unit takes 2.014 seconds/61.4 MiB/no swap, a fixture
measurement only. Mapping/labels/module rollback, enforcing mode and unchanged
DMS PID 4888 pass. Normal graphical/portal compatibility remains open.

The namespace behavior was traced against pinned
[bubblewrap setup](https://raw.githubusercontent.com/containers/bubblewrap/v0.12.0/bubblewrap.c)
and [bind-remount implementation](https://raw.githubusercontent.com/containers/bubblewrap/v0.12.0/bind-mount.c).
The kernel's mount-namespace capability checks and namespace-specific ucount
tables explain the intended boundary; this is an inference checked by the live
negative probes, not proof of the complete release threat model.
[Kernel mount checks](https://raw.githubusercontent.com/torvalds/linux/v6.18/fs/namespace.c),
[namespace limits](https://raw.githubusercontent.com/torvalds/linux/v6.18/kernel/ucount.c).

`provider_inventory.rs` now converts observed Flatpak metadata to the shared
registry in one expected-revision transaction. System/user installation,
architecture, branch, repository and owner distinguish installation identities;
an update changes generation. Partial inventory or missing deployment evidence
cannot remove prior records or another provider's entries. Provenance remains
UNKNOWN; deployment metadata grants no access. Three Fedora source tests pass
for these cases, stale revisions and invalid/duplicate descriptors. Current
ordinary domain/runtime count is 79; explicit Fedora/root fixtures remain 19.
Scoped runtime Clippy passes with `-D warnings`. This intake is internal:
it does not expose a session mutation, populate the production broker or
complete provider/permission/session coverage. Revision 9 predates this
intake and these development-only tools; its receipt is historical for them.

The shared fixed-provider runner also removes blocking wait from failed-request
cleanup. One background reaper retains unreaped leaders and their admission
slots; running and retained children together are capped at 32. Saturation
fails the provider. Eight provider-runner tests pass, including output/error
bounds, inherited-pipe timeout, real child exit and admission retention/release;
the two new checks bring new backend provider/read tests to 24. Scoped backend/
runtime Clippy and the workspace formatter pass. Kernel-uninterruptible I/O
itself was not injected; stalled synchronous spawn/filesystem verification and
hostile process-group escape still require independent worker boundaries.
No such workload is presented as successfully cancelled.

Revision 10 builds/checks offline with the same Fedora tuple and lock above.
RPM SHA-256:
`76057e7647b1e433f7b5fb24a9deac6126edd62b7e7b5301d20659efbed50e9e`;
source SHA-256:
`810561cbde379f598273d04eba15144344fc6c344320eca0b4b73e0c37351ab0`.
The extracted service passes the MAC/Context-read/credential-FD fixture, with
UNKNOWN enforcement, root/0600 private storage, no production database and
unchanged DMS PID 4888. The separately compiled root MAC collector exercises
the background reaper without credential access. No automatic activation,
runtime installation, image input or Center/Context version change occurs.

The subsequent native intake derives an observed registry identity only from
the installed descriptor/content binding. Executable members, architectures
and owners remain distinct; updates replace generation and invalidate the old
generation reference. One-member intake is always partial, preserving other
native members and Flatpaks. Repository/signer identity remains unverified:
RPM membership cannot approve source or transfer a grant across updates.
Two source tests pass and runtime Clippy passes; current ordinary domain/runtime
count is 81, explicit Fedora/root fixtures 19. This native intake is outside
the revision-10 archive and has no production population API. Full native
discovery, source verification, independent workers and phase dependencies
remain open.

## 20. Validation

Run repository static/documentation gates, Rust fmt/test/Clippy, frontend
contracts and packaged real-window interaction/startup/performance, and Python
Context tests from the domain README. Add identity/PID-reuse, resource
inheritance/replacement/alias, direct/interpreter/service/SSH/TTY execution,
ptrace/proc/signal/socket/D-Bus, deputies, FD/environment/display/network escape,
authorization/stale preview/expiry/crash, Flatpak/portal, corruption/full storage/
missing primitive, UI/profile/coverage and existing lock/network/USB/recovery/
update/installer regression suites. Negative tests assert access AND displayed
state; missing telemetry never implies success.

### Local presentation history replacement — source evidence

The former Rust JSON writer is removed after reference audit. The new
`greyward_security_context/local_activity.py` imports its fixed legacy file
once into the existing telemetry store, with transactional deduplication and a
migration receipt. It retains the original file for rollback and preserves
other security history when clearing this collection. New records carry
unverified, non-authoritative presentation quality. No second event database,
generic Context command or new webview permission is added.

Nine focused Python tests cover interrupted commits/replay, retention, bounded
ordering, redaction, forged metadata and unsafe migration inputs. All 276
Context source tests and 86 frontend contracts pass on Fedora. Rust decoder
tests reject unavailable/malformed history instead of treating it as empty.
The private confined Tauri smoke passes export → shared Context history →
clear → empty readback, along with typed broker-unavailable reads and browser
CSP enforcement. The application is positively matched in `greyward_guard_t`.
The development-only automation domain permits SQLite WAL mapping for ordinary
user history; it gains no credential access or application-to-driver transition.
Fixture runtime 15.371 s and peak 626.3 MiB are not performance acceptance.
Temporary modules/mapping are removed and DMS PID 4888 is unchanged.

The source binary receipt for that run is
`1ac0c323c13a2d10cf78a981e451ccaf23565246ef0eb087129c9d5bb9206369`.
The current Cargo lock adds the already-pinned D-Bus crate to the backend;
SHA-256 `ab0b37adc6e52879571b1a92a87c2f5357559e4f5a87a167fef2fc82e3e0aacc`.
The revision-10 RPM remains historical and does not cover this replacement.
The subsequent matching source-window smoke, including bounded provider startup
and updated EN/FR clearing disclosure, also passes. Binary SHA-256
`43c924b54897855804dd85be94557880b56b958cf999acc19364fb69780e7505`;
fixture runtime 15.397 s, peak 831.8 MiB, no fixture swap. Its source build took
37.878 s and used 295.3 MiB swap; these are development receipts, not startup,
idle-memory or release performance acceptance.
Matched Center/Context packaging, full frontend refactoring and installed
acceptance remain pending. See the canonical
[storage contract](../../telemetry/PRIVACY_STORAGE.md) for clear/backup semantics.

### Provider startup deadlines — source evidence

The fixed provider runner now executes startup and pipe collection in four
long-lived workers, with at most eight outstanding jobs. The requesting thread
has a real deadline even when spawn stalls before a child handle exists.
Timed-out work retains admission until it returns; expired queued work never
starts. Saturation and failed workers report provider failure. This is not
cancellation of kernel-stalled work or confinement of hostile executables.
The existing 32-child cleanup budget and one background reaper remain in force.
The subsequent broker read worker covers peer process/filesystem/SQLite reads
as described below. Independent launch/resource descriptor/content preparation
still needs its own worker boundary; the production launch worker remains
unimplemented.

Ten focused provider tests pass on Fedora, including held-work timeout,
expired queue/admission retention, actual child cleanup, inherited-pipe timeout,
output limits and clean metadata environment. Workspace Clippy passes. No
kernel-uninterruptible I/O was injected; the held-worker test exercises the
deadline/admission behavior without disrupting VM storage. Experimental RPM
revision 11 builds offline and passes extracted MAC/read/FD checks; it is
excluded from production inputs.

The package is `greyward-application-security-experimental-0.1.0-11.fc44.x86_64`;
SHA-256 `50aa9c27b75da5fcd8e607f79f1030e548b562a9d2cb2ced8c9dfa154c34bc70`.
Source archive SHA-256
`4923b092633d6df8ecce418ff08cf67a4d7430c5e9237480b88c33a251c394b4`.
Build/check used Fedora Rust/Cargo 1.98.0, the recorded lock, SQLite 3.51.2-2,
D-Bus 1.16.2-1, SELinux policy 44.11-1 and systemd 259.8-1. Ownership is root;
there are no activation scriptlets/presets. The matching MAC test executable
SHA-256 is `ae4ec16be2ebb55d7e5dd49fba3ac051797a424493e2765cc056f4c2a1f7c19f`.
The extracted broker retains UNKNOWN protection, verified root-owned 0600
storage in its private namespace and denial of synthetic credentials/inherited
FDs. The production database remains absent. Module/mapping cleanup passes;
SELinux stays Enforcing and DMS PID 4888 is unchanged. The 4 min 16.666 s
cold build/check duration is a development receipt, not release performance.

`build-application-security-experimental.sh --warm` rebuilds the same archive
and spec against the private Cargo cache, with no acquisition/installation.
Warm build/check passes in 11.719 s; both extracted broker binaries have the
same digest. Warm RPM SHA-256 is
`5575caf811e8abdc8c244e697be55e1aff19d882a2770ad5ad0c53a7dbc373d8`.
RPM headers differ; no byte-identical RPM claim is made. The original validated
RPM is restored at its original path. This is one cold/warm experimental-broker
cache check, not Center/Context or the release's repeated performance protocol.

### Real Secret Service deputy — feasibility evidence

The separate-account `application-security-keyring.sh` fixture seeds and reads
one synthetic value through installed GNOME Keyring 50.0 and libsecret 0.21.7
in an explicitly unconfined positive-control unit, with private HOME, bus and
network. It then labels only that synthetic keyring directory, starts a fresh
confined service and verifies its actual bus peer UID 1002 and generated
`greyward_guard_gkeyringd_t` domain. Both `secret-tool` retrieval and direct
file access fail. The bus service remains present; loading its protected
collection is unavailable, not an empty permission set or a public protection
claim. No kernel-block notification is inferred from an application error.

The final confined fixture runs in 302 ms with a 10.7 MiB peak. Earlier runs
failed before service readiness due to private fixture labels/socket paths;
they are not deputy acceptance. Correct Fedora runtime labels and the enrolled
SELinux user on bootstrap objects fix the fixture without policy widening.
Modules/mappings roll back; DMS PID 4888 and Enforcing are unchanged. No real
credential is inspected. Legitimate reviewed Secret Service profiles and
per-application grant/collection semantics remain release gates; the current
deny result does not validate normal credential workflows.

### Read verification worker — source evidence

The read broker now moves authenticated peer capture, process revalidation and
SQLite projection to one fixed worker, with at most eight outstanding jobs.
The transport's six-second wait remains bounded when verification stalls;
timed-out work retains its slot, expired queued work does not perform reads,
and capacity exhaustion/worker failure remain explicit errors. This neither
cancels kernel-stalled work nor exposes policy mutations. Service initialization
and launch/resource preparation still need their independent bounds.

Two focused tests pass for held verification, expired queues, capacity recovery
and failed workers. The complete runtime source suite passes 67 ordinary tests;
explicit Fedora Clippy passes. The real system-bus source fixture passes
caller-owned list/detail, foreign-owner exclusion, revision rejection,
malformed/unbounded query refusal and forbidden mutation/name replacement.
The test uses synthetic in-memory records, never the production database.
Test executable SHA-256
`22fdfbb6b484765a9f15003a9d77b9d15517075defd92f4c48c6aa4909c0b0e5`;
fixture runtime 101 ms, peak 8.7 MiB. Temporary bus policy is removed and active
DMS PID 4888/Enforcing remain unchanged. Revision 11 is historical to its
archived inputs and does not cover this subsequent read-worker change.

### Wayland security-context protocol — feasibility evidence

The installed Labwc 0.9.6-1.fc44 and Wayland client/scanner 1.25.0-1.fc44
pass a real private UID-1002 test under `greyward_guard_t`. The context listener
retains ordinary compositor/seat/surface/data-device globals while twelve
privileged interfaces advertised on the ordinary connection are absent on the
restricted connection. An explicit bind using the real hidden manager global
ID is rejected with a protocol error. Creator disconnection preserves the
listener-established client; listener expiry does not revoke an existing client.
No grant-expiry/revocation promise is inferred from this protocol.

The ordinary data-device interface remains present. This establishes neither
private clipboard isolation nor denial of the unrestricted compositor socket;
the native provider must still supply only the restricted FD, and ISOLATED
workloads require the selected private nested display. The test changes no
host display or policy. Fixture runtime 142 ms, peak 18.7 MiB; probe binary
SHA-256 `67706dacf98b080e5d5e64d956a0f199d34ab98af484432aaa740d89f4916f26`.
Its scanner input is pinned with retained upstream MIT license in
`spikes/application-security/wayland/source.json`. Enrollment/module/labels
roll back; Enforcing and DMS PID 4888 remain unchanged. Production broker
connection creation and managed-host-socket denial remain open gates.

### Obsolete Flatpak home helper — source retirement

The repository reference audit finds no caller for the exported local-only
home override change/restore helper. The helper and its error type/exports
are removed. Effective reads already use the shared Flatpak provider; existing
overrides are retained. No replacement mutation is exposed until the full
preview/revision/apply/readback provider exists. Removing `home` alone cannot
revoke explicit subpath grants. This preparatory debt cleanup does not complete
Phase 5 or establish Protected Data coverage.

### Preserve existing Flatpak defaults during provisioning

Production/development default seeding no longer resets Bazaar or Haruna
overrides. Both use `environment/flatpak/seed-system-permissions.py` for only
the two existing distributor defaults. Any system global/app record is
preserved; user policy is never written. Read failure stops seeding and failed
readback cannot report success. Legacy broader permissions remain reviewable
instead of being silently removed. The installed .149 policy and active
session are not redeployed by this source change. Six unit tests pass for
fresh/idempotent seeding, byte-identical existing policy, global-policy
preservation, read failures and readback failure. Fourteen actual Flatpak
1.18.4 checks pass using a disposable installation on .149, including the
existing effective-permission fixtures. The provider fixture stages this
shared helper beneath its fixed private build directory; it never modifies
the active user's or system overrides. Fresh-image acceptance remains open.

### Native lock fixture inputs

`application-security-wtype-input.sh` acquires the exact Fedora 44
`wtype-0.4-11.fc44.x86_64` RPM, verifies SHA-256
`97646d188ca009d47297227d8832657d052c19c2670d976e1619a13ecfcac348`
and the Fedora signature fingerprint
`36f612dcf27f7d1a48a835e4dbfcf71c6d9f90a6`, then re-verifies a root-owned
copy before extracting only the binary and MIT license. No RPM installation,
scriptlets, PATH change or host keyboard device is involved. The input check
passes on .149. This is an actuator input receipt, not native-lock acceptance.

The separate-account `application-security-lock.sh`, `lock-session.sh` and
`lock.py` fixture uses a private headless compositor/bus and positively binds
the backend, display and Quickshell to UID 1002 and its confined domain before
any lock IPC. It tests password authentication using private Wayland input,
never IPC unlock. Only that private configuration disables logind integration;
the production setting remains canonical. A temporary random password uses
stdin only, with root-only recovery and restoration on exit.

The actual private PAM test passes: wrong password retains `shouldLock=true`
and `sessionLockSecure=true`; two subsequent password-authenticated cycles
reach secure lock and fully unlocked readback. The live backend, Labwc and
Quickshell are UID 1002 in `greyward_guard_t`. Coordinator runtime 10.176 s,
24.7 MiB peak; the private display is bounded separately. An earlier fixture
readiness failure assumed an explicit backend filename; actual DMS creates a
PID-named socket. The corrected fixture selects the sole private 0600 socket
and validates its live peer before sending lock IPC. No active session is
selected. Original password hash/change date, module and mapping are restored;
SELinux stays Enforcing and active DMS PID 4888 is unchanged. This validates
native PAM on a headless display. Graphical seat, logind, suspend and physical
input acceptance remain separate gates.

## 21. Uncertainties and blocking rules

Confined Fedora/Labwc/UWSM operation, deputy resistance, replacement/export
labels, scalable contexts, crash-safe expiry, compositor interfaces and reliable
attribution are explicit experiments. Failure blocks the affected promise;
mandatory whole-session failure blocks release. Unsupported resources/lifetimes
stay unavailable. Do not use permissive domains, disable enforcing, generate
broad audit2allow policy or widen services merely to pass tests.

## 22. Completion

- [ ] Unified native/Flatpak identity, permissions and events.
- [ ] Direct/same-UID/deputy bypass cannot obtain unreviewed protected access.
- [ ] Supported resource creation/replacement/aliases remain protected.
- [ ] Reviewed raw grants work and in-process risk is explicit.
- [ ] Profiles describe verified behavior, health/coverage separate.
- [ ] All eight first-run flows pass.
- [ ] Safe Open shared runner; obsolete policy/history retired.
- [ ] Existing network/USB/update/recovery/freshness/native-lock regressions pass.
- [ ] Exact packaged tuple and real-window validation pass.
- [ ] Cold/warm, retention and overload budgets pass.
- [ ] Fresh ISO/clean install preserve interactive installer/account/encryption/branding/provisioning.
- [ ] Policy/labels/mappings/packages rollback demonstrated.
- [ ] Architecture/APIs/threat/docs/map/status current.
- [ ] Remaining physical/human tests individually listed, never claimed run.

Release promise: registered sensitive resources are protected from ordinary
workloads across the enrolled session, except explicitly reviewed grants.

## Primary mechanism references

- [SELinux confined users](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html-single/using_selinux/index).
- [Landlock userspace contract](https://docs.kernel.org/userspace-api/landlock.html) and [audit](https://docs.kernel.org/admin-guide/LSM/landlock.html).
- [Seccomp](https://docs.kernel.org/userspace-api/seccomp_filter.html).
- [Labwc 0.9.6 global filter](https://github.com/labwc/labwc/blob/0.9.6/src/server.c).
- [Flatpak commands](https://docs.flatpak.org/en/latest/flatpak-command-reference.html).
- [FileChooser](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.FileChooser.html) and [Documents](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Documents.html).

### Revision-bound policy preparation — source evidence

`policy.rs` prepares one bounded immutable index from root-reconciled
installation/resource/grant records. It returns desired deny rules or reviewed
candidates; it establishes no authorization, kernel enforcement or protection
badge. At most 2,000 resources/grants, 32 grants per installation and 512 run
memberships are admitted. Unknown/foreign resources fail, changed generations
retain inactive grants for review, and different sources/owners cannot inherit
a grant. This-run lookup requires the exact controller-owned boot/PID/start/
context and code-generation record. Rebuilding without a run or grant removes
its candidate; this does not demonstrate workload termination or revocation of
already-read data. Persistent grant transactions, kernel policy compilation and
verified readback remain open.

Nine policy tests pass; the complete runtime suite now has 76 ordinary passing
tests, with 19 explicit root/Fedora fixtures and two separate profiling tests.
Formatter and runtime all-target Clippy pass with Fedora Rust/Cargo 1.98.0.
`application-security-policy-profile.sh` resolves Cargo's exact current test
artifact, then measures it in a bounded private-network 128 MiB unit. Binary
SHA-256 `90058c08e142cc94dbb3b09e0da67c22485996f03e6049b09ec4c75406114952`:
ten cold index preparations of 2,000 records measured median 12.094 ms,
p95/max 13.997 ms, min 9.542 ms. Thirty warm passes produce 60,000 lookups:
median 1.57 microseconds, p95 3.02 microseconds, min 0.60 microseconds,
max 297.70 microseconds. Runtime 402 ms, peak 8.1 MiB, no swap. These are debug
source-index measurements, excluding input cloning; they are neither cold
process starts nor installed launch/enforcement acceptance. No policy package,
production database, account enrollment or active desktop is changed.
### Runtime native restriction core — source evidence

The shared runtime now owns `native_restrictions.rs`; its fixed integration
example under `tests/support/` replaces the retired independent native-worker
workspace. It consumes held O_PATH/CLOEXEC descriptors, refuses shared scratch
or writable code-tree metadata, requires a single unprivileged prepared worker
with empty effective/permitted/inheritable/ambient/bounding capabilities and
an exact GREYWARD domain, and requires full ABI 9 Landlock enforcement. It
prepares seccomp before irreversible restriction, synchronizes filters across
threads, rejects namespace clone flags and returns ENOSYS for pointer-based
clone3 while allowing ordinary thread/fork fallback. This disconnected subset
blocks all new sockets and supplies no network-enabled/graphical profile.
Existing FD closure, namespace/display setup, validated executable selection,
mandatory labels and an independent worker lifetime remain launch prerequisites.
No unrestricted retry is supported after a partial restriction failure.

Four ordinary structural/refusal tests and the private namespace driver pass.
The current combined source suite has 107 ordinary tests: 80 runtime plus 27
domain tests; nineteen root/Fedora fixtures and two profiling fixtures are
separate. Earlier aggregate counts omitted eleven domain integration tests;
this corrects the total without changing phase acceptance. Runtime all-target
Clippy and formatter pass under Fedora Rust/Cargo 1.98.0.
The exact fixed driver SHA-256 is
`76fe00c6030db308d9269fea28031af52824944dea9f55568406b991bcfa9c6d`.
Missing selected input refuses in 36 ms; the positive kernel run passes in
32 ms, peak 5.6 MiB, no swap. It verifies private user/mount/PID/network
namespaces, selected/scratch access, outside/protected denial, network denial,
thread creation, unshare refusal and inherited child-exec denial. Enrollment,
labels and temporary policy roll back; Enforcing and DMS PID 4888 stay unchanged.
This is neither a general launch provider nor a production profile/grant gate.

Product Cargo.lock SHA-256 is
`d8f7d389bd3e07c77c24add06c3d52870ae7ed7e045f493255008320c6f7734a`.
Offline resolution added only Landlock 0.4.7, libseccomp 0.4.0 and their three
new transitive entries; existing pinned package versions were retained.
Builder libseccomp and headers are `2.6.1-2.fc44.x86_64`. Experimental spec
revision 12 includes their build requirement. Its offline cold/warm build and
extracted-service MAC checks pass for the archived Rust inputs below; revision
11 receipts cover only their archived earlier sources.

### Revision 12 package/cache receipt — scoped development evidence

Experimental `greyward-application-security-experimental-0.1.0-12.fc44.x86_64`
builds from source archive SHA-256
`729fd505b652491a64dbe03952e3505889ca3e361789adf882bc0cd20331c25e`,
spec SHA-256
`120f17dc492b9bb7919a95fa4ac109fae01d69417afa487e2b2baa4772a17e8e`.
The cold build/check takes 4 min 56.325 s, peak 1.9 GiB, no swap; RPM SHA-256
`d803be437897f5ed811bbf68e988dcd1e64b5dde8cd1aeacc3331bfd98f7f463`.
The exact archived-input warm build takes 12.545 s, peak 386.7 MiB, no swap.
RPM headers differ, but the extracted broker ELF is identical:
`1c4fea91e6a75c7787c3d504dd67208c34e59ac38705e246d6417eadf7c4569e`.
Build inputs include Fedora Rust/Cargo 1.98.0, sqlite 3.51.2-2, D-Bus 1.16.2-1,
SELinux policy 44.11-1, systemd 259.8-1 and libseccomp 2.6.1-2.

The matching archived MAC-test ELF is
`1064f02ce450462176f630f3c8a86c3abe2f92303610e575d95b970f9b628075`.
The extracted service passes kernel-bound, owner-scoped typed reads, private
0700/0600 database storage, process metadata access and credential-content/
inherited-descriptor refusal. Coverage remains UNKNOWN without effective
profiles. Private units peak at 8.1 MiB, no swap. Temporary mappings, labels,
policy and bus configuration roll back, SELinux stays Enforcing and active DMS
PID 4888 is unchanged. This RPM is not installed or promoted; it provides no
launch or policy-mutation API. Center/Context package-cache, production tuple,
image and clean-install gates remain open. Subsequent source changes are not
covered by this immutable archive receipt.

### Historical Safe Open compatibility correction — superseded source evidence

This receipt predates the shared runner above. The standalone builder and its
independent fixture are retired; the following describes historical behavior.

The existing Python runner now carries a securely selected descriptor through
classification and bubblewrap preparation. It uses descriptor binding with no
pathname fallback and closes the parent descriptor after spawning. A redundant
`/usr/share/applications` submount was removed because the existing read-only
`/usr` mount already supplies it; no filesystem or SELinux allowance was widened.
Preparation is recorded as STARTED; a later failure replaces that event instead
of preserving an initial success claim. Thirteen Safe Open tests and two typed
Context refusal/lifecycle tests pass; the full Fedora Context source suite has
284 passing tests.

The fixed separate-account `application-security-safe-open.sh` fixture verifies
normal selected-file viewing, type detection through the held descriptor,
replacement refusal, read-only exposure and parent FD closure against actual
bubblewrap 0.12. It takes 134 ms, peak 11.4 MiB, no swap. The removed/replaced
source is refused safely by this pinned bubblewrap implementation; it is not
claimed to remain viewable after unlink. Synthetic labels/mapping roll back,
SELinux stays Enforcing and active DMS PID 4888 stays unchanged. This preserves
the legacy workflow and corrects its descriptor race; Safe Open still does not
use the shared Guard isolation runner, and Phase 4 remains IN PROGRESS.

### Durable owner-reviewed policy intentions — source evidence

`policy_intent.rs` retains immutable descriptor-backed reviews and binds them
to the live execution, root policy revision and bounded deadline. Commit consumes
fresh owner authentication, then revalidates the peer, generation, descriptor and
revision. Schema-two tables in the existing private policy database retain
resource metadata and persistent proposals; no second event history is created.
Migration validates the old inventory and preserves both revisions atomically.
Failed migration/storage and stale or foreign reviews leave committed data
unchanged. Old generation reviews remain visible without transferring to changed
code. Timed grants are refused until independent workload expiry is established.
Resource intention coverage must be UNKNOWN; loading a false Protected record
fails. Device/inode metadata is a reconciliation hint, not post-restart authority.

Fourteen focused storage/review tests pass. The combined source count is now
121 ordinary tests (94 runtime, 27 domain); nineteen root/Fedora fixtures and
two profiling tests remain separate. The fixed development
`application-security-policy-intent.sh` resolves exact Cargo artifacts and copies
only reviewed tests into root-owned libexec paths. The root filesystem roundtrip
and concurrent revision checks pass (114 ms, 9.8 MiB); unauthenticated root-broker
intent commit is refused (90 ms, 11.2 MiB). A private terminal agent performs two
actual owner authentications for separate in-memory register/remove intentions
(392 ms, 34.9 MiB). All units report zero swap.

Matching artifact SHA-256 values: storage test
`52f8307e3a2507956daed11e86329829f9daa890235e079f15c1360c4f90b4f4`,
negative peer test
`6c9a79a183036a25506bcf58cac01eb6d50518b3c5f6e4fbc7c8a266aa8707d7`,
fresh-authentication test
`f14af8595a90433bae40002d2bd13ad7b5da6c8c59aa1f649550dbe0f8f1f54c`.
The original test-account password is restored, temporary action removed,
SELinux stays Enforcing, DMS PID 4888 stays unchanged and the production database
remains absent. No public mutations or effective grants are exposed. Kernel
compilation, labels, workload management and authoritative readback remain open;
these source changes are outside the revision-12 archive and complete no phase.

The expanded source test run exposed a read-worker unwind-order race: its
response disconnected before the admission slot was released. The slot now
drops before response disconnection. Worker failure still returns Transport and
never a successful projection; no panic is swallowed or retried. Runtime
all-target Clippy passes with the explicit Fedora toolchain.

### Generated resource-denial policy — 7 October 2026

`resource_policy.rs` prepares canonical, bounded CIL from root policy intentions,
not user policy text or display labels. Stale/foreign records, false Protected
states and duplicates refuse; three tests include the two-thousand-resource
bound. The current full Rust workspace, formatter and all-target Clippy pass
with Fedora Rust/Cargo 1.98.0: 124 ordinary domain/runtime tests (97 runtime,
27 domain), with the nineteen explicit root/Fedora fixtures and two profiling
tests tracked separately. The existing vendored Tao warnings remain unchanged.

The fixed `application-security-resource-policy.sh` development fixture compiles
one synthetic resource label on .149 with SELinux Enforcing. Its eighteen checks
cover ordinary-file positive control, sensitive read/write/append denials,
symlink/hardlink/bind aliases, creation/unlink/link/replacement refusal and label
tampering. Root-created files and an atomic replacement prepared within the
protected directory inherit the label. The access unit takes 53 ms, peak 7.3 MiB.
A second fixed unit first reads and mmaps an ordinary synthetic inode, retains
its descriptor while root relabels that same inode, then confirms denial of
read, PROT_READ mmap and PROT_NONE mmap. Its coordinator takes 106 ms, peak
8.1 MiB; both units report zero swap and no contents are logged.

Policy assertions use a private root-owned semanage configuration with
`expand-check=1`; Fedora's host setting remains `expand-check=0`. An injected
conflicting read allow is rejected by the actual compiler. The first candidate
also asserted denial of `map`, which conflicts with Fedora's broad map-only
allow. The corrected program retains read/open denial: Linux's mmap path checks
read as well as map, including PROT_NONE. The held-descriptor positive/negative
controls establish this on the actual kernel without changing a host boolean.
See the [SELinux mmap implementation](https://raw.githubusercontent.com/torvalds/linux/master/security/selinux/hooks.c).

The test harness initially passed a user-owned log-file descriptor to systemd;
PID 1's write denial prevented the test from starting. Logging now uses a pipe,
and a fixed root-only coordinator explicitly retains the existing unconfined
administrative context. The tested ordinary workload stays in `greyward_guard_t`.
No service permission or ordinary-subject allowance was widened. These are
development harness changes, not production broker configuration.

Matching SHA-256 receipts: emitter
`ecd2eeb1a90bea66351cb617705eb2a6bfc916bdc1763d80c5dd110612d43f1a`;
CIL `808f4dcc64c9e85c569db6ef08f30b27620fc0be73ca990cd03c3e709127d7ca`;
Python helper `57db87a908e94ca4f5345265982e15053af275606aba2eae92e1eb0ab0c936f5`;
shell tool `2c80909da70f4275f851b624d8efd261f351fd6d9a91d56d29f2b14facf4f6e4`.
Both resource modules, labels and the probe login mapping roll back. No UID 1002
process remains, DMS PID 4888 is unchanged, SELinux remains Enforcing and the
production policy database remains absent. The current repository static gate
passes. These sources are outside the archived revision-12 RPM receipt.

This proves a synthetic label/denial boundary, not recursive registration,
approved-tool replacement from outside the directory, revocation of existing
mappings/data, portal enforcement or production session coverage. The compiler
is development-only; all registered-resource projections remain UNKNOWN and
Phase 2 remains IN PROGRESS.

### Live SELinux policy readback — 7 October 2026

`selinux_readback.rs` reads the actual root-owned SELinux filesystem, checks
global enforcing state, resolves kernel class/permission numbers and queries
the fixed development subject's decisions for the generated types. Partial
decisions, any permissive/unknown flag, changed program/revision, changed kernel
sequence and expired leases refuse. Receipts are private process memory and
cannot be deserialized from user history. Between-call deadlines require a
separate hard-bounded worker; they do not claim syscall cancellation.
The [kernel transaction implementation](https://github.com/torvalds/linux/blob/master/security/selinux/selinuxfs.c)
defines the query and its six-field decision response.

Three refusal/lease tests pass. Full workspace tests, formatter and all-target
Clippy pass: 127 ordinary domain/runtime tests (100 runtime, 27 domain), with
the same nineteen explicit root fixtures and two profiling tests separate.
The fixed root fixture refuses absent policy with the kernel's EINVAL response
(19 ms, 4.5 MiB), then verifies loaded file/directory/symlink denial decisions
(17 ms, 1.5 MiB). Its kernel sequence was 936. The access/held-descriptor suites
also pass with this exact emitter. A live receipt is held across actual module
removal; its revalidation then refuses. That bounded removal coordinator takes
5.546 s, peak 248.4 MiB. All units report zero swap.

Matching SHA-256 values: emitter
`ddc04235bf7720522011812a21069ba6cc3222e842b2d58d5c5ecf96fa4fd13e`;
unchanged CIL `808f4dcc64c9e85c569db6ef08f30b27620fc0be73ca990cd03c3e709127d7ca`;
readback source `cde42801ae7244c370506ddbebfdc3f7ed957cb365ca60ad7444ba12af2e2317`;
Python helper `51be3ed21c081a4bee8007be3c98a3b52a722c04b8b7272a1f95a41f037c1d2e`;
shell tool `dca8a217eaadff45536e488a3ec7e9f109735840518696e384f5a15a07d88de9`.
These supersede only the current helper/emitter receipts; earlier results remain
dated evidence. The synthetic tree is restored before module removal, mapping
rolls back and the recovery desktop/SSH remain operational. No production
database, label registration service or broker is activated.

This receipt proves named type-policy decisions for the development subject at
one kernel sequence. It does not prove actual object labeling, whole-session
membership, portal controls, grant activation, past-data revocation or protection
of a registered category. Production projections remain UNKNOWN; all earlier
registration/session/provider gates remain open.

### Retained registration descriptor — 7 October 2026

Successful fresh-authentication commits now return an opaque, single-transfer
`ResourceRegistrationLease`. It retains the original directory descriptor,
authenticated execution, committed intention, revision and deadline instead of
closing the selection at the storage boundary. It cannot be cloned or restored
from serialized metadata. Revalidation checks the live actor, unchanged held
object and exact current root intention/revision. Root preparation derives CIL
only from that owner's current intentions. Metadata inspection uses the process's
still-held FD proxy for a bounded SELinux xattr; it resolves no user pathname,
reads no contents, changes no label and supplies no protection decision.

The matching private terminal-agent fixture again performs two actual owner
authentications. After registering an in-memory intention it transfers the
descriptor once, reads back the existing `user_home_dir_t`, prepares the current
denial program and preserves UNKNOWN coverage. After removal, the retained lease
is rejected. Root filesystem/reopening/concurrent-revision checks pass (89 ms,
9.8 MiB), unauthenticated commit refusal passes (108 ms, 11.2 MiB), and the fresh
authentication/descriptor continuation passes (420 ms, 35.1 MiB), all without swap.
Matching test SHA-256 values: storage
`5e33010a7d3666cd840024a91a0e6ab1a7b1a1837387e9543a85b9894d1cd457`;
negative peer `d7b23a9d86806fbc68655f7f795b763835939de38274a70ee6e0fb651d9af771`;
fresh authentication `f9ac5c23a28161daef1bcbaaf2e69846465c1fee228a3da6b9ad53d67e776bc7`.
The original probe password is restored and the temporary action removed.
All-target workspace Clippy passes. No existing labels, grants, production
database, broker method, authentication policy or active desktop are changed.

This closes descriptor continuity during preparation only. Journaled label
changes, existing-object enumeration, replacement-safe coverage, crash recovery
and the registration API remain unimplemented. A storage acknowledgment and its
lease cannot produce `OperationResult::Completed` or a Protected badge.
