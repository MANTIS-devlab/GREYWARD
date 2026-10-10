# Production Application Security enrollment

Status: normal `.149` development enrollment active, 8 October 2026. Automatic
production installation/upgrade/rescue acceptance remains unvalidated.
Production activation remains gated by actual enforcement/admission/rollback evidence. The [delivery plan](APPLICATION_SECURITY_PLAN.md)
records current source and scoped validation. This document owns the proposed
enrollment lifecycle, not a second application-security product contract.

## Current normal-session implementation

The protected Labwc worker is launched with an explicit environment allowlist.
It therefore sets `XKB_DEFAULT_MODEL=pc105` and `XKB_DEFAULT_LAYOUT=fr` directly,
matching the installed GREYWARD Labwc defaults. Without these values wlroots
falls back to US QWERTY even when `localectl` reports French AZERTY. The setting
is part of the experimental Application Security RPM; it does not change SELinux
policy or broaden the worker's access.

### Approved practical administration work — 9 October 2026

IMPLEMENTED in Center 89 / Context 81 / experimental runtime 32 and session
package 8, with separately compiled SELinux/compositor inputs. The approved
normal-seat activation and core Administration/lock/grant checks pass on `.149`;
whole-desktop rollback remains pending at the user's request to keep the session
running; production recovery acceptance remains IN PROGRESS.
See the [normal-seat compatibility receipt](../history/security-center/2026-10-09-desktop-compatibility.md).
Installed packages alone do not enable Administration. Ordinary
`sudo_exec_t` execution remains denied. A non-setuid graphical sudo handoff requests a root-prepared private
Administration terminal, distinct from native DMS authentication and ordinary
applications. Keep the enrolled login mapping and ordinary role unchanged;
only the prepared terminal may use a separate administrator SELinux identity
and Fedora's confined `sysadm_r/sysadm_t` sudo transition. Fresh authentication
is required on entry; sudo timestamps last two minutes per protected terminal.
The Administration generation includes a hash-matched, unchanged Fedora
password helper. A read-only private bind mount gives it the dedicated
authentication entry label for initial and nested sudo, preserving ordinary
helper isolation without modifying Fedora PAM. Public Flatpak service metadata
permits reads and directory watches; explicit CIL denies remove inherited
ordinary-helper writes. Mount preparation permits ordinary certificate paths
and DMA metadata, while protected-resource reads and DMA open/ioctl stay denied.
Session package 8 selects the supported GTK/wlroots portal backends.
Ordinary screen capture/sharing remains unavailable under the protected
compositor; do not solve that by exposing protected frames or broadening the
authentication domain.
External requests always require review and cannot reuse another terminal's
authority. No privileged output, input descriptor or timestamp is returned to
the requesting process. Security Center has open/status actions, not a generic
root execution API. Desktop entry is first; protected SSH administration is
deferred and development SSH recovery is retained.

The protected surface must deny ordinary overlay, capture, input injection,
process/PTY access and clipboard sharing. Native DMS locking remains canonical;
lock/logout invalidate cached authority without silently killing an existing
administrative command. Root shells remain privileged until explicitly exited,
even after a timestamp expires. Administrator commands can modify protections;
this is an explicit trust boundary, not a Protected Data application grant.
Missing readiness refuses administration and never weakens ordinary coverage.

The native Wayland terminal uses exclusive compositor input, a private devpts
namespace and libvterm. Its root-owned closure binds the desktop manifest, native
terminal, worker, fonts, real sudo and clean Bash generations. Only PID 1 admits
`greyward_admin_u:greyward_admin_r:greyward_admin_t:s0`; real sudo transitions to
Fedora `sysadm_r:sysadm_t`. Ordinary roles remain unchanged. Each new surface
requires argument review and `sudo -k` followed by fresh `sudo -v`. A clean shell
uses no user startup files or ordinary input/output channel. External proposals
are argv arrays, never reconstructed shell strings. Long requests that cannot be
fully displayed are refused; use `sudo -i` and type the complete operation there.

Ctrl+Alt+F12 asks the compositor to identify protected input. The compositor
draws the indicator above application content and reserves that physical key
combination. The surface has an End session control and Ctrl+Shift+Q confirmation.
No clipboard protocol is bound. Lock and protected Polkit requests pause the
surface, remove cached tickets and return input to native DMS authentication;
commands already running retain their explicitly authorized lifetime. Unapproved
proposals expire after two minutes. Invalidation during the initial PAM exchange
prevents a late replacement ticket from executing that proposal. Logout ends the
root-controlled workload. Policy reload and tool/closure changes invalidate
tickets and refuse new admission without killing an authorized package transaction.
The admitted terminal's original inode remains the active-session identity across
package replacement. Eligibility withdrawal or loss of mandatory isolation ends
admission. Missing readiness refuses entry.

VALIDATED on a separate test account: native password/root-shell transition and
synthetic protected-file read, wrong-password refusal, actual tty-cache reuse,
`sudo -k`, two-minute expiry while a command survives, graphical review/root-shell
rendering and exclusive-surface pause/resume. Current-kernel decisions deny 372
ordinary-closure administration process/PTY/runtime accesses; the pre-PAM
terminal cannot read the synthetic registered resource. These are scoped tests,
not normal-seat acceptance. See the [dated receipt](../history/security-center/2026-10-09-practical-administration.md).

Targeted usability changes implement trusted USBGuard read projection, narrowly
typed Flatpak service metadata and unambiguous broker activation. Actual ordinary
reads of Bazaar's public service metadata succeed while direct sudo and protected
file reads remain denied. Empty USB lists are provider results, not fabricated
devices. The workflow service alone owns ApplicationSecurity1. USB mutations
retain their existing typed authorization; this pass does not claim new mutation
support. Authentication backend's unnecessary generic probes remain denied;
no demonstrated safe auth-only upstream startup option was found; removing those
denied backend probes is DEFERRED HARDENING. Runtime 30's root oneshot/path unit
reconciles only public metadata after Flatpak's `.changed` notification and export
directory changes. Its bounded root-private journal preserves original labels
by device/inode across repeat runs and replacements. Actual installed path-event
repair passes, along with adjacent private-alias rejection; no whole-installation
relabeling or periodic process polling. Unsupported exports remain unavailable.

Never permit broad var_lib reads, ordinary USB management, raw input or
general authentication-domain command execution. Each permission adjustment
requires its legitimate workflow and an adjacent denial test. Production rescue
boot and release lifecycle remain unvalidated. Extra compatibility, performance
and physical matrices are DEFERRED HARDENING.

Registered resource reopening now binds kernel filesystem type/ID, inode,
owner and protected label rather than persisting Btrfs's mount device number.
Legacy receipts require verified root migration; they are not silently repaired.
Runtime 28 and the canonical session module fix the observed post-reboot resource
and graphical Flatpak failures. [Scoped evidence and rollback](../history/security-center/2026-10-08-session-resource-flatpak-recovery.md).

The normal development account is deliberately mapped and admitted through
actual greetd PAM, a root-owned matched Labwc seat, private native DMS
authentication and an ordinary confined user manager/SSH shell. Fixed Fedora
Polkit and password helpers run in separate protected domains. Ordinary
workloads cannot inherit them. PAM/authselect were not rewritten.
Root readback checks real process/role membership, scope/lifetime, immutable
closure hashes, fresh exclusive-input readiness, actual kernel decisions and
registered object labels. Missing or changed evidence withdraws coverage.

Real descriptor registration and tested persistent READ-grant creation pass
with fresh authentication. Two unchanged launches succeed; ordinary/direct
reads are denied. The installed Center displays actual protected resources.
GUI revocation and installed Center 66 / Context 68 / runtime 25 now pass in the
[normal-session receipt](../history/security-center/2026-10-08-application-security-normal-session.md).
Root SSH recovery is retained without a new account/password. Protecting `.ssh`
requires a root-owned public authorized-key lookup for the development account;
private keys remain denied to ordinary subjects.

The protected display uses its root-owned XDG data directory. Its generated
closure includes the packaged GREYWARD `themerc` and SVG buttons at
`labwc/themes/Greyward/labwc/`; all assets enter the closure hash manifest.
Loading the ordinary account's writable theme directory is not the repair
path. A verified admitted compositor can reload those trusted decorations
through SIGHUP without replacing the seat or authentication owner.

Only nonexporting key inspection is reviewed. Unsupported temporary grants,
general SSH/signing and IDE profiles stay UNAVAILABLE. Automatic installer/
account-workflow enrollment, upgrade coordination and authenticated offline
rescue boot remain separate unvalidated implementation/release gates. The
lifecycle design below is not an automatic install recipe. Exhaustive optional
matrices, physical and performance acceptance are DEFERRED HARDENING.

## Historical initial implementation and blocking evidence — 7 October

Statements below about absent normal mapping/positive coverage and private-only
authentication are superseded by the current section and receipt above.

The accepted recovery/account/admin decisions are recorded below. Source now
contains the transactional enrollment journal in the existing policy database,
normal-local-account validation, root-private account-origin issuance/readback, per-owner provider/cache/module/display/audit
bindings and a serialized multi-owner broker worker. Production grants use
root-prepared `system_r` subjects; the synthetic owner role remains development
only. These changes compile and pass focused source tests; they have not passed
production kernel, account-admission, multi-user or package acceptance.

The default public service remains read-only. Runtime 20 reads fresh negative
enrollment prerequisites: absent enrollment or an authenticated unconfined peer
is UNAVAILABLE, rather than a permanent default UNKNOWN. Positive whole-session
coverage remains unimplemented; a journal/type-policy check does not supply it.
See the [installed integration evidence](../history/security-center/2026-10-07-application-security-live-integration.md).
The explicit
`--workflows` entry and installed workflow unit now expose the existing
`serve_enrolled` dispatcher on `.149`. Unenrolled normal local accounts receive
managed-isolation capability only; policy changes require the confined enrolled
actor and protected-authentication checks. No preset or production activation
is supplied. See the [live development receipt](../history/security-center/2026-10-07-application-security-live-development.md).
Existing production schema upgrades refuse on ordinary broker open; the future
offline coordinator must snapshot and explicitly migrate before activation.
No installer account is enrolled, no existing mapping is changed and no
production policy is installed by this work.

The maintenance console/target is implemented in source, excluded from the
experimental RPM. It requires explicit maintenance boot, a quiescent system,
actual foreground tty1 and fresh passphrase authentication against the mounted
root's LUKS ancestry. It refuses normal boots, remote/PTY access, ambiguous or
partly unencrypted root dependencies and cached/token-only authentication.
Nine focused tests pass, including real cryptsetup on a private synthetic file
container. Actual maintenance boot, console and installed-system repair/rollback
are **NOT VALIDATED**. No separate account/password was added.

Blocking `.149` evidence: the inherited Fedora ordinary-user template permits
a same-UID sibling to read synthetic process memory and reopen its pipe through
`/proc/PID/fd`. `deny_ptrace` addresses memory attachment, but the SELinux
`PTRACE_MODE_READ` hook uses `file:read`; it does not close the pipe path alone.
A temporary fixture denying both rights stopped the reads but also denied
`/proc/self/attr/current`, which the native worker requires. Blanket same-domain
denial is therefore not a compatible production fix. No real authentication
data or active desktop process was inspected. The temporary modules were removed.

That same-domain fixture is historical failure evidence. The separate
`greyward_as_auth_t` source now preserves self-inspection and denies ordinary
cross-domain process, FD, pipe, signal and socket access. Actual enforcing
kernel probes pass on UID 1002. A matched, generated auth-only DMS shell passes
wrong-password retention, two native PAM unlock cycles and two fresh GUI Polkit
owner challenges on a private headless display. Unlock/reset IPC cannot release
the lock. Fedora PAM is unchanged; the normal DMS desktop is not assigned this
authentication role. See the [authentication receipt](../history/security-center/2026-10-07-application-security-authentication.md).

Production binding checks actual cross-domain kernel decisions and self-read
compatibility. This remains a prerequisite, **not a live coverage verifier**.
Root-owned executable/QML generation, real owner-session/agent binding and the
trusted production compositor/input path must pass before admission. The
private display proof does not validate physical seat0 or production startup.

The persistent-launch choice is now fixed: fresh authentication on creation,
change or material expansion, with reuse only under tested tool restrictions.
Source records the selected profile and checks installation/code generation,
resource scope and policy revision again before root-prepared launch. Generic
legacy grants remain readable/revocable but cannot be activated or launched,
including through the development provider. No launch-time authentication is
added to an unchanged supported persistent grant.

The first profile is deliberately narrow: the pinned Fedora `ssh-keygen`
generation, `-l -f` and three fixed key paths in the validated owner's `.ssh`.
All streams are null; callers receive bounded exit status, never key material,
comments or diagnostics. It is key inspection, **not SSH login/signing, an IDE
exception or general credential export**. Kernel tests verify two reuses,
ordinary/direct-copy denial and denial after withdrawal of the access rule.
Source tests reject changed code/path, expanded arguments and foreign paths.
This is scoped profile evidence, not a complete production broker acceptance.

Unknown/unsupported tools stay UNAVAILABLE. The requested freshly authenticated
restrictive temporary fallback is not yet implemented: single-use authorization,
execution binding and kernel lifetime/revocation still need integration and
proof. It must not become a reusable generic tool/export endpoint. This is
remaining implementation, not DEFERRED HARDENING.

The root coordinator, installer/account-workflow origin handoff, persistent label
reconciliation, package lifecycle, first-session admission and real coverage
provider remain unimplemented. E0–E5 remain unpassed. These are blocking product
work, not DEFERRED HARDENING. Exhaustive optional matrices remain deferred.
Scoped commands, invocations and results are retained in the
[initial enrollment evidence](../history/security-center/2026-10-07-application-security-enrollment-initial.md).

### Required boundary correction before activation

Use separate root-prepared authentication subjects rather than putting
password handling in the ordinary application domain. Preserve each subject's
own SELinux self-inspection and deny ordinary cross-subject process, FD,
memory, signal and authentication-transport access. Validate the actual DMS
native-lock and Polkit path with synthetic sibling probes and real private-seat
authentication; do not test credentials on the active development desktop.

Trusted subjects may load only the matched root-owned executable/QML/plugin
generation and a sanitized environment. Ordinary applications must not gain
those subjects by invoking the same binary with their own QML, plugin,
environment or helper arguments. Audit DMS IPC/file/launch handlers and
compositor/input interfaces for credential-deputy or injection paths before
placing a general desktop service in a trusted authentication domain. Simply
assigning the entire shell a privileged label is not an accepted fix.

For persistent grants use the accepted tested-tool contract above. Different
callers cannot expand code, arguments, resource scope, revision or output
channels. Persistent raw-access profiles for tools with extensions must still
disclose in-process exposure and receive their own tests; they are not implied
by the nonexporting key-inspection profile.

After these boundaries pass, complete root-only account-origin receipts and
offline coordinator, durable descriptor/object/path label recovery, matched
package/schema rollback, first-session admission and independently fresh live
coverage. Only then change installer/provisioning inputs or enable automatic
normal-local-account enrollment. Protected authentication/input, tested grants
and these lifecycle gates are mandatory; optional hardening remains deferred.

## Essential continuation, without expanding hardening

The account-origin API issues complete, root-private, generation-bound records
for one deliberately selected local account, without replacing an existing UID
record. Production provider binding refuses absent, altered or reused origins.
It does not infer installer origin from a UID threshold or enroll an account.
The actual installer/supported-account issuance handoff still needs wiring.

The protected authentication proof resolves the process/FD separation issue.
It does not resolve the production input path: ordinary applications must not
inject input into, capture, or impersonate the protected authentication surface.
Root-prepared admission must bind the real owner session, immutable auth UI and
trusted compositor connection together. The ordinary DMS shell/plugins cannot
be assigned that authority simply to make startup succeed. This is a remaining
architectural integration gate, not extra hardening.

Actual normal-desktop registry inspection on 7 October confirms an unconfined
Labwc peer and virtual keyboard/pointer, capture, session-lock and layer-shell
globals on the normal socket. The
[live integration receipt](../history/security-center/2026-10-07-application-security-live-integration.md)
records the non-mutating query. A normal-account mapping alone cannot supply a
trusted input boundary. Admission must first establish root-prepared trusted
desktop/authentication subjects and their full connection; ordinary applications
must receive the broker-created security-context connection. The existing shell's
required layer-shell interfaces need their own audited, generation-bound desktop
authority, without granting authentication authority to mutable user QML/plugins.
The protected agent must be bound to the actual owner logind session before it
accepts challenges. These are essential implementation gates before admission,
not a reason to substitute launcher-only protection or permanent UNKNOWN.

Finish the fixed coordinator and mapping/label rollback, protected agent/input
admission, independently fresh coverage, then matched package/session acceptance.
No normal-account mapping, default mapping, active-session conversion or image
change is enabled by the current source. Image/hardware matrices and exhaustive
compatibility remain DEFERRED HARDENING for this functional continuation.

## Recommendation

Package the validated SELinux architecture and the existing broker together,
then enroll explicitly identified local accounts before their first session.
Use Fedora's existing PAM SELinux selection for graphical, TTY, SSH and user
manager sessions. Preserve greetd → DMS Greeter → GREYWARD launcher → UWSM →
Labwc, native DMS authentication/locking and existing security-service owners.

Do not change the default SELinux login mapping, rewrite authselect/PAM, replace
`user@.service`, or create a second policy daemon. Starting the broker cannot
confine a running unconfined account. Existing accounts require a controlled
offline maintenance boundary; initial implementation must not attempt live
conversion or terminate an active desktop automatically.

Fresh installs can enroll automatically through the existing first-boot
handoff, after interactive Anaconda account creation and encryption. Automatic
enrollment is conditional on a proven recovery route, compatible packages,
exclusive account preparation and successful policy readback. Failure keeps
the account pending and protection unavailable; it does not launch unconfined.

## Evidence and remaining architectural gaps

Read-only inspection of `.149` on 7 October found SELinux Enforcing,
selinux-policy/targeted 44.11-1.fc44, policycoreutils 3.11-2.fc44,
systemd 259.8-1.fc44, greetd 0.10.3-6.fc44, UWSM 0.24.3-1.fc44,
Labwc 0.9.6-1.fc44 and DMS Greeter 1.6.2-1.fc44. These are observations,
not the accepted production dependency tuple.

The installed `greetd`, `login` and `sshd` PAM stacks contain required
`pam_selinux` session handling. `user@.service` uses `PAMName=systemd-user`;
the effective vendor `/usr/lib/pam.d/systemd-user` also opens SELinux sessions.
An absent `/etc/pam.d/systemd-user` does not mean that PAM integration is absent.
Current explicit mappings are root and `__default__`, both unconfined; the
test-account mapping and development opt-in were removed after validation.
The development greeter invokes Labwc directly and is not the canonical
production launcher configuration.

The successful fixture used a private `login -f` PAM session and confined user
manager. It skipped login authentication; it did not validate production
greetd enrollment. Headless DMS/Labwc, minimum Flatpak, actual kernel grants,
revocation and rollback passed within that fixture. The production session
chain, multi-user subject isolation and package lifecycle still require proof.

The recommendation uses the documented [PAM SELinux session mechanism](https://raw.githubusercontent.com/linux-pam/linux-pam/master/modules/pam_selinux/pam_selinux.8.xml)
and explicit [SELinux login mappings](https://raw.githubusercontent.com/SELinuxProject/selinux/master/python/semanage/semanage-login.8).
The [systemd user-manager model](https://raw.githubusercontent.com/systemd/systemd/v259/man/user%40.service.xml)
also includes processes started outside the user manager. Consequently a
confined manager or cgroup alone cannot establish whole-account coverage.
The lifecycle below is a GREYWARD design inference, requiring pinned Fedora
tests rather than assuming these mechanisms cover every execution path.

## Package and authority boundary

Keep one root-owned application-security database and revision model. Extend
the existing registry, workflows, kernel provider and worker into a production
provider; retain the UID-1002 fixture as development-only. No configuration
switch may turn that fixture into production enforcement.

The production package set must contain a matched runtime, SELinux policy,
Context adapter and Center facade/frontend, with compatibility receipts for
Fedora policy, kernel primitives, systemd, Labwc, UWSM and DMS. Package installation
installs inert policy/program inputs; enrollment activates account mappings and
resources through a journaled, typed administrative transaction. RPM scriptlets
must not map all users, restart their managers or weaken active protection.

The production ordinary login user permits only the ordinary confined role.
Do not copy the prototype's synthetic owner role, unconfined-role allowances
or test access into production mappings. Grant-bearing subjects remain
reachable only through the validated root-prepared immutable entry, with
generation/revision checks. Direct execution, requested SSH roles, `runcon`,
interpreter children and ordinary service transitions cannot acquire them.

Production policy must cover all ordinary domains/transitions allowed to the
enrolled account, not only the compiler's current `greyward_guard_t` denial.
Keep neverallow assertions enabled and test their rejection. No broad
`audit2allow`, permissive domain, authentication synchronization or fallback
unconfined execution is an acceptable compatibility fix.

The present read-only service's `ProtectHome=yes`, namespace restriction and
mount syscall bans cannot label resources or start workers. Design separate
SELinux domains and narrowly scoped fixed installer/worker execution inside
the same authority, with explicit descriptor IPC and necessary privileges.
Derive permissions from demonstrated operations; do not remove the read
service's sandbox wholesale. SELinux policy installation remains privileged;
the UI never submits policy text, commands, arbitrary contexts or service units.

Generalize peer UID, resource ownership, paths, grant contexts, workload handles,
private displays and audit filtering. Bind objects to owner and generation;
account names/UIDs may be reused. User-owned history/configuration, package
membership and a successful Polkit challenge remain insufficient authorization
or enforcement evidence. Preserve fresh owner authentication for per-user
READ grants and fresh administrator authentication for enrollment/system policy.

## Durable lifecycle and transaction contract

Proposed enrollment states are separate from existing protection health:

| Lifecycle state | Meaning and permitted behavior |
|---|---|
| UNENROLLED | No managed enrollment; coverage UNKNOWN, no automatic grants. |
| PREPARED | Exact inputs, recovery and identity validated; changes journaled, no protection claim. |
| PENDING_SESSION | Mapping/labels committed; old processes must be absent and a fresh session verified. |
| ENROLLED | Configuration enrolled; effective protection still requires current live evidence. |
| DEGRADED | A required runtime fact failed; affected grants/launches stop, status explains lost coverage. |
| RECOVERY_REQUIRED | Transaction cannot safely reconcile; ordinary admission refused, recovery remains accessible. |

Store the transaction in the existing root policy database. Include owner
identity, prior explicit mapping/default-context files, module/type revisions,
precise fcontext entries, descriptor-bound original-label journal, compatible
database version, completed stages and rollback inputs. Live receipts belong
under the existing root runtime directory and bind boot, policy sequence,
object/execution generations and bounded expiry. They are not persistent truth.

Serialize enrollment against grants, registration and package reconciliation.
Commit durable intent before changing kernel policy, mappings or labels; record
readback after each stage. On interruption, reconcile actual state against the
journal and resume or roll back only the owned changes. A database commit alone
cannot turn a failed kernel operation into success. Conflicting external policy,
replacement objects or unsupported schema cause explicit recovery failure.

## Fresh installation and subsequent accounts

1. Preserve the proven interactive Anaconda branding, account, partition/LUKS
   flow and `provision-firstboot.sh` handoff. No predefined user or credential.
2. Acquire the installer-created local account through a root-owned verified
   provisioning record. Do not enroll every UID above a threshold, domain users,
   greeter/service accounts or the development/recovery account by inference.
3. Install the matched offline policy/runtime inputs. Verify enforcement,
   recovery authorization and supported home filesystem; perform bounded
   metadata discovery without reading secrets. Unsupported categories remain
   unavailable. Existing Flatpak overrides and credentials stay in place.
4. Establish exclusive first-session preparation, install/read back policy,
   resource labels and precise mappings, then verify the broker. Release
   ordinary admission only after the enrollment preparation transaction commits.
5. Let normal Fedora PAM establish the login and user-manager contexts. At
   GREYWARD session startup verify real contexts and policy evidence before
   starting the normal desktop. Publish effective coverage only after readback.

The existing installer already gates greetd on `/etc/greyward-production-complete`
and tty1 on the pending marker. Its first-boot unit is `Type=exec`: ordering it
before another unit is not proof that provisioning has completed. Enrollment
must extend the existing completion contract, not introduce a second conflicting
success marker. Commit enrollment before `provision.sh` publishes production
completion and before the provisioner starts/verifies greetd. The admission
gate must wait for that committed preparation, not for first-boot exit or
removal of the pending marker: the provisioner itself waits for greetd, so
those dependencies would deadlock. Initial SSH/other TTY and lingering-manager admission must also
be closed during preparation. Prefer the standard first-boot
`systemd-user-sessions`/nologin lifecycle with a bounded completion dependency
over new PAM edits; prove its behavior for every enabled login route on Fedora.
The gate is a bounded fixed helper, not a new long-running authority. A standard
unit is usable only if its actual PAM/admission failure behavior is demonstrated;
otherwise stop activation and keep this engineering gate open.
Keep authenticated recovery separate. If an ordinary route can start before
the transaction, automatic enrollment is blocked rather than racing it.

After initial installation this completion barrier must not hold every boot
behind a long provisioner. Use bounded root policy preflight and per-enrolled
account readiness, with ordinary admission refusing an incompatible policy.
The exact unit dependencies and error presentation must be tested before
implementation is promoted; conditions and service existence are not readiness.

Accounts created later enter enrollment through the same root-owned transaction
from the supported account-creation workflow, before their first session.
Accounts created by other mechanisms stay explicitly UNENROLLED until reviewed.
Changing the global default mapping would silently enroll those accounts and
is outside this design.

## Existing accounts and session integration

Initial migration of an existing account requires authenticated offline
maintenance with ordinary login entry points inactive and no live target-UID
processes, user manager, lingering jobs or grant workers. Password locking alone
does not block public-key SSH. Do not attempt to solve this with a collection
of ad hoc SSH/getty/PAM rewrites or an automatic active-session kill.

Preserve the existing mapping and labels, then prepare in the same order as
fresh installation. Resume normal admission only into a new PAM session.
Session records may outlive their processes; the development guest has stale
background records. Inspect live PIDs/start times, user-manager and worker
lifetime rather than requiring an empty `loginctl` list or trusting its count.

Keep the canonical production launcher and UWSM compositor-first/environment
handoff. A small package-owned readiness check may explain/refuse a bad session;
it is not the MAC boundary. User-writable autostarts, units and launcher bypass
remain confined by kernel policy. Prefer native PAM context selection over
global `SELinuxContext=` overrides on `user@.service`.

DMS, Security Context, Polkit presentation, portals, PipeWire and ordinary
applications must operate under tested allowed domains. Retain native DMS lock,
Fedora authentication, OpenSnitch, DNS, USBGuard, scanner, Update Center and
recovery ownership. Purpose-specific service access cannot become a generic
read/export deputy for protected labels. Host clipboard isolation is not
claimed; graphical ISOLATED keeps the existing private nested display.

## Default application compatibility

Ordinary native/direct/interpreter workloads inherit the mandatory deny
baseline; managed preparation supplies the additional namespaces/Landlock/
seccomp restrictions. Do not claim those extra restrictions on direct exec.
Normal verified native and Flatpak use should not add a permission dialog just
because the account is enrolled. Preserve ordinary-file access and existing
Flatpak settings, disclosing their actual exposure.

Application-specific default profiles (for example a browser's own registered
data) require root-approved source/generation binding and tested executable/
helper transitions. Current RPM membership alone cannot supply that approval.
Do not silently grant legacy IDEs raw SSH keys or use a blanket trusted desktop
domain to restore compatibility. Unsupported preparation remains unavailable
with a relaunch/review route. Default profiles, source validation and native
Flatpak/portal transitions must be supplied and proven for the installed
applications before claiming that enrollment is transparent to normal use.

## Maintaining labels, grants and coverage

Resource registration needs precise, escaped, root-owned persistent label rules
plus the existing object journal; temporary `chcon` labels alone can be undone
by normal relabeling. Do not generate blanket home rules or blindly run recursive
restorecon. Verify inheritance and supported replacement/import behavior;
unsupported individual files should use the supported containing directory.
An authorized copy is outside label continuity. A watcher is not protection.

Persistent grants retain the existing reviewed READ-only semantics. Revalidate
installation/generation and actual kernel policy on updates; unsigned changes
and unapproved source changes cannot inherit access. Keep distinct subject
contexts and existing verified rules when editing one grant. Revoke by reference,
verify new and held-descriptor denial and report required workload termination.
Data already read is not recalled. Do not infer timed or WRITE support from
worker lifetimes. New timed grants require their own kernel/lifetime proof.

Security Center must consume root-owned live evidence for all seven existing
`SessionCoverage` fields: graphical session, user manager, direct execution,
services/scheduled jobs, enrolled remote sessions, resource labels and
deputies/portals. Check global/per-domain enforcement, loaded policy sequence,
explicit mapping/allowed roles, contexts of live session/process generations,
registered-object labels and active grant/workload revisions. Use bounded
event-driven reconciliation with targeted verification, not high-frequency
whole-home or whole-process scans.

A synthetic deny/allow canary can corroborate readiness but does not prove
coverage of all domains or objects. The current read provider checks actual
negative enrollment prerequisites and reports UNAVAILABLE for the unenrolled
normal account. It cannot provide positive coverage or an effective profile;
add those only from independent session/object/input verification. Preserve
expiry, root bus-owner pinning and schema validation.
Incomplete evidence is UNKNOWN/DEGRADED; an absent broker is UNAVAILABLE.
Acknowledgment, desired policy, audit presence or a cgroup never imply PROTECTED.

Previously deferred exhaustive portal/deputy matrices stay deferred. However,
the paths actually enabled in a production coverage claim must be proven or
disabled. In particular generic document exports cannot bypass protected labels.
Do not set `deputies_and_portals=true` from an unrelated synthetic prototype.

## Failure, upgrade and recovery

| Failure | Required outcome |
|---|---|
| Broker unavailable | Existing kernel denies remain; no new grants/preparations, UI UNAVAILABLE, no unrestricted launch fallback. |
| Policy missing/permissive or wrong login context | Refuse ordinary protected-session admission; no effective profile, authenticated recovery available. |
| Resource/readback mismatch | Affected resource unavailable/degraded and no new access grant; reconcile or recover, not silent relabel success. |
| Crash/full storage/stale preview | No unjournaled success; retained deny policy, bounded failure, owned transaction recovery. |
| Audit loss/rotation | Report activity uncertainty; do not confuse missing events with allowed access or disabled enforcement. |
| Incompatible package/database tuple | Refuse activation and retain last compatible policy; package rollback must restore the matched schema/input set. |

Update Center remains the only reviewed update executor. Preflight candidate
compatibility and rollback before applying a matched runtime/policy/Context/Center
transaction. Policy evolution should preserve old denial types until labeled
objects and live grant contexts have been safely reconciled. Do not require
unconfined login during an ordinary compatible upgrade. Role/domain changes
requiring a new session stay pending and are activated at a deliberate boundary.

Rollback is not just a package downgrade or Btrfs snapshot: login mappings,
module store, persistent label rules, actual home objects and the database must
agree. Recovery validates retained input receipts and object identity; it must
not overwrite labels on replaced files or third-party policy changes. Keep
relevant deny types installed until no references remain. Uninstallation must
refuse removal of an active mapped/labeled policy without the explicit recovery
transaction; no scriptlet may automatically weaken enrolled accounts.

Normal recovery prefers the last compatible confined policy/runtime. Explicit
unenrollment weakens protection and requires fresh administrator authorization,
offline quiescence, grant revocation/worker termination, owned label/mapping
restoration and readback. It is never an automatic error fallback.

Before enrollment, prove the accepted offline administration path independently
of the target account. Explicitly select `greyward-maintenance.target` at boot;
authenticate again using the installation's existing LUKS passphrase/recovery
key on the foreground console. Only then offer a clean interactive root shell.
No recovery account/password, remote root login, automatic token authentication,
SELinux-disable fallback or ordinary-session elevation API is supplied. If the
installed policy prevents maintenance itself, use trusted installer/rescue media,
unlock the existing encrypted root and repair the matched mapping/policy/label/
database state offline. This external route also needs actual validation before
enrollment. Normal-session administrative operations remain narrow typed Polkit
actions; ordinary `wheel` membership cannot admit an unconfined shell.

## Risks and containment

| Risk | Containment and blocking evidence |
|---|---|
| Login lockout or first-boot dependency cycle | Recovery authority proven first; preparation precedes the existing completion marker/greetd start; bounded readiness never waits on the greeter it blocks. Actual production-chain failure/retry test required. |
| Concurrent SSH/TTY/linger starts during preparation | Exclusive first-session admission or offline migration; demonstrate all enabled routes closed. Password lock and graphical gate alone are insufficient. |
| Cross-user or alternate-role access | Per-owner identities/mappings, ordinary-only roles, root-only prepared subjects and multi-user denial tests; no copied synthetic owner domain. |
| Broadened worker/broker privileges | Separate narrow fixed domains within the existing authority, descriptor-bound inputs and no generic policy/exec API; review real required operations. |
| Labels undone by restorecon/replacement or rollback | Precise persistent rules, object journals and readback; unsupported replacement paths remain unavailable. Do not blindly restore labels to new objects. |
| Upgrade removes referenced denial/grant types | Matched compatibility/schema transaction, retain old types until reconciled, deny-default generation changes and interruption/rollback proof. |
| False PROTECTED from metadata or partial coverage | Independently fresh kernel/session/resource/grant evidence for all required fields; stale/missing/partial state never mints an effective profile. |
| Installed administrator loses practical recovery | Resolve reviewed administration plus independent LUKS-aware recovery before activation; no auto-created account or broad wheel/sudo exception. |

## Required implementation changes

Initial journal/provider/maintenance source is implemented as described above;
the remaining changes below are required before activation. No current spike
is a production install recipe.

| Owner | Required change |
|---|---|
| `security-center/crates/greyward-application-security/` | Production provider, multi-user ownership, enrollment journal/reconciliation, evidence provider, fixed privileged installer/worker domains, verified grant persistence. |
| `environment/production/selinux/` | New packaged ordinary-session/user-manager and broker/worker policy, constrained role transitions, persistent resource-label integration; retain greeter policy. |
| `security-center/packaging/application-security/` | Matched policy/runtime receipts, production service sandbox, explicit activation/upgrade/uninstall contract; preserve inert development package separation. |
| `security-center/security-context/`, `security-center/tauri/` | Typed enrollment/status/recovery adapter and real coverage projection; review state, pending-session and failure guidance. No generic admin API. |
| `environment/production/provision.sh`, `provision-firstboot.sh`, `provision-firstboot.service` | Existing account records/completion contract, bounded preflight and first-session enrollment; recovery prerequisite and retry semantics. |
| `environment/production/greyward-start-labwc`, session units | Verified admission/readiness and unchanged UWSM/DMS startup; no PAM or global user-manager replacement. |
| `environment/image/`, production manifests/package inputs | Exact offline closure and installer handoff compatibility; account/LUKS/branding interactions preserved. |
| Existing update/recovery owners | Typed compatibility and journal reconciliation around package transactions; preserve one executor. |
| `tests/`, `tools/greyward-dev/` | Separate-account production-path and failure/rollback fixtures with explicit ownership and retained receipts. |

## Ordered implementation and acceptance gates

| Gate | Required evidence before advancing |
|---|---|
| E0: input/recovery contract | Exact package/policy tuple and source review, independent authenticated rescue tested without changing the active development account. |
| E1: production provider | No fixed UID/test roles, multi-user grant separation, descriptor registration, stale/generation refusal and actual kernel deny/allow/revoke. |
| E2: admission/session | Real separate-account greetd authentication → UWSM → Labwc/DMS plus user manager, SSH/TTY/service/timer routes; no pre-transaction ordinary admission or alternate-role bypass. |
| E3: live coverage | Each enabled coverage field independently evidenced, false/stale/permissive context or label never PROTECTED; enabled portal/deputy paths deny protected exports. |
| E4: continuity/recovery | Broker restart/crash, interrupted activation, compatible upgrade and incompatible refusal; mapping/labels/grants/package rollback, recovery reachable, no unconfined fallback. |
| E5: installed product | Matched packages and fresh interactive ISO installation preserve branding/account/LUKS/storage/handoff; DMS login/lock, Flatpak ordinary access and Protected Data deny/allow/revoke. |

Implement E1–E4 first on a separate account/environment, preserving SSH recovery
and the active `.149` desktop. Never restart the user's installer VM or reboot
the development guest without an explicitly arranged disruptive test. No gate
above is currently passed for production enrollment.

DEFERRED HARDENING: expanded optional-provider/hardware/suspend matrices,
exhaustive unrelated edge cases, broad performance/reproducibility and independent
audit. They do not excuse missing mandatory enrollment/coverage/recovery proof.

## Accepted activation decisions — 7 October 2026

1. **Recovery:** authenticated offline boot/rescue using the existing encrypted
   installation and LUKS credentials, supporting repair, known-good rollback or
   explicit unenrollment. No separate recovery account/password is required or
   automatically created. The recovery entry must refuse normal running-system
   use; it is not an ordinary-session bypass.
2. **Accounts:** automatic enrollment only for normal local users created by
   GREYWARD's installer or supported account workflow. Existing users require
   deliberate migration. System/service, external/domain and unsupported users
   are excluded; no change to the global default login mapping.
3. **Administration:** narrow typed Polkit operations remain normal controls.
   Administrators retain an interactive root shell through an explicit fresh
   authentication boundary that ordinary workloads cannot invoke/acquire/inherit.
   The initial source implementation uses an explicitly selected maintenance
   boot before ordinary workloads start, foreground tty1 and fresh LUKS
   authentication. It offers a clean root shell; it supplies no normal-session
   shell/elevation API. The ordinary mapping must expose no unconfined/owner
   role. Installed boot/repair validation remains required.

These decisions authorize implementation. They do not establish a passed
production gate. Existing-account offline migration is deliberately distinct
from an automatic first-install transaction, and actual recovery/administration
proof must precede enabling production enrollment.
