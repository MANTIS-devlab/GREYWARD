# Threat model

## Objective and scope

Security Center observes sensitive system state and may request narrowly scoped
changes. It must not become a privilege-escalation mechanism or a new store of
sensitive telemetry. This threat model covers the Tauri application, Context, narrow privileged
services, packaging and experimental Application Security source. Production
enrollment/whole-session guarantees remain unvalidated.

It does not claim to defend against an attacker who already controls the kernel,
firmware, root account, or the upstream security daemon being queried. It must,
however, report evidence limitations and avoid amplifying such compromise.

## Assets

- Accuracy and freshness of posture results.
- Integrity of firewall-zone and portal-permission changes.
- User consent for every mutation and external request.
- Confidentiality of device, application, network, and event evidence.
- Availability of networking, login, recovery, and security backends.
- Integrity of the Security Center package, check policy, and local snapshot.
- Recovery from failed or partially applied controls.

## Trust boundaries

1. Untrusted presentation inputs entering the unprivileged Tauri webview/Rust facade.
2. The user session bus and portal services.
3. The system bus and upstream root services.
4. Polkit authorization between the user action and upstream mechanism.
5. Kernel/library evidence sources exposed to the unprivileged process.
6. User-owned persistent state and explicit exports.
7. Package build/install boundaries.
8. Existing Security Context and narrow root services, including the
   experimental application-security policy/worker boundary.

The UI is not trusted merely because it is first-party. Upstream D-Bus services
are trusted only for the capability they own. Cached evidence is never an
authorization input.

## Protected administration boundary

Protected desktop administration adds a separate, explicit privileged session.
The enrolled ordinary-role closure must not execute real sudo, attach to its
processes, access private PTYs/descriptors, inject protected input, reuse tickets
or receive command output through handoff. PID 1 verifies peer/session identity
and matched immutable inputs; native argument review and fresh PAM precede
elevation. Compositor verification identifies exclusive input; first-party window
titles and screenshots are not authorization evidence. The webview has fixed
open/status capabilities and no privileged command executor.

An authenticated administrator may read Protected Data and change policy. Code
deliberately run inside Administration shares that authority. Confined sysadm
does not make root commands harmless, and a timestamp expiry cannot revoke an
already running root shell. Root/kernel compromise remains outside this boundary.
See [the enrollment authority](APPLICATION_SECURITY_ENROLLMENT.md) for scoped
evidence and recovery limitations. The subsequent
[normal-seat compatibility receipt](../history/security-center/2026-10-09-desktop-compatibility.md)
records actual activation, fresh Administration authentication, native locking,
937 kernel decisions, Flatpak alias denial and grant reuse/revocation. Nested
sudo uses a generation-matched private Fedora password helper, never the shared
ordinary helper. Screen capture/sharing is unavailable until a consented path
can exclude protected surfaces; broad capture is not an acceptable workaround.

## Adversaries

- Malicious local unprivileged process on the same session or another session.
- Compromised Security Center UI process.
- Malformed or hostile D-Bus service impersonating an absent backend on the user
  bus, or returning oversized/invalid data.
- Compromised upstream system service.
- Local attacker tampering with user-owned snapshots or configuration.
- Malicious device metadata, application IDs, SSIDs, domain names, or journal
  fields intended to exploit parsers or UI markup.
- Supply-chain attacker modifying source, dependencies, packages, or updates.
- Physical attacker relevant to boot, encryption, TPM, and USB checks.
- Confused or rushed user induced to authorize a harmful change.

## Threats and required mitigations

### D-Bus and service abuse

- Pin well-known bus names, object paths, interfaces, signatures, and minimum
  supported versions.
- Rely on the system bus daemon for ownership of privileged well-known names;
  reject fallback peers and arbitrary addresses.
- Bound arrays, strings, nesting, and response time before conversion.
- Treat disappearance, restart, owner change, or schema mismatch as invalidation.
- Never expose a generic proxy from UI to a privileged backend.

### Polkit confusion and authorization reuse

- Request interaction only after a visible, immediate user action.
- Bind authorization to the current D-Bus caller/subject and exact action.
- Use separate action identifiers for materially different future operations.
- Re-read target state after authorization to defeat stale previews.
- Never authorize a batch containing targets not shown in confirmation.
- Do not interpret authentication success as operation success.

### Malformed input and injection

- Use typed parsers and closed enums; reject unknown variants and invalid UTF-8.
- Escape all displayed evidence and prohibit backend-provided markup.
- Never pass evidence into a shell, formatter, regular expression, file path, or
  logging template without type-specific validation.
- Fuzz snapshot decoding, adapter decoding, event normalization, and any future
  privileged method inputs.

### TOCTOU and object replacement

- Identify backend objects with stable IDs plus owner/generation information.
- Prepare from an authoritative read, then re-resolve immediately before apply.
- Verify the result from a new authoritative read.
- Invalidate undo if the object, service owner, boot, or session has changed.
- File selection/registration/preparation uses held descriptors and secure resolution
  constraints; they never trust caller-provided absolute paths.

### Config, cache, symlink, and path attacks

- Presentation/cache directories are user-owned `0700`, files `0600`. Root
  policy/database/journals use separately root-owned restrictive directories;
  user-owned history cannot supply authoritative policy.
- Reject symlinks, hard-link surprises, device files, and unexpected owners.
- Write bounded data atomically in the destination directory.
- Signatures are not used to pretend user-owned cache is trusted. Cached data is
  display context only and must be re-collected before control.
- A corrupt or oversized cache is discarded without following embedded paths.

### Compromised UI

- The UI never runs as root. Fixed typed adapters reach narrow privileged
  operations; authorization and policy stay outside presentation.
- Upstream mechanisms enforce their own typed operations and Polkit policy.
- Control adapters expose an explicit allowlist; no generic shell, D-Bus
  forwarding, filesystem export or policy-generation command is accepted.
- The UI cannot turn a recommendation or arbitrary evidence into an action ID.
- Rate-limit retries and prevent background authorization prompts.

### Compromised root helper/broker

- Activation is owner-specific. The default experimental Application Security
  service has no preset or automatic bus activation; enabling it is not enrollment.
- Minimize code, dependencies, methods, writable paths, Linux capabilities, and
  network address families.
- Apply systemd sandboxing, SELinux confinement, seccomp where compatible, and
  fail closed on policy/version mismatch.
- The helper revalidates all state and never accepts commands, environment,
  unrestricted paths, policy text, or opaque serialized operations.
- Treat helper compromise as root-impacting residual risk and require external
  audit before release.

### Privacy leakage

- Follow `PRIVACY.md`: no undisclosed or uncontrollable network requests,
  persistent opt-out for the default-on Network Identity lookup, bounded local
  retention, sensitivity labels, safe exports, and redacted logs.
- Avoid recording device serials, full SSIDs, public IP addresses, application
  command lines, DNS histories, or access tokens unless a specific visible view
  requires a redacted form.
- Do not copy complete journal or audit records into application state.

### Availability and lockout

- Existing typed USB/network/recovery/update operations retain their narrow
  owners. Application Security source does not alter Fedora authentication,
  native DMS locking, boot or installer encryption flows.
- Firewall-zone changes have preview, previous-value capture, verification, and
  undo; tests include remote-development and active-connection cases.
- Portal permission revocation never deletes the underlying user file.
- Post-V0 Travel Mode and USB control cannot ship without independent recovery
  and automatic rollback prototypes.

### Supply chain

- Pin Rust dependency resolution and source commits; audit licenses and
  advisories; build in a reproducible Fedora environment.
- Never download executable components at runtime.
- OpenSnitch is an admitted production dependency only through the pinned
  GREYWARD control-plane package, with reproducible packaging, update-control,
  rollback, and live-traffic acceptance gates. Portmaster is not a dependency.
- Package signatures, source hashes, SBOM, and clean-build evidence are release
  artifacts.

## Security invariants

- UI UID is never zero.
- The UI contains no `sudo`, shell, command template, or generic executor. Narrow
  root services and Recovery V1 retain explicit typed Polkit boundaries.
- Read-only collection never triggers Polkit.
- Background activity never triggers authentication.
- No state is reported changed until verified.
- No domain is `PROTECTED` while required evidence is unresolved.
- Optional backend absence cannot be silently converted into success.
- External communication is disclosed and has the pre-request controls defined
  in `PRIVACY.md`; a saved opt-out is loaded before any provider request.

## Application Guard and Protected Data — implemented experimental boundary

The current provider is fixed to the isolated development account. SELinux
mandatory denial, descriptor-held registration, root-prepared immutable grant
subjects and persistent READ revocation pass scoped kernel tests. Ordinary
direct execution cannot acquire a reviewed subject through launcher bypass.
The default public read service and installed unconfined session have no
production coverage promise. Exact scope: [current plan](APPLICATION_SECURITY_PLAN.md).

Threats include same-user direct/interpreter/service execution, resource aliases
and replacement, ptrace/process FD access, forged identities/reviews and trusted
service/portal deputies. Limited tests do not prove every enabled production
path. The ordinary compiler currently targets the test subject; production must
cover all permitted transitions. Synthetic owner-role/test permissions must not
enter production enrollment. Kernel enforcement does not depend on UI/history.

Raw grants expose credentials to code/extensions inside the reviewed tool;
already-read/copied data cannot be recalled. Managed isolation has private
namespaces/home/network-off and a private graphical compositor/clipboard.
Security-context host connections alone do not isolate host clipboard. Unknown
RPM signer/source, unsupported payload/Flatpak Safe Open and absent enforcement
stay UNKNOWN/UNAVAILABLE, never implicitly trusted. Root/kernel, compromised
broker/policy installation and malicious privileged package scripts remain
outside the isolation boundary.

DEFERRED HARDENING includes exhaustive optional deputy/portal, hardware,
performance and independent review matrices. Enabled production deputies,
correct grants/live coverage and recoverable session enrollment remain mandatory
before a protection claim. [Enrollment/recovery design](APPLICATION_SECURITY_ENROLLMENT.md)
records approved decisions and initial source, with no production activation.
Synthetic UID-1002 tests exposed an inherited same-domain memory/pipe-read gap;
blanket denial also prevents required self-inspection. The separate authentication
subject now passes cross-domain denial, native PAM and two fresh GUI Polkit
challenges on a private headless display. Persistent launch contracts reject
legacy generic grants, changed identity/revision and broader arguments; the
only current profile discards every output stream from pinned key inspection.
Production input/agent admission, temporary fallback, additional raw-access tool
profiles and lifecycle/recovery remain mandatory work before automatic enrollment.
The [scoped authentication receipt](../history/security-center/2026-10-07-application-security-authentication.md)
does not establish physical-seat or production coverage. The existing account mappings, native DMS
locking and Fedora PAM remain unchanged. Scoped
[evidence](../history/security-center/2026-10-07-application-security-enrollment-initial.md)
must not be treated as a passed production coverage or recovery gate.

## Validation ownership

`TESTING.md` converts these threats into tests. The historical Session 10
exercise records evidence that was available at the time; its missing checks
remain useful validation work, not a single project-wide blocker. New
capabilities must update this model before implementation.
