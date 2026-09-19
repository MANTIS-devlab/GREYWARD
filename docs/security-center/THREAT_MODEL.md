# Threat model

## Objective and scope

Security Center observes sensitive system state and may request narrowly scoped
changes. It must not become a privilege-escalation mechanism or a new store of
sensitive telemetry. This threat model covers the V0 application, its data,
upstream services, packaging, and the planned future privilege boundary.

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

1. Untrusted presentation inputs entering the unprivileged GTK process.
2. The user session bus and portal services.
3. The system bus and upstream root services.
4. Polkit authorization between the user action and upstream mechanism.
5. Kernel/library evidence sources exposed to the unprivileged process.
6. User-owned persistent state and explicit exports.
7. Package build/install boundaries.
8. Future GREYWARD user monitor and, separately, any future root service.

The UI is not trusted merely because it is first-party. Upstream D-Bus services
are trusted only for the capability they own. Cached evidence is never an
authorization input.

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
- Future file operations use file descriptors and `openat2`-style resolution
  constraints; they never trust caller-provided absolute paths.

### Config, cache, symlink, and path attacks

- State directories are user-owned `0700`; files are regular `0600` files.
- Reject symlinks, hard-link surprises, device files, and unexpected owners.
- Write bounded data atomically in the destination directory.
- Signatures are not used to pretend user-owned cache is trusted. Cached data is
  display context only and must be re-collected before control.
- A corrupt or oversized cache is discarded without following embedded paths.

### Compromised UI

- V0 gives the UI no direct root process and no GREYWARD root API.
- Upstream mechanisms enforce their own typed operations and Polkit policy.
- Control adapters expose only the two V0 operation families.
- The UI cannot turn a recommendation or arbitrary evidence into an action ID.
- Rate-limit retries and prevent background authorization prompts.

### Compromised future helper

- Keep the service D-Bus activated and absent from V0.
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

- V0 controls cannot alter authentication, boot, encryption, USB policy, or
  outbound application policy.
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
- The UI contains no `sudo`, shell, command template, or generic executor. The
  Recovery V1 fixed-path helper is the sole GREYWARD Polkit exception.
- Read-only collection never triggers Polkit.
- Background activity never triggers authentication.
- No state is reported changed until verified.
- No domain is `PROTECTED` while required evidence is unresolved.
- Optional backend absence cannot be silently converted into success.
- External communication is disclosed and has the pre-request controls defined
  in `PRIVACY.md`; a saved opt-out is loaded before any provider request.

## Validation ownership

`TESTING.md` converts these threats into tests. The historical Session 10
exercise records evidence that was available at the time; its missing checks
remain useful validation work, not a single project-wide blocker. New
capabilities must update this model before implementation.
