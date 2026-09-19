# Privilege model

## V0 decision

Security Center runs as the logged-in user. The approved Secure DNS exception
is a separate root-owned, hardened D-Bus reconciler in the
`greyward-security-context` package; the Tauri process and Security Context
user service remain unprivileged. Recovery V1 also has one narrow, explicit
user-action exception for local Btrfs snapshot creation and cleanup: the Tauri
facade invokes the fixed `/usr/libexec/greyward-recovery-point` helper through
Polkit. Read-only inspection uses unprivileged libraries, kernel interfaces,
user-session services, and read methods exposed by upstream system services.

Update Center apply has a separate fixed
`/usr/libexec/greyward-update-action` transaction boundary. One `auth_self`
decision authorizes the exact reviewed DNF5, system Flatpak, and fwupd flags;
the helper creates the required pre-update point before DNF5 and accepts no
commands, paths, repository configuration, or arbitrary provider arguments.
User Flatpak stays unprivileged. This is deliberately one prompt rather than a
passwordless rule: passwordless authorization would let any process in the
user session trigger privileged system changes.

When an upstream-backed operation needs administrative authority, the app
invokes the stable upstream D-Bus API and the upstream mechanism performs its
own Polkit check. The Security Center UI never runs as root and never executes
shell commands. The Recovery V1 exception is limited to the fixed helper and
the `create`/`cleanup` argument set; it never accepts UI-provided paths or
commands.

Post-V0 File Security adds one narrow exception: the unprivileged user-bus
service proxies bounded scan and remediation operations to the existing
root-owned `ClamAvScan1` D-Bus service. It accepts only the closed file, folder,
and authorized local-system scan operations described in
`FILE_SECURITY.md`; it is not a general privileged helper. The root service
keeps `ProtectHome=read-only`: quarantine and restore use explicit prepare /
user-session mutation / commit phases, with ownership and SHA-256 verification
at both boundaries. The dedicated `/run/greyward-file-security` transfer area
is the only additional writable runtime path.

## Operation classes

| Class | V0 examples | Authorization |
|---|---|---|
| Read-only local | SELinux mode, boot facts, block topology | None |
| Read-only system D-Bus | fwupd HSI, firewalld state, DNF5 advisories | None unless upstream unexpectedly restricts access; restriction becomes `DENIED` |
| User-session mutation | Portal permission revoke/restore | User bus API and verified schema |
| Upstream privileged mutation | Active connection's firewall zone | NetworkManager/firewalld API and upstream Polkit |
| GREYWARD privileged mutation | Secure DNS per-link reconcile only | Dedicated typed D-Bus service; default active with explicit read-only rollback marker |
| Recovery V1 mutation | Create/clean local Btrfs points | Fixed helper via the `org.greyward.RecoveryPoint` Polkit action, authenticated by the invoking `wheel` user through the graphical agent |
| Update Center apply | Reviewed DNF5, system Flatpak, and fwupd actions, including the pre-update point | One fixed helper via `org.greyward.Update1.apply`; one invoking-user password prompt, no cached or passwordless grant |
| Handoff | Firmware update, storage conversion, recovery workflow | External trusted workflow; Security Center does not claim completion |

## V0 trust-zone control

The request contains only the stable active connection identity and an installed
zone selected from authoritative backend data. The adapter:

1. confirms that NetworkManager owns the active connection;
2. reads its current zone and firewalld state;
3. shows old zone, new zone, scope, and practical inbound-network effect;
4. obtains explicit confirmation;
5. calls the supported upstream method and permits Polkit interaction;
6. re-reads both NetworkManager and firewalld association;
7. reports success only on exact match; and
8. offers a bounded undo to the captured prior zone.

It cannot create/delete zones, edit rich rules, enable panic mode, manipulate
ports/services, reload netfilter, or modify inactive profiles in V0.

## Network Protection typed policy boundary

The post-V0 OpenSnitch Network Protection surface adds one narrow root-owned
system-bus service, `systems.mantis.greyward.OpenSnitchPolicy1`. It is not a
generic helper: the D-Bus policy permits only the `wheel` group, and the
service accepts only validated application path, optional domain/IP/port,
allow/block action, and duration fields. It atomically updates the GREYWARD
policy file; the control-plane heartbeat then refreshes the bounded network
projection. The daemon receives one-shot decisions while persistence remains
in GREYWARD-owned state. It never accepts raw
OpenSnitch operators, nftables, shell text, or arbitrary filesystem writes.

The frontend still calls only the unprivileged Security Context user bus. A
policy save is reported as saved for future matching connections; it is not
claimed as a live daemon rule until authoritative daemon evidence confirms it.
Interactive prompts remain disabled until their complete decision lifecycle is
validated.

## V0 portal control

Portal permission mutation runs without root. A table/resource schema must be
listed as verified in `CAPABILITY_MATRIX.md`. The app displays the application,
resource category, current grant, effect, and restoration behavior. It calls the
documented PermissionStore/Documents method and verifies the changed entry.

Unknown tables and values remain read-only. Revoking a document grant never
deletes the underlying file. Restoration uses the exact captured permission set
only while the resource identity remains unchanged.

## Polkit rules

Security Center does not override policy files for upstream actions. Recovery
V1 and Update Center install only their dedicated fixed-path actions,
`org.greyward.RecoveryPoint` and `org.greyward.Update1.apply`. Each requires the
invoking logged-in user to authenticate for a confirmed request, and the
packaged Polkit rule additionally requires that operator to be in Fedora's
`wheel` group. The update action covers its entire closed provider plan in one
helper process, so it prompts once without using `auth_self_keep`. Both follow
these caller rules:

- set the allow-user-interaction flag only for a user-initiated confirmed action;
- never request authorization during startup, refresh, resume, or background
  collection;
- authenticate the invoking `wheel` user with their own password. The update
  worker is a user systemd service, so its `pkexec` child is not required to
  carry the window's active logind-session flag;
- cancel cleanly with an actionable error when no graphical authentication
  agent exists; the app must be opened in the graphical session so the DMS
  agent can receive the request;
- do not loop after denial or cancellation;
- correlate the response with the exact target and collection generation; and
- revalidate state after the authorization boundary.

Authentication grants permission to attempt an operation. It is not evidence
that the operation succeeded.

## Secure DNS reconciler boundary

`systems.mantis.greyward.SecureDns1` is a dedicated root-owned system-bus
service, not a general privilege broker. It reads NetworkManager and
systemd-resolved state, preserves VPN/private split-DNS ownership, and applies
only the selected per-link DoT/DNSSEC provider through resolve1. Its closed
methods are `GetState`, `SetMode`, `SetProvider`, and `RetrySecureDns`.

The package service is confined with `NoNewPrivileges`, `ProtectSystem=strict`,
`ProtectHome`, private temporary storage, and dedicated state/runtime paths.
Mutation is active by default; creating `/etc/greyward/secure-dns-read-only`
provides an explicit emergency read-only deployment.
The service snapshots and verifies link state before mutation, restores the
verified state on Automatic failure or policy exit, and reports
`VPNProtected` separately from unprotected `Plain` DNS. It never edits
NetworkManager profiles, writes a global resolver configuration, executes
frontend-supplied commands, or silently downgrades Privacy/Custom.

## Future GREYWARD helper gate

A helper can be proposed only when all are true:

1. A roadmap capability passed its prototype and acceptance gate.
2. No stable upstream library or D-Bus method provides the required operation.
3. A narrow operation is materially safer than a documented external handoff.
4. Threat-model, rollback, physical-hardware, SELinux, and Polkit designs exist.
5. The capability matrix marks the operation verified rather than candidate.

The implemented Network Protection service uses the dedicated bus name
`systems.mantis.greyward.OpenSnitchPolicy1` and its versioned Security Context
projection. The bounded File Security service uses
`systems.mantis.greyward.ClamAvScan1`; other helper names remain reserved and
are not implemented. Recovery V1 is the fixed-path Polkit helper exception
described above; it is not a generic helper interface.

## Future helper interface rules

- One typed method per security operation; no generic `Execute`, `ApplyPolicy`,
  file-write, command, script, or opaque JSON method.
- Closed enums and bounded primitives only.
- Caller identity is the unique system-bus name used for Polkit subject binding.
- The service independently resolves objects and computes policy; callers do
  not provide privileged filesystem paths or configuration fragments.
- Authorization happens after structural validation but before sensitive reads
  or mutation; target state is re-read afterward.
- Methods are idempotent where practical and return typed result/revision data.
- Audit records contain action ID, caller UID, result, and redacted target ID,
  never secrets or authorization tokens.

## Implemented service confinement

The packaged root services apply the smallest capability and systemd boundary
validated for their operation. The OpenSnitch control plane retains only
`CAP_CHOWN` for its wheel-readable projection; the bounded ClamAV scanner
retains only `CAP_DAC_READ_SEARCH` so it can inspect user files; the typed
OpenSnitch policy and Secure DNS services receive no ambient or bounding-set
capabilities. All four use `NoNewPrivileges`, private devices and temporary
storage, strict read-only system paths, kernel/clock/hostname protection,
namespace/SUID/realtime restrictions, native system-call architecture, and
Unix-only address families. The ClamAV transfer runtime is traverse-only at
the base (`0711`); per-user transfer directories are `0700` and owned by the
requesting user. The control plane's explicit `CAP_CHOWN` is required to keep
its bounded projections readable by the approved `wheel` group.

SELinux remains enforcing on the supported Fedora base; these systemd controls
are defense in depth and do not replace dedicated SELinux domains or labels.
Never use ad-hoc `chcon` as product policy.

Root-owned state, if ever necessary, lives in a single owned directory with
strict modes, atomic writes, no symlinks, and explicit schema migration. The
service has no external network access unless a future approved capability
demonstrates an unavoidable need.

## Forbidden designs

- Root GTK application or setuid UI.
- Long-lived all-powerful daemon “for future use.”
- `sudo`, `pkexec`, terminal invocation, or shell pipelines.
- Allowing the UI to submit nftables, firewalld, USBGuard, SELinux, systemd, or
  filesystem policy text.
- Authorization cached across unrelated actions or sessions.
- Treating local user ownership of a cache/config file as authorization.
- Weakening SELinux, firewalld, Secure Boot, or upstream policy to ease
  integration.
