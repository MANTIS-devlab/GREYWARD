# Architecture

## Context

Security Center is a standalone Tauri 2 Rust application with a presentation-only webview. It coexists
with canonical DMS v1.5.3 on Labwc. DMS Settings owns generic desktop/system settings;
Security Center owns GREYWARD-specific security and privacy workflows and does not
duplicate the generic settings surface.

## Component model

```text
Tauri application (unprivileged webview + Rust facade)
        |
        v
Security domain + deterministic evaluator
        |
        v
Typed capability adapters
   | user APIs       | upstream system D-Bus/Polkit    | read-only libraries
   v                 v                                 v
Portals/Permission   NM, firewalld, fwupd, DNF5       SELinux, block/boot facts

V1 shell surface:
DMS Secure plugin -> SecurityContext1.GetShellSummary / typed shell actions
                      -> unprivileged Security Context -> normalized providers

Later only, if justified (the approved Secure DNS exception is described below):
UI -> typed adapter -> narrow GREYWARD system D-Bus service -> Polkit
```

The existing `ClamAvScan1` system-bus adapter is a narrow post-V0 exception for
bounded File Security scan and remediation operations. It is not a general
command or filesystem API; its product contract is defined in
`FILE_SECURITY.md`.

The Tauri process always runs as the logged-in user; the webview has only explicit commands. The Tauri facade calls the Security Context through typed session D-Bus values and parses only the returned typed JSON payload, never human-readable `gdbus` output. Adapter output is typed facts;
only the evaluator maps facts to posture. UI components never execute backend
commands or infer protection from display strings.

## Rust workspace boundary

The implementation should use a repository-local `security-center/` workspace
with conceptual packages:

- `greyward-security-domain`: enums, check definitions, evidence types,
  evaluator, serialization, redaction, and no GTK dependency;
- `greyward-security-backends`: asynchronous typed adapters and interface
  version checks;
- `greyward-security-center`: Tauri application facade, frontend, and user actions;
- fixture/test packages kept non-privileged.

The exact crate split may be consolidated during Session 1 only if dependency
direction remains domain <- backends <- UI and the deviation is recorded.

## Collection flow

1. The app creates a collection generation with cancellation and deadline.
2. Independent read-only adapters run concurrently with per-backend timeouts.
3. Adapters validate and normalize bounded evidence without selecting posture.
4. The evaluator applies versioned check policy and freshness rules.
5. The UI receives an immutable snapshot and renders all states, including
   backend failures.
6. A redacted bounded snapshot is persisted atomically for startup context.
7. D-Bus change signals or relevant lifecycle events invalidate only affected
   checks and trigger debounced recollection.

Opening the app must not refresh package metadata, firmware metadata, public-IP
data, or any other network source automatically. Network-bearing refreshes are
separate, labeled user actions.

The Network Activity page uses a narrow `GetNetworkActivity` user-bus query
over the existing redacted OpenSnitch projection. It retrieves session-local
sequence deltas and bounded decision summaries. Approved redacted events also
enter the separate bounded GREYWARD telemetry history through the read-only
`QueryTelemetry` and `GetRelatedTelemetry` methods; this adds no telemetry
daemon, remote enrichment, packet history, or unrestricted journal access.

## Control flow

V0 controls use upstream APIs directly:

1. The UI constructs a typed request from a selected authoritative object.
2. The adapter re-reads current state and prepares a preview with expected
   effect and prior value.
3. The user confirms from an active local session.
4. The adapter invokes the upstream D-Bus method; upstream Polkit owns any
   administrative authorization.
5. The adapter re-reads the same object and verifies the expected predicate.
6. Success and bounded undo are offered only after verification.

Network rule actions preserve the selected application and optional destination
scope through the typed UI → Tauri → Security Context contract. The UI refreshes
the authoritative rule projection after a verified backend result; a callback
alone is not treated as evidence that a rule exists.

No common “execute,” “write file,” or “run as root” interface exists.

## V0 backend ownership

- NetworkManager remains owner of connection profiles.
- firewalld remains owner of firewall zones and nftables policy.
- fwupd remains owner of firmware metadata and operations.
- DNF5 remains owner of package metadata and transactions.
- Portal services remain owner of user permission stores.
- systemd-journald/audit sources remain native evidence owners; GREYWARD's
  approved normalized history is retained separately under the telemetry
  contract.
- USBGuard remains owner of USB policy when installed.

Security Center reads, explains, and invokes only explicitly supported methods.
It never edits those backends' configuration files behind their APIs.

## DMS integration

V0 installs a desktop entry named by the application ID and relies on DMS's
normal application index. There is no panel placeholder and no DMS fork.

The production DMS Secure plugin is a small first-party presentation surface.
It consumes only the versioned GREYWARD user-bus contract:

```text
systems.mantis.greyward.SecurityContext1
  GetShellSummary() -> greyward.security.shell/v1 JSON
  Refresh() -> normalized context summary
  SetPrivacyProfile(s) -> typed verified result
```

The shell contract exposes no raw evidence or arbitrary mutation. The taskbar
is a glanceable posture icon with one contextual badge; the flyout is a curated
snapshot and privacy-profile quick control. Investigation, evidence, history,
network rules, USB trust, threat remediation, and complex update actions stay
in Security Center. If the snapshot is stale or the monitor is absent, the
plugin displays `UNAVAILABLE` rather than preserving stale security truth.

The packaged `greyward-security-center-route` helper accepts the current
Security Center route model and writes a bounded per-user navigation request.
The already-running single instance consumes, focuses, and routes that request;
unsupported destinations fail deliberately instead of being silently remapped.

## Approved privileged Secure DNS exception

The hardened `systems.mantis.greyward.SecureDns1` system-bus reconciler is the
one GREYWARD-owned privileged exception admitted for Secure DNS. It talks only
to NetworkManager and systemd-resolved, applies measured per-link DoT/DNSSEC,
preserves VPN and split-DNS ownership, and exposes verb-specific methods
through the unprivileged Security Context. It never provides generic command
execution or global resolver configuration. Runtime mutation is active by
default; `/etc/greyward/secure-dns-read-only` is the explicit emergency
read-only rollback path.

Recovery V1 is the separate fixed-path Polkit helper exception described in
`PRIVILEGE_MODEL.md`; it is limited to local Btrfs point creation and cleanup
and is not exposed through the Security Context bus. Other new privileged
helpers remain future work and require that gate.

## Failure behavior

- One adapter failure cannot crash the app or erase other domain results.
- Timeouts cancel work and return typed `UNKNOWN` evidence.
- Missing services remain visible as `UNAVAILABLE`.
- Version mismatch disables only the affected capability.
- A failed or unverifiable control never reports success.
- A corrupt local snapshot is ignored and replaced only after a successful
  collection; it cannot influence authorization or backend mutation.

## Packaging and supply chain

Build a conventional Fedora RPM from pinned Rust dependencies with a recorded
source lockfile. The separate `greyward-security-context` RPM owns the
approved Secure DNS service and its typed D-Bus contract; it must not modify
PAM/boot/authentication, install a second resolver, alter DMS configuration, or
create generic root execution.
