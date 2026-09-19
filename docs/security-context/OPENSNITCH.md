# OpenSnitch admission — Session 2

## Result

**ADMITTED — 22 August 2026.** OpenSnitch v1.8.0 is the validated GREYWARD V1 application-network engine. It uses a small GREYWARD-owned gRPC/protobuf control plane on a protected local Unix socket; GREYWARD neither ships nor depends on the Qt UI or its database/history implementation.

## Runtime and control-plane evidence

- Official v1.8.0 x86_64 RPM hash was verified before installation; the RPM header is signed by key 6CD595FEFD12DAE2.
- Fedora 44, kernel 7.1.8-200.fc44.x86_64, SELinux enforcing: daemon active; firewalld remained active; OpenSnitch used inet opensnitch beside inet firewalld; no AVC denial was observed.
- Existing prototype evidence established temporary per-application enforcement, IPv4 recovery after rule removal, and clean daemon restart/stop-start behavior without stale state. That test was preserved rather than repeated.
- The exact v1.8.0 proto/ui.proto exposes five bounded RPCs: Ping, AskRule, Subscribe, bidirectional Notifications, and PostAlert. Connection includes process identity, arguments, user ID, protocol, and destination host/IP/port; Rule provides typed action, duration, and operator fields.
- A non-Qt Python spike using only isolated upstream generated protobuf stubs bound /run/greyward-opensnitch-spike.sock. opensnitchd subscribed and maintained the notification stream directly.
- The spike normalized actual daemon events, including resolver and Python process/destination fields; returned a persistent curl allow rule that the daemon saved under its rules directory; and returned a one-shot Python deny that produced Network is unreachable.
- The source in spikes/opensnitch-control-plane is reproducible test evidence only. It is not shipped production code.

## Production integration

The canonical greyward-security-context RPM now installs the OpenSnitch v1.8.0 generated protobuf bindings, a root-only gRPC control-plane service, a root-only 0600 Unix socket under /run/greyward-opensnitch, and a systemd drop-in that starts opensnitchd with a generated runtime configuration. It never ships opensnitch-ui.

The control plane emits only the bounded redacted SecurityContextSummary schema to /run/greyward-security-context. The installed unprivileged session service owns systems.mantis.greyward.SecurityContext1 and serves GetSummary and Refresh. Security Center reads the same normalized summary through its backend; neither user consumer decodes protobuf or gets a privileged control channel.

Focused Fedora validation passed: services started and restarted with firewalld active; curl was allowed; a typed Python deny was enforced; GetSummary returned one coalesced APP_CONNECTION_BLOCKED event with process and destination display detail; the control socket was root:root 0600; and no OpenSnitch Qt package was installed.
## Ownership and production boundary

- firewalld owns zones, inbound policy, service exposure, and its nftables state.
- OpenSnitch owns application interception, attribution, its rules, and its nftables state.
- GREYWARD owns the narrow local control-plane service, normalized Security Context translation, user-facing decisions, redaction, and retention. It never writes raw nftables.
- The production adapter deliberately binds the v1.8.0 proto, uses the root-only daemon socket, bounds and coalesces events, exposes root-only typed rule actions, and reports unavailable state through the redacted summary. It must not import UI modules, recreate UI history, or proxy arbitrary privileged operations.

## Decision

The old REST/D-Bus-based rejection is superseded. The protocol is usable, documented in the tagged source, and proved independently of Qt/UI/database internals. Session 2 is PASS. Session 3 remains NOT STARTED.

## GREYWARD Network Protection surface

The production GREYWARD surface is not the upstream OpenSnitch GUI. The root
control plane retains a bounded, redacted application-network projection from
the v1.8.0 `Ping` statistics and `Subscribe` rule list at
`greyward.security.network/v1`. The unprivileged Security Context service
exposes that projection through `GetNetworkProtection`; Tauri consumes only
that user-bus method and combines it with separately collected firewalld
state.

The projection includes, when the daemon reports them:

- daemon state, version, freshness, counters, and capability flags;
- application-attributed activity with domain/IP, port, protocol, and
  `ALLOWED` / `BLOCKED` / `UNKNOWN` result;
- bounded application aggregates and recent connections;
- current OpenSnitch rules, with GREYWARD-owned typed policy rules marked
  mutable and upstream rules marked read-only.

GREYWARD never copies process arguments, environment, cwd, raw protobuf
messages, or raw nftables. firewalld remains the system/inbound owner and
OpenSnitch remains the application interception owner; neither source is used
as evidence for the other.

### Feodo threat blocking

GREYWARD optionally consumes only the official Feodo Tracker recommended JSON
feed at `https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json`.
A root-owned 15-minute updater validates exact IP/port entries and atomically
writes a last-known-good snapshot. A valid empty response is recorded as
`EMPTY`; failed retrieval or validation preserves the previous indicators and
reports `STALE` or `ERROR`.

On a fresh installation with no snapshot yet, the feed state is
`INITIALIZING`, not a user-facing alarm. Security Center attention starts
only after an established feed becomes stale or fails. The general Threat
Protection destination is also valid without a focused event; a focused event
is optional for notification deep links.

The existing `AskRule` path evaluates GREYWARD-owned policy tiers in this
order: exact process/IP/port false-positive exception, exact Feodo IP/port
deny, then existing GREYWARD rules. The selected decision is returned to
OpenSnitch as the same one-shot rule used by the existing control plane. No
OpenSnitch daemon change or policy reload is required; the next intercepted
connection reads the atomically replaced GREYWARD snapshot.

Threat matches are retained in Network Activity with provider, indicator, and
malware-family metadata. The user-bus service emits a bounded five-minute
notification for each application/IP/port key and routes a click to the
focused Security Center Threat Protection view. Recovery creates only an
exact application/IP/port exception; it never globally allows an indicator.

The managed Secure DNS profile adds a typed DNS-only decision layer to this
same control plane. Direct application DNS on ports 53 and 853 is denied by
default; `systemd-resolved` may reach only the GREYWARD provider addresses on+DoT, while applications use the local resolved stub. Network Activity can save+an explicit application-plus-DNS-port allow rule as a documented bypass. The+daemon runtime is configured with `InterceptUnknown=true` and+`QueueBypass=false`, so an unavailable control plane does not silently turn this+policy into allow-by-default.

### VPN DNS compatibility

The port-53 exception for a VPN is conditional: `systemd-resolved` is allowed
to reach only DNS addresses currently reported by NetworkManager for an active
VPN device. No active VPN means no upstream port-53 exception. Applications
may still use the local resolved stub because that traffic never leaves the
machine; direct application DNS to external addresses remains denied.

Typed application and application-plus-destination policy saves are routed
through the wheel-authorized root `OpenSnitchPolicy1` system-bus boundary.
They are described as saved for future matching connections until daemon-side
confirmation is observed; the next control-plane heartbeat refreshes the
bounded projection. GREYWARD decisions are returned to OpenSnitch as
one-shot decisions; persistence remains in the GREYWARD policy file so a
removal cannot leave a stale daemon-owned rule behind. Arbitrary OpenSnitch
operators are not exposed.

Interactive prompts remain explicitly `DEFERRED`. `AskRule` is synchronous and
the daemon has a timeout/default path; GREYWARD will not present a live
decision control until request, user decision, authoritative daemon action,
confirmation, and timeout behavior have all passed real GREYWARD-DEV traffic
validation.

## Sources

- [OpenSnitch v1.8.0 release](https://github.com/evilsocket/opensnitch/releases/tag/v1.8.0)
- [OpenSnitch v1.8.0 protobuf contract](https://github.com/evilsocket/opensnitch/blob/v1.8.0/proto/ui.proto)
- [OpenSnitch v1.8.0 daemon gRPC client](https://github.com/evilsocket/opensnitch/blob/v1.8.0/daemon/ui/client.go)
- [OpenSnitch v1.8.0 daemon rule application](https://github.com/evilsocket/opensnitch/blob/v1.8.0/daemon/main.go)
