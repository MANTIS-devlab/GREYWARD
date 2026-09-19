# Backend contracts

## Rules applying to every adapter

An adapter has one backend ID, explicit interface/version requirements, bounded
timeouts, cancellation, normalized typed output, sensitivity metadata, and
fixtures. It never chooses posture, renders UI text, invokes a shell, parses
localized command output, or silently switches to a weaker evidence source.

Fallbacks must be explicit. A fallback can reduce evidence quality and produce
`UNKNOWN`; it cannot preserve a protected result merely for visual continuity.

## System adapters

### SELinux

- Use `libselinux` calls for enabled and enforcement state and a safe configured
  state source where available.
- Distinguish runtime enforcing from boot configuration.
- Do not offer policy toggles, boolean editing, relabel, or permissive mode.
- Activity integration may normalize accessible AVC events without storing raw
  records.

### Boot and kernel

- Inspect UEFI presence and Secure Boot variables through stable kernel/efivar
  facilities with bounded reads.
- Record inaccessible/unsupported variables separately from disabled state.
- Kernel lockdown/taint evidence is explanatory and version-sensitive.
- Firmware configuration remediation is a handoff, never a V0 control.

### Storage and TPM

- Resolve mounted root/home/swap to the complete parent block topology and
  identify crypt layers with a supported library/API.
- Do not infer full-disk encryption from an encrypted removable or unrelated
  volume.
- Never read key material, recovery keys, passphrases, or LUKS key slots beyond
  safe metadata required for readiness.
- TPM adapter reports device/capability only; enrollment is post-V0.

### fwupd

- Prefer `libfwupd`, not human `fwupdmgr` output. Until the planned Rust
  `libfwupd` binding is available, the compatibility adapter may consume only
  fwupd's structured JSON client responses; schema gaps and command failures
  become `UNKNOWN`/`UNAVAILABLE` and never preserve a protected result.
- Read daemon version, devices, cached update metadata, history, host-security
  attributes, and attribute-level recommendations.
- Treat absent plugins/hardware and HSI errors honestly.
- No automatic remote refresh, firmware installation, BIOS setting mutation, or
  report upload in V0.

### DNF5

- Use `org.rpm.dnf.v0` D-Bus through a read-only session with explicit requested
  advisory fields.
- Cached discovery cannot trigger a transaction. Refresh is a separate disclosed
  action if later approved.
- Correlate advisories with upgrade candidates; do not label every update a
  security update.
- Package application, offline scheduling, repository/key changes, and release
  upgrade are outside V0.

### ClamAV / File Security

- The existing root-owned `ClamAvScan1` service is the only component allowed
  to invoke local `clamscan`; the UI and user bus do not run scanner commands.
- V1 accepts only `FILE`, `FOLDER`, and explicitly authorized `SYSTEM` scopes,
  with source ownership, symlink, filesystem-boundary, and quarantine
  exclusions enforced by the service.
- Scan operations, detections, and remediation actions use the typed contract
  in `FILE_SECURITY.md` and the shared bounded telemetry store. Raw scanner
  output is never sent to the UI or persisted as history.
- A completed scan, an incomplete scan, and an unavailable/outdated scanner are
  distinct results. A detection means ClamAV matched a signature; it does not
  establish execution or compromise.
- Definition readiness is supplied by the packaged `clamav-update` lifecycle;
  `INITIALIZING` and `UPDATING` are explicit non-ready states, not clean or
  unavailable aliases. File Activity is a projection of normalized
  `FILE_SECURITY` telemetry, including Safe Open and sanitization outcomes.

## Network adapters

### NetworkManager

- Use `libnm` and its cached object model/signals.
- Collect active connection, connection type, Wi-Fi security where applicable,
  VPN/tunnel presence, DNS configuration/effective resolver context, and zone.
- Never expose stored Wi-Fi/VPN secrets.
- Changing trust zone targets one active connection selected by stable identity;
  see `PRIVILEGE_MODEL.md`.

### firewalld

- Use `org.fedoraproject.FirewallD1` interfaces.
- Read service state, version, default zone, active zones, and association needed
  to explain the selected connection.
- Do not parse or mutate raw nftables in V0.
- Do not expose rich-rule, port/service, panic, direct, reload, or policy-set
  controls.

### DNS

- Combine NetworkManager configuration with the active resolver implementation.
- Report DNSSEC/DoT as enabled only when effective evidence supports it; record
  opportunistic/downgrade modes distinctly.
- Split DNS and VPN-owned DNS are explained rather than flattened into one
  misleading server list.
- Security Center performs no test query during ordinary collection.

## Application adapters

### Flatpak

- Detect user and system installations through supported Flatpak APIs.
- Normalize effective sandbox declarations and overrides, preserving their
  source/precedence.
- State clearly that broad filesystem/device/socket permissions weaken isolation
  but do not prove exploitation.
- Native packages are not treated as sandboxed.

### Portals and PermissionStore

- Inspect bus owner, interface version, backend implementations, and supported
  tables.
- PermissionStore strings are opaque until a versioned schema fixture verifies
  meaning.
- Documents list/info/revoke/grant methods are preferred for document grants.
- Unknown tables remain visible only as unsupported counts; never display or
  mutate opaque payloads as if understood.

## Activity adapter

- Open only journals the current user may read and apply exact field/time/count
  filters through `sd-journal`.
- Normalize a small allowlist: relevant service state changes, firmware history,
  update history, portal changes where signaled, USBGuard events when available,
  and accessible SELinux denials.
- Do not request membership in privileged log groups for V0.
- Truncate, escape, redact, and deduplicate before presentation. The adapter is a
  view, not a log collector.

## USBGuard adapter

- Detect daemon and D-Bus versions before listing devices.
- V0 returns only privacy-safe class/vendor/interface summaries and current
  target state. Serial and descriptor hashes remain hidden/ephemeral.
- Active `applyDevicePolicy`, rule append/update, baseline generation, and daemon
  configuration are disabled until the post-V0 prototype passes.

## Application-network candidates

### Portmaster

Potential architecture:

```text
GREYWARD UI -> unprivileged typed adapter -> authenticated localhost API
              -> Portmaster Core system service -> NFQUEUE/eBPF/proc/DNS
```

Positive evidence: the Core and UI are separate; the Core offers per-app
profiles, connection data, DNS/domain/IP policy, local decisions, and an
authenticated app authorization flow.

Blocking evidence: incomplete external API documentation, an internal database
WebSocket used by the UI, deep DNS ownership, VPN-specific incompatibilities,
self-managed resources/updates, large packaging footprint, and unacceptable
upstream SELinux installation guidance. GREYWARD cannot ship development mode,
disable API authentication, use mutable `latest` assets, retain uncontrolled
self-update, or relabel `/opt` binaries ad hoc.

### OpenSnitch

Potential architecture:

```text
OpenSnitch daemon -> Unix gRPC -> GREYWARD adapter/server -> GREYWARD UI
```

Positive evidence: Linux focus, GPLv3 source, separate daemon/UI, protobuf
schema, local rules, prompt/default action, signed/checksummed RPM releases, and
an application-specific nft table in v1.8.

Validated production boundary: the daemon connects only to a GREYWARD-owned
v1.8.0 protobuf control plane over a root-only Unix socket. GREYWARD consumes
bounded `Ping` statistics, `Subscribe` rules, and `AskRule` decisions through a
redacted user-bus projection. The upstream GUI, database, raw protobuf, and
raw nftables are not shipped or exposed.

Remaining limits are explicit: application activity exists only when the
daemon reports structured events; unknown attribution/result stays unknown;
upstream rules are read-only; typed GREYWARD policy saves are confirmed as
future-policy changes; and interactive prompts are deferred until the full
request/decision/confirmation/timeout lifecycle is validated.

### Network Activity projection

The Security Center exposes a narrow user-bus `GetNetworkActivity` query over
the existing redacted control-plane snapshot. It accepts a session-local
sequence cursor and bounded limit, and returns newest-first activity deltas,
decision counts, and one-minute buckets for the last 30 minutes. The control
plane retains at most 4,096 live events. Approved redacted events may also be
written to the separate bounded GREYWARD telemetry history; that history is
not a generic browsing or DNS history.

The supported user-facing hierarchy is application, destination, and
allowed/blocked/unknown decision. Protocol, port, rule, source, and timestamp
are secondary evidence. Throughput, active connections, DNS request history,
reputation, and remote server-location enrichment are deliberately not
collected or displayed. Destination rows may show an endpoint-country flag
when Security Context resolves the observed public IP from one or more local
sources: the packaged local GeoIP Country database, a primary GeoIP2 database,
an optional second local GeoIP2 database, and/or an optional RFC 8805-style
local geofeed. `geoiplookup`, `mmdblookup`, and feed reads are local, bounded,
cached, and have no network fallback. `GREYWARD_GEOIP_DB`,
`GREYWARD_GEOIP_DB_SECONDARY`, and `GREYWARD_GEOFEED_DB` may point to local
files; `GREYWARD_GEOIP_LEGACY_DB` can override the packaged legacy database.
The resolver makes a stable weighted choice when sources disagree;
the transient projection carries `country_confidence` and
`country_converged`, so the selected country remains visible but is labelled
as low confidence in its accessible label when necessary. A domain suffix may
provide a last-resort display hint only when no IP source answers; it never
overrides IP evidence or claims server location. Reverse DNS, provider
ownership, and private IPs are never treated as location evidence. When no
local source provides a country, the UI shows a neutral world marker. Only
the transient two-letter country code and confidence metadata cross the
user-bus projection;
telemetry history retains the original redacted destination fields without the
enrichment. Application artwork and country markers are local-only; unknown
identities use deterministic fallbacks. Viewing activity must not make a
request to an observed domain or any remote icon service.

### Comparative decision gate

The prototype must use isolated disposable VM/checkpoint boundaries and identical
test traffic. Measure:

- process attribution accuracy and unknown attribution behavior;
- prompt/default-deny and unattended/failover behavior;
- domain/IP rules, DNS ownership, encrypted DNS and bypass behavior;
- IPv4/IPv6, firewalld/nftables ordering and cleanup;
- NetworkManager reconnect, suspend/resume, captive portal, and DNS changes;
- WireGuard/OpenVPN plus representative VPN clients and kill switches;
- local-only mode and every external connection/update;
- idle/load CPU, RSS, wakeups, connection latency, database growth and startup;
- SELinux denials/policy, service confinement and privilege surface;
- API authentication, versioning, completeness and custom-UI feasibility;
- source pinning, clean offline build, RPM ownership, license/SBOM and rollback;
- upstream activity, breaking-change history, maintenance bus factor, and fork
  delta.

The selected integration remains an unmodified pinned daemon behind a thin
GREYWARD adapter. A broad frontend/backend fork or dependency on undocumented
internals is still forbidden. The remaining acceptance work is runtime
validation of the bounded Network Protection surface, not selection of another
backend.

## Flatpak application evidence

Flatpak application details are collected by the typed backend adapter for both user and system scopes. The normalized evidence includes application ID, origin, version, branch, architecture, runtime, manifest permissions, user/system overrides, and an understandable access summary. The effective-access resolver applies manifest context first, then local override additions/removals, before classifying network, filesystem, device, and desktop-service access. Publisher verification is `UNKNOWN` unless an authoritative local source confirms it; Flathub publisher verification is not a safety verdict. Broad filesystem/device access is review evidence, not proof of compromise. The collector does not impose an arbitrary application-list cap: partial scope collection is carried as partial inventory evidence rather than represented as an empty list.

Security Center remains read-mostly for Flatpak. It does not expose arbitrary override editing or generic command execution. Installation and removal belong to Software, and application updates belong to `org.greyward.Update1`.
