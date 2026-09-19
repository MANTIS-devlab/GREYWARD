# Research and runtime evidence

Status labels in this file are evidence maturity, not implementation progress:
`VERIFIED`, `CANDIDATE`, `PROTOTYPE REQUIRED`,
`HARDWARE VALIDATION REQUIRED`, `DEFERRED`, and
`NOT GENERICALLY ENFORCEABLE`.

## Method

Research was performed against the actual GREYWARD repository, the reachable
GREYWARD development VM, and primary upstream documentation current on
2026-08-20. Runtime commands were read-only. No package, policy, service, or
security setting was changed.

Primary references:

- [Fedora SELinux documentation](https://docs.fedoraproject.org/en-US/quick-docs/selinux-getting-started/)
- [fwupd Host Security ID specification](https://fwupd.github.io/libfwupdplugin/hsi.html)
- [fwupd client API](https://fwupd.github.io/libfwupd/class.Client.html)
- [firewalld D-Bus API](https://firewalld.org/documentation/man-pages/firewalld.dbus.html)
- [NetworkManager developer APIs](https://networkmanager.dev/docs/developers/)
- [NetworkManager settings D-Bus reference](https://www.networkmanager.dev/docs/api/latest/nm-settings-dbus.html)
- [DNF5 daemon D-Bus API](https://dnf5.readthedocs.io/en/latest/dnf_daemon/dnf5daemon_dbus_api.8.html)
- [Portal PermissionStore](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.impl.portal.PermissionStore.html)
- [Portal Documents interface](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Documents.html)
- [USBGuard D-Bus API](https://usbguard.github.io/documentation/dbus/usbguard-dbus.html)
- [USBGuard security configuration](https://usbguard.github.io/documentation/configuration)
- [Polkit reference](https://polkit.pages.freedesktop.org/polkit/)
- [systemd crypttab and hardware-token model](https://www.freedesktop.org/software/systemd/man/crypttab.html)
- [systemd journal API](https://www.freedesktop.org/software/systemd/man/sd-journal.html)

## Repository reality

- DMS v1.5.3 is the canonical generic shell on Labwc.
- The former legacy Quickshell tree and `SecurityPlaceholder.qml` were removed;
  canonical DMS presents no Security Center placeholder. Security Center
  integration must use a desktop entry.
- The former standalone GREYWARD Settings GTK4/libadwaita prototype was removed.
  DMS Settings owns generic desktop/system settings; Security Center remains a
  separate Rust application for GREYWARD-specific security and privacy workflows.
- DMS has a first-party `greywardPublicIp` plugin enabled in
  `plugin_settings.json`. It displays public and local addresses together. Its
  QML invokes HTTPS-only `curl` requests against `ipapi.co` and `ipwho.is` only
  while the persistent public-check switch is on. The exact privacy behavior is
  captured in `PRIVACY.md`.
- Existing provisioning installs Fedora security primitives but not Flatpak,
  USBGuard, OpenSnitch, Portmaster, or DNF5 daemon server.

## Runtime snapshot — 2026-08-20

Target: GREYWARD-DEV Hyper-V VM, Fedora Linux 44, kernel
`7.1.8-200.fc44.x86_64`, DMS active with no legacy GREYWARD shell service.

| Capability | Observed evidence | Planning consequence |
|---|---|---|
| SELinux | Enabled, targeted policy, enforcing | V0 can verify effective/configured state; enforcing is not a universal security claim. |
| Boot | UEFI present; `mokutil` reported Secure Boot enabled | V0 can inspect; enabling/changing firmware is a handoff. |
| Root storage | Btrfs root/home on plain `/dev/sda3`; no LUKS layer | Production encryption policy should report `ACTION_REQUIRED`; do not exempt the development VM. |
| TPM | No `/dev/tpmrm0`; systemd capability result partial | TPM-backed claims are unavailable in this VM and require physical hardware. |
| fwupd/HSI | fwupd installed; daemon D-Bus activatable; HSI command failed to return attributes in the guest | Adapter is viable, but HSI correctness is hardware-gated. |
| Updates | DNF exists; `dnf5daemon-server` and PackageKit absent | Add/read through a planned, pinned DNF5 daemon dependency; prototype interface/version before relying on it. |
| Firewall | firewalld active; default public zone bound to `eth0`; nftables present | firewalld remains owner. Unprivileged remote query encountered Polkit for some detail, which must map to denied/unknown rather than shell fallback. |
| Network/DNS | NetworkManager connected; systemd-resolved stub; one DNS server; DNSSEC unsupported and DoT disabled | Show actual transport validation; do not describe ordinary resolver presence as secure DNS. |
| Flatpak | Package absent | Applications domain must show native-app limitation and backend unavailability honestly. |
| Portals | Desktop, Documents, and PermissionStore services active | Portal inspection is feasible even while Flatpak is absent; table semantics still need fixtures. |
| USBGuard | Package/service absent | Observation is optional/unavailable in V0; control is post-V0. |
| OpenSnitch/Portmaster | Both absent | No backend selection can be made from feature documentation alone. |
| Events | auditd and journald active | Unprivileged visibility must be measured per source; V0 must not add broad log-reading privilege. |

The SSH alias in `.secrets/ssh/config` still referenced an old unreachable
endpoint while repository DMS evidence named the live endpoint. This reinforces
that cached configuration is not runtime truth and should be shown as stale or
unknown when authoritative collection fails.

## Primitive findings

### SELinux — VERIFIED for inspection

Use `libselinux` for enabled/enforcing/configured evidence. Do not parse command
output. AVC events are supplementary activity, not proof that a protection is
effective or broken. Security Center must not propose permissive mode as a fix.

### Secure Boot, UEFI, LUKS, TPM — mixed

UEFI and Secure Boot inspection is realistic using kernel/efivar evidence.
Changing Secure Boot is firmware-specific and `NOT GENERICALLY ENFORCEABLE`.

Block topology and LUKS signatures can establish whether root/home/swap have an
encrypted ancestor. In-place conversion is destructive and outside the app;
enrollment of TPM/FIDO2 tokens depends on LUKS2, recovery planning, boot policy,
and physical validation. TPM presence alone proves neither ownership nor policy.

### fwupd/HSI — HARDWARE VALIDATION REQUIRED

`libfwupd` exposes devices, upgrades, history, host security attributes/events,
and HSI. The HSI specification is explicitly under development and x86/UEFI
oriented. Consume individual attributes, result flags, metadata, and
recommendations; do not translate HSI into a GREYWARD score or infer HSI:0 when
attributes cannot be collected.

### Updates — CANDIDATE

The DNF5 daemon provides a typed system D-Bus API, advisory metadata, transaction
resolution, Polkit integration, and offline transactions. V0 needs read-only
cached advisory discovery only. Metadata refresh is an explicit network action;
transaction execution is outside V0. The daemon is absent in the current VM, so
version and Fedora packaging must be verified in Session 3.

### firewalld/nftables — VERIFIED with a narrow control

firewalld documents D-Bus as its primary programmatic configuration interface
and separates runtime from permanent configuration. Direct nftables mutation
would compete with firewalld and is rejected for V0. NetworkManager connection
zone association is the user-facing security control; rich rules, ports,
services, reload, panic mode, and policy sets are outside V0.

### NetworkManager/DNS — VERIFIED for inspection

`libnm` is the preferred GLib interface over command execution. It exposes
connections, Wi-Fi security, VPN activity, DNS configuration, and firewalld zone
association. DNSSEC and DNS-over-TLS values may be defaulted or ineffective when
the selected resolver plugin lacks support; Security Center must display the
effective resolver evidence and uncertainty.

### Flatpak/portals — CANDIDATE

The PermissionStore API is stable but deliberately free-form: table names,
resource IDs, and permission strings are not interpreted by the service. The
Documents interface has explicit list/info/grant/revoke semantics. V0 may mutate
only schemas verified against the installed portal version. Flatpak overrides
and sandbox declarations are configuration, not proof of complete confinement.

### USBGuard — PROTOTYPE REQUIRED for control

USBGuard exposes typed device/policy D-Bus interfaces and a rule language. Its
own documentation warns that improperly configured IPC permits local policy
manipulation and that shutdown/controller restoration choices can weaken
enforcement. V0 observes package/service/device capability only. Active policy
requires physical hotplug, dock, keyboard, recovery, and lockout testing.

### Security events — CANDIDATE

Use `sd-journal` filters and documented backend histories, constrained to data
the user can already read. Do not grant broad journal/audit access just to enrich
the UI. Normalize a small event set and query bounded time/count windows without
persisting raw records.

## Application network control comparison — 2026-08-20

Final planning result: **OPENSNITCH SELECTED** for the bounded GREYWARD
application-network surface. This does not admit the upstream GUI or a
generic privileged rule proxy; the production gate is the live
GREYWARD-DEV Network Protection validation described in `TESTING.md`.

Primary Portmaster evidence:

- [Portmaster source and technical introduction](https://github.com/safing/portmaster)
- [Architecture overview](https://docs.safing.io/portmaster/architecture/overview)
- [Core service](https://docs.safing.io/portmaster/architecture/core-service/core/)
- [OS integration](https://docs.safing.io/portmaster/architecture/os-integration)
- [Developer API](https://docs.safing.io/portmaster/api)
- [Linux installation](https://docs.safing.io/portmaster/install/linux)
- [VPN compatibility](https://docs.safing.io/portmaster/install/status/vpn-compatibility)
- [Packaging repository](https://github.com/safing/portmaster-packaging)

Primary OpenSnitch evidence:

- [OpenSnitch source](https://github.com/evilsocket/opensnitch)
- [OpenSnitch v1.8 releases](https://github.com/evilsocket/opensnitch/releases)
- [Rules](https://github.com/evilsocket/opensnitch/wiki/Rules)
- [FAQ and interception limitations](https://github.com/evilsocket/opensnitch/wiki/FAQs)
- [Build process](https://github.com/evilsocket/opensnitch/wiki/Compilation)

| Criterion | Portmaster | OpenSnitch | Planning assessment |
|---|---|---|---|
| Security model | Root Core service sees raw packets through Linux NFQUEUE; connection attribution uses eBPF and `/proc`; integrated DNS/privacy filter | Root Go daemon intercepts new connections using netfilter/nftables/NFQUEUE with eBPF, audit/ftrace or `/proc` attribution | Both are large privileged enforcement boundaries requiring hostile testing. |
| Privacy | Decisions are local, but signed software/intelligence/filter/GeoIP updates contact Safing infrastructure; optional SPN is external/paid | Core filtering can operate locally; no required cloud account; remote multi-node mode is optional | Portmaster's external data plane needs a complete manifest and local-only verification. |
| Feature coverage | Per-app profiles, DNS interception/encryption, domain/IP/filter lists, monitoring, SPN and split routing | Prompt/default action, process/domain/IP rules, system firewall rules, monitoring and multi-node GUI | Portmaster is broader, but feature count does not decide suitability. |
| API quality | Authenticated localhost HTTP API; external app authorization exists; database WebSocket is explicitly incompletely documented | Protobuf/gRPC between daemon and UI; schema source exists, but UI acts as server and daemon as client | Neither currently supplies a clearly stable, versioned, minimal third-party frontend contract. |
| Custom UI | Core and Electron UI are separate; supported API could permit a GREYWARD UI | Daemon and PyQt UI are separate; GREYWARD may need to implement server/event semantics | Feasible in principle; fragile if internal endpoints or UI database behavior are required. |
| DNS ownership | Secure DNS is integral and cannot be completely disabled; DNS interception supports attribution/filtering | Primarily connection firewall; DNS/eBPF capabilities exist but are less integrated | Portmaster risks competing with systemd-resolved and VPN DNS ownership. |
| firewalld/nftables | Injects iptables-compatible chains/NFQUEUE; coexistence ordering and cleanup with Fedora firewalld need proof | v1.8 groups rules in its own nft table; system firewall features can overlap firewalld | Neither may become a second general firewall owner without explicit boundaries. |
| VPN compatibility | Upstream documents DNS/killswitch conflicts and provider-specific workarounds; recent releases continue VPN fixes | VPN/eBPF/process-attribution behavior varies; upstream documents kernel requirements and failure cases | Test NetworkManager OpenVPN/WireGuard and representative clients under IPv4/IPv6. |
| Resource use | Core, DNS, intelligence database, UI/notifier, and large resource bundle; no acceptable GREYWARD benchmark yet | Smaller daemon RPM plus separate Python/PyQt UI; no GREYWARD benchmark yet | Measure idle/load CPU, RSS, packet latency, wakeups, database growth, and startup. |
| Fedora/SELinux | RPM offered, but official docs recommend manual `chcon` for `/opt` execution and self-managed layout | RPM assets offered; v1.8 uses PyQt6 and an application-specific nft table | Ad-hoc SELinux relabeling is unacceptable; both need native Fedora policy/packaging audit. |
| Packaging/update | Stub/install downloads roughly 300 MB and Portmaster self-updates resources; packaging repo says complex signing is not CI-built | Signed release tag and checksummed daemon/UI RPM assets; RPM config updates may need manual handling | GREYWARD requires pinned source/assets, disabled vendor self-update, SBOM and reproducible RPMs. |
| Licensing | Main and packaging repositories report GPL-3.0; SPN/service/trademark boundaries require legal review | GPL-3.0 | Both are potentially usable, subject to complete component/license and branding review. |
| Upstream/fork risk | Active v2 releases; broad multi-platform product and internal API evolution create dependency risk | Active v1.8 release; smaller project and UI/protobuf dependency history create maintenance risk | No broad fork. Prefer upstream API contributions and a thin adapter. |

### Answer to the key Portmaster question

Portmaster could technically serve as a GREYWARD backend while GREYWARD supplies
the frontend because the Core service and UI are separate and an authenticated
local API exists. It is not yet safe to call this a mature supported integration:
the documented external API is incomplete, full connection/profile UI behavior
appears to depend on a database WebSocket, update/packaging ownership conflicts
with GREYWARD reproducibility, and Linux DNS/netfilter/SELinux integration is
intrusive. Using supported endpoints for a narrow subset may avoid a fork;
reproducing its full UI against internal interfaces would be a fragile de facto
fork and is a no-go.

The historical comparative research ended with `OPENSNITCH SELECTED`. The
bounded integration remains subject to runtime acceptance and must not expand
into a broad frontend fork or generic privileged control surface.

## Harder differentiated features

- **Sensitive Files:** `PROTOTYPE REQUIRED`. Classification is feasible;
  universal enforcement across native apps, Flatpaks, shells, sync tools, and
  privileged processes is not. Do not scan content in V0.
- **High-Risk/Travel Mode:** `FRAGILE / PROTOTYPE REQUIRED`. A bundle can
  conflict with VPN, DNS, USB, remote access, and recovery. It needs preflight,
  transactionality, automatic rollback, physical testing, and a recovery token.
- **Advanced application policy:** remains deferred beyond the typed
  application/application-plus-destination rules exposed by Network
  Protection; it cannot use raw nftables rules submitted by the UI.
- **AI-mediated security:** `DEFERRED`. Local explanation/recommendation may be
  explored later; AI never selects or performs privileged actions autonomously.
