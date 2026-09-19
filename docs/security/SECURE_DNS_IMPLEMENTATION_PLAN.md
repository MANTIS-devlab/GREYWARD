# GREYWARD Secure DNS implementation

Status: implemented in the GREYWARD Security Context. Automatic per-link
mutation is enabled by default; an operator can create
`/etc/greyward/secure-dns-read-only` for a measured emergency rollback or
diagnostic read-only deployment.

## Current and target ownership

NetworkManager owns links, connection state, VPN state, DHCP DNS, DNS
priorities and routing domains. `systemd-resolved` is the only local resolver;
`/etc/resolv.conf` remains its stub symlink. The privileged
`greyward-secure-dns` D-Bus service is a narrow reconciler and the existing
Security Context session service is the only UI-facing authority. No global
`resolved.conf` Quad9 setting, NetworkManager profile rewrite, second resolver
daemon or frontend command execution is used.

The reconciler mutates only one unambiguous, non-VPN link. It snapshots the
resolved per-link DNS state,
applies the selected provider through `resolve1`, probes resolution, and
restores the snapshot when leaving the secure policy or when the managed chain
cannot reach a provider. The service is root-owned, D-Bus activated, constrained by
systemd filesystem protections, and limited to the typed methods below.

## Policy and measured state

Persisted desired policy is in `/var/lib/greyward/secure-dns/policy.json` and
currently supports `Automatic` (default), `Privacy`, and `NetworkDefault`.
Automatic/Privacy use the ordered encrypted provider chain Quad9
(`dns.quad9.net`) → Control D p2 (`p2.freedns.controld.com`) → AdGuard Public
(`dns.adguard-dns.com`), all over DoT port 853. The selected provider is
reported in runtime state; the order is persisted so it is inspectable.

Runtime state is written to `/run/greyward-secure-dns/state.json` and separates:

- `desired_policy`: the user's selected intent;
- `effective_policy`: `SecureProvider`, `VPNOwned`, `NetworkDefault`,
  `Unavailable` or `Disconnected`;
- `effective_owner`: `Greyward`, `VPN`, `Network`, or `None`;
- `effective_transport`: `DoT`, `VPNProtected`, `Plain`, `None` or `Unknown`;
- `degradation_reason`: `CaptivePortal`, `DoTUnavailable`,
  `ResolverUnreachable`, `DNSSECUnavailable`, `SplitDnsAmbiguous`,
  `NetworkDnsOnly`, `NoActiveLink`, `ProviderMisconfigured`,
  `AllProvidersUnavailable` or `StaleState`;
- measured encryption, validation, resolver, link and reconciliation data.

`VPNProtected` means DNS is inside the active VPN tunnel even when the
protocol inside that tunnel is ordinary DNS. It is not a DNS leak. `Plain` is
only unprotected DNS leaving the device outside a protecting VPN.

## Precedence and modes

1. VPN DNS that owns full-route or advertised split-DNS domains wins.
2. The most-specific NetworkManager/resolve1 routing domain owns private,
   enterprise and LAN queries.
3. GREYWARD applies per-link DoT/DNSSEC for eligible public queries.
4. Network Default uses the active NetworkManager/VPN DNS without making
   encryption or validation claims.

Automatic and Privacy try each managed provider in order and keep the first
provider that passes encrypted transport, DNSSEC and resolution validation. If
all three fail, the state is `Unavailable` and direct DNS is fail-closed;
GREYWARD does not silently fall back to DHCP DNS. NetworkDefault remains an
explicit operator opt-out. Ordinary non-DNS networking remains intact.
NetworkDefault reports the measured `DoT`, `VPNProtected` or `Plain` state.

The reconciler never forces the public chain over a VPN, private route or split-DNS owner,
and never creates parallel public DNS paths. The current implementation uses a
bounded periodic reconciliation (30 seconds) and `RetrySecureDns` for an
immediate probe; provider and resolver changes are restored transactionally.

## D-Bus contracts

The privileged system service owns
`systems.mantis.greyward.SecureDns1` at
`/systems/mantis/greyward/SecureDns1` and exposes `GetState`, `SetMode`,
`SetProvider` and `RetrySecureDns`. The unprivileged
`systems.mantis.greyward.SecurityContext1` service exposes
`GetSecureDnsState`, `SetSecureDnsMode`, `SetSecureDnsProvider` and
`RetrySecureDns`, forwarding only typed values to the privileged service.
Tauri invokes the Security Context only. No QML/Tauri surface talks to
NetworkManager, resolved, VPN clients or privileged sockets.

## Security Center behavior

The Network protection surface shows the measured policy, owner, transport,
encryption, validation, active provider, failover chain, VPN/split-DNS explanation
and degradation reason. It exposes the supported mode selector and retry action, while keeping
the provider registry/backend authoritative. Secure-DNS degradation is evidence
for review, not an automatic network block or invented score.

## Validation and evidence

After installing the packaged service on GREYWARD-DEV:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now greyward-secure-dns.service
gdbus call --system --dest systems.mantis.greyward.SecureDns1 \
  --object-path /systems/mantis/greyward/SecureDns1 \
  --method systems.mantis.greyward.SecureDns1.GetState
```

Capture `nmcli -f GENERAL,IP4,DNS,IP6 connection show`,
`resolvectl status`, `resolvectl dns`, `resolvectl domain` and
`resolvectl query`. Use `tcpdump -ni any '(udp port 53 or tcp port 53 or tcp
port 853)'` to prove strict modes do not emit external plaintext DNS. Test
Ethernet, Wi-Fi, IPv4/IPv6, DNSSEC-valid and DNSSEC-broken names, DoT outage,
captive/restricted networks, LAN names, network switching, suspend/resume,
reboot, Proton VPN, Mullvad, generic WireGuard/OpenVPN and split DNS. Confirm
VPN DNS is reported `VPNProtected`, secure state returns automatically after
outage, and policy/state survive GREYWARD update and rollback.

## Rollback and recovery

Stopping or removing the service leaves NetworkManager and resolved usable. On
Automatic failure the last verified snapshot is restored, but the state remains
unavailable and the DNS-only OpenSnitch policy continues to deny direct DNS
outside the managed path. Strict-mode failures remain unavailable rather than
silently downgrading. Creating the read-only marker disables further
mutation; a managed-link snapshot may be restored through `NetworkDefault`.
User VPN
profiles and NetworkManager ownership are never deleted.

## Current validation limits

GREYWARD-DEV currently has one Ethernet link and no Proton, Mullvad,
WireGuard/OpenVPN or captive-portal test network installed. The live
acceptance therefore proves NetworkManager/resolve1 ownership, DoT/DNSSEC,
plain NetworkDefault, Security Context propagation, policy validation,
automatic signal refresh, and stop/start snapshot rollback; VPN precedence,
split-DNS and captive fallback remain required follow-up test cases before a
production release sign-off. `tcpdump` is also not installed in the VM, so
the current plaintext-leak evidence uses resolve1 state and OpenSnitch's
observed systemd-resolved:853 activity; install the documented capture tool in
the dedicated validation image before release sign-off. Fedora currently labels
the custom service `unconfined_service_t`; a dedicated SELinux domain remains a
production-hardening follow-up.

Provider references: [Quad9 encrypted service documentation](https://docs.quad9.net/),
[Control D free resolver endpoints](https://docs.controld.com/docs/free-dns), and
[AdGuard public DNS](https://adguard-dns.io/en/public-dns.html).

## Definition of done

- Automatic is the default and the provider chain is Quad9 → Control D → AdGuard.
- Direct application DNS on ports 53/853 is denied unless it goes through the
  local resolved stub or an explicit app-scoped exception is saved from Network
  Activity.
- This enforcement boundary is deliberately honest: an application that embeds
  arbitrary DNS-over-HTTPS or DNS-over-QUIC inside ordinary HTTPS/QUIC port 443
  is not identifiable from the current OpenSnitch connection contract. Blocking
  that class requires a separate transparent DNS proxy or browser/application
  policy layer and is not claimed by this implementation.
- Per-link, VPN-aware and split-DNS-aware precedence is deterministic.
- `DoT`, `VPNProtected` and `Plain` are distinct measured transports.
- Desired and effective policy/owner/degradation are separate.
- Provider failover is visible, ordered and self-healing.
- The managed profile never silently downgrades to DHCP DNS.
- Security Center reports effective state through the existing authority.
- The validation matrix above passes on GREYWARD-DEV before production
  enablement, including update, rollback, VPN, captive, LAN, suspend and
  reboot journeys.
