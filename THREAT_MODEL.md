# GREYWARD threat model

## Scope and claim

This model covers the current Fedora 44 image, GREYWARD desktop session,
Security Center, Security Context services, update/recovery paths, and packaging
in this repository. It describes intended properties of implemented controls;
it is not a certification, audit result, or claim that GREYWARD is hardened
against highly capable attackers.

The current target is reducing common desktop risk while making failures and
unknown state visible. The implementation has not received independent security
review and lacks broad bare-metal and adversarial validation.

## Assets

- user documents, application data, browser data, and credentials;
- LUKS secrets, backup credentials, and recovery material;
- integrity of the installed OS, boot path, packages, services, and policy;
- integrity and confidentiality of network traffic and resolver selection;
- application, portal, and removable-device authorization state;
- Security Center evidence, policy state, history, and user decisions;
- update provenance and the ability to recover from a failed change;
- the distinction between GREYWARD-owned state and authoritative upstream state.

## Current adversaries and risks

| Risk | Why it is in scope |
|---|---|
| Opportunistic malicious files | ClamAV scanning, quarantine, provenance, and Safe Open are implemented as an additional pre-use file layer. |
| Malicious or over-privileged applications | Flatpak effective permissions, portal state, sensitive-device observations, and OpenSnitch application networking are exposed. |
| Unsafe or hostile networks | firewalld trust zones, per-application decisions, managed DNS, and VPN-aware reconciliation are implemented. |
| Lost or stolen device | The installer requires encrypted storage and the posture model observes LUKS, Secure Boot, and TPM availability. |
| Unauthorized removable devices | USBGuard state and device history are observed; mutation remains with upstream USBGuard policy. |
| Accidental misconfiguration or drift | Typed checks distinguish failed, stale, unavailable, and not-applicable evidence; mutations are re-read where implemented. |
| Persistence in selected user surfaces | Security Context watches a bounded set of autostart, user-unit, shell-startup, and native-messaging locations. It is not a general host IDS. |
| Privacy leakage from sensors or clipboard | PipeWire sensor observations, portal evidence, and sensitive text classification feed a local privacy capsule. |
| Failed or partial updates | The update helper creates a Btrfs recovery point before DNF5, uses the native offline-update path, and reports provider results separately. |
| Confused-deputy and privilege escalation | The UI is unprivileged; privileged operations use named D-Bus methods or fixed helpers with validation and Polkit where implemented. |

## Trust assumptions

GREYWARD currently trusts:

- the Fedora kernel, boot chain, package manager, repositories, crypto-policy
  implementation, SELinux policy, systemd, D-Bus, and Polkit;
- NetworkManager for connection/VPN state, firewalld for host firewall state,
  systemd-resolved for link resolver state, and OpenSnitch for application
  connection mediation;
- fwupd, Flatpak/portals, USBGuard, ClamAV, Btrfs tools, and Restic within their
  documented roles;
- the pinned DMS source and other recorded build inputs;
- root and the installed package set;
- the user to recognize and authorize consequential actions;
- the build host and artifact-staging process until stronger supply-chain
  controls exist.

Security Center is an observer and orchestrator, not the authority for every
subsystem. A compromised trusted provider can return false evidence. Local
posture cannot establish the absence of compromise.

## Security-property mapping

| Threat | Mechanism | Expected property | Important limitations | Current validation |
|---|---|---|---|---|
| Direct DNS bypass | OpenSnitch DNS-port policy plus systemd-resolved local stub | Applications use the managed resolver path | Root, kernel, unsupported protocols, and applications outside OpenSnitch mediation are outside the property | Python policy tests; limited runtime evidence |
| VPN DNS breakage/bypass | Active VPN devices and their observed DNS addresses receive scoped resolver exceptions | A connected VPN can own DNS without allowing arbitrary external resolvers | Depends on NetworkManager device classification and current DNS data; split-DNS combinations need more hardware/runtime testing | Unit tests include NetworkManager-created and externally managed tunnels |
| Host exposure on unsafe networks | NetworkManager connection identity mapped to firewalld zone | The selected connection uses the intended upstream firewall zone | GREYWARD does not replace nftables/firewalld or prove all rules safe | Rust tests and provider re-read; runtime coverage is incomplete |
| Over-broad Flatpak access | Effective manifest plus override evaluation | Reviews use effective access, including negating overrides | Does not sandbox native RPM applications and trusts Flatpak/portal enforcement | Rust unit tests and frontend contract tests |
| Malicious file before opening | ClamAV scan, detection lifecycle, quarantine, provenance, Safe Open | Known signatures can be detected and handled before use | Not EDR, not complete malware protection, can miss unknown/evasive content, and a clean result is not proof of safety | Python tests and recorded Fedora runtime checks; no independent efficacy testing |
| Stolen storage | Installer LUKS requirement and encryption observation | Data at rest is protected while powered off and locked | Does not cover a running/unlocked system, weak passphrases, firmware attacks, or key extraction | Image acceptance checks; broad physical testing missing |
| Unauthorized USB device | USBGuard provider plus inventory/history | Unknown external-device state is visible and upstream policy can enforce rules | Security Center does not currently own general USB authorization; non-USB buses remain separate | Python/Rust source tests; hardware matrix incomplete |
| Unsafe privileged request | Named Tauri commands, validated D-Bus payloads, fixed Polkit helpers | UI input cannot become an arbitrary root command | Several root D-Bus mutations are group-gated rather than per-action Polkit-authenticated; see privilege model | Static/source tests and service-hardening tests; external review needed |
| Failed system update | Fixed DNF5/Flatpak/fwupd plan and pre-update Btrfs point | System update is prepared through native providers with a recovery artifact | A snapshot is not a full backup; firmware and multi-provider partial failure remain possible | Python transaction tests; more failure-injection and bare-metal testing needed |
| Stale or missing evidence | Typed runtime availability, freshness deadlines, collection issues | Unknown evidence is not represented as success | Correctness still depends on adapters and policy definitions | Rust domain tests and frontend contract tests |

## Non-goals and unsupported threats

GREYWARD does not currently claim protection against:

- kernel, hypervisor, or sophisticated firmware compromise;
- malicious hardware, invasive physical attacks, or hardware implants;
- unknown kernel/browser/desktop zero-days used by a targeted attacker;
- a compromised root account or compromised trusted system service;
- build-host, repository, signing-key, or broader supply-chain compromise;
- traffic analysis or anonymity threats;
- complete malware prevention, endpoint detection and response, or forensic
  reconstruction;
- highly capable targeted or state-level adversaries.

## Long-term direction

GREYWARD aims to raise its threat model over time and may eventually pursue
properties relevant to highly capable or state-level adversaries. **That is a
direction, not a current security claim.** The present implementation and
validation are far from sufficient for it.

Credible progress would likely require substantial attack-surface reduction,
stronger application and process isolation, systematic exploit mitigations,
verified/measured-boot improvements, hardware-backed secret handling,
security-focused kernel configuration, reproducible and attestable builds,
stronger update/signing infrastructure, continuous vulnerability research,
independent review, and sustained adversarial testing. Those items are not
promises and some may prove unsuitable for GREYWARD.

## Open questions

- Should group-gated root D-Bus mutations move to per-request Polkit checks?
- Is OpenSnitch the right long-term application-network authority, or should
  policy move closer to nftables/eBPF while retaining explainable identity?
- Which persistence surfaces are useful enough to monitor without creating a
  misleading host-IDS claim?
- What isolation model should cover native applications?
- What boot and supply-chain properties are realistic without controlling
  hardware or all upstream build infrastructure?
- Which GREYWARD-specific mechanisms should instead be upstreamed or replaced?
