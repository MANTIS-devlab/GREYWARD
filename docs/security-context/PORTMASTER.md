# Portmaster admission — Session 2

## Result

**REJECTED — 22 August 2026.** The V1 decision permits Portmaster's upstream Core and intelligence/resource update mechanism. That policy is not the blocker.

## Runtime evidence

A disposable GREYWARD-DEV checkpoint was used. Before installation the VM was Fedora 44 (`7.1.8-200.fc44.x86_64`) with SELinux enforcing, firewalld and NetworkManager active, public zone, and no Portmaster nftables state.

- The official installer RPM is an unsigned bootstrap RPM (`portmaster-1.0.0~2-1.x86_64`) which downloads Portmaster resources; this is supply-chain evidence but not the admission decision.
- The installed upstream `portmaster.service` declares `Conflicts=firewalld.service`.
- Starting Portmaster did not reach an active/API-ready service within the bounded check and then made GREYWARD-DEV unreachable via SSH.
- Restoring the checkpoint returned the canonical DMS, NetworkManager, firewalld, networking, and capture health checks to PASS.

## Decision

Portmaster cannot be GREYWARD's V1 application-network engine while firewalld remains the documented owner of system/inbound policy. Removing the upstream conflict or maintaining a GREYWARD service override would be an unsupported integration and would weaken the ownership boundary; neither is allowed for this session.

No Portmaster package, service, data, firewall rule, or checkpoint remains after cleanup. Do not continue to API, DNS, VPN, IPv6, or resource tests: the firewalld conflict and loss of recoverable normal networking already fail the admission gate.

## Sources

- [Portmaster Linux installation](https://wiki.safing.io/en/Portmaster/Install/Linux-v1)
- [Portmaster developer API](https://docs.safing.io/portmaster/api)
- [Portmaster settings](https://docs.safing.io/portmaster/settings)
