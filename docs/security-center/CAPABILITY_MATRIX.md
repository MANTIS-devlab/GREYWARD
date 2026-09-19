# Capability matrix

This matrix is the product/UX enforcement contract. A feature may appear as a
control only when its row permits it and runtime availability is confirmed.

Legend:

- **Observe:** collect current local evidence.
- **Explain:** translate evidence and limitations.
- **Recommend:** show a non-executing next step or trusted handoff.
- **Control:** mutate through the named bounded API.

## V0 matrix

| Capability | Backend/source | Status | Observe | Explain | Recommend | V0 control | Validation gate |
|---|---|---|---:|---:|---:|---:|---|
| SELinux mode/config | `libselinux` | `VERIFIED` | Yes | Yes | Yes | No | Fedora VM fixtures; enforcing/permissive/disabled |
| UEFI/Secure Boot | efivarfs/kernel evidence | `VERIFIED` inspection | Yes | Yes | Yes | No | UEFI, legacy, inaccessible variables, physical device |
| Kernel lockdown/taint | kernel virtual interfaces, fwupd attributes | `CANDIDATE` | Yes | Yes | Yes | No | Supported kernels and missing-interface fixtures |
| Root/home/swap encryption | block topology and crypt libraries | `VERIFIED` inspection | Yes | Yes | Yes | No | LUKS1/2, Btrfs/LVM, swap, live media, malformed topology |
| TPM presence/capability | kernel TPM interfaces | `HARDWARE VALIDATION REQUIRED` | Yes | Yes | Yes | No | TPM 2.0 hardware, disabled firmware TPM, VM/no TPM |
| Firmware devices/updates | `libfwupd` | `HARDWARE VALIDATION REQUIRED` | Yes | Yes | Yes | No | LVFS-supported/unsupported hardware, offline metadata |
| Host Security attributes/HSI | `libfwupd` | `HARDWARE VALIDATION REQUIRED` | Yes | Yes | Yes | No | Attribute-level mapping; never infer missing HSI |
| Security update advisories | DNF5 daemon D-Bus | `CANDIDATE` | Yes | Yes | Yes | No | Fedora package/version, cached/offline/stale/denied |
| Firewall running state | firewalld D-Bus | `VERIFIED` | Yes | Yes | Yes | No | service absent/failed/running, owner restart |
| Connection trust zone | `libnm` + firewalld D-Bus | `VERIFIED` | Yes | Yes | Yes | **Yes** | active connection only; preview, Polkit, verify, undo |
| DNS transport/DNSSEC | `libnm`, systemd-resolved evidence | `VERIFIED` inspection | Yes | Yes | Yes | No | plugin-effective state, split DNS, VPN, unsupported DNSSEC |
| VPN presence | `libnm` | `VERIFIED` inspection | Yes | Yes | No quality claim | No | active/tunnel/multiple/disconnected cases |
| Flatpak presence/apps | Flatpak installation API | `CANDIDATE` | Yes | Yes | Yes | No | Flatpak absent/present; system/user installations |
| Flatpak overrides | Flatpak API/config model | `CANDIDATE` | Yes | Yes | Yes | No | Effective merged permissions and malformed config |
| Portal service health | portal D-Bus | `VERIFIED` presence | Yes | Yes | Yes | No | backend missing/version mismatch/multiple implementations |
| Verified portal grants | PermissionStore/Documents D-Bus | `CANDIDATE` | Yes | Yes | Yes | **Yes, verified schemas only** | table/version fixtures; revoke, verify, restore |
| Native-app isolation | package/process evidence | `NOT GENERICALLY ENFORCEABLE` | Limited | Yes | Yes | No | Never infer sandboxing from desktop/package metadata |
| Recent security activity | `sd-journal`, backend histories | `CANDIDATE` | Bounded | Yes | Yes | No | unprivileged access, redaction, source gaps, rate limits |
| USBGuard availability/devices | USBGuard D-Bus | `PROTOTYPE REQUIRED` for policy | Read-only | Yes | Yes | No | absent service, safe identifiers, physical hardware |
| Recovery readiness | composed local evidence | `CANDIDATE` | Yes | Yes | Yes | No | no key material read; handoff wording and stale state |
| External-service transparency | first-party manifest + local config | `VERIFIED` for current plugin | Yes | Yes | Disable handoff | No | endpoint/cadence drift test and no induced request |

The Update Center is a separate post-V0 capability governed by the architecture
document below. Its native-provider mutation does not change the read-only V0
posture-control boundary.

## Post-V0 matrix

| Capability | Candidate | Status | Production gate |
|---|---|---|---|
| DMS posture summary widget | GREYWARD unprivileged user monitor | `CANDIDATE` | Stable summary D-Bus, stale behavior, negligible resources, no raw evidence/control |
| Application-aware network control | GREYWARD OpenSnitch v1.8 control plane | `ADMITTED / RUNTIME GATED` | Bounded activity/rules through Security Context; real GREYWARD-DEV traffic, attribution, outcomes, restart, and policy confirmation |
| Network Activity live view | GREYWARD OpenSnitch redacted activity projection | `ADMITTED / RUNTIME GATED` | Session-local cursor deltas, 4,096-event/30-minute bound, real traffic, redaction, stale/unavailable states, no remote enrichment |
| USB authorization policy | USBGuard | `PROTOTYPE REQUIRED` | Physical device matrix, baseline review, IPC ACL, lockout/recovery, rollback |
| Richer activity correlation | upstream event sources | `CANDIDATE` | No new broad log privilege, bounded retention, measured value |
| Sensitive Files classification | GREYWARD local classifier | `PROTOTYPE REQUIRED` | Privacy-safe labels, useful accuracy, no content upload, clear non-enforcement |
| Sensitive Files enforcement | undefined | `NOT GENERICALLY ENFORCEABLE` | Stable cross-application enforcement model required |
| High-Risk/Travel Mode | composed policy transaction | `FRAGILE / PROTOTYPE REQUIRED` | Atomic preflight/apply/verify/rollback, offline recovery, physical testing |
| Advanced application policy | selected application firewall | `DEFERRED / BLOCKED` | Application-network backend selected and identity semantics proven |
| Provider-native Update Center workflow | `org.greyward.Update1` | `ADMITTED / RUNTIME GATED` | Resolve-only Check, explicit provider-native Apply/Restart, readback, authorization, and degraded results |
| AI explanation | local model/rules | `DEFERRED` | Local-only privacy, deterministic evidence citation, non-authoritative output |
| AI privileged action | none | `NOT GENERICALLY ENFORCEABLE` | Prohibited: AI cannot autonomously authorize or execute security mutations |

## UX enforcement rules

- `VERIFIED` does not mean available on the current machine; runtime status must
  also be `AVAILABLE`.
- `CANDIDATE` may appear as read-only V0 capability only with explicit fallback
  and test coverage.
- `PROTOTYPE REQUIRED`, `DEFERRED`, and
  `NOT GENERICALLY ENFORCEABLE` capabilities cannot render enabled production
  controls.
- Hardware-gated checks expose `UNAVAILABLE` or `UNKNOWN` when evidence is
  missing; they do not synthesize failures or successes.
- “Installed,” “running,” “configured,” “observed,” and “enforcing” are distinct
  evidence states.
