# Product contract

## Purpose

GREYWARD Security Center is a standalone first-party application that makes the
security and privacy posture of a GREYWARD device understandable and actionable.
It answers four questions without exaggeration:

1. What protections are actually present and active?
2. What evidence supports that conclusion, and when was it observed?
3. What needs attention, is unknown, or cannot be evaluated here?
4. What can the user safely do next?

The product is a main GREYWARD differentiator because it unifies truthful local
evidence across mature Linux security primitives. DMS continues to own generic
desktop functions such as networking, audio, displays, notifications, and power.

## Audience

The primary audience is a desktop user who wants meaningful protection without
being a Linux security specialist. Secondary audiences are support engineers and
advanced users who need evidence and source details. The default presentation
uses plain language; technical evidence remains available without turning the
product into a SOC or compliance console.

## Principles

- **Local-first:** inspection and evaluation happen on the device. Network
  access is explicit and attributable.
- **Privacy-first:** collect the minimum evidence, retain little, redact by
  default, and disclose every external service.
- **Evidence-based:** every check has a source, observation time, explanation,
  applicability, and capability status.
- **Deterministic:** identical supported evidence produces identical posture.
  No opaque risk model or machine-generated score is permitted.
- **Transparent:** unknown, unavailable, stale, and not-applicable states are
  first-class results.
- **Actionable:** findings explain a safe next step or why no safe control is
  available.
- **Reversible where practical:** a control records prior state, verifies the
  result, and offers undo when the backend permits it.
- **No false security claims:** the UI never equates installation, presence, or
  configuration intent with effective protection.

## Product boundaries

Security Center covers GREYWARD-specific security and privacy views:

- system posture and hardening visibility;
- network protection and trust context;
- application isolation and portal grants;
- data protection visibility;
- device and USB trust readiness;
- privacy and external-service transparency;
- bounded recent security activity;
- recovery and security readiness.

It is not:

- a generic Settings application (DMS Settings remains the general settings owner);
- an antivirus or malware-removal product;
- a SOC, SIEM, pentest, vulnerability-scanning, or compliance dashboard;
- an arbitrary root-command frontend;
- a replacement for Fedora, SELinux, firewalld, NetworkManager, fwupd, Flatpak,
  portals, USBGuard, or their policy engines;
- proof that a compromised administrator or kernel can be contained.

## V0 promise

V0 defines six posture domains—System, Applications, Network, Data, Devices,
and Privacy—plus cross-domain Activity and Recovery views. The implementation
and acceptance status are tracked in `README.md` and `EXECUTION_PLAN.md`; this
contract does not by itself claim that every acceptance gate has passed.

V0 can inspect the approved backends in `CAPABILITY_MATRIX.md`. It may control
only:

1. the trust zone associated with the active NetworkManager connection, using
   upstream NetworkManager/firewalld interfaces; and
2. revocation and restoration of portal permissions whose schema and behavior
   have been verified.

Both controls require explicit user intent, preview, confirmation, result
verification, and immediate undo where supported. V0 does not apply packages or
firmware, convert storage encryption, enroll TPM credentials, authorize USB
devices, or enforce per-application network policy.

The separate Update Center page is governed by
`docs/architecture/UPDATE_CENTER_ARCHITECTURE.md`. Its provider-native apply
and restart workflow is a separately admitted, post-V0 capability and is
runtime-gated; it must not be read as expanding the V0 posture-control promise.
Its visible Check action is resolve-only, while Apply and Restart are explicit
later transitions with provider readback and degraded-result reporting.

Post-V0 Network Protection now adds bounded OpenSnitch application visibility
and typed GREYWARD policy saves behind the separate Security Context contract.
It does not change V0 ownership: firewalld remains the system/inbound owner,
the upstream OpenSnitch GUI is not shipped, and interactive prompts remain
deferred until runtime validation proves their full lifecycle.

## Product language

Use the semantic states defined only in `POSTURE_MODEL.md`. Never display a
numeric posture score, percentage, grade, threat count, or unsupported
superlative such as “completely secure.” Prefer factual wording:

- “SELinux is enforcing” rather than “Malware protection is on.”
- “No encrypted layer was observed for the root filesystem” rather than “Your
  files are exposed.”
- “Firmware security evidence is unavailable on this hardware” rather than
  treating missing HSI as a failure.

Recommendations distinguish a configuration improvement from an active threat.
Security Center never invents urgency to increase engagement.

## External-service position

Security Center itself performs no silent external lookup. Repository-owned and
system services that communicate externally are disclosed in the Privacy view.
The GREYWARD Network Identity widget remains enabled by product decision and
shows public and local IPs side by side. Public lookup contacts
`https://ipapi.co/json/`, falling back to `https://ipwho.is/`; a persistent
switch in the pill popout disables every provider request until manually
re-enabled. Its behavior and disable route must be prominent. The complete
disclosure contract is in `PRIVACY.md`.

## Success

Success is determined by `ACCEPTANCE.md`, not by the amount of functionality
implemented. A smaller truthful V0 is preferable to a broad interface that
implies enforcement the platform cannot guarantee.
