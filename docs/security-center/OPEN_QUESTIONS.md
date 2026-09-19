# Open evidence questions

No unresolved product choice blocks Session 1. These questions require evidence,
not speculative user preference.

## V0 evidence gates

### Physical hardware matrix

- Which GREYWARD target devices represent TPM 2.0, LVFS/HSI-supported firmware,
  unsupported firmware, LUKS2, Secure Boot off/on, and USB docks?
- Owner: Session 10/release engineering.
- Resolution: record model/firmware without publishing device serials; run the
  physical cases in `TESTING.md`.

### DNF5 daemon availability

- Which Fedora 44 package/version supplies the stable daemon API and what cached
  read operations are unprivileged?
- Owner: Session 3.
- Failure direction: mark update posture unavailable; do not add command parsing
  or PackageKit silently.

### Portal table schemas

- Which PermissionStore tables/values are present on the target portal versions,
  and which documented interface owns safe restore semantics?
- Owner: Session 5.
- Failure direction: keep unknown schemas read-only and disable their controls.

### Event visibility

- Which SELinux, firewalld, fwupd, update, portal, and USB events can the normal
  GREYWARD user read without expanded group membership or helper access?
- Owner: Session 6.
- Failure direction: show source unavailable; do not expand privilege for V0.

### Network trust rollback

- How do NetworkManager and firewalld behave when the active connection is
  replaced, disconnects, or changes owner during apply/undo?
- Owner: Session 4.
- Failure direction: invalidate undo and show a verified current-state result.

## Post-V0 evidence gates

### OpenSnitch Network Protection runtime gate

- Can either provide a stable authenticated backend contract for GREYWARD without
  depending on undocumented internals or carrying a broad fork?
- Can vendor self-update be disabled and all artifacts pinned/rebuilt?
- Do Fedora SELinux, firewalld/nftables, systemd-resolved, NetworkManager,
  suspend/resume, IPv6, VPNs, and kill switches remain reliable?
- What are attribution error rates and fail-open/fail-closed behavior?
- What are measured CPU/RSS/wakeups/latency/storage costs?
- Owner: GREYWARD-DEV Network Protection acceptance; Portmaster remains
  rejected and is not a production dependency.

### USBGuard active control

- What baseline safely handles built-in USB devices, docks, keyboards, recovery
  media, and headless/remote development?
- Can IPC ACLs, policy rollback, and daemon failure behavior meet the threat
  model without lockout?
- Owner: USBGuard prototype.

### Sensitive Files

- Can local classification provide useful accuracy without collecting content or
  pretending to enforce native-application access?
- Which stable identity/enforcement primitives could act on a label?
- Owner: Sensitive Files prototype.

### Travel Mode

- Which policy changes are safe to compose, how are conflicts detected, and how
  does recovery work when networking, USB, or the UI becomes unavailable?
- Owner: Travel Mode prototype.

### AI assistance

- Can a local model explain deterministic evidence with reliable citations,
  bounded resources, no data export, and no control authority?
- Owner: deferred AI prototype.

## Closing questions

A question is removed only by recording dated evidence and a decision in
`RESEARCH.md`, `CAPABILITY_MATRIX.md`, and `DECISIONS.md` as applicable. “It
worked once” is not sufficient for a security capability.
