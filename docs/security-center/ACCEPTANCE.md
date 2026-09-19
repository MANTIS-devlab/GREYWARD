# Acceptance contract

Acceptance defines the product outcome independently from implementation ease.
V0 passes only when all criteria below have traceable evidence. Post-V0 features
are explicitly excluded from the V0 gate.

This contract is a validation catalogue, not a claim that the whole project is
blocked on a single gate. The dated
[Session 10 report](SESSION_10_REPORT.md) records which evidence was unavailable
in that environment. Unrun checks remain unknown, not failures and not passes.

## Product truth

- **AC-P01:** Security Center is a standalone application and remains distinct
  from DMS Settings, which owns generic desktop/system settings.
- **AC-P02:** No numeric score, grade, percentage, unsupported threat count, or
  universal-security claim appears in UI, logs, exports, or metadata.
- **AC-P03:** Every visible check has stable identity, semantic state, source,
  observation/freshness time, explanation, applicability, capability status,
  and remediation classification.
- **AC-P04:** Required unknown/stale evidence prevents `PROTECTED` according to
  `POSTURE_MODEL.md`.
- **AC-P05:** Missing/unsupported/denied/failed backends are distinguishable and
  never silently treated as safe.

## V0 capability

- **AC-C01:** System covers SELinux, boot, storage encryption, basic TPM,
  firmware/HSI capability, and security-update readiness with honest hardware
  and metadata limitations.
- **AC-C02:** Network covers active connection trust, firewalld, effective DNS
  evidence, and VPN presence without claiming VPN quality.
- **AC-C03:** Applications distinguishes native apps from sandbox evidence and
  shows Flatpak/portal grants only to the degree supported by verified APIs.
- **AC-C04:** Data, Devices, Privacy, Activity, and Recovery present useful
  evidence and recommendations without implying unsupported enforcement.
- **AC-C05:** The current development VM reports plain root storage and absent
  optional hardware/backends honestly; no development exception fabricates
  protection.

## Controls and privilege

- **AC-S01:** The UI and all ordinary collection run as the logged-in non-root
  user.
- **AC-S02:** Ordinary Security Center collection contains no GREYWARD
  privileged helper, generic executor, or shell-command backend. Recovery V1
  uses only its fixed-path helper through the dedicated Polkit action.
- **AC-S03:** Read-only collection never triggers Polkit or a graphical
  authentication prompt.
- **AC-S04:** Only active-network zone and verified portal-permission control
  families are reachable.
- **AC-S05:** Each control requires immediate explicit intent, exact preview,
  appropriate confirmation, post-authorization target revalidation, result
  verification, and bounded undo/restore when valid.
- **AC-S06:** Cancel, denial, timeout, service restart, concurrent target change,
  mismatch, and undo expiry never report success or mutate unrelated state.
- **AC-S07:** Firmware/package application, encryption/TPM enrollment, USB
  policy, application firewall policy, auth, boot, and recovery secrets are not
  mutable. Recovery V1 may create or clean only its local Btrfs safety point
  through the explicit authenticated workflow.

## Privacy

- **AC-R01:** Ordinary launch, navigation, and local refresh cause no Security
  Center external request.
- **AC-R02:** The Network Identity widget shows public and local IPs together;
  its disclosure names both providers, purpose, triggers/cadence, transmitted
  metadata, memory-only retention, fallback, and persistent pill-switch disable
  route without inducing a lookup. With that switch off, restart and network
  changes cause no provider request until the user manually turns it on.
- **AC-R03:** Every known first-party external service is attributable; detected
  gaps are not represented as no activity.
- **AC-R04:** Persistent state is bounded, user-owned, atomic, symlink-safe, and
  contains no prohibited raw logs, histories, device serials, secrets, keys, or
  recovery material.
- **AC-R05:** Default export is previewed and redacted; no automatic upload
  exists; clearing state affects only Security Center data.

## Security robustness

- **AC-SR01:** Threat-model tests cover D-Bus abuse, Polkit misuse, malformed and
  oversized inputs, TOCTOU, owner replacement, cache/config/path attacks,
  compromised-UI containment, privacy leakage, and availability/rollback.
- **AC-SR02:** All externally supplied strings are bounded, escaped, and safe
  under invalid encoding/control characters.
- **AC-SR03:** Fuzz targets complete without exploitable crash, memory-safety
  defect, uncontrolled resource consumption, or privilege expansion.
- **AC-SR04:** Cached evidence cannot authorize or enable mutation and stale data
  cannot be shown as current.
- **AC-SR05:** No unresolved critical/high security issue passes. Residual risks
  are explicit and linked to affected capability status.

## UX, visual, and accessibility

- **AC-U01:** Overview, six domains, Activity, Recovery, evidence details,
  recommendations, both controls, and all error states are reachable and clear.
- **AC-U02:** Color is never the only state carrier; semantic labels and icons
  remain legible across supported themes/contrast/scales.
- **AC-U03:** Complete keyboard operation, visible focus, accessible names,
  screen-reader announcements, reduced motion, text scaling, and narrow layout
  pass the Session 9 matrix.
- **AC-U04:** `UNKNOWN`, `UNAVAILABLE`, empty activity, and action failure do not
  use reassuring or alarmist false language.
- **AC-U05:** Real interactions, not screenshots alone, pass under canonical
  DMS/Labwc.

## Packaging and integration

- **AC-I01:** Locked source/dependencies build reproducibly with reviewed
  licenses, dependency inventory, and SBOM.
- **AC-I02:** RPM install/update/uninstall is clean, owns only declared Security
  Center files, and has safe ownership/modes.
- **AC-I03:** DMS discovers/launches the desktop entry without a DMS fork,
  configuration mutation, service restart, or Security Center placeholder.
- **AC-I04:** Installing/removing V0 does not enable/disable security services or
  modify DMS, Labwc, SELinux policy, firewalld policy, auth, PAM, greetd, boot,
  encryption, TPM, USB, or unrelated Settings.
- **AC-I05:** Startup/refresh/idle CPU, RSS, wakeups, latency, and storage meet
  thresholds recorded from representative VM/hardware measurements.

## Original V0 process record

These criteria describe the original ten-session bookkeeping model. They are
retained for traceability and do not define current project-wide release status.

- **AC-PR01:** Sessions 1–10 each have a PASS report satisfying their stop
  condition; the current evidence report must explicitly show `PASS` before
  V0 can be called `10/10`.
- **AC-PR02:** Product, threat model, capability matrix, architecture, privilege
  model, roadmap, execution plan, and acceptance have been contradiction-checked.
- **AC-PR03:** VM acceptance and every applicable available physical-hardware case
  have traceable dated evidence; missing required hardware evidence is a named
  release condition/blocker.
- **AC-PR04:** Uninstall and both V0 control rollback paths pass from the release
  candidate.
- **AC-PR05:** The Session 10 report records PASS or the specific evidence that
  was unavailable in that run.

## Explicitly not required for V0

- DMS posture widget/user monitor.
- Portmaster integration.
- Interactive application-aware connection prompts until their full lifecycle
  is proven; the admitted OpenSnitch visibility and typed policy surface are
  now part of the post-V0 Network Protection acceptance gate.
- USBGuard active authorization/policy.
- Rich, unrestricted event correlation/history or AI analysis. The bounded
  normalized telemetry history is governed by `docs/telemetry/` and does not
  make the Security Center V0 UI a generic log viewer.
- Sensitive Files classification/enforcement.
- High-Risk/Travel Mode.
- Advanced application policy or AI-mediated assistance.

Their absence cannot fail V0 and their partial implementation cannot compensate
for a failed V0 criterion.
