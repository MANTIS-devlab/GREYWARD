# GREYWARD internal alpha baseline

Status: **INTERNAL ALPHA — NOT A RELEASE APPROVAL**

The [10 October consolidation and storage assessment](history/migrations/2026-10-10-release-preparation.md)
is **NO-GO for ISO construction** pending exact new package receipts, a separate
adequately sized Fedora builder and the stated mandatory validation gates.
At that assessment, the source candidates were DMS 1.6.2-7, Center 90 / Context
82, and experimental runtime 33; that runtime was excluded from image inputs.
The 10 October AZERTY follow-up now requires a source-matched runtime RPM in the
alpha pipeline and installs it dormant. No ISO was built or approved; see the
[current status](STATUS.md) for the newer scope.

This document is the concise release-facing checklist for the current
GREYWARD repository. It does not replace the architecture, domain contracts,
or the [current status](STATUS.md).

## Current baseline

- Product base: Fedora with Labwc as the canonical compositor, Hyprland as an
  explicit fallback, DankMaterialShell (DMS) for the desktop shell/settings,
  and GREYWARD Security Center for GREYWARD-specific security and privacy.
- Installed-system source of truth: `environment/production/`.
- Internal installer source of truth: `environment/image/`, using direct Fedora
  Anaconda boot/netinst media. It is not a signed release pipeline.
- Development VM source: production plus the explicit
  `environment/development/` overlay. VM behavior is development evidence only.

## Required gates before a release claim

1. Build a candidate with the [ISO creation runbook](architecture/ISO_CREATION.md)
   and retain its base-media checksum, baseline, package manifests, and
   provenance sidecars.
2. Install that exact candidate on a clean test target, complete Anaconda
   account creation, first-boot finalization, and a reboot with the media
   removed.
3. Run `tests/production-acceptance.sh` against the installed production
   system and record failures as failures; a source or VM test is not a
   substitute for installed-image evidence.
4. Run the [Security Center acceptance checks](security-center/ACCEPTANCE.md)
   on the candidate and record Fedora, real-window, privacy, and image-artifact
   evidence.
5. Observe one offline update reboot, including the single Polkit prompt and
   Plymouth progress behavior, and verify that an ordinary reboot does not
   show update-mode status.
6. Complete the documented hardware/device acceptance for the target
   environment, then separately establish signing and provenance policy.

## Known limitations at this baseline

The clean-install/reboot path, intensive bare-metal and edge-case testing,
offline-update reboot observation, and graphical Polkit observation remain
incomplete as recorded in [STATUS.md](STATUS.md). The internal ISO
path is unsigned and hardware-unvalidated. The development VM is contaminated
with development access and must not be presented as production acceptance.

## Bug reports and evidence

Report one issue per defect through the project’s issue or maintainer handoff
channel. Include the exact candidate filename and SHA-256, Fedora base-media
checksum, captured baseline identifier, host/guest environment, command or UI
path, expected versus observed result, and relevant sanitized logs. Never
include `.secrets/`, credentials, private keys, or raw personal data. Mark
runtime observations as `DEVELOPMENT`, `PRODUCTION`, or `CLEAN INSTALL` so
evidence cannot be mistaken for another environment.

## Validation entry points

```powershell
pwsh -NoProfile -File .\tests\static.ps1
pwsh -NoProfile -File .\tools\validate-repository.ps1
```

Use the domain-specific commands in [docs/INDEX.md](INDEX.md) and
`security-center/README.md` for Security Center changes. A passing source
check does not establish VM, image, hardware, or release acceptance.
