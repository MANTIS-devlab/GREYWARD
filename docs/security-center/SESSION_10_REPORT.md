# GREYWARD Security Center — Session 10 report

Status: **HISTORICAL VALIDATION BACKLOG** (original result: `BLOCKED`)

Date: 2026-08-27

This is a dated report from the original V0 validation sequence. It is retained
because its missing evidence remains useful, but it is not the current
project-wide release gate. It does not convert unavailable runtime evidence
into a pass.

Current status note (2026-08-30): a reachable internal-alpha Fedora VM is
available for diagnosis, but it is development-contaminated and does not
replace the clean/canonical `GREYWARD-DEV` runtime and installed-image evidence
listed by this report. Those checks remained unavailable in that environment.

## Evidence available in this workspace

| Check | Result | Evidence |
|---|---|---|
| Python Security Context tests | PASS | `61` tests, `14` skipped, `python -m unittest discover ...` |
| Frontend contract tests | PASS | `18` tests, `node --test security-center/tauri/frontend/ux-contract.test.mjs` |
| Rust build/tests/clippy on Fedora | BLOCKED | This session is on Windows; the available Cargo attempt cannot satisfy the Fedora toolchain/linker gate. |
| Real Tauri interaction suite | PASS for the bounded Network Activity trace | `tools/greyward-dev/run-security-center-interaction.ps1` uses Fedora `tauri-driver` + `/usr/bin/WebKitWebDriver`; other checks in this historical backlog remained open. |
| RPM install/update/uninstall/ownership | BLOCKED | No disposable Fedora package-test environment is available. |
| Network Activity with real traffic | PASS for the bounded interaction cluster | The 2026-09-01 remediation record contains the real Tauri WebDriver trace for pause/resume, filters, history, and Allow/Block rule cleanup. |
| File Security lifecycle | BLOCKED | Clean, detection, quarantine, restore, delete, unavailable, and cancellation paths require the Fedora runtime. |
| Recovery and Restic failure states | BLOCKED | Requires the installed Security Context and user-owned backup/recovery runtime. |
| Telemetry privacy and retention | BLOCKED | Static/unit evidence exists, but the installed runtime and retention exercise were not run in this gate. |
| Security Center startup/refresh/scroll/focus/filter/navigation | BLOCKED | Real-window evidence is still required; source contract tests are retained only as fast checks. |
| No remote requests during ordinary inspection | BLOCKED | Requires runtime network observation in GREYWARD-DEV. |
| Dependency/artifact traceability | BLOCKED | Recording hooks are implemented; exact image-resolved NEVRAs, COPR build IDs, Flatpak commits, and license/SBOM output require a Fedora image build. |

## Gate runner

Run the complete gate from Fedora or GREYWARD-DEV with:

```bash
bash security-center/tests/session10-gate.sh --report /path/to/session-10-run.md
```

The runner fails closed. Runtime evidence is supplied as explicit
`GREYWARD_SESSION10_*_CMD` commands; an omitted command is recorded as
`BLOCKED`, not skipped. The bounded real interaction test is:

```bash
node --test security-center/tauri/frontend/interaction.test.mjs
```

with the Fedora WebDriver environment supplied by
`tools/greyward-dev/run-security-center-interaction.ps1`; CDP is not required.

## Remaining release blockers

- Complete the Fedora Rust, RPM, and installed-image evidence.
- Recreate or otherwise provide a clean GREYWARD-DEV runtime and run real traffic, File
  Security, Recovery/Restic, telemetry, privacy, and UX interaction checks.
- Resolve and archive exact package, COPR, Flatpak, license, and bounded SBOM
  artifacts for the image under test.
- Re-run the full acceptance matrix and only then change this report to PASS if
  every required criterion has traceable evidence.
