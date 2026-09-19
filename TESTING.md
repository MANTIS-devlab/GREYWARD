# Testing GREYWARD

## Development context

Most GREYWARD code has been produced with AI coding agents, and the maintainer
is not a professional software developer or security researcher. That is a
material review risk, not a credential to obscure. Generated code can be
plausible while encoding a wrong assumption, duplicating an upstream mechanism,
or passing tests that only restate its implementation.

GREYWARD compensates with deterministic tests, small privilege boundaries,
static analysis, runtime checks against authoritative providers, reproducible
artifacts, and an explicit invitation to external human review. None of those
turn test quantity or public source into proof of correctness.

## Validation inventory

| Class | Automation | What it establishes | What it does not establish | Current evidence |
|---|---|---|---|---|
| Repository/static | `tests/static.ps1`, `tools/validate-repository.ps1` | file contracts, references, packaging metadata, forbidden development leakage, branding consistency | runtime behavior or security | automated; Windows/PowerShell |
| Rust | fmt, workspace tests, Clippy with warnings denied | domain evaluation, typed snapshots, provider parsing/control logic, compile/lint health | real Fedora D-Bus/provider behavior | automated source tests |
| Python Security Context | unittest discovery under `security-context/tests` | policy validation, update/file/recovery state machines, DNS/VPN cases, service-hardening assertions | installed permissions, SELinux behavior, hardware | automated source tests |
| Frontend | Node test files under `tauri/frontend/` | escaping, routes, interaction contracts, startup/performance budgets | real WebKit/Wayland rendering by itself | automated source tests |
| Image builders | `tests/test_image_*.py`, stage validators, payload checksums | deterministic staging, offline resolution/installability, manifest and media consistency | successful install/reboot on arbitrary hardware | automated source/build-host tests |
| RPM packaging | spec/source validation and RPM build/install workflows | file ownership, dependencies, buildability, package contract | service behavior after install unless runtime checks run | partly automated; Fedora builder required |
| Installed acceptance | `tests/production-acceptance.sh`, `tests/guest-acceptance.sh` | expected packages, units, policy, artifacts, encryption and session prerequisites on the tested system | portability beyond that system | runtime-only |
| Security Center integration | `security-center/tests/session10-gate.sh`, D-Bus and WebDriver workflows | installed provider/UI behavior for the exercised scenario | all failure ordering, malicious peers, or hardware diversity | Fedora runtime/VM; not suitable for generic CI claims |
| Development VM | `tools/greyward-dev/` health, graphics, deploy, capture, and image tools | repeatable development regression environment | release image or bare-metal acceptance | VM-only |
| Bare metal | manual use and issue evidence | actual driver, firmware, power, display, install/update/recovery behavior | untested hardware | no complete durable matrix currently recorded |

## Commands

Repository checks:

```powershell
pwsh -NoProfile -File .\tests\static.ps1
pwsh -NoProfile -File .\tools\validate-repository.ps1
```

Security Center source checks on Fedora:

```bash
cd security-center
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
PYTHONPATH=security-context python3 -m unittest discover -s security-context/tests -p 'test_*.py'
npm --prefix tauri ci
node --test tauri/frontend/interaction.test.mjs
node --test tauri/frontend/startup.test.mjs
node --test tauri/frontend/performance.test.mjs
node --test tauri/frontend/ux-contract.test.mjs
```

Image-source tests:

```bash
python3 -m unittest tests.test_image_baseline tests.test_image_offline tests.test_image_stage_text
```

Installed and UI commands require the Fedora packages and environment described
in `security-center/README.md`. Report the exact environment and do not replace
an omitted runtime check with a source-test claim.

## CI boundary

`.github/workflows/source-validation.yml` runs checks suitable for hosted
runners. It labels them as source validation. It does not claim to validate
Wayland interaction, D-Bus policy on the installed image, SELinux confinement,
firmware, networking, installation, encryption, suspend/resume, or recovery.

## Evidence rules

- Record command, commit, OS/package versions, and result.
- Distinguish synthetic fixture, hosted CI, development VM, installed image, and
  physical hardware.
- A mocked provider proves consumer behavior, not provider integration.
- A successful path does not cover rollback, cancellation, timeout, restart, or
  partial failure.
- A visual screenshot proves only the displayed state at that time.
- A ClamAV clean result means no configured signature matched; it does not prove
  the file safe.
- Flaky or environment-dependent failures must be retained as evidence until
  their cause is understood.

## Missing high-value validation

- independent privilege-boundary and threat-model review;
- broad bare-metal matrix and longer daily use;
- multi-VPN, split-DNS, roaming, and provider restart fault injection;
- update power-loss and partial-provider recovery;
- backup restore drills to a clean system;
- installer failure and repeated first-boot recovery;
- accessibility and multi-display testing;
- crypto-policy generated-backend/compatibility matrix;
- fuzzing of snapshot, JSON D-Bus payload, and external-provider parsers;
- reproducible-build comparison and stronger supply-chain verification.

Public source makes weaknesses inspectable. Reviewers should be able to
demonstrate a faulty test, implementation, or architecture and replace it with
something better.
