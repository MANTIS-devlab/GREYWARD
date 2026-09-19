# Contributing to GREYWARD

GREYWARD welcomes implementation, design, security, hardware, and usability
review. You do not need to understand the whole OS to improve one bounded
subsystem.

## Choose a contribution path

### Report a bug

Report concrete incorrect behavior with the commit/image, environment, steps,
expected result, observed result, and safe logs. Use the bug form, or the
hardware form when a device/driver/firmware combination matters.

### Challenge an assumption

Open a design challenge when you believe the architecture is wrong, a security
assumption is invalid, the usability cost is unjustified, an upstream mechanism
would be better, or a GREYWARD-specific feature should not exist. State the
property being challenged, current evidence, consequences, and a better
alternative if known. Existing decisions are not sacred.

### Improve an implementation

Changes that preserve intended behavior while reducing code, authority,
duplication, or maintenance cost are valuable. Replacing custom code with a
well-supported upstream mechanism can be better than adding another subsystem.

### Improve UI or UX

GREYWARD has a strong visual direction, not a frozen set of pixels. Changes are
welcome when they improve usability, consistency, accessibility, interaction,
responsiveness, information hierarchy, or visual polish while retaining the
restrained GREYWARD identity. Include before/after evidence and test keyboard,
focus, scaling, and narrow-window behavior where relevant.

See [areas for review](docs/contributing/AREAS_FOR_REVIEW.md) for concrete
subsystems that benefit from external expertise.

## Find the owning boundary

| Change | Start here | Primary validation |
|---|---|---|
| Production package/policy | `environment/production/` | static checks and installed acceptance |
| Image/installer | `environment/image/` | image Python tests, stage/media validation, clean install |
| Desktop/session | `environment/session/`, DMS patches | static checks and real Wayland session |
| Security posture/backend | `security-center/crates/` | Rust fmt/test/Clippy |
| Security Context/service | `security-center/security-context/` | Python tests plus installed D-Bus/systemd checks |
| Security Center UI | `security-center/tauri/frontend/` | Node tests plus real WebKit/Wayland interaction |
| Packaging | `packaging/`, `security-center/packaging/` | RPM build/install and file contract |
| Branding | `branding/source/`, generator/manifest | branding validation and affected boot/session surface |

Search references before changing a path. Keep one implementation source of
truth and update the smallest owning document rather than copying explanations.

## Change requirements

- Separate current fact, intended direction, assumption, and unverified claim.
- Keep development-VM evidence distinct from installed-image and bare-metal
  evidence.
- Do not weaken a security boundary just to make a workflow or test pass.
- Add a regression test for behavior changes where practical.
- For privileged code, document caller, input validation, authorization,
  mutation, verification, failure, and rollback.
- Preserve unrelated work in the shared worktree.
- Keep credentials, personal paths, host identifiers, VM state, captures, and
  unreviewed logs out of commits.
- Explain tests not run and why.

Open a design discussion before changing the threat model, privilege boundary,
production package set, installed desktop model, crypto policy, image trust
model, or public licensing.

## Validation

```powershell
pwsh -NoProfile -File .\tests\static.ps1
pwsh -NoProfile -File .\tools\validate-repository.ps1
```

Security Center changes also require the applicable commands in
[TESTING.md](TESTING.md). Runtime-sensitive changes need evidence from the
environment they affect; hosted tests cannot validate hardware, SELinux,
Wayland, firmware, installation, or recovery.

## Security reports

Follow [SECURITY.md](SECURITY.md) for vulnerabilities. Do not put exploit
details, secrets, personal data, or sensitive logs in a public issue before a
private channel exists.

## Licensing

By contributing, you agree that GREYWARD-authored source/documentation
contributions are provided under `GPL-3.0-only` unless explicitly agreed
otherwise. Do not submit third-party code, fonts, artwork, icons, or branding
without source, license, provenance, and redistribution terms.

Designated GREYWARD identity assets are reserved branding under
[LICENSING.md](LICENSING.md) and [branding/LICENSE](branding/LICENSE).
Third-party visual material retains its own terms. A GPL code contribution does
not grant permission to present a fork as an official GREYWARD product.
