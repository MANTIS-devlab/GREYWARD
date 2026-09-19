# GREYWARD agent contract

GREYWARD is a Fedora-based desktop distribution and Security Center project.
Do not redesign product behavior or treat the disposable development VM as a
release image.

Start with:

- [docs/INDEX.md](docs/INDEX.md) for the documentation entry point;
- [docs/REPOSITORY_MAP.md](docs/REPOSITORY_MAP.md) for feature ownership;
- [docs/STATUS.md](docs/STATUS.md) for what is true now versus planned work.

Canonical implementation boundaries:

- `environment/production/` defines the installed system;
- `environment/development/` and `tools/greyward-dev/` are development-only;
- `security-center/` contains the Security Center and Security Context code;
- `packaging/` contains installable package definitions;
- `branding/` contains canonical visual sources and generated assets;
- `tests/` and `tools/` contain validation and development checks.

Before changing a path, search all references with `rg`. Keep one canonical
source per current behavior, update its documentation and map entry, and mark
historical evidence as historical instead of presenting it as current.

Keep Git changes scoped and never overwrite unrelated work. Before handoff,
inspect `git status` and the relevant `git diff`, run the applicable validation,
and leave every touched area at least as clear and clean as before.

Essential checks:

```powershell
pwsh -NoProfile -File .\tests\static.ps1
pwsh -NoProfile -File .\tools\validate-repository.ps1
```

For Security Center changes, also use the commands in
[`security-center/README.md`](security-center/README.md). Do not claim a VM,
image, hardware, or release check passed unless it was actually run.

Completion means the scoped change works, relevant tests pass, documentation
and repository map entries are updated, and no obsolete path or instruction was
introduced. See [`docs/DOCUMENTATION_POLICY.md`](docs/DOCUMENTATION_POLICY.md)
for the detailed repository-maintenance rules.
