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

## Local Git maintenance and approval-gated publication

`main` is the only permanent public branch. At the start of each task, inspect
the worktree, fetch current remote refs, inspect open PRs and CI, and reconcile
the task with already integrated changes. Preserve unrelated edits and unique
unmerged work, including other worktrees. Never use destructive reset, force
push or public-history rewriting without explicit user authorization.

After relevant validation, autonomously commit useful scoped changes locally
and preserve unmerged work. Public actions require the user's explicit approval
for the current task: do not push branches, open/edit/close pull requests, merge,
delete remote branches, or publish tags/releases without that approval. Preparing
and auditing a local public export does not authorize sending it to GitHub.
Read-only fetches and CI/PR inspection remain permitted. When publication is
approved, use the reviewed public-export boundary, retain all checks, and report
CI failures honestly; never disable checks to obtain a green result. Remote
cleanup is also approval-gated. Preserve unpublished work when approval is absent.

The development repository is not a publication source to push wholesale.
Audit the export before publishing: exclude private build-host configuration,
internal accounts, credentials, private ISO-factory infrastructure, sensitive
captures, internal logs and development-only administration procedures.
Retain generic public installation/runtime/build/audit components. When a
necessary component includes private details, publish a sanitized counterpart.
Removing a file from the public export must never delete the private original.
Maintain export safeguards and regression checks against renewed exposure.

Audit completeness against validated component sources, RPM revisions, DMS
receipts, dependency manifests and current public branches. Preserve functional
validated versions rather than automatically publishing the newest experiment.
Keep unsupported features and missing installed/hardware/recovery validation
explicit; ISO composition does not prove clean-install or security acceptance.

Before handoff, verify public file closure, relevant static/Python/Rust/frontend
and repository contracts, remote CI results, secrets/private-file exclusions,
tags/releases/download documentation, and local/remote Git synchronization.
Record unavailable checks honestly and preserve critical project files. These
rules authorize routine local Git maintenance only. Public publication requires
explicit user approval; these rules do not authorize changing a running VM or
publishing an ISO release.
