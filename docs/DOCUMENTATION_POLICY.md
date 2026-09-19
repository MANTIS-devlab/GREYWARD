# Documentation policy

## Canonical documents

Each current subject has one authoritative document. The authority is listed in
`docs/INDEX.md` and, for implementation-heavy subjects, in
`docs/REPOSITORY_MAP.md`. Other documents link to it instead of restating the
same current contract.

Canonical documents describe current behavior and supported boundaries. Update
them in the same change as a behavior, interface, path, package, or validation
change that affects their subject.

## Plans and history

- Active plans belong in the relevant domain directory and must state their
  status and what is not implemented.
- Completed session reports, migration records, screenshots, and rejected
  alternatives belong under `docs/history/`.
- Historical documents must say they are historical and must not be linked as
  current architecture or product specifications.
- Do not delete uncertain information. Consolidate unique current facts into
  the canonical document, then archive the evidence when it remains useful.

## New documentation

Start with `docs/INDEX.md` and choose the smallest existing domain. Add a new
directory or index only when it gives agents a real navigation boundary. Do not
create a second product contract, architecture description, UX specification,
or validation procedure for the same subject.

Use repository-relative Markdown links for repository files. If a historical
record names a removed path, label it as historical and do not use that path as
an executable instruction.

## Repository hygiene

Keep each change scoped to its task and preserve unrelated working-tree
changes. Do not overwrite, reset, or silently reformat unrelated files. Before
handoff, inspect `git status` and the relevant `git diff`, run the applicable
repository validation, and leave every touched area at least as clear and
understandable as before.

## Completion rule

A structural or implementation change is incomplete until its canonical docs,
repository map, tests, and validation commands agree with the resulting tree.
Run `tests/static.ps1` before handoff.

## Context-limited agent rule

Every major implementation area must be discoverable from one row in
`docs/REPOSITORY_MAP.md`. That row names one current authority, the smallest
useful test entry point, and the validation command. Keep the domain README
short enough to orient a new agent; put detailed contracts in the named
canonical document and put dated evidence under `docs/history/`.

When state changes, update the smallest set of truth documents together:

1. implementation or configuration source;
2. canonical domain contract or status, when behavior/state changed;
3. repository-map row, when ownership/path/tests/commands changed;
4. tests or validation, when the contract can be checked automatically.

Do not make an agent infer current truth from commit history, screenshots,
generated output, or a completed plan. Use explicit labels such as
`IMPLEMENTED`, `PLANNED`, `DEFERRED`, `HISTORICAL`, and `BLOCKED`.
