# Public repository publication

The clean public checkout is `F:\GREYWARD-public`, with remote
`https://github.com/MANTIS-devlab/GREYWARD.git`. Update that checkout from the
validated current source tree; never merge or push engineering repository refs
into it. Preserve unrelated public-only files and release records, stage only
reviewed source changes, retain executable script modes, and scan the candidate
for secrets before committing and pushing. The initial-export procedure below
applies when creating a new public checkout, not to subsequent commits in the
existing clean public history.

The existing local repository is an engineering record, not a publication
artifact. Earlier commits contain development-only credentials and workstation
identifiers that were removed from the current tree but remain recoverable from
Git history. Do not add a public remote to this repository, push any of its
refs, or publish a bundle made from it.

Create a new, unrelated Git repository from the validated current tree:

```powershell
pwsh -NoProfile -File .\tools\export-public-repository.ps1 `
  -Destination 'F:\GREYWARD-public' `
  -AuthorName 'MANTIS SYSTEMS' `
  -AuthorEmail 'public-contact@example.org'
```

Use the project's real public contact address in place of the example. The
command refuses a destination inside this working repository, refuses a
non-empty destination, runs both repository validation gates, copies only the
current Git publication candidate (tracked plus non-ignored untracked files),
preserves tracked executable bits, restores executable mode for shebang scripts
from Windows checkouts, and creates one new root commit. Ignored
credentials, build outputs, VM disks, caches, and the private `.git` directory
are not copied.

For an update to the existing public checkout, preserve its configured commit
signing. If the signing key cannot unlock, stop with the reviewed index intact;
do not disable signing or rewrite configuration merely to complete publication.
The [10 October consolidation receipt](history/migrations/2026-10-10-release-preparation.md)
records such a signing-authentication block: no commit or push was created.

Before adding a remote, review the resulting one-commit repository with a
secret scanner appropriate to the hosting organization and inspect its staged
file inventory. Publish only the new repository. Keep this private engineering
repository and all of its refs local; deleting a branch or making a shallow
clone is not sufficient history removal.
