# Public repository publication

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

Before adding a remote, review the resulting one-commit repository with a
secret scanner appropriate to the hosting organization and inspect its staged
file inventory. Publish only the new repository. Keep this private engineering
repository and all of its refs local; deleting a branch or making a shallow
clone is not sufficient history removal.
