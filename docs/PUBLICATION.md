# Public source maintenance

## Sophon 0.5.2 publication — 25 October 2026

[0.5.2 Sophon](patch-notes/0.5.2-sophon.md) is the latest public SourceForge
installer. The export also excludes historical machine-specific prototype settings,
while preserving the private original. Full SFTP readback verifies all
5,147,983,872 ISO bytes and SHA-256,
plus the ten source/provenance/checksum companions. The existing image was
uploaded without rebuilding. It includes Office revision 6, desktop presentation
and Bazaar Explore recovery, alongside the retained offline Polkit and lock fixes.
Clean-install, physical offline and recovery acceptance remain separate; the
Office public RPM update feed is not operational. Use the release's frozen
source archive and four Office source RPMs; public main is not that exact tree.

`main` is the only permanent public branch. Preserve unique work before
integrating and removing temporary branches. Check CI at the exact integrated
commit. Never force-push or rewrite public history without explicit approval.

The authoritative public-source boundary is `tools/publication-policy.json`.
`tools/public-export.py` copies a sanitized current-source snapshot without
private Git history or deletion of private originals. Templates provide public
counterparts to internal build-host and access procedures. Generic package,
installer, runtime, build and security-test sources remain public.
Export requires Gitleaks and refuses the candidate when its secret scan fails.

For updates, start from current public `main`, compare the snapshot against the
public checkout, preserve public-only release records, and remove only explicitly
excluded private material. Validate the candidate with the static, repository,
Python, frontend and Linux Rust checks before publishing. Review secrets and
private-path scans, executable file modes and component receipts. Preserve
configured commit signing. Initial export is distinct from updating existing
history; do not replace public history with a newly initialized repository.

ISO composition, clean installation, live desktop behavior and security/recovery
acceptance are separate evidence. Do not publish an unvalidated experiment as a
completed feature. See `AGENTS.md` for permanent maintenance obligations.

## Approved README gallery — 25 October 2026

The owner approved publication of the supplied screenshots, explicitly allowing
the visible Swiss VPN addresses. The [inventory](assets/screenshots/README.md)
records the eleven selected original PNGs and omitted one-pixel/near-duplicate
inputs. The existing overview GIF is unchanged. Legacy static images are
removed from this public tree; the engineering originals are preserved.
The export requires the current gallery and rejects missing image inputs.
This update covers presentation and attribution, with no ISO upload or change
to the public RC3 download.
