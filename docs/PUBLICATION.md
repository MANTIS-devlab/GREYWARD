# Public source maintenance

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
