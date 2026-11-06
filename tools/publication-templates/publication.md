# Public source maintenance

## Sophon 0.5.5 publication — 6 November 2026

The existing [0.5.5 Sophon ISO](patch-notes/0.5.5-sophon.md) and ten companions
are published on SourceForge. Full SFTP readback verifies all 5,388,173,312
ISO bytes against SHA-256
`6175a18609bb41bdf3f3c12b7c1aabef38c63ea17ad2dec7ec96331d796d2092`,
plus the frozen corresponding sources, four signed Office generation-16 source
RPMs, manifest, verification, release notes and checksums. Strict host-key and
TLS checks remain enabled. The final ISO filename was exposed only after
verification. No ISO was rebuilt for publication.

The source archive contains 5,295 project files with original/published hashes,
source origins, executable modes and all fifteen selected RPM inputs. Its SHA-256
is `f42437f21d3421d538d0c7fee54ce77104303e97e2c0013014cab3e0cfd9bce1`.
It retains the exact validated Center/Context 137 build source; private history,
credentials and host configuration are excluded and documentation is sanitized.
No non-document source bytes change from their recorded origins.
The README gallery and GIF are unchanged.

Use the frozen archive for this image; public main can contain later changes.
Complete clean-install, encrypted-root/recovery and hardware acceptance remain
separate. The previously reported Bazaar Explore recurrence has no confirmed
durable correction in this release.

## Historical Sophon 0.5.4 publication — 2 November 2026

The existing [0.5.4 Sophon ISO](https://github.com/MANTIS-devlab/GREYWARD/blob/main/docs/patch-notes/0.5.4-sophon.md) and ten companions
are published on SourceForge. Full HTTPS readback verifies all 5,267,587,072 ISO
bytes against SHA-256 `7ddb5a378a26138b8349f3fd5bcd42bc479c144417d07248a2ab572ac2fdd959`,
plus the frozen corresponding sources, four signed Office source RPMs,
manifest, verification, release notes and checksums. Strict host-key checking
remains enabled. The final ISO filename is exposed only after these checks.
No ISO was rebuilt for publication.

The source archive contains 5,278 files, an input/hash/mode inventory and exact
validated Security Center build bytes. No non-document source bytes were changed
by sanitization. The archive SHA-256 is
`5712a72eea930c9b0bceaf3ec1935e77134abde731144ee5c054f9acfd4802d1`.
Use that frozen archive for this ISO; public main is not necessarily the same
runtime source revision. The README gallery and GIF are unchanged.

Bazaar Explore's installed recurrence remains a known issue, not a claimed fix.
Composition, media readback, full clean-install/recovery and physical hardware
acceptance are separate; publication does not establish the untested checks.

## Historical Sophon 0.5.3 release — 28 October 2026

[0.5.3 Sophon](https://github.com/MANTIS-devlab/GREYWARD/blob/main/docs/patch-notes/0.5.3-sophon.md) supersedes the preceding public
download. Its ISO, checksums, provenance, frozen corresponding sources and four
signed Office source RPMs are published together. The existing ISO is reused;
its exact SHA-256 and composition limits remain in the release notes. The
public code update contains the matched release fixes and active GitHub Office
channel, while preserving public-only release/gallery records and the GIF.
Clean-install, recovery and physical acceptance remain separate from publication.

## Historical Sophon 0.5.2 publication — 25 October 2026

[0.5.2 Sophon](https://github.com/MANTIS-devlab/GREYWARD/blob/main/docs/patch-notes/0.5.2-sophon.md) was the public SourceForge
installer at that publication. The export also excludes historical machine-specific prototype settings,
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
the visible Swiss VPN addresses. The [inventory](https://github.com/MANTIS-devlab/GREYWARD/blob/main/docs/assets/screenshots/README.md)
records the eleven selected original PNGs and omitted one-pixel/near-duplicate
inputs. The existing overview GIF is unchanged. Legacy static images are
removed from this public tree; the engineering originals are preserved.
The export requires the current gallery and rejects missing image inputs.
This update covers presentation and attribution, with no ISO upload or change
to the public RC3 download.
