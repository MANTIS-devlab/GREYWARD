# GREYWARD Office integration

Status: the initial integration was accepted on 25 October 2026. Generation 9
completed the real GitHub build/sign/public DNF pipeline on 27 October. The
signed remote channel is active on the reference; installed Office applications
remain at revision 6 until the user applies an update. See the separate
acceptance records below; this is not a full Office-format compatibility claim.

## Ownership and identity

`packaging/greyward-office/source.json` is the version/provenance authority.
`packaging/greyward-office/` owns source preparation, the shared RPM recipe,
reviewed per-application patches, signing preparation and update-candidate checks.
The four independent applications have no suite launcher:

| Upstream stable release | GREYWARD | Package | Desktop / Wayland identity |
|---|---|---|---|
| WordCraft 0.11.0 | Writer, blue | greyward-writer | systems.mantis.greyward.Writer |
| GridCraft 0.12.1 | Sheets, green | greyward-sheets | systems.mantis.greyward.Sheets |
| PdfCraft 0.14.0 | PDF, red | greyward-pdf | systems.mantis.greyward.PDF |
| DeckCraft 0.11.1 | Slides, copper | greyward-slides | systems.mantis.greyward.Slides |

This table describes the published generation-9 source lock from 27 October, not
the historical revision-6 packages included in 0.5.2. Installed and channel
acceptance is recorded below; updating a source pin alone is not deployment.

The application SVG family is `branding/source/greyward-{writer,sheets,pdf,slides}.svg`:
coordinated graphite tiles with independent blue, green, red and copper marks.
Librsvg renders the embedded window and launcher/dock PNGs from those sources.
The former revision-5 artwork is retained byte-for-byte as
`greyward-{writer,sheets,pdf,slides}-document.svg`. It belongs to documents rather
than application launchers. Both families are original GREYWARD artwork.

Revision 6 installs the document vectors under unique MIME icon names in both
Greyward and hicolor. The Greyward alias prevents the theme's generic file icon
from winning over hicolor during GTK's fallback lookup. The shared
`artwork.py` generates icon metadata for exactly the same 21 supported MIME
types as the launchers. Original Sheets/Slides detection rules are retained,
including the native `.deckcraft` glob. The hash-locked upstream XML is also
retained as provenance; the installed derived XML is reproduced and checked.
No default application, file association, document engine or thumbnail preference
changes. Unsupported PPT/ODP remain outside the Slides assignment.

Upstream repositories: [WordCraft](https://github.com/storytold/wordcraft),
[GridCraft](https://github.com/storytold/gridcraft),
[PdfCraft](https://github.com/storytold/pdfcraft),
[DeckCraft](https://github.com/storytold/deckcraft).
The software is MIT OR Apache-2.0; upstream separately restricts its trademarks.
Modified builds replace graphical marks and visible product identity, retain
copyright/contributor credits, ship upstream and bundled dependency/font notices,
and explicitly attribute their source without claiming official ArtCraft status.

## Thin customization and security

Patches affect the native entry point and UI crate, not document engines or
format implementations. They set window identities, visible product titles,
first-run dark defaults and graphite/silver chrome accents. Document, cell and
slide colors remain upstream. Existing application preference paths and saved
theme selections are retained; no login-time preference overwrite is added.
PDF's manual update action opens the existing Security Center `updates` route.
The other applications do not acquire an additional updater.

There is no AI configuration, MCP service, autostart task or privileged Office
helper. Normal launchers clear inherited upstream control-port environment
variables; no control flag is passed. Upstream CLI tools are compiled for engine
tests only and are not installed in the RPMs. Runtime listener observation and
ordinary-session/protected-data tests are distinct acceptance checks. No broad
SELinux permission is introduced by this integration.

## Building and provenance

Use an unprivileged Fedora 44 builder with the manifest's private Rust toolchain.
The sequential entry point verifies the Rust/Cargo version before building.
The toolchain archive, source archives, Cargo lockfiles, each release's exact
craft-fonts resource, adapted input files, patches, build recipe and SVG sources
are SHA-256 locked. `prepare.py` checks them before applying the exact patch.
An incompatible input fails; there is no fuzzy text replacement.

Run `build-all.py` in an isolated unit with `User` set to the build account,
`Nice=10`, `MemoryMax=8G`, `CPUQuota=400%`, a private temporary directory and
writable build/cache directories only. Its four builds run sequentially, each
with `CARGO_BUILD_JOBS=2`. Build dependencies include gcc-c++, ALSA/fontconfig/
xkbcommon development headers, Git, librsvg tools, Python and rpm-build. These
are factory requirements, never new ISO runtime dependencies.

```sh
python3 packaging/greyward-office/build-all.py --repo "$REPO" \
  --cache "$INPUT_CACHE" --output "$NEW_BUILD" --target "$CARGO_TARGET"
python3 packaging/greyward-office/verify-inputs.py --repo "$REPO" \
  --rpm "$WRITER_RPM" --rpm "$SHEETS_RPM" --rpm "$PDF_RPM" --rpm "$SLIDES_RPM"
```

Cargo vendors the locked dependency graph before RPM compilation. The SRPM
contains adapted source, fonts, vendored sources/checksums and notices. The RPM
build itself uses `--locked --offline`. Receipts bind the integration sources,
input manifest and packaged launcher, binary, desktop entry and artwork bytes.
Private caches and Rust toolchains stay outside the installed payload.
Keep the source checkout read-only to the build account and outside the unit's
writable output/cache paths. Run promotion checks from a separately trusted
canonical copy, never by importing a script from an unprivileged build output.
The RPM gate rejects scriptlets, file capabilities, unexpected installation
paths, writable or special-mode files and ownership other than root.

Future image staging takes four `--office-rpm FILE` arguments in addition to
the eight pre-existing GREYWARD components. Complete staging, offline resolution and final media extraction reject
absent/stale Office inputs. Installed acceptance checks the four package
file sets with `rpm -V` and requires their direct launchers. The staged `office-source/` is a generic source/verification snapshot,
not a cache or a development account. The actual production package list and
MIME defaults are canonical; future defaults replace Collabora and Papers.
On the reference, removal was performed after the user accepted the replacements;
other installations must retain that acceptance gate.

The source and RPM gates bind application and document artwork separately and
reject missing document vectors, theme aliases or MIME definitions. RPM can
encode identical theme/hicolor vectors as newc hard links; the payload reader
selects the corresponding inode/device group before validating the bytes.
Run `python3 -m unittest tests.test_office_integration` and the opt-in
`python3 tests/fixtures/office-mime-icons-native.py --repo "$REPO"` for native
GIO/GTK resolution in a disposable MIME database. That fixture changes no user
or system settings and does not establish graphical acceptance by itself.

## Files and limitations

Strata remains the normal file manager. Browser/HTML, plain text, mail and image
defaults remain unchanged. Writer owns supported Word/ODT/RTF documents, Sheets
XLSX/XLS/CSV/ODS, PDF owns PDF, Slides owns PPTX and its supported OOXML variants.
The native `.deckcraft` MIME type is retained with the Slides icon; the
upstream Sheets/Slides MIME definitions are installed and hash-checked.
Legacy PPT and ODP are deliberately unassigned. `migrate-associations.py` removes
only retired Collabora/Papers handlers, retaining unrelated user choices.

These young applications do not promise Microsoft Office/LibreOffice fidelity.
Use copies for compatibility tests. Legacy DOC/XLS imports and complex documents
can lose information. Sheets ODS import is limited to the upstream data-oriented
path; do not promise formula/style/object fidelity or a lossless ODS round trip.
Slides does not establish support for PPT/ODP. No macro execution capability is
added. Preserve observed limitations with the acceptance record.

## Updates and publication boundary

`check-updates.py --repo REPO --output NEW-REPORT.json` checks the four official
GitHub stable release feeds without changing the lock or downloading executables.
It compares semantic versions, ignores drafts/prereleases and refuses unverified
release ownership or publication times. Exit 0 means the reviewed source pins
are current, 2 means a newer stable release exists, and 1 means verification is
incomplete. Network failure is never reported as up to date. This is maintainer
discovery, not evidence that a user's installed package or the public RPM feed
is current.

The read-only `Office upstream releases` workflow is now a manual diagnostic.
Its former unpublished six-hour schedule is retired in source. A newer release
or failed check fails the run and retains its JSON report. It has no signing
credentials, write permissions or publication authority. The separate
[six-day GitHub chain](#six-day-github-automation) owns automatic distribution;
its commissioning state is recorded below.

The normal DNF5 provider in Update Center owns package updates and its existing
authorization flow. Its system-RPM path prepares an offline transaction and
requires a restart; Office does not add a separate live updater. A full Update
Center apply/restart acceptance therefore needs separate permission to interrupt
the active reference session. Neither the applications nor this package set adds a new
privileged updater. A stable upstream release becomes a GREYWARD release only
after a reviewed rebuild and acceptance, rather than by installing its official
unmodified RPM over the GREYWARD package.

The launcher-like discovery step therefore precedes a validated GREYWARD rebuild.
Update Center offers the latest **published, validated GREYWARD RPM**, not an
unreviewed upstream binary. An ArtCraft release alone does not populate DNF.
The former disabled local acceptance repository was the reason revision-6
installations received no Office version upgrades. The runtime needs the signed
Office repository, its independently pinned public key and refreshed metadata.
The repository is restricted with `includepkgs` to the four Office packages;
unrelated system packages cannot be supplied by that channel.

`prepare-update.py APPLICATION VERSION --repo REPO --output NEW-CANDIDATE.json`
checks a published non-prerelease tag, resolves its immutable commit and refuses
changed adaptation or font inputs. It prepares a candidate, never activates it.
For a changed UI source, rebase and review the thin patch explicitly, record new
input hashes, then build/test the candidate in a separate source checkout. After
acceptance, promote the lock into the canonical manifest and rebuild; input drift
must not reuse a published NEVRA. `rpmRelease` is a monotonically increasing
shared generation, including when one upstream version changes; resetting it
would downgrade the three unchanged siblings. The candidate tool refuses equal
or older upstream versions. Increment the generation for downstream changes too.

`repository.py` first verifies the complete four-package family against its
source lock, then copies and signs the RPMs, creates repository metadata,
signs `repomd.xml` and exports the public key. It never imports a host key, enables
a repository or uploads files. Supply an independently verified full signing-key
fingerprint and a private GNUPGHOME. Test keys are not production keys.

```sh
python3 packaging/greyward-office/repository.py --repo "$REPO" --gnupg-home "$SIGNING_HOME" \
  --fingerprint "$REVIEWED_FULL_FINGERPRINT" --output "$NEW_REPOSITORY" \
  --rpm "$WRITER_RPM" --rpm "$SHEETS_RPM" --rpm "$PDF_RPM" --rpm "$SLIDES_RPM"
```

With the preceding generation installed, the opt-in native fixture
`tests/fixtures/office-repository-native.py` runs real DNF transaction tests in
disposable RPM roots cloned from the installed SQLite database. It validates the
four signed upgrades, then trusted metadata containing a Writer RPM signed only
by an untrusted disposable key. The installed reference, host trust and desktop
are not changed. Provide `--repository`, `--signing-home`, `--fingerprint` and a
fresh private `--output` under `/var/tmp`; run as root on the Fedora builder.
Its negative repository/key are acceptance artifacts and must never be published.
This does not replace a real Update Center snapshot or an approved apply/reboot
readback on the reference.

The former SourceForge Office layout was never activated. The prepared
`greyward-office.repo.in` now uses the GitHub distribution repository's stable
mirrorlist. Only after signed publication and native readback may the installed
template be activated. Keep `gpgcheck=1` and `repo_gpgcheck=1`; a missing/invalid
signature must fail. Production activation remains separate from publishing
the automation's source or running a build pilot.

`channel.json` is the separate distribution-approval policy. Its public-key
SHA-256 pins `keys/RPM-GPG-KEY-greyward-office.gpg`; the prepared production key's
fingerprint is `35BD325945F35957C77C4CEAE9708C265A840E6C` (expires 26 October
2028). It is separate from the original disposable acceptance key. The public
certificate now includes the dedicated CI signing subkey
`3DE850CC348820672C30C215F6CAE1AFF90E3A62`, expiring 27 October 2027; its pinned
SHA-256 is `d8e947e08b9752b0a14b11a431acbfe1701469aa4c8d3ae570eeb332affbde40`.
The primary secret key and restricted backup stay outside GitHub and build jobs.
Only a secret-subkey export with a stubbed primary is provisioned to the
`office-signing` GitHub environment, restricted to `main`, with no per-release
reviewer requirement. The gate refuses a certificate/subkey expiring within
30 days. The existing primary trust anchor and older signatures remain valid.
Key renewal/rotation requires review and a new pinned public-key hash; do not
silently trust a key downloaded alongside an unverified repository.

`stage-channel.py` validates the pinned key and the exact restricted DNF template.
With `published: false` it stages nothing. After publication approval, complete
remote readback and key verification, set that flag to true in a scoped reviewed
change. `environment/image/build.sh` copies the policy/key/tool into the Office
source snapshot. `build-offline.py` stages the enabled repository and public key
only into **future installed update configuration**, using the production
provisioner's existing `offline/update-repos` and `offline/keys` paths. It does
not add that remote feed to offline image dependency resolution, which continues
to require the four exact hash-verified Office RPMs. Preparing this route does
not constitute an ISO build or a working public channel.
The production offline builder uses `--require-published` and refuses to build
an image with an unpublished channel. Composition checks the exact installed
repository/key bytes before packaging and again after extracting the final media.
An old cached payload without Office updates must fail these checks; the next
ISO cannot silently reproduce the missing-repository defect.

For each promotion:

1. Run stable-release discovery and inspect the official release/immutable tag.
   Rebase any changed UI inputs explicitly; preserve new upstream functionality
   and retained saved-theme preferences. Lock source, fonts/resources and notices.
2. Increment the shared RPM generation, rebuild all four packages sequentially,
   verify the canonical source/payload closure and run the real-engine copy tests.
3. Create a fresh signed repository with the independently verified production
   key. Verify metadata and RPM signatures through real DNF, including rejection
   of a tampered package, and verify Update Center's four upgrade candidates.
4. Keep rollback RPMs. Supply corresponding source RPMs and notices beside the
   new binaries. Upload immutable package/source files first, then metadata files,
   switching `repomd.xml` and its signature last. Clients must fail closed during
   an inconsistent switch; refresh/retry after publication, never disable GPG
   checks. Read back all files and compare the sealed SHA-256 inventory.
5. Only then approve activation of the future-image policy and reference remote
   repository. Recheck DNF and the real Update Center service after refresh.
   Applying its existing offline transaction/restarting the reference requires
   approval to interrupt the session. Record the actual installed versions and
   post-boot transaction readback separately from discovery/build evidence.

## Six-day GitHub automation

**ACTIVE; first complete generation verified, 27 October 2026.** The owner approved
implementation after reviewing the design. The public component repository is
[GREYWARD-office-updates](https://github.com/MANTIS-devlab/GREYWARD-office-updates).
Its publication policy starts disabled; pilot runs build/test without signing or
publishing packages. GitHub source publication does not mean the DNF channel is
operational. The reference retains its local feed and installed applications;
no desktop interruption or ISO build is part of this commissioning step.

### Cadence and durable state

- A cheap hourly Actions wake-up, off the hour, reads durable scheduling state.
  Expensive discovery/build work is due once per **144-hour cycle**, anchored
  to an activation epoch in UTC. Do not use a day-of-month `*/6` cron: it resets
  each month and does not express six elapsed days. The hourly job exits early
  otherwise; it does not build or upload an artifact every hour.
- Store the epoch, last completed cycle and last successful publication in a
  small versioned state document in the distribution repository, not a cache
  that GitHub can evict. A complete no-change upstream check completes a cycle
  without creating another release. Network failure is incomplete, not current.
- After an outage, inspect the latest stable releases once; do not replay every
  missed cycle or publish intermediate versions. Permit one bounded retry per
  day after a failed heavy build; preserve failure state and avoid hourly builds.
  Manual dispatch can request an earlier check for a critical upstream fix.
- Serialize discovery/promotion/cleanup per Fedora/architecture with
  `cancel-in-progress: false`; record the promoted generation idempotently.
  A restarted job reconciles remote state before uploading or deleting anything.
  Do not advance the cycle checkpoint until discovery is complete and any due
  generation is promoted; no-change checks checkpoint immediately. Failed jobs
  stay visible in Actions, with no all-clear claim while a newer upstream release
  remains blocked. Notifications follow GitHub account preferences; a separate
  deduplicated maintainer notifier is not implemented.
- GitHub schedules are best effort, can be delayed/dropped and can be disabled
  after 60 days of repository inactivity. A heartbeat/state update in the
  proposed active distribution repository and a tested inactivity check are
  part of commissioning; do not assume a no-change workflow run itself counts
  as repository activity. No exact six-day availability SLA is promised.

### Build, compatibility and signing

1. Read only the four official stable feeds; reject drafts/prereleases,
   downgrades, changed published tags and incomplete responses. Capture source
   commits, archive/dependency/resource hashes, notices and reviewed GREYWARD
   recipe/artwork revisions. No upstream launcher or executable is installed.
2. Prepare one candidate four-application generation when any application or
   reviewed GREYWARD input changes. Keep the shared monotonically increasing RPM
   release and exact sources for all four; do not create releases on no-change
   checks. Never replace bytes under an already published NEVRA or tag.
3. Preserve the strict manual `prepare-update.py` route. The new automation's
   `candidate.py` permits offset-only changes outside a reviewed adaptation hunk
   only when every original hunk occurs verbatim exactly once. It compares the
   real `git apply` output with those exact transformations, then pins the new
   immutable source and input hashes. Ambiguous/changed hunks, changed licenses,
   NOTICE, fonts, MIME definitions or runtime resources block publication.
   New hashes alone are not approval. No fuzzy patching, AI rebasing or automatic
   edits to trusted patches/tests/security policy are allowed. Upstream-native
   theming hooks remain the longer-term way to reduce compatibility exceptions.
4. Build each app in a fresh pinned Fedora 44 container on standard public Linux
   runners; one app job at a time, two compiler jobs and an 8 GiB memory limit.
   Keep toolchains and build caches out of RPMs/ISOs. Benchmark the heaviest app
   against runner disk and job-time limits before claiming the free tier works;
   do not silently select paid larger runners or fall back to the user's PC.
   Revision 8 appends `-Cdebuginfo=0 -Ccodegen-units=16` to Fedora's existing
   Rust flags. This retains the other flags/hardening and overrides Fedora's
   debug=2/single-unit settings, which otherwise overrode Cargo's bounded profile
   and exhausted 8 GiB during Writer's native test. No test is skipped.
   Because no DWARF is emitted, the recipe produces the runtime and complete
   source RPMs rather than an empty debugsource subpackage. GUI startup checks
   extract and execute the actual packaged binary on a private X11/session bus
   in a separate unprivileged networkless container with software rendering.
5. Require source/RPM closure, native engine round trips, preferences/identity/
   MIME checks, startup without automation listeners, and signed DNF upgrade and
   negative-signature tests. Retain the two repository gates and relevant Office/
   Update Center contracts. Headless CI does not prove hardware, physical input,
   printing or a real reboot; changed GUI/security contracts need review.
6. Build/test jobs receive no distribution key or publication token. A separate
   trusted signing/publishing job accepts only the sealed successful generation,
   checks its provenance and complete inventory, and never executes upstream
   build code. Pin third-party actions; limit credentials to the distribution
   repository. Use a dedicated signing subkey kept outside source, short-lived
   runner key material and an explicit rotation/expiry procedure. Initial key
   provisioning is a one-time operator step, not per-version work.

### GitHub delivery to the existing DNF5 provider

- Use the **separate public Office distribution repository**
  `GREYWARD-office-updates`, with `main` as its only permanent branch. This avoids
  mixing automatic Office releases/cleanup with OS ISO releases and limits the
  publisher's write authority. Its component export contains only Office recipes,
  canonical artwork, dedicated tests and workflows. GREYWARD still uses the audited public
  export; never upload the private development checkout wholesale.
- Put RPMs, corresponding sources/SRPMs, notices, the exact build lock and a
  signed SHA-256 inventory in versioned GitHub Releases. Assemble drafts first;
  compare anonymous download readback with the signed inventory before offering
  them. Release assets are never overwritten. Do not store RPMs, source bundles
  or compiler output in Git history, Actions caches or GitHub Packages.
- GitHub Release assets alone are **not a DNF repository**: DNF expects a
  `repodata/` hierarchy. Keep only the small signed DNF metadata and scheduling/
  channel state in the distribution repository. Metadata contains absolute
  download URLs to the versioned Release RPM assets. Its snapshot is addressed
  by its immutable Git commit, including `repomd.xml` and its signature.
- The installed DNF `mirrorlist` points to a stable raw GitHub channel file.
  That file selects one commit-addressed metadata snapshot. Publish/read back
  the complete snapshot first, then change the single pointer. A client sees
  either the old complete snapshot or the new complete snapshot, not a partly
  rewritten metadata/signature pair. Validate this raw/redirect/DNF path on Fedora
  before activation; do not use `releases/latest` as a moving package URL.
- Preserve the independently pinned public key, `gpgcheck=1`,
  `repo_gpgcheck=1`, the four-package `includepkgs` restriction and the existing
  DNF5 Update Center provider/authorization/reboot behavior. No new privileged
  updater or unattended reboot is introduced. A six-day publication cadence is
  not a forced six-day installation on users' systems.
- `stage-channel.py` and its exact template/policy tests prepare the GitHub
  mirrorlist in place of the retired SourceForge URL. They retain
  source/staged/extracted-media checks. A future ISO must carry the validated
  GitHub channel and exact approved Office tuple; do not bypass the current
  unpublished-channel image guard merely to finish an ISO.

### Exactly three retained generations, with safe promotion

- The unit is a complete **four-app generation per supported Fedora/architecture**,
  not three files or three independently selected versions per app. Retain current
  and two predecessors, including each generation's sources and signatures.
  Unchanged apps are part of the same verified generation. Initially only Fedora
  44 x86_64 is in scope; another supported platform needs its own retained trio.
- Upload/test the next generation before deleting anything. Thus a fourth draft
  or newly published generation may exist briefly during promotion. The settled
  state is three; strict never-more-than-three would require deleting rollback
  material before proving its replacement. A failed candidate never evicts a
  working generation. Failed drafts expire after 48 hours and never enter DNF.
- New metadata advertises only the retained three. Remove the oldest generation
  from the channel, wait a **48-hour download/cache grace**, verify the channel
  again, then delete that entire obsolete Office release and its dedicated tag.
  Only exact automation-owned generation IDs in the distribution repository are
  eligible. Never delete OS releases, unrelated tags or private local originals.
  With the normal six-day cadence, cleanup finishes before the next promotion;
  defer another promotion if cleanup has not reconciled the retained set.
- Immutable Releases can be used, but expiry must delete the whole release
  before its dedicated tag; individual immutable assets cannot be removed.
  Never reuse expired tag names. If remote cleanup fails, report the extra
  generation and retry cleanup rather than silently accumulating more releases.
- Old clients can update directly to current without intermediate releases.
  However a client holding arbitrarily old metadata can request a deleted RPM.
  Keep metadata expiry at six hours and test refresh/re-resolution after a 404,
  preserving prepared offline transactions. A finite three-generation policy
  cannot guarantee every indefinitely paused download remains valid. No GPG
  bypass, silent downgrade or success report on a failed transaction is allowed.
- If a promoted generation proves faulty, withdraw it from offers and select a
  verified retained snapshot. This prevents further distribution; it does not
  automatically downgrade already installed applications. Their recovery needs
  an explicitly approved downgrade or a tested corrective package with increasing
  RPM version ordering. Never claim that changing the channel repairs them.
- Publish sources/notices alongside every served binary and audit bundled
  dependency/resource license obligations before enabling expiry. If any require
  longer source availability, disclose that exception before commissioning.
  Retention limits downloadable generations, not the small source/provenance Git
  history. Do not rewrite public history just to remove metadata records.
  `dependency-policy.json` records the exact license expressions observed in
  generation 7's four native Cargo inventories. Sealing rejects a new/unknown
  expression or missing license metadata pending review; source and bundled
  notice/license files remain in the RPM/SRPM family. This is a drift gate, not
  a claim of automatic legal review of upstream code.
- Intermediate Actions artifacts: at most **one day**, removed immediately by
  a separate trusted transfer job after each application. The complete existing
  RPM/SRPM family is about 675 MiB, exceeding Free's 500 MiB artifact allowance.
  A serialized reusable workflow builds one app, transfers its unsigned files
  into a private tracked release draft, deletes its Actions artifact, then starts
  the next app. A 350 MiB per-app ceiling leaves space for the small candidate.
  The final signing job downloads that complete staging set, checks the family
  and signs it; all staging assets are deleted before the release becomes public.
  Do not run overlapping pilot/manual groups or unrelated artifact-producing
  workflows in this distribution repository. Account-wide shared storage can
  still affect free-tier availability; no billing setting is silently enabled.
  The gate removes leftover owned artifacts from completed runs and deletes only
  owned completed main workflow runs/logs older than 14 days. Inventory is read
  completely before deletion. There are no persistent compiler caches. Cleanup
  has a release dry-run inventory and
  tests for unrelated releases, partial uploads, reruns and interrupted cleanup.

### Implementation and commissioning evidence

Canonical implementation is `packaging/greyward-office/automation/`:
`model.py` owns pure cadence, retention and exact transformations; `candidate.py`
captures official sources; `seal.py` verifies trusted recipe/RPM closure;
`transfer.py` keeps credential-free build jobs separate from draft transport;
`release.py` signs, stages immutable metadata, switches the channel and expires
only tracked releases. `github.py` never forwards API credentials to download
redirects. The three workflow templates and pinned Fedora `Containerfile` are
exported by `bootstrap.py`; they run in the distribution repository, not on the
reference or inside an installed ISO. The export starts disabled even when
exported from an activated recipe; it never copies Git, host logs or caches.

The initial export mistakenly included two bytecode files generated by its final
verification. They were removed from the public head immediately; export now
suppresses bytecode, ignores caches and verifies a complete normalized inventory.
Existing public history was not rewritten. No signing secret was in that export.

Windows tests and Fedora-native tests cover month boundaries, outages/backoff,
exact/ambiguous hunks, candidate trust boundaries, export closure and deletion
scope/recovery. All four real pinned upstream archives pass unique-hunk checks.
On the reference, an isolated subkey-only keyring signs all four generation-7
copies. The real DNF fixture accepts the signed transaction, rejects an unknown
signer under valid metadata, and confirms host package identities unchanged.
Native actionlint and the pinned secret scanner pass the component export;
GitHub component source-validation CI is green. Commissioning corrected the
retired `xorg-x11-utils` dependency (`xwininfo` is standalone), Fedora's Rust
debug/codegen precedence, an empty debugsource subpackage, host bind-directory
metadata preservation, and the explicit X11 keyboard library. The latter is now
also an RPM requirement. Writer passes the complete free-runner build, its four
theme tests and DOCX/PDF engine round trip, the packaged network-disconnected
X11 startup/listener check, and separate transfer. See the
[current pilot](https://github.com/MANTIS-devlab/GREYWARD-office-updates/actions/runs/40576931904).
Writer and Sheets completed that pilot. PDF's pinned OCR origin subsequently
returned HTTP 403 from both the Windows host and GitHub runners. The two
models have a narrowly allowlisted
[byte-identical mirror](https://github.com/deeplabua/deepocr/releases/tag/models-v1);
actual downloads match the unchanged original ArtCraft attribution SHA-256 pins.
`prepare.py` falls back only for those exact origin/checksum pairs. A primary or
mirror checksum mismatch fails immediately; unknown inputs never infer a mirror.
The changed preparation code is bound in the source lock, so the whole family
is rebuilt with consistent provenance. Original attribution/licenses remain.

The first full delivery cycle passed on standard public runners, anchored at
**2026-10-27T21:08:51Z**. The
[successful production run](https://github.com/MANTIS-devlab/GREYWARD-office-updates/actions/runs/40584792859)
built all four applications, ran native document and packaged GUI/listener tests,
signed the complete family and verified public DNF/mirrorlist readback before
confirming generation `office-f44-x86_64-g9`. The initial dispatch was safely
skipped because its runner clock preceded the new epoch; no reservation occurred.
A private GitHub
draft-expiry acceptance deletes only
its exact test draft, with a simulated grace clock and an isolated ledger.
It exposed cached list readback and absent-tag DELETE behavior; exact-ID fresh
reads and a pinned tag-commit check now handle these cases. No production ledger
or published generation was changed by that acceptance. Real private draft
upload/download also passes byte readback and leaves the production ledger
unchanged. The native HTTP mirrorlist/absolute-RPM-URL fixture passes with
valid signatures; both unknown package signers and invalid metadata signatures
are rejected. Its temporary server is loopback-only and closes after the test;
that early fixture was separate from the subsequently successful public GitHub
DNF acceptance. The published inventory SHA-256 is
`f37bef5720ab6e1cf74f3554d47391b55c69a0a058fb0c824402800a545865b9`;
the generation-9 source lock is
`4051c38ad4c89e9d9cec299affbc3bae7b44ed6742e1bac3c7d6f88ff3f250d3`.
The reference independently verifies the inventory with the pinned primary key,
all eight RPM signatures and their hashes. Native round trips cover Writer
DOCX/table/bold/PDF, Sheets XLSX/formulas/two sheets/CSV, PDF search/annotation/
form/page editing/save/render, and Slides PPTX/edit/save/PDF. Packaged startup
checks run with networking disabled and observe no TCP/UDP listener; they
explicitly do not claim physical keyboard/clipboard/printing acceptance.

First-use testing also reproduced DNF5 5.4.6's metadata-key prompt in a fresh
non-root cache. The fixed read-only DNF calls accept configured keys without
a TTY; invalid metadata signatures are still rejected. Center 122 / Context
113 are installed with rollback RPMs retained. Their source-tree fingerprint
matches canonical sources; 215 Rust tests (22 explicit ignores), 419 native
Python tests, Clippy and 101 frontend tests pass. All 1,646 protected desktop
files are unchanged, protected-seat readback is true and Enforcing remains
active. The public channel replaces the fixed local feed, with both GPG checks
and the four-package scope retained. No Office application upgrade or reboot
is performed during channel activation. See the
[Update Center contract](../architecture/UPDATE_CENTER_ARCHITECTURE.md).

At `2026-10-27T22:33:53Z`, the real ordinary-session Update Center reports DNF5
AVAILABLE and exactly four actionable Office offers from `greyward-office`:
Writer `0.10.0-6` to `0.11.0-9`, Sheets `0.11.1-6` to `0.12.1-9`, PDF
`0.13.0-6` to `0.14.0-9`, and Slides `0.10.0-6` to `0.11.1-9`. No Office
compatibility hold is present. The existing six desktop dependency holds stay
in force. Protected-seat readback is true, SELinux is Enforcing and no offline
update is pending. Configurations and the previous public certificate are saved
privately for rollback. This discovery is not another apply/reboot acceptance.

Primary references: [Actions scheduling limits](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows),
[public runner resources](https://docs.github.com/en/actions/reference/runners/github-hosted-runners),
[Release storage](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases),
[immutable Release lifecycle](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases),
and [DNF5 repository configuration](https://dnf5.readthedocs.io/en/stable/dnf5.conf.5.html).

## Acceptance

### Version updates, generation 7 — 27 October 2026

The source lock selects the published stable WordCraft 0.11.0, GridCraft 0.12.1,
PdfCraft 0.14.0 and DeckCraft 0.11.1 releases. Exact UI adaptations were rebased
against their immutable commits. New dictionary, autofill, restore-view and
presentation controls are retained; names, window identities, application/document
icons, existing preference paths and GREYWARD dark chrome remain customized.

All four revision-7 binary/source RPMs were built sequentially with two Cargo
jobs, an 8 GiB unit limit and reduced priority. Canonical verification of the
sealed binaries passes source/manifest/payload/NOTICE/MIME/artwork/path/mode and
ownership gates. The source manifest SHA-256 is
`19bb08c6ad896690dd195faabd311fdeabefb260bde095ba2f196b3531c18924`.
Four actual Writer saved-theme tests pass. Native engine copies pass DOCX
bold/table save/reopen/PDF rendering, XLSX formulas/two sheets/CSV, PDF search/
annotation/form/page editing/save/reopen/render and PPTX editing/save/reopen/PDF/
render. The new PDF engine also reads the PDFs exported by Writer and Slides.
These are engine tests, not new-version physical keyboard/clipboard/GUI acceptance.

The production signing key is separate from the old test key. The prepared
generation contains four signed binary RPMs, four signed source RPMs, signed
repository metadata, the source lock and signed SHA-256 inventory. Real DNF
transaction tests in disposable RPM roots accept all four upgrades. A separate
repository with verified trusted metadata but a Writer RPM signed only by a
new untrusted key is rejected. The disposable Office headers stay unchanged;
no host application install is performed by this fixture.

The reference has a local validated feed, restricted to the four packages and
using the pinned production key with both GPG checks enabled. The earlier
acceptance feed remains disabled. At `2026-10-27T02:20:47Z`, the actual ordinary
session `org.greyward.Update1.GetSnapshot` completed refresh and reported DNF5
AVAILABLE and exactly these four actionable Office candidates, with no Office
compatibility hold:

| Package | Installed | Offered |
|---|---|---|
| greyward-writer | 0.10.0-6.fc44 | 0.11.0-7.fc44 |
| greyward-sheets | 0.11.1-6.fc44 | 0.12.1-7.fc44 |
| greyward-pdf | 0.13.0-6.fc44 | 0.14.0-7.fc44 |
| greyward-slides | 0.10.0-6.fc44 | 0.11.1-7.fc44 |

The 104 Office/image/export source tests pass (six opt-in/native image tests
remain skipped on Windows), the 42 existing Update Center tests pass, Updates
and Network Activity rendering are covered by 101 frontend UX tests, and both
repository gates pass. The signed repository fixture was actually run on Fedora;
it is separate from the Windows skips.
The ten channel/discovery tests also pass on Fedora, along with native Bash
syntax checks of the changed image scripts. A sanitized source export passes the
pinned secret scanner; its only new reviewed false positive is the exact
committed public-key SHA-256 in `channel.json`, scoped to that path/hash/rule.

Historical owner decision earlier on 27 October: retain the initial SourceForge
preparation locally. The later approval of the
[GitHub automation](#six-day-github-automation) supersedes that publication
choice for the scoped Office component. Generation 9 subsequently completed
commissioning and `channel.json` is now published. Future complete image builds
still refuse an unpublished/missing channel. The generation-7 local feed below
is historical evidence, superseded by the signed GitHub channel. No actual reference
apply/reboot or new-version physical GUI/printing acceptance is claimed. The
historical real Update Center apply/reboot below remains generation-5 acceptance.

### Icon revision 6

Historical artwork acceptance, 25 October; these packages remain installed on
the reference pending the generation-7 update. Application tiles
and document-page icons have separate identities; the page vectors are unchanged
from revision 5. Package verification and cache refresh passed. The normal shell
and desktop-icon services are active after reload; system file associations and
USBGuard rules are unchanged. Existing application windows may need reopening to
load their embedded icon. Visual acceptance of the installed icon revision is
pending; the engine and Update Center checks below were not repeated for it.

### Initial revision-5 acceptance

Historical evidence, 25 October (reference acceptance completed within these limits):

- Writer passes DOCX bold/table save/reopen, PDF export and page rendering.
  Its four actual interface-theme tests preserve explicit saved choices.
- Sheets passes an XLSX formula, two worksheets, save/reopen and CSV export
  with calculated-value readback.
- PDF passes text search, annotation, form creation/fill, page rotation,
  save/close/reopen readback and page rendering.
- Slides passes PPTX title/shape editing, save/reopen, PDF export and rendering.
  PDF also reads the text exported by both Writer and Slides. The document
  renders were visually inspected on the test copies.
- All four release-5 RPMs pass canonical source/payload/NOTICE/icon/MIME
  checks, allowed install-path and ownership/mode checks, and absence of
  scriptlets and file capabilities. All four signatures and repository metadata
  were verified through normal DNF trust checks.
- The native source/image/integration suite passes 133 tests (three skips);
  the 42 existing Update Center tests, both repository gates and the public
  export regression suite pass. A pinned secret scan of the changed source
  files found no secrets.
- At this initial acceptance, all four applications were installed at release 5. Writer was genuinely
  upgraded from release 1 by Update Center's authenticated native helper and
  DNF5 offline transaction 43. DNF history is `Ok` and lists only Writer's
  replacement. The running Writer ELF matches the release-5 payload; `rpm -V`
  passes for all four applications. The post-boot Update Center reports
  `COMPLETE`, matches transaction 43, and records its recovery point as valid.
  No offline update remains staged. Recovery-point restoration was not tested.
- All four desktop entries launch review copies in the ordinary confined
  session domain, with no owned INET listeners/UDP sockets observed during
  startup. Desktop-file validation passes. The user confirmed Writer keyboard,
  paste, DOCX, appearance and available-screen behavior, then confirmed the
  four-app keyboard/clipboard, theme/icon, Strata open/save and Slides slideshow
  checks. No compositor or protected-profile update was needed.
- A separate negative test used trusted signed repository metadata containing
  a package signed by an untrusted second key: DNF rejected it and the installed
  package stayed intact.
- SELinux stays Enforcing. All 947 existing kernel permission checks pass;
  an ordinary-session probe is denied opening the protected authentication
  readiness file. Writer probes `/dev/udmabuf` and is denied DMA-device I/O;
  that denial is deliberately retained, while render-node descriptors are open.
  This is not a reason to grant general DMA access. The post-install kernel
  matrix and ordinary-session protected-read denial were checked again. No
  recent AVC matched the new review-window PIDs.
- The real user-session Update Center service reports DNF5 AVAILABLE and
  resolved only Writer 0.10.0-1 → 0.10.0-5 without a compatibility hold. The
  user authorized and completed its Polkit/apply/restart path. The temporary
  acceptance feed is disabled and its disposable key removed from system RPM
  trust after testing. Sealed packages and the public key remain available
  privately; this key is not a production distribution key.
- After explicit user acceptance, Papers and the Collabora system Flatpak
  application were removed. The DNF transaction removed only Papers, with
  dependency cleanup disabled. Flatpak used `--no-related` and no data-removal
  flag; application data and runtimes remain available for rollback. The
  existing Collabora user-data directory remains present. Hash-verified
  Collabora/Papers rollback artifacts and the original MIME file are retained
  privately; no rollback restore has been exercised.
- The active root MIME defaults now assign all 21 supported Office types to
  the four native identities. Ordinary-session GIO readback verifies each
  default after retirement and no retired handler remains registered for
  those types. Strata, browser, image and plain-text defaults are unchanged.
  The RPM-owned generic MIME file and Files component's directory override
  were left intact. Unsupported PPT/ODP are not assigned to Slides.
- One persisted PDF state file was backed up before the update and still exists
  afterwards, but changed during the intervening application use. This is not
  a byte-identical preference-retention proof. Writer's saved-theme choice
  behavior is covered by its four native tests; existing preference locations
  and user data are retained by the package design.

Remaining limits: no configured print destination was available, so physical
printing remains unvalidated. The user confirmed available-screen behavior;
post-retirement DRM readback currently exposes only the laptop panel, so no
simultaneous three-screen automated acceptance is claimed. Startup includes an
optional X11 clipboard probe warning; upstream's Wayland Smithay backend is
built and the user confirmed paste. No X11 or general clipboard permission was
added to suppress the warning. Complex real-world documents and complete
Microsoft Office/LibreOffice fidelity remain outside these small-copy tests.
No ISO was composed or clean-installed and no public update feed was activated.

An existing Update Center limitation was observed: `CancelUpdate` did not clear
its earlier read-only `RESOLVED` preview. This is recorded for a separate core/
profile change; it did not stage an update and does not negate the subsequently
verified apply/restart cycle. Do not claim that preview cancellation passed.

Source regression entry point:

```sh
python3 -m unittest tests.test_office_integration tests.test_image_offline tests.test_image_baseline
pwsh -NoProfile -File tests/static.ps1
pwsh -NoProfile -File tools/validate-repository.ps1
```

Separately verify actual packaged launch, clipboard/keyboard, Strata open/save/
reopen, theme/icon/grouping and available screens. Exercise Writer DOCX formatting,
table and PDF export; Sheets formula/multiple-sheet XLSX and CSV; PDF search,
annotation/form/page editing/save; Slides PPTX editing/save/PDF/slideshow.
Exercise a real downstream revision update through Update Center, preferences
survival and bad-signature rejection. Verify Enforcing and protected-data denial.
No configured printer means physical printing remains unvalidated. Only after
replacement acceptance remove Collabora/Papers on the reference and migrate
their MIME handlers. No ISO composition substitutes for installed acceptance.
