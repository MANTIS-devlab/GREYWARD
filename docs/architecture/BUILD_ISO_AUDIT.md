# GREYWARD build and ISO engineering audit

Assessment date: 4 October 2026. **AUDITED CURRENT SOURCE; IMPROVEMENTS PLANNED.**
This is a dated engineering assessment, not a competing build recipe. Continue
to use [ISO_CREATION.md](ISO_CREATION.md) and
[ISO_REBUILD_QUICKSTART.md](ISO_REBUILD_QUICKSTART.md) for executable instructions.
[The architecture audit](FINAL_ARCHITECTURE_AUDIT.md) and
[backlog](../plans/PRE_RELEASE_IMPROVEMENTS.md) define the shared finding IDs.

This snapshot predates implementation and the user's later native DMS lock-screen
decision. See the [migration tracker](DMS_1_6_MIGRATION_PLAN.md) for current locking
and the backlog for unfinished package/image gates.

10 October pipeline update: this dated snapshot's four-package count is no
longer current. The active stager requires six GREYWARD RPMs, including the
source-matched, inactive `greyward-application-security-experimental` runtime;
use the current [ISO rebuild quickstart](ISO_REBUILD_QUICKSTART.md) and
[creation runbook](ISO_CREATION.md) for the package list and command.

## Pipeline at the 4 October assessment date

GREYWARD does not currently build a live desktop ISO from `.149`. It remasters
Fedora Everything/netinst media with Anaconda stage2 and a full offline payload.
Packer is the development factory, not the production ISO composer.

| Stage | Actual owner/input/output | Cost, network and failure boundary |
|---|---|---|
| 1. Component build | `environment/development/build-security-center.sh` builds center/context RPMs and a source-bound TSV manifest; `tools/build-branding-rpm.ps1` builds branding; `packaging/greyward-dms/build.sh` builds DMS RPM/source RPM | Rust/compiler work and tests; current Security builder uses persistent Cargo target. DMS uses verified source/vendor and offline distribution flags. Build tools are factory inputs. |
| 2. External inputs | Verified F44 Everything ISO, pinned OpenSnitch RPM, DMS source/vendor, selected runtime baseline and Flatpak commits | Downloads/acquisition outside installation. Missing/current-version mismatches must fail here. No use of `latest` for DMS source. |
| 3. Source staging | At assessment time, `environment/image/build.sh` accepted one of each four GREYWARD RPM types, a security manifest and external RPMs; it copied curated production/session/assets | Refused existing output; verified current security source fingerprint and selected DMS receipt; normalised only staged text. This count was superseded by the 10 October pipeline update above. |
| 4. Portable baseline | `baseline.py` binds dirty source file hashes, permitted desktop/terminal preferences, RPM floors and selected Flatpak commits | Does not copy credentials, identity or a VM filesystem. Floors are checked only for selected closure packages, so the builder does not blindly install every development RPM. |
| 5. RPM closure | `build-offline.py` creates fresh DNF installroot/repository configuration, downloads `@core`, boot packages, policy and local RPMs, exports comps, makes local repository | Fedora/COPR metadata and keys require network. Download retries=10, timeout=120 s, parallel downloads=1. Keepcache is inside a temporary root removed afterwards. |
| 6. Source vendors | Same helper stages pinned zsh/p10k inputs and gitstatus binary | Network at factory time; cached read-only runtime gitstatus avoids first terminal network acquisition. Vendor material is not independently package-owned. |
| 7. Flatpak payload | Fresh isolated user/system/config/cache roots, current remote definition, app installs then selected commits, dependency runtimes, `create-usb` export and sideload preparation | Downloads repeat for each compose, including potentially newer app content before checkout to a selected historical commit. Collection IDs and remotes are necessary offline mechanisms. |
| 8. Offline checks | Fresh DNF databases and network namespaces; full RPM and installer implicit closure; fresh Flatpak import | These checks are worthwhile and must remain independent of caches. Solver success does not validate package scriptlets, runtime tuple or first boot. |
| 9. ISO composition | `build-iso.sh` preflights commands/root permission/Everything volume, extracts branding and creates supported Anaconda updates image, stages local root repodata, renders Kickstart, runs `mkksiso` | Uses native Linux scratch space; base media and local payload copied, firmware boot config edited. Conservative installer graphics flag does not define installed renderer policy. |
| 10. Publication | Extract embedded production tree using xorriso; validate staged closure and checksums; exercise copy boundary; publish ISO plus digest/provenance only after inspection | This catches known media-copy/Rock Ridge failures. Publication is media-valid, explicitly not installed-system acceptance. |
| 11. Anaconda | Kickstart local package repository, encryption/Btrfs/storage/account creation, nochroot post copies production payload to `/usr/lib/greyward/installer/production`, primes target boot branding and first-boot units | No development account or live root handoff. `/usr` stage placement protects against separate `/var` subvolume copy mistakes. |
| 12. First boot | `provision-firstboot.sh` verifies payload, masks competing Initial Setup, invokes offline production provisioner, checks baseline/acceptance and removes greetd gate only after ready | Static copying, service setup, system Flatpak installation and account seeding. Failure remains visible/retryable; no network is needed for package construction. |
| 13. Runtime acceptance | Production acceptance on installed image; genuine authentication/hardware cases independently | `.149` guest health and old ISO screenshots do not satisfy this stage for the new DMS package. |

The four current GREYWARD package roles are branding, DMS runtime, Security
Center frontend/backend binary, and Security Context/providers. They are already
built before `build-iso.sh`; an audit should not propose splitting component build
from compose as though that separation were absent. What is missing is a small
convenient orchestrator, persistent download reuse and complete static ownership.

## Highest-value construction fixes

### A1 — fail before expensive work when the closure cannot run the selected shell

The baseline admits package upgrades through version floors. DMS runtime startup
requires exact Quickshell/Labwc/UWSM/Greeter version-release strings. Cached
repositories offer Quickshell -5 and Greeter 1.6.2, unlike the candidate's -2 and
1.6.0. `build-offline.py` can therefore resolve a closure that passes its floor
check yet fails `/usr/libexec/greyward-dms-verify` in production provisioning.

Make dependency selection consume the canonical compatibility policy, then
compare the resolved closure's four packages with the accepted tuple before
Flatpak acquisition or ISO composition. Choose/test a current replacement tuple
or explicitly supply available retained packages. Startup still verifies backend,
shell/plugin hashes and ownership. Releasing a desktop with permanently fixed
dependencies also requires an update path; A1 includes Update Center handling.
This is a real incompatibility between existing policies, not an abstract pinning
recommendation. **MODERATE effort/risk; DO BEFORE RELEASE.**

### A3 — preserve download objects while rebuilding fresh transaction state

Current `offline.mkdir()` and fresh databases prevent stale payloads. Preserve
that. Add persistent factory caches outside `TemporaryDirectory`: RPM objects
keyed by NEVRA and verified digest, repository metadata with explicit refresh,
Flatpak OSTree objects/ref commits, and verified source/vendor archives. Stage
new outputs using copy/reflink/hardlink only where immutable objects cannot be
modified by the consumer. A filename collision with different bytes is an error.

Separate the expensive acquisition result from cheap configuration/branding
composition. Key RPM closure reuse by F44/architecture, package policy, repository
selection/metadata snapshot, component RPM digests and relevant baseline floors;
key Flatpak export by selected app and runtime commits/collection metadata. A
wallpaper edit must not invalidate unrelated download objects. A package-policy
edit must still re-solve dependencies, and every composed tree gets fresh
networkless verification.

Only after reliable reuse, make download concurrency configurable with a modest
factory default. Serial acquisition may be an intentional mirror workaround;
do not remove its retry protection without measurements. Never share a writable
installroot or RPM database across simultaneous builds. **MODERATE effort;
LOW–MODERATE risk; DO BEFORE RELEASE.** No quantified speed-up is claimed before
one cold and one warm build measure acquisition, verification and composition.

### A5 — a small session/default-policy RPM

Keep component RPMs separate. Add `greyward-session` (or equivalently named
desktop-policy package) for root-owned wrappers/helpers, vendor user units,
Labwc session/startup defaults, theme/software/terminal defaults and their exact
runtime dependencies. Use `/usr/bin` or `/usr/libexec` for new package-owned
entrypoints and compatibility symlinks for existing `/usr/local` routes.
Distribute factory defaults under `/usr/share`/appropriate XDG defaults and seed
only a missing user's file. Mutable user preferences are not RPM payload.

Move static install operations out of `provision.sh` incrementally. Do not put
user discovery, disk identity, renderer choice or service readiness into RPM
scriptlets. Keep the first-boot finalizer for account-dependent seeding, offline
Flatpak deployment and actual provider/acceptance checks. RPM systemd macros and
normal presets replace handcrafted unit installation where appropriate.

First bounded deletion: stop overwriting
`/usr/lib/systemd/user/greyward-security-context-user.service` from the installer
stage. The Security Context RPM already owns it; the source manifest already
refuses stale security inputs. Fix/build that RPM instead of hiding a stale
package with another copy. **MODERATE effort/risk; DO BEFORE RELEASE**, limited
to static ownership for this ISO. Rewriting the entire installer is not required.

### A6 — one build identity and component reuse decision

DMS release ID/path/spec version currently repeat `v1.6.2-1` across files. The
development candidate build history installed different RPM bytes with the
same NEVRA. Generate identity from one input and increment the RPM release when
downstream payload changes. Preserve upstream DMS version and full source pins.
The selector's `noreplace` upgrade behavior must be tested: a new RPM path does
not by itself activate the new selector, and replacing the old package need not
leave its previous payload installed. Retain an explicit previous RPM/state
restore path or design parallel-installable payload packages; prove one complete
upgrade/rollback before claiming coexistence.

A tiny build orchestrator should compute per-component inputs, reuse unchanged
RPMs after hash/receipt verification, rebuild affected components, then invoke
the existing ISO composer. Reuse is not “skip all tests”; a cached artifact needs
matching source/build inputs and relevant prior checks. DMS's upstream backend
is unchanged by downstream QML patches, so compiler caches/verified intermediate
reuse can shorten UI packaging without turning it into a floating binary input.
Do not add several subpackages merely for an unmeasured optimisation.
**LOW–MODERATE effort; MODERATE risk; DO BEFORE RELEASE.**

## Current caching and developer iteration: preserve what already works

The canonical Security builder uses a persistent
`~/.cache/greyward/package-cargo-target`, controlled build jobs, separate RPM
outputs and source fingerprinting. Deployment records synchronization, tests,
package build/install/check and launch timing stages. It excludes target and
node_modules from source transfer. These are useful improvements already present.
Normal Security Center changes do not require an ISO: build/test the component,
install its RPMs on the development guest, run real-window acceptance, then
reuse the validated package set for an ISO.

DMS has reversible packaged candidate switching and explicit generated-shell
verification. Use those for QML/plugin/session tests. Do not copy patched QML
over a selected runtime and leave an invalid receipt. Branding has an independent
RPM builder/asset validator; only installer/initramfs changes require boot/media
validation. Leaf UI work should use focused frontend/domain tests during editing,
with the full relevant package gate once before delivery.

One nuance: the Security component builder currently resides in
`environment/development/` while producing production RPMs. Move or expose that
factory function under packaging/build tooling when A6 adds the orchestrator;
retain a compatibility entrypoint. This is a boundary clarification, not a reason
to rewrite its working cache or duplicate the builder.

## Modern Fedora approaches and whether switching helps

Fedora's August 2026 engineering proposal says package live media has moved to
KIWI and proposes moving boot.iso production from Lorax to image-builder for
**Fedora 46**. That is not evidence that a F44 Everything remaster must immediately
change. GREYWARD consumes boot.iso rather than producing Fedora stage2 itself.
[Fedora ModernizeBootISO](https://fedoraproject.org/wiki/Changes/ModernizeBootISO)

The following effort/risk ratings are engineering judgments (1 lowest, 5 highest),
not measured migration estimates. All alternatives need GREYWARD-specific
accounts, encryption, branding, offline apps and fresh-install acceptance.

| Approach | Compatibility and package integration | Speed/cache, debugging and repeatability | Effort / risk | Verdict |
|---|---|---|---|---|
| Existing Kickstart + mkksiso | Already preserves Anaconda account/storage workflow and complete local repositories | Cheapest bounded path; fresh payload checks useful; dependency caches are GREYWARD's responsibility | 2 / 2 for proposed improvements | **DO BEFORE RELEASE:** retain and improve |
| Lorax stage2 build | More control over installer image, but GREYWARD currently only needs supported updates.img branding | Rebuilds installer internals and adds templates/debug surface; little current gain | 4 / 4 | **DON'T BOTHER** for this release |
| livemedia-creator | Can make live/disk/tar images using Anaconda/Kickstart; live root/account workflow differs from current installer | Introduces image installation/compression or virtualization work; no demonstrated faster GREYWARD rebuild | 4 / 4 | **LATER** only if live-demo media becomes a product requirement |
| KIWI NG | Mature Fedora-capable prepare/create model; XML/image scripts can package a prepared root, live or OEM output | Native cache and prepared-root reuse attractive; would still port current installation/first-boot customisations | 4 / 4 | **CONSIDER NOW** only as a time-boxed prototype after A3; production switch **POST-RELEASE** |
| osbuild / image-builder | Blueprints, package resolution, output-specific image pipelines; useful for future disk/appliance artifacts | Stage caching and managed compose improve reuse; custom GREYWARD session/first-boot and installer contracts still need integration | 4 / 4 | **LATER**, compare for automated disk images rather than promising an ISO drop-in |
| bootc / image mode | OCI-built immutable system and image-update deployment model | Container layers can speed image assembly; changes `/usr` mutability and update/recovery/package semantics across the product | 5 / 5 | **NOT WORTH IT BEFORE RELEASE**; separate product architecture project |
| Packer factory | Existing disposable development VM including SSH/Hyper-V tools | Useful package/session iteration; cloning its disk would import accumulated development state | 1 / 1 to keep separation | **KEEP DEVELOPMENT ONLY** |

The mkksiso manual supports adding local repositories, updates images and firmware
boot configuration to an existing installer. It also supports installing a
prepared `liveimg` tar, but that would change the tested root/first-boot path.
[mkksiso](https://weldr.io/lorax/mkksiso.html)
Livemedia-creator uses Anaconda/Kickstart and can use QEMU or no-virt installation.
[livemedia-creator](https://weldr.io/lorax/livemedia-creator.html)
KIWI explicitly separates root preparation and image creation, and its
self-contained workflow can share `/var/cache/kiwi`.
[KIWI](https://osinside.github.io/kiwi/),
[self-contained builds](https://osinside.github.io/kiwi/plugins/self_contained.html)
Image Builder exposes distro-specific image types and firstboot customisations;
verify available Fedora formats before assuming desktop installer support.
[Image Builder](https://osbuild.org/docs/user-guide/introduction/),
[firstboot](https://osbuild.org/docs/user-guide/firstboot/)
Bootc's package-manager documentation describes transient `/usr` overlays rather
than treating ordinary persistent DNF mutation as equivalent to image updates.
[bootc package managers](https://bootc.dev/bootc/package-managers.html)

## Fresh-install differences that matter now

| Evidence | Concrete resolution before the next ISO |
|---|---|
| Candidate tested with older exact Quickshell/Greeter than current repositories supply | A1; fail during closure resolution or test/rebuild the manifest for the new tuple. |
| Current session Python matches source but installed Context RPM is older and lacks shell_runtime.py | A2; package-only service and root provider validation. |
| Required swaylock/swayidle/wlopm were manually added during migration | They are now in production packages; verify actual resolved closure and first-login startup, not just guest presence. |
| VM has legacy dgop and old DMS for rollback | Baseline omission already excludes dgop; do not copy VM disk/runtime selectors or legacy payload into production. |
| Root D-Bus policies/provider files are modified on the guest | Build current Context spec/receipt; validate installed package contents and authorisation fixtures rather than using guest tweaks as acceptance. |
| UWSM plugin is edited after installation | A9 durable packaged fix; repeat after package reinstall/update. |
| Wrapper/session units are unowned | A5; package ownership plus dependency declarations for lock, flock/pgrep and routing helpers. |
| Factory creates the account before GREYWARD defaults are installed | Preserve actual-account seeding; `/etc/skel` alone cannot populate that first account. |
| Guest antivirus signatures are already 168 MB of existing state | A clean offline install must show correct signature availability/freshness; do not infer protection from active scanner service. Decide seed/update behavior using current existing contracts. |
| Hyper-V agents/build tools exist on `.149` | Keep factory-only; inspect final closure for unintended toolchain/SSH packages. Their presence is not a physical-hardware requirement. |

The factory validator's extra media/copy passes, empty verification roots and
first-boot gate are deliberate solutions to earlier failures. Remove repeated
downloads, not these correctness boundaries. Large full-tree payload hashing
is acceptable at build/install boundaries; do not introduce session polling of
the installer tree to “centralise” those checks.

## Recommended target pipeline

```text
Current dirty source + explicit component/desktop input selection
    → per-component source/build fingerprint
    → build or reuse verified GREYWARD RPMs
    → resolve compatible Fedora/COPR closure using persistent object caches
    → export selected Flatpak commits from persistent object cache
    → fresh networkless verification roots
    → stage configuration + package receipts
    → compose existing Anaconda/mkksiso installer
    → extract/validate → GREYWARD-44-<package-set>-<build>.iso
    → clean installed-system acceptance
```

No measured full-build duration exists for the current DMS-migrated input set;
old ISO timings would be misleading. Add stage durations and transferred byte
counts to the existing build output, not a new monitoring daemon. First compare
cold/warm acquisition, solver verification, Flatpak export, staging and compose.
Keep the immutable package-set identifier stable for unchanged inputs while
allowing an explicit build identifier for repeated outputs. Publish final names
only after current extraction checks succeed.

A pinned Fedora builder container can hold tooling/caches and reduce setup drift,
but mkksiso/network namespaces need controlled privilege and native Linux scratch
space. **CONSIDER NOW** (benefit 3, effort 3, risk 3, maintenance reduction 3);
prototype it, do not make containerisation a prerequisite to fix A1/A3.
Independent component builds can run concurrently within VM RAM/CPU limits;
shared destination/RPM databases must remain serialized. More parallelism is
not automatically faster on this guest's constrained builder.

## Release construction decision

Make compatibility, package-only runtime and ownership improvements first;
cache dependency acquisition next; compose once from the validated package set.
Keep the current installer architecture. A new image technology is a worthwhile
experiment only when a measured build/install bottleneck survives these bounded
changes. No new ISO was built or promoted during this audit.
