# GREYWARD ISO creation and installation runbook

Status: **CURRENT CANONICAL PROCEDURE — INTERNAL ALPHA ONLY**

This is the mandatory entry point before creating or testing a GREYWARD
installer ISO. The current builder requires a captured runtime baseline and
vendor base-ISO checksum. The v13 record below is historical evidence; it
predates these gates and is not validation of the current builder.

For the short, copy/pasteable reconstruction path, start with
[ISO_REBUILD_QUICKSTART.md](ISO_REBUILD_QUICKSTART.md), then use this document
for architecture, evidence requirements and incident history.

The finished ISO must install **without internet**, including first boot and
all included applications. Only the build machine needs internet to acquire
dependencies. This is not yet a signed, hardware-certified release pipeline.

## Latest rebuild candidate: 2026-09-19 reboot hand-off and greeter wallpaper

This candidate contains the installer reboot hand-off marker and the persistent
greetd wallpaper synchronization fix. It was built on `.149`; `.120` was not
modified or used for runtime acceptance during this build.

| Field | Recorded value |
|---|---|
| ISO | `output/iso/greyward-installer-44-20260919-reboot-greetd-wallpaper.iso` |
| SHA-256 | `1cd15f08a8a934cbef6568234636c4aaa334b161171532a866bb56ea3c3cf5ad` |
| Volume ID | `GREYWARD-INSTALLER-44` |
| Fedora Everything input | `Fedora-Everything-netinst-x86_64-44-1.7.iso` / `bd285201494dd0ba09b54d05ac707de1401668b8512a573edb5922dcf9d7067e` |
| Build host | `.149` / Fedora 44 |
| Build-time validation | Production stage validation, static checks, repository validation and offline image unit tests passed |
| Runtime validation | Not yet run; `installed_system_tested=false` in the provenance manifest |

The installer now records `anaconda-reboot-requested` immediately before the
Kickstart-owned `reboot --eject`, and first boot records
`anaconda-firstboot-entered`. The bootloader timeout is five seconds so the
LUKS hand-off is visible. Greetd receives the same canonical desktop wallpaper
through `greyward-sync-greeter-wallpaper`, which refreshes the cache before
every greetd start and is checked by production acceptance.

## Known-good artifact: 2026-09-11 Flatpak finalization fix

This is the first candidate in this series that was attached to the dedicated
test VM and booted successfully after the previous first-boot failures. Keep
the artifact and its sidecar together:

| Field | Recorded value |
|---|---|
| ISO | `output/iso/greyward-installer-20260911-offline-flatpakfix.iso` |
| SHA-256 | `f689f0124b02c44815b60ae097641447dd2e01a42f9005c3363feae25bc6ad08` |
| Volume ID | `GREYWARD-INSTALLER-44` |
| Parent candidate | `output/iso/greyward-installer-20260910-offline-final17.iso` |
| Parent SHA-256 | `6787a833096380ff17ecfa9ef78bcb23cd77856b2347875ad61bfd0c3c80d6f0` |
| Fedora Everything input | `cache/iso/Fedora-Everything-netinst-x86_64-44-1.7.iso` / `bd285201494dd0ba09b54d05ac707de1401668b8512a573edb5922dcf9d7067e` |
| Baseline input | `output/iso-baselines/greyward-149-20260909-finalfix.json` / `33b3d5fa6df04b60eabb92aeaba0826be77a86f015762e11a437308cb85c9e88` |
| Security inputs | center `0.1.0-45` (`4f9085b12820bf086474216b9d01fee95d91cb60bea6e959f1376af502620403`); context `0.1.0-50` (`e6be90b7384b989123dd055c8d2b4f7c27a0012dbeb3d0767ac493f541fe4f7e`); manifest `6ab23b2d49a64517f79c623a47e56991bb3ee2a3a567b2288596c391bfbef328` |
| Branding input | `greyward-branding-0.1.0-13.fc44.noarch.rpm` / `1dc01a12f7924c9ddd04a0e94049b4d0173ba2389f6bea33c31a929bca73ebcd` |
| Build host | `.149` / Fedora 44, Flatpak 1.18.2, xorriso 1.5.8 |
| Test VM | `.120` / `GREYWARD-ISO-TEST-20260901` |
| Network during ISO construction | Available only to the builder; Flatpak acceptance used an empty network namespace |

This particular artifact was a bounded, checksum-recorded remaster of the
known-good `final17` payload because `.149` had only 1.5 GiB free when the
full builder was first inspected. Old generated ISO work trees were removed
from the explicitly scoped `.149` ISO-work directory, leaving enough space
for the parent ISO, extracted production tree and new output. The canonical
full builder remains `environment/image/build-iso.sh`; this bounded remaster
must not be mistaken for a replacement image architecture.

## Candidate: 2026-09-18 installation-speed / Anaconda-closure optimization

This candidate was built from the current production source snapshot on `.149`
after the source/baseline guard was satisfied. It keeps the `.149` portable
state and all active Security Center performance fixes. The installation-path
optimization is deliberately narrow: the five selected offline Flatpaks are
installed in one Flatpak transaction, and a verified Anaconda RPM-closure
marker lets first boot skip the duplicate package resolver/transaction on a
fresh installation. Each application commit is still checked against the
captured baseline. The installer remains network-independent; no network
fallback or relaxed commit check was added.

| Field | Recorded value |
|---|---|
| ISO | `output/iso/greyward-installer-20260918-installfast-anaclosure-hyperv-genericgfx.iso` |
| SHA-256 | `a2ac1945838c102cd827fbd5739e5c1bbcaaebd0b20b7738f712d5587c8d59df` |
| Volume ID | `GREYWARD-INSTALLER-44` |
| Build source | `.149` / commit `d800c6ce73ed900f544b80d6d04bb3bd5f791da9`, with the synchronized installer/provisioning, offline Flatpak, and hardware-neutral greeter changes |
| Fedora base | `Fedora-Everything-netinst-x86_64-44-1.7.iso` / `bd285201494dd0ba09b54d05ac707de1401668b8512a573edb5922dcf9d7067e` |
| Runtime baseline | `output/iso-baselines/greyward-149-20260918-installfast-anaclosure-genericgfx.json` / `cae324836c83f230e488844136617d811204467a9fb17a8ba01ca58a57461387` |
| Branding RPM | `greyward-branding-0.1.0-13.fc44.noarch.rpm` / `98735521a449bc3a27cc310fd8b4268c7b6f75dff3c801252bbe8c86a1e0f6a6` |
| Security RPMs | center `0.1.0-45`, context `0.1.0-50`; built and tested together on Fedora `.149` |
| Build-time gates | Security Center Rust tests passed; stage validation passed before and after ISO insertion; ISO checksum and payload hashes passed; Rock Ridge-aware ISO contract passed (`47` required paths) |
| Provenance | `installation_requires_network=false`; installer dependency resolution tested; installed-system/runtime acceptance not yet tested |

The candidate is ready for the next clean Hyper-V installation test on the
dedicated `.120` test VM, followed by a bare-metal installation check. It is
not yet a runtime acceptance result. Do not reuse a repaired disk as evidence
for this candidate, and do not claim a measured wall-clock gain until an
equivalent clean-install comparison is recorded. VMware is not a validation
target for this candidate. The greeter change is hardware-neutral: it selects
Pixman only for known virtual GPUs or systems without a usable DRM render node;
bare-metal systems with a usable render node retain hardware rendering.

The final remaster did all of the following before publication:

1. Extracted the parent ISO production tree and root repository with `xorriso`.
2. Promoted every selected Flatpak ref from
   `refs/mirrors/org.flathub.Stable` to ordinary `refs/heads` refs.
3. Regenerated the OSTree summary with
   `flatpak build-update-repo --collection-id=org.flathub.Stable`.
4. Replaced the staged `install-offline-flatpaks.sh` with the corrected script.
5. Rebuilt `offline/flatpak-inventory.tsv` from the captured refs and commits.
6. Recomputed `production/payload.sha256` after every payload change.
7. Replaced the production subtree with `xorriso -rm_r` followed by `-map`, so
   obsolete files could not remain beside replacements.
8. Replayed the El Torito boot metadata and verified the final volume ID and
   SHA-256.

The clean-target Flatpak test installed Brave, Collabora Office, Aerion,
Bazaar and Haruna plus their runtimes from the ISO repository with networking
disabled. Each installed commit was compared with the `.149` baseline. The
temporary `greyward-offline` remote is removed after success; a failed retry
leaves it available for diagnosis. The new ISO has not yet been clean-installed
in `.120`; the next runtime gate is Hyper-V with a fresh disk and temporary
DVD boot only, followed by a bare-metal check.

The parent payload already contained the fixes that resolved the earlier
installation and first-login failures. They are listed here as a release
summary so a future update does not accidentally remove one while changing a
different component:

| Failure seen during development | Fix retained in this ISO |
|---|---|
| CLI-only or black-screen installations | Fedora Everything/netinst media and one direct graphical Anaconda Kickstart; no Workstation/live profile or GNOME Initial Setup hand-off |
| Anaconda missing `core`/`grub2-tools-extra` | Preserved Fedora `core` comps metadata plus the implicit bootloader RPM closure in both repositories |
| First boot failed in Plymouth/dracut | Select the GREYWARD theme without `-R`, then regenerate all installed kernel initramfs images in the target |
| `pipefail^M` and other shell failures | Normalize staged text line endings and run shell syntax checks before payload hashing |
| RPM/package duplication after remaster | Delete the old ISO subtree before `xorriso -map`; require one current Security Center and Security Context RPM |
| Security Context `session10_bus.py` missing | Package the noarch Python runtime under `/usr/lib/greyward-security-context`, matching the launcher |
| Security providers unavailable after login | First boot uses `systemctl enable --now` for provider services and acceptance requires them active |
| Security Context user bus unavailable | Install the user unit and D-Bus policy independently of compositor variables; verify the real user service and bus |
| Oh My Zsh/Powerlevel10k absent | Provision the canonical vendored shell files and hooks for the actual Anaconda-created user; acceptance checks the runtime files |
| Missing wallpaper/session settings | Keep wallpaper, DMS, Labwc and shell configuration in production-owned sources and apply them to the new user's session |
| Missing minimize button / wrong compositor path | Preserve the Labwc decoration assets and the UWSM `greyward-labwc.desktop` default hand-off |
| Offline Flatpak could not resolve Brave | Isolate all Flatpak roots, promote collection refs, regenerate the summary, install from the ISO-local sideload remote, and verify each commit |

## Updating components without losing a working ISO

Development continues after a known-good image. Treat every ISO as immutable
and every component update as a new candidate. Never modify the only working
ISO, reuse its output filename, or patch an installed test disk and call that
the next image. The previous known-good ISO remains the rollback artifact until
the new candidate passes all gates.

### Change classification

Use the smallest scope that is still honest about risk:

| Change | Minimum required evidence |
|---|---|
| Documentation or tests only | Static checks, repository validation, image unit tests |
| Wallpaper, branding, DMS or shell configuration | Fresh staging, source-hash check, staged text/syntax check, fresh-user graphical login and shell acceptance |
| Flatpak application or runtime commit | Fresh Flatpak export, promoted refs and summary, isolated offline install of the complete selected set, commit comparison |
| Security Center code or RPM | Fedora RPM rebuild, package-script inspection, Security Center tests, exact center/context manifest, provider and D-Bus acceptance |
| RPM package list, Fedora core, bootloader, Kickstart, initramfs or first-boot logic | Complete dependency closure, ISO repository transaction, fresh Anaconda install, first boot, acceptance and media-removed reboot |

If a change crosses more than one row, use the highest-risk row. A visual
change is not “cosmetic” when it changes staged paths, shell startup, the
greeter gate, initramfs generation or the DMS session launcher.

### Candidate update protocol

For each candidate, create a new Linux build workspace and record the source
state before editing:

```bash
git status --short
git rev-parse HEAD
df -h
```

Then follow this order:

1. Change one component boundary at a time. Keep the source, RPMs, baseline,
   Flatpak refs, and external inputs in a candidate-specific directory.
2. Run `tests/static.ps1`, `tools/validate-repository.ps1` and the applicable
   component tests before staging. Do not use a passing development VM as a
   substitute for source tests.
3. If the intended portable state changed, capture a new `.149` baseline with
   `capture-image-baseline.ps1`. Do not recapture merely to hide source drift;
   update the canonical source first and review omitted/normalized values.
4. Build both Security Center RPMs from the same source tree as the image.
   Require exactly one current center RPM, one context RPM and one matching
   `security-center-build-manifest.tsv`.
5. Run the canonical `build-iso.sh` with a new output name, verified Fedora
   base checksum and the reviewed baseline. The builder must use empty DNF and
   Flatpak roots, not the build host's installed state.
6. Require the offline dependency check to complete with networking absent.
   In particular, the Flatpak check must use separate `XDG_*`,
   `FLATPAK_SYSTEM_DIR`, `FLATPAK_SYSTEM_CACHE_DIR` and `FLATPAK_USER_DIR`
   directories, then execute the real first-boot Flatpak script in an empty
   network namespace.
7. Inspect the produced ISO, its payload hash and sidecars. Confirm the root
   repository paths, exactly one Security Center/context RPM, the selected
   Flatpak refs/commits, the Kickstart, and the absence of development-only
   accounts and services.
8. Attach only that checked ISO to `.120`. While the VM is off, set the DVD as
   the complete first firmware device and record the exact ISO path and hash.
   Do not reboot `.149` as part of this test.
9. Run the full VM gate: graphical Anaconda, installation, first boot, actual
   user login, Oh My Zsh and its configuration, Security Center/providers,
   wallpaper, resolution, application minimize controls, logout/login, and a
   reboot with the ISO removed. Keep network disconnected for the standalone
   offline gate.
10. Publish the candidate only after the preceding evidence is recorded. If
    any gate fails, keep the previous ISO unchanged, record the first failure,
    fix the owning source, and produce another uniquely named candidate.

### Component-specific safe update rules

For Flatpak updates, capture the application ref and commit, install the exact
commit during factory staging, export the complete closure, promote collection
mirror refs to ordinary heads, regenerate the summary, and write a non-empty
`offline/flatpak-inventory.tsv`. Test the clean installation by commit, not
only by application name. Flatpak 1.18.2 does not support
`flatpak install --commit=...`; the installed version is pinned by the local
branch and verified with `flatpak info --show-commit`. Do not use `--no-pull`
as a substitute for an offline namespace: it prevents the sideload remote
from resolving. The caller's empty network namespace is the network gate.

For RPM or Security Center updates, compare NEVRA and SHA-256 before staging,
recreate repository metadata, remove obsolete RPMs before mapping replacements,
and run the transaction against an empty target database. Never accept a
package merely because its filename is stable. Inspect `%pre`, `%preun` and
`%post` scripts with Fedora's RPM macros before embedding them.

For shell, session and branding updates, normalize staged text before hashing,
run `bash -n` on shell inputs, validate the actual Anaconda updates image, and
test the newly-created user's session. A working `.149` session proves the
development overlay only; it does not prove that the production provisioner
copied the same files to a fresh account.

For installer, bootloader, initramfs or first-boot changes, require a fresh
installation. A repaired existing disk is useful diagnostic evidence, but it
cannot close the clean-install gate because it may retain packages, EFI boot
entries, user files or completion markers from an earlier candidate.

### Rollback and publication record

Keep the previous ISO, SHA-256 and manifest until the new candidate has passed
the media-removed reboot. Rollback means selecting that immutable previous
artifact and restoring its recorded DVD mapping; it does not mean editing the
new ISO or copying files into an installed root. Every candidate record should
include:

```text
candidate path and SHA-256:
parent candidate and SHA-256:
source revision / intentional dirty changes:
baseline path and SHA-256:
base Fedora ISO and vendor SHA-256:
Security Center RPM NEVRAs and manifest SHA-256:
Flatpak refs and commits:
offline dependency test:
ISO structure/payload verification:
test VM and disk identity:
Anaconda / first boot / login / reboot evidence:
known limitations:
```

## Architecture that must remain intact

    Fedora Everything/netinst ISO
      -> resolve/download RPMs, Flatpaks, DMS and pinned shell sources
      -> verify dependency closure with networking absent
      -> mkksiso + local repository + installer.ks + updates.img
      -> Anaconda owns LUKS, storage, account creation, and reboot
      -> staged production payload on the installed root
      -> retryable first-boot production finalization
      -> production acceptance
      -> greetd -> DMS Greeter -> Labwc

environment/production/ is the installed product. The development VM and its
overlay are build and authoring infrastructure only:

- .149 may be used as a Fedora build host, but the ISO must not depend on it at
  runtime or be made from its installed disk;
- the test ISO VM must use its own fresh or explicitly approved test disk;
- no development account, SSH access, passwordless sudo, Hyper-V agent, or
  development overlay may enter the production payload;
- DMS is presentation-only; installation, provisioning, and acceptance stay
  outside QML.

The canonical implementation is environment/image/build-iso.sh, which calls
environment/image/build.sh. Do not recreate the process with a live
Workstation image, a second Kickstart, a copied VM disk, or an ad-hoc wrapper.

## Working recipe

### 1. Prepare an isolated Linux build workspace

Use a Fedora build host with enough free space for the base ISO, RPM build
trees, Cargo output, staging, and the resulting ISO. Prefer a dedicated Linux
filesystem rather than the Windows-mounted repository for large temporary
trees.

Use Fedora 44 x86_64 with `dnf5`, `createrepo_c`, `flatpak`, `git`, `curl`,
`python3-rpm`, `python3-libdnf5`, `unshare`, `mkksiso`, `xorriso`, `rpm2cpio` and `cpio`.
The offline dependency helper requires root via noninteractive sudo; it uses
disposable RPM databases and Flatpak installations, never the build host's
installed package state. Budget at least 40 GiB free on each staging/output
filesystem; the resulting media is larger than netinst.

The networked dependency phase pins its downloads and DNF resolution to IPv4.
This is a build-host reliability guard for environments with a broken IPv6
route; it is not copied into the installed system and does not constrain the
resulting production ISO.

Record the intended source state and run the repository checks first:

    git status --short
    git rev-parse HEAD

    pwsh -NoProfile -File .\tests\static.ps1
    pwsh -NoProfile -File .\tools\validate-repository.ps1

For repeatability, use a fresh synchronized checkout or a disposable copy
containing only the intended source. If the checkout is dirty, record which
changes are intentional.

### 1a. Capture the current `.149` baseline

From the Windows repository, while the intended desktop preferences are active:

    pwsh -NoProfile -File .\tools\greyward-dev\capture-image-baseline.ps1 -Output output/iso-baselines/greyward-149-YYYYMMDD.json

The helper uses the configured GREYWARD development SSH endpoint and does not modify the VM.
Copy this JSON alongside the build inputs. Inspect `captured_at`, `terminal`,
`dms`, `normalized_dms_keys` and `omitted_dms_keys` before using it.

The baseline records:

- RPM version floors: matching packages installed in the target must be at
  least as new as `.149`. Development-only packages are not installation requests.
- Exact commits and refs of the five production Flatpak applications.
- Selected portable DMS preferences (including bar geometry/colors) and terminal
  appearance. Monitor names, personal paths, added widgets, accounts, credentials,
  network connections, browser profiles and application data are not imported.
- Content hashes of the production/session/Flatpak/patch/branding source tree,
  including intentional uncommitted customizations. The repository remains the
  authority for plugins, wallpapers, Labwc, shell configuration and security policy.

This is a controlled state import, not a VM clone or a complete export of every
user preference. Promote wanted changes listed as omitted/normalized into the
canonical sources, then recapture. Staging rejects source/configuration drift;
do not bypass it or edit the captured digest. Capture after finishing source
and branding changes, and before transferring the final Linux build tree.

On a Linux `.149` checkout the equivalent commands are:

    python3 environment/image/baseline.py policy --repo . --output /tmp/greyward-policy.json
    python3 environment/image/baseline.py capture --policy /tmp/greyward-policy.json --output /srv/greyward-build/baseline.json

Run capture as the desktop user with their session bus. Source staging never
infers a baseline from whichever host happens to run the ISO builder.

### 2. Build the Security Center RPM inputs

Build both RPMs from the same Linux source tree that will be used by the image
stager. The builder emits the source/RPM manifest.

    export GREYWARD_SECURITY_CENTER_SOURCE=/srv/greyward-build/repo/security-center
    export GREYWARD_SECURITY_CENTER_OUTPUT=/srv/greyward-build/rpms
    export GREYWARD_RPMBUILD_PARENT=/srv/greyward-build/rpmbuild
    export GREYWARD_CARGO_TARGET_DIR=/srv/greyward-build/cargo-target
    bash /srv/greyward-build/repo/environment/development/build-security-center.sh

The output must contain exactly one current file for each of:

    greyward-security-center-*.x86_64.rpm
    greyward-security-context-*.noarch.rpm
    security-center-build-manifest.tsv

Do not select RPMs with a broad wildcard from several builds. Check the
manifest's filenames, SHA-256 values, NEVRAs, and source_tree_sha256.

The component build can generate Tauri schemas or other output in the source
tree. Keep build output outside the source tree or start from a clean
disposable copy. If the source hash changes after the manifest is emitted,
stop and reconcile the tree; never bypass the image builder's hash check.

### 3. Build and validate the branding RPM

    pwsh -NoProfile -File .\tools\generate-branding.ps1
    pwsh -NoProfile -File .\tools\validate-branding.ps1
    pwsh -NoProfile -File .\tools\build-branding-rpm.ps1

Use exactly one greyward-branding RPM. It must own:

    /etc/anaconda/profile.d/greyward.conf
    /usr/share/anaconda/pixmaps/greyward-anaconda.css
    /usr/share/anaconda/pixmaps/greyward-anaconda-logo.png

The profile belongs under profile.d, not the old ignored conf.d path. The RPM
is also installed into the target before reboot and Plymouth is rebuilt so the
first installed LUKS prompt can use GREYWARD branding.
Select the theme without Plymouth's `-R` helper, then run
`chroot /mnt/sysroot /usr/bin/dracut --regenerate-all --force`. The installer
kernel can be older than every installed kernel; the rebuild must enumerate
the target's module directories rather than use the running kernel version.
The ISO builder compares the packaged installer and boot assets with the current
source bytes and rejects a stale branding RPM even when its filename is unchanged.

### 4. Validate the base ISO

Use Fedora Everything/netinst media matching the repository's Fedora version,
for example Fedora-Everything-netinst-x86_64-44-1.7.iso. Verify the vendor
checksum and inspect the volume ID:

    xorriso -indev Fedora-Everything-netinst-x86_64-44-1.7.iso -pvd_info

The volume must begin with Fedora-E-; build-iso.sh rejects other media. Do not
use Fedora Workstation/live media. It can hide Anaconda's account page and
defer account creation to GNOME Initial Setup, which GREYWARD does not ship.

### 5. Stage and compose the ISO

Use explicit inputs and a new output name. The external RPMs must match
environment/production/external-rpms.txt.

    repo=/srv/greyward-build/repo
    build=/srv/greyward-build
    bash "$repo/environment/image/build-iso.sh" \
      --base-iso "$build/inputs/Fedora-Everything-netinst-x86_64-44-1.7.iso" \
      --output "$build/greyward-installer-YYYYMMDD.iso" \
      --baseline "$build/inputs/greyward-149-YYYYMMDD.json" \
      --base-sha256 "$verified_vendor_sha256" \
      --branding-rpm "$build/rpms/greyward-branding-CURRENT.noarch.rpm" \
      --security-rpm "$build/rpms/greyward-security-center-CURRENT.x86_64.rpm" \
      --security-rpm "$build/rpms/greyward-security-context-CURRENT.noarch.rpm" \
      --security-build-manifest "$build/rpms/security-center-build-manifest.tsv" \
      --production-rpm "$build/inputs/rpms/opensnitch-1.8.0-1.x86_64.rpm"

The builder embeds installer.ks, GREYWARD updates.img, the production stage,
the manifest-bound Security Center RPMs, and pinned external RPMs. The
Kickstart must retain graphical, visible account creation, encrypted Btrfs
autopartitioning, exclusion of openssh-server, and reboot --eject.

Set `verified_vendor_sha256` from the verified Fedora vendor checksum, not from
an untrusted local download alone. The builder checks it before composition and
requires the complete offline payload before composition. `build-offline.py`
resolves the base, bootloader, kernel and production RPMs from empty installroots;
checks upstream signatures and `.149` version floors; bundles exact application
commits with their Flatpak runtimes/extensions; and downloads the hash-pinned
DMS archive and commit-pinned shell sources, including the terminal prompt binary. It then resolves all RPMs and
installs the Flatpaks in fresh roots with networking absent. Unavailable inputs
fail the build. No installation-time download fallback is permitted.

Anaconda uses the ISO's CD-ROM repository, an explicit generated package list,
and locally preserved Fedora `core` group metadata. The builder exports the
merged group from the same cached repositories used for RPM resolution and
removes production-excluded packages such as `openssh-server`, then passes it
to both `createrepo_c` calls. Anaconda adds `@core` and bootloader
requirements itself: the offline checks must resolve these too, including
`grub2-tools-extra`, `grubby`, and `nvme-cli` for NVMe-backed virtual or physical
install targets, against both the production and ISO-root repositories. An
explicit package list does not replace group metadata.
No mirror lists or remote group metadata are needed. First boot copies
from the installed payload and runs DNF/Flatpak in network namespaces with
no external interfaces. System-service configuration retains the host namespace
for audit/netlink access; the finalizer also denies IP traffic through systemd.
Fedora, COPR and Flathub remain configured for later,
user-initiated updates; the temporary media repository is never persisted as
an enabled update source. This is not a bit-reproducible or signed-release claim.

The ISO-root repository is a separate metadata view over the same RPM closure.
The RPM files live under `greyward/production/offline/rpm/Packages/`, but the
directory passed to `createrepo_c` is `.../offline/rpm`; the tool appends the
`Packages/` component when it writes package locations. Therefore the root
metadata must use `--location-prefix greyward/production/offline/rpm`.
Adding `/Packages` to that prefix produces `Packages/Packages/` URLs and
Anaconda reports `Failed to download packages` even though the RPMs are
present.

The staged provision.sh may be 0644: it is invoked explicitly through bash.
The first-boot wrapper must test readability (test -r), not require an
unrelated executable bit.
After source/baseline validation, `stage-text.py` converts CRLF to LF in the
staged UTF-8 source text and runs `bash -n` on shell scripts. It leaves binary
artifacts, RPMs, offline inputs and captured baseline bytes unchanged. The
before/after hashes are recorded in `artifacts/staged-text.json`; the final
payload checksum covers the normalized files. Do not rely on Git attributes
to sanitize a copied Windows working tree.

### 6. Inspect before attaching

    cd "$build"
    sha256sum -c greyward-installer-YYYYMMDD.iso.sha256
    xorriso -indev "$build/greyward-installer-YYYYMMDD.iso" -pvd_info
    xorriso -osirrox on -indev "$build/greyward-installer-YYYYMMDD.iso" \
      -extract /greyward/production/provision-firstboot.sh /tmp/greyward-firstboot.sh
    grep -n 'test -r "$provision"' /tmp/greyward-firstboot.sh
    xorriso -indev "$build/greyward-installer-YYYYMMDD.iso" \
      -find /greyward/production/rpms -type f -exec report_lba

Inspect installer.ks for graphical, account-page ownership, and the absence
of the development account and SSH server. Copy the ISO to the test host only
after source and destination SHA-256 values match.

Composition uses a temporary filename. Before publication, the builder extracts
the production payload and verifies every recorded file hash, the embedded
baseline, and the GREYWARD volume ID. Only then does it publish the ISO,
`.sha256`, and `.manifest.json` sidecars. Keep them together: the manifest binds
the ISO to the base media, baseline, branding RPM, Security Center build manifest
and staged payload. A failed build must not be renamed into a successful artifact.

### 7. Attach and install in the dedicated test VM

Before booting, ensure enough host disk space for the VHDX, AVHDX/checkpoint,
VMRS file, and installer work. Then stop the test VM, attach only the checked
ISO, set the DVD as the complete first boot order, and verify that an old EFI
File Fedora entry is not ahead of it. Validate the real VMConnect framebuffer;
Get-VM showing Running is not graphical evidence.
Disconnect the test VM's network adapter **before booting**. Keep it disconnected
through installation, first boot, login and a subsequent reboot with the ISO
removed. The dependency checks do not replace this required standalone test.

Expected flow:

    GREYWARD-branded Anaconda
      -> LUKS passphrase
      -> visible account creation
      -> encrypted disk installation
      -> installer reboot/eject
      -> first-boot finalization
      -> GREYWARD graphical login

If the installer shows Fedora branding, no account page, a media-check halt,
or an Anaconda “unknown error”, stop and preserve the installer report/journal.
Do not continue with that artifact.

### 8. Validate the installed result

    systemctl status greyward-production-firstboot.service --no-pager
    journalctl -u greyward-production-firstboot.service -b --no-pager
    test -e /etc/greyward-production-complete
    systemctl is-active greetd.service

The Anaconda `%post` verifies the exact copied production tree before the first
reboot, records `anaconda-reboot-requested`, and preserves
`/root/greyward-payload-check.log` if that boundary fails. The first-boot
finalizer requires that hand-off marker and records
`anaconda-firstboot-entered`, making a missing post-install reboot diagnosable
instead of presenting an unexplained blank console. It also refreshes the
greetd wallpaper override from the canonical desktop wallpaper before opening
the login boundary.
The finalizer verifies payload integrity again; on failure it records the
failed entries in `payload-check.txt` under the preserved stage and displays the
first entries on tty1. It then updates core RPMs as well as installing
production packages, deploys the captured Flatpak commits, and checks the RPM
version floors before opening the login gate. The selected baseline remains at
`/usr/share/greyward/artifacts/runtime-baseline.json` for diagnosis. Flatpak commits
are selected for installation only; ordinary future updates are not masked.

Setup writes a short status to the console, Plymouth when available, and
`/var/lib/greyward/installer/status.txt`. The first-boot wrapper also keeps a
transcript at `/var/log/greyward-production-firstboot.log` and tees the complete
provisioning output to tty1 and journald, including explicit phase markers. The
offline Flatpak helper disables the configured Flathub remote and uses only the
ISO-local sideload repository. There are at most three starts in three
hours, spaced by 30 seconds; each attempt has a 30-minute timeout. Repeated
failure is not progress. The pending stage and greetd gate remain until acceptance
succeeds. Fix the first logged failure, then:

    sudo systemctl reset-failed greyward-production-firstboot.service
    sudo systemctl start greyward-production-firstboot.service

Never create the completion marker manually or bypass acceptance. Do not call
a CLI login a successful install. Verify final package state and a subsequent
reboot too: a kernel installed during first boot becomes active on the next boot.

After acceptance, verify the actual Anaconda-created user's DMS/Labwc session,
GREYWARD theme, wallpaper, Security Center, resolution, logout/login, and a
reboot with the ISO removed. Keep VM graphics/resolution issues separate from
installer correctness.

## Incident ledger: mistakes and prevention

### 2026-09-13: VMware post-provisioning failure had insufficient evidence

The VMware clean-install candidate displayed the first-boot wait message and
advanced through the offline Store and Security Context stages, but later
failed before the graphical greetd session became usable. The encrypted target
root was not available for offline log extraction, and the provisioner grouped
many required service starts into one command, so the exact late failure could
not be identified from the screen. The candidate ISO was also found to contain
the pre-diagnostic version of the source files; it is not being treated as a
validated fix.

The production sources now persist the current provisioning phase and the
failed command, start and verify each required service separately, and record
greetd's status and journal if `dms-greeter`/`labwc` do not appear. The first
boot console keeps the existing live log feedback and includes the last phase
and failure details on retry. The VMware renderer guard clears any stale fixed
DRM-device selector while retaining software-rendering fallbacks, so the same
ISO remains portable to VMware, bare metal, and multi-GPU systems. A new ISO
must pass source/static validation and direct ISO preflight before it is
attached to the validation VM; no VM result is inferred from source checks.

### 2026-09-14: VMware provisioning treated absent Bluetooth hardware as fatal

The NVMe VMware clean-install candidate completed the offline application and
Security Context stages, then stopped while starting `bluetooth.service`.
Systemd reported `Active: inactive (dead)` and repeated `Condition check
resulted in Bluetooth service being skipped`; VMware exposes no Bluetooth
adapter, so this was an expected hardware condition rather than a service
failure. The provisioner nevertheless treated every listed service as
unconditionally mandatory and failed the installation.

The production service gate now skips Bluetooth only when
`/sys/class/bluetooth` is absent. A real adapter still follows the strict
`enable --now` and active-state checks. This keeps VMware and other hardware
without Bluetooth installable without weakening the production requirement on
machines that provide the capability.

### 2026-09-14: VMware greeter renderer fallback was installed in the wrong scope

The NVMe VMware candidate successfully copied and validated the staged
production payload, completed provisioning, and reached the final login
boundary. `greetd` started, but `dms-greeter`/`labwc` exited after
`EGL_NOT_INITIALIZED` and `unable to create renderer`. The VM's `vmwgfx` driver
was present; enabling VMware 3D did not change the result. The important detail
was that DMS Greeter sets `HOME=/var/cache/dms-greeter` before it launches its
compositor, so the installed user's Labwc environment and the greetd service
drop-in were not a reliable source for the child compositor's renderer choice.

The final source-level fix passes the hardware-neutral software-renderer
fallback directly in the `/etc/greetd/config.toml` command with `/usr/bin/env`.
It also sets `XDG_CONFIG_HOME` to the greeter's cache, while the production
user's `labwc-environment` retains only `WLR_RENDERER_ALLOW_SOFTWARE=1` and no
forced `WLR_RENDERER=pixman`. This keeps the fallback local to the login
greeter, preserves hardware acceleration for the installed desktop when
available, and avoids a global systemd drop-in or a custom executable.

The `Permission denied` screenshot came from a wrapper manually injected into
the disposable encrypted VMDK with `guestfish`. Its mode was executable, but
the injection bypassed the normal SELinux labeling path. Removing that wrapper
removes this test-only failure class. VMware Tools remain an optional
integration package; they are not the cause of the renderer failure or a
substitute for the kernel's `vmwgfx` driver.

### 2026-09-16: VMware user session black screen was the accelerated Labwc path

Forensic extraction from the fresh VMware NVMe test disk showed that the login
itself succeeded: UWSM brought up Labwc, DMS connected to the Wayland socket,
and Quickshell began loading. The user journal then recorded repeated
`[types/wlr_linux_dmabuf_v1.c:223] Failed to close buffer handle for plane 0:
Invalid argument` messages from `uwsm_labwc`. Immediately afterward DMS
reported `The Wayland connection experienced a fatal error: Protocol error`,
Quickshell exited with status 255, and `greyward-dms.service` entered its
restart loop. This is the observed cause of the post-login black screen; it is
not an installer or LUKS failure.

The production session entry now starts through
`environment/production/greyward-start-labwc`. It detects VMware's DMI/DRM
identity and exports `WLR_RENDERER=pixman` only for that session before
starting UWSM/Labwc. Physical hardware and other hypervisors retain their
normal renderer. Source checks verify the launcher is staged and installed;
the new ISO still requires a clean VMware install and post-login runtime
observation before it can be called validated.

### Agent mistakes — 2026-09-09 retrospective

These were mistakes in my implementation and validation, not commands the user
should have needed to diagnose or repair.

| My mistake | Correction and evidence |
|---|---|
| I checked explicit package dependencies but missed Anaconda's implicit `core` group and bootloader requirements. | Added comps metadata, `grub2-tools-extra` and `mtools`; checked both repositories against an empty RPM database with networking absent. Package installation then passed. |
| I used Plymouth's `-R` helper in a chroot, assuming it selected the installed kernel. | Selected the theme separately and ran `dracut --regenerate-all --force` inside the target. The next installation booted its installed 7.1.13 kernel. |
| I copied Windows CRLF source files into Linux staging without checking their execution. | Added `stage-text.py` before payload hashing, preserving immutable inputs; normalized six files and added a real Bash regression test. The corrected payload completed first boot and reached the GREYWARD desktop. |
| I handed off successive candidates before proving the complete installation path, leaving the user to discover the next failure. | Recorded each artifact and its actual evidence separately. The exact replacement ISO's clean install and media-removed reboot are still open; tests and a repaired target do not close those gates. |
| I spent too much effort on console recovery and shifted command entry to the user. | Used checksum-guarded repair media to resume setup myself; the user entered only authentication. All product fixes are in the factory sources. The VM is a validation fixture, not the deliverable. |
| I tried bulk text/clipboard input in the basic VM console without a reliable keyboard path. | Switched to observed key presses and tab completion, checking each result and pausing when user input interfered. Do not blindly repeat failed input. |
| I left the Security Context user unit gated on `WAYLAND_DISPLAY`, so a fresh user manager could show it as enabled but inactive and leave Security Center unavailable. | Keep the backend D-Bus unit independent of the compositor environment, start it from `default.target` and `graphical-session.target`, and verify the actual bus name after login. |
| I treated a non-empty Anaconda-created `.zshrc` as proof that the production shell was configured. | The first-boot configurator now installs the canonical GREYWARD Oh My Zsh and Powerlevel10k files unconditionally for the newly-created account; acceptance checks the runtime, source hook, theme, and user shell. |

Validation at this point: 24 image tests, static checks and repository validation
passed. First-boot success was observed on the previously installed target after
applying the replacement ISO's six verified source corrections. A fresh build
and installation through the complete canonical factory are not established by
that bounded remaster/repair test.

### 2026-09-09: first-boot staging failed on Windows line endings

The `offline-bootfix` candidate completed installation and booted its installed
7.1.13 kernel. Direct VMConnect journal inspection found
`provision.sh: line 2: set: pipefail^M: invalid option name`; all three retries
failed before provisioning. The 96-byte error appeared as blob data until
`journalctl -a` was used. Source staging had preserved CRLF in six source files,
including the provisioner and an extensionless shell launcher.

The factory now normalizes staged source text and validates shell syntax before
payload hashing. The `greyward-installer-20260909-offline-stagefix.iso` candidate
retains the package inputs, captured baseline and boot-fix Kickstart. It also
contains a bounded `repair-stage.py` for the affected installed stage: it checks
incoming hashes and baseline identity, accepts only the recorded original or
corrected file hashes, backs up the affected files, restores a verifiable stage,
and restarts normal setup. It does not bypass production acceptance.

On 2026-09-09 the bounded repair was applied through the test console. Normal
first-boot finalization progressed through production configuration, branding,
DMS patches and bundled Flatpak installation, then released the GREYWARD
greeter. The user's login reached the branded Labwc/DMS desktop, observed in
VMConnect. This validates the corrected staged sources on the previously
installed target; it does not replace a fresh installation of this exact ISO
and a subsequent reboot with the media removed. The artifact SHA-256 is
`f48a807e25d22c08ecc5d3737bea0f7d6ef1078cc621367367e6ee8aea7f3b32`.

The production finalizer also seeds the actual Anaconda-created account's
`~/.config/uwsm/default-id` with `greyward-labwc.desktop` when that file does
not already exist. The separate `~/.config/greyward/compositor` marker alone
does not control UWSM's `default` launcher; without both values a fresh login
can select `hyprland.desktop` and stall in the fallback compositor path.

### 2026-09-08: post-install boot-theme rebuild failure

The dependency-corrected `greyward-installer-20260908-offline-fixed.iso`
passed package installation but failed in `%post`. Its test VM debugger showed
`ScriptError` from `plymouth-set-default-theme -R greyward`: dracut could not
find `/lib/modules/6.19.10-300.fc44.x86_64`. This is the running installer
kernel, not the newer baseline-checked target kernel. The Plymouth helper
invokes `dracut -f`; chroot does not change the running kernel.

The canonical Kickstart now selects the theme without `-R` and separately
regenerates all installed kernels. Errors remain fatal; branding is not
silently skipped. Static and image regression checks reject the old command.
The replacement `greyward-installer-20260908-offline-bootfix.iso` changes only
the embedded Kickstart and retains the dependency-corrected production payload
and captured baseline. At that handoff a complete test install was still open;
the subsequent boot and CRLF failure are recorded above. Neither a solver check
nor successful composition proves first-boot acceptance.

### 2026-09-08: offline ISO dependency selection failure

`greyward-installer-20260907-offline.iso` (SHA-256
`d0d325f903e057c4f32c1154c090fb799daeae84aa0a9d30bbed551a90f09a72`)
reached Anaconda 44.30-2's debugger with `NonCriticalInstallationError`:
`No match for argument: grub2-tools-extra` and `No match for argument: core`.
This was read directly from the failed test VM, not inferred from build logs.
The old resolver checked explicit RPMs only and both generated repositories
omitted comps metadata. The factory now includes the implicit bootloader
requirements, preserves the actual Fedora core group in both repositories,
and resolves Anaconda's requests with an empty RPM database and no network.
Dependency validation remains distinct from a full clean installation.

The bounded repair artifact `greyward-installer-20260908-offline-fixed.iso`
(SHA-256 `ddf9b6b5fa8c71423bfb095440fc69373f2fe70e31b4976f48fdbdb543df4d42`)
preserves the original baseline and Kickstart while adding the core metadata,
the matching `grub2-tools-extra` RPM and its missing `mtools` dependency. The
sidecar records the parent ISO hash. Both repositories and the published ISO
passed offline resolution; embedded payload hashes passed. This is not a
completed installation test. New builds must use the corrected factory above.

| Failure | Root cause/evidence | Prevention |
|---|---|---|
| Missing DVD ISO | A VM pointed to a deleted output ISO. | Resolve the path, verify the hash, and record the DVD mapping before start. |
| Old disk booted | EFI restored File Fedora ahead of the DVD. | Set and verify DVD-only first boot while the VM is off. |
| .149 used as product image | Development VM and independent ISO target were conflated. | Keep build host, development VM, and test ISO VM separate; the ISO must be standalone. |
| No account / CLI result | Wrong live/Workstation-style profile delegated setup to GNOME Initial Setup. | Use Fedora Everything/netinst and the direct Anaconda Kickstart only. |
| Anaconda unknown error | A D-Bus traceback was treated as transient. | Preserve the report/journal and fail the image gate until media and inputs are revalidated. |
| VMware NVMe install failed with `No match for argument: nvme-cli` | The Hyper-V test used a SCSI disk and did not exercise Anaconda's NVMe dependency request; the offline RPM closure omitted `nvme-cli`. | Resolve `nvme-cli` with the boot/storage package set and verify it through the networkless installer-repository check. |
| Media-check halt | Media check was mistaken for proof of installability. | Verify vendor/final SHA-256 and ISO structure; keep media test diagnostic. |
| Missing Security Center contract | Stale or mismatched RPMs entered staging. | Require one current center/context RPM, manifest, hashes, NEVRAs, and all contract paths. |
| Old plugin/package copy | Stable filenames/timestamps hid a stale deployed artifact. | Use unique outputs and verify artifact hashes/NEVRAs against the selected source. |
| Two production Kickstart templates | `build.sh` staged the obsolete `environment/http/greyward.ks.tmpl` while ISO composition used `environment/image/installer.ks.tmpl`; a candidate could therefore embed the old text-mode/network/Plymouth flow. | Keep one canonical installer template under `environment/image/installer.ks.tmpl`; stage and compose from that path, and test that the old production template is absent. The 2026-09-09 `offline-canonfix` artifact is a bounded Kickstart repair and is not a fresh-install proof. |
| Root ISO repository pointed to `Packages/Packages/` | The offline subrepository and RPM closure were correct, but the ISO-root `createrepo_c --location-prefix` already included `Packages/` even though the source directory was `.../offline/rpm`; the tool added that component a second time. Anaconda's `cdrom` source then failed to download packages. | Keep the root prefix at `greyward/production/offline/rpm`; inspect a root primary metadata entry and require it to resolve to an actual ISO path before attaching the candidate. |
| Remastered ISO rejected its own payload | A post-build RPM/metadata replacement changed files under `greyward/production` after `payload.sha256` had been copied from the base ISO. First boot correctly reported checksum failures for `offline/rpm/repodata/repomd.xml` and the Security Center manifest. | Recompute `production/payload.sha256` after every payload replacement and before the ISO is written; verify the manifest from the final ISO, not only from the remaster workspace. |
| RPM replacement failed in `%preun` | A package rebuilt in Ubuntu lacked Fedora's systemd RPM macro expansion, leaving invalid literal `%systemd_*` scriptlets. Replacing the staged context RPM then failed during the first-boot DNF transaction. | Build Security Context with Fedora RPM macros; if a non-Fedora repair environment is unavoidable, define every required scriptlet macro explicitly and inspect `rpm -qp --scripts` before embedding the RPM. Keep the staged RPM and offline-repository RPM at the same NEVRA. |
| Remaster retained an obsolete RPM beside the replacement | `xorriso -map` overlaid the corrected production tree but did not delete files that were already present in the base ISO. The published image therefore contained both Security Context RPM 46 and 49, and first boot rejected the three matching Security Center inputs with `test 3 -eq 2`. | Remove replaced ISO trees with `-rm_r` before mapping the clean tree, then validate the final ISO itself contains exactly one Security Center RPM and one Security Context RPM. |
| Manually remastered VMware candidate omitted required first-boot files | Windows ISO inspection used short ISO9660 aliases and the manual remaster copied an incomplete production tree. The checksum manifest was internally consistent because it had been regenerated from that incomplete tree; first boot then failed at the staged-payload validation gate before provisioning. | Treat `build-iso.sh` as the only ISO producer. Validate the staged tree and the extracted final ISO against the literal `provision.sh` file contract, require exactly one current Security Center RPM set, and run the direct Rock Ridge-aware VMware preflight before attaching a candidate. |
| `.149` baseline blocked the current closure on retired Kitty packages | The development VM still contained `kitty-kitten`, `kitty-shell-integration` and `kitty-terminfo`, while production intentionally migrated to Black Box and no longer owns those packages. The generic baseline floor check treated that host residue as a production requirement. | Keep the baseline floor strict for shipped packages but explicitly omit the documented retired Kitty/Tabby package names from capture and comparison. Do not edit a captured baseline ad hoc to hide an unexplained mismatch. |
| First boot reported only a generic staged-payload failure | The ISO payload verified on the build host, but the Anaconda `%post` copy boundary was not independently checked and the first-boot gate used `sha256sum --quiet` without preserving failed entries. A guest-side mismatch therefore stopped provisioning without naming the affected path. | Verify the copied tree during `%post`, verify it again at first boot, retain the failed entries in `payload-check.txt`, and make the builder exercise the same recursive copy boundary before publication. |
| Noarch Security Context installed code under the wrong library directory | The RPM spec used `%{_libdir}` and placed Python modules in `/usr/lib64` on x86_64, while every packaged launcher imports them from `/usr/lib/greyward-security-context`. The service then exited with `No such file or directory` for `session10_bus.py`. | Keep this noarch runtime under `%{_prefix}/lib/greyward-security-context`, matching the launcher contract, and inspect the built RPM path plus execute the entrypoint in the installed-session test. |
| Offline Flatpak finalization waited on Flathub | The installer used a valid sideload repository but did not isolate the caller's network before deploying, so Flatpak could attempt to refresh the configured HTTPS remote before a local runtime was installed. `--no-pull` was also incorrectly treated as a way to select the sideload repository; Flatpak 1.18.2 instead limits resolution to its cache and rejects the local sideload remote. | Run the installer in an empty network namespace, use the ISO-local `file://` remote with `--sideload-repo`, and validate the exact Flatpak 1.18.2 command contract in a clean user installation. Do not use `--no-pull` here. Remove the temporary remote with `--force` only after all selected refs are installed; this removes configuration, not installed data. |
| Offline Flatpak finalization could not resolve Brave | `flatpak create-usb` on the builder produced the application and runtime objects under `refs/mirrors/org.flathub.Stable`, but Flatpak 1.18.2 published no usable summary branches (`offline/flatpak-inventory.tsv` was empty). The builder's user-only check could also see host system objects, while first boot used a clean system installation and failed with `Nothing matches com.brave.Browser in remote flathub`. | Promote every collection ref to ordinary heads, run `flatpak build-update-repo`, install from a temporary ISO-local `file://` remote with `--sideload-repo`, verify the captured commit after deployment, remove that remote only after success, isolate both user and system Flatpak directories in the builder check, and reject an empty inventory before publishing. |
| First production login showed Security providers unavailable although the Security Context user service was running | First-boot provisioning only enabled system provider units after `multi-user.target`; they were not started until a later reboot, while the user session queried them immediately. | Use `systemctl enable --now` for provider services during first-boot finalization and make production acceptance require every provider to be active. |
| VMware first boot stopped making disk progress after the Collabora/Store phase while the finalizer remained visible and guest tools were unavailable | The final service-start and acceptance boundary had no per-check checkpoint, and individual `systemctl`/acceptance calls could wait behind a guest service without a useful timeout. Host-side VMware evidence showed the test NVMe disk stopped changing after the Store phase. | Print the finalizer entry and acceptance checkpoint before each validation group, bound required service starts and acceptance to explicit timeouts, and preserve the last phase/failure files. Do not call a candidate fixed until a fresh NVMe install reaches acceptance, removes the ISO, and reboots to greetd. |
| VMware candidate finalizer failed immediately after `finalizer entered`, before any acceptance checkpoint | The final ISO's Rock Ridge payload inspection passed all 47 required paths and hashes, so the failure boundary is the installed-target preflight or its Anaconda copy boundary, not the package/Store tail or greetd hand-off. The five preflight `test` commands collapsed any missing or unreadable staged path into the same generic message. | Report each staged-path preflight check and persist the exact missing/unreadable path and stage location before proceeding. Keep the media-side contract validation and Anaconda `%post` copy checksum; do not relax a required input to hide the failure. |
| VMware candidate reported `production stage directory is missing` on the first boot even though direct ISO inspection passed | The ISO contained `/GREYWARD/PRODUCTION`, but the Anaconda `%post --nochroot` copied from one assumed runtime mount path and did not make the media-source boundary explicit before arming the first-boot gate. The installed helper then correctly refused to run without its required staged payload. | Resolve the installer media by the required `greyward/production/payload.sha256` marker across Anaconda's known mount locations, use a read-only optical-media fallback, and verify the target marker immediately after copying. Abort `%post` with mount diagnostics if the source is unavailable; never let first boot discover this as a generic missing-stage error. |
| VMware candidate still reached first boot with the pending marker but without the production stage | The payload was copied under `/var/lib/greyward/installer` during Anaconda's `--nochroot` post-install phase. Fedora's automatic encrypted Btrfs layout can mount `/var` separately on the installed system, so content written before that mount boundary is not a reliable location for immutable installer payloads. | Copy the verified payload to `/usr/lib/greyward/installer/production` on the installed root filesystem. Keep only the retry/status markers under `/var/lib/greyward/installer`, and make the first-boot helpers consume the root-backed path. |
| Anaconda `%post` failed at the final `production-pending` marker on the root-payload candidate | Moving the immutable payload to `/usr/lib` fixed the Btrfs mount-boundary issue, but the `%post` assumed `/var/lib/greyward/installer` already existed. On a fresh automatic encrypted Btrfs install it did not, so `touch production-pending` aborted after all payload and service setup had succeeded. | Create `/mnt/sysroot/var/lib/greyward/installer` explicitly immediately before writing the marker. Keep this check in the image tests so the marker boundary cannot regress silently. |
| VMware first boot completed provisioning but then reported production stage directory is missing | The guest journal proves the payload was present, offline provisioning and acceptance completed, then Labwc failed with Found 0 GPUs because the greeter command set WLR_DRM_DEVICES= to an empty value. The finalizer also deleted the stage and pending marker before validating the greeter; its automatic retry then exposed the misleading missing-stage error. | Keep DRM discovery enabled while forcing only WLR_RENDERER=pixman for the greeter. Retain the stage, pending marker, and tty1 gate until both dms-greeter and labwc are observed alive; delete them only at the successful login-boundary commit point. |
| First-boot failed immediately | Staged provision.sh was 0644, while the wrapper used test -x; it failed before creating greetd. | Invoke through bash and use test -r; inspect the wrapper inside every ISO. |
| Retry loop looked like progress | Restart=on-failure repeated a deterministic failure every five seconds. | Read the first journal failure, use the bounded service timeout, and require acceptance before greetd. |
| No graphical interface | The failed first-boot gate left no /etc/greetd/config.toml. | Diagnose provisioning and rebuild; do not patch the installed disk as the final fix. |
| Fedora installer branding | Anaconda ignored branding under conf.d. | Use profile.d, inject updates.img, and inspect the real installer screen. |
| First LUKS prompt unbranded | Plymouth was configured too late. | Install branding and rebuild the target initramfs in Anaconda %post before reboot. |
| Default DMS / black screen | Partial provisioning and development/session assumptions were mixed. | Keep production session files hardware-neutral and release greetd only after acceptance. |
| Bad resolution blamed on ISO | Hyper-V display/compositor state was not separated from install state. | Run a separate VM graphics gate; never import VM-only Labwc settings into production. |
| SSH in production | Development assumptions leaked into production packages. | Exclude openssh-server in the installer and verify package/unit state after install. |
| Build disk filled | Old ISOs, Cargo targets, RPM trees, and failed stages accumulated. | Check df -h, use a dedicated Linux work root, new outputs, and exact scoped cleanup. |
| Source hash changed | Cargo wrote four generated Tauri schemas after the RPM manifest was made. | Keep the source immutable between component build and image staging, or rebuild the manifest; never bypass the check. |
| Reused failed disk | Old EFI entries and installer state made later runs ambiguous. | Use a fresh or explicitly approved test disk and record ISO/disk identity per run. |

## Historical v13 run record

The recipe above produced this internal artifact on 2026-09-06:

    Artifact: greyward-clean-installer-20260906-v13-firstboot-fix.iso
    Volume:   GREYWARD-INSTALLER-44
    SHA-256:  6954299491d0fb9c85e5a6b2954b43f17a2f0d8df1a9364826aa0bdf0e4fdefe

The ISO structure, embedded RPM names, volume ID, and corrected first-boot
wrapper were inspected. Repository static and documentation validation passed.
This record does not replace a fresh clean install, reboot, acceptance, and
real VMConnect graphical validation for release evidence.

## Canonical sources and final checks

- environment/image/build-iso.sh — ISO composition;
- environment/image/build.sh — production staging and provenance checks;
- environment/image/installer.ks.tmpl — direct Anaconda flow;
- environment/development/build-security-center.sh — RPM/manifest builder;
- environment/production/provision-firstboot.sh and its service — first-boot gate;
- environment/production/production-acceptance.sh — installed contract;
- environment/image/README.md — concise image boundary;
- docs/security-center/remediation/2026-09-01-production-iso-pipeline.md —
  historical evidence only.

Before handoff:

    pwsh -NoProfile -File .\tests\static.ps1
    pwsh -NoProfile -File .\tools\validate-repository.ps1
    python3 -m unittest discover -s tests -p 'test_image_*.py'
    git diff --check
    git status --short
