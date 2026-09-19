# GREYWARD production ISO pipeline remediation

Date: 2026-09-01

Status: **LIVE PIPELINE RETIRED — DIRECT ANACONDA REDESIGN IMPLEMENTED; CLEAN RUNTIME VALIDATION PENDING**

## Scope

This remediation covers the production-image path behind the observed ISO
problems: stale Security Center payloads, the first-reboot Initial Setup loop,
the temporary `greyward` account surviving installation, the GNOME session
remaining in the environment selector, and the stock Anaconda welcome page.
The v3 ISO was built and its ISO/squashfs contents were inspected, but runtime
testing showed that the temporary `greyward` account still survived and the
post-reboot GNOME Initial Setup path still looped. Those are failed runtime
gates, not completed fixes. The corrective source was then composed on Alpha
as v6. Its ISO/squashfs content is validated, including the event-gated live
reboot wrapper, the first-boot finalizer, and the staged DMS plugins. A clean
installation through first boot is still required before these fixes can be
called runtime-verified.

The historical v6 artifact was:

`greyward-alpha-composed-20260904-firstboot-fix-v6.iso`

SHA-256:
`50954825494011b06c2735003674318fd3c8a3e4409f4e4a8a81a869263f44dd`

The alpha development VM was used as a read-only runtime reference. It reported
Fedora 44 and `greyward-security-center-0.1.0-45.fc44.x86_64`,
`greyward-security-context-0.1.0-44.fc44.noarch`, and
`greyward-branding-0.1.0-7.fc44.noarch`. Its installed Anaconda is
`44.30-2.fc44`; the actual package contains the native `custom_stylesheet`
configuration hook and `.product-logo` stylesheet slot. Alpha exposes no source
Git commit or Security Center build manifest, so its package NEVRAs are a
runtime reference, not proof that a dirty checkout produced the same payload.

## Current decision and runtime truth — 2026-09-05

The live-composed workflow is retired. The latest live runtime observation was:
returning to the live desktop triggered the automatic reboot, but the first
installed boot still showed a Quickshell crash, an `Initializing...` loop, and a
second automatic reboot. Earlier runs also left the default `greyward` account
behind. These are failed live-pipeline results; they are not evidence that the
new installer works.

The replacement is a direct Fedora boot/netinst installer customized with
`mkksiso`. Its default boot-menu action is `Install GREYWARD OS`; Anaconda owns
storage/encryption, account creation, and the native completion reboot. No live
desktop, GDM autologin, `liveinst` wrapper, temporary account, or account-handoff
service is part of this path. The production stage is embedded as installer
media content, while network-dependent DMS/Flatpak work runs once through the
retryable installed first-boot service. Greetd remains gated until installed
production acceptance succeeds.

This source redesign is intentionally not marked runtime-verified until a clean
encrypted install is executed from a newly built ISO and the installed system
is read back after reboot.

The first direct installer artifact built from the synchronized source is
`greyward-direct-installer-20260905.iso` on Alpha, with SHA-256
`c1aa51a69b7a89e82921391e8133dd619564d2b782bcbad6665be97d4a35a96d`. Its ISO
structure and embedded inputs were inspected successfully; no VM installation
claim is made yet.

## Root causes

### High — Security Center package drift

The image boundary accepted two RPM filenames without binding them to the
source tree that produced them. The component releases use stable `45/44`
release numbers, so an older RPM could look current while containing an older
UI/backend. The stage also had no single package-owned file contract.

### High — competing first-boot owners

The target Kickstart enabled `firstboot`, installed GNOME Initial Setup, and
the production finalizer had a `GREYWARD_FIRSTBOOT=1` branch that re-enabled
GDM. This allowed the installed target to present a second account/setup owner
after Anaconda had already completed installation, producing the reported
`Initializing...` loop.

### High — temporary account copied without a cleanup owner

The live root necessarily contains the temporary `greyward` user. The live
installer wrapper removed the hand-off units before Anaconda copied the root,
so the installed target had no reliable post-install owner to remove that
user. A path-only trigger also missed accounts created before the first target
boot.

### Medium — incorrect installer branding boundary

The repository still described a GNOME Initial Setup resource overlay even
though the actual requested product surface is Anaconda. That was both stale
documentation and the wrong customization mechanism for the current Fedora
installer path.

### Medium — Anaconda profile was not selected at runtime

The first branding implementation installed its configuration in
`/etc/anaconda/conf.d/`, but Fedora Anaconda reads product profiles from
`/etc/anaconda/profile.d/`. Alpha's Anaconda journal consequently detected
`fedora` and loaded `fedora.css`; the ISO could contain the GREYWARD asset
without applying it. The follow-up fix installs `greyward.conf` in
`profile.d`, layers it on the Fedora profile, and lets Anaconda detect it for
Fedora systems.

### Critical — live root copied a masked Initial Setup unit into the target

The composed live image is also the source root for the interactive
`liveinst` installation. Its live-composition branch previously created
`/etc/systemd/system/initial-setup.service -> /dev/null` to prevent the live
session from showing Fedora Initial Setup. Anaconda copied that mask into the
installed target and later failed while enabling the unit during “Configuring
the installed system”, producing `Error enabling service initial-setup.service:
1`.

The live branch now un-masks and disables the unit without creating a mask.
The installer Kickstart keeps `firstboot --disable`, and the installed
first-boot finalizer creates the mask only after Anaconda exits and before the
production display manager starts.

### Critical follow-up — three first-boot defects remained

Manual installation of the rebuilt ISO confirmed that the original Anaconda
failure was fixed, but exposed three lifecycle defects: the temporary
`greyward` account survived, GNOME Initial Setup stayed in an
`Initializing...` loop after reboot, and the GNOME session remained in the
environment selector. The common architectural cause was that the live root
was still writing `production-ready` before installation. `liveinst` could
copy that marker into the target, making account hand-off eligible before the
installed first-boot finalizer had completed. In parallel, `provision.sh`
generated an inline first-boot helper while the staged
`provision-firstboot.sh` existed separately, allowing the two implementations
to drift. The v3 runtime result also showed that the finalizer created the
marker but never invoked the account-handoff helper, so account deletion did
not execute. Its live launcher used `exec liveinst`, so the successful
installer returned to the live desktop without a controlled reboot.

The corrective path is explicit: the live root never creates or retains
`production-ready`; both the live wrapper and installer `%post` remove a stale
copy defensively; only the canonical first-boot helper creates it after
masking Initial Setup and completing production provisioning; and account
hand-off is ordered after that helper. The finalizer now invokes the helper
inline with no reboot, making it the sole lifecycle owner and preventing a
service/path race. Because `liveinst` rejects Kickstart
files, the live composition keeps the production stage at
`/var/lib/greyward/installer/production`, including the first-boot helper and
service, so the interactive installer copies the complete workflow into the
target. The installed finalizer removes GDM, GNOME Initial Setup, and the
dependent GNOME Wayland session with DNF's `--no-autoremove` safeguard. The
live GDM greeter retains its internal greeter session but removes the
user-facing GNOME desktop entry, leaving GREYWARD Labwc as the supported
desktop choice.

### Medium — installed provenance trace typo

The installed package-source inventory used the unsupported DNF query tag
`%{EPOCHNUM}`. Alpha consequently recorded that literal text in its source
inventory. The query now uses the supported version/release/architecture fields
and keeps the RPM inventory authoritative for exact NEVRAs.

## Fixes implemented

- `environment/development/build-security-center.sh` now emits
  `security-center-build-manifest.tsv` with a deterministic source-tree hash,
  RPM hashes, filenames, and NEVRAs.
- `environment/image/build.sh` and `build-iso.sh` require and forward that
  manifest for complete image staging. They verify the source hash, RPM hash,
  NEVRA, filename, and every path in
  `environment/production/security-center-contract.tsv`.
- Complete staging also rejects a branding RPM that lacks the Anaconda logo,
  stylesheet, or configuration hook, preventing the stable branding release
  number from hiding an old installer payload.
- Production provisioning repeats the package file contract and installed
  NEVRA checks, installs the contract/manifest as image traceability artifacts,
  and fixes the DNF source-inventory query. Installed acceptance repeats the
  manifest schema/NEVRA checks and verifies RPM ownership for every contract
  path.
- The installed target now uses `firstboot --disable` and does not re-enable
  GNOME Initial Setup during Anaconda's installation phase. The live source
  root never carries an Initial Setup mask into `liveinst`; the first-boot
  finalizer masks `initial-setup.service` only after Anaconda exits, before
  the display manager, and never re-enables GDM. The production path
  converges to greetd → DMS Greeter → Fedora PAM → Labwc.
- The first-boot implementation is single-sourced in
  `environment/production/provision-firstboot.sh` and
  `provision-firstboot.service`; the target provisioner installs those staged
  files instead of generating a second inline copy. The helper masks
  `initial-setup.service` only after Anaconda has exited.
- `production-ready` is a post-Anaconda marker. The live composition branch
  does not create it, the live installer removes any stale copy before
  `liveinst`, and the Kickstart `%post` removes it again after copying the
  live root. This is the guard against the temporary-account race.
- The installed finalizer removes live-only `gdm`, `gnome-initial-setup`, and
  `gnome-session-wayland-session` packages with `--no-autoremove`, and
  acceptance rejects their presence or any GNOME session entry. The live
  greeter removes only the user-facing GNOME session entry while retaining
  GDM's internal greeter session needed to launch Anaconda.
- The hand-off scans the local Anaconda-created `/etc/passwd` record and
  validates exactly one real account. The first-boot finalizer now calls the
  helper inline with `GREYWARD_HANDOFF_NO_REBOOT=1`, so account deletion and
  acceptance happen before the display-manager gates are released. The legacy
  service/path files remain only as disabled recovery artifacts; their target
  symlinks are no longer created, eliminating competing lifecycle owners.
- The live installer now records the Anaconda attempt boundary and requests a
  reboot only when Anaconda reports its authoritative `IPMI_FINISHED` event
  (8). A cancel/abort/failure event (9/10), or an ambiguous result, returns to
  the live desktop without rebooting.
- The branding RPM now installs the canonical GREYWARD symbol into Anaconda's
-  product-logo slot through an automatically detected Fedora-derived profile
  and the supported GTK custom stylesheet hook. Fedora's base identity and
  Anaconda behavior remain unchanged; only the product logo and dark
  sidebar/navigation chrome are customized. No unsupported global dark-theme
  override or Anaconda fork was introduced.

Follow-up on 2026-09-02: Alpha runtime logs proved that the original
`conf.d` placement was ignored. The branding source, RPM file contract,
production acceptance, and manifest now use `/etc/anaconda/profile.d/greyward.conf`;
the branding RPM release is 0.1.0-8.

## Validation performed

- Read-only SSH inspection of Alpha `.149`: identity, package NEVRAs, owned
  Security Center files, enabled/active provider services, and build-artifact
  inventory.
- `pwsh -NoProfile -File .\tests\static.ps1` — passed.
- `pwsh -NoProfile -File .\tools\validate-repository.ps1` — passed.
- Native Git Bash `bash -n` for the component builder, image builders,
  account hand-off, production provisioner, first-boot helper, and acceptance
  script — passed.
- Previous v3 ISO built on Alpha's production builder:
  `/mnt/greyward-iso-build/iso-results/greyward-alpha-composed-20260903-firstboot-fix-v3.iso`.
  SHA-256: `f333a246e946fa66db84e0af64ba13e6a8535d8770eb01fcb594a1eaf2d81587`.
- ISO/squashfs inspection confirmed the staged production provisioner,
  canonical first-boot helper/service, `production-pending`, all four DMS
  GREYWARD plugins, and the Labwc session. It also confirmed no
  `production-ready` marker, masked `initial-setup.service`, or user-facing
  `gnome.desktop` entry is embedded in the live root.
- The same ISO was copied to the local test staging path and its SHA-256
  matched the builder output.
- Frontend contracts: 60 passed; the separate real-Tauri interaction test was
  skipped because no WebDriver runtime was supplied.
- Security Context Python suite: 116 passed, 22 skipped.
- Runtime lifecycle result for v3: **failed** — `greyward` remained after
  installation and GNOME Initial Setup still showed the infinite
  `Initializing...` state. V6 content is validated, but no v6 runtime pass is
  claimed yet.
- V6 test-VM runtime check on 2026-09-04: the exact VMConnect framebuffer
  showed the live GREYWARD desktop after the installer returned; the expected
  automatic reboot was not observed. Hyper-V recorded the VM OS boot at
  19:06:17 with no later worker stop/start event in the inspected interval.
  This is a failed lifecycle gate, not evidence that the v6 wrapper works.
- The same VM has an automatic Standard checkpoint and is currently backed by
  a 32-GiB dynamic VHDX through an `AVHDX` differencing disk. Hyper-V event
  3050 at 18:54:42 reported `0x80070070`: only about 1.97 GiB remained on
  `F:`, so Hyper-V could not create the required 4096-MiB VMRS memory file.
  This host-storage condition must be cleared before repeating the lifecycle
  test; it is recorded separately from the installer reboot defect.
- Rust formatting/test execution was attempted but blocked on the Windows host
  because the MSVC `link.exe` linker is unavailable.

## Remaining limitations and next validation

The previous ISO was booted and manually installed far enough to reproduce the
three lifecycle defects above. V6 contains the corrective source changes, but
the automatic-reboot gate has now also failed to reproduce in the test VM and
the test volume is critically full. V6 cannot be called runtime-verified. On
a clean retry after the VM storage condition is corrected:

1. boot v6 in the test VM and start the live GDM session;
2. verify the Fedora + GREYWARD branded welcome page and supported dark chrome;
3. create the real account in Anaconda and complete encrypted Btrfs/LUKS
   installation;
4. verify the wrapper reboots after a successful Anaconda completion; then
   verify no GNOME Initial Setup loop, no surviving `greyward` user, and no
   GDM/autologin production transition;
5. verify `production-ready`, the Security Center manifest, all contract paths,
   provider readback, greetd/DMS/Labwc login, and the final acceptance marker;
6. reboot and repeat login/logout plus the Security Center runtime gate.

The lack of a source commit/build manifest on Alpha remains an infrastructure
limitation; the new image manifest prevents this ambiguity for future images.
