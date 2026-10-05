# GREYWARD installer compatibility investigation

Status: **IN PROGRESS — 5 October 2026.** The user rejected the October installer
test. No replacement ISO or installation is accepted until the actual interactive
flow passes. Native DMS locking remains canonical.

## Proven baseline and inspected evidence

The retained September artifact is
`greyward-installer-20260919-gitstatus-cleanup-security-autoupdate-terminalbrief.iso`,
SHA-256 `fb578bfd6797b9cc6d1e5bef7b52620a5622ea7bfc5ba0a4e2f631f13630b953`.
The inspected October artifact is `greyward-installer-20261004-6-6-53-58.iso`,
SHA-256 `30db0c70ca747ca9e56f9ae8a1aff8ab7c6a036829b6eff7a39faf0288cbe25a`.
Both were read directly on .149, without changing a running test installation.

Git commit `2c83da1` (6 September) already records the direct Fedora Everything
Anaconda workflow, graphical account ownership, encrypted Btrfs and `updates.img`.
The later working-tree/ISO implementation added offline closure, target-root
payload verification and first-boot finalization. Git HEAD alone therefore cannot
reconstruct the proven September artifact; its embedded files are the baseline.

| Required behavior | Known-good implementation | October product artifact comparison |
|---|---|---|
| GREYWARD Anaconda | `inst.profile=greyward`, `inst.updates` on every kernel entry; profile under `/etc/anaconda/profile.d`; custom CSS/logo | Same boot routing in three ISO configurations and the appended EFI partition. All three customization files are byte-identical to September. |
| Interactive account | No `user` or `rootpw` command; `hidden_spokes` and `hidden_webui_pages` explicitly empty | Preserved in the product Kickstart/profile. |
| Interactive LUKS | `autopart --type=btrfs --encrypted` without a passphrase | Preserved in the product Kickstart. |
| Storage flow | Native Everything profile, `zerombr`, `clearpart --all --initlabel`, encrypted Btrfs autopartitioning | Preserved; no replacement partition implementation. |
| First encrypted boot | Branding RPM installed in `%post`, select GREYWARD Plymouth theme, regenerate all target-kernel initramfs images | Same implementation. Running the installer kernel's initramfs rebuild would be incorrect. |
| First-boot handoff | Copy verified payload into `/usr/lib/greyward/installer/production`; gate login while offline provisioning/acceptance runs; Anaconda owns reboot/eject | Preserved. October adds explicit reboot-request/entered markers and a five-second bootloader timeout. |

The customization hashes in both inspected artifacts are:

- profile: `49e5eb541c51ea786bf6b35068dac4b9e0ea896387bac17ee2bd75f358105d0b`;
- stylesheet: `b1ff112847c060e0341946cf296e68f61bfeda7793b88936f8a014012a33282c`;
- logo: `235d90ce3f537ca359b608a296a197cbb97bf0236e3f8e98551b18439fe2d194`.

The compressed `updates.img` hashes differ because archive metadata differs;
the extracted customization bytes do not. Inspection evidence is private under
`/mnt/greyward-build/pre-release/installer-regression-audit/`.

## Demonstrated regression boundary

The agent introduced a second bootable test-answer DVD, built from stock Fedora
media. It was attached at SCSI location 2, ahead of the product DVD at location 1
when the new disk was blank. This validation path was wrong:

- its boot entries used `GREYWARD-TEST-ANSWERS:/answers.ks`;
- it omitted `inst.profile=greyward` and `inst.updates` entirely;
- it supplied a predefined account and encrypted-disk passphrase;
- it supplied `rd.plymouth=0 plymouth.enable=0`, inherited by the installed boot.

That path demonstrably bypasses all the user-facing behavior under review and
explains the stock Fedora/prompt-free automated run. It is invalid acceptance
evidence even though it used the product stage2 and package payload. It must
never be used again to validate installer compatibility. The user's running VM
and installer are left untouched. Product-only graphical verification is still
required; matching artifact contents alone is not a graphical PASS.

## Restoration and prevention

Keep the known-good Kickstart, profile, CSS, logo, storage logic, Plymouth and
first-boot flow. Packaging/caching changes adapt around those boundaries.
`environment/image/installer-contract.py` now inspects the composed product
media before publication, including its actual appended EFI partition. It rejects
foreign Kickstart routing, preseeded account/encryption, hidden native pages,
changed partition policy, missing/stale customization and disabled Plymouth.
Focused mutation fixtures exercise these failures. This is a media-contract
gate; it does not replace actual installer acceptance.

Graphical acceptance must boot only the published product ISO on a fresh,
isolated disk. No answer DVD, automated credentials, additional Kickstart or
Plymouth-disabling diagnostics may be present. Preserve the previous disk/ISO,
disconnect networking, and never interfere with a VM the user is installing.

## Required actual-flow results

Replacement candidate: `output/iso/greyward-installer-20261004-interactive-6-6-53-58.iso`,
SHA-256 `c8df013a9583fe86b12454810078424f4e73e267cc2378ee17c35f644c8f4de6`.
The build passed the composed-media contract (including the appended EFI image),
exact offline dependency resolution, extracted payload checksums, production
stage validation and the recursive-copy check. All 60 Fedora image tests passed;
both required repository gates passed. These are factory/source results.

Actual console checks use only the new `GREYWARD-INSTALLER-COMPAT-20261004`
VM (`a6097e15-46e0-4265-8833-cb7f49475e9d`), a blank 60 GiB disk on the host's
C: volume, and disconnected networking. The C: location avoids exhausting F:
while preserving existing test disks. Its one DVD is the byte-verified replacement
product ISO. Neither existing user VM was changed. Private evidence:
`output/pre-release-execution/installer-compatibility-vm.json`,
`interactive-iso-build.log`, `interactive-image-fixtures-final.log`.

Product-only VMConnect observation shows the GREYWARD symbol/custom dark styling,
native `User Creation` with `No user will be created`, and an automatically opened
`DISK ENCRYPTION PASSPHRASE` dialog. Both passphrase fields are empty and
`Save Passphrase` is disabled. There is no predefined account or supplied key.
At this first observation the console was left at that prompt; installation had
not begun. The user subsequently completed installation and reached the desktop.
Preserved private
evidence: `installer-interactive-prompt.png` and `installer-console-observation.json`
under `output/pre-release-execution/`. Credentials and authenticated encrypted
boot require the user's interactive input; no answer-media substitute is allowed.

PASS requires observed evidence. FAIL below means the required acceptance gate
is not closed; it does not invent a product defect when a test has not run.

| Gate | Result | Evidence / outstanding work |
|---|---|---|
| GREYWARD Anaconda customization visible | PASS | Product-only VMConnect screenshot shows GREYWARD symbol and custom styling; branding bytes also match September. |
| Account creation offered | PASS | Native User Creation page visibly requires configuration; no account is preseeded. |
| LUKS/encryption setup offered and working | FAIL | Empty interactive passphrase prompt is observed; successful encrypted install/unlock is still pending. |
| Expected partition/storage flow preserved | FAIL | Native encrypted Btrfs contract preserved; actual storage page and written partitions remain pending behind passphrase prompt. |
| GREYWARD first-boot handoff preserved | FAIL | The user's completed installation reaches the desktop; first-boot logs and media-removed boot remain unverified. |
| Installed desktop reaches current DMS 1.6 GREYWARD environment | FAIL | DMS desktop observed, but its default duck wallpaper and missing greeter background fail GREYWARD identity acceptance. |

## Fresh-install background and protection regressions

The user reported missing greeter/desktop backgrounds and two protection review
cards after completing this installation. The new isolated VM's disconnected
adapter was connected to Default Switch without restarting it; its taskbar then
showed a local address and successful public-IP lookup. No existing VM was changed.

Both canonical JPEGs are present in the payload. Two consumer defects explain
the backgrounds:

- The separately packaged `dank-greeter` 1.6.2 reads `wallpaperPath` from
  `/var/cache/dms-greeter/session.json`. The previous helper copied an image but
  supplied only the bundled shell's newer `greeterWallpaperPath` setting.
  The helper now atomically writes the actual standalone greeter's selection,
  preserving unrelated state. See upstream [SessionData](https://github.com/AvengeMedia/dank-greeter/blob/v1.6.2/quickshell/Common/SessionData.qml)
  and [GreeterContent](https://github.com/AvengeMedia/dank-greeter/blob/v1.6.2/quickshell/Modules/Greetd/GreeterContent.qml).
- Labwc attempted wallpaper IPC for ten seconds after the service became active;
  this did not establish shell readiness. Session migration now seeds the
  wallpaper before QML starts when session state is absent, retaining a legacy
  wallpaper choice and leaving existing session state untouched. Both autostarts
  no longer overwrite user selections through that timing loop.

Session RPM `0.1.0-7` built successfully. Fedora image fixtures (62) and migration
fixtures (18) pass, including cache updates, malformed/symlink preservation,
fresh state and existing wallpaper choices. Private evidence is under
`/mnt/greyward-build/pre-release/logs/wallpaper-*` and
`/mnt/greyward-build/pre-release/wallpaper-regression-audit/`.
These are package/source results; the current installed VM still has the previous
payload. Replacement-image and actual background acceptance remain open.

ClamAV's collector already distinguishes first download (`INITIALIZING`) from
unavailable/stale protection. The shell projection discarded that distinction,
creating the generic Review card. It now preserves initialization and presents
preparation as activity, with scanning readiness unconfirmed. Unknown definition
age remains unknown. Unavailable, outdated and failed protection still require
attention. Center 54/Context 59 built with verified payload receipts. All 227
Security Context tests pass both from source and with all 30 loaded project
modules pinned to the extracted Context RPM. Rust fmt/tests/Clippy and all 78
frontend contracts pass. Exact security/session component cache reuse passes.
Evidence: `logs/fresh-install-package-extraction.log`,
`logs/fresh-install-packaged-context-tests.log`,
`logs/fresh-install-packaged-context-imports.json` and
`logs/fresh-install-component-reuse.json`. Read-only extracted-module checks
on .149 report ClamAV CURRENT and Secure DNS SecureProvider; these are explicitly
development-host observations, not fresh-install acceptance. No changed package
was installed and no running service was restarted. Secure DNS's actual installed
state and service logs have been requested; its warning is not suppressed merely
because the system is freshly installed.

The user's 4 October terminal capture subsequently reports `DoTUnavailable`,
one `eth0` link, DHCP resolver `172.26.144.1`, and `route_domains=["mshome.net"]`.
This establishes the domain guard that skipped provider setup. A switch change
was rejected by the user as a VM workaround and reversed: the test VM remains
on Default Switch. The Hyper-V-specific prototype was rejected before deployment.
Context 61 was a diagnostics-only candidate; it did not resolve local/public DNS.
The installed VM still reports unavailable; no DNS PASS is claimed.
The two diagnostic commands were pasted into one journalctl invocation; its
`Failed to add match 'resolvectl'` error is command syntax, not a resolver error.

On 5 October the actual Context RPMs embedded in September 11, September 19,
September 19 wallpaper and October 4 media were extracted and compared. All four
contain a byte-identical DNS reconciler (SHA-256
`2645314fa8628d41439f335752c4453be8ef24e3551fbb8e9a881e54f18cb4fb`). The
September 19 wallpaper and October 4 OpenSnitch selector ASTs also match. All
four enforce DNS ports 53/853, enable the DNS service, and neither provision a
read-only marker nor a persistent resolver override. Executing each extracted
reconciler against the supplied DHCP/domain fixture reproduces `DoTUnavailable`
without attempting a provider. The optimized image path did not remove a working
DNS setting; the current network exposed an existing compatibility gap.
Evidence: `output/pre-release-execution/dns-history/extracted-iso-dns-inputs.json`,
`dns-history-comparison.json` and `historical-private-domain-reproduction.json`.

The generic candidate preserves DHCP/private domains and uses a reversible public
scope inside resolved. It does not identify Hyper-V or change the user's VM.
All 239 Context source tests pass. Real isolated resolved instances passed public
DoT/DNSSEC, private resolution, no public query at the private fixture server and
restoration for `home.arpa` and `mshome.net`; the host's resolver/interfaces remain
untouched. Evidence: `logs/portable-dns-resolved-home-arpa.log`,
`logs/portable-dns-resolved-mshome-net.log`, `logs/portable-dns-source-context-tests.log`.
Center 57/Context 62 built and pass 239 extracted/installed-package tests with
31 project imports pinned to RPM bytes. The actual root service on .149 passes
public encryption, private resolution, scoped admission, no public query at the
private fixture, and restoration; no recent AVC was found and the DMS PID stayed
unchanged. Evidence: `logs/portable-dns-installed-service-canary.log`,
`logs/portable-dns-installed-context-tests.log`, `logs/portable-dns-avc-recent.log`.
Only .149's paired Security packages were updated; the user's installation VM is
untouched. Replacement-image acceptance remains open. The [Secure DNS contract](../security/SECURE_DNS_IMPLEMENTATION_PLAN.md)
records the runtime scope and precise permission/rollback boundary.

A repeated 58/63 installed-service canary subsequently found that SIGHUP clears
removed DNS servers but retains an omitted global `Domains=` assignment. The
earlier restoration check covered link metadata and file removal, missing this
orphaned `~.` route. Its complete-restoration claim is superseded. The new
candidate explicitly empties and observes the public scope before removing its
runtime file; a recognized removal marker supports retry after interrupted reload.
Tests now assert global route removal as well as link restoration and mode reentry.
The test restored the development host's original link settings; the user's VM
was untouched. Center 59/Context 64 built with verified receipts and clean installed
RPM integrity. All 242 tests pass with 31 imports pinned to extracted and installed
RPM modules. Two consecutive actual-unit canaries pass public/private resolution,
wheel-authorized NetworkDefault, return to Automatic, and global/link restoration;
DMS's PID is unchanged. The real audit-log query found no recent AVC.
Evidence: `logs/portable-dns-restoration-installed-service-canary-{1,2}.log`,
`logs/portable-dns-restoration-installed-context-tests.log`,
`logs/portable-dns-restoration-avc-recent.log`, and
`logs/portable-dns-restoration-component-reuse.json`. The final ISO is being
published from this exact set as
`output/iso/greyward-installer-20261005-portable-dns-6-7-59-64.iso`, SHA-256
`736b87cefbe9ef3ed0c4b766538f9ab1d606400643d9aad673451f0f998f7a94`.
Factory checks pass; fresh-install acceptance remains open for the user's test.

The build/run procedure remains [ISO_CREATION.md](ISO_CREATION.md); approved
engineering statuses remain in [PRE_RELEASE_IMPROVEMENTS.md](../plans/PRE_RELEASE_IMPROVEMENTS.md).
