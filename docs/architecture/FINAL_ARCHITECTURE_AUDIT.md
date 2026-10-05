# TOP 10 CHANGES ACTUALLY WORTH MAKING

Engineering assessment of the local GREYWARD tree and `.149`, 4 October 2026.
Recommendations are **PLANNED**, not implementation or release acceptance.
The [implementation backlog](../plans/PRE_RELEASE_IMPROVEMENTS.md) owns priorities;
the [build audit](BUILD_ISO_AUDIT.md) owns the detailed pipeline assessment.

This is the assessment snapshot before implementation. The user's later native
DMS lock-screen decision supersedes its swaylock recommendation; the
[migration tracker](DMS_1_6_MIGRATION_PLAN.md) owns the current lock contract.

| Rank / ID | Specific change | Why it earns a place before the next ISO |
|---|---|---|
| 1 / A1 | Make DMS compatibility requirements agree with the ISO solver and Update Center | Cached repositories already offer Quickshell `0.3.1-5` and Greeter `1.6.2`; the runtime refuses anything except `0.3.1-2` and `1.6.0`. A green dependency solve can lead to a failed first boot. |
| 2 / A2 | Validate current Security Center/Context RPMs without development overrides | VM RPMs are center release 45/context 46, while source specs are 47/52. The session runs current loose Python source; installed root providers are a different generation. |
| 3 / A3 | Reuse verified RPM and Flatpak downloads across ISO builds | Both download stores are inside disposable directories. Even a branding-only ISO rebuild starts dependency acquisition again. |
| 4 / A4 | Profile and bound Security Context collection work | Two short cgroup samples measured 32.68% and 11.26% of one core. Full projection reads, a posture subprocess and repeated provider reads deserve attention before tiny shell timing differences. |
| 5 / A5 | Give copied session/default policy a package owner | The wrapper, lock entrypoint and DMS unit are unowned on `.149`; the provisioner also overwrites a Security Context RPM-owned unit. RPM updates cannot fully express the installed desktop. |
| 6 / A6 | Generate release identity once and retire same-NEVRA candidate replacement | Fourteen development DMS builds used `1.6.2-1`; selector, spec and manifest repeat that identity. Different bytes behind one package version undermine ordinary upgrade/rollback selection. |
| 7 / A7 | Include Flatpak 1.18.4 and Fedora's fwupd 2.1.8 in the next tested input set | Flatpak fixes concrete privileged file operations and desktop process-group handling; fwupd fixes crashes/leaks and adds hardware support. Both appear in cached Fedora metadata. |
| 8 / A8 | Retire the 2018 GeoIP database as an assumed production dependency | The VM's only country database dates to April 2018. Local-only endpoint hints are useful; obsolete data and host-dependent tests are not. |
| 9 / A9 | Deliver the UWSM Labwc mkdir fix through packaging | Provisioning edits `/usr/share/uwsm/plugins/labwc.sh`; a UWSM reinstall can silently remove that correction. Current upstream source still lacks the directory creation at the write site. |
| 10 / A10 | Remove proven unused production payload, starting with hyprpaper and staged DMS build patches | DMS owns wallpapers; development deployment already kills hyprpaper. Build-time patches and plugin sources are copied into the ISO after the runtime RPM has already incorporated them. |

## Evidence and limits

The source authority is the dirty working tree on `codex/dms-1.6-migration`, not
public GREYWARD GitHub. Inspection found 266 porcelain entries before this audit's
documentation edits. HEAD was `d800c6ce73ed900f544b80d6d04bb3bd5f791da9`
(6 September, wallpaper commit); recent commits do not describe the current
package, security or DMS implementation. Status, relevant tracked diffs and
untracked implementations were inspected. No reset, commit, deployment,
restart, update transaction or lock action was performed for this audit.

Read-only SSH revalidated Fedora 44, UUID
`72ac85e6-feb0-482c-b4cb-410f73abe49b`, MAC `9a:70:47:8f:9d:67`, enforcing
SELinux, active candidate/idle units, API 34, internal sampler and one Quickshell
notification owner. Raw audit samples are retained under ignored
`output/pre-release-audit/`. Earlier migration results are explicitly dated in
[the candidate evidence](../history/migrations/2026-10-04-dms-1.6.2-candidate.md).
No fresh ISO, physical device or rendered interaction test was run here.

External research used project release notes, documentation, repository source,
GitHub release/tag APIs and Fedora engineering pages. Search summaries were
checked against primary pages where a version affected a recommendation.
For example, an older indexed Flatpak result said 1.18.3; the release API and
release page establish 1.18.4. No claim depends on public GREYWARD being current.
Fedora's bootc documentation endpoint was access-denied; the comparison uses
bootc's own documentation instead. UWSM has tags but no GitHub release feed.

## Actual current architecture

| Boundary | Current implementation and runtime evidence | Judgment |
|---|---|---|
| Base | Fedora 44; running kernel `7.1.13-200.fc44`; systemd `259.8-1.fc44`; normal mutable RPM system with encrypted Btrfs installation | Keep Fedora-owned kernel/system integration; this is not an Atomic deployment. |
| Build/install | Four GREYWARD RPMs, selected external OpenSnitch RPM, isolated dependency closure, Everything/netinst ISO remastered with `mkksiso`, Anaconda storage/account creation, gated first boot | Sound division; acquisition and copied configuration are the costly remaining layers. |
| Repositories | Fedora plus `sdegler/hyprland`, `errornointernet/quickshell`, `avengemedia/danklinux`; local offline installation repository | COPRs serve selected desktop packages, not general security truth. Exact selected runtime requirements need solver support. |
| Session | greetd → separately packaged DMS Greeter → Labwc through UWSM → environment import → user units | Keep one compositor/session owner. Environment import is a real Wayland startup dependency. |
| Desktop | Labwc `0.9.6-1.fc44`, UWSM `0.24.3-1.fc44`, Quickshell `0.3.1-2.fc44`, GREYWARD DMS `1.6.2-1.fc44` | Active development candidate, not a proven release tuple. |
| DMS ownership | Unchanged distribution Go backend, embedded vanilla diagnostics, generated upstream QML override, ten patches/twenty upstream files, four first-party system plugins | Good current compromise; no independently maintained full shell fork. |
| Identity/settings | Theme, launcher assets, taskbar configuration and plugin defaults originate in repository payloads; state migration preserves user settings/pins with private backups | Keep identity and user-state ownership; package factory defaults without making later upgrades overwrite preferences. |
| Security Center | Rust domain/backend workspace and Tauri/WebKit frontend; locked Tauri 2.11.5, Wry 0.55.1, patched Tao 0.35.3 for Labwc decorations | Keep product architecture. Avoid a toolkit rewrite to eliminate one narrow decoration patch. |
| Security Context | Unprivileged session projection/notification publisher, typed D-Bus interfaces, root OpenSnitch policy/Secure DNS/scan providers; persistence, sensors, devices and telemetry modules | Keep typed authority and freshness. Separate provider collection from presentation refresh cost. |
| Updates/recovery | User Update Center aggregates DNF5, Flatpak, fwupd and signatures; fixed privileged helper prepares native offline changes with a Btrfs safety point; automatic timer delegates to that helper | One mutation boundary already exists. Do not replace it with DMS's updater or another generic executor. |
| Authentication | Fedora PAM, swaylock wrapper, swayidle 600-second lock/900-second blanking, wlopm; DMS requests hand off externally | Keep. Real unlock/suspend acceptance remains open; process presence is insufficient proof of a secure lock. |
| Network | NetworkManager `1.56.1-2.fc44`, firewalld `2.4.4-1.fc44`, systemd-resolved/Secure DNS, OpenSnitch `1.8.0-1` with GREYWARD control-plane/policy services | These perform different jobs: connectivity, host firewall, DNS policy and application egress. No daemon is redundant merely because it touches networking. |
| File protection/devices | ClamAV `1.4.6-1.fc44`, freshclam, typed scan/quarantine service, USBGuard `1.1.4-1.fc44`, GVfs/portals | Keep action authorization and truthful unavailable state. VM has no representative Wi-Fi/Bluetooth hardware. |
| Software | Flatpak `1.18.2-1.fc44`, Flathub commits in image baseline, Bazaar launcher/selection helpers, native Files/viewers | Update Flatpak; retain offline distribution and normal native file integration. |
| Screenshots | DMS interactive screenshot CLI; grim used by development capture/health | Already adopted. Grim is development evidence tooling, not a redundant user workflow to merge. |
| Runtime state | D-Bus subscriptions plus bounded caches/polling; session presentation and update snapshots; separate DMS config/state/cache | Improve expensive collectors, not the authoritative-state model. UNKNOWN must remain distinct from SAFE. |

This reconstructs source policy, not just whatever happens to be running on the
development guest. `opensnitch.service` is active: an initial probe for
`opensnitchd.service` returned inactive because that is the process name, not
the installed service. Likewise `clamav-update` is absent as an exact installed
package name while freshclam is active; package aliases/providers must be queried
before diagnosing missing antivirus updating.

## Component/version decisions

“Current upstream” is checked as of 4 October, not a promise about future
repositories. Fedora package backports matter more than raw upstream numbers.

| Component | GREYWARD current | Current upstream / consequential difference | Recommendation |
|---|---|---|---|
| Fedora/kernel | F44 / kernel 7.1.13 | F45 is beta; final target 20 October. No demonstrated kernel deficiency in this audit. [Fedora schedule](https://fedorapeople.org/groups/schedule/f-45/f-45-key-tasks.html) | **KEEP** F44 for this release; follow stable Fedora kernel updates. No custom kernel or F45 beta migration. |
| DMS | Candidate 1.6.2 | Latest release 1.6.2: clipboard pinning, truthful battery capability, frame/scale and screenshot fixes are already included. [Release](https://github.com/AvengeMedia/DankMaterialShell/releases/tag/v1.6.2) | **KEEP** implemented migration; resolve A1/A6 and finish its actual acceptance. |
| Quickshell | 0.3.1-2.fc44 | Upstream 0.3.1; cached COPR rebuild is -5. 0.3.1 has lock/sleep/DPMS, unplug, notifications and IPC crash fixes. [Changelog](https://quickshell.org/changelog/) | **WORTH TESTING** -5 as part of A1, not a new upstream migration. |
| DMS Greeter | 1.6.0-1.fc44 | 1.6.2 fixes embedded UI group access and session launch journald handling. Cached COPR has 1.6.2. [Releases](https://github.com/AvengeMedia/dank-greeter/releases) | **WORTH TESTING** 1.6.2 with login/logout and current PAM; numeric match alone proves nothing. |
| Labwc | 0.9.6 | 0.9.8 maintenance branch; latest 0.20.2 uses newer wlroots generation. 0.9.7 fixes layer-shell/disabled-output behavior involving wlopm. [Releases](https://github.com/labwc/labwc/releases) | **WORTH TESTING** 0.9.8 if Fedora-compatible package exists; **LATER** 0.20.x unless it solves a reproduced hardware problem. |
| UWSM | 0.24.3 | Tag API lists 0.27.0; documentation describes changed transient session variables since 0.26. Upstream Labwc write still lacks mkdir. [Tags API](https://api.github.com/repos/Vladimir-csp/uwsm/tags?per_page=5), [source](https://github.com/Vladimir-csp/uwsm) | **KEEP** current version pending focused prototype; fix delivery of existing workaround rather than blindly replacing session semantics. |
| Flatpak | 1.18.2 | Stable 1.18.4 fixes privileged file deletion/overwrite, host process-group signaling and export filtering; cached Fedora 1.18.4 available. [Release](https://github.com/flatpak/flatpak/releases/tag/1.18.4) | **UPDATE NOW** through Fedora; recheck offline imports, app launch, portals and removal. |
| fwupd | 2.1.7 | 2.1.8 fixes parser/crash/leak paths and device recovery, adds dock/device support; available in cached Fedora metadata. [Release](https://github.com/fwupd/fwupd/releases/tag/2.1.8) | **UPDATE NOW** through Fedora; read-only enumeration on VM, physical update path separately. |
| NetworkManager | 1.56.1 | 1.58 exists; networking changes require Wi-Fi/VPN testing. [Upstream release](https://networkmanager.dev/blog/networkmanager-1-58/) | **KEEP** stable Fedora stream; **LATER** manual minor-series replacement without a specific benefit. |
| firewalld | 2.4.4 | Upstream 2.5.2; no demonstrated missing GREYWARD capability. [Release](https://github.com/firewalld/firewalld/releases/tag/v2.5.2) | **KEEP** Fedora-supported version; **IGNORE** a custom build merely to match upstream. |
| OpenSnitch | 1.8.0 | Release API still selects 1.8.0. GREYWARD uses typed policy/control-plane integration, not stock UI. [Release](https://github.com/evilsocket/opensnitch/releases/tag/v1.8.0) | **KEEP** pin and control plane; do not switch to a development snapshot by default. |
| ClamAV | 1.4.6 | 1.4.6 supported LTS patch / 1.5.4 current series. [Functionality/version table](https://docs.clamav.net/appendix/FunctionalityLevels.html) | **KEEP** maintained Fedora LTS engine; signature freshness matters more than a gratuitous engine-series upgrade. |
| USBGuard | 1.1.4 | Latest release 1.1.4; includes IPC privilege and FD/resource corrections. [Releases](https://github.com/USBGuard/usbguard/releases) | **KEEP**; test typed device actions on hardware. |
| Restic | 0.19.1 | Latest release 0.19.1. [Releases](https://github.com/restic/restic/releases) | **KEEP** existing backup boundary; no Borg/rustic replacement before release. |
| Tauri/Tao | Tauri 2.11.5 / vendored Tao 0.35.3 | Tao 0.37.1 exists, with latest notes focused on Windows behavior, not proof of GREYWARD's Labwc decoration needs. [Releases](https://github.com/tauri-apps/tao/releases) | **KEEP** locked runtime now; **LATER** remove patch only after exact native-window parity. |
| GeoIP | API 1.6.12; April 2018 country data | Legacy data/API retired; modern local MMDB support already exists in GREYWARD. [MaxMind retirement](https://blog.maxmind.com/geoip-legacy-databases-have-been-retired/) | **UPDATE NOW** the data-selection policy, not merely the old library package. A8 defines the bounded change. |

Systemd, DNF5, PipeWire and portal versions should remain Fedora-managed; this
audit found no benefit large enough to justify replacing those base components.
The DNF5 offline mechanism is supported upstream and fits current transactions.
[DNF5 offline command](https://dnf5.readthedocs.io/en/latest/commands/offline.8.html)

## Architecture recommendations and redesign filter

### A1 — coherent compatibility at solve, update and startup

**Current problem:** [verify.py](../../packaging/greyward-dms/verify.py) compares
four complete version-release strings. The RPM declares lower-bound/general
dependencies, while [build-offline.py](../../environment/image/build-offline.py)
solves current repositories and checks floors, not this exact tuple. A read-only
mock changed only Quickshell's RPM release from -2 to -3; selection failed with
`Unvalidated DMS compatibility tuple`. Cached metadata offers -5 and Greeter
1.6.2 today. First-boot failure is inferred from these independently observed
paths; a newly built failing ISO was not produced.

**Proposed design:** retain strict backend/generated-shell pairing. For the next
ISO, select an explicitly tested dependency tuple, constrain the solver to it,
and reject closure mismatch before composition. For ordinary post-install
updates, make the same compatibility policy visible to the fixed Update Center
helper: approve a tested replacement set with its manifest, or retain the
incompatible desktop subset while other updates continue. Do not freeze all
Fedora updates indefinitely or silently disable runtime verification.

**Concrete gain:** prevents “install succeeded, shell refused” and update-induced
desktop outages. **Effort MODERATE; risk MODERATE; DO BEFORE RELEASE.** A focused
package-upgrade/reboot/rollback case proves this better than more string tests.

### A2 — validate the package boundary actually being released

**Current problem:** `.149` runs center 45/context 46; specs are 47/52. The active
session drop-in points at a development `session10_bus.py`. Its `user_bus.py`
hash matches local source, but differs from the installed package file. The
installed package lacks `shell_runtime.py`; that feature is supplied by the
overlay. Non-root `rpm -V` also found changed D-Bus configuration/control-plane
files; permission errors in that output are not missing-file proof.

**Proposed design:** use the existing builder to package current source, then
validate in a dedicated account/session without loose-source overrides and
with package-owned root providers. Do not overwrite the recovery guest merely
to obtain a clean-looking status. Link resulting package bytes to the input
manifest used for the ISO. **Gain:** catches real source/package omissions.
**Effort LOW–MODERATE; risk LOW; DO BEFORE RELEASE.**

### A3 / A5 / A6 — construction and ownership

The [build audit](BUILD_ISO_AUDIT.md) specifies these designs. Reuse verified
download objects with fresh solver databases (A3), install session/default
policy through a small `greyward-session` RPM (A5), and derive spec/runtime
path/selector identity from one release input with monotonic RPM revisions
(A6). They replace repeated network work, unowned copied executables and
independently repeated release literals. A3: **MODERATE effort / LOW–MODERATE
risk**; A5: **MODERATE / MODERATE**; A6: **LOW–MODERATE / MODERATE**. All are
**DO BEFORE RELEASE**, with A5 limited to static ownership first.

### A4 — shared, bounded security collection

**Current problem:** [ShellRuntime](../../security-center/security-context/greyward_security_context/shell_runtime.py)
wakes every two seconds, performs full summary work on dirty state or ten-second
expiry, and refreshes privacy/device state on intervening ticks. The summary's
five-second posture cache invokes the Security Center CLI. That process creates
a new Rust collection/cache each invocation; its in-process three-second cache
cannot persist between CLI launches. Capsule construction reads USB and Secure
DNS, and full summary adds persistence/history/profile reads.

**Runtime evidence:** five-second cgroup sample 32.68% of one core; independent
15-second sample 11.26%, same main PID. DMS was 0.66% in the first sample; Update
Center 0%. One `--print-posture` completed in 671 ms. These are short development
observations with uncontrolled user activity, not idle budgets or attribution.
Observed children were persistent `pw-dump --monitor` and clipboard watchers;
they are already event-oriented and should not be replaced with polling.

**Proposed design:** first profile provider calls/counts and invalidation causes.
Coalesce dirty events, avoid rebuilding unchanged provider results and renew
presentation leases only from actual valid observations. If posture subprocess
work dominates, expose the existing Rust evaluator through a small headless
CLI snapshot path that excludes unrelated Overview enrichment; evolve to one
shared evaluator only if that bounded change is insufficient. Keep all typed
schemas, failure states, deadlines and signals. **Gain:** less repeated scanning
and UI/session CPU with no loss of security meaning. **Effort MODERATE; risk
MODERATE; PROTOTYPE BEFORE DECIDING** on a larger service refactor. The profiling
and bounded duplicate-work fix are **DO BEFORE RELEASE** if the load reproduces
with packaged providers. A full Rust rewrite of Security Context is not justified.

### A8 — useful local country hints without fossil data

**Current problem:** the package spec requires GeoIP/GeoLite legacy data; VM
`GeoLiteCountry.dat` is dated 4 April 2018. The resolver supports modern MMDB,
secondary data, geofeed and ccTLD fallback, but a legacy-only vote still produces
MEDIUM confidence with no data-age check. IPv6 and changed assignments cannot
be treated as accurate current locations. Ambient database presence also caused
test failures during migration until fixtures isolated it.

**Proposed design:** make location data an explicit optional input, with source,
age and availability in the projection. Prefer an approved current local MMDB
when supplied and ensure its reader dependency is present. Otherwise return
unknown/weak labelled hint and stop requiring fossil data. Do not introduce a
runtime network lookup, mandatory MaxMind account or undisclosed database fetch.
Replace ambient-path tests with injected database fixtures. **Gain:** less false
confidence and two obsolete mandatory packages removed. **Effort LOW–MODERATE;
risk LOW–MODERATE; DO BEFORE RELEASE.**

### A9 / A10 — narrow compatibility debt and release cruft

**Current problem:** the former `environment/production/patch-uwsm-labwc.sh` (subsequently retired)
mutates a package-owned plugin; reinstalling UWSM can discard the patch. The
[current upstream plugin](https://raw.githubusercontent.com/Vladimir-csp/uwsm/master/uwsm-plugins/labwc.sh)
still writes the computed drop-in without making its directory. Merely upgrading
does not establish removal eligibility.

**Proposed design:** carry the small patch in an explicit UWSM package build or
use a documented plugin override after verifying lookup precedence. Keep its
fresh-login/fresh-home regression test; remove mutation from provisioning once
delivery is proven. **Gain:** durable update behavior. **Effort MODERATE; risk
MODERATE; DO BEFORE RELEASE**, alongside A1 rather than a broad UWSM redesign.

A10 is a bounded reference/runtime audit: remove hyprpaper after checking the
fallback session, remove build-only DMS patch/plugin-source staging once the
stage validator no longer requires it, and leave grim/authoring tools outside
production. **Effort LOW; risk LOW–MODERATE; DO BEFORE RELEASE.** Making Hyprland
an optional package set is **POST-RELEASE** unless the product withdraws fallback
support explicitly; its current manifest declares a supported fallback.

## DMS post-migration assessment

The chosen hybrid boundary is appropriate today. The backend stays upstream,
QML is assembled rather than independently forked, whole-shell selection is
explicit, and first-party plugins use release-matched system delivery. A pure
plugin/configuration design still cannot replace core Polkit/notification/bar
behavior with demonstrated parity. Keeping narrow patches is cheaper than
building another shell or redesigning GREYWARD interactions.

Debt already removed includes the unused RunningApps scale patch, changelog
source patch replaced by a migration marker, redundant single-window minimize
hunks, old icon ordering logic and external dgop as a production dependency.
External dgop remains installed only for development rollback. Source archives
and vanilla diagnostic UI are inputs/features, not an old shell to reinstall.

Ten patches still touch twenty upstream files: identity/interactions, settings,
icons, notification styling/quiet semantics, popout reclamation, repeated custom
lock signals and Update Center routing. Five plugin QML files plus network math
remain downstream. The new lock/update hunks explain why the original eighteen-
file estimate was not met. Do not count generated 638 DMS + 74 common QML files
as an independently authored fork. Keep the patch manifest and exact preimages.

DMS 1.6 already supplies internal sampling, async loading, explicit selection,
system icon improvements, screenshot metadata and split settings/session state.
Do not propose adopting them again. Remaining improvement is primarily packaging
and lifecycle compatibility (A1/A5/A6), followed by evidence-backed deletion when
upstream adds exact extension points. Changing lock authority to DMS, enabling
Island/dynamic themes, or a second updater has poor pre-release return.

## Performance interpretation

Earlier matched post-panel-cycle ten-minute runs recorded combined RSS medians
866,271,232 bytes (normalized 1.5.3) and 584,966,144 (custom 1.6.2), approximately
32% lower. CPU medians from cgroup accounting were 5.307% versus 0.203% of one
core. These are observations, not a complete four-way/hardware acceptance.
Warm start/restart to settings IPC measured candidate p95 4,239/4,233 ms; first
old run 3,836/3,782, repeated old run 4,272/4,664. Baseline variance leaves the
budget unresolved; protocol completion is not rendered latency.

This audit's boot inspection reported 19.643 s total, graphical target at
6.552 s userspace and greetd at 4.996 s. The development boot did not execute a
fresh production first-boot path, so those numbers cannot estimate installation.
Likewise instantaneous RSS and lifetime `%CPU` from `ps` are not idle evidence.

Next useful performance work: bounded profiling of A4 on package-only services;
existing real Tauri Overview/Apps/Files/Devices/Updates navigation suite; rendered
first-open/revisit observations; one measured cold/warm image build after A3.
No new hours-long timing exercise or speculative renderer/toolkit replacement
is required to decide these priorities.

## Functional security assessment

The important boundaries survive the migration: root-owned runtime selection,
0600 same-user backend socket checks, typed Security Context actions, caller-UID
scan/quarantine operations, D-Bus policy separation and the fixed Polkit update
helper. Presentation hints are not authoritative evidence. Root services have
different necessary file/system capabilities; merging them for a smaller daemon
count would broaden privilege and complicate failures.

The automatic-update timer delegates to the same fixed helper as reviewed
updates; it is not a redundant second executor. However, A1 applies to it too:
preparing a desktop dependency upgrade must respect the tested shell tuple.
Do not infer safety from the timer being enabled; it was inactive on this guest.

The earlier real-lock termination caused Labwc's expected protected black
surface. It was recovered and acknowledged by the user; it did not prove password
unlock or suspend correctness. Keep swaylock and Fedora PAM, and retain a small
real-authentication gate. No broad privilege API, PAM rewrite, enforcement disable,
or speculative certification/signing programme is recommended by this audit.

## THINGS WE CAN DELETE OR SIMPLIFY

| Item | Classification / condition |
|---|---|
| Production hyprpaper dependency | **REMOVE** after fallback reference check; no canonical wallpaper owner requires it. |
| DMS patch and first-party source copies in the completed installer stage | **REMOVE** once stager/validator consume the packaged receipt; retain source in Git/build inputs. |
| GeoIP legacy mandatory dependencies and fallback confidence assumption | **REMOVE/REPLACE** under A8; preserve modern local lookup and unknown states. |
| Provisioner's overwrite of the RPM-owned Security Context user unit | **REMOVE** after current package receipt is required; source-staging already rejects stale security source manifests. |
| Same-NEVRA candidate replacement and repeated runtime identity literals | **REPLACE** with A6; leave historical receipts intact. |
| Editing UWSM's installed plugin in provision.sh | **REPLACE** under A9; the underlying mkdir fix remains necessary. |
| Repeated dependency downloads into throwaway roots | **SIMPLIFY** with A3; fresh verification roots stay. |
| Hyprland/portal fallback payload | **KEEP** while declared supported; optionalize later, not silent deletion. |
| dgop 1.6, legacy DMS payload and candidate backups on `.149` | **DEVELOPMENT ONLY**, retain until rollback gates end; exclude from fresh production selection. |
| Packer, SSH/Hyper-V access, compilers, build logs and diagnostic tools | **DEVELOPMENT ONLY**; production package list already separates the intended boundary. Audit actual closure for transitive leakage. |
| First-boot gate, pending/ready/error markers, media closure checks | **KEEP**: they prevent known incomplete-login/install failures. |
| Narrow DMS identity/security patches | **KEEP** until an exact replacement passes parity, not because upstream offers a similarly named feature. |

## KEEP AS-IS

Keep Fedora's package/SELinux/PAM model, Anaconda's encryption and account UI,
Labwc as the canonical compositor, UWSM session ownership, the DMS hybrid,
first-party typed security plugins, Update Center's native-provider delegation,
separate privileged providers, local-only security state, and portable preference
capture instead of copying a development disk. These already solve useful
problems. Replacing them would consume more debugging time than this release gains.

Keep persistent PipeWire/clipboard watchers and existing Rust/Cargo caches.
Cache improvements should build on them, not claim they do not exist.
Keep four separate RPM responsibilities; adding a session policy RPM is more
useful than merging frontend, Python authority and boot branding into one large
package. The build alternative comparison explains why KIWI is worth a later
prototype and bootc is a separate product project, not a quick ISO optimisation.

## Small final manual-test list

1. Lock/unlock with the real password, wrong-password rejection, repeated
   loginctl lock, suspend/resume and display wake. Never kill the real locker.
2. Taskbar/launcher hitboxes, grouped minimise, notification actions and Polkit
   readability at the user's normal scaling; multi-output/hotplug where available.
3. On physical hardware: Wi-Fi/Bluetooth/VPN/DNS, microphone/camera/USB permission
   readback, and firmware/device handling applicable to that machine.

Fresh ISO construction/installation, packaged-source drift, tuple validation and
collector profiling are engineering tasks, not items transferred to the user.
The audit itself is complete when these reports and their evidence are validated;
the recommendations and release gates remain separately unimplemented/unrun.
