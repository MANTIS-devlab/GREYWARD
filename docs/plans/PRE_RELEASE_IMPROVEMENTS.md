# GREYWARD pre-release implementation backlog



**IN PROGRESS — 5 October 2026.** This is the actionable result of the

[architecture audit](../architecture/FINAL_ARCHITECTURE_AUDIT.md) and

[build/ISO audit](../architecture/BUILD_ISO_AUDIT.md). It does not re-open completed

DMS migration implementation or certify its remaining acceptance gates.



The user subsequently selected native DMS locking. Its current implementation and

SSH-only checks are recorded in the [migration tracker](../architecture/DMS_1_6_MIGRATION_PLAN.md).

This supersedes the assessment's external-lock recommendation.



Execution remains IN PROGRESS. Native DMS locking is canonical; retired external

lockers are not a rollback target. The package-only and source gates below are

separate from the completed cold/warm closure and still-open final ISO and clean-install gates.



On 4 October the user took over ISO testing. The rejected candidate is
`output/iso/greyward-installer-20261004-6-6-53-58.iso`, SHA-256
`30db0c70ca747ca9e56f9ae8a1aff8ab7c6a036829b6eff7a39faf0288cbe25a`.
Factory and package checks passed, but installer acceptance failed. The agent's
auxiliary bootable answer DVD bypassed branding, account and encryption prompts
and disabled Plymouth. Its installation progress is invalid compatibility
evidence. The retained September product ISO and October product ISO preserve the
same native interactive installer boundary; actual product-only acceptance is
still required. See [the compatibility investigation](../architecture/ISO_INSTALLER_COMPATIBILITY.md).
The replacement build adds composed-media checks and uses the same package tuple.
It published `output/iso/greyward-installer-20261004-interactive-6-6-53-58.iso`
(SHA-256 `c8df013a9583fe86b12454810078424f4e73e267cc2378ee17c35f644c8f4de6`)
with factory gates passing. Product-only interactive acceptance remains separate.
The new isolated console confirms branding, User Creation and an empty LUKS
passphrase prompt. The user subsequently completed installation and reached the
desktop; encrypted
boot/storage logs remain unverified. Missing desktop/greeter backgrounds and
fresh protection warnings reopened installed-image acceptance. Session 7 and the
Context 59 candidate addressed confirmed consumer/projection defects. Supplied DNS state identified the Default Switch private search suffix;
the switch workaround was reversed. Four actual retained ISO packages reproduce
the same historical domain guard; a portable split-scope candidate passes 239
Context source tests and isolated real resolved checks. Installed-image DNS is
still unaccepted. See the compatibility investigation for evidence.
Fresh install/login/reboot and native-runtime rollback remain IN PROGRESS.
Native DMS locking remains canonical; `.149` was not rebooted.

## Approved execution status



Updated 5 October after portable-DNS package validation. Evidence paths below refer to the private

`.149` execution workspace `/mnt/greyward-build/pre-release/`; generated artefacts

are not committed. VALIDATED is reserved for completed item acceptance.



| Approved item | Status | Evidence / work still required |

|---|---|---|

| A1 | IN PROGRESS | Exact Quickshell 0.3.1-5/Labwc 0.9.6-1/UWSM 0.24.3-1/Greeter 1:1.6.2-1 tuple installed; manifest-derived runtime, Update Center exclusions and ISO solver constraints implemented. Final 59/64 ISO closure and installer media checks pass (`logs/portable-dns-restoration-iso-build.log`); clean-install and native-runtime rollback checks remain open. |

| A2 | VALIDATED | Final Center 59/Context 64 installed on .149 with no loose-source service overrides and clean root RPM integrity. All 242 Context tests pass with 31 extracted/installed imports pinned to RPM bytes; two actual-unit cycles pass encrypted public/private DNS, wheel-authorized NetworkDefault, return to Automatic, and global/link restoration. DMS PID unchanged; real audit-log query has no recent AVC. Evidence: `logs/portable-dns-restoration-installed-context-tests.log`, `logs/portable-dns-restoration-installed-service-canary-{1,2}.log`, `logs/portable-dns-restoration-rpm-verify.log`, `logs/portable-dns-restoration-typed-dns-read.log`. Packaged Rust tests pass; unchanged Rust sources retain fmt/Clippy evidence and 78 frontend contracts pass. Earlier package-window startup/route benchmarks remain dated evidence. Clean-install and final visual acceptance are separate, open gates. |

| A3 | VALIDATED | Actual empty-cache acquisition retained 3,614,681,973 bytes; warm run retained zero new bytes and received 208,064 interface bytes. Both fresh resolver checks and all six exact Flatpak installs passed in empty network namespaces; inventories match (`cold-evidence/`, `warm-evidence-52-57/`). All 48 image fixtures passed (`logs/final-image-53-58-fixtures.log`). Final metadata-only package revisions are freshly resolved again during ISO composition. |

| A4 bounded/profiled work | VALIDATED | Six untraced 10-second Context samples: median 17.5744% of one core before, 15.8453% after, 15.3155% final. Alternating old/new/old commands preserve consumed state/counts; headless wall median 0.633 s versus GUI 0.736 s. Twenty invalidations coalesce into one callback; provider scan counts are unchanged. See `profile-final/consumed-contract-and-timings.json` and the performance record. No broad evaluator refactor is justified; no memory saving is claimed. |

| A5 | IMPLEMENTED | Session 0.1.0-6 installed; fresh-wallpaper state fix built as 0.1.0-7 with 18 migration and 62 image fixtures passing; package defaults/helpers/units/PAM ownership verified. Identical unowned root-provider units backed up and retired; preferences preserved. Complete clean-install ownership acceptance pending. |

| A6 | IN PROGRESS | DMS 1.6.2-6 built offline with strict preimages and unchanged backend. All receipt hashes verified for DMS 6/session 6/Center 53/Context 58/branding 15. Actual component reuse plus corruption/identity fixtures passed. New Center 54/Context 59/session 7 receipts and exact warm component reuse pass (`logs/fresh-install-component-reuse.json`). Final 59/64/session 7 receipts and exact verified warm component reuse pass (`logs/portable-dns-restoration-component-reuse.json`). Native-runtime rollback pending on clean test installation. |

| A7 | IN PROGRESS | Flatpak 1.18.4/fwupd 2.1.8 installed. Actual firmware enumeration succeeded (`logs/fwupd-devices.json`); this is Hyper-V device evidence. Offline app operations/portals and final installed image remain pending; physical firmware is manual. |

| A8 | VALIDATED | Optional local source, age/confidence/UNKNOWN propagation and UI hints implemented; fossil mandatory data removed. Missing/IPv6/stale cases, country UI contract, installed 225-test suite and typed API reads passed (`logs/final-installed-58-pinned-tests.log`, `logs/final-57-api-*.json`). Final 58 changes are package metadata only. |

| A9 | IN PROGRESS | UWSM mutation retired; package-owned launcher prepares both directories. Unmodified upstream Labwc plugin exercised with fresh HOME/runtime before/after two exact RPM reinstalls; RPM integrity clean (`logs/final-image-fixtures.log`). Clean installed-session login pending. |

| A10 | IMPLEMENTED | Unused hyprpaper, staged DMS patch/plugin copies and duplicate package-owned unit overwrite removed. Complete warm stage/media checks passed (`logs/final-iso-warm-build.log`, PRODUCTION_STAGE_VALIDATION=PASS, 28 declared paths). Final 59/64 ISO repeats these checks successfully (`logs/portable-dns-restoration-iso-build.log`). |

| Relevant A11 testing | IN PROGRESS | Exact Quickshell -5/Greeter 1.6.2 tuple installed; API 34, four plugins and native password unlock observed. DMS -6 automatically reclaimed a secure surface after a locked-session restart (`logs/native-6-lock-before.json`, `logs/native-6-lock-after.json`). Fresh greeter/login/image checks pending. Optional Labwc 0.9.8 is DROPPED WITH REASON: configured Fedora repositories offer 0.9.6-1 only; no forced wlroots generation change. |



Scores use 1–5: benefit and maintenance reduction increase with value; effort

and debug/regression risk increase with cost. Order follows practical release

impact, not an artificial arithmetic score. Related micro-work is grouped.



| Priority / ID | Change | Benefit | Effort | Debug risk | Maintenance reduction | Why now / completion evidence |

|---|---|---:|---:|---:|---:|---|

| DO NOW / A1 | Align DMS tuple, ISO solve and Update Center compatibility | 5 | 3 | 3 | 4 | Available repo versions already conflict. A resolved compatible closure, package upgrade/reboot, READY desktop and previous-runtime restore must pass. |

| DO NOW / A2 | Build current center/context RPMs and validate without loose-source overrides | 5 | 2 | 2 | 3 | `.149` mixes source with older RPMs. Current packaged session/root providers must expose the same typed behavior and truthful failures. |

| DO NOW / A7 | Include Fedora Flatpak 1.18.4 and fwupd 2.1.8 in tested inputs | 5 | 2 | 2 | 2 | Concrete upstream fixes; cached Fedora builds available. Test offline Flatpak install/launch/remove/portal paths, firmware enumeration and applicable hardware separately. |

| DO NOW / A6 | Generate release ID/spec paths and preserve unique package revisions | 4 | 2 | 3 | 4 | Distinct DMS candidate bytes share -1. New downstream payload must have distinct identity; selector upgrade and recoverable previous RPM/state must work. |

| DO NOW / A3 | Add persistent RPM/Flatpak object caches with fresh verification roots | 5 | 3 | 2 | 4 | Every compose discards downloads. A cold/warm build must reuse unchanged objects and still catch incompatible or stale closure. |

| DO NOW / A5 | Package static session/default policy; remove duplicate RPM-unit overwrite | 4 | 3 | 3 | 5 | Unowned helpers and copied RPM-owned units make fresh images diverge. Compare installed package file/dependency ownership and prove preserved existing preferences. |

| DO NOW / A9 | Package the narrow UWSM Labwc mkdir workaround | 4 | 3 | 3 | 3 | RPM reinstall can remove the installer mutation. Fresh-home login must pass before and after UWSM reinstall/update. |

| DO NOW / A8 | Remove mandatory fossil GeoIP data; inject optional current local data and age-aware hints | 3 | 2 | 2 | 3 | April 2018 data yields undeserved confidence and ambient tests. Unknown/IPv6/missing/stale data cases must remain truthful and network-free. |

| DO NOW / A10 | Remove unused hyprpaper and completed-stage build-only DMS inputs after reference checks | 2 | 1 | 2 | 3 | DMS owns wallpapers; runtime RPM already contains assembled output. Stage/media validation and declared fallback must still pass. |

| CONSIDER NOW / A4 | Profile/coalesce collector work; prototype headless posture snapshot path if needed | 4 | 3 | 3 | 4 | Repeated short samples showed significant Context CPU. First reproduce on A2 packages; measure reduced call/scan counts without weakening leases/failure states. Profiling is DO NOW; larger evaluator refactor depends on evidence. |

| CONSIDER NOW / A11 | Test Quickshell -5/Greeter 1.6.2 and optionally Labwc 0.9.8 | 3 | 3 | 3 | 2 | Addresses A1 and relevant compositor fixes. No forced wlroots-generation jump; require real login/lock/display parity. |

| CONSIDER NOW / A12 | Prototype a pinned builder container and modest acquisition concurrency | 3 | 3 | 3 | 3 | Can simplify factory setup after A3; keep native scratch/privilege requirements and measure cold/warm stages. |

| LATER / A13 | KIWI/image-builder prototype for live/disk artifacts | 3 | 4 | 4 | 3 | Useful ecosystem direction; no evidence a complete port beats caching the existing installer before this ISO. |

| LATER / A14 | Optional Hyprland fallback packaging, modern Tao parity and newer UWSM/Labwc series | 2 | 4 | 4 | 3 | Can remove dependencies/patches after support and parity decisions; not justified by version numbers alone. |

| DON'T BOTHER / A15 | bootc switch, shell fork, toolkit rewrite, merged privileged daemon or second updater before release | 1 | 5 | 5 | 1 | Broad product/update/authority changes have no demonstrated pre-release return. Keep the working ownership boundaries. |



## Final answers



1. **Highest-value improvements:** A1's release/update compatibility, A2's package-

   only validation, A7's useful Fedora updates and A3's reusable dependencies.

2. **Unnecessary complexity:** static files copied by a large provisioner,

   rewriting package-owned units/plugins, independently repeated release IDs,

   and expensive security projection recomputation. Not the separate firewall,

   connectivity, DNS and egress authorities.

3. **Architectural changes worth doing now:** a small session policy RPM, one

   component build/identity orchestrator, persistent object caches, compatible

   transaction selection; bounded collector optimisation after profiling.

4. **Tempting redesigns not worth doing:** bootc/Atomic migration, replacement

   installer/live-account flow, a complete shell/toolkit rewrite, or combining

   differently privileged providers.

5. **Actual updates:** Flatpak 1.18.4 and fwupd 2.1.8 through Fedora; test the

   current Quickshell rebuild and Greeter together under A1. Keep DMS 1.6.2,

   ClamAV's maintained LTS, OpenSnitch, USBGuard and Restic. Test newer compositor

   series only for identified behavior, not novelty.

6. **Entire removals:** proven unused hyprpaper, fossil GeoIP mandatory packages,

   redundant staged patch/plugin build inputs and the RPM-unit overwrite.

   Delete runtime UWSM mutation only after delivering its correction durably.

7. **Faster/simpler ISO creation:** cache acquisition and reuse compatible closures;

   preserve current fresh offline checks and mkksiso publication boundaries.

8. **Faster/simpler packages:** retain Cargo/compiler caches, rebuild affected

   components only, reuse matching receipts, use unique RPM revisions and one

   package-set invocation. Do not rebuild the whole desktop for a frontend edit.

9. **Development without full ISO builds:** focused source checks → affected

   RPM(s) → reversible `.149` deployment/package-only session → real interaction

   checks. ISO/boot validation is needed for install/boot integration changes and

   the final validated set, not every leaf edit.

10. **Implementation sequence:** resolve A1 selection/update policy; rebuild A2

    current packages with A7 tested updates; implement A6/A5/A9 ownership and

    identities; profile A4 and apply only demonstrated bounded fixes; implement

    A3 and A8/A10; run cold/warm construction and one clean install; finish real

    auth/display/hardware cases; promote that exact tested input set.



## Acceptance scope



The audit reports are delivered, not an authorisation to implement every redesign.

No ISO build, dependency update, service restart or production promotion was

performed for this assessment. Manual cases are limited to genuine authentication,

visual/scaling/display interaction and physical devices, listed in the architecture

audit. Engineering tasks and incomplete technical gates stay with the project.
