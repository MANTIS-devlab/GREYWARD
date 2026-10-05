# 5 October 2026 pre-release implementation record

**Historical evidence, not release acceptance.** This records the implementation
published after the DMS migration and installer/DNS investigation. Current
acceptance remains in [STATUS](../../STATUS.md) and the
[approved backlog](../../plans/PRE_RELEASE_IMPROVEMENTS.md).

## Changes published

- Adopt DMS 1.6.2 through an unchanged distribution backend, a generated matched
  shell override, verified dependency pins and ordered, strict-preimage patches.
  Package first-party plugins and preserve typed Security Context/Update Center
  ownership. Native DMS locking is the accepted default; external sway lockers
  are retired.
- Package session defaults, helpers and policy; preserve user state with bounded
  migrations and backups. Use native Labwc/UWSM integration without mutating the
  installed UWSM source. Seed the fresh desktop wallpaper in split session state
  and set the standalone greeter's actual `wallpaperPath` state.
- Add immutable component receipts and reusable RPM/Flatpak caches. Resolve and
  install the exact offline closure in fresh verification roots on every compose.
  Validate the composed ISO's actual installer customization and interactive
  account/encryption contract. Retire the auxiliary preseeded test-media path.
- Preserve private search-domain DNS through systemd-resolved while enforcing
  strict encrypted public DNS in a reversible runtime scope. Keep VPN, ambiguous
  links and administrator-owned configuration guarded. Verify uncached encrypted
  answers and complete global/link restoration; expose failures truthfully.
- Show fresh ClamAV initialization as preparation without claiming protection is
  ready. Coalesce Security Context invalidations, use the headless posture reader,
  and keep optional country data age-aware and unknown when unavailable.
- Refresh architecture, ownership, licensing/provenance, contribution guidance,
  validation entry points and the explicit approved-item status ledger.

Publication also preserves the existing public first-boot handoff check: a
successful user login can replace the greeter without being reported as a
first-boot failure. That previously published check was restored to the engineering
source during comparison. The retained ISO was not rebuilt during publication;
its clean-install acceptance remains open. Existing public download references
and release records are preserved.

## Exact candidate input set

| Package | Version/release |
|---|---|
| GREYWARD DMS | 1.6.2-6 |
| GREYWARD session | 0.1.0-7 |
| Security Center | 0.1.0-59 |
| Security Context | 0.1.0-64 |
| GREYWARD branding | 0.1.0-15 |
| Quickshell / Labwc / UWSM | 0.3.1-5 / 0.9.6-1 / 0.24.3-1 |
| Dank greeter | 1:1.6.2-1 |

The test artifact is
`greyward-installer-20261005-portable-dns-6-7-59-64.iso`, SHA-256
`736b87cefbe9ef3ed0c4b766538f9ab1d606400643d9aad673451f0f998f7a94`.
Its manifest declares `installed_system_tested=false`. Generated images, VM disks,
credentials, raw runtime logs and private engineering Git history are excluded
from publication.

## Completed evidence

- Both mandatory repository gates passed before publication.
- The public checkout also passes both gates, all 78 frontend contracts and three
  native-lock contracts. Windows image tests pass with seven platform skips;
  the full 62-test Fedora evidence above remains the applicable image result.
  Gitleaks 8.30.1 scanned the staged changes and complete indexed source tree.
  Reviewed false positives were two public QML preimage SHA-256 values and a
  synthetic clipboard-classification test token; no actual credential was found.
- Final Security Context source/extracted/installed RPM suites: 242 tests, with
  31 project imports pinned to packaged bytes. Root RPM integrity checks passed.
  Two actual hardened-service cycles exercised public/private DNS, authorized
  NetworkDefault opt-out, return to Automatic, and complete global/link restore.
  The desktop shell PID remained unchanged; the actual audit-log query found no
  recent AVCs. See the backlog for the retained private evidence locations.
- Rust package tests passed; unchanged Rust sources retain recorded format and
  Clippy checks. All 78 frontend contracts, 62 Fedora image fixtures and 18
  migration fixtures passed. Earlier real-window measurements remain dated
  evidence, separate from this image's acceptance.
- Cold acquisition retained 3,614,681,973 bytes. Warm acquisition retained zero
  new objects. Fresh offline RPM solving and six exact Flatpak installations
  passed. The final component tuple passed verified warm reuse.
- Six 10-second profiling samples reduced median Context CPU from 17.5744% to
  15.3155% of one core; twenty invalidations coalesced into one callback. This
  justifies the bounded optimization, not a wider evaluator rewrite or a memory
  reduction claim.
- Final ISO factory closure, embedded receipts, installer contract and 28
  production paths passed. Transfer SHA-256 matched; the direct media validator
  passed 38 required paths. Its isolated console visibly offered GREYWARD
  branding, User Creation and an empty LUKS passphrase prompt.

## Remaining acceptance

The user is testing the final ISO. Clean installation, installed greeter/desktop
wallpaper, final network behavior, login/reboot, native-lock PAM/suspend, rollback
and applicable physical hardware remain open. This commit publishes implemented
and tested source; it does not promote a production release or claim those gates
have passed. See the [installer investigation](../../architecture/ISO_INSTALLER_COMPATIBILITY.md)
and [ISO runbook](../../architecture/ISO_CREATION.md).
