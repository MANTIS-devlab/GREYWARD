# Security Center performance pass — 2026-10-08

Scoped normal-desktop development evidence; not ISO, hardware or production
release acceptance. Current methods/results and remaining latency issues are
in [PERFORMANCE.md](../../security-center/PERFORMANCE.md).

## Installed inputs and rollback

Center `0.1.0-84.fc44`, Context `0.1.0-72.fc44`, Application Security
experimental runtime `0.1.0-27.fc44`, UID 1001 deliberately enrolled on `.149`.
Root-owned matched desktop and authentication policy were not changed.

| Input | SHA-256 |
|---|---|
| Center RPM 84 | `cc93459238eb8d7d30c03e740ea937b4238eb778df4e9cbc0d97fb28203e8699` |
| Center binary 84 | `3c31f49f49a607dc9319241f501e11be5695738fb743577f0d02432ca011db02` |
| Center source archive 84 | `295d5c3605108e2b4059c6db9e215121c21a297b5f04f71f59c85bac7f7725a3` |
| Center spec 84 | `b192af392fedc74e455ca8c6e1e075ff5a844b42deb58b2edae16ffe9693ebdc` |
| Context RPM 72 | `4a681da24f85b30c708fed365e84c47c071b455435c0df8b8fe33daf9bd98097` |
| Runtime RPM 27 | `26e4b572b5e452fd817f0208d489b6cd54c9d2d88d7ea5cd092622801a7dfff5` |
| Guard binary | `d6b4c9013dab1dd18ecc38a6178ef6e0a310bdcda1d18e76e987c4603aea4019` |
| Matched desktop manifest | `5073490e79c72dda4c26bab442f5ea38da5615600b54b00b37a7f63946be6946` |

These hashes are build/installation receipts, not enforcement evidence.
Private root backups retain the Center 80 baseline and intermediate package
receipts under `/var/lib/greyward-development/application-security-live/`.
The final receipt is `performance-20261008/recovery`; rollback reinstalls the
matched previous Center package, closes only Center and launches it again.
No policy, labels, account mapping, PAM, compositor, DMS or network switch
change is required. No reboot/logout was performed. SSH recovery remained
available and disk space was checked; no user or recovery data was deleted.

## Implemented behavior and security limits

Persistent shell/navigation, lease-aware renewal, concurrent independent
application reads, independently loaded optional Overview history and
Recovery's omission of unrelated device history are in the existing frontend
and typed Tauri facade. Route/operation binding prevents stale async success,
failure and timers from changing a later visit. A failed history read now stays
UNAVAILABLE rather than looking like successful empty history.

Fresh root/kernel coverage, resource/grant authorization, readback, review
workflow and lease expiry remain unchanged. No positive security result is
cached beyond its real lease. No parallel event store or generic privileged
command was introduced. Runtime source received equivalent style/docs-only
Clippy cleanup; installed runtime 27 was not rebuilt or replaced by this pass.

## Validation

- Offline Fedora Center RPM build/install and installed binary/package integrity.
- Rust formatting; 204 workspace tests; workspace/all-target Clippy with
  warnings denied for first-party code. Pinned Fedora Rust/Clippy 1.98 was used;
  existing vendored tao warnings remain dependency diagnostics.
- Frontend: 133 tests passed, three external-driver suites skipped by the
  source test invocation. Actual desktop profiling below supplies separate
  runtime evidence; skipped suites are not represented as passed.
- Context Python: 303 tests passed.
- Repository static and documentation gates.
- Ten warm-cache process launches each for baseline 80 and final 84.
- 110 baseline route visits and 220 final route visits across 11 routes;
  no JavaScript errors, but one Network deadline failure per final run.
- 60-second baseline/final idle CPU and RSS samples plus a second-run
  30-second memory observation. No compiler was running during measurement.
- Native normal/maximized/restored/minimum screenshots; real Devices and
  Recovery reads; real activity disclosure focus/open continuity.
- Root desktop verifier returned `verified: true`; recovery SSH remained usable.

Raw local development evidence is retained in ignored
`output/performance-20261008/` (before80/after84/extended84 JSON, startup and
idle JSON, test/build logs and actual final screenshots). The guest evidence
is under `/var/tmp/greyward-application-security-build/`. The canonical
read-only reusable driver is
[security-center-benchmark.py](../../../tools/greyward-dev/security-center-benchmark.py).

## Remaining work

Network provider reads sometimes exceed the existing 12-second deadline;
Context/provider long-tail latency is not resolved. Other route p95 regressions
are documented without attributing them to a proven cause. Broader contention
tracing, longer leak/performance runs, physical gestures, suspend, clean-image
and hardware testing remain **DEFERRED HARDENING**. This measured scoped pass
is not a promise that every route or security provider meets release budgets.
