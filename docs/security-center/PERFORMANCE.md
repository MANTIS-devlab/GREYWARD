# Security Center performance pass 2 and startup audit

This is the canonical performance record for the September 2026 GREYWARD
Security Center work. Pass 1 established bounded shared snapshots, targeted
Updates rendering, adaptive scan polling, telemetry indexes, and action
refreshes. Pass 2 concentrates on Fedora/Tauri runtime evidence and the
remaining provider and cache bottlenecks. The startup audit below extends that
record without reopening the completed navigation, cache, scan, or application
inspection work.

## Baseline

The comparison build is the installed Fedora first-pass package
`greyward-security-center-0.1.0-45.fc44.x86_64`. The after build is the
guest-local debug Tauri binary built from this worktree with
`--features custom-protocol`. Both were exercised through guest-local
`tauri-driver` 2 and Fedora `WebKitWebDriver`, using the real Wayland session
and Security Context services on GREYWARD-DEV through the managed development alias.

The benchmark measures process/session startup to the first Overview marker,
then route readiness from DOM navigation to the route marker. It also records
the frontend command boundary, five 500 ms idle samples, and process RSS.
Initial Overview IPC is intentionally not counted because instrumentation is
installed after the first useful frame; the startup time includes it.

| Area | First-pass baseline | Evidence |
|---|---:|---|
| Tauri session to first Overview | 2,441 ms | installed RPM, real Fedora/WebKit run |
| Overview first useful frame | included above | real Fedora/WebKit run |
| System first navigation | 789 ms | installed RPM, real Fedora/WebKit run |
| File Security first navigation | 501 ms | installed RPM, real Fedora/WebKit run |
| Updates first navigation | 131 ms | installed RPM, real Fedora/WebKit run |
| Applications first navigation | 660 ms | installed RPM, 5 system Flatpaks |
| Devices first navigation | 4,183 ms | installed RPM, real Fedora/WebKit run |
| Overview return | 867 ms | installed RPM |
| Applications revisit | 981 ms | installed RPM |
| File Security revisit | 369 ms | installed RPM |
| Idle Security Center process | 0% sampled CPU, 3,968 KiB RSS | five samples |
| Launcher fallback | 1 check / 750 ms | source and first-pass contract |
| Flatpak permission inspection | 113–119 ms serial for 5 apps | guest provider measurement |

The prior first-pass report’s Windows-only statements are historical: this
pass did reach the canonical Fedora guest. Host Rust linking remains a
separate Windows limitation and is not used as runtime evidence.

The guest’s read-only provider trace before the page-specific device change
showed the dominant full-graph components as: complete posture helper 703 ms,
DNF security query 554 ms, firewall query 186 ms, and the five-application
Flatpak permission/override sequence 127 ms. Firmware version/security/update
probes were 20–22 ms each; NetworkManager was 10 ms; portal probes were 4–5
ms each. The full core collector already runs independent providers
concurrently, so Pass 2 removed unrelated providers from Devices and
parallelized that page’s remaining independent reads rather than extending
the global cache window.

## Startup audit

The launch timeline was measured in the real Fedora Wayland session using the
guest-local debug binary, `tauri-driver` 2, and Fedora `WebKitWebDriver`. The
startup test was run as three independent process launches after the first
five-run trace established the variance range. The release comparison used
three independent launches. These are process restarts with warm OS/filesystem
caches; they are not a claim about a cold boot.

The launch-gated Rust trace and WebView marks produced this representative
debug timeline (milliseconds from the external WebDriver launch request):

| Stage | Observed median / range | What it means |
|---|---:|---|
| Rust process entry → Tauri setup complete | 143 ms / 137–150 ms | instance lock, builder, window setup |
| Tauri setup → document script | about 1,140 ms | Tao/WebKit/WebView startup; no GREYWARD provider work |
| Document script → app script | 11 ms / 10–11 ms | synchronous HTML, CSS, icon catalog, and localization loading |
| First shell DOM | 1,305 ms / 1,289–1,314 ms | truthful loading shell exists |
| First shell + navigation-interactive frame | 1,383 ms / 1,365–1,383 ms | navigation handlers are bound and the shell has painted |
| Initial authoritative Overview request start | 1,306 ms / 1,289–1,315 ms | first IPC request for security posture |
| Initial core collection complete | 2,185 ms / 2,149–2,197 ms | concurrent authoritative providers returned |
| First authoritative Overview DOM | 2,253 ms / 2,220–2,265 ms | posture and domain cards are rendered |
| First authoritative Overview frame | 2,325 ms / 2,282–2,331 ms | first measured useful, painted Overview |
| WebDriver session to frame-synchronized completion | 2,572 ms / 2,568–2,866 ms | includes driver/session overhead; not the UI frame itself |

The first five-run trace (before adding the frame wait to the startup test)
measured process-to-Overview DOM/session values of 2,284–2,657 ms, median
2,390 ms. The frame-synchronized sample is the better user-visible measure;
the two samples differ because WebDriver completion can lag the already
painted document.

### Critical path findings

- Rust/Tauri initialization is small: the instance lock and setup completed in
  137–150 ms. No plugin initialization, database migration, telemetry store
  construction, Flatpak inventory, device/recovery collection, update-center
  request, or Security Context initialization runs before the first Overview
  request.
- WebKit/WebView startup is the largest fixed interval. The document began at
  about 1.27–1.29 s and the first shell frame at about 1.37–1.38 s. The
  frontend bundles are synchronously loaded, but document-to-app-script time
  was only 10–11 ms; changing their load order was therefore not justified.
- The initial Overview collection is the main GREYWARD-controlled interval.
  Its measured provider ranges were: security updates 762–825 ms (median
  786 ms), NetworkManager/firewall 398–488 ms (median 437 ms), Flatpak
  335–380 ms (median 359 ms), firmware 239–344 ms (median 242 ms), USB
  82–97 ms, and portal 34–92 ms. They already execute concurrently, so the
  collection is bounded by the slowest authoritative provider rather than the
  sum.
- The Overview response-to-frame tail was about 68–143 ms in these runs. It
  includes serialization, WebView IPC delivery, DOM construction, layout, and
  paint, not another backend collection.

Security Context and SQLite remain warm, independently managed session
services on GREYWARD-DEV. The initial Overview Rust path reads local activity
history directly and does not call the Security Context bus. This was verified
from the command path and the launch trace, rather than inferred from source
layout.

### Startup decision

No speculative startup refactor was made. The shell is already rendered and
interactive while authoritative posture is pending, and the initial Overview
request already starts immediately after that shell is installed. Deferring
the security-update or Flatpak providers would make the Overview incomplete
without reducing the first authoritative posture requirement; replacing the
authoritative `dnf5 --security` read with a cache would violate freshness.
The measured remaining majority is Tauri/WebKit/process startup, followed by
the slowest required provider. The release binary was 9.2 MiB versus 205 MiB
for debug, but its three-run authoritative-frame median was 2,382 ms and its
session median was 2,772 ms, so release linking did not produce a reliable
startup improvement in this guest sample.

The instrumentation is gated by `GREYWARD_STARTUP_TRACE` or the temporary
`/tmp/greyward-startup-trace.enable` marker and does not alter security state
or readiness semantics. `startup.test.mjs` provides the repeatable real
runtime measurement; `performance.test.mjs` retains the broader navigation
and idle regression coverage.

## Findings

1. Devices still paid for unrelated posture work and then serialized device
   history, recovery-point status, and backup status. The real installed build
   made this the dominant cold route at 4.18 s.
2. Flatpak inventory was correctly authoritative but performed two subprocess
   reads per application serially. This was an N+1 process pattern, although
   Flatpak exposes no supported bulk effective-permission endpoint in this
   environment.
3. Presentation caching applied too broadly. Network policy, privacy,
   applications, devices, scans, and updates are mutable state and cannot
   safely reuse a five-second page projection when an external actor changes
   them.
4. The file scan service persists progress and emits telemetry, but its D-Bus
   contract has no progress signal. The frontend therefore cannot subscribe to
   a validated structured scan event stream yet.
5. Launcher deep links are file-backed. The Tauri boundary has an event path
   for in-app changes but no single-instance IPC endpoint or filesystem watch
   bridge for the launcher script, so a bounded compatibility poll remains.

## Optimizations

- Added a device-specific authoritative collection path. Devices now collect
  only boot/storage/TPM, USB, and recovery facts; firmware, package, network,
  portal, and Flatpak providers remain on the full posture path.
- Parallelized the independent device history, recovery helper, and backup
  status reads after local device facts are collected.
- Kept full core collection concurrent across its independent providers and
  retained the three-second shared snapshot for Overview, System, and Evidence.
- Changed Flatpak scope enumeration to run user and system list reads together,
  then inspect each application’s effective permissions and overrides in
  bounded batches of four. The reads remain authoritative and are not
  permanently cached.
- Restricted short-lived frontend page reuse to derived posture presentations
  (`Overview`, `System`, and `Evidence`). Mutable pages always request a fresh
  backend projection on navigation; explicit action refreshes remain forced.
- Added explicit user-bus cache invalidation for successful privacy-profile,
  network-policy, and USB trust mutations. Existing Tauri action paths already
  force the affected page after successful file, update, network, and privacy
  actions.
- Retained adaptive, non-overlapping File Security polling. The service’s
  current D-Bus API does not provide a trustworthy progress event to replace
  it; no synthetic percentage was added.
- Retained launcher fallback polling at 1.5 s (40 checks/minute), down from
  750 ms (80 checks/minute). It is visibility-aware and remains a compatibility
  fallback, not the normal state-change path.

These changes do not turn mutable security data into a durable cache. Flatpak
permissions, scan status/detections, update transactions, network action
readbacks, privacy profile confirmation, and device trust results remain
authoritative at the action or page boundary.

## Cache correctness classification

| State | Reuse policy | Invalidation / authority |
|---|---|---|
| Derived Overview/System/Evidence presentation | up to 5 s in the frontend; core snapshot up to 3 s | invalidated by posture/deviation/privacy/network/USB state events; explicit refresh bypasses |
| User-bus posture and shell summary | 5 s / 2 s bounded caches | `Refresh` and successful mutable profile/network/USB actions clear caches |
| Network policy and secure DNS | no mutable page reuse | forced network read after successful action |
| Privacy profile | no page reuse | helper result is verified against requested profile, then forced read |
| Flatpak effective permissions/overrides | no application-page cache | collected per application on every Applications open/refresh |
| File scan status and detections | adaptive status polling; no result cache | action completion forces File Security read; cancellation/failure remain explicit |
| Updates transaction | targeted refresh while busy | action deletes Updates page cache and reloads authoritative state |
| Device trust / USB state | device page is not reused | USB trust action clears shared caches; device read collects current facts |

Application permission mutation is not exposed as a Security Center action; it
is performed by Flatpak tooling outside this UI. Because the Applications
page is excluded from presentation reuse, the next open reads current
permissions and overrides rather than presenting a cached success or failure.

## Runtime verification

The following was actually run in GREYWARD-DEV:

- guest-local Tauri performance test across Overview, System, File Security,
  Updates, Applications, Devices, Overview return, Applications revisit, and
  File Security revisit;
- real command capture at the frontend invoke boundary;
- five idle CPU/RSS samples;
- installed first-pass RPM run using the same route script;
- five installed system Flatpaks (Brave, Collabora, Aerion, Bazaar, Haruna)
  with real `flatpak info --show-permissions` and `flatpak override --show`;
- real Privacy export workflow, including exported-file permissions and JSON
  validation;
- attempted real Standard → Private privacy transition. The Fedora helper
  refused the change and reported `REFUSED` / rollback failure; the effective
  state remained Standard. This is an environment/action failure, not a stale
  success: the UI did not claim Private.

The existing broad interaction test therefore did not reach later network
mutations in this guest run. Its result was one expected privacy-transition
failure after the export check, and it must not be reported as a complete
action-suite pass.

Targeted checks also added/ran for cache invalidation, device-specific
collection, bounded Flatpak inspection, and the real Tauri route benchmark.
The Python Security Context suite passed with 133 tests and 25 expected skips
after adding cache invalidation coverage. The frontend contract suite and
guest Rust build were run; the Windows Rust linker limitation remains noted
where applicable.

## Before / after

| Workflow | Before | After | Observed result |
|---|---:|---:|---|
| Tauri session → Overview | 2,441 ms | 2,372 ms | 3% lower in this run; startup still about 2.4 s |
| System first navigation | 789 ms | 51 ms | 94% lower |
| File Security first navigation | 501 ms | 377 ms | 25% lower |
| Updates first navigation | 131 ms | 366 ms | slower in this run; no gain claimed |
| Applications first navigation | 660 ms | 453 ms | 31% lower |
| Devices first navigation | 4,183 ms | 694 ms | 83% lower |
| Overview return | 867 ms | 172 ms | 80% lower |
| Applications revisit | 981 ms | 173 ms | 82% lower; current run was a fresh authoritative read |
| File Security revisit | 369 ms | 171 ms | 54% lower |
| Flatpak permission inspection, 5 apps | 113–119 ms serial | 61–86 ms bounded parallel | 29% lower at median; effective reads preserved |
| Idle process RSS | 3,968 KiB | 3,776 KiB | lower in these samples; not a memory benchmark |
| Launcher fallback | 80/min | 40/min | half as many compatibility checks |

Route values are single-run observations from the same guest session class,
not statistically stable benchmark claims. The largest repeatable architectural
result is the Devices reduction; startup and Updates need a larger controlled
sample before further tuning.

Captured command behavior from the after run included one `get_overview` for
System, one `get_filesecurity` for File Security, one `get_updates` for
Updates, one `get_applications` for Applications, and one `get_devices` for
Devices. Idle sampling added two `consume_navigation_request` calls over the
2.5-second sample window, consistent with the 1.5-second compatibility timer.

## Remaining bottlenecks

- Startup remains about 2.3 s to the first measured authoritative Overview
  frame and about 2.4 s to the normal process/session marker in the real
  WebKit session. The trace shows that most of the interval is WebKit/process
  startup; the remaining code-controlled interval is the slowest authoritative
  provider, currently `dnf5 --security`. A supported lower-latency update
  provider or WebKit/Tauri startup improvement would be needed for a material
  next reduction.
- Updates varied substantially (131 ms before versus 537 ms after). This needs
  repeated runs with Update Center provider state held constant before any
  optimization is justified.
- Flatpak still starts two authoritative subprocesses per application because
  the available Flatpak CLI has no bulk effective-permission API here. A future
  supported machine-readable API or a long-lived permission service could
  remove that remaining process overhead; indefinite caching is not acceptable.
- File progress remains adaptive polling until the ClamAV service exposes a
  versioned D-Bus progress signal carrying started, detection, cancellation,
  failure, and completion states.
- Launcher fallback still performs one file check every 1.5 s because the
  launcher writes a runtime file and the existing Security Center has no
  single-instance event bridge or filesystem watcher. The next architectural
  step is an explicit Tauri single-instance/event endpoint; reducing the poll
  further would only trade responsiveness for idle work.
