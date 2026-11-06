# Behavioral intelligence

GREYWARD's local behavioral integration is observation-only. It adds explainable
incidents to the existing Security Center; SELinux, Application Guard and
OpenSnitch retain enforcement. Scores never authorize process termination,
firewall changes or privileged commands. This is local development, not ISO or
public-release acceptance.

## Sensor and trust boundary

Context 132 retains normal system execution identities in the bounded ancestry
map without writing zero-score, uncorrelated NORMAL system events into durable
user investigation history or the incident cache. Unknown/nonzero system
observations and root descendants attributed to an ordinary user remain
eligible. Normal user assessments, detection rules and scores are unchanged.
Bounded pruning ranks evidence fairly by UID, favoring incident-linked records
within each owner's budget. Snapshots report that caller's actual retained
record count and oldest/newest observation; seven days is an upper age limit,
not guaranteed coverage. No score is invented for an evicted record.

`greyward-intelligence` packages Tetragon 1.7.1 userspace built from pinned
upstream sources, cilium/ebpf 0.22.0 and a zero-fuzz cleanup compatibility patch.
The official 1.7.1 binary failed on Fedora's extended Linux 7.2 BTF header.
The newer parser fixes that incompatibility. The package reuses the release's
CO-RE BPF objects; `packaging/greyward-intelligence/source.json` owns archive,
Go lock and patch digests. TLS/SHA-256 and Go checksums were verified; an
independent upstream signing identity was not verified.

The privileged sensor has no listening gRPC, metrics, health, profiling or
Kubernetes endpoint. It emits exec/exit plus two kernel-filtered probes:
selected persistence-file write permission requests and IPv4/IPv6 connection
attempts. Its exported and persisted projections retain executable paths and kernel
execution IDs, excluding command arguments and working directories. Tetragon
can parse exec arguments internally in privileged transient memory; this is
not a claim that the sensor never reads them. No file contents, packet
payloads or credentials are requested by the two GREYWARD probes.
The root-only raw export is not a user API. No probe contains an enforcement
action. Kernel attachment needs elevated BPF capabilities; this is a trusted
sensor, not a sandbox for untrusted probe definitions. Root-owned policies
must be reviewed before adding coverage.

The provider has no Linux capabilities and no network address family beyond
AF_UNIX. Its sole system-bus method is `GetSnapshot(s)` on
`systems.mantis.greyward.Intelligence1`. D-Bus supplies the actual sender UID;
request fields cannot override it. UID filtering precedes limits. A root caller
also receives only its own records. The ordinary desktop does not receive
unattributed root-service incidents; root descendants of its exact observed
execution chain can retain that actor identity. There is no user-supplied ingestion,
process control, policy editor or generic privileged execution interface.
Reads are capped at 120 records, 4 KiB requests and a per-UID token bucket.
Security Context exposes a fixed asynchronous read to the existing Tauri UI.

## Assessment and correlation

Each evaluated record carries a rules version, observation source, timestamp,
execution identity, confidence and contributing factors. Unanalysed historical behavior remains UNKNOWN. A current destination-reputation
lookup is explicitly scoped as a current assessment, never a fabricated past score.

| Classification | Meaning |
| --- | --- |
| Neutral / UNKNOWN | Evidence unavailable, attribution incomplete or not evaluated |
| Green / NORMAL | No suspicious factor requiring attention in observed evidence |
| Yellow / POLICY_BLOCKED | Existing policy denied an operation; no suspicious behavior established |
| Orange / SUSPICIOUS | Severity index 35–74 with explainable behavioral indicators |
| Red / HIGH_THREAT | Index 75–100 and at least two independent behavioral domains |

The index is **not a probability of compromise**. Confidence is separate:
heuristic incidents are MEDIUM even where kernel execution attribution is exact.
An unusual execution location adds 10 context points and does not alert alone.
An unexpected interpreter child of an incoming-file/document process adds 35;
a selected persistence write request in that chain adds 35; public outbound
activity in that chain adds 15. Six regularly spaced public attempts spanning
at least 60 seconds can add 20 in an already unusual chain. This is not proof
of command and control. Unexpected observed root transitions outside known
privilege brokers add 40. Repeated factors do not repeatedly increase scores.
Known destination-feed matches remain a separate, qualified network indicator.

Correlation uses exact Tetragon exec IDs, boot identity, actor UID and a
10-minute window. It never joins by PID reuse, executable name or path alone.
An observed root descendant may retain its originating ordinary actor; another
ordinary UID starts a separate boundary. Partial cache attribution is neutral.
Restart preserves stored incidents but does not invent missing ancestry.
New episodes retain earlier case history. Timelines retain 32 observations,
chains 16 nodes, and expose truncation rather than implying completeness.

## Presentation and notifications

There is no separate Intelligence page or Overview incident panel. **Security
History** shows nonzero behavioral assessments by default alongside established
security events. Process activity explicitly exposes all retained system
observations. Focused incident reads include network/system evidence together.
**Network Activity** contains only the existing OpenSnitch decision records;
raw kernel connection attempts must never become duplicate “Observed attempt”
rows or replace an Allowed/Blocked outcome.

The shared header/row column contract has one Intelligence field. Network risk
uses the existing six inspection levels: 1–2 green, 3–4 yellow, 5–6 red. These
levels are an inspection priority, not a probability, proof of safety or a
firewall decision. Missing/invalid connection metadata remains `Not assessed`.
The system/process severity index retains its separate 0–100 contract above.

`network_patterns.py` evaluates at most 4,096 retained connection observations,
in event-time order, over 60-second windows. Twelve distinct TCP ports on one
destination or sixteen addresses in one IPv4 /24 or IPv6 /64 on a selected
administration/data service are service-discovery evidence (weight 35, 3/6).
Web/CDN/DNS fan-out, retries, a single uncommon port, Tor/privacy tools and
policy denials alone contribute no suspicious weight. Authorized scanners can
match; the explanation says so. Overlapping vertical/horizontal scan patterns
contribute once. No traffic is generated or inspected by this evaluator.

`process_identity.py` derives an opaque boot/PID/kernel-birth-tick key while a
pidfd confirms liveness; it does not read memory or arguments. Sensor exec IDs
and OpenSnitch records must independently validate against that instance;
connection time and kernel UID reject exited/reused or foreign processes.
`network_intelligence.py` makes one UID-scoped, bounded cached batch read, never
joins process behavior by executable name, and attaches retained explanations
for a related exact process instance. Coalescence distinguishes PID, UID, transport and the hashed network flow
within the existing 15-second window. It never copies an old process key onto
an independently unverified statistics record: matching flow metadata alone
cannot rule out PID reuse. Exited short-lived processes cannot be
retrospectively assigned invented keys. A transient first identity failure is
retried on later observations at most every five seconds; an unverified PID is
never treated as an exact join. This is a process-instance relationship,
not proof of a historical connection outcome or exact exec-generation match.

Network-only patterns evaluate exact instances and an explicitly labelled
application/UID activity group in parallel. Intermittent process-key availability
and separate short-lived instances do not split that application-level pattern.
Equal-strength evidence prefers exact-instance attribution; overlapping scopes
contribute only once. That is not presented as a kernel process join.
Historical records without an executable or verified instance stay uncorrelated.
Live pattern evaluation precedes UI pagination. History evaluates an independent
bounded 512-record context query; truncation is exposed as partial coverage.
Historical assessments describe current analysis of retained evidence, never an
invented past detector result. No cross-user process evidence is returned.

The existing locally refreshed Feodo recommended IP/port list is intentionally
narrow: it is not general IP/domain reputation. Only an exact IP **and port**
match in a successfully updated, at-most-24-hour-old snapshot contributes weight
70 (5/6). A persisted `threat` tag, failed refresh or nonmatching indicator cannot
substitute for current validation. There is no domain reputation engine. The
panel shows freshness, indicator count and these limits. HTTPS validates feed
transport; the upstream list is not represented as cryptographically signed.

The strongest evidence weight sets the network index. Independent suspicious
process behavior, service-discovery pattern and fresh reputation can add at most
20 corroboration points; repeated/overlapping indicators are not summed. For
example, a current C2 IP/port match plus independent suspicious execution can
reach 90 (6/6). Factors, score components, attribution, evidence window and
confidence are displayed independently of sensor health. No score-based blocking
or process killing is introduced; OpenSnitch remains the decision owner.

Current observation health is separate from historical completeness. Recovery
requires distinct consecutive execution/export round trips, verified selected
policy attachments, export catch-up and 30 seconds without a new gap.
`sensor_health.py` tracks a bounded set of pending probes across reader delay;
issuing a new probe no longer invalidates the previous outstanding response.
Probe age, matched/sent counts, latency, catch-up and specific health reasons are
reported. Unexpected reader exceptions are journaled instead of silently hidden.
Historical loss counters persist. The old counter mixed dropped-event counts
with throttle/gap reports, so the UI explicitly labels it a legacy reported-loss
counter, **not** a threat count, gap-episode count or current health verdict.
Recovery never declares missing history complete. ACTIVE means tested selected
coverage is operating; independently proving zero kernel ring loss is unsupported.
Failed reads preserve retained rows while marking current observation unavailable.

Deterministic private fixtures in `test_network_assessment.py` exercise actual
OpenSnitch Ping protobuf ingestion, the GREYWARD evaluator, full-window user API,
process evidence and decoration. They never enter the live incident store.

Expected desktop FUSE privilege elevation is narrowly recognized for root-owned,
non-writable `fusermount3` under the system document portal/GVfs FUSE parent and
its direct system mount child. This does not trust arbitrary descendants or
suppress other factors. Periodic public communication requires an independent
interpreter, persistence or unexpected-privilege indicator before it can escalate
an incident; location alone plus normal polling is insufficient.

The existing Feodo timer is a required production service. The configured feed
is refreshed by its existing bounded updater, with no new enforcement interface
or changes to personal VPN/routing settings.

The existing DMS publisher receives stable incident IDs, application, score,
confidence and reason. The GREYWARD identity remains the app icon; the larger
severity artwork uses DMS's native `image-path` preview, and the title also spells
out `score/100` for readability in compact notification modes. Fixed SVG artwork
uses enlarged digits and a fuller 128-pixel canvas. No protected DMS shell files
or authentication profiles change. Orange cases notify once; updates replace
quietly and escalation to red can notify again after dismissal. Green activity
does not notify. Review opens the focused case directly in Security History, including cases
with network factors. Old saved Intelligence routes
normalize to History. References are strictly validated in the route helper,
notification router, native reader and frontend. Existing DMS preferences, DND
and urgency handling remain authoritative; no separate publisher or overlay is
added. Synthetic visual fixtures never enter the live provider or live history.

## Bounds, lifecycle and failure

Raw export rotates at 8 MiB with two backups. SQLite is capped at 32 MiB plus
bounded WAL; evidence is pruned in batches to 5,000 records / seven days,
incidents to 256 / seven days. Used-page pressure triggers earlier historical
eviction at 16 MiB, leaving headroom below the 32 MiB hard database quota. At most 4,096 process identities are cached.
Global bounds can evict one user's older records during another user's burst;
the interface does not promise complete forensic retention. Export throttling,
rotation overruns and reported daemon losses mark coverage degraded. Exact
retained-inode cursors recover across provider restarts and drain bounded
backups before current data; unavailable history remains explicitly incomplete.

Every 15 seconds a fixed `/usr/bin/true` health probe is executed; the provider
must observe its actual kernel exec event. A running process alone does not
establish coverage. The sensor's fixed startup helper checks its two
pinned policy attachment links under the sensor's existing capabilities. Its
root-only receipt must match the actual daemon PID and current boot. Missing
or mismatched receipts degrade coverage; the provider receives no BPF
capability. This is startup attachment evidence, not independent continuous
verification against a privileged administrator detaching a program. A stale BOOTTIME heartbeat fails unavailable, including
across suspend. Kernel ring loss is not independently proven absent. Reported
gaps are retained through provider restarts for the current boot. Missing
sensors never produce a green coverage claim. Failure does not disable existing
security controls.

The two units have explicit CPU weights, low scheduling priority and memory
limits (sensor 512 MiB, provider 160 MiB), strict system mounts and root-only
state. No existing SELinux policy, protected session, authentication, personal
VPN or kernel parameter is weakened. The sensor owns a separate bpffs prefix;
rollback must never clear global bpffs or OpenSnitch maps.

## Log assessment labels

System-history badges use **Nothing suspicious** with a check mark for an
explicit zero assessment. No numeric zero competes with the row's connection
decision. Its tooltip limits that statement to the assessed evidence; it is not
a safety guarantee. Unknown, missing, non-numeric or out-of-range indices remain
**Not assessed** with a neutral dash, including UNKNOWN records carrying zero.
Nonzero assessments show their index out of 100 and a short label; the expanded
row retains scope, confidence and contributing evidence. **Allowed / Blocked**
continues to describe the actual existing firewall decision independently.

Network rows instead show a numeric **Risk /6** inspection priority. The existing
explainable evidence index maps as follows: zero → 1, 1–19 → 2, 20–49 → 3,
50–69 → 4, 70–89 → 5, 90–100 → 6. Levels 1–2 are green, 3–4 yellow, 5–6 red.
The number itself inherits the level color. Unknown or invalid evidence stays
neutral **Not assessed**; it is never assigned a reassuring 1. This is not a
probability, guarantee, country-based reputation or an automatic blocking rule.

The backend assigns `risk_score`/`risk_scale` from the actual assessment for each
supported firewall record. Exact process-instance factors and verified Feodo
matches can raise priority; a block alone cannot. A verified no-match with no
other linked indicator gives level 1 within that limited assessment scope.
When process/reputation coverage is unavailable, a complete observed IP, transport
and service port still support a **low-confidence connection-metadata** assessment:
routine metadata gives 1; common non-encrypted-by-default TCP service ports give
2; Windows file-sharing/RPC ports to a public address give 3. These are inspection
hints, not claims about packet contents, actual encryption or malicious intent.
They do not create incidents, alerts or blocking rules. Missing/malformed metadata
still stays unassessed, and the expanded detail explicitly states missing coverage.
Rows remain sorted by the underlying evidence index when risk sorting is chosen;
expansion retains factors, scope, confidence and related process evidence.
The frontend's matching conversion also supports retained older typed records.

## Build, installation and rollback

Use `packaging/greyward-intelligence/build.sh RPM_TOP VERIFIED_ARCHIVES` as an
isolated low-priority builder with two Go/Cargo jobs, project-local caches and
an 8 GiB ceiling. Build Center and Context with their existing RPM recipes.
Dependencies/caches are development tools, not ISO inputs. Install the matched
RPM set only after validation; preserve the previous Center/Context RPMs and
root-owned policy/unit backups. Enable only the two new units, reload the D-Bus
configuration, then restart the existing user Context service. A desktop logout
or compositor/authentication update is unnecessary.

Rollback stops/disables these two units, removes the new sensor RPM and
reinstalls the saved matching Center/Context RPMs, then reloads systemd/D-Bus
and the user Context. Preserve root-only state as historical evidence. Never
remove unrelated units, keys, configurations or global BPF pins.

This task does not promote a new production image tuple or publish packages.
The new package is an explicit local installation, not an implicit default in
an existing ISO manifest. The local validation receipt owns actual versions,
measurements and remaining acceptance boundaries.

## Known limits

This is a bounded behavioral detector, not full EDR. It does not inspect all
syscalls, arbitrary file reads, document contents, encrypted traffic or every
persistence mechanism. Interpreter arguments are deliberately not captured, so
script-path attribution is limited. Incoming-location rules currently recognize
temporary paths and literal Desktop/Downloads path components; custom or
localized incoming-directory names are not fully covered. The selected home persistence prefixes are
materialized for users present at installation; new user paths require reviewed
policy regeneration. Existing administrator policy edits are preserved.

Kernel connection hooks describe attempts, not OpenSnitch allow/deny outcomes
or successful sessions. Legacy OpenSnitch records lack an exact exec-ID bridge;
they are not assigned an incident by pathname guessing. Repeated connection
patterns can be legitimate. Detection is advisory and may miss attacks or
produce false positives. Kernel updates and physical suspend/resume require
separate acceptance; missing attachment degrades coverage. Current new detail
copy is English; global navigation retains the existing language mechanism.


## Primary upstream references

- [Tetragon event model](https://tetragon.io/docs/concepts/events/)
- [Tetragon package installation](https://tetragon.io/docs/installation/package/)
- [Tetragon compatibility FAQ](https://tetragon.io/docs/installation/faq/)
- [cilium/ebpf extended BTF-header correction](https://github.com/cilium/ebpf/pull/2042)

The local manifest and actual kernel tests, rather than those references alone,
establish the installed compatibility evidence.


Rules 3 also recognize Fedora boot-status maintenance by its canonical protected
setuid helper and exact systemd launch chain (including the observed same-PID
exec-FD trampoline). This classification exception grants no permissions or
inherited descendant trust. SELinux/OpenSnitch outcomes remain independently
owned. See the verified local case and regression limits (private development evidence).

## Local network validation, revision 135

The 6 November assessment receipt (private development evidence)
records the installed local tuple, deterministic/private and live benign checks,
measured performance, historical loss accounting and collector activation deferred
to preserve the current network session. It does not establish public/ISO acceptance.

## Live score presentation, revision 136

The Activity poll timer is created whenever Live becomes active, including a
History-loaded route switched back to Live. History stops that timer; a fresh
route owns exactly one timer. The existing route/request guards reject late
responses after leaving the page. Manual Refresh requests a bounded full current
window. Every fifteen seconds Live also re-assesses that window, so retained
connections can acquire process evidence after their sequence was first received.
Those reassessment snapshots do not count existing paused rows as new activity.

A focused row button no longer freezes all list rendering. A matching row's
control regains focus without scrolling after replacement. Actual editable
controls still defer replacement to preserve in-progress user input. Severity
thresholds and firewall policy decisions are unchanged.

The original private score fixtures do not establish that the user's running
window updates. Real validation must compare an actual event returned through
the session API with the actual running window's accessible risk label, and
exercise automatic refresh after route/mode changes without clicking Refresh.

The real-window follow-up (private development evidence)
records revision 137's mixed-identity correction and the actual automatic delivery
of real 3/6 test rows. Earlier isolated six-level tests did not establish live UI
behavior and must not be cited as such.
