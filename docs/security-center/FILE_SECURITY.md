# File Security

This is the canonical product and implementation contract for GREYWARD File
Security. It describes the deliberately small workflow:

`Scan → Detect → Explain → Quarantine → Restore or Delete`.

## Scope

GREYWARD uses the existing Security Context boundary and local ClamAV
invocation. The installed integration uses three scan modes:

- **File scan:** one user-owned regular file selected by the user, or a background batch of up to 64 files.
- **Folder scan:** one user-owned directory, scanned recursively without
  following symlinks.
- **System files scan:** a deliberate scan of ordinary files on the local root
  filesystem. It excludes `/proc`, `/sys`, `/dev`, `/run`, removable mounts
  under `/media`, `/mnt`, and `/run/media`, network or other filesystem mounts,
  and GREYWARD quarantine. It is not advertised as a complete operating-system
  scan and does not inspect live pseudo-filesystems.

ClamAV's output is parsed by the backend. The frontend receives bounded,
structured operation and detection results rather than raw scanner output.
Unknown totals use activity/phase progress; the UI must not invent a percentage.
Only one file-security operation may run at a time.

Scanning is available only when the ClamAV engine and a current security
database are both confirmed. The packaged `clamav-update`/freshclam service
owns definition installation and refresh; the Security Context reports
`CURRENT`, `OUTDATED`, `ERROR`, or `UNAVAILABLE` from verified metadata and
never starts an ad-hoc update. The existing root scanner's read-only
`ClamAvScan1.GetClamAvStatus` supplies bounded engine/definition metadata to
Context; the confined session never probes scanner execution or database files.
Absent, denied, malformed or stale provider evidence is UNAVAILABLE, even when
freshclam is active. Engine availability, definition presence/freshness and scan
activity are separate; CURRENT means on-demand scan capability, not real-time
protection. Definition publication is read from the daily CVD/CLD header, not its copy time.
The generation also includes main/bytecode changes. Scan receipts separately bind
the engine and scan-policy generation. Publication is not proof of
a successful local update transaction; `last_successful_update` remains null without that evidence.
Additive status fields default to absent for older Rust consumers' inputs.
If the engine or definitions are
not ready, the service refuses a new operation rather than queueing a scan that
could not produce a trustworthy result; the UI keeps the page readable and
explains the actual state.

## Automatic arrivals and definition recovery

The existing session service owns `arrival_scanner.py`; it adds no second scanner
or updater. It watches configured XDG Downloads/Desktop directories and mounted
USB filesystems verified against UDisks' USB connection identity. Unmounted,
unapproved, network and system volumes are never added as USB roots.

A private persistent SQLite queue coalesces events and waits at least eight
seconds for stable inode/size/mtime/ctime metadata. Partial-download names,
aliases, hidden entries, non-owned files and files over 256 MiB are not queued.
Existing Downloads/Desktop contents are not silently treated as arrivals at
first activation. Persistent traversal watermarks catch changes during downtime;
a newly mounted USB volume is enumerated. Batches contain at most 32 files and share one ClamAV process/database load.
Live arrivals and home reconciliation take priority over USB bulk backlog.
Root monitors are installed before resuming persisted batches, so a large
volume traversal does not delay observing a new root-level arrival. Saturated traversal resumes
without dropping its cursor. Confirmed per-file receipts prevent rescanning
healthy files from a mixed failed batch. Failures back off; restarts resume pending work; removed mounts are withdrawn.
An explicit foreground request cancels that user's background batch, then
retries briefly. Success is silent. Actual threat notices reuse the existing
notification route, with persistent content-hash deduplication. No automatic
quarantine, deletion or file-operation blocking is introduced.

The packaged continuous Freshclam daemon remains the sole updater. Its drop-in
retries failed processes after two minutes and preserves native CDN cooldowns.
An offline refresh failure does not invalidate still-current installed
definitions. Missing/malformed/old definitions stop new scans. Security Center
shows definition publication, age and updater lifecycle separately; a failure
is not evidence of a successful refresh or of an unsafe system.

## Receipts in existing file properties

Context 132 shares engine/updater probes for at most five seconds and retains
their original observation timestamp. Definition file replacement/metadata
change invalidates that cache immediately. `GetFileScanInfoBatch` accepts at
most 32 supplied paths and applies the bus caller's UID separately to every
selection. Arrival reconciliation uses batches rather than repeated per-file
D-Bus exchanges. Single-file Properties remains API compatible.

Status/property/summary/start reads use a bounded worker pool and reply through
the GLib loop. At most eight requests are admitted, with one compatibility scan
waiter, so a slow property read does not occupy the D-Bus dispatcher. Legacy
`ScanPath` uses the same serialized scan manager as `StartScan`; it does not
launch a competing scanner. Saturation is BUSY/unknown, never a clean result.

An unchanged file that hit an engine limit retains a partial/unknown receipt.
Automatic retry waits for changed content or definitions; manual scans remain
available. Transient errors keep the existing bounded backoff. The internal
`PARTIAL_LIMIT` marker preserves the seven-column receipt schema so older RPMs
can still write it on rollback; older readers treat that marker as incomplete,
never valid/clean. No successful scan is inferred from queue completion.

Strata keeps its native `Scan with GREYWARD` job and gains folder selection.
The desktop adds the same action using the existing companion window. Native
Properties in Strata and on the desktop show `GetFileScanInfo` receipts.
Receipts are scoped by UID and exact selection, include the scan time and
ClamAV engine/definition/policy generation, and are invalidated by inode/metadata/tree changes, definition
updates or incomplete results. A file inspected within a folder also receives
its own receipt. No receipt means **not scanned**, never clean.
For folders and drives, a receipt certifies only a completed scan of that
whole selection. Individual background file receipts do not certify an entire
volume. User-owned removable contents are supported; content owned by another
account is skipped rather than read with root privileges.

File/folder scan arguments are held no-follow descriptors after owner/type
validation. Pinned directory descriptors retain the caller's DAC/POSIX ACL
traversal checks; owning a leaf does not bypass another account's private parent.
Protected Data resource labels and protected authentication runtime/shared-memory
labels are refused by ordinary scans, including the compatibility entry point. ClamAV does not recursively resolve user-controlled paths as root.
Scanner-limit alerts, ignored children, changed selections/definitions,
interruption, timeout and failure remain partial/non-clean. A completed scan
means only that no *known* threat was found in the observed selection.

Resource bounds are explicit: 256 MiB per file, 512 MiB expanded scan size,
4096 open scan files/8192 traversal entries per manual operation, 8192 queued
arrival records per live-arrival/bulk priority class, 16384 entries per enumerated directory and 512 directory
monitors, with resumable bounded reconciliation for missed events. Large/inaccessible/symlinked trees do not receive a valid clean
badge. This is asynchronous arrival scanning, not real-time access prevention;
files can be opened before a background scan completes.

## Operation contract

Operations are stored in the shared telemetry database and have a stable
`operation_id`, mode, scope, state, phase, counters, timestamps, scanner and
database versions, and a bounded user-facing detail. States are:

`QUEUED`, `SCANNING`, `FINALIZING`, `COMPLETED`, `PARTIAL`, `CANCELLED`,
`FAILED`, and `INTERRUPTED`.

`COMPLETED` with zero detections means **No known threat detected**. It does
not mean that a file is guaranteed safe. `PARTIAL`, `FAILED`, `CANCELLED`, and
`INTERRUPTED` are never rendered as clean.

If the owning Security Context worker disappears while a scan is active, the
next status or summary read durably changes that record to `INTERRUPTED` with
its observed counters intact. A recovered page therefore shows the result as
the last scan rather than a stale operation that appears to be running.

## Detection lifecycle

Detections are durable records with a detection ID, operation ID, redacted
file reference, original path needed for remediation, detection name,
timestamps, scanner/database versions, optional size/hash, state, and action
history. States are:

`DETECTED`, `QUARANTINED`, `RESTORED`, `DELETED`, `QUARANTINE_FAILED`,
`RESTORE_FAILED`, and `DELETE_FAILED`.

The detection name is evidence from ClamAV. A detection does not prove that a
file executed or compromised the system.

The active review list contains unresolved detections, restored files and
failed actions. Successfully quarantined and deleted detections move to the
collapsed **Handled detections and history** section; restore/delete controls
remain available there for quarantined objects. Viewing a detection alone does
not acknowledge or remediate it.

For `DETECTED` records, the service also projects fresh `source_status` metadata:
`PRESENT`, `MISSING` or `UNKNOWN`. An absent source moves the historical record
out of active review and displays **Source no longer present**, without offering
an impossible quarantine action. This does not claim that the file was cleaned
or quarantined. Permission errors and symlink aliases remain `UNKNOWN` and
require review. The durable detection and action history are unchanged; if the
source reappears, it returns to active review. Remediation still independently
checks identity/hash and does not trust this existence projection.

## Quarantine and restore

Quarantine is root-owned under `/var/lib/greyward/quarantine/<owner uid>` with
mode `0700`; objects have opaque UUID names and mode `0600`. Metadata is stored
separately and is written durably. The source is copied and hash-verified
before removal. Source reads use no-follow file descriptors; the remediation
path rechecks regular-file type, owner, hash, and device/inode identity before
unlinking, so a raced path alias cannot redirect the operation. Because the
hardened root service keeps `ProtectHome=read-only`, the root service prepares
the verified object and the unprivileged user-bus service removes the requesting
user's source only after the same checks. The root service then commits or
records the failure. A failed source removal retains the verified copy and
reports `QUARANTINE_FAILED`; it must not be reported as a successful
quarantine.

Restore is never automatic. By default it copies to a GREYWARD review-staging
directory and refuses to overwrite an existing destination. The root service
stages a verified transfer object under `/run/greyward-file-security/<uid>`;
the user session opens each home directory component without following
symlinks, creates the destination with exclusive no-follow semantics, and the
root service commits it after ownership/hash verification. The quarantined copy remains
until the user explicitly deletes it, so restore does not silently discard the
evidence. The durable detection record retains the review-staging path after a
successful restore so the File Security page can identify where the restored
copy was placed without replaying a raw action log. Permanent deletion removes
that quarantined object and records the action. Quarantine is excluded from
system scans.

## Safe Open descriptor contract

Strata migration source supplies native literal-argv actions for Safe Open,
scanning and Security Context, without an unrestricted opening fallback. The
existing companion's `--safe-open ABSOLUTE_PATH` dispatches only the typed
`SafeOpen` request and accepts only `ok: true` with `state: LAUNCHED` as launch
evidence. It does not establish successful workload completion. Unknown scan
results return failure and are not described as completed. The Strata integration is maintained in `packaging/greyward-files/`; no second
file manager is introduced by scanning.

Current functional source holds the ordinary selected file descriptor through
classification and handler selection, then sends it to the shared application
broker's `PrepareSelectedDocumentLaunch(hsasb)` workflow. Root preparation
revalidates the selected object, refuses protected-label content copying and
uses the same immutable code/private home/namespace/Landlock/seccomp worker
and lifetime as Guard. Script/AppImage handlers use its validated payload
provider; graphical handlers use private nested Labwc/clipboard.

The former standalone bubblewrap preparation and fallback are retired.
A changed selection, absent provider, failed confinement or unsupported handler
returns failure/unavailable; Safe Open does not retry unrestricted or select a
different handler silently. A configured Flatpak document handler is explicitly
UNAVAILABLE pending a provider that preserves native Flatpak/portal semantics.
Ordinary Flatpak launches/overrides otherwise remain unchanged.

Preparation/starting is not proof that the document was successfully viewed.
Later exit/readback determines the operation result in existing telemetry.
The separate-account product workflow verifies ordinary native-handler viewing
and protected selection refusal; it does not validate installed production
packages or the active desktop's complete handler catalogue. Exact receipt and
limits: [current application-security audit](APPLICATION_SECURITY_PLAN.md).
Old bubblewrap-only receipts are historical, not current acceptance.

## Privilege boundary

The unprivileged Security Context proxies typed calls to the existing root-owned
ClamAvScan1 service. The Unix UID comes from D-Bus, never request JSON. Every
operation has durable ownership; reads, nested detections/actions, activity,
cancellation and remediation are scoped before limits or filesystem probes.
Unknown-owner historical records remain restricted. Root administration can
maintain historical quarantine; ordinary users cannot recover attribution from
current path ownership. The user-bus fallback uses only its per-user store.

Caller-owned file/folder scans and cancellation need no Polkit prompt. System
scans still require root or actual wheel membership, checked in the service.
No raw clamd socket or arbitrary scanner command line is exposed.

User file/folder scans require the selected source to be a readable regular
file or directory owned by the requesting user, with symlink paths and the
user-service-private `/tmp` and `/var/tmp` namespaces rejected before queueing.
System-file scans are an explicitly authorized administrative operation.

## Telemetry and history

The shared telemetry store records semantic events for scan start, completion,
cancellation/failure, detections, quarantine, restore, deletion, Safe Open,
sanitized-copy outcomes, and scanner availability. It stores bounded detection
and operation records, including the user-visible restore staging path, not raw
ClamAV output or a complete scanned-path history. See
[the telemetry model](../telemetry/EVENT_MODEL.md) and
[storage/privacy policy](../telemetry/PRIVACY_STORAGE.md).

## UI ownership

The File Security page in `security-center/tauri/frontend/app.js` is the sole
primary detection/quarantine surface. Overview may summarize a finding but
must deep-link here. Safe Open and file context remain secondary tools. The
page polls only the current operation status and updates that bounded region;
it must preserve scroll, focus, filters, and navigation state.

Threat notifications do not perform remediation through a second legacy path.
Their only action is to open the authoritative Security Center File Security
surface, where the current detection record and the guarded quarantine,
restore, and deletion transitions are read back.

## Native scan notifications

Security Context's `NotificationRouter` is the sole scan notification publisher.
The file-context companion keeps its existing local progress/result and Strata
Jobs integration; it does not launch a second `notify-send` for scan completion
or failure. Safe Open notices remain independent.

`scan_notices.py` projects recent manual completions from the UID-scoped root
summary (latest plus at most eight recent operations). A newer background job
cannot conceal a manual completion. Successful background work stays silent;
existing finding notices own threat reporting, without an additional completion
toast. Delivery keys are bounded to 128 operations in the user's private runtime
state and survive Context/DMS restarts for the current login. A completed manual
operation is announced once; a later deliberate scan is a new operation.

Native DMS cards retain user notification preferences and layout. The selected
item is the plain-text title, followed by a larger colored result and a useful
caption (for example the number of checked files). Dynamic rich-text content is
escaped; ordinary filename text is never interpreted as markup. Green requires
an explicitly completed, nonempty scan with zero detections, errors and skipped
files; partial/failed scans are amber, findings red, cancellations/empty selections
neutral. Missing counters never produce a clean claim. The fixed result artwork
uses a revisioned local-file URI so the running DMS loads current packaged
artwork without a global cache purge or shell restart. This is a static state
mark, not an elapsed-progress or severity gauge.

The one Review/View scan action opens the authoritative File Security page;
notifications expose no privileged remediation or additional IPC. The original
publisher correction (private development evidence)
remains valid; its initial visual treatment is superseded by the
scan-window refinement (private development evidence).

### Contextual scan window

`file-context/greyward-file-context.py` owns the GTK file-security companion.
Its main composition is the selected item, current scan result, four direct
operation counters (checked, detections, skipped, errors), and a persistent
action footer. An indeterminate native progress bar and Cancel scan appear
only while work is active; cancellation still reaches the existing operation.
No percentage or whole-file-safety claim is inferred from activity.

Provenance, device posture, scan receipts, Safe Open and sanitized-copy actions
remain available in the File context & options disclosure. Device posture is
not presented as a verdict on the selected file. Only a still-valid file receipt
can restore a clean state on reopening; an empty or incomplete operation cannot
be painted green. Unknown counters remain dashes. Long names wrap/ellipsize,
the evidence region scrolls, and the primary actions stay outside that scroller.

The typography, restrained graphite gradient, light edge and coordinated result
mark belong only to this companion and its scan notifications. There is no
system-wide theme, DMS settings, protected profile or authentication change.

## Validation

Backend tests live in `security-center/security-context/tests/` and frontend
contract tests live in `security-center/tauri/frontend/ux-contract.test.mjs`.
At minimum validate clean, EICAR/test-fixture detection, folder and system
scope, cancellation, scanner/signature failures, quarantine/restore/delete,
collision and disk-space failures, restart interruption, history consistency,
quarantine non-execution, and no secret leakage. Runtime acceptance must be
performed on a representative installed GREYWARD system; Windows-only syntax
checks do not replace it. The current physical reference is `<validation-host>`.
The 29 October installed validation (private development evidence)
records package closure, real scans and the before/after cross-user regression,
with interactive and hardware limits distinguished from backend acceptance.
