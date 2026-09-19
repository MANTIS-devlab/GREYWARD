# File Security

This is the canonical product and implementation contract for GREYWARD File
Security. It describes the deliberately small workflow:

`Scan → Detect → Explain → Quarantine → Restore or Delete`.

## Scope

GREYWARD uses the existing Security Context boundary and local ClamAV
invocation. V1 supports three scan modes:

- **File scan:** one user-owned regular file selected by the user.
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
`CURRENT`, `INITIALIZING`, `UPDATING`, `OUTDATED`, or `UNAVAILABLE` from that
lifecycle and never starts an ad-hoc update. If the engine or definitions are
not ready, the service refuses a new operation rather than queueing a scan that
could not produce a trustworthy result; the UI keeps the page readable and
explains the actual state.

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

## Privilege boundary

The unprivileged Security Context exposes typed user-bus methods and proxies
the bounded operation/remediation calls to the existing root-owned,
one-shot-style ClamAV D-Bus service. The service is constrained by the system
D-Bus policy and does not expose a shell or arbitrary ClamAV access. The V1
repository currently uses the existing desktop-admin (`wheel`) D-Bus policy;
it does not add a new daemon or claim a separate Polkit action until the
authorization model is reviewed against the installed policy.

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

## Validation

Backend tests live in `security-center/security-context/tests/` and frontend
contract tests live in `security-center/tauri/frontend/ux-contract.test.mjs`.
At minimum validate clean, EICAR/test-fixture detection, folder and system
scope, cancellation, scanner/signature failures, quarantine/restore/delete,
collision and disk-space failures, restart interruption, history consistency,
quarantine non-execution, and no secret leakage. Runtime acceptance must be
performed in GREYWARD-DEV; Windows-only syntax checks do not replace it.
