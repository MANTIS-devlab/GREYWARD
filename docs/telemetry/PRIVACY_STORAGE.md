# Privacy and storage

The user-readable normalized history is a per-user SQLite store at
`$XDG_STATE_HOME/greyward/telemetry/events.sqlite3` (normally
`~/.local/state/greyward/telemetry/events.sqlite3`). It is local,
schema-controlled, append-oriented, and not opened directly by the UI.

Root-owned collectors do not write this user database. They keep the same
approved events in a bounded ephemeral spool at
`/run/greyward-security-context/telemetry-events.jsonl`; the unprivileged
Security Context user service imports and deduplicates that spool into its own
store during background reconciliation. History and digest reads use read-only
connections and do not import records or generate findings. Journald remains the native
source of truth, so a reboot can lose only the handoff copy before import.

The store uses SQLite WAL mode with bounded checkpoints. The default total
budget is 128 MiB, including the database, WAL, shared-memory file, and
temporary storage. Expired investigation events are deleted first; oldest
investigation events are removed before semantic events under size pressure.
Forced eviction is reported in source status. Corruption is detected and the
store is quarantined rather than treated as an empty history.

GREYWARD producers also emit the same already-redacted event envelope to
journald when the Python systemd journal binding is available. Journald is the
native evidence reference and per-user SQLite is the indexed historical
projection; no raw native message or complete journal record is copied into
the store.

Persisted network activity is limited to timestamp, application identity,
already-observed destination domain/IP, protocol, port, decision, control/rule
attribution, correlation IDs, and quality metadata.

Protected Data denials may retain a historical kernel PID, a bounded executable
basename, audit occurrence time and collection policy revision. Full executable
paths, process titles and arguments are discarded. Application identity stays
UNKNOWN without generation-bound evidence; historical PIDs are never joined to
current processes. Resource references resolve to registry labels at UI refresh,
not stored secret paths. Legacy records are not retroactively attributed.

Never store packet contents, URLs or HTTP paths, payloads, process arguments,
environment variables, passwords, tokens, keys, clipboard contents, document
contents, generalized browsing or DNS history, remote enrichment, raw
OpenSnitch protobuf, raw nftables, or complete journal records.

Redaction happens before insertion. Inputs are type-checked, length-bounded,
control-character-free, and safe for display. Secret-looking keys are removed
and untrusted messages are never used as shell, path, markup, or query text.
Native evidence references do not copy the referenced raw record; an expired
reference is reported as unavailable.

Device history uses a local HMAC key over approved stable device metadata. Raw
serial numbers and hardware identifiers are not persisted. If a stable device
identity cannot be safely derived, the record is low-confidence and reconnects
are not merged as the same device. USB telemetry unavailable is represented as
unavailable, never as zero devices.

## Security Center local activity (source implementation)

`greyward_security_context/local_activity.py` owns the compatibility projection
for presentation actions. It uses this same SQLite store, the fixed
`security-center/presentation` source and `LOCAL_ACTIVITY` category. These
records are explicitly unverified, non-authoritative observations; they cannot
establish a protection result or kernel evidence.

Background reconciliation imports the former
`$XDG_STATE_HOME/greyward/security-center/activity.json` once. Events and the
migration receipt commit together, with deterministic deduplication, a 64-item
collection limit and 30-day semantic retention. The original JSON is retained
unchanged as a historical rollback input; new writes use only telemetry.
Private paths and secret-looking values are redacted before persistence.

The typed Context methods `GetLocalActivity`, `RecordLocalActivity` and
`ClearLocalActivity` expose only this fixed collection. Clearing verifies its
removal and prevents reimport; it preserves other security history and the
original rollback file. It therefore does not erase all stored security data.
Unavailable or malformed reads remain unavailable, rather than an empty list.
This source replacement requires a matched Center/Context package promotion;
the currently installed Context 64 is not acceptance evidence for these methods.
