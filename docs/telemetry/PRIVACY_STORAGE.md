# Privacy and storage

The user-readable normalized history is a per-user SQLite store at
`$XDG_STATE_HOME/greyward/telemetry/events.sqlite3` (normally
`~/.local/state/greyward/telemetry/events.sqlite3`). It is local,
schema-controlled, append-oriented, and not opened directly by the UI.

Root-owned collectors do not write this user database. They keep the same
approved events in a bounded ephemeral spool at
`/run/greyward-security-context/telemetry-events.jsonl`; the unprivileged
Security Context user service imports and deduplicates that spool into its own
store before answering history or digest queries. Journald remains the native
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
