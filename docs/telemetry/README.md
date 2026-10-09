# GREYWARD telemetry

This is the canonical documentation for GREYWARD's normalized telemetry
contract. Native journald, kernel, audit, OpenSnitch, NetworkManager,
firewalld, DNS, update, recovery, and Security Context evidence remains
authoritative; this layer provides safe semantic history and bounded queries.

## Authorities

- [EVENT_MODEL.md](EVENT_MODEL.md) — event envelope, typed fields, and versioning.
- [SOURCES.md](SOURCES.md) — source ownership, adapters, and availability.
- [PRIVACY_STORAGE.md](PRIVACY_STORAGE.md) — redaction, SQLite history, limits, and deletion.
- [CORRELATION_QUERY.md](CORRELATION_QUERY.md) — correlation, pagination, and AI boundary.
- [TESTING.md](TESTING.md) — privacy, retention, parser, and incident reconstruction tests.

## Retention layers

1. **Live activity:** the OpenSnitch in-memory working set, approximately 30
   minutes and 4,096 events, for the Network Activity UI.
2. **Investigation history:** approved normalized events in bounded SQLite,
   retained for 7 days by default.
3. **Important semantic events:** failures, degradation, configuration changes,
   update, recovery, and service lifecycle events in the same store, retained
   for 30 days by default.

The SQLite store is local history, not a SIEM and not a replacement for native
evidence.

Findings are derived when normalized events are ingested and when device state
is reconciled/reviewed. Digest/history reads use read-only SQLite connections;
they do not create storage, migrate schema, import the root spool or reopen
resolved findings. The existing session runtime imports the root spool during
background collection. It also backfills existing event-derived findings in
batches of at most 64, with a transactional stable-event-ID cursor and without
resetting existing resolutions. No parallel history database is introduced.
Live provider collection and device observation remain separate from that
historical projection; they can reconcile state. Missing/corrupt history stays
unavailable rather than becoming an empty successful result. This source change
is not yet deployed in a new Context package.
