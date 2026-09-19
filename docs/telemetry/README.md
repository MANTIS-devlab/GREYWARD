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
