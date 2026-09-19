# Telemetry testing

Tests must cover:

- envelope validation, schema migration, typed fields, and bounded payloads;
- secret, token, environment, command-line, path, and control-character redaction;
- persisted network activity containing only its approved projection;
- live 4,096-event/30-minute behavior remaining separate from history;
- 7-day investigation and 30-day semantic expiry;
- 128 MiB database/WAL/temporary-file budget and forced eviction reporting;
- deterministic cursor pagination under inserts;
- bidirectional related-event lookup and heuristic-confidence labeling;
- malformed input, corrupted SQLite, journal/source gaps, and permission denial;
- reboot/session boundaries and source freshness;
- high-volume ingestion without blocking live Security Context behavior;
- root-collector handoff through the bounded runtime spool into a per-user
  SQLite database, including deduplication and malformed-line rejection;
- reconstruction of blocked network, restarting service, failed update,
  security-control degradation, and configuration-failure chains.

Run the focused suite with:

```text
PYTHONPATH=security-center/security-context python3 -m unittest discover -s security-center/security-context/tests -p 'test_telemetry.py'
```

The GREYWARD-DEV acceptance pass must additionally generate real network
activity, update/recovery operations, service failure, and reboot boundaries.
