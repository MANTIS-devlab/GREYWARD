# Correlation and query

Exact correlation uses boot ID, session ID, operation ID, DNF transaction ID,
systemd unit/invocation ID, rule ID, application identity, network identity,
and explicit parent event IDs. PID links require boot and process-start
context.

Heuristic links are allowed only with a documented time window and basis, and
are marked `HEURISTIC`. Supported relations include `FOLLOWS`, `CAUSED_BY`,
`RETRY_OF`, `SAME_OPERATION`, `SUPERSEDES`, and `RELATED_TO`. Reboots are hard
boundaries.

The existing `GetNetworkActivity` method remains the live cursor API. Historical
and incident queries use the narrow read-only methods:

```text
QueryTelemetry(request_json) -> response_json
GetRelatedTelemetry(request_json) -> response_json
```

Queries are limited to time, source, component, category, event type, severity,
assessment, application, boot/session, operation, transaction, unit, rule, and
bounded result size. Pagination uses an opaque `(occurred_at, event_id)` cursor,
not offsets. Responses include available ranges, source freshness, truncation,
eviction, and permission/unavailability state.

The user-bus also exposes purpose-built projections: `GetSecurityCenterDigest`
for Security Center, `GetShellSummary` for the compact DMS plugin,
`GetNetworkHistory`, `GetDeviceOverview`, and `GetCapabilityHistory`. The first
two call the same backend aggregation logic; frontends do not aggregate raw
events or infer findings.

Future local AI receives bounded observations, related events, deterministic
signals, confidence, uncertainty, event IDs, and native references. It receives
no unrestricted journal dump and has no endpoint that changes source evidence
or performs remediation.
