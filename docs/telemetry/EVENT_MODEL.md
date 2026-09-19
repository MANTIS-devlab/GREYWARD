# Event model

Schema identifier: `greyward.telemetry.event/v1`.

Each normalized event has a stable `event_id`, `schema`, `occurred_at`,
`observed_at`, optional `monotonic_ns`, `boot_id`, optional `session_id`,
`component`, `source`, `category`, `event_type`, `action`, `outcome`,
`severity`, `assessment`, correlation identifiers, `quality`, safe
`native_evidence`, bounded relations, and typed `details`.

`severity` is impact (`INFO`, `NOTICE`, `WARNING`, `ERROR`, `CRITICAL`).
`assessment` is interpretation (`NORMAL`, `NOTEWORTHY`, `DEGRADED`, `FAILED`,
`POTENTIALLY_SUSPICIOUS`, `UNKNOWN`). A blocked connection is not suspicious
unless an explicit rule or source signal supports that assessment.

Network `event_type` describes what happened, such as
`CONNECTION_ATTEMPT`, `POLICY_DECISION`, or `CONTROL_STATE_CHANGE`.
`protocol` describes TCP, UDP, QUIC, or another transport/application protocol;
these are separate concepts.

Typed domains cover boot, service lifecycle, kernel/storage, authentication,
processes, network, DNS, devices, updates, configuration, recovery, and
GREYWARD operations. Producers must use only fields meaningful to their
domain; raw messages are not a substitute for typed details.

Events use `retention_class: investigation` or `semantic`. Investigation
events expire after 7 days by default; semantic events expire after 30 days.
Schema changes require a new version or a documented additive migration.

## Device identity

External-device history stores only an opaque identity derived as
`HMAC(local_key, approved_stable_metadata)`. The local key is user-owned and
mode `0600`; raw serials, descriptors, and hardware identifiers are never
stored or displayed. When approved stable metadata is insufficient, the event
uses `identity_confidence: LOW` and does not claim reconnect deduplication.

Only approved external/removable classes enter device history. Internal
USB-backed components are not treated as external devices.
