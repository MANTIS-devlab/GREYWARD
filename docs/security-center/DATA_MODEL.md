# Data model

This file is the sole authority for Security Center runtime and serialized data
contracts. Rust names are illustrative but normative at the field/behavior
level.

## Identifiers and versioning

- Application ID: `systems.mantis.greyward.securitycenter`.
- Snapshot format: `greyward.security.snapshot/v1`.
- Check IDs use stable dotted names such as `system.selinux.mode` and
  `network.firewall.active-zone`.
- Backend IDs are stable implementation-neutral names such as `selinux`,
  `fwupd`, `network-manager`, and `portal-permission-store`.
- Renaming a check requires an explicit migration alias. Meaning changes require
  a new definition version.

## Core types

```text
PostureSnapshot
  schema: string
  generated_at: UTC timestamp
  boot_id: optional redacted identifier
  evaluator_version: string
  policy_profile: string
  domains: list<DomainResult>
  checks: list<CheckResult>
  collection_issues: list<CollectionIssue>

CheckResult
  check_id: string
  definition_version: integer
  domain: Domain
  state: PostureState
  reason_code: string
  summary: localized-message key + safe parameters
  explanation: localized-message key + safe parameters
  observed_at: UTC timestamp
  fresh_until: UTC timestamp
  applicability: Applicability
  requiredness: Requiredness
  capability_status: CapabilityStatus
  evidence: list<Evidence>
  remediation: optional RemediationDescriptor
```

`Domain` and `PostureState` are closed enums defined by `POSTURE_MODEL.md`.
Unknown serialized enum values are rejected as version skew and presented as a
collection issue, not silently coerced.

## Evidence

```text
Evidence
  evidence_id: string
  source: EvidenceSource
  kind: EvidenceKind
  value: typed scalar or bounded typed object
  sensitivity: PUBLIC | DEVICE | USER | SECRET
  display_policy: FULL | REDACTED | SUMMARY_ONLY | NEVER_EXPORT
  observed_at: UTC timestamp
  provenance: backend version and interface version
```

Evidence sources identify a library/API and object, not a shell command.
Examples include a D-Bus bus/interface/property, a library call, an efivar name,
or a kernel virtual-file identity. Raw journals, environment blocks, command
lines, access tokens, file contents, and unrestricted paths are not evidence
values.

Evidence values have explicit maximum lengths and collection sizes. Strings are
valid UTF-8 or converted to a typed invalid-evidence error. Rendering treats all
backend text as data; it never interprets markup.

## Product projections

Route projections preserve the distinction between measured evidence and
product presentation. The frontend renders backend-owned semantic presentation
keys and does not maintain another check-ID-to-copy or check-ID-to-route table.
Implementation identifiers may appear only in a named technical disclosure.
Timestamps cross the Rust/frontend boundary as RFC 3339 UTC values; the
frontend formats them in the active desktop locale rather than consuming
backend-formatted English date strings.

```text
ApplicationAccess
  inventory_state: AVAILABLE | PARTIAL | UNAVAILABLE
  inventory_total, shown_count, review_needed_count: exact complete-inventory
    counts when AVAILABLE; discovered-only counts when PARTIAL
  applications[]:
    name: user-facing application name
    access_state: SCOPED | REVIEW_NEEDED
    access_categories: normalized NETWORK | PERSONAL_FILES | HOST_FILES |
      DEVICES | ALL_DEVICES | DESKTOP_SERVICES | SCOPED
    review_reasons: normalized categories only
    technical: app identifier, installation/runtime identity, manifest grants,
      and local overrides
  effective access: backend applies manifest context before local override
    additions/removals; raw records never determine primary presentation

EvidencePresentation
  domain_key, title_key, summary_key, recorded_result_key, recommendation_key:
      semantic product-copy keys owned by the backend presentation adapter
  values: bounded interpolation values only
  remediation: optional route + semantic action key
  no_remediation_key: product-safe explanation when no direct action exists
  state: measured posture state
  accepted_deviation: boolean
  technical: check reference, reason code, observed_at, fresh_until

BackupOperation
  kind: BACKUP | VERIFY | RESTORE
  state: RUNNING | COMPLETED | FAILED
  started_at, completed_at: UTC timestamps
  problem: CHECK_PASSPHRASE | CHECK_DESTINATION | TRY_LATER |
    SERVICE_UNAVAILABLE | TRY_AGAIN, when failed
```

`BackupOperation` is durable helper state. A frontend working indicator is not
an authoritative backup result. Raw Restic output and stored provider errors do
not cross this projection boundary.

## Application-network projection

The additive user-bus contract `greyward.security.network/v1` is separate from
the DMS-facing `greyward.security.context/v1` summary:

```text
NetworkProtection
  schema: greyward.security.network/v1
  generated_at: UTC timestamp
  fresh_until: UTC timestamp
  opensnitch: source health, version, freshness, bounded counters, capabilities
  applications: grouped application activity summaries
  activity: bounded normalized connections
  rules: bounded normalized rules with source and mutability

NetworkActivity
  event_id: bounded stable identifier
  sequence: monotonic session-local cursor
  occurred_at: UTC timestamp
  application: display label
  executable: bounded executable identity or null
  destination: host, IP, and port where reported
  protocol: bounded protocol label or null
  decision: ALLOWED | BLOCKED | UNKNOWN
  rule_name: matched rule or null
  source: normalized producer

NetworkActivityQuery
  schema: greyward.security.network.activity/v1
  session_id: control-plane observation session
  generated_at: UTC timestamp
  fresh_until: UTC timestamp
  next_sequence: next session-local cursor
  reset: boolean when the requested cursor is no longer retained
  summary: bounded counts and one-minute buckets for 30 minutes
  rule_mutation: TYPED_POLICY or UNAVAILABLE
  events: newest-first bounded event batch
```

OpenSnitch and firewalld remain separate evidence sources. Network activity is
redacted and bounded; process arguments, environment, cwd, raw protobuf, raw
nftables, and unrestricted paths are never serialized. A missing daemon is
`UNAVAILABLE`; a stale heartbeat is `DEGRADED`; neither state is coerced to
 protected. The live activity working set is limited to 4,096 events or 30
minutes. Approved redacted network events may also enter the separate bounded
telemetry history; this does not create a browsing or DNS history. Throughput,
active connection counts, DNS history, reputation, and server-location
enrichment are not part of this contract. The Security Context may derive a
local endpoint-country flag from the observed public destination IP using
local GeoIP databases and optional local geofeed data; when those sources are
empty, it may carry a separate `DOMAIN_SUFFIX` display hint with `VERY_LOW`
confidence. That hint never overrides IP evidence or claims server location,
and reverse DNS, provider ownership hints, and remote services are never used.
The
resolver always selects a deterministic country when at least one local source
answers, and exposes transient `country_confidence` and `country_converged`
metadata alongside the two-letter code. These fields are activity projection
metadata and are not serialized into the telemetry event. Missing, private,
or unresolved addresses use a neutral world marker and remain explicitly
unknown.

Security Center history uses `GetSecurityCenterDigest`; the DMS plugin uses the
compact `GetShellSummary` projection. Both are built from one backend
aggregation path. External-device identity is an opaque local
`HMAC(local_key, approved_stable_metadata)` value. Missing or unsafe stable
metadata is low-confidence and cannot promise reconnect deduplication.
Disconnected unknown devices remain seven-day history but are not active
unresolved findings by default. Repeated blocked network activity is
noteworthy history and does not create `Review needed` without an additional
deterministic security signal.

## Capability status

The research/roadmap maturity labels are serialized as:

- `VERIFIED`
- `CANDIDATE`
- `PROTOTYPE_REQUIRED`
- `HARDWARE_VALIDATION_REQUIRED`
- `DEFERRED`
- `NOT_GENERICALLY_ENFORCEABLE`

Runtime availability is separate:

```text
AVAILABLE | ABSENT | UNSUPPORTED | DENIED | FAILED | VERSION_MISMATCH
```

This prevents a researched candidate from being presented as available merely
because a package name exists.

## Applicability and collection errors

```text
Applicability
  applies: boolean
  reason_code: string
  facts: bounded non-sensitive map

CollectionIssue
  backend_id: string
  category: ABSENT | DENIED | TIMEOUT | MALFORMED | STALE | VERSION | INTERNAL
  safe_message: localized-message key
  observed_at: UTC timestamp
  retryable: boolean
```

Internal error details may go to the local journal under a stable correlation ID
after redaction. The snapshot contains only safe messages.

## Remediation

```text
RemediationDescriptor
  action_id: string
  mode: RECOMMENDATION | HANDOFF | USER_API | UPSTREAM_POLKIT | GREYWARD_HELPER
  title: localized-message key
  consequence: localized-message key
  reversibility: REVERSIBLE | PARTIALLY_REVERSIBLE | IRREVERSIBLE
  confirmation: NONE | STANDARD | HIGH_RISK
  availability: runtime capability
  expected_effect: typed predicate
```

V0 permits `UPSTREAM_POLKIT` only for the active-network trust-zone operation
and permits `USER_API` for verified portal permission changes. It does not
implement `GREYWARD_HELPER`.

An undo token is memory-only, short-lived, bound to the action, caller session,
backend identity, original object identity, and exact prior value. It is invalid
after reboot, connection replacement, backend restart that changes identity, or
expiry.

## Activity

```text
ActivityItem
  event_id: transient correlation identifier
  category: fixed enum
  severity: INFORMATION | REVIEW | IMPORTANT
  occurred_at: UTC timestamp
  source: EvidenceSource
  title/details: localized-message keys + redacted parameters
  related_check_id: optional string
```

V0 activity is a bounded in-memory/query result, not a second full security log.
Approved normalized events are persisted separately by the GREYWARD telemetry
history contract; full journal entries are never copied. File Security adds
typed bounded scan-operation, detection, and action records to that same local
store; it does not create a second database. `severity` controls presentation
only and does not alter posture without a check definition.

## Local state

Permitted persistent state:

- user preferences under `$XDG_CONFIG_HOME/greyward/security-center/`;
- one bounded posture snapshot and non-sensitive UI state under
  `$XDG_STATE_HOME/greyward/security-center/`.

Files are owned by the user, mode `0600`, written to a same-directory temporary
file, flushed, and atomically renamed. Directories are mode `0700`. Symlinks and
non-regular targets are rejected. The posture cache remains file-based; the
separate bounded telemetry history uses SQLite as documented in
`docs/telemetry/PRIVACY_STORAGE.md`.

Exports are explicit user actions through the file chooser portal. The default
export omits `SECRET`, applies redaction to `DEVICE` and `USER`, includes schema
and timestamps, and clearly labels stale/unknown evidence.
