# GREYWARD Update Center Architecture

## Purpose

GREYWARD Update Center is a security-aware aggregation, orchestration, and evidence layer. It presents trusted provider state in one place and delegates every update operation to the native provider mechanism.

## Core principle and non-goals

GREYWARD does not:

- implement an update engine or package manager;
- download or manage payloads itself; native providers perform all package, application, firmware, and database work;
- implement a custom rollback or reboot mechanism;
- create a GREYWARD update channel;
- maintain an independent package database;
- expose provider-specific installation, upgrade, rollback, reboot, or refresh commands; native workflow methods remain provider-agnostic and delegate to authoritative providers;
- place provider-specific logic in the UI.

Native provider tools remain responsible for all update and rollback operations.

Recovery V1 adds one narrow pre-update safety step to the existing DNF5
workflow: immediately before an offline transaction is scheduled, the fixed
GREYWARD update transaction helper creates a local Btrfs recovery point. The
same authenticated helper then invokes only the reviewed system-scope native
provider operations. This is a safety point only; it is not a custom rollback
API and does not change Update Center's provider-native update ownership. See
`docs/recovery/RECOVERY_V1.md` for the separate backup and recovery boundary.

## Mandatory implementation order

1. Define the D-Bus contract and normalized data model.
2. Implement provider adapters in priority order.
3. Validate real provider data through the service boundary.
4. Implement bounded evidence history.
5. Integrate the UI against the normalized D-Bus snapshot.

The UI is not the starting point. The complete workflow must be validated as:

```text
provider -> adapter -> D-Bus snapshot -> UI
```

## Authoritative providers

| Priority | Provider | Responsibility |
| --- | --- | --- |
| 1 | rpm-ostree or DNF5 | Host-selected system provider: rpm-ostree for a booted Atomic deployment, otherwise DNF5 for normal Fedora; deployment/package state, pending updates, reboot context, and history |
| 2 | Flatpak | User and system applications, available versions, origins/remotes, and application update history |
| 3 | fwupd | Firmware devices, available releases, restart requirements, provider metadata, and firmware history |
| 4 | freshclam/ClamAV | Signature database version, freshness, last successful update, and failure state |

GREYWARD components are part of the `system` category because they are delivered by the rpm-ostree deployment. There is no separate GREYWARD update category or provider.

Exactly one system provider is exposed in each snapshot. A booted ostree host
selects `rpm-ostree`; a normal Fedora host selects DNF5. The non-selected
provider is omitted rather than reported as `UNAVAILABLE`, because its absence
is expected and is not a degradation of the host's authoritative update path.

## Service boundary

The service exposes a versioned user-bus API:

```text
Bus name:    org.greyward.Update1
Object path: /org/greyward/Update1
```

The UI consumes only this service. It must not invoke rpm-ostree, Flatpak, fwupd, freshclam, or provider-specific command-line tools.

The DMS Secure plugin does not call `org.greyward.Update1` directly. Security
Context reads the bounded transaction state and projects only the update phase
into `greyward.security.shell/v1`. The taskbar shows an update badge only for
an active phase (`RESOLVING`, `AUTHENTICATING`, `DOWNLOADING`, `INSTALLING`,
`VERIFYING`, `PREPARING_RESTART`, or `RESTARTING`). `READY_TO_RESTART` is a
separate flyout message; `COMPLETE`, `FAILED`, and stale terminal records are
never presented as an update currently in progress.

### Normalized reads and bounded native actions

The contract provides normalized read operations such as:

- `GetSnapshot()` — return the current aggregate snapshot;
- `GetProviderStatus()` — return provider availability and collection state;
- `GetHistory()` — return bounded normalized evidence history.

`GetSnapshot()` is non-blocking at the service boundary: it returns the last
successful aggregate immediately and sets `snapshot_refreshing` while provider
queries run in the background. A first read returns explicit `CHECKING` provider
states instead of holding the D-Bus loop open.

Native workflow methods are provider-agnostic:
- `UpdateAll()` — resolve actionable native-provider updates;
- `ApplySystemUpdate()` — authorize and apply through native mechanisms;
- `RestartAndApply()` — request the native restart/apply flow;
- `CancelUpdate()` — cancel only where the native provider supports it.

The UI uses normalized reads and one provider-agnostic workflow. Native action methods delegate to the authoritative provider and return provider-reported state/progress:

- `SnapshotChanged`;
- `ProviderStatusChanged`;
- `HistoryChanged`.

The API must not expose provider-specific commands, package payload operations, custom rollback, or custom reboot logic. Native provider actions remain authoritative; GREYWARD only coordinates them and reports their state.

`UpdateAll()` is strictly a resolve/check transition and has no provider side
effects. `ApplySystemUpdate()` is the explicit mutation transition: it applies
the system provider and then runs only optional providers whose normalized
snapshot reported an actionable update, including when the system provider had
no candidate. A successful optional-provider command is not terminal until a
fresh aggregate snapshot confirms the resulting provider state; an unavailable
or still-actionable provider is surfaced as degraded instead.

The Updates page uses one presentation precedence for its hero, progress region,
action, and live status: an active check or transaction comes first, followed by
`READY_TO_RESTART`, a failed transaction, currently available records, provider
degradation/unavailability, and only then a terminal historical result or the
idle/current state. Thus a completed older transaction cannot replace a current
available-update state. The user-facing Check action invokes the resolve-only
workflow; applying and restarting remain separate actions.

## Provider state

Every provider reports one of these states:

- `AVAILABLE` — provider data was collected successfully;
- `DEGRADED` — partial, stale, malformed, or otherwise limited data was collected;
- `UNAVAILABLE` — the provider is missing, inaccessible, unsupported, or failed completely.

Each state includes:

- collection timestamp;
- last successful data timestamp, when available;
- reason or diagnostic code;
- human-readable diagnostic detail suitable for logs and UI explanation.

A provider failure is never represented as “no updates.” The aggregate snapshot remains useful when any individual provider is degraded or unavailable.

## Normalized data model

Normalized records use these categories only:

- `system`;
- `application`;
- `firmware`;
- `security`.

Each record should preserve:

- stable record identifier;
- category and provider;
- name and provider identifier;
- source, origin, or remote;
- user/system scope or firmware device;
- current version;
- available or pending version;
- update availability;
- pending deployment state;
- reboot requirement;
- rollback availability;
- signature state;
- security relevance;
- provider metadata such as advisory IDs, CVEs, release notes, commit IDs, or digests;
- observation and freshness timestamps;
- provider error or degraded information where relevant.

Unknown values are explicit values, not omitted values and not false defaults.

For system records, the service must make operational context visible:

```text
GREYWARD OS
Update available
Current:  version A
Pending:  version B
Reboot:   Required
Rollback: Available
```

## Evidence-based security context

The service reports evidence, not invented conclusions.

- `Verified` is used only when the authoritative provider confirms verification.
- `Security fix` is used only when explicit provider advisory, CVE, or security metadata exists.
- Trust, signature validity, risk, and security impact are never inferred from names, versions, remotes, URLs, or update size.
- Missing evidence is represented as `Unknown`.
- Restart and rollback fields follow the same provider-confirmed-or-unknown rule.
- ClamAV database freshness is presented as security intelligence freshness, not as a classification of another software update.

## Bounded evidence history

GREYWARD maintains a small normalized evidence journal. This is not a package database and does not store package payloads or downloaded artifacts.

Each entry records only provider-reported or directly observed evidence:

- record identifier;
- normalized component/package identity and category;
- provider;
- previous version;
- resulting version;
- timestamp;
- source;
- result: `SUCCESS`, `FAILURE`, or `UNKNOWN`;
- provider transaction or history identifier, when available.

The presentation keeps architecture and other NEVRA fragments out of version
transitions. If a provider does not supply a previous/resulting version or a
transaction result, the UI says that the field was not supplied instead of
inventing a transition or outcome.

The default retention bound is 200 newest entries total. Older entries are evicted when the bound is exceeded. Native provider history is preferred; GREYWARD must not claim success unless the provider reports success.

Example:

```text
Firefox
145.0 -> 145.1
Date:   provider timestamp
Source: Flathub
Result: SUCCESS
```

## Runtime and failure behavior

- The service runs without elevated UI privileges on the user bus.
- Provider adapters use native APIs; update actions delegate to native provider mechanisms.
- Queries use bounded timeouts and capability detection.
- The production package contract installs `dnf5daemon-server` and
  `dnf5daemon-server-polkit`; the daemon is the preferred D-Bus backend for
  unprivileged resolution. The bounded `dnf5 check-upgrade --json` path remains
  the read fallback. Apply uses the fixed
  `/usr/libexec/greyward-update-action` helper for the reviewed DNF5, system
  Flatpak, and fwupd plan. One `auth_self` Polkit decision covers that closed
  transaction, including the required recovery point; authorization is neither
  passwordless nor cached across actions. User Flatpak updates remain
  unprivileged. While the same helper is still authorized, it asks DNF5 to
  create `/system-update` with `DNF_SYSTEM_UPGRADE_NO_REBOOT=1` and verifies
  that the link targets the stored offline transaction. The later visible
  Restart action therefore uses logind's native active-session policy without
  a second password prompt. After the new boot, a DNF5 plan reaches `COMPLETE`
  only when a matching newer DNF5 history record reports `Ok`; a failed or
  missing provider result remains a visible failure. During that native offline
  boot, the branding package switches Plymouth to update mode before DNF5 starts.
  Its script theme shows explicit install/do-not-power-off copy and consumes
  Plymouth's provider-reported fraction for its progress bar; it shows a
  non-numeric preparing state until that first value arrives. An unavailable
  optional Fedora OpenH264 repository is isolated
  and deferred when it is replacing the installed `noopenh264` placeholder;
  the transaction records that warning while other system updates proceed.
- The helper accepts only provider-selection flags, a bounded operation ID,
  and validated package names produced by the essential-driver resolver. It
  accepts no executable, repository, path, shell text, or arbitrary provider
  arguments. A passwordless rule is intentionally not installed because any
  process running as the user could otherwise initiate privileged updates.
- The service returns partial snapshots when a provider is missing, stale, unsupported, or failing.
- Cached successful state may be retained, but its age must be visible.
- A stale or failed provider must not silently overwrite a valid state with an empty update list.

### Scheduled unattended system updates

The installed production package also ships `greyward-auto-update.timer`. It
runs every two days with a randomized delay and invokes the root-owned
`greyward-auto-update` service. The service performs a read-only `dnf5
check-upgrade --json`; when the normal Fedora system provider reports an
update, it delegates the mutation to the same fixed
`/usr/libexec/greyward-update-action` boundary used by Update Center. That
boundary creates the Recovery V1 safety point and prepares DNF5's native
offline transaction. No user-supplied arguments, shell text, `sudo`, `pkexec`,
or passwordless Polkit rule is involved, and the timer never reboots the
machine automatically. A logged-in desktop user receives a notification that
the update was prepared and a restart is required. System Flatpak, firmware,
and user-scope application updates remain explicit Update Center workflows.

## Validation strategy

Validation must cover the real user workflow, not only adapter unit tests.

### Provider and adapter validation

- rpm-ostree current deployment, pending deployment, reboot, rollback, and history;
- Flatpak user and system installations, update availability, source, versions, and history;
- fwupd device updates, restart requirements, advisory metadata, and history;
- freshclam fresh, stale, missing, and failed database states;
- absent binaries, unavailable services, permission failures, malformed responses, and timeouts.

### End-to-end validation

For each available provider, verify:

1. real provider state is collected;
2. the adapter normalizes it;
3. `org.greyward.Update1` exposes it;
4. the UI renders it without provider knowledge;
5. degraded and unavailable states remain visible with timestamps and reasons.

Acceptance requires the mixed-provider Update Center to remain useful when Flatpak, fwupd, ClamAV, rpm-ostree, or DNF5 is unavailable. No UI code may contain provider-specific commands, schemas, or decision logic.

## Acceptance criteria

The implementation is complete when GREYWARD can display through one normalized security context:

### System

- rpm-ostree status;
- pending update;
- reboot requirement;
- rollback availability;
- update/deployment history.

### Applications

- Flatpak updates;
- application source;
- current and available versions;
- bounded history.

### Firmware

- fwupd status;
- available firmware metadata;
- restart and history context where provided.

### Essential PCI driver support

The normal Fedora/DNF5 system provider also performs a bounded check for
unbound PCI devices in the display (`03`), network (`02`), and mass-storage
(`01`) classes. A device with a sysfs `driver` link is considered handled;
GREYWARD does not choose between working drivers or replace Nouveau. For an
unbound device, its sysfs `modalias` is passed to DNF5 `repoquery
--whatprovides modalias(...)` and only an available, non-debug RPM from the
currently enabled repositories is surfaced as a normal `system` record.

The DNF5 daemon adds those package names to the same in-memory install/update
goal as the existing system update. Apply gives the fixed helper only the
validated package names; when any are present, DNF5's multi-action `do` command
combines the full upgrade and their installation into one stored offline
transaction. There is no second offline goal, separate UI transaction, or
privileged service. If the modalias has no suitable provider, or a matching
package is already installed, the device remains `UNRESOLVED` and no
speculative action is taken. Firmware remains owned exclusively by fwupd.

### Security

- ClamAV database freshness;
- last successful update;
- stale or failure state.

The complete provider -> adapter -> D-Bus snapshot -> UI workflow is validated with real provider data and degraded-provider scenarios. No provider mutation or independent GREYWARD update mechanism exists.

## Flatpak application-layer integration

Flatpak is the normalized `application` provider. The adapter scans user and system scopes with bounded native queries and preserves application ID, origin, version, architecture, branch, runtime, and explicit unknown trust/restart values. Flatpak tabular output is not JSON and must be parsed as tabular data. `UpdateAll` runs user and system Flatpak transactions through the provider boundary; no Tauri/QML surface may call Flatpak directly. Progress is indeterminate unless the native provider reports a trustworthy value, and cancellation is advertised only when supported.

Bazaar/Software is an install, remove, and discovery surface. GREYWARD Update Center remains the canonical application-update workflow; Bazaar update controls are disabled through its distributor configuration.
