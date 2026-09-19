# V0 execution plan

Status: Historical V0 execution sequence. Sessions 1–9 record implementation
and runtime iteration; Session 10 is retained as a validation backlog rather
than a current project-wide release gate. Fedora, real-window, runtime, privacy,
and image-artifact evidence remains useful for alpha/beta testing.

Run sessions in order. A session marked `PARTIAL` remains incomplete until its
stop condition passes or an approved deviation updates this plan. Post-V0
milestones never increment the V0 count.

The V0 read-only statement below applies to posture controls and adapters. The
separate, runtime-gated Update Center workflow is governed by
`docs/architecture/UPDATE_CENTER_ARCHITECTURE.md`; its explicit native-provider
Apply/Restart transitions are not a V0 posture-control claim.

Global do-not-touch boundary for every session: DMS functional/core code,
Labwc, PAM, greetd, authentication, boot, disk-unlock behavior, system security
configuration, unrelated Settings code, STENOS, and legacy Security Center
placeholders. Do not install experimental security backends unless a later
prototype plan explicitly authorizes an isolated environment.

## Session 1 — Application foundation and domain contract

**OBJECTIVE**

Create the Rust workspace, empty GTK4/libadwaita application, build/RPM skeleton,
test harness, stable domain types, snapshot v1 serialization, semantic states,
and deterministic evaluator.

**WHY**

Every backend and UI view depends on a tested evidence contract. Establishing it
first prevents adapters or visuals from inventing posture semantics.

**INPUT DOCS**

`PRODUCT.md`, `ARCHITECTURE.md`, `DATA_MODEL.md`, `POSTURE_MODEL.md`,
`PRIVILEGE_MODEL.md`, `TESTING.md`, `ACCEPTANCE.md`.

**SCOPE**

- Workspace/crate dependency direction.
- Application ID and empty navigable window.
- Closed enums, check definitions, results, evidence, capability/runtime status,
  remediation descriptors, collection issues, snapshot v1.
- Pure applicability, freshness, check evaluation, and domain aggregation.
- JSON round-trip and forward-version rejection fixtures.
- Reproducible dependency lockfile and basic RPM metadata.

**DO NOT TOUCH**

No live backend calls, D-Bus control, DMS plugin, root service, security setting,
or real posture copy beyond fixture labels.

**IMPLEMENTATION BOUNDARY**

The domain crate has no GTK or backend dependency. The empty UI consumes fixture
snapshots only. No subprocess dependency is introduced.

**VALIDATION**

- Clean build and test from documented Fedora build dependencies.
- Exhaustive aggregation table across six states and requiredness classes.
- Snapshot round-trip, unknown version/enum, malformed, bounds, and migration
  alias tests.
- Lints and dependency/license inventory.

**VISUAL VALIDATION**

Launch the empty window under canonical DMS/Labwc and verify native decoration,
application ID, focus, scaling, and no placeholder/panel change.

**SECURITY VALIDATION**

Prove the process UID is nonzero, the package contains no Polkit action/helper,
and domain parsing rejects oversized/unknown data safely.

**ROLLBACK IF RELEVANT**

Remove only the newly installed development RPM/files; no system state should
otherwise differ.

**ACCEPTANCE**

Application builds and launches, all domain tests pass, snapshots round-trip,
and aggregation exactly matches `POSTURE_MODEL.md`.

**STOP CONDITION**

Stop before implementing any live adapter. Report Session 1 PASS only with the
test and package inventory evidence.

## Session 2 — Evidence framework and core system posture

**OBJECTIVE**

Implement adapter lifecycle, cancellation/timeouts, evidence normalization,
redaction, freshness/cache handling, and read-only SELinux, boot/kernel,
storage-encryption, and basic TPM adapters.

**WHY**

These checks establish useful honest posture without network access or
privileged mutation and exercise the complete evidence pipeline.

**INPUT DOCS**

`ARCHITECTURE.md`, `BACKENDS.md`, `DATA_MODEL.md`, `POSTURE_MODEL.md`,
`PRIVACY.md`, `THREAT_MODEL.md`, `RESEARCH.md`.

**SCOPE**

- Concurrent collection generations, per-adapter deadline, cancellation,
  invalidation, and immutable results.
- Atomic bounded XDG snapshot/preferences storage.
- `libselinux` runtime/config evidence.
- UEFI/Secure Boot and supported kernel facts.
- Complete root/home/swap block topology and encrypted-ancestor evidence.
- TPM device/capability presence without enrollment or secret reads.
- Fixtures for enforcing/permissive/disabled, UEFI/legacy, LUKS/plain, TPM/no
  TPM, denied, malformed, timeout, stale, and boot change.

**DO NOT TOUCH**

Do not change SELinux, firmware, boot, storage, TPM, mounts, encryption, or
system files. Do not invoke `getenforce`, `mokutil`, `lsblk`, `cryptsetup`, or
`systemd-analyze` as product backends.

**IMPLEMENTATION BOUNDARY**

Adapters return typed facts only. Local state is user-owned, `0700`/`0600`,
bounded, symlink-safe, and never an authorization source.

**VALIDATION**

- Unit/fixture tests for each state and topology.
- GREYWARD VM comparison against separately collected diagnostic evidence.
- Resume/reboot/stale invalidation tests.
- Corrupt/oversized/symlinked cache tests.

**VISUAL VALIDATION**

Fixture-only diagnostic view or test harness displays protected, action-required,
unknown, unavailable, and stale evidence without clipped/unsafe text. No final UI
polish is required.

**SECURITY VALIDATION**

Confirm read-only file/library access, bounded data, no secrets/key slots,
escaped evidence, no root/Polkit, and cache tampering cannot alter evaluation
without fresh authoritative evidence.

**ROLLBACK IF RELEVANT**

Remove user cache/preferences and development package; system security state is
unchanged.

**ACCEPTANCE**

The VM honestly reports SELinux enforcing, UEFI/Secure Boot evidence, plain root
storage, and unavailable TPM capability. Every query failure has a deterministic
safe state.

**STOP CONDITION**

Stop after core-system checks and framework tests pass. Do not add fwupd, DNF,
network, portal, event, or control work.

## Session 3 — Firmware and update readiness

**OBJECTIVE**

Implement read-only fwupd device/HSI/history and DNF5 security-advisory adapters
with explicit cached/offline/stale/unsupported behavior.

**WHY**

Firmware and security-update readiness are central posture facts, but V0 must
not silently access the network or apply updates.

**INPUT DOCS**

`RESEARCH.md`, `CAPABILITY_MATRIX.md`, `BACKENDS.md`, `PRIVACY.md`,
`POSTURE_MODEL.md`, `TESTING.md`.

**SCOPE**

- `libfwupd` daemon/version, devices, cached updates, history, individual host
  security attributes and HSI metadata.
- DNF5 daemon package/interface verification, read-only sessions, upgrade
  candidates and matched security advisories from cached metadata.
- Missing daemon, offline, stale metadata, no supported devices, HSI unavailable,
  denied, timeout, malformed, and version mismatch fixtures.
- Clear future handoff text without apply buttons.

**DO NOT TOUCH**

No metadata refresh on app open, firmware flash, BIOS setting change, report
upload, package transaction, repository/key change, offline update scheduling,
reboot, or fallback command parsing.

**IMPLEMENTATION BOUNDARY**

Use `libfwupd` and `org.rpm.dnf.v0`. If the DNF5 daemon API/package is unsuitable,
record the evidence and expose `UNAVAILABLE`; do not substitute PackageKit or
CLI parsing without a plan change.

**VALIDATION**

- Recorded D-Bus/library interface versions and typed fixture coverage.
- Cached, empty, stale, network-offline, daemon restart, denied, and malformed
  cases.
- Advisory-to-package matching correctness.
- Hardware HSI cases where available; Hyper-V unavailability is an expected
  honest result, not full hardware acceptance.

**VISUAL VALIDATION**

Diagnostic/detail presentation differentiates “no updates,” “metadata stale,”
“unsupported device,” and “unable to check.” Attribute-level HSI detail does not
look like a GREYWARD score.

**SECURITY VALIDATION**

Packet capture/network monitoring proves ordinary collection makes no external
request. No transaction or firmware method is reachable from V0 code paths.

**ROLLBACK IF RELEVANT**

Remove only Security Center build/package additions. If a build dependency was
added to the image definition, revert only that declared dependency change; no
runtime service state is enabled by the app package.

**ACCEPTANCE**

Read-only firmware/update evidence is deterministic and truthful across all
documented failure cases; no mutation or hidden network activity occurs.

**STOP CONDITION**

Stop before implementing refresh/apply workflows or network posture.

## Session 4 — Network posture and reversible trust control

**OBJECTIVE**

Implement NetworkManager, DNS, VPN-presence, and firewalld inspection plus the
single active-connection trust-zone control with verification and undo.

**WHY**

This supplies useful network protection context and exercises the approved
upstream Polkit control boundary without becoming a firewall editor.

**INPUT DOCS**

`BACKENDS.md`, `PRIVILEGE_MODEL.md`, `THREAT_MODEL.md`, `POSTURE_MODEL.md`,
`UX_SPEC.md`, `TESTING.md`, `ACCEPTANCE.md`.

**SCOPE**

- `libnm` active connection, type, applicable Wi-Fi security, VPN/tunnel
  presence, DNS/effective resolver facts, and connection zone.
- firewalld service/version/default/active zone and selected connection
  association.
- Exact control flow from `PRIVILEGE_MODEL.md`, including preview, confirmation,
  upstream Polkit, re-read, result, and bounded undo.
- Offline, split DNS, DNSSEC/DoT modes, VPN, firewalld missing/restart, connection
  replacement, denial, cancellation, and mismatch tests.

**DO NOT TOUCH**

No raw nftables, rich rules, ports, services, panic, reload, zone creation,
inactive-profile edits, VPN configuration, resolver changes, remote-access
changes, or GREYWARD Polkit policy/helper.

**IMPLEMENTATION BOUNDARY**

Only one active NetworkManager connection and an installed upstream zone can be
targeted. The adapter—not the UI—resolves and validates object identity.

**VALIDATION**

- Unit/D-Bus mock tests for all reads/actions.
- VM action matrix: confirm/cancel/deny/succeed/timeout/service restart/object
  replacement/undo/undo expiry.
- Verify unrelated connection/firewall settings byte-for-byte or via complete
  API snapshots before/after.
- Test IPv4, IPv6, offline, VPN, reconnect, suspend/resume, and SSH development
  connectivity safety.

**VISUAL VALIDATION**

Exercise preview, graphical authentication wait, cancel, success, failure,
refresh, and undo under DMS/Labwc using keyboard and pointer.

**SECURITY VALIDATION**

No background Polkit prompt, no authorization reuse, target revalidation across
the authorization boundary, bounded zone values, and no success before exact
verification.

**ROLLBACK IF RELEVANT**

Use the captured prior zone through the same verified API; if identity changed,
invalidate undo and show current authoritative state. The session ends with the
original VM zone restored.

**ACCEPTANCE**

Network posture is honest and the one mutation family is bounded, user-initiated,
verified, reversible, and leaves unrelated configuration unchanged.

**STOP CONDITION**

Stop before adding any other firewall, DNS, VPN, or application-network control.

## Session 5 — Application isolation and portal permissions

**OBJECTIVE**

Implement Flatpak/application isolation visibility, portal health, Documents and
PermissionStore evidence, and revoke/restore only for verified permission
schemas.

**WHY**

Users need to distinguish sandboxed permissions from native-app trust while V0
retains a safe user-session remediation path.

**INPUT DOCS**

`RESEARCH.md`, `CAPABILITY_MATRIX.md`, `BACKENDS.md`, `PRIVILEGE_MODEL.md`,
`PRIVACY.md`, `UX_SPEC.md`, `TESTING.md`.

**SCOPE**

- User/system Flatpak presence, apps, declared permissions, and effective
  overrides through supported APIs.
- Portal owner/version/backend health.
- Versioned fixture registry for understood PermissionStore tables.
- Documents list/info/revoke/grant where documented.
- Preview, verify, bounded restore, app/resource replacement, unknown table,
  absent Flatpak, and malformed payload behavior.

**DO NOT TOUCH**

No Flatpak install/remove/update, broad override editor, native sandbox claim,
unknown PermissionStore mutation, direct database editing, file deletion, or
root helper.

**IMPLEMENTATION BOUNDARY**

Unknown tables/values are opaque and read-only. Controls are compiled/registered
per verified schema and portal version, not generated from arbitrary strings.

**VALIDATION**

- Flatpak absent and populated test environments.
- System/user install precedence and override fixtures.
- Portal missing/version mismatch/owner restart.
- Revoke, re-read, restore, resource deletion/replacement, denial, malformed and
  concurrent-change tests.

**VISUAL VALIDATION**

Exercise native-versus-sandboxed explanation, empty/unknown tables, grant detail,
revoke consequence, success/failure, and restore. Verify paths/identifiers are
redacted appropriately.

**SECURITY VALIDATION**

Prove unknown schemas cannot reach mutation, document revocation does not delete
the underlying file, backend strings are escaped/bounded, and restore is bound
to the exact unchanged resource.

**ROLLBACK IF RELEVANT**

Restore the exact captured permission set through the same documented API while
the resource identity remains valid; end test environments at their baselines.

**ACCEPTANCE**

Application posture never overclaims native-app isolation, and every enabled
portal control is schema-verified, user-scoped, re-read, and restorable.

**STOP CONDITION**

Stop before application-network enforcement or general permission editing.

## Session 6 — Privacy transparency and security activity

**OBJECTIVE**

Implement the external-service registry, current GREYWARD public-IP disclosure,
local-retention/export views, and a bounded recent security-activity feed.

**WHY**

Privacy behavior and meaningful recent changes must be visible without creating
remote telemetry, raw event retention, or a duplicate unbounded event warehouse.
Approved normalized local history follows the centralized `docs/telemetry/`
contract.

**INPUT DOCS**

`PRIVACY.md`, `DATA_MODEL.md`, `BACKENDS.md`, `THREAT_MODEL.md`, `UX_SPEC.md`,
`RESEARCH.md`, `TESTING.md`.

**SCOPE**

- Reviewed first-party external-service manifest and local configuration
  detection.
- Public-IP owners/endpoints/cadence/cache/fallback/disable-route disclosure
  without inducing a request.
- Security Center retained-data categories, clear-state and export preview.
- Bounded normalized events from sources the user can already read.
- Source unavailable, empty, rate-limited, malformed, injected, duplicate, and
  high-volume fixtures.

**DO NOT TOUCH**

Do not disable/change the public-IP widget, add telemetry/upload, request broad
log privileges, persist raw events, scan DNS/browser history, or add SOC/threat
counts.

**IMPLEMENTATION BOUNDARY**

The manifest identifies expected external behavior; local observation confirms
configuration without network probes. Activity uses allowlisted fields,
time/count bounds, normalization, and redaction.

**VALIDATION**

- Compare manifest to repository network endpoints and fail tests on drift.
- Prove opening Privacy/Activity produces no external request.
- Event source/visibility tests under normal user permissions.
- Retention size/time, clear-state, redacted/default export, malformed text, and
  no-event/source-unavailable tests.

**VISUAL VALIDATION**

Review disclosure cards, long endpoints, last-known/unknown activity, export
preview, clear-state confirmation, populated/empty/unavailable Activity, and
redaction labels.

**SECURITY VALIDATION**

No hidden network activity, no secret/raw record in state/log/export, safe
markup handling, and no new group membership or privileged reader.

**ROLLBACK IF RELEVANT**

Clearing Security Center state removes only its user-owned snapshot/preferences;
test exported artifacts are deleted from the test destination. Authoritative
backend logs/config remain untouched.

**ACCEPTANCE**

Every known first-party external request is attributable/disclosed, Security
Center itself is quiet by default, and activity is useful, bounded, and honest
about visibility gaps.

**STOP CONDITION**

Stop before richer correlation, monitoring daemon, external upload, or public-IP
configuration mutation.

## Session 7 — Device and recovery readiness

**OBJECTIVE**

Implement read-only USBGuard/device capability and composed recovery-readiness
views without policy mutation or secret recovery-material access.

**WHY**

Device trust and recovery matter to the product, but safe enforcement requires
physical prototypes beyond V0.

**INPUT DOCS**

`CAPABILITY_MATRIX.md`, `BACKENDS.md`, `PRIVACY.md`, `THREAT_MODEL.md`,
`UX_SPEC.md`, `RESEARCH.md`, `TESTING.md`.

**SCOPE**

- USBGuard package/service/D-Bus/version and privacy-safe connected-device
  summaries when available.
- Clear unavailable state when absent.
- Recovery composition from encryption, safe recovery-mechanism metadata,
  firmware/update readiness, and documented GREYWARD recovery handoffs.
- Absent/failed USBGuard, malformed device rule, hotplug, sensitive identifiers,
  no encryption, and unavailable recovery metadata fixtures.

**DO NOT TOUCH**

No USB authorization/rules/baseline/daemon config/IPC ACL, no device blocking,
no recovery-key read/validation, no encryption/TPM enrollment, no boot or auth
change.

**IMPLEMENTATION BOUNDARY**

V0 device data is transient/redacted. Recovery is an evidence composition and
handoff, not a setup wizard or claim that recovery was tested.

**VALIDATION**

- USBGuard absent/present service mocks and safe device parsing.
- Physical read-only hotplug when hardware is available.
- Recovery state matrix across encrypted/plain, firmware supported/unsupported,
  and metadata available/unknown.
- Verify no serial/hash/key material in cache/log/export.

**VISUAL VALIDATION**

Exercise Devices absent/present/hotplug and Recovery ready/attention/unknown
states. Recommendations must be visually distinct from active controls.

**SECURITY VALIDATION**

Static/runtime proof that USBGuard mutation methods and secret reads are absent.
Malformed device strings cannot inject markup or exhaust the UI.

**ROLLBACK IF RELEVANT**

Not applicable to authoritative security state; remove test fixtures and user
cache only.

**ACCEPTANCE**

No device policy can be changed, identifiers remain private, and recovery
wording distinguishes observed facts, unknowns, recommendations, and handoffs.

**STOP CONDITION**

Stop before active USB control, recovery setup, Sensitive Files, or Travel Mode.

## Session 8 — Complete Security Center UX

**OBJECTIVE**

Build the complete V0 Overview, six domains, Activity, Recovery, evidence detail,
recommendation, confirmation, operation feedback, and error-state experience.

**WHY**

Backend correctness must become a coherent product where every capability and
limitation is understandable and reachable.

**INPUT DOCS**

`PRODUCT.md`, `UX_SPEC.md`, `DESIGN.md`, `POSTURE_MODEL.md`, `DATA_MODEL.md`,
`CAPABILITY_MATRIX.md`, `PRIVACY.md`, `ACCEPTANCE.md`.

**SCOPE**

- Responsive navigation and Overview/domain/activity/recovery pages.
- Domain cards, priority findings, freshness/refresh, detail/evidence groups,
  capability notices, recommendations/handoffs.
- Complete zone and portal-control UX connected to tested adapters.
- Loading, cancellation, empty, stale, missing, denied, malformed, version
  mismatch, offline, partial collection, action success/failure/undo states.
- Export preview and safe copy behavior.

**DO NOT TOUCH**

No new backend capability, control family, DMS widget, generic Settings page,
numeric score, threat counter, placeholder, or root UI.

**IMPLEMENTATION BOUNDARY**

The UI renders immutable domain data and invokes only registered remediation
descriptors. It cannot synthesize action IDs or reinterpret evidence.

**VALIDATION**

- Automated UI/state tests across all semantic states and combinations.
- Navigation/deep link/cancellation/action integration tests.
- Copy/export redaction tests and no-control capability tests.
- Repeated launch/refresh/action lifecycle and leak/crash review.

**VISUAL VALIDATION**

Exercise every page and state under DMS/Labwc at default and narrow sizes with
pointer and keyboard. Capture representative images for Session 9 comparison.

**SECURITY VALIDATION**

Unsupported capabilities cannot render enabled controls; backend markup is
escaped; no stale snapshot enables mutation; controls re-resolve through the
adapter.

**ROLLBACK IF RELEVANT**

Use adapter-specific undo for test mutations and restore fixture/user state.

**ACCEPTANCE**

Every V0 capability is reachable, honest, evidence-backed, and consistent with
the capability matrix. All unsupported enforcement remains visibly unavailable
or recommendation-only.

**STOP CONDITION**

Stop before visual polish/packaging expansion or adding any post-V0 feature.

## Session 9 — Visual, accessibility, and desktop integration

**OBJECTIVE**

Finish GREYWARD visual treatment, responsive/accessibility/localization quality,
RPM ownership, icon/desktop entry, clean install/uninstall, and canonical DMS
launcher discovery.

**WHY**

Security information must remain legible and operable across real desktop states
and integrate without modifying the shell.

**INPUT DOCS**

`UX_SPEC.md`, `DESIGN.md`, `ARCHITECTURE.md`, `PRIVACY.md`, `TESTING.md`,
`ACCEPTANCE.md`.

**SCOPE**

- Semantic visual tokens/components, responsive layout and reduced motion.
- Keyboard order, accessible names/status announcements, screen-reader and high
  contrast behavior, text scaling, localization extraction/readiness.
- Canonical icon use, desktop metadata/categories/keywords, RPM files/deps/SBOM.
- Install, DMS index discovery/launch, update over prior development build,
  uninstall, and retained user-state behavior.

**DO NOT TOUCH**

No DMS functional/core patch, DMS config change, shell widget/placeholder,
authentication/boot/system security change, or backend expansion.

**IMPLEMENTATION BOUNDARY**

Use GTK/libadwaita behavior and repository branding assets. The RPM owns only
Security Center files and does not enable services or install experimental
backends.

**VALIDATION**

- Package content/dependency/license/SBOM and clean build tests.
- Clean install/update/uninstall and orphan-file check.
- DMS application discovery and launch without shell restart/fork.
- Accessibility automation/manual matrix and localization build.

**VISUAL VALIDATION**

Complete every case in `DESIGN.md`, including scale, window width, state, action,
light/dark/high contrast, reduced motion, long text, keyboard and screen reader.
Screenshots plus exercised interaction evidence are required.

**SECURITY VALIDATION**

Verify package permissions/ownership, non-root launch, no unexpected service or
Polkit files, no mutable remote assets, and safe desktop-entry arguments.

**ROLLBACK IF RELEVANT**

Uninstall the RPM and verify DMS/session/security configuration is unchanged;
remove user state only when explicitly testing full purge behavior.

**ACCEPTANCE**

The app is visually coherent, accessible, responsive, package-owned, cleanly
removable, and discoverable in DMS with no Security Center placeholder.

**STOP CONDITION**

Stop before release hardening; do not start the V1 monitor/widget.

## Session 10 — Security hardening and validation evidence

**HISTORICAL RESULT:** `BLOCKED` in the environment used for that report. See
[SESSION_10_REPORT.md](SESSION_10_REPORT.md). This status records missing
evidence and does not change the acceptance criteria.

**OBJECTIVE**

Close the V0 threat model and acceptance contract through abuse testing,
fuzzing, privacy review, VM/physical validation, performance measurement,
rollback verification, and final cross-document/result review.

**WHY**

Implementation completeness is not release readiness. The product handles
sensitive evidence and authorized changes and must withstand hostile states.

**INPUT DOCS**

All Security Center documents, especially `THREAT_MODEL.md`, `TESTING.md`,
`PRIVACY.md`, `PRIVILEGE_MODEL.md`, and `ACCEPTANCE.md`.

**SCOPE**

- Fuzz snapshot/adapter/event and action inputs.
- D-Bus owner/version/spoof/restart, Polkit denial/cancellation/reuse, TOCTOU,
  symlink/cache/config tampering, malformed/oversized/untrusted text, stale
  evidence, and denial-of-service tests.
- Complete GREYWARD VM acceptance plus available physical TPM/HSI/LUKS/USB and
  network/VPN tests.
- CPU/RSS/wakeup/startup/refresh/storage and repeated lifecycle measurement.
- Privacy/network capture, package/SBOM/dependency/advisory review.
- Cross-check product, threat model, capability matrix, architecture, privilege
  model, roadmap, execution plan, and acceptance for contradictions.

**DO NOT TOUCH**

No post-V0 milestone, new capability, relaxed invariant, system-security
workaround, or acceptance downgrade to obtain PASS.

**IMPLEMENTATION BOUNDARY**

Only fixes necessary to make the approved V0 pass are allowed. A missing
hardware case is recorded as a specific release validation condition, not
fabricated or silently omitted.

**VALIDATION**

Run the complete `TESTING.md` matrix, produce traceable evidence for every
`ACCEPTANCE.md` criterion, and confirm all ten session reports.

**VISUAL VALIDATION**

Repeat critical screenshots/interactions after hardening fixes and compare with
Session 9 baselines. Validate real error/action flows, not fixture images alone.

**SECURITY VALIDATION**

Close every V0 threat with a test/result, accepted residual risk, or explicit
release blocker. No critical/high unresolved issue may pass.

**ROLLBACK IF RELEVANT**

Test RPM uninstall and both V0 action rollbacks from installed release
candidates. Restore the development VM baseline/checkpoint after destructive
fault injection confined to the authorized test environment.

**ACCEPTANCE**

Every V0 criterion in `ACCEPTANCE.md` is PASS with evidence, or the release is
reported blocked with exact unmet criteria. Post-V0 work is irrelevant to V0
PASS.

**STOP CONDITION**

Stop after V0 PASS/BLOCKED report. Do not begin the posture widget,
Portmaster/OpenSnitch, USB control, Sensitive Files, Travel Mode, or AI work.

## Post-V0 milestones

These are not V0 sessions and have no implementation authorization from this
document. Before work, create a bounded plan with the same fields above.

- V1 posture monitor and DMS summary widget.
- Portmaster versus OpenSnitch comparative prototype.
- Selected application-network backend integration or documented rejection.
- USBGuard active-control prototype/integration.
- Richer security activity.
- Sensitive Files prototype.
- High-Risk/Travel Mode prototype.
- Advanced application policy.
- Local AI-mediated explanation/recommendation prototype.





