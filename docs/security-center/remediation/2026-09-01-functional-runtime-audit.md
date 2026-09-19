# SECURITY_CENTER_REMEDIATION_09

Date: 2026-09-01

Status: source remediation completed for the exercised workflows; the Alpha
runtime was restored, the optimized RPMs were deployed, and the installed
application was relaunched and health-checked. The complete clean runtime
gate and every GUI workflow remain open.

## Scope audited

The broad pass covered Overview/global posture, System/Protection, ClamAV and
File Security, scan scopes and accounting, detection explanation, quarantine,
restore and deletion, firewall and NetworkManager trust zones, OpenSnitch
visibility and policy boundaries, Secure DNS, Network Activity, Application
Access and Flatpak/portal evidence, Privacy profiles and disclosures, Update
Center providers and transactions, firmware/security updates, Devices and
USBGuard, Restic/recovery, telemetry/history, exports, Technical Details,
notifications, dialogs, navigation, IPC, systemd, D-Bus/Polkit, helper
processes, persistence, degraded states, and shared frontend/backend
infrastructure.

## Defects found and root causes

### High impact

- File Security remediation used pathname-based copy/removal at a privilege
  boundary. Symlink components, raced source replacement, and a user-bus
  restore destination could redirect or desynchronize the object being acted
  on. The root cause was treating an already-checked path string as stable
  across a later filesystem operation.
- `UpdateAll()` could enter optional-provider mutation during a resolve/check
  path, and a provider-only update could be skipped when DNF reported no
  candidate. Successful provider commands were also previously accepted
  without an authoritative fresh readback. The root cause was overlapping
  legacy and Update Center operation semantics.

### Medium impact

- A stalled ClamAV stream could keep an operation busy indefinitely; non-C
  scanner output could also prevent an actionable detection from being
  recorded, while exit status 1 was not safe when parsing produced no record.
- The privileged DNF5 helper itself had no timeout, even though its caller was
  bounded. Native interactive picker children could similarly outlive a
  timed-out frontend request.
- Privacy profile application could leave a partial NetworkManager/firewalld
  mutation after an authorization failure; Restic reconfiguration could lose
  the previous configuration on failure.
- Safe Open handler discovery, Restic mount validation, and several shared
  provider probes were not consistently bounded or fail-closed.
- A notification and an obsolete Session 10 path exposed a second direct
  quarantine operation; the notification path could fall back to a legacy
  user-owned quarantine when the root service was unavailable.
- Provider failures and fwupd urgency were liable to be presented as success,
  availability, or restart requirements without the corresponding verified
  state. The Rust firmware overview also parsed human `fwupdmgr` output rather
  than a structured client response.
- The first Fedora deployment build also exposed two source compatibility
  defects: a `Result::is_some_and` call that could not compile on the guest,
  and a missing import for the canonical trust-zone control function. These
  were build-time defects in the existing integration path, not new runtime
  implementations.
- The Overview promoted every unavailable check to a global `UNAVAILABLE`
  state, even when the unavailable check was only recommended and all required
  protection remained evaluated. The root cause was aggregating raw check
  counts instead of the already-aggregated domain states and requiredness.

### Contract/documentation impact

- The V0 posture contract says package/firmware application is read-only,
  while the separately admitted Update Center architecture permits explicit
  native-provider Apply/Restart. The implementation intent was valid but the
  scope boundary was not stated together, making the product contract
  ambiguous.

## Fixes implemented

- Hardened File Security with no-follow source descriptors, regular-file and
  owner checks, hash and device/inode rechecks before source removal, and
  exclusive no-follow creation of user restore destinations. Added bounded
  scanner watchdog behavior, fixed C-locale parsing, and fail-closed handling
  when ClamAV reports a detection without an actionable path.
- Made Update Center resolve/check side-effect free; Apply runs optional
  providers even when DNF has no candidate, and successful provider actions
  require a fresh snapshot readback. Provider-only availability exposes the
  Apply action, failures remain visible, and fwupd urgency is no longer
  treated as a reboot requirement.
- Added timeouts to the privileged DNF helper, DNF/Update Center D-Bus calls,
  interactive picker children, shared provider probes, Safe Open discovery,
  mount validation, Secure DNS, USBGuard, and relevant file/security calls.
- Preserved old Privacy configuration on failed reconfiguration and kept
  rollback/readback state explicit. Removed legacy direct notification
  quarantine behavior and routed users to the authoritative File Security
  page.
- Replaced firmware human-output heuristics with structured JSON parsing that
  maps absent or unrecognized schema to `UNKNOWN`/`UNAVAILABLE`.
- Fixed the two guest build defects, then rebuilt and deployed both optimized
  RPMs through the canonical GREYWARD-DEV deployment runner. The Overview now
  directs an unavailable posture to unavailable evidence instead of reporting
  that no action is needed.
- Made compact posture aggregation follow the documented domain/requiredness
  precedence. Optional unavailable evidence now yields `PROTECTED` or `SECURE`
  with an explicit limitation message; required uncertainty and unknown
  domains still yield `UNAVAILABLE`.
- Made Update Center expose exactly one host-selected system update provider:
  Fedora hosts use DNF5 and ostree hosts use rpm-ostree. The nonselected
  provider is omitted rather than reported as unavailable; the pending and
  completed snapshots use the same selection logic.
- Updated File Security, backend, product, capability, execution-plan, README,
  and Update Center architecture documentation to describe the actual
  boundaries and deferred runtime gates.

## Automated validation

The final command results are:

- Python bytecode compilation: passed; Security Context unit suite: **116
  passed, 22 environment-gated skips**.
- Frontend UX contract: **60 passed, 0 failed**; interaction harness: **1
  environment-gated skip**.
- Rust formatting: passed. Workspace `cargo check --workspace --locked`
  reached dependency compilation but is blocked on this Windows host because
  the MSVC `link.exe` linker is unavailable; no Rust source diagnostic was
  emitted before that environment failure.
- Guest Fedora workspace tests: **27 passed, 0 failed**. Canonical Alpha RPM
  deployment, installed-package checks, Tauri launch, and the GREYWARD health
  gate all passed; the health gate returned `RESULT: HEALTHY`.
- Repository static validation: passed; repository validation: passed;
  `git diff --check`: passed.

## Runtime validation

The exact VMConnect console for the running
`GREYWARD-ALPHA-GEN2-20260828` guest was inspected with current screenshots.
The initial SSH timeout was traced to the active installed `TRAVEL` profile:
NetworkManager assigned `eth0` to firewalld's `drop` zone, whose target was
`DROP` and which exposed no SSH service. Through the Hyper-V console path, the
canonical installed profile helper was set to `STANDARD`. Authoritative
readback then confirmed `Public`, `eth0 -> public`, the expected `dhcpv6-client
mdns ssh` services, and `sshd` listening on port 22; direct `greyward-dev` SSH
access succeeded afterward.

The installed Security Center was launched through
`/usr/bin/greyward-security-center-launch` and its Overview was visible in the
real guest desktop. Installed D-Bus providers were read directly: ClamAV
reported current definitions, File Security returned real scan/detection and
quarantine history, and the Security Context services were active. The
optimized RPM deployment was then completed through the canonical runner; the
installed launcher was started again and the Overview screenshot showed the
new `Some evidence is unavailable` limitation action. Final readback confirmed the
`STANDARD` profile, firewalld `public` with `eth0`, SSH listening on port 22,
the user Security Context service, and the ClamAV, Secure DNS and OpenSnitch
control-plane services active. The installed posture diagnostic and
guest-local backend diagnostic both reported
the same six domains; after the aggregation correction the overall state is
`PROTECTED` with one optional unavailable check because the recommended
`system.firmware.hsi` capability is absent in this VM. The direct posture CLI
can show a null ClamAV projection when run
outside the graphical user-session environment; the session context file and
the dedicated D-Bus `GetClamAvStatus` endpoint both returned `CURRENT`, and
File Security consumed that authoritative provider path.

This is a partial installed-application/runtime validation, not a claim that
all GUI workflows, hardware, image, release, or package checks passed.

## Remaining limitations and deferred architecture

- The clean canonical interaction/runtime gate still needs a complete
  guest-local run after the source fixes; this Alpha validation does not cover
  every GUI action or persistence-after-restart workflow. The optimized RPM
  deployment and application launch themselves are verified.
- The Rust firmware adapter still has a planned `libfwupd` binding as the
  canonical long-term interface. Its current compatibility path is structured
  JSON only and is deliberately conservative when the schema is unavailable.
- USBGuard mutation remains intentionally deferred/prototype-gated; OpenSnitch
  interactive prompts remain deferred until their complete runtime lifecycle
  is validated; the existing wheel-group root ClamAV D-Bus policy still needs
  an installed-policy security review.
- No unrelated subsystem was rewritten solely to make this audit appear
  green, and no runtime limitation was hidden as a successful validation.
