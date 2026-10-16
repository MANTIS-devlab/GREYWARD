# Network rules

Canonical ownership: Security Context's `network_rules.py` normalizes stored
policy and matches outbound connections. `network_rule_transactions.py` prepares
revision-bound, expiring reviews; `network_policy_service.py` owns privileged
authorization and writes. `network_firewall.py` makes typed native firewalld
D-Bus calls. The existing OpenSnitch control plane supplies live decisions and
readback. No additional daemon or parallel rule database is introduced.

## Contract

Security Center → named Tauri commands → session Security Context → existing
root OpenSnitchPolicy1 service → OpenSnitch or firewalld. Application and incoming
batches are separate. Permanent policy remains in
`/etc/greyward/opensnitch-policy.json`, with a validated last-good recovery copy.
The RPM marks the policy `config(noreplace)` so upgrades preserve local rules.
The root service refuses writes until the control plane confirms schema v2.
That acknowledgement must belong to the current active control-plane instance;
root-owned descriptor metadata and typed systemd readback bind its generation.
An idle statistics stream does not disable editing. Loaded/Observed still need
fresh revision/match evidence. Private synchronous calls use separate connections
without GLib disconnect watches or process-exit-on-disconnect behavior.

The Rules page offers application/incoming views, reviewed creation, edits,
duplication, enable/disable, deletion, order, bulk changes, search, lifecycle
filters, pagination and versioned reviewed import/export. Activity prefills
the same editor; it never authenticates a historical application identity.

Application conditions combine with AND; values in destinations and port lists
combine with OR. Application rules use explicit order and first-match behavior
within their tier. Feodo threat blocking and managed DNS retain priority;
ordinary Allow rules cannot become exceptions. Dedicated exception transactions
remain explicit. Defaults preserve ordinary outbound Allow.

Executable rules match the resolved host executable path and selected Unix UID,
not a verified immutable application generation. Replacing code at that path
changes which code benefits. Interpreter paths include other code using that
interpreter; helpers with different executable paths require their own rules.
Individual Flatpak/script identity scopes are unavailable. Hostname evidence is
OpenSnitch's observed hostname, not URL filtering or TLS inspection. Unknown
hostnames do not match hostname-only rules. Proxies/tunnels hide destinations.

Supported lifetimes: permanent, current boot, 15 minutes, one hour. Application
expiration is checked at each privileged matching decision, including after
restart; firewalld uses native runtime timeouts for timed incoming rules.
Boot rules bind to kernel boot identity. OpenSnitch responses are bounded
one-shot decisions; independently persisted engine rules are not created.
General Allow once and interactive prompts remain unavailable pending a real
daemon timeout/cancellation acceptance gate.

Fresh protected Polkit authentication is required for each desktop Apply or
reviewed batch. Wheel is eligibility only. Authorization uses the live system
bus caller and active local seat, not frontend identity or Administration's
sudo cache. Tokens bind recipient UID, revision and exact candidate; stale,
cancelled, replayed or expired reviews cannot write. Legacy mutations reach
the same root authorization, with asynchronous session forwarding. Explicit
root maintenance retains root's existing policy authority.

Native incoming rules affect the selected zone and only their exact generated
rich-rule entries. Runtime and permanent readback are separate. GREYWARD never
saves all runtime settings or reloads firewalld. Before native writes, a bounded
recovery journal is committed in the existing policy; interrupted operations
restore affected entries on service startup. Identical external rules cannot be
adopted. Partial rollback failure is explicit and blocks editing until recovery.
Native changes are capped at 128 affected entries per transaction (including
runtime/permanent planes). Existing active-zone services, ports and unsupported
rich rules have a separate bounded read-only disclosure; none are adopted.

Saved, Loaded by engine and Observed matching are distinct. Match counts and
last observation exist only after actual control-plane decisions; they reset
when that process restarts and are not packet counters. Duplicate-condition
shadow warnings are predictions, not exhaustive reachability/conflict proofs.
Undo is a short-lived server reference, requires another reviewed authentication
and refuses intervening revision changes. Capacity is 1,024 stored rules;
overflow rejects the whole transaction without eviction.

Removal/expiry changes future decisions. It does not necessarily terminate
established connections or recover transmitted data. External/upstream engine
rules remain in the existing read-only projection; the editable list contains
GREYWARD-owned policy only. Global deny, VPN kill switches, NAT/forwarding,
arbitrary rich expressions and interface-specific application rules are outside
this delivery.

## Validation and rollout status

Focused and regression suites pass: 384 Context tests on Fedora, 138 frontend
tests and 208 Rust tests (22 ignored). Static and repository validation pass.
These checks cover matcher, migration, transaction, transport and packaging
contracts; they do not replace the outstanding desktop acceptance below.

Installed development candidate: Center 102 / Context 96. Actual installed
OpenSnitch tests demonstrate a root-UID curl block, same-UID Python separation,
different-UID curl access, disable/re-enable, policy-service restart persistence,
stale/forged refusal and cleanup. Native incoming tests from a separate machine
demonstrate wrong-source refusal, correct-source access, a blocked adjacent port,
runtime/permanent readback and renewed denial after removal. Synthetic rules
and listeners are removed. The real ordinary session's Context projection
returns schema v2, actor UID and available editing; its old development override
is retained as a disabled backup. The running Center ELF matches the installed
binary. Source checks alone are not treated as this enforcement evidence.

Real non-administrator D-Bus mutation is denied. An administrator's Apply and
legacy write both refuse a locked desktop without changing policy. Successful
protected GUI authentication, cancellation/wrong-password interaction, visual
review, narrow-window/keyboard and actual WebKit import/export acceptance remain
pending because the desktop is locked. IPv6/UDP packet, real-time expiry and
clean-image acceptance are separate uncompleted gates; model/source tests do
not substitute for them. Interactive prompts remain deferred.

The first development upgrade exposed CRLF script entry points and an unsafe
implicit restart of the required control-plane unit, which also stopped
OpenSnitch. Service operation was restored; SSH, compositor, authentication
closure and firewalld remained intact. RPM preparation now normalizes executable
scripts, and the builder normalizes spec files. The Context upgrade no longer
implicitly restarts the control plane. Later coupled engine activation requires
explicit maintenance approval or the normal offline-update boot; neither is
performed as a further development activation here.

Retain matched old RPMs and exact policy/last-good files before activation.
Rollback must stop the new policy writer, restore the old policy format before
loading the old control plane, remove only GREYWARD-owned incoming entries,
then restore matched packages. Never feed v2 rules to the legacy matcher: UID,
CIDR and protocol conditions would be misinterpreted. Do not reboot, reload
firewalld, terminate the graphical session or change SSH during development
validation. ISO composition and clean installation remain separate gates.
