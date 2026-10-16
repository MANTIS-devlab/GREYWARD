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

The Rules page combines application and incoming rules in one table and one
Source → Destination → Services → Action editor, with optional traffic filters.
Provider-local A/I order markers must not imply one cross-engine chain. Mixed
selections expose separate provider batches; no combined atomic Apply is offered.
The page offers reviewed creation, edits,
duplication, enable/disable, deletion, order, bulk changes, search, lifecycle
filters, pagination and versioned reviewed import/export. Activity prefills
the same editor; it never authenticates a historical application identity.

The service picker searches installed firewalld names, labels and port/protocol
pairs. The existing root service reads `getServiceSettings2`; there is no new
service database. Reads are bounded to 1,024 definitions, 64 port pairs per
definition and a two-second collection budget, cached for 30 seconds. Incomplete
metadata is explicitly unavailable rather than replaced with guessed ports.
Incoming named services retain their full native semantics. Application rules
snapshot explicit ports/protocols: a service can be selected only when every
protocol has the same port set and no helper, include, source or destination
condition would be lost. Asymmetric definitions cannot be broadened into a
port/protocol cross-product. Explicit custom ports remain available. Future
firewalld definition updates affect native incoming services; outgoing port
snapshots remain the reviewed ports. Table service names are descriptive aliases
for exact matching port sets, not additional application identity evidence.

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

The existing fixed-helper Polkit rule also handles this exact network action:
wheel callers require AUTH_SELF without retained authorization. This permits
the user-systemd transport to challenge even when Polkit does not attach that
process to a logind session. The root broker separately requires an active,
unlocked local seat before requesting the challenge; the rule grants no write
authority on its own. A no-interaction check must return a challenge, never
authorization, for an eligible caller without a fresh password.

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

The unified workflow candidate passes 388 Context tests on Fedora and 155
frontend tests (three optional browser checks skipped). Its RPM build and live
visual validation are pending. The prior installed candidate passed 386 Context
tests on Fedora, 150 frontend
tests and 208 Rust tests (22 ignored). Static and repository validation pass.
These checks cover matcher, migration, transaction, transport and packaging
contracts; they do not replace the outstanding desktop acceptance below.

Center 102 failed to bootstrap with the network module loaded: its controller
received the lexical `esc` helper before initialization. Center 103 moves
controller creation after the helper. The regression executes every bundled
script in actual HTML order for Overview and Rules with provider reads pending;
it reproduces the pre-fix ReferenceError and does not invent provider state.
This startup check runs in the existing network-rule CI suite. It supplements,
rather than replaces, normal installed desktop validation.
The normal Center 103 process was restarted and its executable hash matches the
installed binary. Live accessibility readback from that exact process confirms
Network protection and Rules render with the real backend, including the empty
rule list and editor controls. This is installed UI evidence, not a screenshot
or visual-quality acceptance; VMConnect remains minimized.

Installed development candidate: Center 103 / Context 98. Actual installed
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
legacy write both refuse a locked desktop without changing policy. A
no-interaction Polkit readback for a sessionless eligible caller changes from
refusal to a required AUTH_SELF challenge, with authorization remaining false.
This verifies challenge eligibility without entering credentials. Successful
protected GUI authentication, cancellation/wrong-password interaction, visual
review, narrow-window/keyboard and actual WebKit import/export acceptance remain
pending. The desktop is unlocked; the console must be visible for visual review.
IPv6/UDP packet, real-time expiry and
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

## Workflow references

The source/destination/service/action organization is informed by
[Stormshield filtering-rule creation](https://documentation.stormshield.eu/SNS/v5/en/Content/HowTo_-_Implementing_a_filtering_rule/Adding-filter-rule.htm).
GREYWARD retains its own visual assets and its two existing enforcement providers.
The service read model follows the native
[firewalld D-Bus contract](https://firewalld.org/documentation/man-pages/firewalld.dbus.html).
