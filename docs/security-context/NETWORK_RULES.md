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

The Rules page has separate **Application rules** and **IP filtering** workspaces.
Applications use a searchable installed-app list with real icons/names rather than
an editable path field. IP filtering presents incoming and outgoing rules in a
policy table: position, enabled state, action, name, source, destination, service.
Cells open a focused native HTML dialog; enable/disable still prepares a review,
never an unauthenticated write. New IP drafts default to disabled. Configuration
(enabled/disabled) remains separate from actual Saved/Loaded/Observed evidence.

Incoming IP rules use native firewalld services/ports, source IP/subnet and local
zone. Outgoing IP rules reuse the existing OpenSnitch all-applications matcher
(`path="*"`, `all_applications=true`), limited in the editor to destination IP/CIDR.
The source is this computer, with explicit current-user/all-user scope. No new
firewall, database or policy tier is introduced. Outgoing IP and application rules
share their existing first-match order; displayed OUT positions are global engine
positions, including entries in the other workspace. Incoming IN positions remain
separate. Provider-local reviewed batches do not imply cross-provider atomicity.
This is a local-computer policy UI, not a routing/NAT/transit-filtering appliance.
OpenSnitch connection decisions do not become packet inspection or retroactive
termination of established connections merely because the UI says IP filtering.

`network_applications.py` reads Gio desktop entries in the ordinary session
Context, including installed Flatpak export directories. The list is bounded to
256 entries/five seconds and cached for 30 seconds. Icons are decoded to bounded
48px PNGs outside the root broker. Names/icons are display metadata, never
application identity or authorization evidence. Native ELF targets resolve
without executing launchers; a packaged wrapper may use a unique same-name ELF
from its owning RPM. Shared interpreters, ambiguous launchers, home-only targets
unavailable to the root service, and individual Flatpaks stay visibly unsupported.
Selecting a desktop name cannot accidentally authorize every interpreter/Flatpak.
The root broker independently resolves/reviews the executable and account scope.
Existing executable scopes remain in technical detail; the app picker supplies
no generic execution or arbitrary-file API and does not create AppSec grants.

The page retains reviewed creation, edits, duplication, ordering, bulk management,
search, lifecycle filters, pagination, undo and versioned import/export. Application
and outgoing-IP exports filter the corresponding OpenSnitch rows; incoming exports
retain the existing provider schema. Activity can prepare the application editor,
without treating historical application names as verified identities.

The service picker searches installed firewalld names, labels and port/protocol
pairs. The root service reads `getServiceSettings2`; there is no new service
database. Reads are bounded to 1,024 definitions, 64 port pairs per definition and
a two-second collection budget, cached for 30 seconds. Incomplete metadata is
explicit rather than replaced with guessed ports. Incoming services retain their
full native semantics. Outgoing rules snapshot explicit ports/protocols only
when every protocol has the same port set and no helper/include/source/destination
condition would be lost. Asymmetric definitions cannot become a broader cross-
product. Custom ports remain available. Incoming service definitions may change
through native firewalld administration; outgoing snapshots retain reviewed ports.
Application search and service focus/filtering update only their result lists;
they preserve the focused input and existing modal instead of replacing the
whole connected view. A regression test refuses connected-dialog replacement
during these events. This avoids repeated focus churn, without claiming to fix
every native WebKit clipboard failure.

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
The D-Bus adapter follows firewalld's bus-name owner, so starting before firewalld
or restarting that daemon does not leave this provider stuck in an unavailable
state after the next refresh.

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

## 18 October release reconciliation and `<validation-host>` installation

Installed package versions diverged: `<development-host>` had Security Center 0.1.0-110 /
Context 0.1.0-100, while `<validation-host>` had Security Center 0.1.0-100 / Context
0.1.0-103. The `<development-host>` Security Center included rule creation, but its Context
was older than the one already on `<validation-host>`. The current source was therefore
packaged together as Security Center 0.1.0-111 / Context 0.1.0-105. This
keeps the newer Context baseline and includes the rule editor's installed-app
catalog and clearer IP-rule scope/order review.

The canonical component builder passed on `<development-host>`; its Rust workspace tests
passed. Focused validation also passed: 88 Fedora Context network tests, 21
frontend tests, `tests/static.ps1`, and `tools/validate-repository.ps1`. Both
RPMs were installed on `<validation-host>`. Installed NEVRA, payload ownership and `rpm -V`
readback match the new releases; SELinux is Enforcing and firewalld, OpenSnitch
and `greyward-opensnitch-policy` remain active. Package installation created
or changed no firewall rule. The user has not yet visually checked the updated
Security Center window, so package/readback validation is not visual acceptance.

| Package | Installed NEVRA | SHA-256 |
|---|---|---|
| Security Center | `greyward-security-center-0.1.0-111.fc44.x86_64` | `b5d2d1e02a99e206d2a8fe76e1588289e9b04000c865edca1fb67e6f9becfb27` |
| Security Context | `greyward-security-context-0.1.0-105.fc44.noarch` | `6e2b6b10ffba470c7e9820ae9530134207aff8d886b50d7d9a2ffc03b2df2f82` |

## Validation and rollout status

Installed performance baseline on 16 October: a static open rule dialog consumed
202.4% WebKit CPU over three seconds; closing it reduced the same process to
0.3%. With compilation stopped, provider reads were 0.386s/0.451s cold and
0.022–0.032s warm. The network-dialog backdrop is now a static dark layer without
live blur; the raised obsidian surface and edge/shadow treatment remain.
Numeric service searches match actual ports or containing ranges: searching
443 no longer matches 8443 just because of its text. Suggestions can open above
the field, and Escape closes suggestions before permitting native dialog
cancellation. Removing blur alone only reduced the open-dialog load to
178.0–179.6%. Thread readback located the sustained work in WebKit's threaded
compositor and llvmpipe. An installed A/B launch with
`WEBKIT_DISABLE_COMPOSITING_MODE=1` reduced the same open dialog to 1.0% WebKit
CPU in two three-second samples. This changes compositing, never sandboxing.

Center 110's canonical desktop launcher selects that documented WebKit mode
only when every detected DRM card uses display-only `hyperv_drm`. An unknown,
missing or different driver, including a mixed hardware-GPU setup, retains
WebKit's normal default. An explicit environment override is respected.
Normal installed launch confirms automatic selection and matching installed/
running executable hashes. Final unlocked visual confirmation of this packaged
launch remains pending; the desktop auto-locked during the last build.
No security policy, DMA-device permission or system-wide rendering setting changed.

Current installed separated workflow: 392 Fedora Context tests and 160 frontend
checks pass (three optional browser checks skipped). The real unprivileged catalog
returns 33 applications, 21 supported native targets, all with icons, in 0.419s.
Firefox and Strata wrapper resolution uses the same generic RPM mechanism.
Center 110 / Context 100 is installed. The normal session service returns 32
applications, all with icons, including 21 supported native targets, in 0.432s.
The root-independent prototype’s 33-entry result above was a separate environment
snapshot; entry counts are not a fixed product claim. Actual outgoing-IP testing
blocks HTTPS to one synthetic public destination while leaving that IP’s HTTP
port available; root engine readback reports OBSERVED with three decisions.
After exact rule removal, HTTPS succeeds again and original settings/rules match.
No personal policy, SSH access, firewall engine or graphical session was changed.
The installed application picker was visually inspected in VMConnect after
unlocking. Full interaction and protected authentication acceptance remain
pending: Center 105 and 107 crashed during automated text-entry checks. The SIGSEGV
starts in WebKit `Clipboard::formats`, called by GTK's clipboard-target callback
(WebKitGTK 2.54.1 / GTK 3.24.52). This establishes the failing native path, not
the underlying cause. The application reopened through its normal route; the
desktop and security services stayed running. Clipboard stability is unresolved;
source tests and readback do not substitute for desktop acceptance.
Actual keyboard filtering, Firefox selection with its icon, service suggestions
and keyboard cancellation were exercised in the installed UI before locking.
The upstream USBGuard unit fixture now explicitly selects its mocked upstream
identity instead of accidentally depending on the host's enrolled login. Its
separate enrolled-projection/no-fallback test remains enabled; 392 tests pass
under the enrolled ordinary account without changing device permissions.
The installed Center 104 / Context 99 evidence below is the prior mixed UI baseline.


The previous unified workflow was installed as Center 104 / Context 99. Its tests passed:
388 Context tests on Fedora, 156 frontend checks (three optional browser checks
skipped), and 208 Rust tests (22 ignored). Static/repository gates pass. The
installed Context payload differs only in `network_firewall.py`; engine code,
authorization and policy are unchanged by installation. The normal-user typed
read path returns all 265 actual installed definitions in 0.488 seconds, with
both providers editable while unlocked. Running/installed Center hashes match.
SSH, greetd, firewalld, OpenSnitch, control-plane, protected compositor and
authentication processes remain unchanged, with SELinux Enforcing.
Visual/keyboard and protected GUI authentication acceptance remain pending. The prior installed candidate passed 386 Context
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
or visual-quality acceptance; VMConnect was minimized at that check.

Earlier Center 103 / Context 98 enforcement baseline. Actual installed
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
pending. Live visual review requires an unlocked desktop.
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
