# Installed Application Security development — 7 October 2026

Scoped development evidence, not production protection or image acceptance.
The current authority is [the delivery plan](../../security-center/APPLICATION_SECURITY_PLAN.md).
This supersedes the earlier Center 60 / Context 65 review deployment.

## Actual deployment

The real `.149` public `ApplicationSecurity1` owner is now the explicitly
enabled `greyward-application-security-workflows.service`. It uses the shared
root-owned schema-four database, identity cache, dispatcher and isolation runner;
no parallel mock provider or private bus substitutes for this deployment.
Center 61 / Context 67 are installed and running as normal user `development-user` (1001).
The running Center binary SHA-256 is
`2733961529726432608a09e40580f1fc8787fe7fe77cc57adb82a38e201a4fa9`.

Package SHA-256:

| Package | Digest |
|---|---|
| Center 0.1.0-61.fc44.x86_64 | `81c4a5a5aab743b2cb7ca9f80d6a9107c8c0fde8c40098aa8618a7cc16b43afb` |
| Context 0.1.0-67.fc44.noarch | `cde7d8f7edd69a552fab631eda99e2b84956c3432f1ee3736d716f46420c5f5b` |
| Application Security 0.1.0-19.fc44.x86_64 | `22da808719cc7dd41aed666946b4ac9862ddbaa29c05a5a96496049bcc968cfb` |

Runtime revisions 16–18 exposed real integration failures: the system bus could
not receive the root service's standard-stream pipes, broker-side mounts were
invisible to PID 1, and umask 0077 made internal scratch paths inaccessible after
privilege drop. Fixed development policy permits root-service stream transport
and PID 1's labeled disposable tmpfs; ordinary host-to-worker inspection remains
denied. Internal root modes are explicit inside a mode-0700 private parent.
Runtime 19 also removes the Wayland helper's UID-1002 test constant and timestamps
actual isolated inventory observations. All failures refused unrestricted launch.

Inputs, compiler/test logs and exact artifacts are retained under ignored
`output/application-security/20261007-live-development/` and guest
`/var/tmp/greyward-application-security-build/`. Root-private activation receipts,
policy inputs and package rollback artifacts are under
`/var/lib/greyward-development/application-security-live/` (0700).

## Scope and evidence

Center/Context reads return AVAILABLE transport with UNKNOWN coverage and no
effective profile. `ListAccessGrants` separately reports isolation capability
and denies policy-change capability for this unenrolled account. Available
transport or stored selected-code identity does not claim PROTECTED.

The installed revision-18 script check passed as UID 1001: host home absent,
host session/system buses absent, HOME=/work, Internet socket creation denied.
The first network check failed because it expected connection denial while the
worker already denied socket creation; only the exact unchanged owned test
script was corrected. No restriction was weakened.

Final revision-19 installed checks pass as normal UID 1001: headless home/bus/
network isolation, exact ordinary selected-document bytes through the shared
runner, graphical private-display readiness and a real installed Context
`PrepareApplicationLaunch` / `StartApplicationLaunch` receipt. A real graphical
review workload is left open on the desktop. This is not a fake Center bridge.

Context 67 fixes the observed owner-change failure: broker restart invalidates
all pending leases; the first stale request fails, the next request verifies the
new root owner and succeeds without restarting Context. No mutation is replayed.
Two focused tests cover discarded mutation/launch leases and subsequent reads.

Focused frontend contracts: 100 passed. Context workflow contracts: 11 passed.
Final runtime library contracts: 54 passed, 5 explicit environment tests ignored.
Final workspace formatting and runtime all-target Clippy pass. Native Flatpak
`com.brave.Browser` execution of its runtime `/usr/bin/true` passes; this proves
minimum launch compatibility, not Protected Data enforcement for Flatpak.
Both required repository gates pass: `tests/static.ps1` and
`tools/validate-repository.ps1`. The scoped diff passes `git diff --check`.

The existing DMS PID 4888 and Labwc PID 4813 remained alive, SELinux Enforcing
and SSH active. No reboot, account password/mapping, user-secret labeling,
Fedora PAM, native DMS lock or ISO change was made. Disk preflight left about
9 GiB available after the earlier verified compiler-cache cleanup. No further
user/development/recovery data was deleted.

## Recovery and remaining functional work

The development rollback tool first verifies the owned activation receipt,
database integrity, absence of enrollment/resources/grants/label journals,
absence of login mappings and policy-input digests. It refuses to treat later
Protected Data enrollment as an isolation-only rollback. Actual withdrawal
stops the owned workflow/workload units, removes only the owned development
SELinux user/modules and preserves policy inventory and user files. `--check`
is read-only and passed on the installed final state. Actual owned development
withdrawal and reactivation also passed: the public bus owner, service, owned
modules and SELinux worker identity disappeared, login mappings stayed identical,
and DMS/Labwc/Center process identities and SSH remained operational. The exact
runtime-19 inputs were then reactivated; Context resumed real reads and the
headless, selected-document and graphical launch checks passed again. The
root-private recovery result is retained beneath
`/var/lib/greyward-development/application-security-live/withdraw-reactivate-20261007/`.
This verifies isolation-only development recovery, not account enrollment,
resource-label or production package/schema rollback.

The prior Center 60 / Context 65 RPMs and restrictive backup remain in the
earlier root-private review directory. No whole-session enrollment is enabled:
the protected authentication/input path, admission, label persistence, lifecycle
and live coverage verifier remain essential implementation. Grant/resource
mutations are unavailable for the unenrolled session because that security
boundary is incomplete, not because `.149` is treated as production.

Configured Flatpak Safe Open handlers, temporary/WRITE raw grants, general SSH
or IDE persistent profiles remain unavailable. Native Flatpak overrides are
preserved. Exhaustive compatibility, portal/deputy, performance, hardware,
physical-seat/suspend and image/release matrices remain DEFERRED HARDENING.
