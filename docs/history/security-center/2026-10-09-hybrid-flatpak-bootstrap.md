# Bounded hybrid Flatpak proof — 9 October 2026

Historical execution receipt. Current authority:
[Application Security plan](../../security-center/APPLICATION_SECURITY_PLAN.md).
This is **not** a successful permission-provider or graphical acceptance receipt.

## Outcome

**BLOCKED / NO-GO for proceeding to the bridge against the current session.**
The two approved product gates remain **NOT DEMONSTRATED**. No Allow decision,
Collabora grant, shared-portal content permission, frontend hook or production
provider was installed. GNOME Text Editor and the manual authorization scenarios
were not reached. This does not establish that the hybrid is impossible; its
shared IPC trust prerequisite must be resolved before widening the experiment.

## Baseline and bounded implementation

`.149`: Enforcing; Center 89 / Context 81 / experimental runtime 32;
Flatpak 1.18.4; xdg-desktop-portal 1.22.1; dbus-broker 37-8.fc44.
Root filesystem had 5.1 GiB available. Existing changes were preserved.

The new development-only bootstrap consists of:

- `spikes/application-security/selinux/greyward_hybrid_flatpak_probe.te`:
  a separate subject outside `userdomain`, private state and code labels,
  namespace setup and immutable system-deployment reads. No registered-resource
  access or ordinary-to-workload transition. Compilation includes `neverallow`
  checks against ordinary memory inspection, FD use and private-state content.
- `tools/greyward-dev/application-security-hybrid-bootstrap.py`:
  root-owned PID-1 launch under the existing synthetic UID 1002, private runtime,
  pinned system deployment, no session/document/a11y bus, network disabled,
  bounded CPU/memory/lifetime and cleanup. Only the runtime's `/usr/bin/true`
  is attempted; the actual application UI is never launched or authorized.
- `tools/greyward-dev/application-security-hybrid-bus-check.py`:
  a non-mutating normal-account check of the actual shared user broker. It
  never attaches, reads/writes memory or copies a valid target descriptor.

The template is generic; Collabora supplies representative installed inputs,
not app-specific allow rules. Root-owned reflink copies avoid relabeling live
deployments or adding content permissions for mixed host labels within them.
Copy intake checks root ownership and non-writable entries, but is not yet the
descriptor-bound generation/extension verification required for an actual grant.

## Bootstrap observations

The temporary policy compiled and installed against the actual Fedora policy.
Startup reached bubblewrap/runtime construction after correcting namespace
setup, private memfd, deployment `.ref` locking and private dconf mapping rights.
An early fixture mount mistake was corrected by explicitly binding the new
fixture into its private mount namespace. A stop timeout was corrected with
explicit stop limits and PID-1 signal rights; that test workload was reaped.

The system KDE deployment contains `alsa_var_lib_t` objects despite most files
being `var_lib_t`. A reflink experiment normalized only disposable code copies:
9,353 app entries and 58,228 runtime entries checked. No live deployment was
relabelled. The last launch still returned **1**: bubblewrap was denied metadata
access to the journal socket; service/userdb access remained intentionally denied.
This is bootstrap progress, not a working graphical workload or either gate.

Root-only JSON receipts remain at
`/var/tmp/greyward-hybrid-proof-20261009/bootstrap-2.json` through
`bootstrap-12.json`. Their compile/launch/audit/cleanup results distinguish a
failed application launch from a successful harness exit. The final tested
policy hash in receipt 12 was
`10b88ed200aadeea5cbaa6a84925497c1f092b0790bb9a47a5ece3dd35f14e28`.
Subsequent source changes make cleanup failures retain the fixture, add generic
app selection and make failed bootstraps exit nonzero; that revised bootstrap was syntax
checked but not rerun after the stop boundary was found.

## Mandatory shared-bus trust failure

The normal account's broker, PID 1220412/start ticks 3902343, was
`greyward_guard_u:greyward_guard_r:greyward_guard_dbusd_t:s0`.
The probe caller was the actual enrolled UID 1001 in `greyward_guard_t`.

| Non-mutating check | Actual result |
|---|---|
| Open `/proc/1220412/mem` read-only, close without reading | **Succeeded** |
| `pidfd_getfd(held_pidfd, -1, 0)` | **EBADF (9)**; passed the preceding attach-mode check |
| Open process memory read/write | Denied; not sufficient to rule out ptrace access |
| Memory bytes read/written / valid descriptors copied | **0 / 0 / 0** |

Installed policy also permits `greyward_guard_usertype` →
`greyward_guard_dbusd_t` process `ptrace` while `deny_ptrace` is off; Yama
`ptrace_scope` is 0. The probe verifies UID, packaged executable, pidfd and start
ticks. It does not prove actual code injection or a protected-file bypass.

The [kernel pidfd implementation](https://github.com/torvalds/linux/blob/master/kernel/pid.c)
checks `PTRACE_MODE_ATTACH_REALCREDS` before retrieving the requested descriptor;
an intentionally invalid target descriptor therefore tests authorization without
stealing an existing FD. The pinned
[dbus-broker v37 SELinux implementation](https://github.com/bus1/dbus-broker/blob/v37/src/util/selinux.c)
performs `send_msg` checks in the bus process itself. These source references
explain the result; upstream master is not presented as the installed kernel's
exact source receipt.

A prepared application context alone does not protect the shared IPC intermediary.
Protecting only the portal frontend leaves that intermediary outside the required
trust boundary. Its compromise could invalidate forwarded identity/routing and
userspace message checks. Names, live PIDs or historical AVCs cannot compensate
for that missing trust closure. No real attack against the running broker was
performed.

**Required reassessment:** protect and verify the bus/frontend/proxy closure,
including entry, configuration, process inspection, activation and instance IPC,
before binding a portal request to a grant. This is broader than silently adding
one URI-return hook. A fresh trusted bus activation can disrupt the existing
desktop, which this task explicitly forbids. No bus policy, bus configuration or
activation was changed to work around this constraint. Do not replace this with
a private portal or a second authorization daemon.

## Cleanup, regressions and limits

All temporary modules and workload processes were removed; disposable reflink
trees were deleted after their labels were restored. Root receipts and source
staging are retained. No account mapping, registered labels, grant records,
Flatpak overrides, production package or user profile was changed. No reboot,
logout, graphical restart or Administration restart occurred.

Final checks: SSH remained connected; Labwc retained PID 1220462 in the protected
display context; the existing workflow service was active; SELinux remained
Enforcing; no hybrid module or workload remained. Free space returned to 5.2 GiB.
Normal-account `GetCoverage` still returned revision 8, PROTECTED/AVAILABLE with
inventory UNKNOWN. That is the existing provider's readback; it does not validate
the proposed shared-bus grant architecture or demonstrate a protected-file bypass.
Python AST parsing of the final harness passed, and the normal-account bus check
ran successfully. `tests/static.ps1` and `tools/validate-repository.ps1` both
passed. No Rust, Context or Center implementation changed, so their full suites
were not rerun. Existing positive desktop workflows were not re-exercised and are not
claimed as fresh acceptance. The new grant, revoke, child-scope, original-file
editing, persistence and first-use UI gates remain unrun; no manual authorization
test entry point is ready. The five-working-day investigation budget was not
exhausted; work stopped on the mandatory trust prerequisite, not a time limit.
