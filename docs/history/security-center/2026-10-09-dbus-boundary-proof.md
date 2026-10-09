# Bounded D-Bus boundary prerequisite — 9 October 2026

Scoped development evidence, not generic Flatpak permission delivery. Current
authority: [Application Security plan](../../security-center/APPLICATION_SECURITY_PLAN.md).
This follows the [hybrid bootstrap](2026-10-09-hybrid-flatpak-bootstrap.md) and
[first-use prerequisite](2026-10-09-first-use-permission-proof.md).

## Decision and installed scope

**A passes: the inspection gap admits a small reversible correction. B passes
the existing native actor/preview negative checks, but portal-request-to-Flatpak
recipient association is NOT IMPLEMENTED. NO-GO for resuming the permission
bridge or claiming either end-to-end product gate.**

Normal `.149`: Enforcing, runtime 32, Center 89, Context 81. Root filesystem
5.2 GiB available. User bus is packaged dbus-broker 37-8.fc44 under UID 1001,
`greyward_guard_u:greyward_guard_r:greyward_guard_dbusd_t:s0`. User service
launcher PID 1220406, bus PID 1220412/start ticks 3902343; a11y bus PID 1222298.
Protected Labwc PID 1220462, native authentication PID 1220482 and root workflow
broker PID 1142355 remained running. SSH remained available throughout.

Explicit development module `greyward_session_bus_boundary` is currently active.
Its source is `spikes/application-security/selinux/greyward_session_bus_boundary.cil`.
It subtracts only ordinary-role process `ptrace` permission to the existing
session/a11y bus type, with a matching `neverallow`. No allow rule, global
boolean, user mapping, bus unit, activation or production package changed.
This is an unpackaged development overlay, not an image/enrollment change.

## A: actual kernel and compatibility results

| Check | Before | Corrected |
|---|---|---|
| Main bus memory descriptor open, immediately closed | Allowed | Permission denied |
| Main bus invalid-target `pidfd_getfd`, no valid FD copied | EBADF (9), attach check passed | EPERM (1) |
| A11y bus same two checks | Prior template allows inspection | Both denied live |
| Ordinary-role kernel readback | Inspection permitted for some subjects | All 62 admitted domains denied |
| Ordinary bus `send_msg`, socket, FD and process-metadata masks | Recorded | Identical to baseline |
| Stock FileChooser request from installed Collabora sandbox | Request succeeds and closes its own chooser | Same result |
| Root broker and Context coverage | AVAILABLE, revision 8 | AVAILABLE, revision 8 |
| Administration root/Context projection | Available, inactive, 120-second window | Same result |

The chooser test runs a transient Python probe inside the installed Flatpak;
it is not Collabora's actual editing workflow or protected-folder authorization.
No selected document was exported or read. Process memory bytes read/written
and valid target FDs copied remain **zero**. The policy closes attach-mode
checks used by the tested interfaces; it does not prove every process-injection
or broker-compromise route absent.

The tested fixtures are `tools/greyward-dev/application-security-hybrid-bus-check.py`
(`--expect-denied`), `application-security-bus-kernel-check.py`, and
`application-security-bus-compatibility.py` (`--portal-app com.collaboraoffice.Office`)
in the same tools directory. The compatibility fixture reuses the existing
first-use probe's FileChooser function rather than adding a portal implementation.

## B: existing root review and its limits

Actual installed calls reject extra forwarded UID/PID/app-ID/request fields,
an unimplemented portal-review method, unknown apply/read references and an
unreviewed launch. Grant projections remain identical.

`tools/greyward-dev/application-security-bus-review-check.py` exercises a real
metadata-only registration preview on an empty disposable home-Btrfs directory:

- Correct live owner reads its PENDING preview and cancels it successfully.
- Another same-UID process cannot read or apply that preview.
- A preview belonging to an exited process cannot be read or applied by another.
- An old policy revision is rejected.
- A selected directory changed after preview produces FAILED/READBACK_FAILED,
  no committed revision and no verified-success claim. Interactive authentication
  is disabled and object revalidation fails before authorization.

No directory registration, relabel, resource policy, grant, user approval or
authentication was performed. An exited-owner preview is left only in bounded
in-memory operation state to expire; disposable directories are removed.
Early harness attempts correctly encountered unsupported tmpfs and then a typed
preview envelope parsing mistake; the corrected home-Btrfs fixture passes.

Source inspection confirms `peer_bus.rs` obtains the real system-bus sender's
ProcessFD/UID/context and `execution.rs` holds/revalidates that execution.
`policy_intent.rs` and `workflow.rs` bind the native preview, descriptors,
revision and live actor before authorization/commit. These checks establish
the immediate caller and native operation ownership, not the original Flatpak
behind an untrusted portal forwarder. No accepted interface binds a protected
portal selection to a root-prepared Flatpak workload or displays the required
root-verified application/generation/resource/scope in protected approval.

The new policy does not attest bus startup/configuration, revoke old handles,
protect portal/proxy processes or prevent approved applications becoming IPC
deputies. Existing coverage readback concerns the installed providers; its
PROTECTED state does not validate this proposed generic permission architecture.

## Rollback, receipts and remaining acceptance

Rollback was actually rehearsed: remove only `greyward_session_bus_boundary`,
observe the original ALLOWED/EBADF behavior, reinstall the same CIL and observe
DENIED/EPERM again. Bus PID and start ticks are identical across the sequence.
The corrected module is retained as the explicit development candidate.
Root SSH rollback: `semodule -r greyward_session_bus_boundary`. No session or
bus restart is required to remove this isolated overlay. Removing it restores
the known inspection gap; do not describe that as a secure permission boundary.

Root-only receipts/source live under `/var/tmp/greyward-bus-boundary-20261009/`:
kernel-before/after JSON, compatibility before/after, native-review JSON,
rollback/restored JSON and installed-module inventory. Files are mode 0600,
directory 0700. No credentials or secret contents are collected.

Both repository gates and final Python syntax checks pass. Focused installed
kernel/read/negative-operation probes above pass. No Rust, Context or Center
implementation changed; full suites and fresh interactive PAM/sudo were not
rerun. Administration availability/kernel isolation is not a fresh interactive
sudo acceptance claim. No application/bus/compositor/authentication service was
restarted; no reboot, logout or power operation occurred.

Further proof remains blocked on root-verified portal request/recipient binding,
prepared Flatpak subjects, helper/single-instance isolation, original-file
editing/saving, writable and once-lifetime grants, persistent reuse and revocation.
No new private bus, daemon, proxy, permission framework or portal fork was added.
Any continuation must resolve that boundary explicitly within the existing
minimal-architecture limits, not promote this inspection test into feature GO.
