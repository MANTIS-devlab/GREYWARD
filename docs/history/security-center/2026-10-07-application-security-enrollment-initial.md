# Initial production-enrollment evidence — 7 October 2026

HISTORICAL scoped receipt. Current authority:
[enrollment design](../../security-center/APPLICATION_SECURITY_ENROLLMENT.md).
This record does not validate production enrollment or a release package.

## Scope and preservation

Branch `codex/dms-1.6-migration`, HEAD
`d800c6ce73ed900f544b80d6d04bb3bd5f791da9`. Existing dirty source was preserved;
no commit/reset, reboot, active-session restart, account mapping, global SELinux
boolean or installer/ISO change was made. Baseline inventory, original touched
files and logs are retained under ignored
`output/application-security/20261007-enrollment/`.

Source includes the existing-database enrollment journal/CAS, local-account
validation, per-owner providers/caches/workload/display/audit binding and
serialized multi-owner dispatch. Production subjects use root-prepared
`system_r`; the synthetic owner role remains development only. The default
binary/service is still read-only, with UNKNOWN coverage. Existing production
schema upgrades refuse on broker open until offline snapshot/migration exists.
Maintenance console/target source is not packaged or enabled.

## Synthetic process-boundary evidence

Only UID 1002 and newly forked fixture processes were targets. No personal
file, DMS process, authentication data, input device or active desktop socket was
read. The probe changes no policy itself:
[application-security-enrollment-boundary.py](../../../tools/greyward-dev/application-security-enrollment-boundary.py).

| Invocation | Fixture | Actual result |
|---|---|---|
| `f3da0dba720945cbb5d4419e80f2fe2c` | Fedora `user_u:user_r:user_t:s0`, inherited ordinary-user template | Synthetic sibling memory ALLOWED; `/proc/PID/fd` pipe ALLOWED; self-context readable. Exit 0 confirms the expected gap, not security acceptance. |
| `80f1bea787734e539f20b417b048c117` | Private `system_u:system_r:greyward_boundary_probe_t:s0`, blanket read/ptrace denial | Synthetic memory DENIED/EPERM; pipe DENIED/EACCES; `/proc/self/attr/current` UNAVAILABLE. Exit 0 confirms expected incompatibility, not a production fix. |

Temporary fixture sources:
[ordinary template](../../../spikes/application-security/selinux/greyward_enrollment_boundary_probe.te),
[incompatible denial](../../../spikes/application-security/selinux/greyward_enrollment_boundary_deny.cil).
Never install these as production policy. Units used UID/GID 1002, the explicit
fixture context, 25-second runtime limit, no capabilities, NoNewPrivileges,
private network/tmp and protected home/system. Runtime was 57 / 50 ms. All
fixture modules and `/run` files were removed afterward.

Kernel: `7.1.13-200.fc44.x86_64`. The upstream
[SELinux ptrace hook](https://raw.githubusercontent.com/torvalds/linux/master/security/selinux/hooks.c)
uses `file:read` for `PTRACE_MODE_READ`, separately from process ptrace. Actual
fixture results support this distinction. `deny_ptrace` remained off; it was
not globally changed. Production binding now requires live denial of both
rights. This necessary refusal gate is not coverage and is incompatible with
the prototype's required self-inspection. Authentication subjects/input
transport require architectural work before activation.

Reviewed-tool broker-deputy behavior is a blocking **source gap**, not a
validated exploit: preparation accepts a new same-owner caller and its arguments
without separate fresh launch-intent authorization. Older direct-exec tests do
not cover that path. A focused cross-caller test and launch-authorization/profile
design remain mandatory.

## Focused validation and remaining gates

Builds reused the unprivileged Fedora offline cache and explicit `/usr/bin`
Cargo/Rust/Clippy. No root Cargo, dependency download or expanded performance
matrix was used. Commands:

```text
python -m unittest discover -s tests -p test_application_enrollment.py
sudo env GREYWARD_LUKS_FIXTURE=1 /usr/bin/python3 -I tests/test_application_enrollment.py
cargo test --locked --offline -p greyward-application-security
cargo-clippy clippy --locked --offline -p greyward-application-security --all-targets -- -D warnings
```

Local eight maintenance tests pass; the live fixture is skipped unless selected.
Fedora runs nine and passes. Real cryptsetup accepts the synthetic correct key
and refuses the wrong one on a private 32 MiB file container; actual root disks,
passphrases, VT, boot and installed repair/rollback were not tested. Rust and
Clippy logs are retained beside the baseline; ignored Fedora tests stay ignored.
Final runtime suite: 115 passed, 0 failed, 21 environment-specific tests ignored.
Workspace formatting and runtime all-target Clippy pass. Fedora Context suite:
296 passed. Frontend UX suite: 89 passed. Both repository gates pass. The initial
Windows Context run had 14 errors from unavailable Linux-only descriptor APIs
and 69 skips; it is not a Fedora failure or a passed platform check. No source
was changed to hide that mismatch; the actual Fedora suite was rerun successfully.

Post-fixture: SELinux Enforcing; only `greyward-dms-greeter` GREYWARD module;
root and `__default__` mappings remain `unconfined_u`; active Labwc PID 4813 and
DMS PID 4888 unchanged; SSH operational. E0–E5 remain unpassed. Authentication
separation, reviewed-launch intent, durable label/schema recovery, account
origin/admission and installed maintenance/rollback are blocking work, not
DEFERRED HARDENING. Exhaustive optional matrices remain deferred.
