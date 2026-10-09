# Application Security experimental package

Status: real normal-session DEVELOPMENT implementation, not release acceptance. Canonical
[current implementation and receipts](../../../docs/security-center/APPLICATION_SECURITY_PLAN.md);
[production enrollment design](../../../docs/security-center/APPLICATION_SECURITY_ENROLLMENT.md)
has approved decisions and normal `.149` enrollment using the protected native
authentication domain and root-owned matched seat. See the
[normal-session receipt](../../../docs/history/security-center/2026-10-08-application-security-normal-session.md)
for real resources, tested grants, kernel outcomes and recovery. Automatic
production installation/upgrade/rescue acceptance remains unvalidated.
The following earlier package observations are historical:
The initial installed development path paired Center 61 / Context 66 with the
explicit workflow service and the real public system bus. Context 67 now adds
restart recovery without replaying mutations. The path exposes managed
isolation independently of enrollment. Runtime 20 reads negative prerequisites
and reports missing enrollment UNAVAILABLE; positive whole-session coverage is
not implemented. Policy
changes remain unavailable for unenrolled callers. The dated live-development
receipt in the delivery plan records the exact runtime revision and tests;
archived revision-13 checks do not validate this path. DMS 1.6.2-6 is retained.

## Delivery and authority

The package sources provide the default read broker, separate development
broker, Guard CLI, native worker, root-owned empty 0555 immutable-entry mount
target and pinned Wayland security-context helper. No preset, automatic D-Bus
activation, account enrollment or current image inclusion is supplied. No
scriptlet changes mappings/labels or starts protection.

The default `systems.mantis.greyward.ApplicationSecurity1` broker exposes
`ListApplications`, `GetApplication`, `GetCoverage`, `ListProtectedResources`
and `GetProtectedResource`. Pages have bounded limits 1–100 and opaque cursors;
later pages require the observed revision. Foreign/missing records are scoped
without disclosing private paths. Invalid/corrupt state fails rather than
creating a fallback inventory. Coverage never becomes PROTECTED from
stored metadata or root-owned package files.

The development binary uses `systems.mantis.greyward.ApplicationSecurityDevelopment1`
and a fixed enrolled UID-1002 provider with development database/policy paths.
Its typed reviews bind actual peer, expected revision and generation, require
fresh owner Polkit authentication, then verify kernel registration, persistent
READ grants or reference-based revocation. It does not implement production
multi-user policy, enrollment or evidence. The UID-1002 opt-in is root-owned and
ignored by other accounts; tests remove it at rollback.

Production source adds an enrollment journal and per-owner provider/workload
bindings. The explicit `greyward-application-security-workflows.service` uses
the same dispatcher on `ApplicationSecurity1`, with no preset. Normal local
accounts may prepare restrictive isolation; enrolled resource/grant operations
still require the protected authentication boundary and confined actor. Read
capabilities carry separate `isolation` and `policy_changes` booleans, validated
by Context/Tauri. Neither capability establishes whole-session coverage.
Lifecycle, live coverage and policy/admission gates remain incomplete.
Ordinary broker open refuses an older production database schema rather than
silently invalidating rollback. No RPM activation/mapping change is supplied.

`maintenance.py`, `greyward-maintenance.target` and its console service are
source only and **excluded from this experimental spec**. They require explicit
offline boot, trusted foreground tty1, no ordinary workloads and fresh LUKS
passphrase authentication. Nine focused tests include a real synthetic cryptsetup
container; actual boot, console, policy repair and known-good rollback are not
validated. The future package must install/test the matched lifecycle tools
before this becomes an installed recovery path. No new recovery account exists.

## Managed workflows

The shared native worker supports immutable ELF, fixed Python/sh/bash composite
script identity and bounded Type-2 x86_64 AppImage extraction without executing
the downloaded runtime/FUSE. Graphical ISOLATED uses private nested Labwc,
clipboard and Xwayland. Payloads have private home/namespaces, no network or
host session bus/display socket and no Protected Data grant. Readiness verifies
SELinux, Landlock, seccomp and dropped privileges before exec; no unrestricted
fallback exists.

Safe Open uses this runner with a retained selected descriptor and rejects
protected-label copying. Configured Flatpak document handlers are explicitly
unavailable pending the native provider. WRITE/timed raw grants are unavailable;
reviewed tools support persistent READ only. In-process extensions share access.
Current new reviews/reuse additionally require the pinned nonexporting
`openssh-key-inspection/v1` profile. Generic legacy records may be withdrawn but
cannot activate/launch, even in development. SSH login/signing, IDE raw access
and the restrictive temporary fallback are unavailable pending their own
contracts. The authentication assembler and production SELinux inputs are
source only, excluded from the experimental spec and all image inputs.

Development CLI forms (not an enrollment/install recipe):

```text
greyward-guard run [--graphical] -- FILE [ARGS]
greyward-guard --development resource register DIR
greyward-guard --development grant review /usr/EXEC RESOURCE_REF
greyward-guard --development run --grant GRANT_REF -- /usr/EXEC [ARGS]
greyward-guard --development grant revoke GRANT_REF /usr/EXEC
greyward-guard --development run [--graphical] -- FILE [ARGS]
```

The GUI revokes by reference without requiring the old executable to remain.
CLI compatibility retains its executable argument. Neither CLI nor GUI sets up
missing enrollment prerequisites. The owned development test coordinator does.
Root AVC/failed-syscall evidence is a bounded transport into existing telemetry,
not a second history database; attribution/global coverage remain UNKNOWN.

## Builds and validation

Use the fixed development builder `tools/greyward-dev/build-application-security-experimental.sh`
with pinned Fedora `/usr/bin` Cargo/Rust tools, the committed lock/vendor input
and offline resolution. Do not invoke Cargo as root or download in `%build`.
The spec retains source/licenses and required libseccomp/Wayland helper inputs.
The builder's `--warm` compares the same archived inputs/private cache; older
receipts remain [historical](../../../docs/history/security-center/2026-10-07-application-security-package-notes.md).

Latest source workflow evidence is in the plan, including actual kernel grants,
Safe Open, graphical payloads and GUI review/cancel. Full GUI commit, matched
package-only acceptance and production coverage are pending. Extended cache,
performance, hardware and release/image matrices are DEFERRED HARDENING.
Explicit development activation is owned by
`tools/greyward-dev/application-security-live-enable.sh` and its checked rollback
companion. The additional development CIL protects managed workers from the
unconfined host and permits fixed root-service stream transport plus PID 1's
disposable tmpfs setup. The broker's root-private parent remains mode 0700;
internal traversable paths are explicitly set despite umask 0077. PID 1 mounts
the private home inside each workload namespace. These inputs do not enroll a
login or label user secrets. They are excluded from production image inputs.
