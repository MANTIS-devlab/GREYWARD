# Security Center desktop review deployment — 7 October 2026

Historical development deployment receipt, not production enrollment, image
acceptance or user approval of the interface. Current capability authority:
[Application Security plan](../../security-center/APPLICATION_SECURITY_PLAN.md).

## Disk preflight and bounded cleanup

Before any deployment, `.149` had a 62 GiB encrypted Btrfs root/home filesystem,
59 GiB used, approximately 1,006 MiB available (99% used). Inspection identified
compiler artifacts rather than user files as the safe cleanup candidates:

- Verified `/home/development-user/.cache/go-build` against `go env GOCACHE`, ownership
  and its cache README; `go clean -cache` increased available space to 3.5 GiB.
- Verified the exact debug incremental directory beneath
  `/var/tmp/greyward-application-security-build/security-center/target`, its
  CACHEDIR.TAG and absence of a running Cargo build. Removed only `debug/incremental`;
  available space increased to 9.7 GiB. Sources, debug executables/dependencies,
  package caches, test receipts, recovery material and user data were retained.
- The canonical package builder invalidated changed first-party compiler outputs
  in its dedicated Cargo target through existing source fingerprints. External
  dependency outputs remained cached.

After build, installation and window replacement, `df -h /` reported 49 GiB used,
10 GiB available, 84% used. No VM/disk/filesystem extension was needed.

## Matched packages and installation

The existing `environment/development/build-security-center.sh` built the actual
source workspace after `environment/image/stage-text.py` normalized its fresh
staging copy. An initial CRLF-related RPM preparation failure installed nothing;
the normalized retry succeeded. The source, registry and existing dependency
cache were reused. The transient user build had bounded CPU/memory/runtime;
the successful build completed in 13 minutes 37 seconds. Rust tests were skipped
by this packaging invocation; no new full-workspace or release acceptance claim
is made here.

| Receipt | Value |
|---|---|
| Source tree SHA-256 | `bd07a358b40eabf72ecd9fd1f93a9abc42a26a825d1f75a2802b467fb37850a2` |
| Center | `greyward-security-center-0.1.0-60.fc44.x86_64` |
| Center RPM SHA-256 | `4f62919c29cd5edf4a9f24cad8f678cacdd453df92c2a335cfece7df2c9b10b5` |
| Context | `greyward-security-context-0.1.0-65.fc44.noarch` |
| Context RPM SHA-256 | `91c6d8980f59f273f69491e49025212e0a91c93dec9e0086104a78da0a70e0e3` |
| Installed/running Center SHA-256 | `e00a50b26e890a1fa421bddb64f488f640e95b5269f526e84ac97c8019f540da` |

Before upgrade, the installed 59/64 package-owned paths and NEVRA receipts were
saved under the root-only, mode-0700 development directory
`/var/lib/greyward-development/security-center-desktop-review-20261007/`.
Its mode-0600 installed payload archive contains 103 entries and has SHA-256
`fb8d458ab3d0acc2a5a897256877437a1101d40e956ebda462d9e06cc8241b34`.
This is a file/metadata backup, not retained original RPMs or a rehearsed package
rollback. Original packages were not found in the bounded search.

Root-owned copies of both new RPMs passed digest and `rpm -Uvh --test` checks.
The local upgrade used `--nopostun` to suppress the old packages' automatic
system-service restarts. New scriptlets were inspected; upgrade did not activate
enrollment. Only the user Context service was restarted explicitly. Both installed
packages passed `rpm -V`; the desktop entry passed `desktop-file-validate`.
No runtime/Guard/policy package or image input was installed or promoted.

## Live desktop and backend evidence

- The old Center PID 236425 still held the deleted previous binary, SHA-256
  `64696ec9932b507cae690d1b6e108bda6eaa45e9f3dd091b9d60c7bdae25f63a`.
  UID, path and digest were checked before sending SIGTERM through a pidfd.
- Exactly one replacement `/usr/bin/greyward-security-center` was verified:
  UID 1001, PID 2586886, with executable digest matching the installed new binary.
  Canonical route requests for Applications and Protected Data were consumed.
  Protected Data was left open for the user's review.
- User Context PID 2582399 owned the actual typed API. `GetApplicationCoverage`,
  `ListApplications` and `ListProtectedResources` returned
  `greyward.application-security/v1`, source state `UNAVAILABLE`, reason
  `BROKER_UNAVAILABLE`, and a null projection. System bus
  `systems.mantis.greyward.ApplicationSecurity1` had no owner. No synthetic data
  or protection success was supplied to the user session.
- SELinux remained Enforcing. Login mappings remained default/root unconfined;
  no isolated-account or production enrollment mapping was added. Production
  enrollment remains disabled. Mutating Guard/grant workflows cannot be reviewed
  as functional in this unenrolled session.
- Labwc PID 4813, DMS PID 4888 and SSH daemon PID 4166 remained present. No desktop
  restart, reboot, authentication change or network-service restart was performed.
  Context had zero restarts since its deliberate upgrade restart; this is a
  bounded observation, not a stability acceptance test.

Automatic screenshots were attempted without changing the display. `grim`
reported `no supported format found`; DMS capture reported `frame capture failed`.
No actual-seat visual PASS is claimed. The user must review the displayed pages;
older private-window screenshots are not evidence for this deployment.

## Focused checks and review boundary

The 99 frontend contracts and eight focused Context workflow tests passed. Both
repository gates passed before deployment and were rerun after documentation.
Generated local receipts are under ignored
`output/application-security/20261007-desktop-review/`, including the build
manifest and live-verification JSON.

Deployment stops at user UI/UX review. Production enrollment, real-seat grant
authorization, release/image acceptance and DEFERRED HARDENING remain open as
described by the current plan. This receipt does not approve the interface.
