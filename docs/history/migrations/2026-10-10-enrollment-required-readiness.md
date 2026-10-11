Historical pre-assembly snapshot. Subsequent candidate packaging and copied-store checks are recorded in [the enrollment authority](../../security-center/APPLICATION_SECURITY_ENROLLMENT.md). Production acceptance remains pending.

# Enrollment-required ISO readiness — 10 October 2026

Status: **NO-GO**. The user requires enrollment integration before ISO
construction. An ISO omitting Application Security is not an accepted fallback.
This receipt supersedes the earlier storage and pending-login observations;
it does not supersede the unresolved enrollment/recovery gates.

## Verified installed state and storage

Read-only SSH inspection confirms session 31 is running for `stendev` on seat0.
Labwc PID 6739 runs in `greyward_as_display_t`; the private authentication bus
runs in `greyward_as_auth_t`. SELinux is Enforcing. Session 9's repaired login
route has therefore admitted a real protected compositor. This is not a fresh
installation, full graphical interaction test or offline recovery rehearsal.

Installed packages remain Center 89 / Context 81 / experimental runtime 32 /
Session 9 / Branding 15 / DMS 1.6.2-6. Candidate artifacts are Center 90 /
Context 82 / Session 9 / Branding 15 / DMS 1.6.2-8. Retained artifact digests
were recomputed and recorded in `enrollment-required-readiness.json` beside
the original release preparation receipt in the local build output.

The dedicated build filesystem now has approximately 41 GiB free. Only the
completed 12 GiB Rust compiler cache beneath the exact existing build root was
retired after checking its cache marker, resolved path and absence of running
build processes/executables. RPMs, source archives, logs, previous candidates,
recovery inputs and user data were preserved. Its input receipt was retained.
Root still has approximately 4.9 GiB free; expensive builds must use the dedicated
build volume. The previous ISO storage blocker is cleared.

## Actual package-level failure

The DMS 1.6.2-8 RPM was extracted into a new directory on the dedicated build
volume. The existing exact-input authentication assembler was run against its
original shell and release receipt, without installation or activation.
It failed with `Matched DMS package shell/receipt required`.

`security-center/packaging/application-security/authentication/assemble.py`
explicitly accepts only `v1.6.2-6`. Independently, `desktop/prepare.py` copies
revision-6 binary/shell inputs and records revision 6. Removing the check or
changing a release name is insufficient evidence: the new derivative needs the
existing preimage, package and real authentication acceptance gates.
No check was bypassed, no grant was created and no live closure was replaced.

## Blocking release integration

1. The selected protected compositor is not RPM-owned. The experimental runtime
   spec omits automatic SELinux installation, protected-desktop assembly,
   maintenance service and enrollment activation. The image expects its existing
   five GREYWARD packages; adding this experimental RPM would not supply closure.
2. `PolicyStore::prepare_account` currently issues `ExplicitMigration` origin.
   There is no completed installer-account enrollment transaction in the existing
   first-boot provisioner. Installer-origin admission, bounded failure/retry and
   rollback must be implemented before moving the completion marker.
3. `/usr/libexec/greyward-maintenance` is absent and the maintenance console unit
   reports `LoadState=not-found`. The source console authenticates LUKS but
   explicitly does not implement the enrollment/policy repair lifecycle.
   Installed encrypted rescue boot and matched repair/rollback remain unvalidated.
4. Runtime 33 intentionally leaves deputy/portal coverage false. Existing
   supported native isolation and reviewed inspection grants must not be described
   as generic Flatpak permission support or complete provider coverage.

The accepted enrollment authority requires independently proven offline recovery
**before enrollment**. A compiler, chroot or still-running development session
cannot prove encrypted boot recovery. `.149` must not be rebooted or interrupted;
the requested final test VM must remain ready for the user's manual installation.
Consequently that mandatory acceptance needs a separate disposable encrypted
validation installation, rather than an experiment on the active alpha system.
No automatic installer enrollment is activated while that gate is missing.

## Outcome

No fresh ISO or test VM was created. No reboot, logout, graphical/bus restart,
policy change, account mapping change or package deployment occurred during this
readiness check. Earlier session-9 recovery installation remains separately
recorded. No publication occurred. Proceeding without enrollment or treating
experimental package installation as enforcement would violate the selected
release boundary.