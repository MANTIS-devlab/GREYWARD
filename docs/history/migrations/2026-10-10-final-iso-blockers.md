# Final ISO blocker investigation — 10 October 2026

Status: **NO-GO for ISO construction or manual acceptance**. This is a source
correction and targeted release-integration audit, not an enforcement receipt.
The user subsequently authorized use of the existing `.149` build workspace.
Read-only installed checks and a network-isolated DMS RPM rebuild use that
workspace; no installed package, account mapping, service or active session is
changed. No storage was deleted and no installer VM was created.

## Source and retained evidence

The retained preparation receipt identifies functional source
`8a5ede628c3a8ab8045473c4284afcf41772a353`, Center 90, Context 82, session 8
and branding 15. It reports 208 Rust passes (22 ignored), 331 Context passes
and 95 frontend passes. Those are previous build evidence, not tests rerun here.
The public checkout at this investigation is
`182650322e47c86b2140ea8d91e4d0a52233568c`, with two subsequent README commits.
Existing package artifacts and logs remain unchanged.

## Python constraint correction

`packaging/greyward-dms/assemble.py` compares installed Fedora tool NEVRAs with
`environment/production/dms-release.json` before opening upstream archives.
The Python 3.14.7-1.fc44.x86_64 receipt originated in commit `c65623de` on
5 October; the saved build failure reports installed Python 3.14.8-1.fc44.x86_64.
This is a stale GREYWARD toolchain receipt, not an upstream Python ceiling.

The candidate now pins exactly **3.14.8-1.fc44.x86_64**, with a distinct DMS
package identity **1.6.2-8**. Source/vendor digests, upstream commit, Go minimum,
distribution tags, offline vendor build and every other tool pin are unchanged.
Verification has not been loosened. `tests/test_dms_build_inputs.py` exercises
rejection of stale Python and unrelated Go drift, and verifies that matching
tools still reject an unverified upstream archive.

**Affected RPM rebuild: PASS** in the user-authorized existing workspace.
Live RPM queries confirm Python 3.14.8-1, Go 1.26.8-2 and rpm-build 6.0.2-1.
The build runs in a separate network namespace and installs nothing.
All 50 tested upstream Go packages pass; unprivileged CLI help and the absent
self-update check pass. RPM digest verification passes. The retained RPM is
`greyward-dms-1.6.2-8.fc44.x86_64.rpm`, SHA-256
`1090e7d5e22144a84440f7c02b5251c38a77f43c02e8f51f771108f873ce8814`.
An initial root invocation failed the upstream no-root CLI rule; it was rerun
unprivileged with the check intact. No installed-session compatibility is claimed.

## Application Security release integration blocker

The existing runtime is a development implementation, not a complete production
package closure:

- `security-center/packaging/application-security/greyward-application-security-experimental.spec`
  revision 33 installs broker/worker programs, explicit workflow services,
  D-Bus/Polkit definitions and assembly sources. It does not install/activate the
  required session/authentication/display/Administration SELinux modules,
  enroll accounts or install the maintenance console. No automatic preset is supplied.
- `desktop/prepare.py` still requires a particular development Labwc binary
  digest and explicitly uses the DMS `v1.6.2-6` shell/receipt. It cannot be used
  unchanged to attest the new DMS candidate or the stock compositor package.
  Live `rpm -qf` confirms `/usr/lib/greyward/application-security/desktop/bin/labwc`
  is not owned by any package. The installed runtime is still experimental 32,
  Center 89 and Context 81; rebuilding candidates does not deploy them.
- `environment/image/build.sh` stages only the greeter SELinux module;
  `environment/production/provision.sh` installs that module and has no
  Application Security enrollment transaction before its completion marker.
- `maintenance.py` explicitly contains no enrollment/policy repair lifecycle
  implementation. Its authenticated console prototype is not proof of installed
  rescue boot, repair or known-good rollback.

Required order is a matched runtime/policy/protected-compositor/authentication
package closure, policy/context readback and authenticated recovery proof,
then an installer-account enrollment transaction before ordinary login admission.
User mappings must not be activated merely because the Rust binary compiled or
the RPM installed. Root-controlled grants and generation checks, protected
authentication, Administration separation and SELinux Enforcing remain mandatory.

The installed-session and recovery requirements in
[APPLICATION_SECURITY_ENROLLMENT.md](../../security-center/APPLICATION_SECURITY_ENROLLMENT.md)
E0–E5 cannot be validated by source tests or a chroot. A separate Fedora test
system with a protected graphical seat and an encrypted rescue installation is
needed. The active development session is not a clean-install/rescue substitute.
Rebooting it remains prohibited. Consequently no
automatic enrollment, image integration or coverage claim was enabled here.
Clean first-boot admission and authenticated encrypted rescue/rollback cannot
be proven by the still-running development desktop. Stopping before promotion
is the requested security gate, not a successful integration claim.

## Supported scope and package consistency

Existing development support is distinct from production acceptance: native
ISOLATED execution and narrowly reviewed key-inspection READ grants exist;
generic IDE/SSH raw grants, writable Flatpak grants and the hybrid portal
authorization flow are not implemented product features. No permission mechanism
was invented to satisfy image checks. Missing enforcement remains unavailable.

| Component | Candidate | Evidence here |
|---|---|---|
| DMS | 1.6.2-8 | Offline RPM rebuild and upstream/package checks pass |
| Security Center | 0.1.0-90 | Retained prior package/test receipt |
| Security Context | 0.1.0-82 | Retained prior package/test receipt |
| Session | 0.1.0-8 | Existing source/spec and prior receipt |
| Branding | 0.1.0-15 | Existing source/spec and prior receipt |
| Application Security | experimental 0.1.0-33 | Excluded from production; enrollment unresolved |

The Center/Context truthfulness fixes remain in source and retained packages.
Production provisioning still selects the packaged
`/usr/share/backgrounds/greyward/greyward-wallpaper-black-art-4k.jpg`, seeds
new-account DMS wallpaper and invokes `greyward-sync-greeter-wallpaper` before
greetd. These are source contracts, not newly verified installed visuals.

Host storage at inspection: C approximately 98.8 GiB, F 152.9 GiB and D 65.1 GiB
free. The existing Linux build filesystem has 31 GiB free; root has 5.1 GiB.
After the rebuild the build volume has approximately 29 GiB free.
That is sufficient for the bounded DMS build but below the ISO runbook's
40 GiB free-space gate. No deletion or storage expansion is performed.
No fresh ISO, ISO checksum or manual-testing GO is available.

## Scoped validation in this investigation

- Both repository gates pass in both the public and engineering working trees.
- DMS Python suite: 19 passed, 10 Fedora/installed-fixture skips (29 total).
  The three new build-input checks also pass under actual Fedora Python 3.14.8.
- Image Python suite: 55 passed, seven platform skips (62 total).
- Enrollment source tests: eight passed, one platform skip (nine total).
- Scoped whitespace checks pass. Branding's canonical 12-consumer check passes.

These results are not kernel enforcement, installed recovery, clean-install or
visual wallpaper acceptance. Existing 208/331/95 evidence remains separately
retained; it was not replaced by these smaller suites.
