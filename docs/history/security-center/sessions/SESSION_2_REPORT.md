# GREYWARD Security Center V0 — Session 2 Report

> Historical implementation report; not a current architecture document.

SESSION OBJECTIVE REVIEW

THIS SESSION WAS SUPPOSED TO:
- implement the reusable evidence framework;
- add SELinux posture;
- add boot-security posture;
- add storage-encryption posture;
- add TPM posture;
- integrate them into the evaluator and UI;
- validate them on GREYWARD-DEV.

RESULT:
PASS

COMPLETED:
- Added a bounded, deterministic concurrent collection framework with cancellation and timeout handling.
- Added typed read-only adapters for SELinux kernel state, UEFI/Secure Boot efivar, mountinfo storage protection, and TPM device capability.
- Integrated normalized facts into the existing domain evaluator and snapshot v1 schema without changing the domain contract.
- Integrated live posture rendering into the existing GTK/libadwaita application; the UI consumes evaluator output and invents no conclusions.
- Added normal and unavailable/error-oriented tests, including the distinction between actionable plain root storage and unavailable TPM capability.
- Added a non-installed diagnostic binary for real Fedora evidence capture.

REAL GREYWARD POSTURE OBSERVED:
- SELinux: Enforcing; evaluated PROTECTED.
- Boot: UEFI with Secure Boot enabled; evaluated PROTECTED.
- Storage encryption: root storage observed plain (Btrfs root on the VM system disk, no encrypted ancestor); evaluated ACTION_REQUIRED.
- TPM: no usable `/dev/tpmrm0` exposed to the guest; evaluated UNAVAILABLE, not a security failure.

NOT COMPLETED:
- Later V0 capabilities (HSI/DNF5, network controls, Flatpak, privacy, USBGuard, final UX, packaging hardening, and release gate) were not started.

SELF-DETECTED ISSUES:
- The Fedora `selinux` Rust crate was not available in the VM cache and crates.io resolution was unavailable. The adapter therefore uses the stable read-only `/sys/fs/selinux/enforce` interface instead; no subprocess or security mutation was introduced.
- The RPM spec text still describes the initial foundation in its summary/changelog; the package contents and runtime behavior are Session 2-correct, but that metadata wording should be refreshed in a later packaging-focused session.

VALIDATION:
- build: PASS — Fedora release workspace build.
- tests: PASS — 14 workspace tests, including normal and unavailable-state coverage.
- Clippy: PASS — `cargo clippy --workspace --all-targets --locked -- -D warnings`.
- RPM: PASS — `rpmbuild -ba`, RPM install, and clean uninstall.
- runtime: PASS — installed binary launched as non-root UID 1000 under the canonical DMS/Labwc graphical session with Wayland and user D-Bus; bus name `systems.mantis.greyward.securitycenter` registered.
- logs: PASS — runtime log was empty; no launch error observed.

FILES CHANGED:
- `security-center/Cargo.toml`
- `security-center/Cargo.lock`
- `security-center/crates/greyward-security-backends/Cargo.toml`
- `security-center/crates/greyward-security-backends/src/*.rs`
- `security-center/crates/greyward-security-center/Cargo.toml`
- `security-center/crates/greyward-security-center/src/main.rs`
- `.secrets/ssh/config` (managed alias updated to the confirmed fixed GREYWARD endpoint)
- `docs/history/security-center/sessions/SESSION_2_REPORT.md`

REMAINING PLAN

SESSIONS REMAINING: 8

SESSION 3:
Firmware/HSI and DNF5 security-update readiness.

SESSION 4:
Network posture and reversible active-connection trust-zone control.

SESSION 5:
Flatpak isolation, portal health and permission revoke/restore.

SESSION 6:
Privacy transparency, external-service disclosure, retention/export and activity.

SESSION 7:
USBGuard/device visibility and recovery readiness.

SESSION 8:
Complete V0 Security Center UX and error/action states.

SESSION 9:
Visual/accessibility quality, packaging integration and DMS discovery.

SESSION 10:
Hardening, abuse/privacy/performance testing, rollback and final V0 release gate.

NEXT SESSION:
Session 3.

Plan deviation: the approved helper identified the canonical Hyper-V guest as `GREYWARD-DEV` rather than the supplied `GREYWARD-DEV-BUILD`. Per explicit user authorization, the guest was moved from the dynamic Default Switch to the existing dedicated `GREYWARD-DEV-NAT` network; the managed `greyward-dev` alias was updated and SSH access was verified. The historical private address is intentionally redacted. No Security Center scope was expanded by this deviation.
