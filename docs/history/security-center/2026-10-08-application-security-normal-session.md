# Application Security — normal development session, 8 October 2026

Status: PASS for scoped normal-session development integration; dated evidence,
not release acceptance.

This receipt supersedes the 7 October unenrolled `.149` integration state.
The normal `development-user` account is deliberately enrolled. Its real greetd PAM
session, ordinary user manager and SSH shell use `greyward_guard_u` /
`greyward_guard_r` / `greyward_guard_t`. SELinux remains Enforcing. Fedora
PAM/authselect are unchanged. No reboot, installer, image or LUKS change occurred.

## Implemented boundary

- A root-owned matched Labwc derivative owns the actual seat and gates protected
  authentication input. Ordinary DMS/desktop applications remain confined.
- An auth-only, generated DMS native shell uses a private bus/configuration and
  separate authentication domains. Fixed Fedora Polkit/chkpwd helpers perform
  fresh authentication. Root pidfd/lifetime and readiness checks withdraw the
  seat on authentication-owner loss; process existence alone is insufficient.
- Admission/readback checks the real login mapping, process roles, user manager,
  root scope, matched file digests, fresh native authentication heartbeat,
  kernel cross-domain decisions and registered object labels.
- The shared schema-four broker/store supplies descriptor registration,
  generation/revision-bound reviewed grants and fresh resource projections.
  Stored grants are intentions; prepared launch verifies the tested domain.
- Only `openssh-key-inspection/v1` is currently reviewed: the pinned installed
  `ssh-keygen -l -f` generation, fixed registered key paths, read-only access,
  disconnected private unit and suppressed streams. This is not general SSH,
  signing, IDE or credential export access. Unsupported tools remain unavailable.

The normal account's actual `.ssh` directory is registered. Existing keys were
not overwritten. A new validation-only Ed25519 key was created where none
existed; it is not authorized on another system. No secret contents appear in
receipts or test output. The CLI's default category/label are CUSTOM / Custom
protected directory; registration does not imply automatic discovery.

## Live evidence

| Check | Result / scope |
|---|---|
| Actual normal session enrollment | PASS: mapped graphical session/user manager and ordinary SSH shell; root verifier reports effective PROTECTED / AVAILABLE with fresh evidence. |
| Descriptor registration | PASS: actual `.ssh` O_PATH handoff, fresh protected native Polkit/PAM, COMPLETED at policy revision 2 with verified readback. |
| Reviewed grant | PASS: fresh protected native Polkit/PAM, COMPLETED at revision 3, generation-bound persistent READ profile. |
| Ordinary/direct bypass | PASS: ordinary open and direct `ssh-keygen` cannot read the registered private key. |
| Reuse | PASS: two real Guard launches with unchanged grant returned success without another authentication prompt. Output streams were discarded. |
| Normal Flatpak | PASS: existing Brave Flatpak can read ordinary `/etc/os-release` and cannot read the protected key. Existing overrides preserved. |
| UI projection | PASS: installed Center 66 renders the real protected directory, live PROTECTED hero, details and available workflows. Nine focused backend tests include expired-positive rejection. Actual normal-desktop screenshot inspected. |
| GUI revocation | PASS: real Center review/confirm, private native Polkit/PAM, revision 5 → 6, grant disappears; existing Activity contains POLICY_REVOCATION / COMPLETED / verified_readback=true from root-broker-operation-readback. Subsequent managed launch is denied. |
| Package coherence / restart | PASS: Center 66 / Context 68 / runtime 25 installed, `rpm -V` clean. Actual broker restart retains registered-object readback and effective PROTECTED; two launches using the persisted reviewed grant succeed before final GUI revocation. |
| DMS/Labwc / recovery | PASS: normal desktop active, native protected owner challenges succeed; root and ordinary SSH available. Earlier failed helper admission returned to the greeter and was recoverable through root SSH. |

Protection failure exposed narrow missing Fedora helper entrypoints, shadow DAC
capability and Polkit result transport permissions. The separate helper domains
now have these fixed permissions; ordinary subjects acquire no credential,
authentication process, input or grant-domain authority. O_PATH reception uses
the specific directory ioctl handoff, not file content access. Normal Flatpak
private mount destinations include tmpfs shared memory and existing device
permissions; protected-resource access remains independently denied.

The native authorization handoff now unloads the competing ordinary lock
password form. The Center suspends background inventory renewal during a
review/apply so it cannot crowd the policy/authentication worker queue; operation
polling remains active and cached leases still expire. The real final GUI
sequence progressed through applying/readback and published verified completion.
The earlier timeout did not falsely report success; revision 4 had committed
before the UI recovered. A second creation/reuse/revocation verified the fix.

## Installed inputs and focused source checks

| Artifact | SHA-256 |
|---|---|
| Center `0.1.0-66.fc44.x86_64` RPM | `9222dabfed07af8a725c9dc455cd135d2f0851c9496a8839f112203694510e3a` |
| Context `0.1.0-68.fc44.noarch` RPM | `200087689feed20d8103eed6b9164ceb1a02a1ac184c595fe64dfaa913b20309` |
| Runtime `0.1.0-25.fc44.x86_64` RPM | `28a02eac96e823a668a3b6b4720886a5aeb8507d478d74acf6c20995354cf681` |
| Installed Center executable | `a4aa25abf94b2a16ba01ada4ad923a66bbf24c1c3f8a0f8b2d80c4d80a143e14` |
| Installed Guard executable | `b430f94ef2c136b9572af640e8ca259bacae032bc732169a823b6b33472a3928` |

DMS remains `v1.6.2-6`; Quickshell `0.3.1-5.fc44`, Labwc upstream `0.9.6`
with the pinned protected-input derivative, UWSM `0.24.3-1.fc44`.
Source compositor commit `12987307a5de32db5acbb3f59d41277373ab969e`,
matched executable digest
`28bcc07a71fa235ae314385b06b33869779c5dfc761a01592ddd5fb0c39eab80`.
Root receipts retain the generated shell/seat closure and installed policy inputs.

PASS: workspace formatting on Fedora, nine backend read tests, 105 focused frontend tests, three
authentication-assembly tests, nine enrollment tests (one Linux-only synthetic
cryptsetup test skipped on Windows), and both repository gates. Runtime 24
completed its packaged Cargo check for runtime/domain/backend suites. Runtime
25 changes the Python authentication assembly only; its RPM uses `--nocheck`
after those Rust checks and the focused assembly tests. No new Clippy, full
workspace/Tauri suite, performance or reproducibility acceptance is claimed.

The temporary `greyward_live_input_test` policy and three root-only keyboard/
capture test binaries were removed after the actual UI walkthrough. Coverage,
normal SSH and Flatpak/protected-key denial pass again without that module.
The private input-test directory was removed. The final validation grant is
revoked; the registered directory remains protected.

## Development recovery and rollback

Root-private originals, package receipts, policy snapshots, login mappings and
generated desktop inputs are retained under
`/var/lib/greyward-development/application-security-live/enrollment-20261008`.
The existing host key has a root SSH recovery entry restricted to the known
development host; no recovery account/password was created. A previously
inherited NOPASSWD ALL development sudo rule was removed, not restored.

Protecting `.ssh` also correctly denies the dropped-UID OpenSSH public-key
lookup. The development account's existing **public** authorized keys are copied
to root-owned `/etc/ssh/greyward-authorized-keys/development-user`; a user-specific sshd
drop-in selects that path. Private keys remain protected. This is an explicit
development integration receipt; production key management/ownership is not
automatically supplied by the experimental package.

Rollback requires root/offline authority: stop/withdraw reviewed workloads,
restore journaled object labels, then restore saved mapping/desktop/package
inputs across a deliberate session boundary. Preserve root SSH until normal
public-key lookup is verified. Do not restore an old policy database while
leaving new labels/grant modules active. Do not run the 7 October historical
withdrawal script as a current complete rollback procedure.

## Limits and DEFERRED HARDENING

This validates one real development account/seat, not automatic production
installer enrollment or a clean-image release. Arbitrary IDE tools, write/timed
raw grants and unknown-tool temporary fallback remain UNAVAILABLE. Flatpak
inventory is incomplete and remains UNKNOWN; global application inventory is
not inferred from available broker transport. Native isolated script/AppImage
and graphical support retain their documented provider constraints.

DEFERRED HARDENING: exhaustive portal/deputy/alias and multi-user matrices,
performance/reproducibility/overload, physical-seat/suspend and clean ISO
acceptance, supported account-management/public-key lifecycle, authenticated
offline rescue boot and complete installed rollback rehearsal. These checks
must not be represented as passed or turned into broader production promises.
