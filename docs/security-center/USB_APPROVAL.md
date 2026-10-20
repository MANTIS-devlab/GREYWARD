# Protected USB approval

The installed taskbar **Trust always** workflow was validated on 18 October
2026: physical password entry, protected Polkit approval, exact-device ALLOW,
kernel authorization, an on-disk USBGuard rule and matching-alert removal.
Unapproved devices remained blocked and SELinux remained Enforcing. This is
installed-system evidence, not clean-ISO, reboot or reconnect acceptance.

## Enforcement and corrections

The ordinary taskbar invokes the fixed `greyward-usbguard-approval` client in
`greyward_usbguard_approval_t`. It reads bounded availability metadata and uses
the protected authentication shell's IPC. It has no USBGuard mutation authority.
The protected shell launches `greyward-usbguard-auth-approval` in the separate
`greyward_usbguard_auth_approval_t` domain. Its fixed isolated Python entrypoint
requests upstream USBGuard approval with interactive Polkit authorization, then
verifies exact device identity, authorization and persistent trust. Only a
verified result can complete the request. The UI refreshes shared provider state.

Five integration defects were corrected:

- Atomic FileView replacement inherited the general auth-runtime label. A
  dedicated metadata directory/default file transition now labels replacement
  inodes correctly; the internal authentication heartbeat remains private/atomic.
- Qt IPC initialization needed private sockets and its own anonymous buffers.
  These receive narrow permissions and a client-owned type; generic tmpfs,
  private authentication files and cgroup access remain denied.
- The Python module defined `main()` without calling it. The fixed CLI emits
  structured evidence and a failure status when approval cannot be verified.
- Form creation could precede Qt keyboard-window activation. The protected form
  now restores input focus on window entry and visibility, without a timer that
  steals focus from buttons. Diagnostics contain booleans, never keys or secrets.
- Rule parsing treated `parent-hash` as the device's own `hash`. Only the actual
  device hash or serial establishes its stable identity.

The USB helper also has its own SELinux domain in the confined desktop role,
but it is intentionally excluded from `greyward_as_ordinary`. The protected
seat verifier tolerates only that reviewed non-ordinary domain when comparing
policy revisions; it recognizes a running helper only for the exact executable,
UID, SELinux context and active logind session scope. Ordinary role coverage
must remain identical to the saved receipt. This keeps policy updates from
mistaking the USB helper for a user application without weakening session
coverage checks.

Canonical owners are the two Go clients and verifier in `packaging/greyward-dms/`,
`authentication/assemble.py` and `desktop/materialize.py` under
`security-center/packaging/application-security/`, the USB approval SELinux
module, enrollment migration, Context `usbguard.py`/`usbguard_session.py` and
the first-party `greywardSecure` widget. No custom USB daemon or manual allow
rule substitutes for the protected user decision.

## Next ISO inputs

The canonical source tuple is DMS **1.6.2-25**, Security Context
**0.1.0-104**, Application Security **0.1.0-61** and Enrollment **0.1.0-52**.
Enrollment requires the exact DMS/Application Security pair; DMS requires the
fixed Context minimum. New revisions prevent reuse of previously built identities.
The validated installation uses earlier RPMs with backed-up matched source
hotfixes. The new tuple still needs normal package-build and image acceptance.

Complete staging invokes `environment/image/verify-usbguard-inputs.py` for all
four selected RPMs. It refuses missing or stale packaged verifier, Python CLI,
adapter, auth assembler, materializer, migration and SELinux compiler inputs.
Enrollment ships those public compiler inputs beside its compiled modules; its
canonical build compiles the modules from those inputs. DMS receipts also bind
both Go helper source hashes. Matching versions alone cannot bypass these checks.
Existing source/package fingerprints, module compilation and runtime enforcement
checks remain required; source-byte readback is not independent MAC validation.

## Regression gates

CI runs the USB action tests with real Python subprocess invocation, assembly,
package-verifier, migration, build-input and stale-RPM contracts. The new staging
check has positive fixtures and rejects changed/missing payloads and stale Go
receipts, including an observed rejection of an older real Enrollment RPM.

The explicit Fedora offscreen gate `tests/test_authentication_input_focus.py`
uses the generated form, synthetic input, disabled Polkit and a child-only
network namespace. It demonstrates the previous late-entry failure and restored
input while preserving button navigation. See the command in
[Security Center validation](../../security-center/README.md).

Before accepting a fresh image, repeat the actual normal-seat taskbar/password
flow, rule/device/kernel readback and matching-alert check; test unauthorized
callers remain denied. Do not infer persistence across unplug/replug or reboot
from a file write, and do not restart a live user's session without approval.
