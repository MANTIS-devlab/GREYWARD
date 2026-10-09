# Protected authentication and reviewed-tool evidence — 7 October 2026

Historical scoped receipt. Current authorities are the
[delivery plan](../../security-center/APPLICATION_SECURITY_PLAN.md) and
[enrollment design](../../security-center/APPLICATION_SECURITY_ENROLLMENT.md).
This receipt does not establish production enrollment or whole-session coverage.

The working tree on `codex/dms-1.6-migration`, based on
`d800c6ce73ed900f544b80d6d04bb3bd5f791da9`, was preserved. Before-change hashes,
copies and logs are retained locally beneath
`output/application-security/20261007-authentication-enrollment/`. Installed
Center 59, Context 64 and DMS 1.6.2-6 remained unchanged. Experimental runtime
specification 15 is source only; it was not built or promoted.

## Implemented boundary

Separate `greyward_as_auth_t` policy preserves self-inspection while preventing
the ordinary subject from reading authentication process memory, descriptors,
pipes or transport, sending signals, or entering its executable domain. It
uses Fedora's existing PAM helpers; no PAM/authselect configuration is rewritten.
The generated auth-only DMS shell is pinned to the installed release receipt
and exact Lock/Pam preimages. Normal desktop QML and user plugins do not acquire
this role. The assembly provides no unauthenticated unlock/reset IPC.

Persistent review records now select a tested tool profile. Reuse requires the
same installation, content generation, resource scope and policy revision.
Legacy generic intents remain revocable but cannot activate or launch. Fresh
owner authorization remains required for grant creation/change, without a new
challenge on every unchanged supported launch.

The initial `openssh-key-inspection/v1` profile accepts only pinned Fedora
`openssh-10.2p1-14.fc44.x86_64` `/usr/bin/ssh-keygen` generation
`bb13e6ff90ade685d2154772b6a25729e5a5a98193fdb7d6ceba53cad315a109`,
`-l -f`, and three fixed owner key paths. All streams are null. This proves
key inspection, not SSH login/signing, IDE access or general credential export.
Unsupported tools and temporary raw-access grants remain unavailable.

## Actual enforcing-kernel results on .149

| Check | Result | Scope |
|---|---|---|
| Six cross-domain process/FD/pipe/signal/entry probes; self reads | PASS | Synthetic UID 1002 subjects, not production coverage |
| Wrong password retains native lock; two successful PAM unlock cycles; unlock/reset IPC refused | PASS | Matched auth-only shell, private headless Labwc; production seat/loginctl untested |
| Two fresh GUI owner Polkit challenges in protected domain | PASS | Fixed owner-action fixture, not full production grant transaction |
| Two unchanged tool reuses; ordinary/direct-copy execution denied; access withdrawal denies next launch | PASS | Synthetic resource and root-prepared tool domain, null output |
| Password restored, owned processes/modules/action removed; SSH and main DMS/Labwc unchanged | PASS | Fixture rollback, not installed-system recovery |

Native proof command, run through PID1 to avoid inheriting the SSH controller's
immutable audit login identity:

```bash
sudo -n systemd-run --quiet --collect --wait --pipe \
  --unit=greyward-authentication-check -p RuntimeMaxSec=95 \
  -p SELinuxContext=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 \
  /usr/bin/bash /var/tmp/greyward-application-security-build/authentication-check/application-security-authentication-check.sh --native-lock
```

The root fixture uses a private `login -f` PAM/logind session (login
authentication skipped), validates its owner/cgroup, and binds its protected
agent before releasing helpers. This is a test arrangement, not a production
login recipe. Quickshell's [pinned listener implementation](https://raw.githubusercontent.com/quickshell-mirror/quickshell/v0.3.1/src/services/polkit/listener.cpp)
constructs a Unix-session agent; UID presence alone is not registration evidence.
No password is passed in arguments, environment, or collected logs. Final
native stdout is retained in `native-lock.log` in the local evidence directory.
The reported coverage remains UNKNOWN.

Source verification before the final null-stream command adjustment: runtime
117 tests passed, 21 explicit Fedora tests ignored; all-target Clippy passed.
Portable assembly tests: 3 passed. Maintenance tests: 8 passed locally, one
Linux/root test skipped (its earlier Linux receipt is separate evidence).
Repository and subsequent source-check results are recorded by the current
implementation receipt, not inferred from these earlier checks.

## Final source and Security Center product check

The shared product view uses real typed Context responses, one session coverage
summary, searchable applications, grouped resources, contextual access/history
and native structured review dialogs. EN/FR copy, existing branding, keyboard
focus/cancel and privacy-preserving technical disclosure remain in the existing
vanilla frontend. Recorded grants are explicitly distinct from live protection.
Only a denial carrying the kernel source, decision and evidence quality is
presented as blocked; an incomplete record remains unconfirmed.

Final focused source results on the same builder: **145 Rust tests passed**
(118 runtime, 27 domain), **21 explicit integration tests ignored**; fmt check
and all-target Clippy passed. **8 Context workflow tests** and **99 frontend
tests** passed. Portable authentication assembly remains three passing tests.
The new account-origin issuance/readback API writes a complete root-private
receipt without replacing an existing UID record. Its matching tests do not
establish installer handoff or automatic enrollment.

The final real Tauri window ran on the private UID-1002 headless Labwc display:
invocation `83eb22d172d346edbbe92dcf14cb25cb`, exit 0, 11.788 seconds, source
Center SHA-256 `ce01710f9292c9a45b9ed421106762f23f764390e472b5dade912165dd931cc6`.
Actual Context/facade reads, both redesigned routes, invalid-selector refusal,
shared history/export/clear and browser CSP refusal passed. No broker was active:
the real response and displayed state were **UNAVAILABLE**. No mocked bridge or
preview records were used. This fixture was unconfined and tested presentation,
not the enrollment boundary or GUI authentication/commit. Screenshots, stdout
and source logs are retained in the ignored local evidence directory as
`applications.png`, `protected-data.png`, `ui-final.log`, `runtime-final.log`
and `frontend-final.log`.

After cleanup there were no UID-1002 processes, development selector or probe
login mapping. SELinux remained Enforcing; active DMS PID 4888 and SSH remained
operational. No installed package, active session, enrollment or image changed.

## Remaining essential work

Root-owned production executable/input admission, owner-session agent binding,
installer account-origin handoff, durable label reconciliation, lifecycle
coordination, independently fresh coverage and installed recovery remain gates.
No automatic account mapping or production feature claim was enabled. Temporary
grant integration and additional useful tested tool profiles are implementation
work, not optional hardening. Historical generic-tool receipts do not validate
the current restricted contract.

DEFERRED HARDENING: exhaustive optional-provider matrices, physical seat/suspend,
broad performance/reproducibility and independent audit. These do not substitute
for the essential admission, deny/allow/revoke and recovery evidence.
