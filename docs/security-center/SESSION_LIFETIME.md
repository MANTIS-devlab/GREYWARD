# Protected desktop lifetime

The canonical implementation is
`security-center/packaging/application-security/desktop/session.py`.
The existing workflow broker validates the caller's kernel execution identity,
ordinary confined role, enrolled account and real local greetd PAM seat. This
contract does not introduce another admission route, privileged user interface
or an unconfined fallback.

## Admission and supervision

Admission already holds the validated owner's pidfd. It now passes that exact
handle to the guardian rather than reopening /proc ownership after a possible
exec. The guardian joins the root-controlled, nondelegated logind seat scope,
checks its actual kernel cgroup, initializes its process/authentication watch
and acknowledges readiness over a private pipe. The parent waits at most three
seconds and verifies the live guardian's pidfd and exact scope before reporting
ADMITTED. Failed or missing acknowledgement fails admission.

This ordering matters because PID 1 collects children left in the short-lived
admission service when its main process exits. The former parent returned
without waiting for its forked guardian to migrate; scheduling could leave
protected workers alive without a supervisor. A missing guardian was observed
in the 29 October incident; the precise historical child exit was not logged.
The old ordering's race is reproduced in an isolated native PID 1 fixture and
is removed by the acknowledgement protocol.

The guardian still watches owner/display/authentication pidfds plus the fixed
protected authentication heartbeat. Existing readiness freshness, SELinux,
PAM and role checks are unchanged. Owner/input loss closes the exact seat via
logind/PID 1. Initialization errors and console-label restoration errors cannot
skip that scope-stop request. The generation-bound seat locator remains until
the next admission confirms that its old owner and workers have disappeared;
it is not discarded while old protected workers could still be running.

## Scoped update and recovery

Application Security 85 carries the worker. Enrollment 87 requires that matched
runtime and adds the existing root-only migrator's `--refresh-session-only`
mode. It refreshes only session.py, the desktop integrity receipt and its
Administration cross-reference, using the existing immutable input validation,
file lock, atomic label-preserving writes, verification and rollback. It does
not reload the DMS shell, update authentication UI or load SELinux policy.
Verifier-only mode remains available and unchanged by default.

Migration still refuses a real local graphical session and scans for surviving
protected processes. A logind closing locator alone is not a running desktop:
it is ignored only with an absent original leader, absent exact kernel cgroup
and an inactive PID 1 scope. Missing or conflicting evidence still refuses.
This allows recovery without restarting logind or terminating the user manager.

Abandoned old seats require generation/boot/UID/context/scope-verified root
maintenance before refreshing the profile. Do not blindly delete a seat file,
kill all user processes or clear Wayland sockets while a display is listening.
Keep matched prior RPMs and the previous immutable receipts for rollback.

## Validation boundary

29 October recovery and native regression evidence (private development evidence)
records the installed package tuple, isolated native lifecycle proof and the
remaining interactive login boundary. The source tests are in
`tests/test_application_desktop.py`, `tests/test_dms_shell_migration.py` and
`tests/test_session_admission_route.py`. Use both repository gates as well.
No ISO or publication is implied by local package/profile activation.
