# Application Security development fixtures

Current source and validation authority:
[Application Security plan](../../docs/security-center/APPLICATION_SECURITY_PLAN.md).
[Production enrollment design](../../docs/security-center/APPLICATION_SECURITY_ENROLLMENT.md)
is PLANNED. Policy in this directory is a development fixture, not an installable
production account/session policy. Do not copy synthetic owner-role allowances,
UID-1002 paths or test root permissions into installed policy.

`selinux/greyward_session_bus_boundary.cil` is a reversible, explicitly installed
development inspection correction for the existing user/a11y bus type. The
kernel/compatibility/native-review fixtures in `tools/greyward-dev/` and
[scoped receipt](../../docs/history/security-center/2026-10-09-dbus-boundary-proof.md)
verify its limited behavior and rollback. It adds no allow, grant, portal or
production enrollment. Request-to-Flatpak recipient association remains absent.

The bounded hybrid Flatpak bootstrap adds a disposable subject/code/state
template in `selinux/greyward_hybrid_flatpak_probe.te`. It is not installed
product policy or a grant. Its root harness and normal-account bus check are
`tools/greyward-dev/application-security-hybrid-bootstrap.py` and
`tools/greyward-dev/application-security-hybrid-bus-check.py`. The
[9 October receipt](../../docs/history/security-center/2026-10-09-hybrid-flatpak-bootstrap.md)
records the blocked IPC trust prerequisite and removed test modules. Do not
continue into a portal bridge or describe the bootstrap as either product gate.

The latest combined source workflow is
`tools/greyward-dev/application-security-registration-guard.sh --workflow`.
It owns the separate synthetic account, labels/journal, private modules/units
and restores password/mapping/labels plus the development selector. It does
not enroll the active development user or restart DMS/SSH. The 7 October
receipt has five fresh owner authentications, actual concurrent READ grant/
revocation, ordinary/direct bypass denial, shared Safe Open, ELF/script/
AppImage/private graphical isolation and private GUI review/cancel. Exact
invocation/hashes and limits are in the current plan; this is not a fresh
production greetd/package test.

Older `--end-to-end` and standalone bubblewrap-only Safe Open recipes belong
to [historical experiments](../../docs/history/security-center/2026-10-07-application-security-spikes.md).
The current Safe Open shares the broker runner, refusing unsupported Flatpak
handlers and protected-label copying with no unrestricted fallback.

The selected first-run work remains functional source integration. Exhaustive
optional portal/deputy, performance, hardware and release matrices are DEFERRED
HARDENING. Production enrollment implementation is not authorized by these
recipes. Preserve the active desktop and independent recovery access; never
reboot/lock the user's session or mutate an installer VM to repeat a fixture.
