# Installer enrollment candidate

This package reuses the existing broker, SELinux modules, protected Labwc patches,
authentication assembler and Administration worker. It adds no permission daemon
or generic Flatpak grant mechanism. It is a **test candidate**, not production
acceptance. The development host must not install or activate it for ISO assembly.

The offline builder consumes the original pinned compositor archive and applies
the two existing patches. Six existing policy modules are compiled; the private
compositor and its source/digest receipt are RPM-owned. Package installation has
no mapping, service-start or policy-loading scriptlets.

Revision-3 clean-install acceptance failed: installer-origin storage was missing.
Revision-4 source creates strict root-owned private broker and origin storage before broker calls,
checkpoints prepared inputs and retains failure diagnostics. Changed inputs or
partially applied mappings refuse continuation. The bounded r3 recovery helper
is test evidence only; its locally patched installation does not establish
revision-4 package or image acceptance.

R6's 0.3.5 first-boot receipt was observed at phase `PREPARING`. The later
retries failed with `Installation transaction incomplete` because the coordinator
only resumed `PREPARED_INPUTS`; the original exception that first left the receipt
in `PREPARING` was not captured. Revision 19 safely retries this stage only when
the installer account identities and original SELinux mappings still match, the
origin directory is empty, and every generated partial tree is root-owned and
non-writable by group/other. It rebuilds those fixed trees from packaged inputs,
reuses only exact existing SELinux user definitions, and preserves the original
policy export. Changed mappings, unexpected origin state, or unsafe partial files
still fail closed. This repairs the permanent retry dead end; clean-install
acceptance is still required to identify any separate first-attempt failure.
The RPM builder also stages a private copy and runs the repository's Linux text
normalizer before compiling SELinux policy, so Windows checkout line endings do
not change the policy meaning or break package construction.

Anaconda records only its normal local accounts after account creation. The
existing first-boot gate installs the matched packages, prepares policy and the
ordinary-role closure, assembles authentication from verified DMS selection,
prepares root-issued installer enrollment, and maps those accounts before opening
login. Existing accounts require deliberate migration. Missing or changed inputs
leave login gated; stored enrollment never establishes PROTECTED coverage.

The ordinary-role generator retains the reviewed USB approval client in the
role inventory but excludes it from `greyward_as_ordinary`, alongside the
protected display domain. Its exact executable/context/session admission is
checked separately by the unchanged live verifier. R6's fresh installation
previously included the helper in ordinary coverage and therefore failed that
check; the migrated `<validation-host>` reference did not exercise the same generation path.
Generated CIL/JSON regression tests cover both cases. ISO staging checks the
generator and verifier inside the selected RPM even on an installed-RPM import;
the existing AppSec 69 RPM must be rebuilt in a matched candidate before the
next image can contain this fix. Repairing an existing installation requires
an offline policy/receipt migration, not editing the inventory alone.

On retry, a `PENDING_SESSION` receipt is validated before the quiescence check.
That phase only reads back the prepared enrollment, so a normal user process
must not strand first boot after a previous attempt completed the mapping.
`PREPARING` and `PREPARED_INPUTS` retain the quiescence requirement because they
can still assemble policy or activate account mappings. The receipt does not
replace live graphical-session coverage verification.

20 October source/media verification: the helper extracted from candidate
0.4.4's Enrollment 60 RPM still checks quiescence first. Its RPM SHA-256 is
`79562e1872292f401e5fc2f154a3c8ca73c33296edce1b73b9c2b7ebca1a1980`.
The pending-session regression fails against those actual packaged bytes and
passes with the source correction. All 23 installer-enrollment tests pass in
an isolated Linux/Python 3.12 environment, including invalid mapping, account,
input digest, schema, enforcement and service readbacks. This is a source
validation result, not Fedora SELinux enforcement or installed acceptance.
The candidate's first-boot, provisioner, zsh configurator and acceptance scripts
match current production source after line-ending normalization. No new RPM
or ISO contains the retry correction. R6's protected transaction phase and
seat-verifier failure remain unobserved; the retry defect must not be presented
as their established cause. See [current status](../../docs/STATUS.md).

21 October follow-up: R6's offline readback confirms `PENDING_SESSION`, all
three enrollment-input digests, 1,014 protected desktop files, matching local
account/origin records and the configured login mapping. Its setup log reaches
final checks three times without committing completion. The first-boot
readiness predicate incorrectly requires `dms-greeter`: the pinned 1.6.2
[launcher](https://raw.githubusercontent.com/AvengeMedia/dank-greeter/v1.6.2/core/internal/launcher/logging.go) replaces itself with Labwc and starts Quickshell. Source now checks
the greeter's compositor plus UI, and accepts an already logged-in desktop
only through the existing root seat verifier. Six Linux shell-boundary tests
pass. This does not establish that R6's protected-seat degradation is fixed.
The same AppSec/Enrollment/DMS/Session versions on `<validation-host>` verify successfully
in the broker's SELinux context in about 0.6 seconds. R6's subsequent rescue
hot patch reached the desktop, but its live verifier rejected the ordinary
role closure. A second approved offline migration corrected only the helper's
attribute membership and dependent receipts, with file/store backups and
without remapping accounts or changing the broker journal. After normal
reboot/login, six live verifier readbacks pass, SELinux is Enforcing, and the
user confirms that the authenticated Administration console opens.
No new ISO has been validated; see [current status](../../docs/STATUS.md).

For an already enrolled development system, the explicit protected DMS migration
refreshes the root-owned authentication profile and session worker from the
matched Application Security RPM. The session worker must use the private
`wayland-0` alias when DMS runs with a private `XDG_RUNTIME_DIR`; an absolute
socket path is joined to that directory and cannot reach the compositor. The
migration verifies the existing desktop and Administration receipts, records
both updated inputs in those receipts, and refuses while the local graphical
seat is active. Run it only after logging out; each replacement has rollback
data until final receipt verification succeeds.

When only the protected-seat verifier changes, run
`greyward-migrate-protected-dms-shell --refresh-verifier-only` after logging out.
This uses the same root-owned source and quiescent checks, updates only
`verify.py` plus the desktop and Administration integrity receipts, and restores
all three from the prior receipt if final verification fails.

SELinux Enforcing, protected authentication, Administration approval, terminal-
scoped sudo authentication and ordinary sensitive-resource denials remain required.
Source runtime 34 retains explicit missing deputy/portal coverage; generic IDE,
SSH signing and writable Flatpak sensitive-resource grants remain unavailable.

Authenticated offline entry is selected explicitly with
`systemd.unit=greyward-maintenance.target` at boot. The existing console requires
fresh LUKS authentication and a quiescent foreground physical console. It provides
the clean root shell for repair. `greyward-enrollment rollback-initial` restores
only this fresh installation's account mappings; it refuses once registered
resources/grants exist and retains policy types and evidence. Later resource,
grant, upgrade and account-management migration remain unfinished; do not claim
that initial rollback implements those workflows. There is no recovery account,
normal-session repair endpoint or permissive fallback.

Required manual candidate acceptance on the **separate installed test VM**:

- Native installer branding, interactive account/encryption and first boot work.
- New account reaches the protected Labwc/DMS seat; Center shows real coverage.
- Administration authenticates; ordinary synthetic protected-file reads fail.
- Native applications and ordinary Flatpak/portal workflows still work.
- Offline encrypted maintenance and fresh-install rollback work without disabling
  SELinux. The build host is never rebooted to perform these tests.

Compilation, source tests and private policy linking are package evidence only.
No clean-install, graphical authentication or recovery pass may be inferred.
