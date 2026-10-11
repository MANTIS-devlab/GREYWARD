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

Anaconda records only its normal local accounts after account creation. The
existing first-boot gate installs the matched packages, prepares policy and the
ordinary-role closure, assembles authentication from verified DMS selection,
prepares root-issued installer enrollment, and maps those accounts before opening
login. Existing accounts require deliberate migration. Missing or changed inputs
leave login gated; stored enrollment never establishes PROTECTED coverage.

For an already enrolled development system, the explicit protected DMS migration
refreshes the root-owned authentication profile and session worker from the
matched Application Security RPM. The session worker must use the private
`wayland-0` alias when DMS runs with a private `XDG_RUNTIME_DIR`; an absolute
socket path is joined to that directory and cannot reach the compositor. The
migration verifies the existing desktop and Administration receipts, records
both updated inputs in those receipts, and refuses while the local graphical
seat is active. Run it only after logging out; each replacement has rollback
data until final receipt verification succeeds.

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
