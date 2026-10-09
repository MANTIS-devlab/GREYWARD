# Practical administration — scoped development evidence

Historical implementation record, 9 October 2026. Current authority:
[Application Security enrollment](../../security-center/APPLICATION_SECURITY_ENROLLMENT.md).
Normal-seat activation/acceptance is still IN PROGRESS. This record does not
establish production or authenticated rescue-boot acceptance.

## Source and installed inputs

Preserved the pre-existing working tree (458 entries at the initial inventory).
No reset, commit, reboot, ISO change, authentication rewrite or ordinary-role
administrator admission. Installed Center 88 / Context 81 / experimental runtime
30 on Fedora 44. SELinux remains enforcing; `development-user` retains
`greyward_guard_u:greyward_guard_r:greyward_guard_t:s0`.

Root-private rollback directory:
`/var/lib/greyward-development/application-security-live/administration-20261009/before`.
It retains runtime 28 / Center 87 / Context 80 RPMs, the matched old desktop
closure, sudo configuration, unit configuration and mapping/package receipts.
Candidate compositor and Administration closures are staged separately.
The disposable test account and its random password/sudo configuration were
removed after the tests; no recovery account was created.
The compositor pin is
`bd5f5ddec12c066e0893a0a4874cbc5d55e157d5b93d3ebe6cd2bdc7b863ba64`.

The new terminal is package-built C/Wayland/Cairo/Pango/libvterm, without a shell
string API, ordinary IO channel or clipboard. Root admission validates account,
peer PID/start time, local seat, coverage and immutable generations. A private
devpts instance isolates tty timestamps and terminal descriptors. Fedora real
sudo/PAM supplies authentication and the confined sysadm transition. The backend
accepts bounded argv proposals; Security Center only opens the fixed `-i`
operation and reads status. Native DMS retains lock/authentication ownership.

## Validation actually run

| Check | Result and evidence |
|---|---|
| Real native PAM and root role | PASS, separate UID 1003; actual `id -u` = 0, sysadm role/domain, synthetic protected-file read. No real credential contents read. |
| Wrong password | PASS, `greyward-admin-wrong-password` root/private-mount unit; refusal and no root command. |
| Invalidated initial PAM | PASS, `greyward-admin-interrupted-pam`: valid fixture password cannot execute the proposal after ticket invalidation during authentication. |
| Stale proposal | PASS, real 121-second graphical review wait then Enter; no PAM/command child starts (`greyward-admin-expired-review`). |
| Cache/lifetime | PASS, `greyward-admin-cache-check4`, 09:50:17–09:52:22: cache reuse, `sudo -k` denial, renewal, 125-second elevated command completes, subsequent `sudo -n` denied. |
| Ordinary separation | PASS, `greyward-admin-negative-kernel`: 372 current-kernel negative process/PTY/runtime decisions across the entire prepared ordinary closure; pre-PAM protected-file read denied. |
| Graphical terminal | PASS, separate-account private-display check 22: review and compositor identification visually inspected, real masked PAM/root shell, pause/resume, End session button and key repeat. Supporting fixture, not normal-desktop acceptance. |
| Ordinary resource/sudo | PASS on real enrolled SSH shell: synthetic protected-file read denied; direct `/usr/bin/sudo -V` denied. |
| Flatpak metadata | PASS, actual Bazaar exported service metadata readable after bounded public-metadata labeling; no broad `var_lib_t` read added. Actual normal launch still pending. |
| Metadata updates | PASS, runtime 30 root path/oneshot repairs a recreated `var_lib_t` label after the real installation change marker; original-label journal remains unique and intact. Two root fixture tests cover replacement, idempotence and private alias rejection. |
| USB projection | PASS, actual fixed broker read returns provider device list (empty on this VM). No ordinary USBGuard management permission. |
| Ordinary coverage | PASS after installed package update/build completion, trusted PID-1 verifier: `{"verified":true}`. Root SSH inspection is not the trusted coverage provider. |
| Package checks | PASS, native compiler `-Wall -Wextra -Werror`, RPM runtime domain/backend tests and Center workspace tests; final matched package inputs rebuilt. |
| Focused tests | PASS: administration 5 (including inherited-descriptor isolation), frontend UX 93, Context full suite 326; runtime Clippy all-targets with warnings denied; both repository gates pass. |

The first full Context run failed because its terminal-brief fixture was absent
from the staged source; including that existing source made all 326 pass. The
Center staging archive initially omitted its third-party notices; the corrected
RPM contains them. Failed staging rejected writable source-directory modes
before touching the active runtime; copied immutable staging modes corrected it.
The protected graphical test exposed private PTY and readonly compositor keymap
label requirements; only those dedicated types were permitted. Descriptor
handoff was corrected so closed destination descriptors are prepared in the
child, with inherited root descriptors closed before dropping privileges.

Disk inspection found 39 GiB of compiler cache. This pass deletes no user,
recovery, system or development data. It repairs old root-owned entries only
inside the dedicated compiler cache so nonroot package builds work. The encrypted
62 GiB root has about 1.3 GiB free at this record; further large builds need
separately reviewed cache cleanup or disk expansion.

## Pending mandatory acceptance

Normal-seat logout/login, actual command handoff and Center status, protected
input/lock handoff on that seat, normal Flatpak/Brave and focused Update Center
regression, grant reuse/revocation and actual matched-closure rollback rehearsal
remain unpassed. No normal desktop was stopped without the user's session-boundary
decision. Fresh authentication is not inferred from a mock or a successful read.

## Recovery and limitations

Keep root SSH throughout development activation. End Administration first,
invalidate its tickets, end the affected seat, restore the matched desktop and
package tuple, and restart the normal login. Remove only the development sudo
adapter/configuration owned by this activation. Preserve the ordinary mapping,
resource labels and policy/grant state. Restore public Flatpak metadata labels
only for objects whose recorded device/inode still match, before removing its
type module. Never blanket-relabel home or remove policy under live privileged
workloads. Production offline LUKS-based repair boot is still unvalidated.

Protected SSH administration, generic IDE/SSH/GPG grants, ordinary USB mutations
not already supported, removing harmless denied native-auth backend probes, and broad
performance/physical/compatibility/adversarial matrices are DEFERRED HARDENING.
Mandatory normal-seat isolation, truthful coverage and recoverable rollback are
not deferred.
