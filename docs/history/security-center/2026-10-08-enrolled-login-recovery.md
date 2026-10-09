# Enrolled graphical login recovery — 8 October 2026

Development evidence from normal `.149`; not production lifecycle acceptance.

## Cause and correction

After boot, greetd authenticated `development-user` but the GREYWARD session exited.
The protected-seat broker relabels the console before ordinary UWSM startup.
The login process retained console standard descriptors, producing denied
ordinary-domain writes/ioctls against the protected authentication terminal.

The canonical `desktop/login.py` now detaches those descriptors before broker
admission without changing its PID or greetd parent. Input is `/dev/null`;
output/errors go to owner-only `/run/user/<uid>/greyward-desktop-start.log`.
Symlink runtimes/logs and multiply linked logs are rejected before truncation.
SELinux policy, account mapping, PAM and native DMS locking remain unchanged.

Successful session startup exposed a separate shell failure: the audited
`greywardSecure/SecureWidget.qml` development overlay had been deployed without
updating `firstPartyFiles` in the selected root-owned DMS receipt. Verification
correctly refused it. Only that receipt entry was updated, after comparing the
installed root-owned file against canonical source SHA-256
`73ada5155e8477ae66132cf86031975aad2e963d7cd383fac65fafa98dfdcf2c`.
Integrity verification remains enabled. Development overlays must update their
matched receipt atomically; a running shell alone does not validate next startup.

## Evidence

- Actual greetd password login selected GREYWARD (Labwc), UID 1001.
- UWSM desktop proxy active; root protected-seat verifier: `verified: true`.
- DMS service active after the receipt correction; actual VMConnect console
  shows GREYWARD wallpaper, complete bottom taskbar and desktop controls.
- SSH recovery remains usable; no reboot or enrollment rollback performed.
- Four Fedora descriptor tests pass: real stdin/stdout/stderr detachment,
  private log permissions, symlink rejection and hardlink rejection before
  truncation. The final source wrapper is installed for subsequent logins.

The greeter also offered GNOME and Hyprland; an earlier attempt selected
Hyprland. This recovery validates GREYWARD (Labwc), not those other sessions.
Repeated logout/login, another reboot and production image lifecycle are not
claimed by this receipt; the working desktop was left running.

## Recovery files

Root-only `/var/lib/greyward-development/application-security-live/login-recovery-20261008/`
contains `login-before.py` and `release-before.json`. These permit scoped
restoration of the wrapper/receipt; restoring the old receipt while retaining
the newer plugin intentionally fails verification. Preserve a matched plugin
and receipt when rolling back. No policy or account-mapping restoration is
required for this fix.
