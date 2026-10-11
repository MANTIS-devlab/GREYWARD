# Enrolled login routing recovery — 10 October 2026

Status: installed routing repaired; user-authenticated graphical login acceptance
is pending. This is a development-machine recovery, not ISO acceptance.

## Cause and correction

Greetd accepted the enrolled user's password and opened the PAM session, but
UWSM launched `/usr/bin/labwc` in `greyward_guard_t`. Logind could not hand over
`/dev/input/event0` or `event1`; libinput reported no devices and the compositor
exited, returning to greetd. These input denials are intentional protections.

The installed session-8 desktop entry and launcher matched the RPM defaults.
Its installation timestamp was 9 October 12:04 CEST; the entry selected ordinary
UWSM/Labwc instead of the existing protected `desktop/login.py` route. The
previous development-only entry override was not preserved by package ownership.
The preceding DMS build did not deploy a runtime or change session routing.

`environment/production/greyward-start-labwc` now routes subjects whose SELinux
user is `greyward_guard_u` through the existing isolated Python login selector.
That selector detaches console descriptors and calls broker-controlled desktop
admission. Missing or failed protected admission has no ordinary fallback.
Unenrolled subjects retain the existing renderer/UWSM behavior. No account is
enrolled automatically and no policy/device permission is relaxed.

Session **0.1.0-9** was built and installed on the development machine with
successful RPM transaction preflight and clean post-install `rpm -V`.
SHA-256: `2252c1657661033a275248e3f40870f3b4e54bb659e7eef05b66946cf7f9dc68`.
The canonical desktop entry again uses the package launcher, so future package
installation retains the route rather than overwriting a local entry override.

## Evidence and recovery

- Fedora login-descriptor tests: four passed.
- Fedora shell admission tests: three passed, covering enrolled routing,
  unenrolled routing and failure without fallback. These do not prove a live seat.
- SELinux remains Enforcing. Greetd and SSH remain running; no reboot, logout,
  service restart, PAM change, mapping change or new grant was performed.
- The original launcher and desktop entry are retained in the root-only
  `/var/lib/greyward/recovery/login-20261010/` directory. Session-8 artifacts are
  preserved alongside session 9. Rolling back to session 8 alone reintroduces
  the routing bug; preserve protected routing for any enrolled account.
- A real login retry was requested. Until it succeeds, restored normal desktop,
  protected authentication and compositor process evidence remain **NOT RUN**.

The existing build disk was remounted after the observed new boot to run bounded
tests and build the small session RPM. This recovery issued no boot operation.
Production package closure, encrypted rescue acceptance and ISO gates remain
separate unresolved work.
