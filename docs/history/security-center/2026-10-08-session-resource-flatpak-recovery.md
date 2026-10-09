# Protected resource / Flatpak recovery — 8 October 2026

Scoped development repair on normal `.149`; not release lifecycle acceptance.
The prior login receipt proved seat startup, not full resource or browser use.

## Confirmed causes

1. The registered SSH directory journal recorded Btrfs device number 53. After
   reboot the same inode and protected label were on device number 52. Mount-time
   `st_dev` is not a persistent Btrfs filesystem identity. The broker correctly
   withheld effective protection when its old object receipt failed readback.
2. The confined Flatpak compatibility policy covered simple runtime execution
   but missed Chromium/Zypak's portal child-spawn path. The portal could not
   inspect the app's descendant user namespace; subsequent bubblewrap setup
   lacked descendant DAC permission and access to namespace handles. Failed
   Brave instances accumulated without a usable browser window.
3. Public-IP lookup had a separate availability problem: ipapi.co returned 429;
   a prior fallback transport failure caused a 30-minute cooldown even after
   connectivity recovered. Local and Flatpak HTTPS tests succeeded. Secure DNS
   reported active encrypted DoT; the unavailable IP label was not proof of a
   broken host connection.

## Corrections and boundaries

New registration journals bind kernel filesystem type/ID in addition to inode,
owner and root-only protected label. Reopening permits a changed mount device
number only with that matching filesystem identity; live descriptor/tree checks
remain mandatory. Legacy journals retain strict device checking. The existing
`.149` SSH receipt was separately migrated by root after checking the same root
inode/owner, every original object, bounded current tree and exact labels.
No resources were relabeled, grants created or policy revisions changed.
An older binary cannot interpret the additive journal field: restore the backed-up
database together with runtime 27 for rollback, never silently downgrade storage.

The canonical session policy adds only descendant `cap_userns` sys_ptrace and
dac_override plus namespace-handle open/read/getattr. No host capability is
added. Protected-resource and authentication/grant-domain denials remain in
force. The temporary candidate module was removed after installing the canonical
compiled session module. SELinux remains enforcing; no authentication changes.

Public-IP fallback distinguishes rate limiting from transient failures. Three
bounded retries at 35/70/140 seconds recover transport/5xx failures; HTTP 429
retains the provider cooldown. Opt-out stops retries and invalidates callbacks.
No address is persisted or fabricated. The installed development plugin and
selected root-owned `firstPartyFiles` digest were updated together.

## Evidence

- Normal broker coverage returns effective PROTECTED, AVAILABLE, all coverage
  fields true and policy revision 6. Inventory health remains UNKNOWN; resource
  coverage is not used to invent inventory certainty.
- Root seat verifier returns `verified: true`; normal DMS and Context are active.
- Actual VMConnect shows Brave using the existing profile and loading an HTTPS
  page. The taskbar shows the provider-returned public IP and separate local IP.
- Actual Applications view shows Your registered data is protected, replacing
  Session protection is incomplete. Both repository gates pass.
- Native directory read and Flatpak protected-file read are denied; ordinary
  HTTPS returns 200. Parent namespace sysctl write-open is denied.
- Focused Rust suite: 57 pass, five explicitly ignored privileged fixtures;
  stable filesystem/device and mismatched filesystem tests pass. Clippy for
  the runtime library passes with warnings denied using the Fedora driver.
- Runtime 28 package build runs application-security, domain and backend tests.
  Center 85 / Context 76 are retained. SSH remains available; no new reboot,
  session logout or permissive fallback was used for this repair.

One post-install HTTPS sample timed out; immediate DNS/HTTPS and repeat checks
recovered with encrypted DNS still active. These samples establish current
connectivity, not a claim of uninterrupted provider/network availability.

## Recovery and remaining gates

Root-only `/var/lib/greyward-development/application-security-live/session-repair-20261008/`
retains the pre-migration SQLite snapshot, runtime 27 RPM, active receipt and
public-IP plugin/selected DMS receipt. Restore matched old storage/runtime and
matched plugin/receipt during an authenticated recovery operation.

Repeated reboot verification, additional browsers/deputies, production lifecycle,
physical-seat and broad compatibility testing remain DEFERRED HARDENING. This
repair does not promote the development tuple into an ISO or claim those gates.
