# Manual screenshots

Status: candidate implementation; installed/physical acceptance is recorded in
[current status](../STATUS.md). The published RC3 does not contain this change.

Press **Print Screen** on the unlocked desktop, then drag a rectangle with the
mouse. Click a screen to capture that complete screen, or press **Esc** to cancel.
The previews show a frozen snapshot from the key press. Only the selected pixels
are saved in the user's Pictures/Screenshots directory, then opened in Swappy
for annotation, saving edits and copying. No password or Polkit prompt is
required. Cancellation creates no saved image. The selected original remains
saved if the editor is closed or fails. The Screenshot launcher explains the
physical shortcut; window picking and continuous screen sharing are not
implemented.

GNOME Screenshot 41 depends on GNOME Shell's screenshot service, absent in
Labwc; its X11 fallback fails on this Wayland desktop. Installing another
portal-dependent application alone does not fix it: GREYWARD intentionally
hides ordinary capture protocols from both apps and the WLR portal.

## Authority and boundaries

`labwc-screenshot.patch` reserves physical Print input in the protected
compositor. It creates one private socketpair/client and gives FD 3 to the fixed
ordinary receiver. Only that exact server-owned client sees `wl_shm`,
`wl_output`, `zxdg_output_manager_v1` and `zwlr_screencopy_manager_v1`.
The private-client check precedes SID-based privileges because the socketpair
originates in the display domain. The child must never inherit that domain's
input, lock, clipboard or other globals. A command argument, app ID or a public
Wayland connection cannot create this grant.

The channel expires three seconds after creation. A repeated key is ignored
while it exists. A native lock request destroys clients and their in-flight
frames before protected surfaces can render. Abandoned locks stay blocked.
After unlock, every enabled output must commit a fresh ordinary pixel buffer
before another capture can start; an unlocked flag or a mode-only commit is
insufficient. New output topology revokes existing channels as well.

The receiver checks the kernel socket peer, invokes fixed Grim on that inherited
FD, accepts only a bounded complete PNG and closes the channel before decoding
or displaying an ordinary selection UI. GTK layer-shell previews show the
frozen image on each output; Slurp handles mouse selection on a separate public
Wayland connection. The full image has no saved pathname: it is privately
spooled to an unlinked temporary file, decoded in ordinary memory, then closed.
Only the cropped selection is saved with mode 0600. No new capture global,
input permission or longer capture deadline is needed to let the user select
an area. The narrow display socket read/write/getattr/getopt
permission supports the returned FD; it grants no auth socket, process access,
host input, additional home access or ordinary capture global. SELinux stays
enforcing. No privileged screenshot service, new role exception or auth-domain
expansion is introduced.

Selection coordinates use the global logical output layout, including negative
origins and mixed scales; the PNG retains Grim's composited resolution. Output
metadata is checked before/after capture and before saving. Display changes
cancel selection instead of saving a rectangle against stale geometry. Selection
times out after 90 seconds; a user-runtime lock prevents repeated key presses
from opening multiple selectors. The lock and full snapshot are released before
the editor runs. Native lock surfaces still cover ordinary preview windows;
no capture connection is retained during selection.

Python's inherited-socket constructor inspects the socket address/type before
wrapping the FD; `getattr` is descriptor metadata, not process inspection.
See the [upstream constructor](https://github.com/python/cpython/blob/v3.14.0/Modules/socketmodule.c#L5312-L5347).

This is a bounded manual disclosure, not isolation between all ordinary native
apps: a same-user process able to steal the receiver's FD could use the
remaining three-second window on ordinary frames. It still receives only the
limited globals and is cut off by the same deadline/lock boundary. Saved images
are ordinary user data; the user controls their later sharing.

## Packaging, migration and verification

Session 36 owns the receiver/launcher and requires Grim, Swappy, Slurp,
GTK layer-shell and Pycairo. It updates only the ordinary receiver and launcher
from Session 35 and can be installed without restarting the desktop. Enrollment
83 source builds the matched compositor and display policy, records the screenshot
patch digest, and provides the explicit root-only `greyward-migrate-screenshot`
command. It requires a stopped login service and a quiescent desktop, verifies
the package/active receipts, extracts the old policy, updates the private
compositor and linked Administration digest, and restores them on failure.
Account mappings and protected authentication files are preserved. The normal
DMS shell migration remains separate. Both operations require an approved
session interruption on an active installation.

Enrollment 83 adds recovery of an orphaned protected `/dev/tty1` label during
this quiescent migration. It requires greetd stopped, no enrolled-account
sessions/processes, no seat receipt and no protected display/authentication
workers. Only the expected root-owned VT character device and its canonical
`tty_device_t` label are accepted. An active seat, unknown label/device or
unreadable process state refuses recovery. Ordinary access to the protected
console remains denied. Enrollment 83 is now built with normal checks and is
embedded in the local [0.5.1 Sophon image](../patch-notes/0.5.1-sophon.md).
The physical reference still uses Enrollment 82; the new migration has not been
activated there, and Sophon fresh-install acceptance remains open.

Activation must preserve the enrolled broker mode: use
`greyward-application-security-workflows.service` and verify its D-Bus interface
contains `StartDesktop` before reopening greetd. The experimental read service
conflicts with it and lacks session admission; do not restart both units as a
group. Installed executable hashes and kernel permission checks alone do not
verify this service-mode invariant or prove a usable login. The read-only
`tools/greyward-dev/desktop-compatibility-kernel-check.py` now checks the service
mode, command line, live bus-owner PID and admission method before its 947 kernel
decisions. `tests/test_desktop_broker_readback.py` covers the read-only broker
regression and rejects mismatched/changed owners or missing methods.

Complete image staging rejects stale receiver, launcher, migration, policy,
patch and compositor-source receipts, including installed-RPM imports. A live
hotfix is never treated as proof that an older RPM contains the correction.

`tests/test_screenshot_boundary.py` tests receiver rejection and, with
`GREYWARD_LABWC_SOURCE` set to the pinned canonical archive on Fedora as root,
builds a disposable headless compositor. Fixture-only input/peer adapters exercise
two-output PNG capture, ordinary denial, the restricted registry, retained
bindings, deadline, native session-lock revocation and a frozen stale frame
across unlock. Those adapters are absent from the production patch. Mounts are
confined to the fixture's mount namespace; no host policy or desktop is changed.
`tests/test_screenshot_migration.py` tests receipt integrity, and
`tests/test_flatpak_session_compatibility.py` compiles the display policy.
`tests/test_screenshot_region.py` verifies coordinate mapping, cancellation,
descriptor closure before decoding and real cropped PNG output/permissions.
The unprivileged `tests/fixtures/screenshot-region-headless.py` launches a
separate headless display with synthetic pixels/input. It exercises cross-output
dragging, mixed DPI, whole-screen click, cancellation and output removal with the
real GTK/Slurp UI. Run it on Fedora with
`GREYWARD_REGION_HEADLESS_TEST=1 python3 tests/fixtures/screenshot-region-headless.py`.
It never connects its synthetic pointer to the user's display.
Hardware acceptance separately requires the physical key, saved PNG readback,
editor confirmation, ordinary denial and protected-screen denial.

On 24 October the matched Session 35 / Enrollment 82 / AppSec 83 packages were
activated on the physical reference after an approved session closure. Package
verification, the protected compositor/source receipts and all 947 kernel
permission checks passed with SELinux Enforcing. USB rules and the DMS selector
were unchanged. The active broker executable matches the installed package.
The first physical login attempt failed: forced logout left the console label
protected, and the activation controller selected the conflicting read-only
broker. The orphaned console label was restored after proving no protected seat
remained, then the enabled workflow service was explicitly started. Its live
interface now exposes `StartDesktop` and the read-only service is inactive.
The user subsequently confirmed successful login and physical Print Screen
opening Swappy without Polkit. Readback verified the original 5,560 x 1,920 PNG
with mode 0600, a saved edited PNG and ordinary-domain Swappy. A real confined
user-manager Grim invocation is still denied the public capture protocol and
produces no PNG. The fresh seat projects Protected/INFO, the extended
broker/kernel checker passes, and SELinux remains Enforcing. The published
RC3 installer predates this change. Local Sophon composition includes the
matched successor and is recorded separately from installed acceptance.

The user subsequently reports completing the locked-screen Print test and
unlocking normally. That is user-reported physical evidence; the original file
baseline was not a time-correlated lock trace. Session 36 area selection is now
installed with byte-matched RPM/source payloads. Its six native unit tests and
all five headless selector cases pass. Protected manifests, USB rules, DMS
selector and workflow-broker PID stayed unchanged during installation. On
25 October the user confirmed correct mouse-region output in Swappy without
Polkit and successful Esc cancellation. Direct readback found new saved PNGs
with mode 0600 and clean installed Session 36 package verification. The Esc
gesture itself is user-reported acceptance, supported by native cancellation
tests rather than a time-correlated physical file trace.
