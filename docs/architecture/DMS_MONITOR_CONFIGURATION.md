# DMS monitor configuration on protected Labwc

## Resolved diagnosis — 10 October 2026

The latest screenshot still shows “WLR output management protocol not
supported.” Read-only inspection of `.149` found SELinux Enforcing, the
protected DMS v1.6.2-13 shell, and two DMS instances: the protected shell in its
private authentication runtime and the ordinary `greyward-dms.service` under
the systemd user manager.

The ordinary service's startup log reports that it tries to connect to
`/run/user/1001//run/user/1001/wayland-0`. Its runtime directory is already
`/run/user/1001`, but GREYWARD's session launcher sets `WAYLAND_DISPLAY` to the
absolute path `/run/user/1001/wayland-0` when starting and finalizing UWSM.
DMS joins those two values, producing an invalid socket path before a Wayland
connection is attempted. This is an environment/path bug, not an SELinux denial
or a missing compositor protocol.

The fix pins `WAYLAND_DISPLAY=wayland-0` in
`environment/session/greyward-dms.service`. That unit setting overrides the
absolute environment inherited from UWSM for DMS and its QML process only. The
private protected shell keeps its separate `XDG_RUNTIME_DIR` and broker-created
socket alias. The corrected `greyward-session` RPM was installed on `.149` and
only DMS was restarted. Its log then confirmed successful WLR output-manager
initialization; `wlr-randr` read back the VM output at 2560×1440. SELinux stayed
Enforcing. The interactive Settings check is the user's acceptance step.

The ISO stager verifies that the DMS unit, DMS state migration and first-session
monitor profile extracted from the supplied `greyward-session` RPM match the
source byte for byte. It refuses stale RPMs before creating the stage. Build
the session RPM from the same checkout before creating an ISO. The focused DMS
and image-staging contract tests cover the socket override, first-session
profile and stale-RPM rejection. Full image creation remains a separate
Fedora-host check.

Earlier diagnosis attributing the current screenshot to the stale protected
v1.6.2-12 copy was incorrect. Migration to v1.6.2-13 did complete, but it did
not fix the ordinary DMS service's absolute display path. The historical
migration details remain below as evidence of that earlier attempt.

## Source fix and security boundary

The protected compositor patch now advertises only `zwlr_output_manager_v1` to
ordinary clients in addition to the existing chrome interfaces. DMS uses this
protocol for live mode/resolution, refresh rate, scale and output placement.
Clients identified through Wayland security-context-v1 remain subject to
Labwc's upstream sandbox allowlist, which does not include output management.
Input injection, capture, output power and session-lock globals remain absent
from the ordinary-client allowlist.

The protected authentication session now sets `WAYLAND_DISPLAY=wayland-0`.
After Labwc creates its admitted socket, the root broker creates a fixed
`wayland-0` symlink inside the private authentication runtime pointing to that
session's socket. DMS and its output-management client then resolve the same
socket while `XDG_RUNTIME_DIR`, D-Bus, configuration, cache and state remain in
the protected runtime. The broker validates the socket owner/type and private
runtime directory before creating the alias, and removes only a prior symlink
with that fixed name during session renewal.

The ordinary DMS service has a separate user-manager runtime at
`/run/user/$UID`. Its unit pins the relative `WAYLAND_DISPLAY=wayland-0`, so
DMS resolves the socket beneath that runtime instead of joining two absolute
paths. The protected shell's private alias and the ordinary service's runtime
path are separate connections to the same admitted compositor socket.

`environment/patches/dms/greyward-wlr-output-readiness.patch` applies the
response-based readiness change to the pinned DMS source. The API reply must
contain an output list before Settings exposes monitor controls. A 5-second
request timeout permits retry and makes a missing response visible in the
shell log. The exact source preimage, patch hash, assembled shell digest and
package identity are recorded in `environment/production/dms-release.json`;
the offline DMS package builder and ISO composition path consume that manifest.

Labwc's peer policy identifies clients by SELinux domain, not DMS app identity.
Consequently, other ordinary unsandboxed applications can also change display
arrangement. That is a display-availability tradeoff; it does not grant screen
capture, input, lock or protected-data access. The live DMS changes remain
session-only; the compositor patch does not add display-control privileges.

## First-session display defaults

The production DMS defaults enable matching-profile auto-selection and package
one unnamed output profile for exactly `Virtual-1` at 1920×1080, scale 1. DMS
matches the profile by its output set, so it does not apply to physical
connectors such as eDP, DP or HDMI. Bare-metal sessions keep the mode selected
for their connected display. The VM starts at the reliable 1920×1080 default;
the user can choose another advertised mode in DMS Settings if the virtual
display provides one.

The session migration copies that profile only before the first GREYWARD DMS
session, only when `monitors.json` does not already exist, and never when the
DMS 1.6 migration marker shows an established session. It enables auto-select
only as a default and preserves explicit settings, profiles and later user
changes. On `.149`, the existing marker and manually selected 2560×1440 mode
remain untouched. Labwc's `reuseOutputMode` retains the mode selected by the
greeter during compositor startup; the protected Polkit readiness gate still
must complete before the normal desktop is admitted.

## ISO inclusion and validation

`packaging/greyward-enrollment/build.sh` includes the Labwc patch in the
enrollment RPM source, and `greyward-enrollment.spec` applies it to the pinned
Labwc source with zero fuzz before compiling the protected compositor. The
protected session package includes `session.py`. The DMS package builder
assembles the QML patch against the pinned DMS source and verifies the shell
digest; the image build selects that DMS release from the same manifest.
`packaging/greyward-session/greyward-session.spec` installs
`environment/session/greyward-dms.service`, and the image builder requires the
`greyward-session` RPM, so the relative display override enters future images
through the normal session package. That RPM also carries the first-session
monitor profile, migration logic and Labwc output-mode reuse setting.
Enrollment revision 8 also installs
`/usr/libexec/greyward-migrate-protected-dms-shell`. Its root-only explicit
migration verifies the existing desktop and Administration file/tool receipts,
refuses while a protected session is running, assembles from the verified
selected DMS RPM, repairs a stale Administration-to-desktop hash when both trees
are independently valid, and refreshes the copied DMS payload and dependent
receipts. It compares the assembled shell and authentication input even when
the DMS release identifier is unchanged, so a protected-shell-only fix is not
skipped; it does nothing when those payloads already match. The next login then
uses the migrated shell.

The focused source contracts are `python tests/test_protected_compositor_display.py`
and `python tests/test_dms_wayland_runtime.py`.
The original source-only inspection and the R6 candidate report are historical
records; they predate the live update below.

## Historical `.149` update — 10 October 2026

The protected Labwc source was rebuilt from the pinned Labwc 0.9.6 archive with
both GREYWARD patches applied at zero fuzz. The enrollment RPM was rebuilt as
`0.1.0-6`; its three Meson tests pass. A retained `0.1.0-1` RPM was stale and
did not contain the output-management addition, so it was not used.

The RPM's protected compositor was extracted without installing the RPM or its
newer package dependencies. That exact binary now replaces `.149`'s private
Labwc executable, and the root-owned desktop manifest was updated and verified.
SELinux remains Enforcing. A separate headless Labwc session using the packaged
binary exposed the output-management protocol to `wlr-randr`; a scale change
from 1.0 to 1.25 and back succeeded.

The Labwc/global and protected socket path fixes are deployed. Their source
manifest validates all 1,011 protected desktop files, and the graphical session
started with the corrected socket alias. DMS logs confirm protocol-manager
binding and the `wlroutput` capability. Settings nevertheless continued to
show the error, which led to the QML readiness fix above. Its DMS shell was
assembled from the pinned source and vendor archives with the exact patch
inventory and receipt checks. Candidate `greyward-dms-1.6.2-9.fc44` built on
`.149` in a network-isolated namespace; its Go test suite passed. For live
diagnosis, the patched QML service was copied into the protected desktop payload
and its root-owned file receipt updated. The installed DMS RPM selector remains
`v1.6.2-6`; this one-file overlay is a development check, while future ISO
builds consume the complete `v1.6.2-9` package from the release manifest. The
prior graphical session was returned to the greeter. Settings recognition and
a display-mode transaction await a fresh interactive login and visual check.
No new ISO was built in this update.

## Historical follow-up — capability-based readiness attempt

This attempt changed the QML readiness flag to follow the advertised
capability. It did not fix the visible Settings error and is superseded by the
request/response diagnosis above. The live DMS API response confirms that the
backend can answer; the shell must base availability on that response.

## Superseded live `.149` recheck — 10 October 2026

The earlier stale-generation diagnosis did not explain the current failure.
`.149` is now running the protected `v1.6.2-12` shell, whose DMS API advertises
`wlroutput`. The active Settings screen still shows the unavailable message,
while a direct read-only request returns the monitor state. The response-based
source patch is being assembled as `v1.6.2-13`; deployment and visual
verification are recorded below after they occur.
