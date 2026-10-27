# GREYWARD Flatpak + Software Integration Plan

Status: implemented on the physical reference and included in local 0.5.1 Sophon
composition; fresh-image installation acceptance remains open. Published RC3
predates these repairs. [Sophon evidence](../patch-notes/0.5.1-sophon.md) owns the
current image tuple and verification.

## AMD Flatpak startup correction — 24 October 2026

On the physical reference, Bazaar 0.9.7 failed before its own startup:
Bubblewrap could not inspect `/dev/kfd`, labeled `hsa_device_t`, while preparing
Flatpak's existing DRI-device sandbox. The ordinary SELinux subject lacked
metadata permissions for that AMD node. The canonical session policy now allows
only `getattr` and `mounton`, matching its existing DMA metadata boundary.
Device `open`, `read`, `write` and `ioctl` remain denied. No Flatpak override,
software renderer setting, application CLI or authorization policy is changed.

The initial correction targeted Enrollment 81 and was activated as a persistent,
scoped policy-only hotfix while Enrollment 79 / AppSec 82 remained installed.
That step replaced no protected profile or RPM payload. The later screenshot
migration activated Enrollment 82 / AppSec 83 on the reference, retaining these
rights. Enrollment 83 is now built and embedded in local Sophon, without being
deployed over that active session. None of this changes published RC3.
After activation the normal Software wrapper starts both Bazaar daemon and GUI
in `greyward_guard_t`, and the session still reports Protected with SELinux
Enforcing. Physical icon/window confirmation is recorded separately in current
status; process startup is not a complete store/search/install acceptance test.

`tests/test_flatpak_session_compatibility.py` compiles the real session policy and
checks that its KFD rule grants metadata only. The read-only
`tools/greyward-dev/desktop-compatibility-kernel-check.py` also verifies the
live metadata/I/O split alongside the existing protected-input and
Administration denials.

## Flatpak installation compatibility — 24 October 2026

Three independently reproduced failures must not be confused with catalogue
connectivity or a completed application installation:

- The offline installer previously installed refs from `greyward-offline`, then
  force-deleted that remote. Deployment origins remained dangling. The canonical
  installer now uses `flathub` for the local media transaction, verifies each
  exact commit and origin, and restores its official HTTPS URL, commit-signature
  verification and enabled state through an EXIT trap, including on failure.
  The unsigned local summary is used only inside the verified media transaction
  in an empty network namespace. It is never retained as HTTPS trust policy.
- Flatpak's system helper returns an already-open revokefs socket. The confined
  caller had FD-use permission but lacked socket read/write, so D-Bus returned
  an invalid descriptor list. The session policy adds those two socket rights
  only; direct helper connection, helper-file access and process control remain
  denied. Deployment authorization still belongs to the existing Polkit path.
- OSTree writes symbolic-link objects through its FUSE staging mount. Creating
  a temporary link failed with a concrete `fusefs_t:lnk_file create` AVC and
  `Writing content object: Permission denied`. Permit FUSE symlink creation,
  atomic rename and cleanup only. This adds no regular-file write exception,
  protected-resource access, host mount capability or io_uring permission.

Existing installations with dangling origins require compatibility repair;
changing future media alone does not repair them. On the physical reference,
the missing origin was restored as an enabled, signature-verified official
Flathub alias, hidden from enumeration and automatic new dependency selection.
Existing refs, application data and commits were preserved by that repair.
It must remain while those deployments still name it; new installs use normal
`flathub`. No arbitrary allow rule, application reinstall or cache reset is
part of this repair.

`tests/test_flatpak_session_compatibility.py` compiles the actual policy and
checks the exact added rights. `tests/test_flatpak_offline_origins.py` is an
explicit native gate using isolated toy app/runtime deployments and the real
installer in a network namespace; it verifies both successful installation and
trust restoration after failure, without touching host Flatpak installations.
Set `GREYWARD_TEST_FLATHUB_REPO` to a verified official descriptor to run it.
`tools/greyward-dev/flatpak-revokefs-check.py`, run in an ordinary graphical
session, exercises the actual helper descriptor and symlink create/read/rename/
unlink path, unmounts, and cancels only its own scratch pull. It installs nothing.
The kernel check additionally proves installed-content write and helper-control
denials. These checks do not replace GUI installation and deployment readback.

The first live repair used persistent scoped policy modules; the later matched
Enrollment 82 deployment retains the canonical rights. The DMS2 image selects
its built Enrollment 83 successor. Published RC3 remains unchanged.
Complete staging also compares the Enrollment RPM's session `.te`/`.fc` inputs
with canonical source on both source-build and installed-import paths through
`verify-usbguard-inputs.py --kind flatpak-session`. A patched live reference
cannot silently export its older RPM as a fixed image input.
Personal VPN transport failures remain separate: an approved MTU adjustment and
successful catalogue refresh are not proof that every large transfer succeeds.
See [current evidence](../STATUS.md) for the actual GUI transaction outcome.

## Explore recovery and next-image acceptance — 25 October 2026

Status: **SCOPED SOURCE CORRECTION PREPARED; ORIGINAL CACHE LOSS UNRESOLVED**.
On an installed
Sophon test system, Bazaar 0.9.7 could install applications while Explore showed
“Can't Reach Flathub”. The configured system Flathub remote was enabled and used
the correct HTTPS URL. The clock was synchronized. HTTPS certificate validation
and catalogue API requests succeeded both on the host and through libsoup inside
the ordinary confined Bazaar Flatpak sandbox. No VPN was active. Neither a clock
change nor the physical reference's personal VPN MTU adjustment was needed.

The failed state had no serialized Bazaar `core/flathub-cache`, even though its
Flatpak catalogue and installed-app operations worked. After closing Bazaar with
no active installation, reopening the normal GREYWARD Software launcher and
using Explore's retry button, the application's own log recorded a successful
Flathub state synchronization in about 2.24 seconds. Readback of the resulting
GVariant cache was valid and contained the current UTC day, 20 categories, five
weekly picks and the daily pick. The user confirmed Explore displayed applications
and categories. Detailed diagnostic logging was then removed from the running
launch. This is a verified recovery, not an implemented upstream code fix.

The upstream [0.9.7 Explore page](https://gitlab.gnome.org/World/bazaar/-/blob/v0.9.7/src/bz-flathub-page.c)
uses its generic offline page when the configured repository exists but the
Explore state object is absent. Its [state initialization](https://gitlab.gnome.org/World/bazaar/-/blob/v0.9.7/src/bz-flathub-state.c)
loads several API collections separately from Flatpak installation metadata;
a failed required request rejects that initialization. Thus the message alone
does not prove a broken network, a missing installation fix, or a clock problem.
The initial failed request was not logged, and the diagnostic retry succeeded;
its original trigger remains unknown. Do not label this a confirmed TLS, MTU,
SELinux or upstream endpoint defect.

Subsequent examination explicitly read both retained user journals and both
system boots, rather than relying only on the root journal's default view.
Network telemetry contained allowed Bazaar catalogue connections and the
successful Explore API connection. It did not supply the missing original API
error. The Selection launcher currently redirects the spawned wrapper's stderr
to `/dev/null`; historical launches therefore cannot be assumed to retain their
application request errors.

A separate **real-binary A/B reproduction** identified the recovery defect in
the [0.9.7 startup condition](https://gitlab.gnome.org/World/bazaar/-/blob/v0.9.7/src/bz-application.c):
the three-hour minimum startup refresh interval is checked even when Explore
has no valid state. At the failed-state readback, `last-refresh-time` was about
30 minutes old but `core/flathub-cache` was absent. Two disposable profiles in
the actual ordinary confined Flatpak were then run with `--no-window-refresh`,
separate private session buses, keyfile settings and temporary cache/config/data
directories. No active Bazaar instance, user preferences or system network
configuration was changed by these tests.

| Identical empty profile except for refresh timestamp | Observed result |
| --- | --- |
| Timestamp set to the current time | Exit 0 in 0.46 seconds; no Explore synchronization started and no Explore cache created |
| Timestamp set to zero | Explore synchronization logged; valid current-day cache with 20 categories created; process completed in 10.36 seconds |

Both test profiles lacked host portals on their deliberately private bus. Those
warnings occurred in both cases; the control still fetched and serialized
Explore successfully. This demonstrates the missing-cache refresh suppression,
not full graphical/portal acceptance, and does not establish why the original
cache was absent. The original user's verified working cache was preserved.

Recovery for an affected desktop:

1. Finish or cancel installations, then close Bazaar.
2. Reopen Software through its usual icon or
   `/usr/local/libexec/greyward-software`, then open Explore and retry once.
3. Confirm real categories/applications appear. An app-install success or a
   successful `curl` request alone does not establish Explore acceptance.
4. If it still fails, capture Bazaar's own stderr during the retry, alongside
   UTC/NTP and system remote state, before proposing a change. Preserve existing
   caches, remotes, installed apps and user preferences. Keep diagnostic logs
   private and stop verbose logging after the test.

### Prepared startup correction and inclusion gates

The earlier recovery-only state is superseded by
`environment/flatpak/greyward-bazaar-start`. The normal Software wrapper copies
this GREYWARD-owned helper alongside its curated content into the existing
read-only `xdg-config/bazaar` exposure, then runs it through `flatpak run
--command=sh`. Inside the unchanged sandbox, the helper checks Bazaar 0.9.7's
actual `$XDG_CACHE_HOME/io.github.kolunmi.Bazaar/core/flathub-cache` (with the
normal home-cache fallback). If it is absent or empty, it sets only Bazaar's
`last-refresh-time` to zero through its own GSettings schema, before executing
the normal `bazaar-daemon` with unchanged application arguments. A nonempty cache
and its refresh interval are preserved. No cache is deleted or preseeded, and
there is no polling/restart loop, network preflight or extra authorization.
If the GSettings write fails, stderr reports it and Bazaar still launches.

This fixes the reproduced **missing/empty-cache startup suppression**. It does
not parse or repair nonempty corrupt caches, recover an already-open instance
after a network failure, or guarantee Flathub service availability. A scoped
upstream retry change remains separate work if those cases reproduce.

Production provisioning installs the helper under `/usr/share/greyward/bazaar`
and the wrapper under `/usr/local/libexec`. The existing source stager copies
the entire canonical Flatpak directory and normalizes its text. New
`environment/image/verify-software-inputs.py` compares the complete normalized
wrapper, helper and provisioner bytes against the selected checkout, rejecting
missing, symlinked or older inputs even with self-consistent payload hashes.
The check runs after source staging, before ISO composition, and again on the
payload extracted from the resulting ISO. The production-stage validator also
requires both files, and installed acceptance compares both installed startup
files with the immutable installer payload. The development deployer follows
the same helper installation path. No RPM rebuild is needed for these existing
provisioner-owned Software assets; no current package tuple is relabeled.

`python3 -m unittest tests.test_software_explore_recovery` tests the real shell
helper, wrapper wiring, argument preservation, settings failure and stale/missing
image rejection. The source CI image job includes this test; the static gate
also rejects a missing or bypassed helper. The opt-in
`tests/fixtures/bazaar-explore-native.py --helper PATH` must run **inside the
installed Bazaar Flatpak**, with the prepared helper available in that sandbox.
It uses a Unix-socket-only GTK Broadway display and disposable private buses,
settings/cache/data to compare the unmodified startup, the corrected startup
and a fully seeded warm cache, including Bazaar's cache-version marker. It
installs no app and does not restart the user's Bazaar or use the real display.
These checks prepare the next build; no ISO was constructed or existing image
modified for this correction. New-image installed acceptance remains mandatory.

Prepared-code validation on 25 October: all 12 targeted tests passed natively
on Fedora, including the complete wrapper invoking the helper and stale-input
rejection. The real confined Bazaar 0.9.7 fixture passed all three cases:
unmodified cold-cache/recent-timestamp startup produced no Explore state;
the prepared helper produced a valid current-day 20-category state; a subsequent
warm launch did not synchronize and retained the exact serialized-cache SHA-256.
The complete corrected startup took about 14 seconds including normal daemon
idle exit; that duration is not a UI opening-time measurement. The private GTK
test display preserved Flatpak's runtime/certificate-broker namespace; no TLS
bypass was used. The original user's cache timestamp, 20-category state and
running Bazaar PID stayed unchanged, with SELinux Enforcing. Both repository
PowerShell gates pass. The helper/wrapper were not installed over that running
desktop; full next-image installed acceptance and offline recovery remain open.

For the **next ISO**, add these installed-system acceptance checks to the normal
Software journey: first-open Explore with no pre-existing per-user Bazaar cache;
populate categories; close/reopen and verify cached content remains usable; start
offline, restore networking and retry; separately install and launch an app.
Record the bundled Bazaar version and distinguish observed results from pending
tests. Do not embed this test account's cache or diagnostic launch units in an
image, automatically reset users' caches, broaden SELinux/Flatpak permissions,
disable TLS verification, or impose a VPN MTU workaround. The source correction
above is not included in the already-composed Sophon artifact; offline recovery
and a fresh cache-free walkthrough still require next-image release acceptance.

## Verified baseline

GREYWARD targets Fedora 44 with Labwc as the canonical session and DMS as the shell. Flatpak is a production application layer, and Bazaar (Flatpak ID io.github.kolunmi.Bazaar) is the implementation underneath the GREYWARD Software product. The system Flathub remote is added during provisioning and Bazaar is installed system-wide. Security Center and Update Center remain authoritative GREYWARD surfaces; Bazaar is not an update authority.

Bazaar is a GTK4/libadwaita application. The upstream Flatpak exposes distributor customization through YAML content configuration and the supported extra-curated-config command-line option (with extra-content-config retained as a backwards-compatible alias). It does not provide a stable external CSS/theme API. A full visual fork would therefore create a large maintenance obligation and is intentionally not used.

## Target architecture

The production flow is:

Flatpak and portals
→ system Bazaar package
→ GREYWARD Software desktop identity and launch wrapper
→ per-user Bazaar curated content
→ Update Center for application updates
→ Security Center for application-security evidence.

## Default production applications

The production package baseline provides [manual screenshots with Swappy](SCREENSHOTS.md), [GREYWARD Office](OFFICE_INTEGRATION.md), Loupe,
File Roller, Firefox as an alternate browser, and CUPS-based printer support.
The following three applications are installed system-wide from the production
Flathub remote and are first-class parts of the normal desktop:

| Role | Application | Flatpak ID | Desktop ID |
|---|---|---|---|
| Mail | Aerion | `io.github.hkdb.Aerion` | `io.github.hkdb.Aerion.desktop` |
| Web browser | Brave | `com.brave.Browser` | `com.brave.Browser.desktop` |
| VPN | Proton VPN | `com.protonvpn.www` | `com.protonvpn.www.desktop` |

`environment/flatpak/default-applications.list` is the canonical install list.
`environment/flatpak/mimeapps.list` assigns Aerion to `mailto:`, Brave to HTTP,
HTTPS and HTML, the native Office applications to their supported document formats,
with no preselected video player. PDF is assigned to GREYWARD PDF and common image
formats to Loupe, independently of browser registration order.

The session sets the dark Adwaita preference for GTK/libadwaita applications;
the three Flatpak applications use their normal desktop theme integration and
standard portals. Brave and Proton VPN receive
no GREYWARD-specific permission broadening, and Aerion uses its standard Flatpak sandbox permissions.

The wrapper at environment/flatpak/greyward-software is the only GREYWARD launch path. It uses only options supported by the installed Bazaar release. It:

1. creates the user Bazaar configuration directory;
2. renders the repository-owned content template with the current home path;
3. renders the GREYWARD banner and copies the GREYWARD symbol into that same directory;
4. passes Bazaar the sandbox-visible xdg-config/bazaar path with its supported extra-curated-config argument;
5. falls back to an uncurated Bazaar launch if the template is unavailable.

Fresh installations seed only the read-only `xdg-config/bazaar` access for
Software through the shared
`environment/flatpak/seed-system-permissions.py` entrypoint. Production and
development deployment both use it. Any existing system global/app override
is preserved; user overrides are never reset. Failed reads stop seeding rather
than masquerading as absent policy. Readback verifies the default record,
not Protected Data enforcement. Earlier reset-based deployment is historical;
legacy `/etc/bazaar` or broader permissions require explicit review rather than
silent removal. The selected Application Security rollout preserves existing
permissions until that review. The new seeding behavior is source-tested;
fresh-image/package acceptance remains separate.

## GREYWARD visual customization

The customization is deliberately upstream-compatible:

- environment/flatpak/greyward-privacy-runtime.yaml provides the GREYWARD landing content, recommendation sections, availability note, and banner configuration;
- environment/flatpak/greyward-software-banner.svg provides a self-contained 1600 x 220 obsidian banner with the canonical emblem and centered silver typography;
- environment/flatpak/greyward-software is the reproducible per-user renderer and launcher;
- environment/flatpak/software-runtime.desktop gives the app the stable Software identity;
- environment/flatpak/bazaar-main-runtime.yaml records the GREYWARD main-config decision for a future native/package Bazaar build.

The official Flathub build cannot safely consume a host /etc/bazaar main configuration under the current narrow sandbox. Consequently, the hide-auto-update-options main-config setting is documented and staged for a native/package build, but is not falsely claimed as active in the official Flatpak. Update Center remains canonical regardless; Bazaar’s own update controls must be treated as an upstream limitation until Bazaar provides a narrower main-config hook.

There is no GREYWARD CSS fork, patchset, or altered Flatpak security policy. This preserves Bazaar updateability and avoids a fake native skin that would drift from upstream.

The banner is generated by `tools/generate-software-banner.py` from the canonical
symbol and identity palette. Regenerate it rather than editing its embedded
logo paths. Its height matches the existing 220px curated row; the central
content remains inside a 560px safe area for the row's existing `cover` fit.
It has no external image/font URLs, user-home placeholder, blur, decorative grid
or slogan. The selection YAML and application behavior are unchanged.
Native SVG rendering and centered 800/600px cover crops were inspected on
25 October. On the physical reference, the system asset, user-rendered asset
and file read inside Bazaar's sandbox match the new source hash. The previous
assets were backed up. A running Bazaar must be reopened to release its old
image object; actual app-window appearance after reopening remains user review.
The production provisioner consumes the same asset for future image builds;
the published ISO has not been rebuilt by this artwork change.

## Curated recommendations

The curated landing uses real AppStream IDs from configured Flatpak sources:

- Proton Pass: me.proton.Pass
- Proton Mail: me.proton.Mail
- Proton VPN: com.protonvpn.www
- Signal: org.signal.Signal
- KeePassXC: org.keepassxc.KeePassXC
- Cryptomator: org.cryptomator.Cryptomator
- Tor Browser launcher: org.torproject.torbrowser-launcher
- qBittorrent: org.qbittorrent.qBittorrent
- Mullvad Browser: net.mullvad.MullvadBrowser

Mullvad VPN has no Flathub application at the time of implementation. It is explicitly described in the availability note and is not rendered as a broken install tile. Community/unverified packages remain clearly subject to source and publisher review; GREYWARD makes no claim that publisher verification alone proves application security.

Unavailable IDs must be omitted by Bazaar’s content resolution rather than represented as fake installed apps. Search and normal categories remain available.

## Platform and portals

- environment/production/provision.sh installs Flatpak, xdg-desktop-portal-gtk and the Labwc portal selection.
- environment/flatpak/labwc-portals.conf selects GTK for general desktop portals and WLR for screenshot/screencast.
- Flatpak system and user inventory are handled by the existing provider contracts.
- File chooser, OpenURI, notifications, inhibit, theme/font, camera/microphone, screenshot and screencast behavior must be tested with real applications, not fixtures.
- No frontend is allowed to execute arbitrary Flatpak or provider commands.

The production provisioner installs the default applications after adding the
system Flathub remote. Re-running provisioning is idempotent because Flatpak
keeps the same app IDs and handles upgrades through the existing GREYWARD
Update Center application provider. Bazaar exposes the same apps for search
and details; it is not a second installation source for the default baseline.

## Software identity and DMS

The user-facing product name is Software. The desktop file and DMS pin use io.github.kolunmi.Bazaar as the stable application/window identity, while Exec points to the GREYWARD wrapper. The default DMS bar keeps the native merged AppsDock immediately after the workspace selectors. A dedicated single-action greywardSoftware widget sits immediately to the right of greywardSecure; it launches the GREYWARD wrapper and activates Bazaar's curated Selection tab through /usr/local/libexec/greyward-software-selection. `greyward-dms-session-migrate` seeds Software only when the DMS-owned `barPinnedApps` key has not yet existed; after that, the user's pin list is authoritative.

The Security Center open_software command launches only /usr/local/libexec/greyward-software and accepts no provider, executable, or arbitrary arguments.

## Update Center ownership

Update Center and org.greyward.Update1 remain the canonical update workflow. Flatpak is represented by the existing Applications provider with user/system scope, app ID, origin, version, runtime, architecture, branch, update availability, observation time, and explicit unknown trust/restart values. Update All invokes fixed native provider operations and records provider output without inventing progress. Bazaar is not advertised as a second update center.

## Security Center application view

Security Center may show backend-authoritative application evidence:

- scope, origin, version, runtime, architecture and branch;
- network, file, device and D-Bus access summaries;
- permission and override counts;
- broader-access evidence;
- portal health separately from Flatpak availability.

Version one remains informational. It does not expose arbitrary permission mutation or generic Flatpak rule execution. Any future control must be typed, preconditioned, backend-authoritative and resettable.

## Deployment and migration

Fresh production images install the runtime assets under /usr/share/greyward/bazaar, the wrapper under /usr/local/libexec, and the Software desktop entry under /usr/local/share/applications. GREYWARD-DEV deployment follows the same layout and narrows any prior /etc/bazaar override.

Existing users retain their Flatpak remotes, installed applications and DMS pins. A new account is seeded with Software, while an existing DMS `barPinnedApps` list is never rewritten, so an intentional unpin remains authoritative across DMS/GREYWARD updates. Existing per-user Bazaar configuration is not overwritten beyond the GREYWARD-owned rendered content file and banner assets.

## Acceptance journeys

1. From the dedicated Software widget to the right of Security Center, open Software. Confirm the existing Bazaar window is reused when present, the curated Selection tab is active, and only one running/window identity is shown.
2. Search, open details, install and launch a real Flatpak. Exercise portals and check keyboard navigation, scaling and content-length behavior.
3. Confirm the installed app appears in Security Center with correct scope, origin, runtime and access evidence.
4. Create or observe an application update under Update Center → Applications, run Update All, and inspect provider result, failure state and history.
5. Run with no network, missing Flathub, missing Bazaar, malformed content, missing portal owner and a user/system scope failure. Each state must be explicit and actionable.
6. Test fresh login, reboot, upgrade deployment, 1440×900 and 1100×700 windows. Confirm the banner, recommendation rows, search, details, dialogs and error/empty states remain readable.
7. Confirm the official Flatpak sandbox does not regain host /etc access: the effective override must contain xdg-config/bazaar:ro and no /etc/bazaar permission.

Latest GREYWARD-DEV evidence from this implementation:

- the wrapper starts Bazaar 0.9.4 with the supported extra-curated-config argument and the curated YAML passes the live schema validator;
- the effective system override is exactly xdg-config/bazaar:ro after migration;
- the rendered YAML and banner are visible inside the sandbox, while /etc/bazaar is not;
- real desktop captures were taken at output/greyward-runtime/bazaar-1440x900.png and output/greyward-runtime/bazaar-1100x700.png.

The captures confirm the upstream dark libadwaita surface, navigation, search and window composition at both targets. The curated provider is loaded through the GREYWARD wrapper; the official Flatpak still opens its normal Explore view by default because start-on-curated belongs to Bazaar main configuration, which the official build does not expose through a narrow per-user hook. That limitation is intentional and is retained as a documented upstream integration item rather than solved by broadening the sandbox.

## Implementation sequence

1. Platform: provision Flatpak, portals, system Flathub, the four default applications, and Bazaar; deploy runtime content/wrapper assets.
2. Desktop: install the Software identity, enable the adjacent single-action DMS widget, migrate the DMS pin, and apply the repository-owned MIME defaults.
3. Content: validate curated YAML, AppStream resolution, banner and unavailable-app note.
4. Cross-surface: validate Update Center and Security Center inventory/evidence against real installed applications.
5. End-to-end: run the journeys above on GREYWARD-DEV, then promote the same assets into the production image.

## Deferred work and risks

- A true Bazaar-wide GREYWARD palette requires an upstream theme hook or a small maintained patch; the repository intentionally does not fork GTK/libadwaita styling.
- The official Flatpak build cannot receive the Bazaar main configuration without a broader host filesystem permission; enabling that would violate the current security boundary.
- App-specific Software deep links remain deferred until Bazaar exposes a stable, validated URI/CLI contract.
- Permission mutation remains deferred until a typed backend contract exists.
- Flatpak transaction progress/history may be indeterminate on Fedora 44; unknown values must remain explicit.

## Definition of done

Software feels GREYWARD through its curated landing, restrained banner, desktop identity, DMS placement and launch path; Bazaar remains upstream-updateable; Flatpak sandbox permissions remain narrow; search, details, install/update flows, portals and errors remain functional; Update Center owns updates; Security Center exposes real application evidence; and the complete acceptance journeys pass on GREYWARD-DEV at both supported window targets.
