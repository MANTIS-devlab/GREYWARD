# GREYWARD Flatpak + Software Integration Plan

Status: implemented for the GREYWARD-DEV deployment path; production image changes are staged in the repository and remain subject to the production image acceptance gate.

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

The production package baseline provides GNOME Screenshot, OBS Studio, Papers, Loupe,
File Roller, Firefox as an alternate browser, and CUPS-based printer support.
The following five applications are installed system-wide from the production
Flathub remote and are first-class parts of the normal desktop:

| Role | Application | Flatpak ID | Desktop ID |
|---|---|---|---|
| Mail | Aerion | `io.github.hkdb.Aerion` | `io.github.hkdb.Aerion.desktop` |
| Office documents | Collabora Office | `com.collaboraoffice.Office` | `com.collaboraoffice.Office.desktop` |
| Local video | Haruna | `org.kde.haruna` | `org.kde.haruna.desktop` |
| Web browser | Brave | `com.brave.Browser` | `com.brave.Browser.desktop` |
| VPN | Proton VPN | `com.protonvpn.www` | `com.protonvpn.www.desktop` |

`environment/flatpak/default-applications.list` is the canonical install list.
`environment/flatpak/mimeapps.list` assigns Aerion to `mailto:`, Brave to HTTP,
HTTPS and HTML, Collabora Office to common office formats, and Haruna to common
local video formats. PDF is explicitly assigned to Papers and common image
formats to Loupe, independently of browser registration order.

The session sets the dark Adwaita preference for GTK/libadwaita applications;
the five Flatpak applications use their normal desktop theme integration and
standard portals. Haruna receives only a GREYWARD system override that
disables network access by default for local playback. A user can explicitly
grant that permission later for online features. Brave and Proton VPN receive
no GREYWARD-specific permission broadening, and Aerion/Collabora use their
standard Flatpak sandbox permissions.

The wrapper at environment/flatpak/greyward-software is the only GREYWARD launch path. It uses only options supported by the installed Bazaar release. It:

1. creates the user Bazaar configuration directory;
2. renders the repository-owned content template with the current home path;
3. renders the GREYWARD banner and copies the GREYWARD symbol into that same directory;
4. passes Bazaar the sandbox-visible xdg-config/bazaar path with its supported extra-curated-config argument;
5. falls back to an uncurated Bazaar launch if the template is unavailable.

The system Flatpak override exposes only xdg-config/bazaar read-only. Provisioning and upgrade deployment reset the old GREYWARD Bazaar override before adding this single permission, so the legacy /etc/bazaar path is removed rather than left as a negative override. This keeps the official Flatpak sandbox narrow and avoids granting the application broad host /etc access.

## GREYWARD visual customization

The customization is deliberately upstream-compatible:

- environment/flatpak/greyward-privacy-runtime.yaml provides the GREYWARD landing content, recommendation sections, availability note, and banner configuration;
- environment/flatpak/greyward-software-banner.svg provides an obsidian/graphite GREYWARD banner with restrained silver typography and the symbol;
- environment/flatpak/greyward-software is the reproducible per-user renderer and launcher;
- environment/flatpak/software-runtime.desktop gives the app the stable Software identity;
- environment/flatpak/bazaar-main-runtime.yaml records the GREYWARD main-config decision for a future native/package Bazaar build.

The official Flathub build cannot safely consume a host /etc/bazaar main configuration under the current narrow sandbox. Consequently, the hide-auto-update-options main-config setting is documented and staged for a native/package build, but is not falsely claimed as active in the official Flatpak. Update Center remains canonical regardless; Bazaar’s own update controls must be treated as an upstream limitation until Bazaar provides a narrower main-config hook.

There is no GREYWARD CSS fork, patchset, or altered Flatpak security policy. This preserves Bazaar updateability and avoids a fake native skin that would drift from upstream.

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
