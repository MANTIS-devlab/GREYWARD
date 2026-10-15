# Native window placement

Status: IMPLEMENTED configuration; partial installed interaction validation.

GREYWARD uses Labwc's native edge/corner snapping, with no additional window
manager, tiling daemon or application-specific rule. The canonical source is
`environment/session/labwc/rc.xml`, packaged by `packaging/greyward-session/`.
The defaults retain a 10-pixel inner/outer edge range, a 50-pixel corner range,
top-edge maximization and `notifyClient=always`. Left/right edges select half
the usable output, corners select quarters, and the top selects maximization.
Applications retain their minimum-size constraints; smaller requested tiles
are not a promise that every application can fit. DMS panel reservations remain
owned by the compositor's normal usable-area calculation.

Enrolled sessions use the root-owned configuration assembled by
`security-center/packaging/application-security/desktop/prepare.py`, not the
account's writable Labwc configuration. Enrollment obtains its source from the
packaged session defaults. Changes must preserve this preparation and manifest
boundary; editing an ordinary user's configuration alone does not update an
already admitted protected compositor.

## Next ISO retention gate

Retain this existing configuration in the next candidate. `tests/static.ps1`
rejects missing/disabled edge or corner snapping, missing top maximization and
missing client notifications. `environment/image/build.sh` compares the actual
Session RPM's Labwc configuration with the canonical source before staging,
rejecting stale or missing packaged defaults. This gate performs no live reload
and does not authorize composing or publishing an ISO.

On 15 October, the real development desktop showed Strata snapped to the left
half while preserving the taskbar. Maximization/restoration through native
window controls also worked. Automated right/top/corner dragging and detachment
were inconclusive because VMConnect input did not reliably reproduce the
gestures. They remain NON VERIFIED, as do multimonitor and clean-install
acceptance. No configuration, security policy or running session was changed
for those interaction checks. An earlier statement that all drag gestures were
validated would be incorrect.

Upstream contract: [Labwc 0.9.6 configuration](https://github.com/labwc/labwc/blob/0.9.6/docs/labwc-config.5.scd#window-snapping).
