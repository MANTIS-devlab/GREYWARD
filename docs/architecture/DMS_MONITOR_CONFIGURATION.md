# DMS monitor configuration

## Root cause

DMS received an absolute `WAYLAND_DISPLAY` from the UWSM session, such as
`/run/user/1001/wayland-0`. DMS combines that value with
`XDG_RUNTIME_DIR=/run/user/1001`, producing a nonexistent double-prefixed
socket path. The compositor protocol was available; SELinux was not blocking the
request.

## Fix and security boundary

`environment/session/greyward-dms.service` sets
`WAYLAND_DISPLAY=wayland-0` for the ordinary DMS service. DMS then resolves
the socket below its normal runtime directory. This changes only the service's
Wayland socket name. The protected DMS shell retains its private runtime and
broker-created socket alias; no SELinux rule or application permission was
weakened.

On `.149`, the corrected session RPM was installed and only the DMS user
service was restarted. Its log confirmed WLR output-manager initialization,
and `wlr-randr` read the output at 2560×1440 while SELinux remained Enforcing.

## ISO protection

The session RPM spec is advanced to Release 9. The production stager verifies
the source unit has the relative display name, extracts the unit from the
supplied `greyward-session` RPM, and byte-compares it with source. If an older
RPM would reintroduce the path bug, staging stops with an error. The normal
`build-iso.sh` flow calls this stager, so the check is part of future ISO
creation. Build the session RPM from the same checkout before staging.

## Validation

Run `python3 tests/test_image_offline.py`. A complete Fedora ISO build remains the
end-to-end release check.
