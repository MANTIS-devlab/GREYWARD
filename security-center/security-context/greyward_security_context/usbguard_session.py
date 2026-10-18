"""Run a USBGuard approval from the active protected desktop process tree."""
import json
import re
import sys
from pathlib import Path

try:
    from .usbguard import UsbGuardAdapter, UsbGuardError
except ImportError:  # Executed by the fixed, SELinux-confined launcher with -I.
    # Python isolated mode intentionally omits the script directory. Restore
    # only this root-owned package directory so the fixed adapter can import.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from usbguard import UsbGuardAdapter, UsbGuardError


CONNECTION_REF = re.compile(r"^[0-9a-f]{32}$")


def request_trust(reference, mode, adapter=None):
    """Ask USBGuard to trust one current device and verify its live state."""
    if not CONNECTION_REF.fullmatch(str(reference)):
        return {"ok": False, "state": "INVALID", "detail": "The USB device reference is invalid."}
    if mode not in {"once", "always"}:
        return {"ok": False, "state": "INVALID", "detail": "Choose a supported USB approval."}

    adapter = adapter or UsbGuardAdapter()
    try:
        device = next((item for item in adapter.list_devices()
                       if item.get("connection_ref") == reference), None)
        if not device:
            return {"ok": False, "state": "REMOVED", "detail": "The device is no longer connected. Refresh and try again."}
        if device.get("controller"):
            return {"ok": False, "state": "REFUSED", "detail": "USB host controllers cannot be approved here."}
        if device.get("state") not in {"BLOCK", "REJECT"}:
            return {"ok": False, "state": "STALE", "detail": "The device state changed. Refresh and try again."}
        if mode == "always":
            if not device.get("can_persist"):
                return {"ok": False, "state": "REFUSED", "detail": "This device has no stable identity for persistent trust."}
            adapter.always_allow(device["device_id"])
        else:
            adapter.allow_once(device["device_id"])

        confirmed = next((item for item in adapter.list_devices()
                          if item.get("device_id") == device.get("device_id")
                          and item.get("identity_metadata") == device.get("identity_metadata")), None)
        if not confirmed:
            return {"ok": False, "state": "REMOVED", "detail": "The device changed before USBGuard could confirm approval."}
        if not confirmed.get("authorized") or (mode == "always" and not confirmed.get("trusted")):
            return {"ok": False, "state": "FAILED", "detail": "USBGuard did not confirm approval. The device remains blocked."}
        detail = "Trusted for future connections." if mode == "always" else "Allowed until disconnected."
        return {"ok": True, "state": "COMPLETE", "detail": detail}
    except UsbGuardError as error:
        return {"ok": False, "state": error.state, "detail": str(error)}


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2:
        result = {"ok": False, "state": "INVALID", "detail": "A device reference and approval mode are required."}
    else:
        result = request_trust(args[0], args[1])
    sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
