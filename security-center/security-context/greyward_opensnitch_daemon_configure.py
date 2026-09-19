#!/usr/bin/python3
"""Generate a runtime OpenSnitch config without mutating vendor configuration."""
import json
import os
import tempfile
from pathlib import Path

SOURCE = Path("/etc/opensnitchd/default-config.json")
DESTINATION = Path("/run/greyward-opensnitch/daemon-config.json")
SOCKET = "unix:///run/greyward-opensnitch/control-plane.sock"

config = json.loads(SOURCE.read_text(encoding="utf-8"))
config.setdefault("Server", {})["Address"] = SOCKET
config["InterceptUnknown"] = True
config.setdefault("DefaultAction", "allow")
# GREYWARD's DNS policy must not silently bypass when the control plane is
# unavailable. Application DNS is denied by the typed control-plane decision;
# a bypass here would turn that policy into best-effort telemetry.
config.setdefault("FwOptions", {})["QueueBypass"] = False
descriptor, temporary = tempfile.mkstemp(prefix=".daemon-config-", dir=DESTINATION.parent)
try:
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(config, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, DESTINATION)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
