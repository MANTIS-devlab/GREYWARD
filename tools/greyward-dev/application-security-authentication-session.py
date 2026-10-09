#!/usr/bin/python3 -I
"""Fixed root-prepared private-seat authentication test, UID 1002 only.

All binaries/QML/configuration come from the root fixture. No active user bus,
display, environment or command is accepted. Not installed by any package.
"""
import os
import ctypes
import json
from pathlib import Path
import subprocess
import time

BASE = Path("/run/greyward-application-security-lock")
assert os.getuid() == os.geteuid() == 1002
assert Path("/proc/self/attr/current").read_text().strip("\0\n") == "system_u:system_r:greyward_as_auth_t:s0"
# Root moves the fixed leader into its private PAM/logind session scope before
# any renderer/helper starts. No user-provided session identifier is accepted.
admission_deadline = time.monotonic() + 6
while not (BASE / "session-admitted").exists():
    if time.monotonic() >= admission_deadline:
        raise RuntimeError("Private session admission unavailable")
    time.sleep(.05)
library = ctypes.CDLL("libsystemd.so.0")
session = ctypes.c_char_p()
result = library.sd_pid_get_session(0, ctypes.byref(session))
(BASE / "session-readback.json").write_text(json.dumps({"result": result, "cgroup": Path("/proc/self/cgroup").read_text().strip()}))
environment = {
    "PATH": str(BASE / "bin"), "HOME": str(BASE / "home"), "USER": "greyward-guard-probe", "LOGNAME": "greyward-guard-probe",
    "XDG_RUNTIME_DIR": str(BASE / "runtime"), "XDG_CONFIG_HOME": str(BASE / "config"),
    "XDG_STATE_HOME": str(BASE / "state"), "XDG_CACHE_HOME": str(BASE / "cache"),
    "XDG_CONFIG_DIRS": "/etc/xdg", "XDG_DATA_DIRS": "/usr/share", "LC_ALL": "C.UTF-8",
    "DBUS_SESSION_BUS_ADDRESS": "unix:path=" + str(BASE / "runtime/bus"), "WAYLAND_DISPLAY": "wayland-0",
    "WLR_BACKENDS": "headless", "WLR_HEADLESS_OUTPUTS": "1", "WLR_RENDERER": "pixman",
    "QT_QUICK_BACKEND": "software", "LIBGL_ALWAYS_SOFTWARE": "1", "XDG_CURRENT_DESKTOP": "GREYWARD:labwc",
    "QT_QPA_PLATFORM": "wayland",
    "QV4_FORCE_INTERPRETER": "1", "QML_DISABLE_DISK_CACHE": "1", "DMS_DISABLE_HOT_RELOAD": "1",
}


def launch(name, arguments):
    target = BASE / "bin" / name
    metadata = target.stat()
    assert metadata.st_uid == 0 and metadata.st_mode & 0o022 == 0
    with (BASE / (name + ".log")).open("wb") as output:
        return subprocess.Popen([str(target), *arguments], env=environment, stdin=subprocess.DEVNULL, stdout=output, stderr=output, close_fds=True)


def ready(process, path):
    until = time.monotonic() + 5
    while time.monotonic() < until:
        if process.poll() is not None:
            raise RuntimeError("Fixed private process exited before readiness")
        if path.exists():
            return
        time.sleep(.1)
    raise RuntimeError("Fixed private endpoint unavailable")


bus = launch("dbus-daemon", ["--nofork", "--config-file=" + str(BASE / "session-bus.conf")])
ready(bus, BASE / "runtime/bus")
display = launch("labwc", ["-C", str(BASE / "config/labwc")])
ready(display, BASE / "runtime/wayland-0")
backend = launch("dms", ["run", "--session", "-c", str(BASE / "shell")])
until = time.monotonic() + 65
while time.monotonic() < until:
    if any(process.poll() is not None for process in [bus, display, backend]):
        raise RuntimeError("Private authentication process exited")
    time.sleep(.1)
raise RuntimeError("Hard-bounded controller lifetime exceeded")
