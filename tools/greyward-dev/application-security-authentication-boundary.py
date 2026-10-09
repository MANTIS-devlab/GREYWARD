#!/usr/bin/python3 -I
"""Synthetic UID-1002 cross-domain probe; no real credentials or policy writes.

Root PID 1 launches the two subjects. The controller supplies only synthetic
PID/start/FD/address metadata on stdin; there is no arbitrary target argument.
Self inspection must work in both domains. This is not session coverage.
"""
import ctypes
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

MARKER = b"GREYWARD_SYNTHETIC_AUTH_SENTINEL"
AUTH = "system_u:system_r:greyward_as_auth_t:s0"
ORDINARY = "system_u:system_r:greyward_guard_t:s0"
ENTRY = "/run/greyward-authentication-boundary/auth-python"


class Iovec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]


def current():
    return Path("/proc/self/attr/current").read_text().strip("\0\n")


def host():
    if current() != AUTH:
        raise RuntimeError("Root-prepared authentication subject required")
    storage = ctypes.create_string_buffer(MARKER)
    read, write = os.pipe()
    try:
        os.write(write, MARKER)
        print(json.dumps({"pid": os.getpid(), "start": Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()[19],
                          "descriptor": read, "address": ctypes.addressof(storage), "size": len(MARKER),
                          "context": current(), "self_read": True}), flush=True)
        if sys.stdin.readline() != "finish\n":
            raise RuntimeError("Fixed controller lifetime required")
    finally:
        os.close(read)
        os.close(write)


def denied(action):
    try:
        action()
    except OSError as error:
        return error.errno in {errno.EACCES, errno.EPERM}
    return False


def reader():
    if current() != ORDINARY:
        raise RuntimeError("Separate ordinary subject required")
    value = json.loads(sys.stdin.readline(2048))
    if set(value) != {"pid", "start", "descriptor", "address", "size", "context", "self_read"} or value["context"] != AUTH or value["size"] != len(MARKER):
        raise RuntimeError("Only the fixed synthetic authentication fixture is supported")
    pid = value["pid"]
    handle = os.pidfd_open(pid)
    try:
        # Root has verified UID/start/context and holds the host alive. The
        # ordinary reader must not require access to protected /proc metadata.
        pipe = denied(lambda: os.open(f"/proc/{pid}/fd/{value['descriptor']}", os.O_RDONLY | os.O_NONBLOCK))
        storage = ctypes.create_string_buffer(len(MARKER))
        local = Iovec(ctypes.addressof(storage), len(MARKER))
        remote = Iovec(value["address"], len(MARKER))
        library = ctypes.CDLL(None, use_errno=True)
        library.process_vm_readv.restype = ctypes.c_ssize_t
        count = library.process_vm_readv(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
        memory = count == -1 and ctypes.get_errno() in {errno.EACCES, errno.EPERM}
        signal_blocked = denied(lambda: os.kill(pid, signal.SIGCONT))
        entry_blocked = denied(lambda: subprocess.run([ENTRY, "-I", "-c", "pass"], check=True, timeout=3))
        results = {"authentication_self_read": value["self_read"], "ordinary_self_read": current() == ORDINARY,
                   "authentication_pipe_denied": pipe, "authentication_memory_denied": memory,
                   "authentication_signal_denied": signal_blocked, "authentication_direct_entry_denied": entry_blocked}
        passed = all(results.values())
        print(json.dumps({"schema": "greyward.authentication-boundary-probe/v1", "uid": 1002,
                          "checks": results, "passed": passed, "coverage": "UNKNOWN"}), flush=True)
        if not passed:
            raise RuntimeError("Authentication boundary failed")
    finally:
        os.close(handle)


if __name__ == "__main__":
    if sys.platform != "linux" or os.getuid() != 1002 or os.geteuid() != 1002 or sys.argv[1:] not in [["--host"], ["--reader"]]:
        raise RuntimeError("Fixed separate-account fixture only")
    (host if sys.argv[1] == "--host" else reader)()
