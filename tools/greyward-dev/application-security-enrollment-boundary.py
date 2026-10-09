#!/usr/bin/python3 -I
"""Synthetic sibling-process probe, isolated UID 1002 only; changes no policy.

An allowed result demonstrates the inherited policy gap. A denied result with
self-context read unavailable demonstrates why blanket same-domain denial is
not a compatible production fix. Neither result establishes session coverage.
"""
import ctypes
import errno
import json
import os
from pathlib import Path
import signal
import sys
import time

MARKER = b"GREYWARD_SYNTHETIC_AUTH_SENTINEL"


class Iovec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]


def reader(pid, descriptor, address, size, expected):
    context = "UNAVAILABLE"
    try:
        context = Path("/proc/self/attr/current").read_text().strip("\0\n")
    except PermissionError:
        pass
    pipe_allowed = False
    pipe_error = 0
    try:
        opened = os.open(f"/proc/{pid}/fd/{descriptor}", os.O_RDONLY | os.O_NONBLOCK)
        try:
            pipe_allowed = os.read(opened, 128) == MARKER
        finally:
            os.close(opened)
    except OSError as error:
        pipe_error = error.errno
    buffer = ctypes.create_string_buffer(size)
    local = Iovec(ctypes.addressof(buffer), size)
    remote = Iovec(address, size)
    library = ctypes.CDLL(None, use_errno=True)
    library.process_vm_readv.restype = ctypes.c_ssize_t
    count = library.process_vm_readv(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
    memory_error = ctypes.get_errno() if count < 0 else 0
    memory_allowed = count == size and buffer.value == MARKER
    if expected == "--expect-allowed":
        passed = pipe_allowed and memory_allowed and context != "UNAVAILABLE"
    else:
        passed = (not pipe_allowed and pipe_error in {errno.EACCES, errno.EPERM}
                  and not memory_allowed and memory_error in {errno.EACCES, errno.EPERM}
                  and context == "UNAVAILABLE")
    print(json.dumps({"schema": "greyward.enrollment-boundary-probe/v1",
                      "scope": "synthetic same-UID sibling memory and pipe only",
                      "uid": os.getuid(), "context": context,
                      "foreign_pipe_read": pipe_allowed, "pipe_errno": pipe_error,
                      "same_domain_memory_read": memory_allowed, "memory_errno": memory_error,
                      "expected": expected, "passed": passed, "coverage": "UNKNOWN"}), flush=True)
    return 0 if passed else 1


def main():
    if sys.platform != "linux" or os.getuid() != 1002 or os.geteuid() != 1002:
        raise RuntimeError("Only the isolated UID-1002 Linux fixture is supported")
    if len(sys.argv) != 2 or sys.argv[1] not in {"--expect-allowed", "--expect-denied"}:
        raise RuntimeError("Choose the expected fixture result explicitly")
    control_read, control_write = os.pipe()
    victim = os.fork()
    if victim == 0:
        os.close(control_read)
        pipe_read, pipe_write = os.pipe()
        marker = ctypes.create_string_buffer(MARKER)
        os.write(pipe_write, MARKER)
        os.write(control_write, json.dumps([os.getpid(), pipe_read,
                                           ctypes.addressof(marker), len(marker)]).encode())
        os.close(control_write)
        time.sleep(10)
        os._exit(0)
    os.close(control_write)
    try:
        identity = json.loads(os.read(control_read, 1024))
        os.close(control_read)
        sibling = os.fork()
        if sibling == 0:
            os._exit(reader(*identity, sys.argv[1]))
        _, status = os.waitpid(sibling, 0)
        return os.waitstatus_to_exitcode(status)
    finally:
        try:
            os.kill(victim, signal.SIGTERM)
        except ProcessLookupError:
            pass
        os.waitpid(victim, 0)


if __name__ == "__main__":
    raise SystemExit(main())
