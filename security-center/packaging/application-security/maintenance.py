#!/usr/bin/python3 -I
"""Fresh LUKS authentication on an explicitly selected, quiescent boot console.

No daemon, account creation, command arguments, token/cache authentication or
normal-session entry. This file contains no enrollment/policy implementation.
This source supplies console authentication only. Package activation and the
enrollment/repair lifecycle tools remain gated and unimplemented.
"""
from __future__ import annotations

import getpass
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

TARGET = "greyward-maintenance.target"
ENVIRONMENT = {"PATH": "/usr/sbin:/usr/bin", "LANG": "C.UTF-8"}
MAX_OUTPUT = 65536


class Unavailable(RuntimeError):
    """A prerequisite failed; no administrative shell may start."""


def selected_boot(command_line: str) -> bool:
    units = [word for word in command_line.split() if word.startswith("systemd.unit=")]
    return units == [f"systemd.unit={TARGET}"]


def bounded_command(arguments: list[str]) -> str:
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True,
                            env=ENVIRONMENT, check=True, timeout=10)
    if len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT:
        raise Unavailable("System evidence is too large")
    return result.stdout.decode("utf-8", errors="strict")


def ordinary_uid(fields: str) -> bool:
    # All UID forms matter: a setuid-root process retaining an ordinary real
    # UID is still a workload, not an authenticated maintenance subject.
    values = fields.split()
    if len(values) != 4 or any(not value.isdecimal() for value in values):
        raise Unavailable("Process ownership could not be established")
    return any(1000 <= int(value) < 60000 for value in values)


def require_quiescent_boot() -> None:
    if os.getuid() != 0 or os.geteuid() != 0:
        raise Unavailable("Offline maintenance requires root service authority")
    if not selected_boot(Path("/proc/cmdline").read_text()):
        raise Unavailable("Select GREYWARD maintenance explicitly at boot")
    if bounded_command(["/usr/bin/systemctl", "is-active", TARGET]).strip() != "active":
        raise Unavailable("Maintenance target is not active")
    # Do not automatically stop/kill a user's session. Refuse if another target
    # or process was started on what should have been a maintenance-only boot.
    for unit in ("multi-user.target", "graphical.target", "greetd.service"):
        state = bounded_command(["/usr/bin/systemctl", "show", unit,
                                 "--property=ActiveState", "--value"]).strip()
        if state not in {"inactive", "failed"}:
            raise Unavailable("An ordinary login/service target is active")
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            text = (entry / "status").read_text()
        except FileNotFoundError:
            continue
        uid = next((line[4:].strip() for line in text.splitlines()
                    if line.startswith("Uid:")), None)
        if uid is None or ordinary_uid(uid):
            raise Unavailable("Ordinary workloads are present; maintenance refused")


def require_console() -> None:
    expected = Path("/dev/tty1").stat()
    if not stat.S_ISCHR(expected.st_mode) or expected.st_uid != 0:
        raise Unavailable("Trusted virtual console is unavailable")
    if Path("/sys/class/tty/tty0/active").read_text().strip() != "tty1":
        raise Unavailable("Maintenance console is not the active virtual console")
    for descriptor in (0, 1, 2):
        actual = os.fstat(descriptor)
        if not os.isatty(descriptor) or actual.st_rdev != expected.st_rdev:
            raise Unavailable("Streams, PTYs and remote sessions are not maintenance consoles")
    descriptor = os.open("/dev/tty", os.O_RDONLY | os.O_NOCTTY | os.O_CLOEXEC)
    try:
        # /dev/tty's inode device number is the multiplexor, not tty1. Compare
        # the actual controlling/foreground process group instead.
        if os.tcgetpgrp(descriptor) != os.getpgrp() or os.tcgetpgrp(0) != os.getpgrp():
            raise Unavailable("Controlling console does not match")
    finally:
        os.close(descriptor)


def encrypted_root_device(tree: dict) -> tuple[str, str]:
    # lsblk -s supplies the kernel's inverse block-device dependency tree for
    # the mounted root. A similarly named unrelated LUKS device is insufficient.
    devices = tree.get("blockdevices")
    if not isinstance(devices, list) or len(devices) != 1:
        raise Unavailable("Root block-device identity is ambiguous")
    candidates: list[tuple[str, str]] = []
    visited = 0

    def walk(node: dict, encrypted: bool, depth: int) -> None:
        nonlocal visited
        visited += 1
        if depth > 16 or visited > 64 or not isinstance(node, dict):
            raise Unavailable("Unsupported root block-device ancestry")
        encrypted = encrypted or node.get("type") == "crypt"
        if encrypted and node.get("fstype") == "crypto_LUKS":
            path, uuid = node.get("path"), node.get("uuid")
            if not isinstance(path, str) or not re.fullmatch(r"/dev/[A-Za-z0-9_./-]+", path):
                raise Unavailable("Invalid encrypted root-device path")
            if not isinstance(uuid, str) or not re.fullmatch(r"[0-9a-fA-F-]{36}", uuid):
                raise Unavailable("Invalid LUKS root identity")
            candidates.append((path, uuid.lower()))
            # This LUKS container protects the complete dependency branch.
            return
        children = node.get("children", [])
        if not isinstance(children, list):
            raise Unavailable("Unsupported root dependency record")
        if not children:
            raise Unavailable("Unencrypted root dependency is not a recovery credential")
        for child in children:
            walk(child, encrypted, depth + 1)

    walk(devices[0], False, 0)
    candidates = list(dict.fromkeys(candidates))
    if len(candidates) != 1:
        raise Unavailable("A single encrypted root ancestry is required")
    return candidates[0]


def root_device() -> tuple[str, str]:
    mounts = json.loads(bounded_command(["/usr/bin/findmnt", "--json", "--target", "/",
                                       "--output", "SOURCE,FSTYPE,TARGET"]))
    entries = mounts.get("filesystems", [])
    if len(entries) != 1 or entries[0].get("target") != "/":
        raise Unavailable("Mounted root could not be established")
    source = str(entries[0].get("source", "")).split("[", 1)[0]
    if not source.startswith("/dev/"):
        raise Unavailable("Root is not an encrypted block filesystem")
    tree = json.loads(bounded_command(["/usr/bin/lsblk", "--inverse", "--json",
                                      "--output", "PATH,TYPE,FSTYPE,UUID", source]))
    path, uuid = encrypted_root_device(tree)
    actual = Path(path).resolve(strict=True)
    if not actual.is_block_device() or not str(actual).startswith("/dev/"):
        raise Unavailable("Root encryption device was replaced")
    if bounded_command(["/usr/sbin/cryptsetup", "luksUUID", str(actual)]).strip().lower() != uuid:
        raise Unavailable("Root encryption identity changed")
    return str(actual), uuid


def verify_passphrase(device: str, password: str) -> bool:
    if not password or len(password.encode("utf-8")) > 4096 or "\0" in password:
        return False
    # Explicit stdin key bytes override automatic tokens/keyring discovery.
    # Nothing is placed in arguments, environment, files or journal output.
    result = subprocess.run(["/usr/sbin/cryptsetup", "open", "--type", "luks",
                             "--test-passphrase", "--key-file=-", device],
                            input=password.encode("utf-8"), stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, env=ENVIRONMENT, timeout=90, check=False)
    return result.returncode == 0


def main() -> int:
    if len(sys.argv) != 1:
        raise Unavailable("Maintenance accepts no command or execution arguments")
    require_quiescent_boot()
    require_console()
    device, uuid = root_device()
    print("GREYWARD offline administration and recovery.\n"
          "Confirm the installed system's LUKS passphrase to open a root shell.", flush=True)
    authenticated = False
    for _ in range(3):
        require_console()
        password = getpass.getpass("LUKS passphrase: ")
        try:
            authenticated = verify_passphrase(device, password)
        finally:
            del password
        if authenticated:
            break
        print("Authentication failed.", flush=True)
    if not authenticated:
        raise Unavailable("Fresh LUKS authentication was not established")
    require_quiescent_boot()
    require_console()
    if root_device() != (device, uuid):
        raise Unavailable("Encryption identity changed during authentication")
    # No startup files, user bus/display/agent environment or inherited FDs.
    # The root mapping remains Fedora's existing unconfined mapping; ordinary
    # enrolled roles cannot reach this transition or invoke this console.
    environment = dict(ENVIRONMENT, HOME="/root", USER="root", LOGNAME="root",
                       TERM="linux", GREYWARD_MAINTENANCE="authenticated")
    return subprocess.call(["/usr/bin/runcon", "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023",
                            "/usr/bin/bash", "--noprofile", "--norc"], env=environment,
                           close_fds=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Unavailable, OSError, ValueError, subprocess.SubprocessError):
        print("GREYWARD maintenance unavailable. No administrative shell was started.\n"
              "Use trusted installer/rescue media and the existing LUKS credentials.", file=sys.stderr)
        raise SystemExit(1)
