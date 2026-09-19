#!/usr/bin/env python3
"""Render the small GREYWARD startup brief without contacting any provider."""

import os
import platform
import re
import shutil
import socket
import sys
import time
from pathlib import Path


def _runtime_dir():
    value = os.environ.get("XDG_RUNTIME_DIR")
    if value:
        return Path(value)
    uid = getattr(os, "getuid", lambda: None)()
    return Path("/run/user") / str(uid) if uid is not None else Path("/tmp")


def _text(value, fallback="UNKNOWN"):
    value = str(value or "").replace("\n", " ").replace("\r", " ").strip()
    return value[:80] or fallback


def _os_version():
    fields = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator:
                fields[key] = value.strip().strip('"')
    except OSError:
        pass
    name = fields.get("NAME", "Linux")
    version = fields.get("VERSION_ID") or fields.get("VERSION", "unknown")
    version = re.sub(r"[^A-Za-z0-9._ -]", "", version)[:24] or "unknown"
    return f"{name} {version}"


def _uptime():
    try:
        seconds = max(0, int(float(Path("/proc/uptime").read_text().split()[0])))
    except (OSError, ValueError, IndexError):
        return "unknown"
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def _memory():
    values = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, separator, value = line.partition(":")
            if separator:
                values[key] = int(value.strip().split()[0])
    except (OSError, ValueError, IndexError):
        return "unknown"
    total = values.get("MemTotal")
    available = values.get("MemAvailable")
    if not total or available is None:
        return "unknown"
    used = max(0, min(100, round((total - available) * 100 / total)))
    return f"{used}% used"


def _width():
    try:
        return int(os.environ.get("COLUMNS", "")) or shutil.get_terminal_size((80, 24)).columns
    except ValueError:
        return 80


def _fit(value, width):
    value = str(value)
    if len(value) <= width:
        return value.ljust(width)
    if width < 4:
        return value[:width]
    return value[: width - 3] + "..."


def _card(lines, color, width):
    # Keep the card ASCII-only: Black Box can render it correctly before the
    # user's Nerd Font and prompt have finished initializing.
    inner = max(48, min(78, width - 6))
    top = "+-- GREYWARD " + "-" * max(0, inner - 10) + "+"
    body = [f"| {_fit(line, inner)} |" for line in lines]
    bottom = "+" + "-" * (inner + 2) + "+"
    result = [top, *body, bottom]
    if not color:
        return result
    border = "\033[38;5;67m"
    text = "\033[38;5;252m"
    return [
        f"{border}{line}\033[0m" if index in (0, len(result) - 1) else f"{text}{line}\033[0m"
        for index, line in enumerate(result)
    ]


def render(value, color=True, width=80):
    metadata = f"{_os_version()} | kernel {platform.release()}"
    runtime = f"up {_uptime()} | memory {_memory()}"
    shell = os.path.basename(os.environ.get("SHELL", "zsh"))
    host = _text(socket.gethostname(), "unknown")
    if width < 68:
        return "\n".join(
            [
                "+-- GREYWARD --+",
                metadata,
                runtime,
                f"shell {shell} | host {host}",
            ]
        )
    return "\n".join(_card([metadata, runtime, f"shell {shell} | host {host}"], color, width))


def render_compact(value, color=True):
    return "GREYWARD | {} | {} | shell {}".format(
        _os_version(), f"up {_uptime()} / memory {_memory()}", os.path.basename(os.environ.get("SHELL", "zsh"))
    )


def main():
    if not sys.stdout.isatty():
        color = False
    else:
        color = os.environ.get("TERM", "") != "dumb"
    print(render({}, color=color, width=_width()))


if __name__ == "__main__":
    main()
