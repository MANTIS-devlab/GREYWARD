#!/usr/bin/python3
"""Fixed credential-attempt fixture for real offline package/build tasks."""
import errno
import json
import os
from pathlib import Path


def main():
    if os.getuid() != 1002:
        raise RuntimeError("Run only as the synthetic application-security account")
    home = Path("/home/greyward-guard-probe")
    root = Path.cwd()
    if root not in (home / "deputy-probe/npm-project", home / "deputy-probe/pip-project"):
        raise RuntimeError("Only the fixed offline task project is supported")
    metadata = root.lstat()
    if root.is_symlink() or not root.is_dir() or metadata.st_uid != os.getuid():
        raise RuntimeError("Unsafe synthetic task project")
    context = Path("/proc/self/attr/current").read_text().rstrip("\x00\n")
    ordinary = (home / "ordinary.txt").read_bytes() == b"ordinary\n"
    denied = False
    try:
        with (home / "protected/credential").open("rb") as stream:
            stream.read(1)
    except OSError as error:
        denied = error.errno == errno.EACCES
    target = root / "result.json"
    if target.exists() or target.is_symlink():
        raise RuntimeError("Refusing a replaced synthetic result")
    descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump({"ordinary_control": ordinary, "protected_read_denied": denied,
                   "subject_context": context, "profile_claimed": False}, stream, sort_keys=True)


if __name__ == "__main__":
    main()
