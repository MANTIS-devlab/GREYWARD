#!/usr/bin/python3
"""Initialize MailCraft's appearance when the profile has no preferences."""

import os
import sys
import tempfile
from pathlib import Path

DEFAULTS = b'{"theme":"dark","darkStyle":"neutral","accent":"teal"}\n'


def seed_defaults(config):
    folder = config / "mailcraft"
    target = folder / "ui.json"
    if os.path.lexists(target):
        return
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=folder) as pending:
        pending.write(DEFAULTS)
        pending.flush()
        try:
            os.link(pending.name, target)
        except FileExistsError:
            pass


def main():
    try:
        seed_defaults(Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"))
    except OSError as error:
        print(f"MailCraft appearance defaults unavailable: {error}", file=sys.stderr)
    os.execv("/usr/bin/mailcraft", ["/usr/bin/mailcraft", *sys.argv[1:]])


if __name__ == "__main__":
    main()
