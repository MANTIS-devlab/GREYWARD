"""Selected desktop constraints shared by read-only and privileged updates."""
import json
from pathlib import Path
import re
import subprocess

VERIFIER = Path('/usr/libexec/greyward-dms-verify')
NAMES = frozenset(('quickshell', 'labwc', 'uwsm', 'dms-greeter'))


def constraints():
    if not Path('/etc/greyward/dms-release').exists():
        return {}  # Security Center also runs outside a GREYWARD desktop.
    result = subprocess.run([str(VERIFIER), '--constraints'], check=True,
                            capture_output=True, text=True, timeout=15)
    values = json.loads(result.stdout)
    if (not isinstance(values, dict) or set(values) != NAMES or
            any(not isinstance(v, str) or not re.fullmatch(r'[A-Za-z0-9.+_:~-]+', v)
                for v in values.values())):
        raise ValueError('Invalid selected DMS compatibility policy')
    return values


def dnf_options():
    # A new tuple is delivered and tested with a new runtime RPM. General
    # updates retain this tuple instead of breaking the next graphical login.
    values = constraints()
    return ['--exclude=' + ','.join(sorted(values))] if values else []
