#!/usr/bin/python3 -I
"""Capture local accounts at Anaconda's completed target boundary, not at login."""
import json
import os
from pathlib import Path
import re


def accounts(passwd):
    result = []
    for line in passwd.splitlines():
        fields = line.split(':')
        if len(fields) != 7 or not fields[2].isdigit() or not fields[3].isdigit():
            continue
        name, _, uid, gid, _, home, shell = fields
        uid, gid = int(uid), int(gid)
        if 1000 <= uid < 60000 and 1000 <= gid < 60000 and re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', name) and home == '/home/' + name and shell in {'/bin/bash','/usr/bin/bash','/bin/zsh','/usr/bin/zsh','/bin/sh','/usr/bin/sh'}:
            result.append({'name': name, 'uid': uid, 'gid': gid, 'home': home, 'shell': shell})
    if not result or len(result) > 256 or len({r['uid'] for r in result}) != len(result):
        raise RuntimeError('Installer normal-local-account inventory is missing or ambiguous')
    return result


if __name__ == '__main__':
    if os.getuid() or os.geteuid():
        raise RuntimeError('Installer root authority required')
    # Only executed in Anaconda's mounted target, not the development host.
    root = Path('/mnt/sysroot')
    output = root / 'var/lib/greyward/installer/accounts.json'
    payload = {'schema': 'greyward.installer-accounts/v1', 'accounts': accounts((root / 'etc/passwd').read_text())}
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(payload, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
