#!/usr/bin/env python3
"""Build the small, signature-verified GREYWARD Swappy adaptation as an ordinary user."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import urllib.request

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--inputs', type=Path, help='Optional directory containing the two upstream release files')
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error('Use an unprivileged package builder')
    manifest = json.loads((HERE / 'source.json').read_text())
    if hashlib.sha256((HERE / 'greyward-window.patch').read_bytes()).hexdigest() != manifest['patchSha256']:
        parser.error('Patch changed without refreshing source.json')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    for name in ('BUILD', 'BUILDROOT', 'SOURCES', 'SPECS', 'RPMS', 'SRPMS'):
        (output / name).mkdir()
    for name, expected in manifest['inputs'].items():
        local = HERE / name if name.endswith('.gpg') else (args.inputs / name if args.inputs else None)
        if local is not None:
            data = local.read_bytes()
        else:
            url = 'https://github.com/jtheoof/swappy/releases/download/v1.5.1/' + name
            with urllib.request.urlopen(url, timeout=60) as response:
                data = response.read(4 * 1024 * 1024)
        if hashlib.sha256(data).hexdigest() != expected:
            raise SystemExit('Source checksum mismatch: ' + name)
        (output / 'SOURCES' / name).write_bytes(data)
    for name in ('greyward-window.patch', 'source.json'):
        shutil.copyfile(HERE / name, output / 'SOURCES' / name)
    shutil.copyfile(HERE / 'swappy.spec', output / 'SPECS/swappy.spec')
    subprocess.run(['rpmbuild', '--define', '_topdir ' + str(output), '-ba', str(output / 'SPECS/swappy.spec')], check=True)


if __name__ == '__main__':
    main()
