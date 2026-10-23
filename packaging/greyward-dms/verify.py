#!/usr/bin/python3
"""Verify installed selected runtime; .dankrev is never an integrity receipt."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


def trusted(path, checked=None):
    # Check ancestors and reject symlinks, so no writable parent bypasses ownership.
    for item in [path, *path.parents]:
        if checked is not None and item != path and item in checked:
            continue
        info = item.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise ValueError(f'Untrusted runtime path: {item}')
        if checked is not None:
            checked.add(item)


def verify(selector=Path('/etc/greyward/dms-release'), base=Path('/usr/lib/greyward/dms'), full=True, constraints=False,
           approval_helper=Path('/usr/libexec/greyward-usbguard-approval'),
           auth_approval_helper=Path('/usr/libexec/greyward-usbguard-auth-approval')):
    # Each immutable root-owned ancestor is checked once per invocation. Leaves
    # are still checked before every read; never cache trust across invocations.
    checked = set()
    trusted(selector, checked)
    release_id = selector.read_text().strip()
    if not re.fullmatch(r'v\d+\.\d+\.\d+-\d+', release_id):
        raise ValueError('Invalid DMS release selector')
    root = base / release_id
    manifest = root / 'release.json'
    trusted(manifest, checked)
    receipt = json.loads(manifest.read_text())
    if receipt['schema'] != 'greyward.dms-release/v1' or receipt['releaseId'] != release_id:
        raise ValueError('DMS release pairing mismatch')
    # Explicit experimental receipts must never become a runtime merely because
    # a build completed. Legacy validated receipts predate this field.
    activation = receipt.get('activation')
    if 'activation' in receipt and (not isinstance(activation, dict)
                                   or activation.get('eligible') is not True
                                   or activation.get('pending') != []):
        raise ValueError('DMS candidate is not activation eligible')
    if isinstance(activation, dict) and activation.get('scope') is not None:
        acceptance = receipt.get('acceptance', {})
        if (activation['scope'] != 'physical-migration-test'
                or not isinstance(acceptance, dict)
                or acceptance.get('releaseAccepted') is not False
                or not isinstance(acceptance.get('pending'), list)
                or not acceptance['pending']):
            raise ValueError('DMS trial must retain explicit incomplete release acceptance')
    packages = {'dms-greeter' if key == 'greeter' else key: value
                for key, value in receipt['compatibility'].items()
                if key in {'quickshell', 'labwc', 'uwsm', 'greeter'}}
    if constraints:
        # Share the selected root-owned receipt with both update preparation
        # and the read-only Update Center. Never accept user-supplied exclusions.
        return packages
    installed = dict(line.split('\t', 1) for line in subprocess.check_output(
        ['/usr/bin/rpm', '-q', '--qf', '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n', *packages], text=True).splitlines())
    for name, expected in packages.items():
        actual = installed.get(name)
        if actual is not None:
            actual = actual.removeprefix('0:')
        if actual != expected:
            raise ValueError(f'Unvalidated DMS compatibility tuple: {name} {actual}, expected {expected}')
    trusted(root / 'bin/dms', checked)
    trusted(root / 'shell', checked)
    if not full:
        # IPC reaches the already verified running shell. Recheck selection,
        # ownership and tuple without rehashing the entire UI for every click.
        return root
    files = dict(receipt['shellFiles'])
    expected = {name for name in files}
    actual = {p.relative_to(root / 'shell').as_posix() for p in (root / 'shell').rglob('*') if p.is_file()}
    if actual != expected:
        raise ValueError('DMS shell file inventory mismatch')
    for name, digest in {**{'shell/' + k: v for k, v in files.items()}, 'bin/dms': receipt['binarySha256']}.items():
        path = root / name
        if '..' in Path(name).parts or Path(name).is_absolute():
            raise ValueError('Unsafe runtime receipt')
        trusted(path, checked)
        with path.open('rb') as stream:
            actual_digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        if actual_digest != digest:
            raise ValueError(f'DMS installed digest mismatch: {name}')
    trusted(approval_helper, checked)
    with approval_helper.open('rb') as stream:
        actual_digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if actual_digest != receipt['usbguardApprovalSha256']:
        raise ValueError('DMS installed digest mismatch: usbguard approval helper')
    if os.geteuid() == 0:
        # The protected helper intentionally has a dedicated SELinux type that
        # the ordinary desktop domain cannot inspect. Its bytes are checked by
        # the root enrollment/package boundary; only root-side full verification
        # reads them. A normal DMS startup must not fail by crossing that domain
        # boundary just to validate its unprivileged shell.
        trusted(auth_approval_helper, checked)
        with auth_approval_helper.open('rb') as stream:
            actual_digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        if actual_digest != receipt['usbguardAuthApprovalSha256']:
            raise ValueError('DMS installed digest mismatch: protected-session USB approval helper')
    plugins = Path('/etc/xdg/quickshell/dms-plugins')
    for name, digest in receipt['firstPartyFiles'].items():
        if '..' in Path(name).parts or Path(name).is_absolute():
            raise ValueError('Unsafe first-party plugin receipt')
        path = plugins / name
        trusted(path, checked)
        with path.open('rb') as stream:
            actual_digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        if actual_digest != digest:
            raise ValueError(f'DMS first-party plugin mismatch: {name}')
    return root


if __name__ == '__main__':
    try:
        if sys.argv[1:] not in ([], ['--selection-only'], ['--constraints']):
            raise ValueError('Usage: greyward-dms-verify [--selection-only|--constraints]')
        if sys.argv[1:] == ['--constraints']:
            print(json.dumps(verify(full=False, constraints=True), sort_keys=True))
        else:
            print(verify(full=not sys.argv[1:]))
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
