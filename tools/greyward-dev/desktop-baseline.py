#!/usr/bin/env python3
"""Read-only Linux desktop metadata; optional root-only, no-overwrite backup.

Does not contact the user's bus, run a desktop client, collect argv/environment,
or change a service. Backup archives are private, machine-local recovery data.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import time


PACKAGES = ('greyward-dms', 'greyward-files', 'greyward-session',
            'greyward-security-center', 'greyward-security-context',
            'greyward-application-security-experimental', 'greyward-application-enrollment',
            'quickshell', 'labwc', 'qt6-qtbase', 'qt6-qtdeclarative', 'danksearch', 'uwsm')
SERVICES = ('greetd', 'usbguard', 'polkit', 'firewalld',
            'greyward-application-security-workflows')
RECOVERY_PATHS = ('etc/greyward', 'etc/greetd', 'etc/pam.d/greyward-dms-lock',
                  'etc/systemd/system/greetd.service.d', 'etc/xdg/quickshell/dms-plugins',
                  'etc/selinux/targeted', 'var/lib/selinux/targeted', 'usr/lib/greyward/dms',
                  'usr/lib/greyward/application-security/desktop',
                  'usr/share/greyward/dms', 'usr/share/greyward/dms-greeter-ui',
                  'usr/share/greyward/files', 'var/lib/greyward/application-security')


def command(argv):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False)
        return {'exit': result.returncode, 'out': result.stdout.strip(), 'error': result.stderr.strip()}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'exit': None, 'out': '', 'error': type(error).__name__}


def capture():
    outputs = {}
    for connector in sorted(Path('/sys/class/drm').glob('card*-*')):
        try:
            outputs[connector.name] = (connector / 'status').read_text().strip()
        except OSError:
            pass
    selector = Path('/etc/greyward/dms-release')
    return {'schema': 'greyward.desktop-baseline/v1', 'captured_at': int(time.time()),
            'scope': 'installed metadata only; no visual, performance or security acceptance',
            'selinux': command(['getenforce']),
            'packages': command(['rpm', '-q', '--qf', '%{NEVRA}\n', *PACKAGES]),
            'rpm_verification': command(['rpm', '-V', 'greyward-dms', 'greyward-files', 'greyward-session']),
            'services': {name: command(['systemctl', 'show', name, '-p', 'ActiveState', '-p', 'SubState', '-p', 'Result'])
                         for name in SERVICES},
            'outputs': outputs, 'selected_release': selector.read_text().strip() if selector.exists() else None}


def private_directory(destination):
    destination = Path(destination)
    # No exist_ok: never reuse an old backup or follow its symlink.
    destination.mkdir(mode=0o700)
    info = destination.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('Backup directory must be private and owned by the caller')
    return destination


def backup(destination, uid, root=Path('/')):
    if os.geteuid() != 0:
        raise PermissionError('Recovery backup requires root')
    destination = private_directory(destination)
    import pwd
    account = pwd.getpwuid(uid)
    home = Path(account.pw_dir)
    if uid <= 0 or not home.is_absolute() or home.is_symlink() or home.stat().st_uid != uid:
        raise ValueError('Explicit ordinary account with an owned real home is required')
    names = list(RECOVERY_PATHS)
    for suffix in ('.config/DankMaterialShell', '.config/dms', '.config/strata',
                   '.config/pcmanfm-qt', '.config/greyward', '.config/mimeapps.list',
                   '.local/state/DankMaterialShell', '.local/state/dms',
                   '.local/share/DankMaterialShell', '.local/share/dms'):
        names.append(str(home / suffix).lstrip('/'))
    present = [name for name in names if (root / name).exists() or (root / name).is_symlink()]
    # Native tar retains ACLs, xattrs and SELinux labels. Symlinks are archived,
    # never dereferenced; do not include runtime sockets or authentication logs.
    archive = destination / 'recovery.tar'
    subprocess.run(['tar', '--create', '--file', str(archive), '--acls', '--xattrs', '--selinux',
                    '--numeric-owner', '--directory', str(root), '--', *present], check=True)
    os.chmod(archive, 0o600)
    with archive.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    with tarfile.open(archive) as stream:
        if not stream.getmembers():
            raise ValueError('Empty recovery archive')
    result = capture()
    result['backup'] = {'archive': archive.name, 'sha256': digest,
                        'included_roots': present, 'restore_rehearsed': False,
                        'exact_rpm_rollback_available': False,
                        'consistency': 'File archive only; capture a quiescent final snapshot before policy migration.'}
    target = destination / 'baseline.json'
    target.write_text(json.dumps(result, indent=2) + '\n')
    os.chmod(target, 0o600)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backup', type=Path, help='New private recovery directory, never reused')
    parser.add_argument('--uid', type=int, help='Explicit enrolled ordinary UID for backup')
    args = parser.parse_args()
    if args.backup and args.uid is None:
        parser.error('--backup requires --uid')
    result = backup(args.backup, args.uid) if args.backup else capture()
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
