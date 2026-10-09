#!/usr/bin/python3
"""Root-only, disposable Flatpak subject bootstrap; no grants or approvals.

Runs only a system Flatpak runtime's /usr/bin/true on the existing synthetic
account. Does not run the application UI, touch its profile, or attach to the
normal desktop. A bootstrap PASS is not either product feasibility gate.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import tempfile
import time

MODULE = 'greyward_hybrid_flatpak_probe'
SUBJECT = 'system_u:system_r:greyward_hybrid_flatpak_probe_t:s0'
STATE = 'system_u:object_r:greyward_hybrid_flatpak_state_t:s0'
CODE = 'system_u:object_r:greyward_hybrid_flatpak_code_t:s0'
APP = 'com.collaboraoffice.Office'


def run(argv, *, cwd=None, timeout=60):
    result = subprocess.run(argv, cwd=cwd, capture_output=True, text=True,
                            timeout=timeout, env={**os.environ, 'LC_ALL': 'C'})
    return {'code': result.returncode, 'stdout': result.stdout[-32768:],
            'stderr': result.stderr[-32768:]}


def checked(argv, **kwargs):
    value = run(argv, **kwargs)
    if value['code']:
        raise RuntimeError(f'{argv[0]} failed: {value}')
    return value['stdout']


def managed_code(application, base):
    """Bounded root system-deployment copy, requiring Btrfs-style reflinks.

    This is preparation evidence, not a reviewed application identity. An
    actual provider must retain/revalidate descriptor-bound generations and
    validate extensions before reusing a grant.
    """
    info = ['flatpak', 'info', '--system']
    runtime = checked([*info, '--show-runtime', application]).strip()
    values = {}
    for name, reference in (('app', application), ('runtime', runtime)):
        location = Path(checked([*info, '--show-location', reference]).strip())
        location = location.resolve(strict=True)
        if not str(location).startswith('/var/lib/flatpak/'):
            raise RuntimeError('Only the pinned system installation is supported')
        files = location / 'files'
        count = 0
        # Symlinks remain symlinks; no host target is followed or copied.
        for directory, dirs, entries in os.walk(files, followlinks=False):
            for entry in [Path(directory), *(Path(directory) / n for n in dirs + entries)]:
                count += 1
                meta = entry.lstat()
                if count > 100000 or meta.st_uid != 0 or (not entry.is_symlink() and meta.st_mode & 0o022):
                    raise RuntimeError('Mutable/unowned or oversized code input')
        destination = base / ('code-' + name)
        checked(['cp', '--reflink=always', '-a', str(files), str(destination)], timeout=60)
        checked(['chcon', '-R', '-h', CODE, str(destination)])
        values[name] = {'path': str(destination), 'source': str(location),
                        'commit': checked([*info, '--show-commit', reference]).strip(),
                        'entries_checked': count}
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('policy', type=Path)
    parser.add_argument('receipt', type=Path)
    parser.add_argument('--app', default=APP)
    args = parser.parse_args()
    if len(args.app) > 255 or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*){2,}', args.app):
        parser.error('A bounded system Flatpak application ID is required')
    if os.geteuid() != 0 or checked(['getenforce']).strip() != 'Enforcing':
        parser.error('Root and SELinux Enforcing required')
    account = pwd.getpwnam('greyward-guard-probe')
    if account.pw_uid != 1002 or account.pw_dir != '/home/greyward-guard-probe':
        parser.error('Existing synthetic account identity changed')
    if MODULE in checked(['semodule', '-l']).split():
        parser.error('Existing experiment module; refuse to overwrite')
    output = args.receipt.absolute()
    if output.exists() or not output.parent.is_dir():
        parser.error('Receipt must have an existing parent and not exist')
    source = args.policy.resolve(strict=True).read_bytes()
    start = int(time.time())
    receipt = {'schema': 'greyward.hybrid-flatpak-bootstrap/v1',
               'policy_sha256': hashlib.sha256(source).hexdigest(),
               'gates': {'A': 'NOT DEMONSTRATED', 'B': 'NOT DEMONSTRATED'},
               'approval_performed': False, 'protected_access_added': False}
    installed = False
    launched = False
    unit = f'greyward-hybrid-bootstrap-{start}.service'
    # Failed cleanup must leave the fixture available for root inspection;
    # never implicitly delete code/state while a test workload could be live.
    with tempfile.TemporaryDirectory(prefix='greyward-hybrid-', dir='/var/tmp', delete=False) as build:
        base = Path(build)
        (base / (MODULE + '.te')).write_bytes(source)
        (base / (MODULE + '.if')).write_text('')
        (base / (MODULE + '.fc')).write_text('')
        receipt['compile'] = run(['make', '-f', '/usr/share/selinux/devel/Makefile',
                                  MODULE + '.pp'], cwd=base, timeout=180)
        if receipt['compile']['code']:
            output.write_text(json.dumps(receipt, indent=2) + '\n')
            os.chmod(output, 0o600)
            shutil.rmtree(base)
            return 1
        try:
            # Mark attempted before installation: even a timeout must trigger
            # removal; this never overwrites a pre-existing module.
            installed = True
            checked(['semodule', '-i', str(base / (MODULE + '.pp'))], timeout=180)
            home = base / 'home'
            runtime = base / 'runtime'
            for path in (home, runtime):
                path.mkdir(mode=0o700)
                os.chown(path, account.pw_uid, account.pw_gid)
                checked(['chcon', STATE, str(path)])
            # The parent is newly created fixture data, never an existing home.
            os.chmod(base, 0o711)
            checked(['chcon', STATE, str(base)])
            commit = checked(['flatpak', 'info', '--system', '--show-commit', args.app]).strip()
            receipt['deployment'] = commit
            receipt['application'] = args.app
            receipt['managed_code'] = managed_code(args.app, base)
            launched = True
            receipt['launch'] = run([
                'systemd-run', '--quiet', '--wait', '--unit=' + unit,
                '-p', 'User=1002', '-p', 'Group=1002',
                '-p', 'SELinuxContext=' + SUBJECT,
                '-p', 'NoNewPrivileges=yes', '-p', 'PrivateTmp=yes',
                '-p', 'BindPaths=' + str(base),
                '-p', 'KillMode=control-group', '-p', 'TimeoutStartSec=20',
                '-p', 'TimeoutStopSec=2', '-p', 'StandardOutput=null',
                '-p', 'StandardError=null',
                '-p', 'RuntimeMaxSec=20', '-p', 'MemoryMax=512M',
                '-p', 'CPUQuota=100%',
                '--setenv=HOME=' + str(home), '--setenv=XDG_RUNTIME_DIR=' + str(runtime),
                '/usr/bin/flatpak', 'run', '--system', '--commit=' + commit,
                '--runtime-commit=' + receipt['managed_code']['runtime']['commit'],
                '--app-path=' + receipt['managed_code']['app']['path'],
                '--usr-path=' + receipt['managed_code']['runtime']['path'],
                '--sandbox', '--no-session-bus', '--no-a11y-bus',
                '--no-documents-portal', '--unshare=network',
                '--command=/usr/bin/true', args.app], timeout=35)
        except (RuntimeError, subprocess.TimeoutExpired) as error:
            receipt['error'] = str(error)
        finally:
            receipt['stop'] = run(['systemctl', 'stop', unit])
            state = run(['systemctl', 'show', unit, '-p', 'ActiveState', '--value'])['stdout'].strip()
            pid = run(['systemctl', 'show', unit, '-p', 'MainPID', '--value'])['stdout'].strip()
            idle = not launched or (receipt['stop']['code'] == 0 and state in ('inactive', 'failed') and pid == '0')
            receipt['audit'] = run(['ausearch', '-m', 'AVC,USER_AVC', '-ts',
                                    time.strftime('%H:%M:%S', time.localtime(start)), '-i'])
            receipt['audit']['stdout'] = '\n----\n'.join(
                event for event in receipt['audit']['stdout'].split('----')
                if 'greyward_hybrid_' in event)
            # Remove the experimental labels while their types still exist.
            # Only this new fixture tree is touched; never relabel a user home.
            receipt['restore_fixture_labels'] = run([
                'chcon', '-R', '-h', '-t', 'tmp_t', str(base)]) if idle else {'code': 1}
            restored = receipt['restore_fixture_labels']['code'] == 0
            if installed and idle and restored:
                receipt['remove_module'] = run(['semodule', '-r', MODULE], timeout=180)
            receipt['enforcing_after'] = checked(['getenforce']).strip()
            print(json.dumps(receipt, indent=2), flush=True)
            output.write_text(json.dumps(receipt, indent=2) + '\n')
            os.chmod(output, 0o600)
            if not idle or not restored or receipt.get('remove_module', {}).get('code', 1):
                raise RuntimeError('Cleanup incomplete; retain the fixture/module for root recovery')
            shutil.rmtree(base)
    print(json.dumps({'receipt': str(output), 'gates': receipt['gates'],
                      'launch': receipt.get('launch', {}).get('code')}))
    return 0 if receipt.get('launch', {}).get('code') == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
