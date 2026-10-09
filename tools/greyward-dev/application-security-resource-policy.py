#!/usr/bin/python3
"""Fixed synthetic checks for generated labels, not production coverage."""
import errno
import json
import mmap
import os
import pathlib
import select
import stat
import subprocess
import sys
import time

BASE = pathlib.Path('/mnt/greyward-resource-label-probe')
RESOURCE = BASE / 'protected'
EXPECTED_TYPE = 'greyward_as_resource_' + 'd' * 64 + '_t'


def denied(operation):
    try:
        result = operation()
        if isinstance(result, int):
            os.close(result)
    except PermissionError as error:
        if error.errno in (errno.EACCES, errno.EPERM):
            return
        raise
    raise RuntimeError('Expected a mandatory synthetic resource denial')


def subject():
    if os.getuid() != 1002 or os.geteuid() != 1002:
        raise RuntimeError('Only the owned probe account is supported')
    context = pathlib.Path('/proc/self/attr/current').read_text().strip('\0\n')
    if context != 'greyward_guard_u:greyward_guard_r:greyward_guard_t:s0':
        raise RuntimeError('Missing mandatory probe domain')


def held_descriptor():
    subject()
    descriptor = os.open(BASE / 'late-file', os.O_RDONLY | os.O_CLOEXEC)
    try:
        identity = os.fstat(descriptor)
        if os.read(descriptor, 1) != b's':
            raise RuntimeError('Synthetic descriptor read positive control failed')
        os.lseek(descriptor, 0, os.SEEK_SET)
        with mmap.mmap(descriptor, 0, flags=mmap.MAP_PRIVATE, prot=mmap.PROT_READ) as mapping:
            if mapping[:1] != b's':
                raise RuntimeError('Synthetic mmap positive control failed')
        with mmap.mmap(descriptor, 0, flags=mmap.MAP_PRIVATE, prot=0):
            pass
        print(f'RESOURCE_FD_READY={identity.st_dev}:{identity.st_ino}', flush=True)
        if sys.stdin.readline(32) != 'CHECK\n':
            raise RuntimeError('Missing fixed descriptor-check handshake')
        if os.getxattr(descriptor, 'security.selinux').decode().strip('\0').split(':')[2] != EXPECTED_TYPE:
            raise RuntimeError('Held descriptor label readback failed')
        denied(lambda: os.read(descriptor, 1))
        for protection in (mmap.PROT_READ, 0):
            denied(lambda p=protection: mmap.mmap(descriptor, 0, flags=mmap.MAP_PRIVATE, prot=p))
        print(json.dumps({'schema': 'greyward.application-security.resource-fd-probe/v1',
                          'passed': True, 'positive_read_and_mmap': True,
                          'read_denied': True, 'read_mmap_denied': True,
                          'prot_none_mmap_denied': True, 'contents_logged': False}), flush=True)
    finally:
        os.close(descriptor)


def coordinate_descriptor(fixture_text):
    if os.getuid() != 0 or os.geteuid() != 0:
        raise RuntimeError('Private root development coordinator required')
    fixture = pathlib.Path(fixture_text)
    state = pathlib.Path('/var/lib/greyward-development/application-security')
    if fixture.parent != state or not fixture.name.startswith('resource-policy.') or fixture.resolve() != fixture:
        raise RuntimeError('Unexpected private synthetic fixture')
    for directory in (fixture, state):
        identity = directory.lstat()
        if not stat.S_ISDIR(identity.st_mode) or identity.st_uid != 0 or stat.S_IMODE(identity.st_mode) != 0o700:
            raise RuntimeError('Unsafe private root receipt')
    descriptor = os.open(fixture / 'home/late-file', os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    child = None
    try:
        identity = os.fstat(descriptor)
        if not stat.S_ISREG(identity.st_mode) or identity.st_uid != 1002 or identity.st_nlink != 1:
            raise RuntimeError('Invalid fixed descriptor fixture')
        child = subprocess.Popen([
            '/usr/bin/systemd-run', '--wait', '--pipe', '--collect', '--unit=greyward-appsec-resource-fd-probe',
            '-p', 'RuntimeMaxSec=30', '-p', 'MemoryMax=128M', '-p', 'CPUQuota=100%', '-p', 'TasksMax=32',
            '-p', 'User=greyward-guard-probe', '-p', 'Group=greyward-guard-probe',
            '-p', 'SELinuxContext=greyward_guard_u:greyward_guard_r:greyward_guard_t:s0',
            '-p', 'NoNewPrivileges=yes', '-p', 'CapabilityBoundingSet=', '-p', 'PrivateNetwork=yes',
            '-p', 'PrivateMounts=yes', '-p', 'PrivateTmp=yes', '-p', 'ProtectSystem=strict',
            '-p', f'BindPaths={fixture}/home:/mnt/greyward-resource-label-probe',
            '/usr/bin/python3', '-I', '/usr/local/libexec/greyward-application-security-resource-policy-probe',
            '--held-descriptor'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ready = bytearray()
        deadline = time.monotonic() + 15
        while b'\n' not in ready and time.monotonic() < deadline:
            if select.select([child.stdout], [], [], 0.1)[0]:
                chunk = os.read(child.stdout.fileno(), 4096)
                if not chunk:
                    break
                ready.extend(chunk)
                if len(ready) > 4096:
                    raise RuntimeError('Oversized readiness metadata')
        expected = f'RESOURCE_FD_READY={identity.st_dev}:{identity.st_ino}\n'.encode()
        if bytes(ready) != expected:
            _, errors = child.communicate(timeout=5)
            print(errors[-2048:].decode(errors='replace'), file=sys.stderr)
            raise RuntimeError('Held object was not confirmed by the fixed subject')
        context = os.getxattr(descriptor, 'security.selinux').decode().strip('\0').split(':')
        if context[2] != 'user_home_t':
            raise RuntimeError('Descriptor positive setup has an unexpected label')
        context[2] = EXPECTED_TYPE
        # Label the held inode, not a path supplied by the child.
        os.setxattr(descriptor, 'security.selinux', (':'.join(context) + '\0').encode())
        output, errors = child.communicate(b'CHECK\n', timeout=15)
        if child.returncode != 0:
            print(errors[-2048:].decode(errors='replace'), file=sys.stderr)
            raise RuntimeError('Held descriptor/read/mmap checks failed')
        result = json.loads(output)
        if any(result.get(field) is not True for field in [
                'passed', 'positive_read_and_mmap', 'read_denied',
                'read_mmap_denied', 'prot_none_mmap_denied']):
            raise RuntimeError('Missing descriptor denial result')
        print(json.dumps(result))
    finally:
        subprocess.run(['/usr/bin/systemctl', 'stop', 'greyward-appsec-resource-fd-probe.service'], capture_output=True, timeout=5, check=False)
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        os.close(descriptor)


def coordinate_policy(fixture_text):
    if os.getuid() != 0 or os.geteuid() != 0:
        raise RuntimeError('Root development coordinator required')
    fixture = pathlib.Path(fixture_text)
    state = pathlib.Path('/var/lib/greyward-development/application-security')
    if fixture.parent != state or not fixture.name.startswith('resource-policy.') or fixture.resolve() != fixture:
        raise RuntimeError('Unexpected private policy fixture')
    for directory in (fixture, state):
        identity = directory.lstat()
        if not stat.S_ISDIR(identity.st_mode) or identity.st_uid != 0 or stat.S_IMODE(identity.st_mode) != 0o700:
            raise RuntimeError('Unsafe private policy receipt')
    child = subprocess.Popen([
        '/usr/bin/systemd-run', '--wait', '--pipe', '--collect', '--unit=greyward-appsec-policy-lifecycle-child',
        '-p', 'RuntimeMaxSec=30', '-p', 'MemoryMax=64M', '-p', 'CPUQuota=100%', '-p', 'TasksMax=16',
        '/usr/local/libexec/greyward-application-security-policy-readback-probe',
        '--check-development-lifecycle'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        ready = bytearray()
        deadline = time.monotonic() + 5
        while b'\n' not in ready and time.monotonic() < deadline:
            if select.select([child.stdout], [], [], 0.1)[0]:
                chunk = os.read(child.stdout.fileno(), 4096)
                if not chunk:
                    break
                ready.extend(chunk)
                if len(ready) > 4096:
                    raise RuntimeError('Oversized lifecycle handshake')
        if bytes(ready) != b'POLICY_READBACK_READY\n':
            _, errors = child.communicate(timeout=5)
            print(errors[-2048:].decode(errors='replace'), file=sys.stderr)
            raise RuntimeError('Live kernel receipt was not established')
        # Only this root-private synthetic tree and the exact development module
        # installed by the enclosing tool are changed.
        subprocess.run(['/usr/sbin/restorecon', '-R', str(fixture)], capture_output=True, timeout=5, check=True)
        subprocess.run(['/usr/sbin/semodule', '-r', 'greyward_resource_label_probe'], capture_output=True, timeout=15, check=True)
        output, errors = child.communicate(b'CHECK\n', timeout=5)
        if child.returncode != 0:
            print(errors[-2048:].decode(errors='replace'), file=sys.stderr)
            raise RuntimeError('Cached kernel receipt survived policy removal')
        result = json.loads(output)
        if result.get('policy_removal_invalidates_cached_readback') is not True:
            raise RuntimeError('Missing actual policy-removal denial')
        print(json.dumps(result))
    finally:
        subprocess.run(['/usr/bin/systemctl', 'stop', 'greyward-appsec-policy-lifecycle-child.service'], capture_output=True, timeout=5, check=False)
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)


def main():
    subject()
    control = BASE / 'ordinary.txt'
    control.write_text('ordinary synthetic control')
    if control.read_text() != 'ordinary synthetic control':
        raise RuntimeError('Ordinary file control failed')
    checks = 1
    for name in ['initial', 'new-file', 'atomic']:
        path = RESOURCE / name
        if os.getxattr(path, 'security.selinux').decode().strip('\0').split(':')[2] != EXPECTED_TYPE:
            raise RuntimeError('Generated resource label readback failed')
        if path.stat().st_uid != 1002:
            raise RuntimeError('Synthetic resource must be owned by the subject')
        for flags in [os.O_RDONLY, os.O_WRONLY, os.O_WRONLY | os.O_APPEND]:
            denied(lambda p=path, f=flags: os.open(p, f | os.O_CLOEXEC))
            checks += 1
    for name in ['symlink', 'hardlink', 'bound-alias']:
        denied(lambda p=BASE / name: os.open(p, os.O_RDONLY | os.O_CLOEXEC))
        checks += 1
    denied(lambda: os.open(RESOURCE / 'created-by-ordinary', os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600))
    denied(lambda: os.unlink(RESOURCE / 'initial'))
    denied(lambda: os.link(RESOURCE / 'initial', BASE / 'created-hardlink'))
    denied(lambda: os.replace(control, RESOURCE / 'atomic'))
    checks += 4
    result = subprocess.run(['/usr/bin/chcon', '-t', 'user_home_t', str(RESOURCE / 'initial')], capture_output=True, timeout=3, check=False)
    if result.returncode == 0:
        raise RuntimeError('Ordinary subject removed protected labeling')
    if not control.exists() or not (RESOURCE / 'initial').exists():
        raise RuntimeError('A refused operation mutated its source')
    print(json.dumps({'schema': 'greyward.application-security.resource-policy-probe/v1',
                      'passed': True, 'checks': checks + 1, 'generated_label_readback': True,
                      'new_file_and_atomic_labels': True, 'production_coverage_claimed': False}))


if __name__ == '__main__':
    if sys.argv[1:] == ['--held-descriptor']:
        held_descriptor()
    elif len(sys.argv) == 3 and sys.argv[1] == '--coordinate-descriptor':
        coordinate_descriptor(sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == '--coordinate-policy':
        coordinate_policy(sys.argv[2])
    elif len(sys.argv) == 1:
        main()
    else:
        raise RuntimeError('Only fixed development probe modes are supported')
