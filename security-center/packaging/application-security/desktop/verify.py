#!/usr/bin/python3 -I
"""Fresh root seat/role readback. Stored admission is only a locator.

No secret contents or process arguments are collected. Any unexpected process,
changed policy/input, missing auth owner or changed login mapping fails closed.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import re
import setools
sys.dont_write_bytecode = True
sys.path.insert(0, '/usr/lib/greyward/application-security/desktop')
from session import BASE, STATE, AUTH_CONTEXT, DISPLAY_CONTEXT, generation, private_file, process


def kernel_decision(subject, target, cls, rights):
    root = Path('/sys/fs/selinux/class') / cls
    index = int((root / 'index').read_text())
    mask = sum(1 << (int((root / 'perms' / r).read_text()) - 1) for r in rights)
    with open('/sys/fs/selinux/access', 'r+') as transaction:
        transaction.write(f'{subject} {target} {index}'); transaction.flush()
        transaction.seek(0)
        fields = transaction.read(128).split()
    if len(fields) != 6 or int(fields[5], 16) != 0 or int(fields[1], 16) & mask != mask:
        raise RuntimeError('Incomplete mandatory kernel decision')
    return int(fields[0], 16) & mask, int(fields[4])


def reviewed_worker(path, uid, context, cgroup):
    """Only a PID-1-created fixed reviewed worker is an admitted exception.

    A context name or ordinary user scope is insufficient. Ordinary subjects
    cannot create/modify this system unit or execute its prepared entrypoint.
    """
    if not re.fullmatch(r'system_u:system_r:greyward_as_grant_[0-9a-f]{64}_t:s0', context):
        return False
    match = re.fullmatch(r'0::/system.slice/(greyward-appsec-launch-[0-9a-f]{32}\.service)', cgroup)
    if not match:
        return False
    result = subprocess.run(['/usr/bin/systemctl', 'show', match[1], '-p', 'MainPID',
        '-p', 'User', '-p', 'SELinuxContext', '-p', 'NoNewPrivileges', '-p', 'PrivateNetwork', '-p', 'ExecStart'],
        capture_output=True, text=True, check=True, timeout=1)
    fields = dict(line.split('=', 1) for line in result.stdout.splitlines())
    return fields['MainPID'] == path.name and fields['User'] == str(uid) and fields['SELinuxContext'] == context and fields['NoNewPrivileges'] == 'yes' and fields['PrivateNetwork'] == 'yes' and 'path=/usr/libexec/greyward-guard-entry ;' in fields['ExecStart']


def ssh_transport(path, context):
    # Fedora retains a dropped-UID SSH transport worker after authenticated PAM
    # admission. It is a fixed root-created service, not a user application or
    # grant-bearing subject; its executed shell must still be in the mapped role.
    if context != 'system_u:system_r:sshd_session_t:s0-s0:c0.c1023' or (path/'exe').resolve() != Path('/usr/libexec/openssh/sshd-session'):
        return False
    parent=Path('/proc')/(path/'stat').read_text().rsplit(')',1)[1].split()[1]
    return parent.stat().st_uid == 0 and (parent/'exe').resolve() == Path('/usr/libexec/openssh/sshd-session') and (parent/'attr/current').read_text().strip('\0\n') == context


def administration_worker(path, uid, context, cgroup):
    """An explicit root-admitted administration exception, never ordinary coverage."""
    if context not in {f'greyward_admin_u:{role}:{domain}:s0' for role,domain in
            [('greyward_admin_r','greyward_admin_t'),('greyward_admin_r','greyward_admin_sudo_t'),
             ('greyward_admin_r','greyward_admin_password_t'),('sysadm_r','sysadm_t')]}:
        return False
    if cgroup != f'0::/system.slice/greyward-admin-{uid}.service':
        return False
    record = json.loads(private_file(STATE/f'admin-{uid}/session.json'))
    terminal = Path('/proc')/str(record['pid'])
    executable=terminal.joinpath('exe').stat()
    if record['uid'] != uid or terminal.stat().st_uid != uid or terminal.joinpath('stat').read_text().rsplit(')',1)[1].split()[19] != record['start'] or terminal.joinpath('attr/current').read_text().strip('\0\n') != 'greyward_admin_u:greyward_admin_r:greyward_admin_t:s0' or record.get('executable') != {'device':executable.st_dev,'inode':executable.st_ino}:
        return False
    if record['namespace'] != path.joinpath('ns/mnt').stat().st_ino or record['namespace'] == Path('/proc/1/ns/mnt').stat().st_ino:
        return False
    return record['manifest'] == hashlib.sha256(private_file(Path('/usr/lib/greyward/application-security/administration/manifest.json'))).hexdigest()


def verify(uid):
    manifest = generation()
    seat = json.loads(private_file(STATE / f'seat-{uid}.json'))
    if seat['uid'] != uid or seat['boot'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip() or seat['manifest'] != hashlib.sha256(private_file(BASE / 'desktop.json', 1024 * 1024)).hexdigest():
        raise RuntimeError('Admission generation changed')
    handles = []
    try:
        handles.append(process(seat['leader'], 0, seat['leader_start']))
        handles.append(process(seat['actor'], uid, seat['actor_start']))
        status = subprocess.run(['/usr/bin/loginctl', 'show-session', seat['session'], '-p', 'User', '-p', 'Leader', '-p', 'Seat', '-p', 'Remote', '-p', 'Class', '-p', 'Active', '-p', 'Scope'], capture_output=True, text=True, check=True, timeout=1)
        fields = dict(line.split('=', 1) for line in status.stdout.splitlines())
        if fields != {'User': str(uid), 'Leader': str(seat['leader']), 'Seat': 'seat0', 'Remote': 'no', 'Class': 'user', 'Active': 'yes', 'Scope': seat['scope']}:
            raise RuntimeError('Seat membership changed')
        for worker in seat['workers']:
            handles.append(process(worker['pid'], uid, worker['start']))
        manager = int(subprocess.check_output(['/usr/bin/systemctl', 'show', f'user@{uid}.service', '-p', 'MainPID', '--value'], timeout=1))
        if Path(f'/proc/{manager}/attr/current').read_text().strip('\0\n') != 'greyward_guard_u:greyward_guard_r:greyward_guard_t:s0':
            raise RuntimeError('User manager is not confined')
        # Query the current policy, not a package's claimed role/type inventory.
        policy = setools.SELinuxPolicy()
        if not policy.mls or Path('/sys/fs/selinux/enforce').read_text().strip() != '1':
            raise RuntimeError('Mandatory enforcement unavailable')
        prepared = json.loads(private_file(BASE / 'ordinary.json'))
        domains = sorted(str(t) for t in policy.lookup_role('greyward_guard_r').types()
                         if any(str(a) == 'domain' for a in t.attributes()))
        ordinary = sorted(str(t) for t in policy.lookup_typeattr('greyward_as_ordinary').expand())
        if domains != prepared['domains'] or ordinary != prepared['ordinary']:
            raise RuntimeError('Ordinary role coverage changed')
        if os.getxattr('/dev/tty1', 'security.selinux').decode().strip('\0') != 'system_u:object_r:greyward_as_seat_tty_t:s0':
            raise RuntimeError('Physical authentication input unavailable')
        sequence = None
        for name in ordinary:
            for target in ['event_device_t', 'mouse_device_t', 'console_device_t', 'greyward_as_seat_tty_t']:
                allowed, seq = kernel_decision(f'greyward_guard_u:greyward_guard_r:{name}:s0',
                    f'system_u:object_r:{target}:s0', 'chr_file', ['open', 'read', 'write', 'ioctl'])
                if allowed or sequence is not None and sequence != seq:
                    raise RuntimeError('Ordinary input authority present')
                sequence = seq
            for role, domain in [('greyward_admin_r','greyward_admin_t'),('greyward_admin_r','greyward_admin_sudo_t'),('greyward_admin_r','greyward_admin_password_t'),('sysadm_r','sysadm_t')]:
                for cls, rights in [('process',['ptrace','signal','sigkill','sigstop','setpgid']),('fd',['use'])]:
                    allowed, seq = kernel_decision(f'greyward_guard_u:greyward_guard_r:{name}:s0',f'greyward_admin_u:{role}:{domain}:s0',cls,rights)
                    if allowed or sequence != seq:
                        raise RuntimeError('Ordinary administration authority present')
            for target,cls,rights in [('greyward_admin_runtime_t','file',['open','read','write']),('greyward_admin_devpts_t','chr_file',['open','read','write','ioctl'])]:
                allowed,seq=kernel_decision(f'greyward_guard_u:greyward_guard_r:{name}:s0',f'system_u:object_r:{target}:s0',cls,rights)
                if allowed or sequence != seq:
                    raise RuntimeError('Ordinary private-terminal authority present')
        mapping = policy.lookup_user('greyward_guard_u')
        if sorted(str(r) for r in mapping.roles) != ['greyward_guard_r']:
            raise RuntimeError('Unexpected user role')
        from ctypes import CDLL, c_char_p, byref
        lib = CDLL('libselinux.so.1')
        seuser, serange = c_char_p(), c_char_p()
        account = manifest['accounts'][str(uid)]
        if lib.getseuserbyname(account['name'].encode(), byref(seuser), byref(serange)) != 0 or seuser.value != b'greyward_guard_u' or serange.value != b's0':
            raise RuntimeError('Login mapping changed')
        CDLL(None).free(seuser); CDLL(None).free(serange)
        ready_path = STATE / f'auth-{uid}/runtime/authentication-ready.json'
        ready = json.loads(private_file(ready_path, 4096, owner=uid))
        stamp = ready_path.stat()
        if ready['schema'] != 'greyward.authentication-readiness/v1' or ready['polkitRegistered'] is not True or stamp.st_uid != uid or not -1 <= time.time() - stamp.st_mtime <= 3:
            raise RuntimeError('Authentication owner unavailable')
        auth_pid = ready['pid']
        if type(auth_pid) != int or Path(f'/proc/{auth_pid}/attr/current').read_text().strip('\0\n') != AUTH_CONTEXT or Path(f'/proc/{auth_pid}/exe').resolve() != BASE / 'bin/qs':
            raise RuntimeError('Authentication executable changed')
        if ready['polkitActive'] is True and ready['exclusiveInput'] is not True:
            raise RuntimeError('Exclusive authentication input unavailable')
        ordinary_contexts = {f'greyward_guard_u:greyward_guard_r:{t}:s0' for t in ordinary}
        observed_display = observed_auth = False
        for path in Path('/proc').iterdir():
            if not path.name.isdecimal():
                continue
            try:
                if path.stat().st_uid != uid:
                    continue
                fd = os.pidfd_open(int(path.name))
            except (FileNotFoundError, ProcessLookupError):
                continue
            handles.append(fd)
            try:
                context = (path / 'attr/current').read_text().strip('\0\n')
                if context in ordinary_contexts:
                    continue
                cgroup = (path / 'cgroup').read_text().strip()
                if context in {AUTH_CONTEXT, DISPLAY_CONTEXT} and cgroup.endswith('/' + seat['scope']):
                    if context == DISPLAY_CONTEXT:
                        if int(path.name) != seat['workers'][0]['pid'] or (path / 'exe').resolve() != BASE / 'bin/labwc':
                            raise RuntimeError('Unexpected display subject')
                        observed_display = True
                    else:
                        observed_auth |= int(path.name) == auth_pid
                    continue
                if reviewed_worker(path, uid, context, cgroup):
                    continue
                if administration_worker(path, uid, context, cgroup):
                    continue
                if ssh_transport(path, context):
                    continue
                # PID 1's immutable PAM cleanup child carries no application
                # profile; ordinary processes cannot create this subject.
                if context == 'system_u:system_r:init_t:s0' and (path / 'exe').resolve() in {Path('/usr/lib/systemd/systemd'), Path('/usr/lib/systemd/systemd-executor')} and (path / 'stat').read_text().rsplit(')', 1)[1].split()[1] == str(manager) and cgroup == f'0::/user.slice/user-{uid}.slice/user@{uid}.service/init.scope':
                    continue
                raise RuntimeError('Unconfined or unadmitted workload remains')
            except FileNotFoundError:
                continue
        if not observed_display or not observed_auth:
            raise RuntimeError('Protected seat owner missing')
        _, final_sequence = kernel_decision('greyward_guard_u:greyward_guard_r:greyward_guard_t:s0',
            'system_u:object_r:greyward_as_seat_tty_t:s0', 'chr_file', ['read'])
        if sequence != final_sequence:
            raise RuntimeError('Kernel changed during readback')
        return ready['exclusiveInput'] is True if len(sys.argv) == 3 and sys.argv[2] == '--locked' else True
    finally:
        for fd in handles:
            os.close(fd)


if __name__ == '__main__':
    if os.getuid() != 0 or os.geteuid() != 0 or len(sys.argv) not in [2, 3] or (len(sys.argv) == 3 and sys.argv[2] != '--locked'):
        raise RuntimeError('Root bounded readback required')
    try:
        result = verify(int(sys.argv[1]))
    except Exception:
        result = False
    print(json.dumps({'verified': result}))
