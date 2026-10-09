#!/usr/bin/python3 -I
"""Root-only admission for the fixed protected terminal; no elevation fallback."""
import ctypes
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import signal
import socket
import select
import stat
import struct
import subprocess
import sys
import time
import unicodedata

BASE = Path('/usr/lib/greyward/application-security/administration')
STATE = Path('/run/greyward-application-security')
CONTEXT = 'greyward_admin_u:greyward_admin_r:greyward_admin_t:s0'

def bind_descriptors(read_fd, ready_write):
    os.dup2(read_fd, 3, inheritable=True)
    os.dup2(ready_write, 4, inheritable=True)
    # Destination descriptors may be closed in the parent. Prepare them in
    # preexec and close inherited root handles before changing credentials.
    if ctypes.CDLL(None, use_errno=True).close_range(5, ctypes.c_uint(-1), 0):
        raise RuntimeError('Administration descriptor isolation failed')

def validated_arguments(arguments):
    if not isinstance(arguments, list) or not 1 <= len(arguments) <= 128:
        raise ValueError('Missing or excessive administration request')
    if any(not isinstance(a, str) or any(unicodedata.category(c) in ('Cc', 'Cf', 'Cs') for c in a) for a in arguments):
        raise ValueError('Invalid administration arguments')
    if sum(len(a.encode()) for a in arguments) > 16384:
        raise ValueError('Administration request too large')
    return arguments

def generation():
    manifest = private_json(BASE / 'manifest.json')
    if manifest.get('schema') != 'greyward.administration/v1' or set(manifest.get('files', {})) != {'terminal', 'worker.py', 'fonts.conf', 'unix_chkpwd'}:
        raise RuntimeError('Incomplete administration generation')
    if manifest.get('desktop') != hashlib.sha256(Path('/usr/lib/greyward/application-security/desktop/desktop.json').read_bytes()).hexdigest():
        raise RuntimeError('Mismatched protected desktop')
    for name, digest in manifest['files'].items():
        path = BASE / name
        meta = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(meta.st_mode) or meta.st_uid or meta.st_mode & 0o022 or meta.st_nlink != 1 or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError('Administration generation changed')
    if set(manifest.get('tools', {})) != {'/usr/bin/sudo', '/usr/bin/bash', '/usr/bin/unix_chkpwd'}:
        raise RuntimeError('Missing trusted tool generations')
    for name, digest in manifest['tools'].items():
        path = Path(name)
        meta = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(meta.st_mode) or meta.st_uid or meta.st_mode & 0o022 or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError('Trusted administration tool changed')
    if manifest['files']['unix_chkpwd'] != manifest['tools']['/usr/bin/unix_chkpwd']:
        raise RuntimeError('Mismatched Fedora password helper')
    return manifest

def kernel_revision():
    # The kernel publishes this page using a sequence counter. A policy load
    # must invalidate tickets, not mistake an intermediate page for failure.
    for _ in range(8):
        first = Path('/sys/fs/selinux/status').read_bytes()[:20]
        second = Path('/sys/fs/selinux/status').read_bytes()[:20]
        version, sequence, enforcing, loaded, _ = struct.unpack('=5I', second)
        if version == 1 and not sequence & 1 and first == second:
            return enforcing, loaded
        time.sleep(.001)
    raise RuntimeError('Kernel policy readback unavailable')

def private_json(path, maximum=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid or st.st_nlink != 1 or st.st_mode & 0o022 or st.st_size > maximum:
            raise RuntimeError('Untrusted prepared input')
        return json.loads(os.read(fd, maximum + 1))
    finally:
        os.close(fd)

def prepare(uid, pid, ticks, request):
    if os.getuid() or os.geteuid():
        raise RuntimeError('Root admission required')
    account = pwd.getpwuid(uid)
    if uid < 1000 or 'wheel' not in [grp.getgrgid(g).gr_name for g in os.getgrouplist(account.pw_name, account.pw_gid)]:
        raise RuntimeError('Local administrator required')
    process = Path('/proc') / str(pid)
    handle = os.pidfd_open(pid)
    try:
        if process.stat().st_uid != uid or process.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19] != str(ticks):
            raise RuntimeError('Caller changed')
        if process.joinpath('attr/current').read_text().strip('\0\n') != 'greyward_guard_u:greyward_guard_r:greyward_guard_t:s0':
            raise RuntimeError('Enrolled ordinary subject required')
        lib = ctypes.CDLL('libsystemd.so.0')
        session = ctypes.c_char_p()
        if lib.sd_pid_get_session(pid, ctypes.byref(session)) < 0:
            # Desktop applications started by the user manager are outside the
            # greetd scope. Accept only that root-created user's manager slice,
            # anchored to the independently verified root seat admission.
            group = process.joinpath('cgroup').read_text().strip()
            if not group.startswith(f'0::/user.slice/user-{uid}.slice/user@{uid}.service/'):
                raise RuntimeError('Local graphical session required')
            sid = private_json(STATE / f'seat-{uid}.json')['session']
        else:
            sid = session.value.decode()
            ctypes.CDLL(None).free(session)
        result = subprocess.run(['/usr/bin/loginctl', 'show-session', sid, '-p', 'User', '-p', 'Active', '-p', 'Remote', '-p', 'Seat'], capture_output=True, text=True, check=True, timeout=2)
        fields = dict(line.split('=', 1) for line in result.stdout.splitlines())
        if fields != {'User':str(uid), 'Active':'yes', 'Remote':'no', 'Seat':'seat0'}:
            raise RuntimeError('Active local seat required')
        checked = subprocess.run(['/usr/bin/python3','-I','/usr/lib/greyward/application-security/desktop/verify.py',str(uid)],capture_output=True,text=True,timeout=3)
        if checked.returncode or json.loads(checked.stdout) != {'verified': True}:
            raise RuntimeError('Protected desktop readiness missing')
        generation()
        arguments = validated_arguments(private_json(request)['arguments'])
        return account, arguments
    finally:
        os.close(handle)

def run(uid, pid, ticks, request):
    account, arguments = prepare(uid, pid, ticks, request)
    manifest_generation = private_json(BASE / 'manifest.json')
    kernel_generation = kernel_revision()
    directory = STATE / ('admin-' + str(uid))
    directory.mkdir(mode=0o700, exist_ok=True)
    meta = directory.lstat()
    if directory.is_symlink() or not directory.is_dir() or meta.st_uid or meta.st_mode & 0o077:
        raise RuntimeError('Unsafe administration runtime')
    mutex = os.open(directory / 'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    fcntl.flock(mutex, fcntl.LOCK_EX | fcntl.LOCK_NB)
    # PID 1 supplies a private mount namespace. A separate devpts instance keeps
    # Fedora sudo's internal user_devpts_t PTY unreachable from ordinary /dev/pts.
    if Path('/proc/self/ns/mnt').stat().st_ino == Path('/proc/1/ns/mnt').stat().st_ino:
        raise RuntimeError('Private administration mount namespace required')
    pts = directory / 'pts'
    pts.mkdir(mode=0o700, exist_ok=True)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.mount(b'devpts', os.fsencode(pts), b'devpts', 0, b'newinstance,ptmxmode=0666,mode=0620'):
        raise RuntimeError('Private devpts unavailable')
    os.setxattr(pts/'ptmx','security.selinux',b'system_u:object_r:greyward_admin_devpts_t:s0')
    if libc.mount(os.fsencode(pts), b'/dev/pts', None, 4096, None) or libc.mount(os.fsencode(pts/'ptmx'), b'/dev/ptmx', None, 4096, None):
        raise RuntimeError('Private terminal mount unavailable')
    # Fedora's shared chkpwd_t belongs to the ordinary-role closure. Preserve
    # its separation from administrator descriptors by binding an unchanged,
    # verified helper with a dedicated entry label only inside this namespace.
    if libc.mount(os.fsencode(BASE/'unix_chkpwd'), b'/usr/bin/unix_chkpwd', None, 4096, None) or libc.mount(None, b'/usr/bin/unix_chkpwd', None, 4096 | 32 | 1 | 2 | 4, None):
        raise RuntimeError('Private administration authentication unavailable')
    payload = directory / 'request.bin'
    descriptor = os.open(payload, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.write(descriptor, b'\0'.join(a.encode() for a in arguments) + b'\0')
    finally:
        os.close(descriptor)
    os.setxattr(payload, 'security.selinux', b'system_u:object_r:greyward_admin_runtime_t:s0')
    source_fd = os.open(payload, os.O_RDONLY | os.O_NOFOLLOW)
    read_fd = fcntl.fcntl(source_fd, fcntl.F_DUPFD_CLOEXEC, 10)
    os.close(source_fd)
    ready_read, ready_write = os.pipe()
    safe_write = fcntl.fcntl(ready_write, fcntl.F_DUPFD_CLOEXEC, 10)
    os.close(ready_write)
    ready_write = safe_write
    auth_state = STATE / f'auth-{uid}/runtime/administration-state.json'
    def active_state(active):
        # Native auth reads only this root-controlled boolean. No request or
        # command content enters the authentication process.
        temporary = auth_state.with_suffix('.pending')
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
        try:
            os.write(descriptor, json.dumps({'active':bool(active), 'validUntilMs':int(time.time()*1000)+1500}).encode())
            os.setxattr(descriptor,'security.selinux',b'system_u:object_r:greyward_as_auth_runtime_t:s0')
        finally:
            os.close(descriptor)
        os.rename(temporary, auth_state)
    env = {'PATH':'/usr/bin:/usr/sbin:/bin', 'HOME':str(directory), 'USER':account.pw_name,
           'LOGNAME':account.pw_name, 'LANG':'C.UTF-8', 'TERM':'xterm-256color',
           'XDG_RUNTIME_DIR':str(directory), 'WAYLAND_DISPLAY':f'/run/user/{uid}/wayland-0',
           'XDG_CONFIG_HOME':str(directory), 'XDG_CACHE_HOME':str(directory),
           'PS1':'Administration \\u@\\h:\\w\\$ ', 'FONTCONFIG_FILE':str(BASE/'fonts.conf')}
    tool_metadata = {name: (Path(name).stat().st_ino, Path(name).stat().st_mtime_ns) for name in manifest_generation['tools']}
    warning = Path('/var/lib/greyward/application-security') / f'administration-warning-{uid}.json'
    warning_revision = {'schema':'greyward.administration-warning/v1','revision':2}
    reviewed_request = False
    try:
        if private_json(warning) == warning_revision:
            env['GREYWARD_ADMIN_WARNING_ACKNOWLEDGED'] = '1'
    except FileNotFoundError:
        pass
    def acknowledge_warning():
        nonlocal reviewed_request
        reviewed_request = True
        descriptor = os.open(warning, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as output:
            json.dump(warning_revision, output)
            output.flush(); os.fsync(output.fileno())
    def admission():
        bind_descriptors(read_fd, ready_write)
        os.initgroups(account.pw_name, account.pw_gid)
        os.setgid(account.pw_gid)
        if ctypes.CDLL('libselinux.so.1').setexeccon(CONTEXT.encode()):
            raise RuntimeError('Administrator context unavailable')
        os.setuid(uid)
    child = None
    pending = b''
    def acknowledgement(expected):
        nonlocal pending
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            while b'\n' in pending:
                line, pending = pending.split(b'\n',1)
                if line == expected:
                    return True
                if line == b'REVIEWED':
                    acknowledge_warning()
                    continue
                if line != b'LIVE':
                    return False
            if select.select([ready_read], [], [], max(0,deadline-time.monotonic()))[0]:
                chunk = os.read(ready_read, 128)
                if not chunk:
                    return False
                pending += chunk
        return False
    try:
        active_state(True)
        child = subprocess.Popen([str(BASE/'terminal')],env=env,stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                                 preexec_fn=admission,close_fds=False)
        os.close(read_fd); read_fd = -1
        os.close(ready_write); ready_write = -1
        if not acknowledgement(b'READY'):
            raise RuntimeError('Exclusive administration input unavailable')
        ledger = directory / 'session.json'
        record = {'uid':uid, 'pid':child.pid,
                  'start':Path(f'/proc/{child.pid}/stat').read_text().rsplit(')',1)[1].split()[19],
                  'executable':{'device':Path(f'/proc/{child.pid}/exe').stat().st_dev,'inode':Path(f'/proc/{child.pid}/exe').stat().st_ino},
                  'namespace':Path(f'/proc/{child.pid}/ns/mnt').stat().st_ino,
                  'manifest':hashlib.sha256((BASE/'manifest.json').read_bytes()).hexdigest()}
        with os.fdopen(os.open(ledger,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600),'w') as output:
            json.dump(record,output)
        notify = os.environ.get('NOTIFY_SOCKET')
        if not notify:
            raise RuntimeError('PID 1 admission required')
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notifier:
            notifier.connect('\0' + notify[1:] if notify.startswith('@') else notify)
            notifier.sendall(b'READY=1')
        paused = False
        retired = False
        review_deadline = time.monotonic()+125
        while child.poll() is None:
            if not reviewed_request and time.monotonic()>review_deadline:
                raise RuntimeError('Administration review expired without execution')
            current_kernel = kernel_revision()
            if current_kernel[0] != 1:
                raise RuntimeError('Mandatory administration isolation lost')
            if current_kernel != kernel_generation:
                # Every policy reload drops the ticket, even a compatible one.
                # An authorized running root command remains alive. Coverage
                # independently withdraws when the changed policy is unsafe.
                child.send_signal(signal.SIGURG)
                kernel_generation = current_kernel
            if 'wheel' not in [grp.getgrgid(g).gr_name for g in os.getgrouplist(account.pw_name, account.pw_gid)]:
                raise RuntimeError('Administrator eligibility withdrawn')
            if not retired:
                try:
                    changed = private_json(BASE/'manifest.json') != manifest_generation or any((Path(name).stat().st_ino,Path(name).stat().st_mtime_ns) != previous for name,previous in tool_metadata.items())
                except FileNotFoundError:
                    changed = True
                if changed:
                    # A legitimate sudo/Bash upgrade must not kill DNF in the
                    # middle of its transaction. Drop tickets, refuse new
                    # admission via generation(), retain authorized commands.
                    child.send_signal(signal.SIGURG)
                    retired = True
            if select.select([ready_read], [], [], 0)[0]:
                pending += os.read(ready_read, 128)
                if len(pending) > 4096:
                    raise RuntimeError('Invalid terminal heartbeat')
                if b'REVIEWED\n' in pending:
                    acknowledge_warning()
                    pending = pending.replace(b'REVIEWED\n', b'')
                pending = b'\n'.join(line for line in pending.split(b'\n') if line != b'LIVE')
            readiness = STATE / f'auth-{uid}/runtime/authentication-ready.json'
            with readiness.open() as source:
                auth = json.load(source)
            auth_pid = auth.get('pid')
            if type(auth_pid) != int or Path(f'/proc/{auth_pid}/attr/current').read_text().strip('\0\n') != 'system_u:system_r:greyward_as_auth_t:s0' or Path(f'/proc/{auth_pid}/exe').resolve() != Path('/usr/lib/greyward/application-security/desktop/bin/qs') or time.time() - readiness.stat().st_mtime > 4:
                raise RuntimeError('Native authentication lost')
            requested = auth.get('lockRequested') is True or auth.get('polkitActive') is True
            if requested and not paused:
                child.send_signal(signal.SIGUSR1)
                if not acknowledgement(b'PAUSED'):
                    raise RuntimeError('Administration lock handoff failed')
                active_state(False)
                paused = True
            elif not requested and paused and auth.get('exclusiveInput') is False:
                active_state(True)
                # FileView change is observed before reacquiring; DMS no longer
                # requests a lock, and successful native PAM already completed.
                time.sleep(.2)
                child.send_signal(signal.SIGUSR2)
                if not acknowledgement(b'READY'):
                    raise RuntimeError('Administration resume failed')
                paused = False
            active_state(not paused)
            time.sleep(.2)
    finally:
        active_state(False)
        os.close(ready_read)
        if read_fd >= 0:
            os.close(read_fd)
        if ready_write >= 0:
            os.close(ready_write)
        if child is not None and child.poll() is None:
            child.terminate()
            child.wait(timeout=3)
        payload.unlink(missing_ok=True)
        (directory / 'session.json').unlink(missing_ok=True)
        os.close(mutex)

def status(uid):
    result = {'schema':'greyward.administration/v1','available':False,'active':False,'authentication_window_seconds':120}
    try:
        try:
            record = private_json(STATE/f'admin-{uid}/session.json')
            path = Path('/proc')/str(record['pid'])
            executable=path.joinpath('exe').stat()
            result['active'] = record['uid'] == uid and path.stat().st_uid == uid and path.joinpath('stat').read_text().rsplit(')',1)[1].split()[19] == record['start'] and path.joinpath('attr/current').read_text().strip('\0\n') == CONTEXT and record['executable']=={'device':executable.st_dev,'inode':executable.st_ino} and path.joinpath('cgroup').read_text().strip()==f'0::/system.slice/greyward-admin-{uid}.service'
        except FileNotFoundError:
            pass
        account = pwd.getpwuid(uid)
        if 'wheel' not in [grp.getgrgid(g).gr_name for g in os.getgrouplist(account.pw_name,account.pw_gid)]:
            return result
        generation()
        checked = subprocess.run(['/usr/bin/python3','-I','/usr/lib/greyward/application-security/desktop/verify.py',str(uid)],capture_output=True,text=True,timeout=3)
        if checked.returncode or json.loads(checked.stdout) != {'verified':True}:
            return result
        result['available'] = True
    except (OSError,ValueError,KeyError,RuntimeError,subprocess.SubprocessError):
        pass
    return result

if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--status' and os.getuid() == os.geteuid() == 0:
        print(json.dumps(status(int(sys.argv[2]))))
        sys.exit(0)
    if len(sys.argv) != 5:
        raise RuntimeError('Fixed root entry only')
    run(int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), Path(sys.argv[4]))
