#!/usr/bin/python3 -I
"""Fixed broker-owned seat worker; not a general command or user service.

The broker supplies kernel-authenticated UID/PID/start time. A real local PAM
session leader is required. Privileged display/auth inputs are root-prepared;
ordinary desktop services remain in the mapped user's confined user manager.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import select
import subprocess
import sys
import time
sys.dont_write_bytecode = True

BASE = Path('/usr/lib/greyward/application-security/desktop')
STATE = Path('/run/greyward-application-security')
AUTH_CONTEXT = 'system_u:system_r:greyward_as_auth_t:s0'
DISPLAY_CONTEXT = 'greyward_guard_u:greyward_guard_r:greyward_as_display_t:s0'
def protected_keyboard_environment():
    """Load the Anaconda-selected XKB settings from the immutable receipt."""
    manifest = json.loads(private_file(BASE / 'desktop.json', 1024 * 1024))
    files = manifest.get('files', {})
    for name in ('keyboard.json', 'keyboard_config.py'):
        if name not in files:
            raise RuntimeError('Installed keyboard selection is missing from protected desktop')
    helper_path = BASE / 'keyboard_config.py'
    helper_bytes = private_file(helper_path, 128 * 1024)
    if hashlib.sha256(helper_bytes).hexdigest() != files['keyboard_config.py']:
        raise RuntimeError('Protected keyboard validator receipt mismatch')
    namespace = {'__name__': 'greyward_protected_keyboard_config'}
    exec(compile(helper_bytes, str(helper_path), 'exec'), namespace)
    settings = json.loads(private_file(BASE / 'keyboard.json', 4096))
    settings = namespace['validate_settings'](settings)
    return namespace['environment'](settings)


def requires_software_renderer(dmi_root=Path('/sys/class/dmi/id'),
                               drm_root=Path('/sys/class/drm'),
                               dri_root=Path('/dev/dri')):
    """Keep the known virtual/no-render-node fallback local to this display.

    The protected compositor has a fixed environment allowlist, so it must
    make the same read-only hardware decision as the ordinary session launcher
    instead of inheriting the user's renderer variables.
    """
    identities = []
    for name in ('sys_vendor', 'product_name', 'board_vendor'):
        try:
            identities.append((dmi_root / name).read_text().casefold())
        except OSError:
            continue
    if any(re.search(r'vmware|hyper-?v|virtual machine', value)
           for value in identities):
        return True

    for vendor_file in drm_root.glob('card*/device/vendor'):
        try:
            vendor = vendor_file.read_text().strip().casefold()
        except OSError:
            continue
        if re.fullmatch(r'(?:0x)?(?:15ad|1414)', vendor):
            return True

    return not any(dri_root.glob('renderD*'))


def renderer_environment(kind, dmi_root=Path('/sys/class/dmi/id'),
                         drm_root=Path('/sys/class/drm'),
                         dri_root=Path('/dev/dri')):
    """Use GLES2 on capable hardware; keep authentication and VM fallback CPU-only."""
    if kind not in ('authentication', 'display'):
        raise ValueError('Unknown protected renderer scope')
    software = kind == 'authentication' or requires_software_renderer(
        dmi_root, drm_root, dri_root)
    values = {
        'WLR_NO_HARDWARE_CURSORS': '1',
        'WLR_DRM_NO_MODIFIERS': '1',
    }
    if software:
        values.update({
            'WLR_RENDERER': 'pixman',
            'WLR_RENDERER_ALLOW_SOFTWARE': '1',
            'LIBGL_ALWAYS_SOFTWARE': '1',
        })
    else:
        # Pixman cannot import the client DMA-BUFs wlroots needs for outputs on
        # a secondary GPU. GLES2 supplies that import path. Do not permit an
        # accidental software GL fallback on a machine with usable render nodes.
        values['WLR_RENDERER'] = 'gles2'
    return values


def private_file(path, maximum=65536, owner=0, retry_replaced=False):
    # Quickshell atomically replaces the mutable readiness record. An open
    # descriptor can lose its final link before fstat even though the new
    # record is healthy. Retry only that demonstrated replacement race; never
    # relax immutable input checks or reuse a previously accepted heartbeat.
    for _attempt in range(3 if retry_replaced else 1):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            st = os.fstat(fd)
            if retry_replaced and st.st_nlink == 0:
                current = os.stat(path, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != (st.st_dev, st.st_ino):
                    continue
            if st.st_uid != owner or st.st_mode & 0o022 or st.st_nlink != 1 or st.st_size > maximum:
                raise RuntimeError('Unsafe fixed input')
            return os.read(fd, maximum + 1)
        finally:
            os.close(fd)
    raise RuntimeError('Readiness input keeps changing')


def generation():
    manifest = json.loads(private_file(BASE / 'desktop.json', 1024 * 1024))
    if manifest['schema'] != 'greyward.protected-desktop/v1':
        raise RuntimeError('Unprepared desktop')
    if not {'keyboard.json', 'keyboard_config.py'} <= set(manifest.get('files', {})):
        raise RuntimeError('Installed keyboard selection is missing from protected desktop')
    for name, digest in manifest['files'].items():
        if name.startswith('/') or '..' in Path(name).parts:
            raise RuntimeError('Invalid fixed generation')
        if hashlib.sha256(private_file(BASE / name, 128 * 1024 * 1024)).hexdigest() != digest:
            raise RuntimeError('Desktop generation changed')
    return manifest


def process(pid, uid, ticks):
    handle = os.pidfd_open(pid)
    path = Path('/proc') / str(pid)
    if path.stat().st_uid != uid or path.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19] != str(ticks):
        os.close(handle)
        raise RuntimeError('Caller generation changed')
    return handle


def session(pid, uid):
    lib = ctypes.CDLL('libsystemd.so.0')
    value = ctypes.c_char_p()
    if lib.sd_pid_get_session(pid, ctypes.byref(value)) < 0:
        raise RuntimeError('No actual PAM session')
    sid = value.value.decode()
    libc = ctypes.CDLL(None)
    libc.free(value)
    result = subprocess.run(['/usr/bin/loginctl', 'show-session', sid,
                             '-p', 'User', '-p', 'Leader', '-p', 'Seat', '-p', 'Remote',
                             '-p', 'Class', '-p', 'Active', '-p', 'Scope'],
                            capture_output=True, text=True, check=True, timeout=2)
    fields = dict(line.split('=', 1) for line in result.stdout.splitlines())
    if fields['User'] != str(uid) or fields['Seat'] != 'seat0' or fields['Remote'] != 'no' or fields['Class'] != 'user' or fields['Active'] != 'yes':
        raise RuntimeError('Fresh local PAM seat required')
    scope = fields['Scope']
    if scope != f'session-{sid}.scope':
        raise RuntimeError('Invalid seat scope')
    # greetd retains the root PAM worker as logind leader and execs the
    # selected user command in its direct child (upstream session/worker.rs).
    leader = int(fields['Leader'])
    parent = Path('/proc') / str(leader)
    if parent.stat().st_uid != 0 or parent.joinpath('exe').resolve() != Path('/usr/bin/greetd') or not parent.joinpath('attr/current').read_text().startswith('system_u:system_r:xdm_t:'):
        raise RuntimeError('Actual greetd PAM parent required')
    if pid != leader and Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[1] != str(leader):
        raise RuntimeError('Only the selected direct session command is admitted')
    leader_ticks = parent.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19]
    return sid, scope, leader, leader_ticks


def worker(kind, uid, gid, sid):
    # The root parent attaches this stopped worker to the admitted scope before
    # it may create children. No claimed XDG_SESSION_ID establishes membership.
    if os.read(0, 1) != b'G':
        raise RuntimeError('Admission gate closed')
    os.close(0)
    manifest = generation()
    account = manifest['accounts'][str(uid)]
    auth = STATE / f'auth-{uid}'
    context = AUTH_CONTEXT if kind == 'authentication' else DISPLAY_CONTEXT
    env = {'PATH': str(BASE / 'bin') + ':/usr/bin:/usr/sbin',
           'USER': account['name'], 'LOGNAME': account['name'], 'LANG': 'C.UTF-8',
           'XDG_SESSION_ID': sid, 'XDG_SESSION_TYPE': 'wayland',
           'XDG_CURRENT_DESKTOP': 'GREYWARD:Labwc', 'XDG_SESSION_DESKTOP': 'greyward-labwc',
           'HOME': str(auth / 'home') if kind == 'authentication' else account['home'],
           'XDG_RUNTIME_DIR': str(auth / 'runtime') if kind == 'authentication' else f'/run/user/{uid}',
           'DBUS_SESSION_BUS_ADDRESS': f'unix:path={auth}/runtime/bus' if kind == 'authentication' else f'unix:path=/run/user/{uid}/bus',
           # Keep XDG_RUNTIME_DIR private. DMS's output-management client joins
           # it with WAYLAND_DISPLAY, so this must name the broker-created alias
           # below instead of repeating the absolute compositor socket path.
           'WAYLAND_DISPLAY': 'wayland-0', 'QT_QUICK_BACKEND': 'software',
           'QT_QPA_PLATFORM': 'wayland', 'QT_QPA_PLATFORMTHEME': 'generic',
           'QT_STYLE_OVERRIDE': 'Fusion', 'GDK_BACKEND': 'wayland',
           'QV4_FORCE_INTERPRETER': '1', 'QML_DISABLE_DISK_CACHE': '1',
           'DMS_DISABLE_HOT_RELOAD': '1'}
    env.update(renderer_environment(kind))
    if kind == 'authentication':
        # Qt's implicit clipboard is separate from DMS's disabled collector.
        # Keep focus/lock surfaces out of ordinary clipboard FD transfers.
        # Only this root-prepared process tree receives this native Qt option;
        # wl_seat and ext_session_lock_manager_v1 remain available.
        env['QT_WAYLAND_DISABLED_INTERFACES'] = (
            'wl_data_device_manager,zwp_primary_selection_device_manager_v1,'
            'zwlr_data_control_manager_v1,ext_data_control_manager_v1')
        sys.path.insert(0, str(BASE))
        from materialize import authentication_environment
        env.update(authentication_environment(auth, manifest['source']['dms']))
        command = [str(BASE / 'bin/auth-python'), '-I', str(BASE / 'authentication.py')]
    elif kind == 'display':
        # The protected compositor uses its root-owned XDG config directory
        # and this explicit environment allowlist. Do not load user-writable
        # Labwc environment files; pass the root-prepared Anaconda selection.
        env.update(protected_keyboard_environment())
        env.pop('WAYLAND_DISPLAY', None)
        env['PATH'] = '/usr/bin:/usr/sbin'
        env['XDG_CONFIG_HOME'] = str(BASE / 'labwc')
        env['XDG_DATA_HOME'] = str(BASE / 'labwc')
        env['XDG_CACHE_HOME'] = str(STATE / f'display-cache-{uid}')
        command = [str(BASE / 'bin/labwc'), '-C', str(BASE / 'labwc')]
    else:
        raise RuntimeError('Unknown fixed worker')
    os.setgroups([])
    os.setgid(gid)
    lib = ctypes.CDLL('libselinux.so.1', use_errno=True)
    if lib.setexeccon(context.encode()) != 0:
        raise RuntimeError('Required transition unavailable')
    os.setuid(uid)
    os.execve(command[0], command, env)


def start(uid, pid, ticks):
    manifest = generation()
    account = manifest['accounts'][str(uid)]
    handle = process(pid, uid, ticks)
    sid, scope, leader, leader_ticks = session(pid, uid)
    state = STATE / f'seat-{uid}.json'
    if state.exists():
        previous = json.loads(private_file(state))
        try:
            prior = process(previous['actor'], uid, previous['actor_start'])
        except (OSError, RuntimeError):
            # Stale locators cannot admit a process; all old workers must also
            # have disappeared before private runtime files may be renewed.
            for item in previous['workers']:
                try:
                    prior_worker = process(item['pid'], uid, item['start'])
                except (OSError, RuntimeError):
                    continue
                os.close(prior_worker)
                raise RuntimeError('Previous seat cleanup incomplete')
            state.unlink()
        else:
            os.close(prior)
            raise RuntimeError('A seat is already admitted')
    if Path(f'/proc/{pid}/attr/current').read_text().strip('\0\n') != 'greyward_guard_u:greyward_guard_r:greyward_guard_t:s0':
        raise RuntimeError('Unconfined session refused')
    # PAM has already established this local seat. Type its physical console
    # separately so ordinary terminal/SSH PTYs remain usable without granting
    # applications access to the authentication seat's raw keyboard channel.
    tty = subprocess.check_output(['/usr/bin/loginctl', 'show-session', sid, '-p', 'TTY', '--value'], text=True, timeout=1).strip()
    if tty != 'tty1':
        raise RuntimeError('Unprepared physical console')
    tty_path = '/dev/' + tty
    original_tty = os.getxattr(tty_path, 'security.selinux').decode().strip('\0')
    os.setxattr(tty_path, 'security.selinux', b'system_u:object_r:greyward_as_seat_tty_t:s0')
    sys.path.insert(0, str(BASE))
    from materialize import materialize
    materialize(uid, int(account['gid']), manifest['source']['dms'])
    for name in ['authentication.log', 'authentication-ready.json', 'bus', 'wayland-0']:
        old = STATE / f'auth-{uid}/runtime' / name
        if old.exists() or old.is_symlink():
            if name == 'wayland-0' and not old.is_symlink():
                raise RuntimeError('Unsafe protected display alias')
            old.unlink()
    cache=STATE/f'display-cache-{uid}'
    cache.mkdir(mode=0o700,exist_ok=True)
    if cache.is_symlink() or cache.stat().st_uid not in (0,uid):
        raise RuntimeError('Unsafe display cache')
    os.chown(cache,uid,int(account['gid']))
    os.setxattr(cache,'security.selinux',b'system_u:object_r:greyward_as_display_runtime_t:s0')
    # logind owns this nondelegated scope. Root attaches only its stopped,
    # fixed children through the kernel cgroup interface; no ordinary subject
    # receives delegation or a generic migration operation.
    cgroup = subprocess.check_output(['/usr/bin/systemctl', 'show', scope, '-p', 'ControlGroup', '--value'], text=True, timeout=1).strip()
    if cgroup != f'/user.slice/user-{uid}.slice/{scope}':
        raise RuntimeError('Root-controlled admitted scope required')
    control = Path('/sys/fs/cgroup'+cgroup+'/cgroup.procs')
    meta=control.stat()
    if meta.st_uid != 0 or meta.st_mode & 0o022:
        raise RuntimeError('Untrusted scope controller')
    children = []
    try:
        for kind in ['display', 'authentication']:
            if kind == 'authentication':
                # The auth shell has a private XDG_RUNTIME_DIR. Give DMS a
                # fixed relative socket name there, linked to this admitted
                # session's compositor socket after Labwc has created it.
                target = Path(f'/run/user/{uid}/wayland-0')
                socket_stat = target.stat()
                if not target.is_socket() or socket_stat.st_uid != uid:
                    raise RuntimeError('Admitted Wayland socket changed')
                runtime = STATE / f'auth-{uid}/runtime'
                runtime_stat = runtime.lstat()
                if not runtime.is_dir() or runtime.is_symlink() or runtime_stat.st_uid != uid or runtime_stat.st_mode & 0o077:
                    raise RuntimeError('Unsafe protected runtime directory')
                os.symlink(str(target), runtime / 'wayland-0')
            log = os.fdopen(os.open(STATE / f'{kind}-{uid}.log', os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600), 'wb')
            os.setxattr(STATE / f'{kind}-{uid}.log', 'security.selinux', f'system_u:object_r:greyward_as_{"auth" if kind == "authentication" else "display"}_runtime_t:s0'.encode())
            child = subprocess.Popen(['/usr/bin/python3', '-I', str(BASE / 'session.py'), '--worker', kind,
                                      str(uid), str(account['gid']), sid], stdin=subprocess.PIPE,
                                     stdout=log, stderr=log, close_fds=True)
            children.append(child)
            migration = os.open(control, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                if os.fstat(migration).st_uid != 0:
                    raise RuntimeError('Scope controller changed')
                os.write(migration, str(child.pid).encode())
            finally:
                os.close(migration)
            if not Path(f'/proc/{child.pid}/cgroup').read_text().strip().endswith('/'+scope):
                raise RuntimeError('Actual scope attachment failed')
            child.stdin.write(b'G'); child.stdin.close()
            if kind == 'display':
                end = time.monotonic() + 6
                while not Path(f'/run/user/{uid}/wayland-0').exists():
                    if child.poll() is not None or time.monotonic() >= end:
                        raise RuntimeError('Seat display unavailable')
                    time.sleep(.05)
        evidence = {'schema': 'greyward.seat-admission/v1', 'uid': uid, 'leader': leader, 'leader_start': leader_ticks, 'actor': pid, 'actor_start': ticks,
                    'session': sid, 'scope': scope, 'tty_original': original_tty, 'boot': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                    'manifest': hashlib.sha256(private_file(BASE / 'desktop.json', 1024 * 1024)).hexdigest(),
                    'workers': [{'pid': c.pid, 'start': Path(f'/proc/{c.pid}/stat').read_text().rsplit(')', 1)[1].split()[19]} for c in children]}
        temporary = state.with_suffix('.pending')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as output:
            json.dump(evidence, output); output.flush(); os.fsync(output.fileno())
        os.rename(temporary, state)
        deadline = time.monotonic() + 8
        while not authentication_ready(uid):
            if any(c.poll() is not None for c in children) or time.monotonic() >= deadline:
                raise RuntimeError('Protected authentication startup failed')
            time.sleep(.1)
        # A root guardian joins the actual nondelegated seat. It survives a
        # broker restart and closes the entire session on owner/input loss.
        guardian = os.fork()
        if guardian == 0:
            migration = os.open(control, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            os.write(migration, str(os.getpid()).encode()); os.close(migration)
            for descriptor in [0, 1, 2]:
                replacement = os.open('/dev/null', os.O_RDWR)
                os.dup2(replacement, descriptor); os.close(replacement)
            monitor(uid, pid, ticks, sid, children, state, tty_path, original_tty)
            os._exit(0)
        print('ADMITTED', flush=True)
    except Exception:
        for child in children:
            try:
                child.kill(); child.wait(timeout=2)
            except ProcessLookupError:
                pass
        os.setxattr(tty_path, 'security.selinux', original_tty.encode())
        state.unlink(missing_ok=True)
        raise
    finally:
        os.close(handle)


def authentication_ready(uid, failure=None):
    def unavailable(reason):
        if failure is not None:
            failure.append(reason)
        return False

    try:
        path = STATE / f'auth-{uid}/runtime/authentication-ready.json'
        ready = json.loads(private_file(path, 4096, owner=uid, retry_replaced=True))
        if ready['schema'] != 'greyward.authentication-readiness/v1':
            return unavailable('readiness-schema')
        if ready['polkitRegistered'] is not True:
            return unavailable('polkit-registration')
        if not -1 <= time.time() - path.stat().st_mtime <= 4:
            return unavailable('heartbeat-age')
        if Path(f"/proc/{ready['pid']}/attr/current").read_text().strip('\0\n') != AUTH_CONTEXT:
            return unavailable('authentication-context')
        return True
    except OSError:
        return unavailable('readiness-io')
    except RuntimeError:
        return unavailable('readiness-input')
    except (ValueError, KeyError, TypeError):
        return unavailable('readiness-format')


def record_guardian_event(sid, reason):
    # stdout/stderr are detached in the guardian. Keep a bounded reason in
    # the system journal, without logging credential or readiness contents.
    # Logging must never prevent the mandatory scope teardown.
    try:
        import syslog
        syslog.openlog('greyward-seat-guardian', facility=syslog.LOG_AUTHPRIV)
        syslog.syslog(syslog.LOG_ERR, f'Admitted session {sid} closed: {reason}')
    except (ImportError, OSError):
        pass


def monitor(uid, pid, ticks, sid, children, state, tty_path, original_tty):
    handles = [process(pid, uid, ticks)] + [os.pidfd_open(c.pid) for c in children]
    try:
        while True:
            exited = select.select(handles, [], [], 1)[0]
            if exited:
                roles = ['session-owner-exited', 'display-owner-exited', 'authentication-owner-exited']
                index = next(i for i, handle in enumerate(handles) if handle in exited)
                reason = roles[index] if index < len(roles) else 'protected-worker-exited'
                record_guardian_event(sid, reason)
                break
            failure = []
            if not authentication_ready(uid, failure):
                record_guardian_event(sid, failure[0] if failure else 'authentication-unavailable')
                break
    finally:
        # logind/PID 1 terminates the admitted scope and ordinary UWSM lifetime;
        # no unlocked desktop survives loss of protected authentication.
        state.unlink(missing_ok=True)
        os.setxattr(tty_path, 'security.selinux', original_tty.encode())
        try:
            subprocess.run(['/usr/bin/loginctl', 'terminate-session', sid], timeout=3)
        finally:
            # Fedora may abandon a logind scope when KillUserProcesses is off.
            # These root-attached protected workers must not outlive admission.
            # Ask PID 1 to retire this exact validated seat scope, including this
            # guardian; never terminate the whole user or an SSH session.
            subprocess.run(['/usr/bin/systemctl', 'stop', '--no-block',
                            f'session-{sid}.scope'], check=True, timeout=3)


def lock_session(uid):
    seat = json.loads(private_file(STATE / f'seat-{uid}.json'))
    if seat['uid'] != uid or seat['boot'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip():
        raise RuntimeError('Seat changed')
    handles = [process(w['pid'], uid, w['start']) for w in seat['workers']]
    try:
        sid, scope, _, _ = session(seat['leader'], uid)
        if sid != seat['session'] or scope != seat['scope']:
            raise RuntimeError('Seat changed')
        subprocess.run(['/usr/bin/loginctl', 'lock-session', sid], check=True, timeout=2)
    finally:
        for handle in handles:
            os.close(handle)


if __name__ == '__main__':
    os.umask(0o077)
    if os.getuid() != 0 or os.geteuid() != 0:
        raise RuntimeError('Only the root broker prepares the seat')
    if len(sys.argv) == 5 and sys.argv[1] == '--start':
        start(*map(int, sys.argv[2:]))
    elif len(sys.argv) == 6 and sys.argv[1] == '--worker':
        worker(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5])
    elif len(sys.argv) == 3 and sys.argv[1] == '--lock':
        lock_session(int(sys.argv[2]))
    else:
        raise RuntimeError('Fixed seat operation required')
