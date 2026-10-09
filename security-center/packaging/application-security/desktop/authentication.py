#!/usr/bin/python3 -I
"""Immutable DMS native-lock/Polkit process in the protected auth domain."""
import os
from pathlib import Path
import subprocess
import time
import signal

BASE = Path('/usr/lib/greyward/application-security/desktop')
runtime = Path(os.environ['XDG_RUNTIME_DIR'])
uid = os.getuid()
if uid < 1000 or uid != os.geteuid() or Path('/proc/self/attr/current').read_text().strip('\0\n') != 'system_u:system_r:greyward_as_auth_t:s0':
    raise RuntimeError('Protected authentication subject required')
log = os.open(runtime / 'authentication.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
os.dup2(log, 1); os.dup2(log, 2); os.close(log)
children = []
def terminate(_signal, _frame):
    raise SystemExit(0)
signal.signal(signal.SIGTERM, terminate)
try:
    bus = subprocess.Popen([str(BASE / 'bin/auth-dbus'), '--nofork',
                            '--config-file=' + str(runtime.parent / 'session-bus.conf')],
                           stdin=subprocess.DEVNULL, close_fds=True)
    children.append(bus)
    deadline = time.monotonic() + 4
    while not (runtime / 'bus').exists():
        if bus.poll() is not None or time.monotonic() >= deadline:
            raise RuntimeError('Private authentication bus unavailable')
        time.sleep(.05)
    backend = subprocess.Popen([str(BASE / 'bin/dms'), 'run', '--session',
                                '-c', str(BASE / 'shell')],
                               stdin=subprocess.DEVNULL, close_fds=True)
    children.append(backend)
    while all(child.poll() is None for child in children):
        time.sleep(.2)
    raise RuntimeError('Authentication owner lost')
finally:
    for child in children:
        if child.poll() is None:
            child.terminate()
    for child in children:
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            child.kill()
