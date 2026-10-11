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
splash = None
def terminate(_signal, _frame):
    raise SystemExit(0)
signal.signal(signal.SIGTERM, terminate)

def stop_splash(process):
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill(); process.wait(timeout=2)

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
    try:
        # This immutable, noninteractive surface is intentionally separate
        # from the full DMS shell so it can cover compositor startup sooner.
        splash = subprocess.Popen([str(BASE / 'bin/qs'), '-p', str(BASE / 'shell/startup')],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, close_fds=True)
    except OSError as error:
        print(f'Optional startup backdrop unavailable: {error}', flush=True)
    backend = subprocess.Popen([str(BASE / 'bin/dms'), 'run', '--session',
                                '-c', str(BASE / 'shell')],
                               stdin=subprocess.DEVNULL, close_fds=True)
    children.append(backend)
    startup_ready = runtime / 'authentication-ready.json'
    while all(child.poll() is None for child in children):
        if splash is not None and startup_ready.is_file():
            # The full auth shell wrote its first readiness record. Give its
            # background layer a frame to map, then retire the early surface.
            time.sleep(.25)
            stop_splash(splash)
            splash = None
        time.sleep(.05 if splash is not None else .2)
    raise RuntimeError('Authentication owner lost')
finally:
    stop_splash(splash)
    for child in children:
        if child.poll() is None:
            child.terminate()
    for child in children:
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            child.kill()
