#!/usr/bin/python3
"""Private-bus concurrency test; never connects to the real system/user bus.

Run as a non-root builder under dbus-run-session with a fresh work directory.
Synthetic slow reads exist only in this private provider, never in live history.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def run(work):
    if os.getuid() == 0 or not os.environ.get('DBUS_SESSION_BUS_ADDRESS'):
        raise RuntimeError('Requires an unprivileged private dbus-run-session')
    work = Path(work).resolve()
    work.mkdir(exist_ok=False)
    env = dict(os.environ, DBUS_SYSTEM_BUS_ADDRESS=os.environ['DBUS_SESSION_BUS_ADDRESS'])
    # Fixed code only: injected sleep makes real D-Bus dispatch contention
    # deterministic, without hanging filesystems or changing live services.
    provider = '''import time
import dbus, dbus.mainloop.glib
from gi.repository import GLib
from greyward_security_context import clamav_service as s
from greyward_security_context.file_security import FileSecurityManager
from greyward_security_context.telemetry import TelemetryStore
from pathlib import Path
import sys
dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus=dbus.SystemBus(); name=dbus.service.BusName(s.BUS_NAME,bus=bus)
manager=FileSecurityManager(TelemetryStore(Path(sys.argv[1])/'history.sqlite3'))
original=s.FileSecurityManager; s.FileSecurityManager=lambda: manager
service=s.ClamAvScan(bus,s.OBJECT_PATH)
def slow(path, *, owner_uid):
    Path(sys.argv[1]+'/reading').touch()
    time.sleep(2)
    return {'state':'NOT_SCANNED','validity':'UNKNOWN','caller_uid':owner_uid}
manager.scan_info=slow
s.clamav_status=lambda: {'status':'UNAVAILABLE','observed_at':'synthetic private fixture'}
Path(sys.argv[1]+'/ready').touch()
GLib.MainLoop().run()
'''
    with (work/'provider.log').open('wb') as log:
        service = subprocess.Popen([sys.executable, '-u', '-c', provider, str(work)],
            env=env, stdout=log, stderr=log)
        clients = []
        def command(method, *args):
            return ['gdbus', 'call', '--system', '--timeout', '12', '--dest',
                'systems.mantis.greyward.ClamAvScan1', '--object-path',
                '/systems/mantis/greyward/ClamAvScan1', '--method',
                'systems.mantis.greyward.ClamAvScan1.'+method, *args]
        try:
            deadline = time.monotonic()+5
            while not (work/'ready').exists() and service.poll() is None and time.monotonic()<deadline:
                time.sleep(.05)
            if not (work/'ready').exists():
                raise RuntimeError('Private provider failed; inspect provider.log')
            slow = subprocess.Popen(command('GetFileScanInfo', '/synthetic-only'), env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            clients.append(slow)
            deadline = time.monotonic()+3
            while not (work/'reading').exists() and time.monotonic()<deadline:
                time.sleep(.02)
            if not (work/'reading').exists():
                raise RuntimeError('Slow read did not enter the private provider')
            start = time.monotonic()
            fast = subprocess.run(command('GetScanStatus', 'no-such-private-operation'),
                env=env, capture_output=True, text=True, check=True, timeout=2)
            latency = time.monotonic()-start
            if latency >= .8 or slow.poll() is not None:
                raise RuntimeError('Slow property read blocked D-Bus status dispatch')
            output, error = slow.communicate(timeout=5)
            if slow.returncode or 'NOT_SCANNED' not in output or str(os.getuid()) not in output:
                raise RuntimeError('Asynchronous reply/caller identity failed: '+error)
            for _ in range(10):
                clients.append(subprocess.Popen(command('GetFileScanInfo', '/synthetic-only'),
                    env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
            responses = [p.communicate(timeout=12)[0] for p in clients[1:]]
            if not any('BUSY' in r for r in responses) or any(p.returncode for p in clients):
                raise RuntimeError('Bounded admission or asynchronous reply failed')
            bad = subprocess.run(command('GetFileScanInfoBatch', json.dumps(['/x']*33)),
                env=env, capture_output=True, text=True, check=True, timeout=2)
            if 'UNAVAILABLE' not in bad.stdout:
                raise RuntimeError('Oversized batch accepted')
            result = {'status_dispatch_ms': round(latency*1000, 2),
                'slow_read_seconds': 2, 'busy_replies': sum('BUSY' in r for r in responses),
                'scope': 'isolated D-Bus dispatch/admission; not live scan acceptance'}
            (work/'result.json').write_text(json.dumps(result, indent=2)+'\n')
            print(json.dumps(result))
        finally:
            for p in clients:
                if p.poll() is None:
                    p.terminate()
                    p.wait(timeout=3)
            service.terminate()
            service.wait(timeout=3)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('work', type=Path)
    run(parser.parse_args().work)
