#!/usr/bin/python3
"""Fixed synthetic cgroup expiry proof; no broker/grant API is implemented."""
import json
import os
from pathlib import Path
import select
import signal
import sys
import time

UNIT = 'greyward-application-security-grant-lifetime.service'
DOMAIN = 'greyward_probe_tool_t'
RESOURCE = Path('/home/greyward-guard-probe/resource-grants/ssh/synthetic')


def workload():
    if os.getuid() != 1002 or Path('/proc/self/attr/current').read_text().split(':')[2] != DOMAIN:
        raise RuntimeError('The fixed grant context was not established')
    with RESOURCE.open('rb') as credential:
        if credential.read(1) != b's':
            raise RuntimeError('Synthetic grant positive control failed')
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        child = os.fork()
        if child == 0:
            # A fork retains the explicitly permitted grant/descriptor. Lifetime
            # expiry must terminate it even when it ignores the polite stop.
            while True:
                time.sleep(1)
        print(json.dumps({'schema': 'greyward.application-security.lifetime-workload/v1',
                          'main_pid': os.getpid(), 'child_pid': child}), flush=True)
        while True:
            time.sleep(1)


def main_pid():
    # Fixed system unit, not a supplied command or arbitrary unit identifier.
    import subprocess
    result = subprocess.run(['/usr/bin/systemctl', 'show', UNIT, '-p', 'MainPID', '--value'],
                            capture_output=True, check=True, timeout=2,
                            env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
    return int(result.stdout.strip())


def observe():
    if os.getuid() != 0 or os.geteuid() != 0:
        raise RuntimeError('The observer must be root')
    deadline = time.monotonic() + 3
    pid = 0
    children = []
    while time.monotonic() < deadline:
        pid = main_pid()
        if pid > 1:
            try:
                children = [int(value) for value in Path(f'/proc/{pid}/task/{pid}/children').read_text().split()]
            except FileNotFoundError:
                children = []
            if len(children) == 1:
                break
        time.sleep(0.05)
    if pid <= 1 or len(children) != 1:
        raise RuntimeError('A live parent and forked child are required')
    descriptors = []
    try:
        for target in [pid, children[0]]:
            descriptor = os.pidfd_open(target, 0)
            descriptors.append(descriptor)
            status = Path(f'/proc/{target}/status').read_text()
            uid = next(line for line in status.splitlines() if line.startswith('Uid:')).split()[1:]
            if uid != ['1002'] * 4:
                raise RuntimeError('Unexpected workload ownership')
            if Path(f'/proc/{target}/attr/current').read_text().split(':')[2] != DOMAIN:
                raise RuntimeError('Unexpected workload domain')
            if Path(f'/proc/{target}/cgroup').read_text().strip() != f'0::/system.slice/{UNIT}':
                raise RuntimeError('Workload escaped its root-controlled membership')
        pending = set(descriptors)
        deadline = time.monotonic() + 12
        poller = select.poll()
        for descriptor in pending:
            poller.register(descriptor, select.POLLIN)
        while pending and time.monotonic() < deadline:
            for descriptor, events in poller.poll(250):
                if events & select.POLLIN:
                    pending.discard(descriptor)
                    poller.unregister(descriptor)
        if pending:
            raise RuntimeError('A grant-bearing descendant survived the workload deadline')
        print(json.dumps({'schema': 'greyward.application-security.lifetime-probe/v1',
                          'terminated_workloads': 2, 'pidfds_verified': True,
                          'production_grant_claimed': False}))
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


if __name__ == '__main__':
    if sys.argv[1:] == ['--fixed-workload']:
        workload()
    elif sys.argv[1:] == ['--fixed-observer']:
        observe()
    else:
        raise RuntimeError('Only fixed synthetic modes are supported')
