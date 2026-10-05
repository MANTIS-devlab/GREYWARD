#!/usr/bin/env python3
"""Opt-in disposable-VM protocol timing. This does not measure rendered frames."""
import argparse
import json
from pathlib import Path
import statistics
import subprocess
import time


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL, timeout=35).strip()


def summarize(values):
    values = sorted(values)
    return dict(median=statistics.median(values), p95=values[min(len(values)-1, int(len(values)*.95))], minimum=min(values), maximum=max(values))


def ready(cli):
    deadline = time.monotonic()+30
    while time.monotonic() < deadline:
        try:
            result = run(cli, 'ipc', 'call', 'settings', 'get', 'customPowerActionLock')
            if json.loads(result) == '/usr/local/bin/greyward-session-lock':
                return
        except (ValueError, subprocess.SubprocessError):
            pass
        time.sleep(.05)
    raise RuntimeError('Shell settings IPC and normalized lock routing did not become ready')


def benchmark(cli, count, panels=True):
    result = {}
    for operation in ('start', 'restart'):
        readings = []
        for _ in range(count):
            if operation == 'start': run('systemctl', '--user', 'stop', 'greyward-dms.service')
            began = time.monotonic()
            run('systemctl', '--user', operation, 'greyward-dms.service')
            ready(cli)
            readings.append((time.monotonic()-began)*1000)
        result[operation+'IpcReadyMilliseconds'] = dict(summary=summarize(readings), samples=readings)
    if not panels:
        return result
    # Completion of an IPC method is distinct from display/render completion.
    for target, opening, closing in [('launcher','open','close'), ('settings','open','close'), ('notifications','open','close'), ('control-center','open','hide'), ('powermenu','open','close')]:
        readings = []
        try:
            for _ in range(30):
                began = time.monotonic(); run(cli, 'ipc', 'call', target, opening)
                readings.append((time.monotonic()-began)*1000)
                time.sleep(.1)
                run(cli, 'ipc', 'call', target, closing)
        finally:
            run(cli, 'ipc', 'call', target, closing)
        result[target+'IpcCompletionMilliseconds'] = dict(summary=summarize(readings), samples=readings)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--cli', required=True)
    parser.add_argument('--label', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--count', type=int, default=10)
    parser.add_argument('--skip-panels', action='store_true')
    args = parser.parse_args()
    if args.output.exists(): parser.error('Use a new output path to retain prior evidence')
    if args.count <= 0: parser.error('Sample count must be positive')
    result = benchmark(args.cli, args.count, panels=not args.skip_panels)
    result.update(label=args.label, scope='Warm-filesystem service start/restart to settings IPC; panel IPC completion, not rendered latency')
    args.output.write_text(json.dumps(result, indent=2)+'\n')
