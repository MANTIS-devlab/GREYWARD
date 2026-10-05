#!/usr/bin/env python3
"""Opt-in combined backend/UI idle measurement. No rendered-latency claim."""
import argparse
import json
import os
from pathlib import Path
import statistics
import subprocess
import time


def sample():
    properties = dict(line.split('=', 1) for line in subprocess.check_output(
        ['systemctl','--user','show','greyward-dms.service','-p','ActiveState','-p','ControlGroup','-p','MainPID'], text=True).splitlines())
    group = properties.get('ControlGroup', '')
    main_pid = int(properties.get('MainPID', '0'))
    if properties.get('ActiveState') != 'active' or not group.startswith('/') or main_pid <= 0:
        raise ValueError('Cannot measure an inactive or unidentified DMS service')
    cgroup = Path('/sys/fs/cgroup') / group.lstrip('/')
    pids = set()
    for file in [cgroup/'cgroup.procs', *cgroup.rglob('cgroup.procs')]:
        if file.exists(): pids.update(file.read_text().split())
    accounting = dict(line.split() for line in (cgroup/'cpu.stat').read_text().splitlines())
    cpu_usage = int(accounting['usage_usec'])
    rss, threads = 0, 0
    for pid in pids:
        try:
            values = (Path('/proc')/pid/'stat').read_text().rsplit(')', 1)[1].split()
            rss += int(values[21]) * os.sysconf('SC_PAGE_SIZE')
            threads += int(values[17])
        except (FileNotFoundError, ProcessLookupError): pass
    if str(main_pid) not in pids:
        raise ValueError('DMS main process disappeared during measurement')
    return {'at': time.monotonic(), 'mainPid': main_pid, 'cpuUsageMicroseconds': cpu_usage, 'rssBytes': rss, 'threads': threads, 'processes': len(pids)}


def measure(duration, interval):
    readings = [sample()]; deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        time.sleep(min(interval, max(0, deadline-time.monotonic())))
        readings.append(sample())
        if readings[-1]['mainPid'] != readings[0]['mainPid']:
            raise ValueError('DMS restarted during measurement; repeat the run')
    cpu = [(b['cpuUsageMicroseconds']-a['cpuUsageMicroseconds'])/1_000_000/(b['at']-a['at'])*100
           for a,b in zip(readings, readings[1:])]
    if any(value < 0 for value in cpu): raise ValueError('Service CPU accounting reset; repeat the run')
    def summary(values):
        ordered=sorted(values)
        return {'median': statistics.median(values), 'p95': ordered[min(len(ordered)-1, int(len(ordered)*.95))], 'min': min(values), 'max': max(values)}
    return {'cpuOneCorePercent': summary(cpu), 'rssBytes': summary([x['rssBytes'] for x in readings]), 'samples': readings}


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--label',required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--duration',type=int,default=600)
    parser.add_argument('--interval',type=int,default=5)
    args=parser.parse_args()
    if args.duration <= 0 or args.interval <= 0: parser.error('Duration and interval must be positive')
    if args.output.exists(): parser.error('Use a new output path to retain prior evidence')
    result=measure(args.duration,args.interval)
    result.update(label=args.label, durationSeconds=args.duration,
                  scope='Service cgroup including DMS, Quickshell and exited helpers; idle only', cpuAccounting='cgroup-v2 usage_usec')
    args.output.write_text(json.dumps(result,indent=2)+'\n')
