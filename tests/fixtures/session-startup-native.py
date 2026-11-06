#!/usr/bin/python3
"""Exercise real PID 1 ordering/retry limits with private, disposable units.

Copies the production service contracts, substituting fixed test commands and
an isolated target. Never starts/stops a production desktop or user manager.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
import uuid


def run(repo, work):
    if os.getuid() != 0:
        raise RuntimeError('Requires root for disposable systemd units')
    repo, work = Path(repo).resolve(), Path(work).resolve()
    work.mkdir(exist_ok=False)
    prefix = 'gw-stability-test-'+uuid.uuid4().hex[:12]
    names = {k: prefix+'-'+k+suffix for k, suffix in
        [('dms', '.service'), ('icons', '.service'), ('session', '.target')]}
    directory = Path('/run/systemd/system')
    paths = [directory/n for n in names.values()]
    if any(p.exists() for p in paths):
        raise RuntimeError('Private fixture name already exists')
    def call(*args, check=True):
        return subprocess.run(['systemctl', *args], capture_output=True, text=True,
            timeout=20, check=check)
    def transform(text):
        text = '\n'.join(l for l in text.splitlines() if not l.startswith('ConditionEnvironment='))+'\n'
        return text.replace('greyward-dms.service', names['dms']).replace(
            'greyward-desktop-icons.service', names['icons']).replace(
            'graphical-session.target', names['session']).replace('[Service]',
            '[Service]\nSELinuxContext=system_u:system_r:unconfined_service_t:s0')
    dms = transform((repo/'environment/session/greyward-dms.service').read_text())
    icons = transform((repo/'environment/session/greyward-desktop-icons.service').read_text())
    dms = dms.replace('ExecStart=/usr/local/bin/greyward-dms run --session',
        'ExecStart=/usr/bin/sleep infinity')
    post = work/'ready.py'
    post.write_text('import time\nfrom pathlib import Path\ntime.sleep(1)\nPath('+repr(str(work/'ready'))+').touch()\n')
    dms = dms.replace('ExecStartPost=/usr/local/libexec/greyward-dms-runtime-check --desktop-only --wait 30',
        'ExecStartPost=/usr/bin/python3 '+str(post))
    command = work/'icons.py'
    command.write_text('import time\nfrom pathlib import Path\nassert Path('+repr(str(work/'ready'))+').exists()\nPath('+repr(str(work/'icons'))+').touch()\ntime.sleep(60)\n')
    icons = icons.replace('ExecStartPre=/usr/local/libexec/greyward-dms-runtime-check --desktop-only',
        'ExecStartPre=/usr/bin/true').replace('ExecStart=/usr/local/libexec/greyward-desktop-icons',
        'ExecStart=/usr/bin/python3 '+str(command))
    try:
        paths[0].write_text(dms.replace('ExecStartPre=/usr/local/libexec/greyward-dms-session-migrate', 'ExecStartPre=/usr/bin/false'))
        paths[1].write_text(icons)
        paths[2].write_text('[Unit]\nDescription=Disposable startup test target\n')
        call('daemon-reload')
        call('start', names['session'])
        call('start', '--no-block', names['dms'])
        deadline = time.monotonic()+28
        result = {}
        while time.monotonic()<deadline:
            result = dict(x.split('=', 1) for x in call('show', names['dms'], '-p',
                'ActiveState', '-p', 'NRestarts', '-p', 'Result').stdout.splitlines())
            if result.get('ActiveState') == 'failed' and int(result.get('NRestarts', 0)) >= 3:
                logs = subprocess.check_output(['journalctl', '-u', names['dms'], '-o', 'cat', '--no-pager'], text=True)
                # Fedora 259 retains Result=exit-code for an ExecStartPre
                # failure even when its next activation hits the start limit.
                if 'Start request repeated too quickly' in logs:
                    (work/'failure-journal.txt').write_text(logs)
                    break
            time.sleep(.2)
        if not (work/'failure-journal.txt').exists() or int(result['NRestarts'])>3 or (work/'icons').exists():
            raise RuntimeError('Broken migration was not bounded or started icons: '+str(result))
        call('stop', names['dms'], names['icons'], check=False)
        call('reset-failed', names['dms'], names['icons'], check=False)
        paths[0].write_text(dms.replace('ExecStartPre=/usr/local/libexec/greyward-dms-session-migrate', 'ExecStartPre=/usr/bin/true'))
        call('daemon-reload')
        call('start', names['dms'])
        deadline = time.monotonic()+4
        while not (work/'icons').exists() and time.monotonic()<deadline:
            time.sleep(.1)
        if not (work/'icons').exists():
            raise RuntimeError('Icons did not start after restored readiness')
        result['restored_ready_ordering'] = True
        (work/'result.json').write_text(json.dumps(result, indent=2)+'\n')
        print(json.dumps(result))
    finally:
        call('stop', *names.values(), check=False)
        call('reset-failed', names['dms'], names['icons'], check=False)
        for p in paths:
            p.unlink(missing_ok=True)
        call('daemon-reload')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('repo', type=Path)
    p.add_argument('work', type=Path)
    a = p.parse_args()
    run(a.repo, a.work)
