#!/usr/bin/python3
"""Fixed synthetic resource scope/child-exec checks; no grant API or secrets."""
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import stat

ROOT = Path('/home/greyward-guard-probe/resource-grants')
PROFILES = {
    'greyward_guard_t': None,
    'greyward_probe_tool_t': 'ssh',
    'greyward_probe_browser_t': 'browser',
}


def main():
    if os.getuid() != 1002:
        raise RuntimeError('Only the separately owned synthetic account is supported')
    domain = Path('/proc/self/attr/current').read_text().split(':')[2]
    if domain not in PROFILES:
        raise RuntimeError('An independently established probe domain is required')
    child_mode = sys.argv[1:] in (['--child'], ['--child-with-fd'])
    if sys.argv[1:] not in ([], ['--child'], ['--child-with-fd']) or (child_mode and domain != 'greyward_guard_t'):
        raise RuntimeError('The restricted child did not establish its required domain')
    if sys.argv[1:] == ['--child-with-fd']:
        descriptor = os.fstat(0)
        if not stat.S_ISCHR(descriptor.st_mode) or descriptor.st_rdev != os.makedev(1, 3) or os.read(0, 1) != b'':
            raise RuntimeError('Inherited credential FD escaped domain revalidation')
    with Path('/home/greyward-guard-probe/ordinary.txt').open('rb') as ordinary:
        if not ordinary.read(1):
            raise RuntimeError('Ordinary positive control is missing')
    passed = 0
    for category in ('ssh', 'browser', 'other'):
        expected = category == PROFILES[domain]
        try:
            # Read one byte to establish enforcement; never emit contents.
            with (ROOT / category / 'synthetic').open('rb') as stream:
                actual = stream.read(1) == b's'
        except OSError as error:
            if error.errno != errno.EACCES:
                raise
            actual = False
        if actual != expected:
            raise RuntimeError('Resource scope was not enforced')
        passed += 1
        if child_mode:
            continue
        child = subprocess.run(['/usr/bin/cat', str(ROOT / category / 'synthetic')],
                               env={'PATH': '/usr/bin', 'HOME': '/home/greyward-guard-probe', 'LANG': 'C'},
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=3, check=False)
        if child.returncode == 0:
            raise RuntimeError('A restricted child retained the raw resource grant')
        passed += 1
    if not child_mode:
        child = subprocess.run(['/usr/bin/python3', '-I', '/usr/local/libexec/greyward-application-security-grant-probe.py', '--child'],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=3, check=False)
        if child.returncode != 0:
            raise RuntimeError('Restricted child domain/positive control was not verified')
        passed += 1
        if PROFILES[domain] is not None:
            with (ROOT / PROFILES[domain] / 'synthetic').open('rb') as held:
                inherited = subprocess.run(['/usr/bin/python3', '-I', '/usr/local/libexec/greyward-application-security-grant-probe.py', '--child-with-fd'],
                                           stdin=held, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                           timeout=3, check=False)
            if inherited.returncode != 0:
                raise RuntimeError('Raw grant survived a restricted child descriptor transition')
            passed += 1
    if domain == 'greyward_guard_t':
        for target in ('greyward_probe_tool_t', 'greyward_probe_browser_t'):
            attempted = subprocess.run(['/usr/bin/runcon', f'greyward_guard_u:greyward_guard_owner_r:{target}:s0',
                                        '/usr/bin/cat', str(ROOT / PROFILES[target] / 'synthetic')],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       timeout=3, check=False)
            if attempted.returncode == 0:
                raise RuntimeError('Ordinary execution acquired a grant-bearing context')
            passed += 1
    print(json.dumps({'schema': 'greyward.application-security.grant-probe/v1',
                      'domain': domain, 'passed': passed, 'profile_claimed': False}))


if __name__ == '__main__':
    main()
