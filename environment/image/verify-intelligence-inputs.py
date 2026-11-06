#!/usr/bin/env python3
"""Keep the selected behavioral runtime aligned with its pinned ISO sources."""
import argparse
from pathlib import Path
import re
import subprocess


INPUTS = {
    'usr/share/greyward/intelligence-source.json': 'packaging/greyward-intelligence/source.json',
    'usr/libexec/greyward-intelligence/configure-policies': 'packaging/greyward-intelligence/configure-policies.py',
    'usr/libexec/greyward-intelligence/attest-sensor': 'packaging/greyward-intelligence/attest-sensor.py',
    'usr/lib/systemd/system/greyward-intelligence-sensor.service': 'security-center/security-context/systemd/greyward-intelligence-sensor.service',
    'usr/lib/systemd/system/greyward-intelligence-provider.service': 'security-center/security-context/systemd/greyward-intelligence-provider.service',
    'etc/dbus-1/system.d/systems.mantis.greyward.Intelligence1.conf': 'security-center/security-context/dbus/systems.mantis.greyward.Intelligence1.conf',
}


def verify_payloads(repo, read):
    for installed, source in INPUTS.items():
        if read(installed).replace(b'\r\n', b'\n') != (repo/source).read_bytes().replace(b'\r\n', b'\n'):
            raise ValueError('Stale intelligence runtime input: ' + installed)


def verify(repo, rpm):
    spec = (repo/'packaging/greyward-intelligence/greyward-intelligence.spec').read_text()
    fields = [re.search(r'^'+key+r':\s*(\S+)', spec, re.M)[1].replace('%{?dist}', '')
              for key in ('Name', 'Version', 'Release')]
    identity = subprocess.check_output(['rpm', '-qp', '--qf', '%{NAME} %{VERSION} %{RELEASE}', str(rpm)], text=True).split()
    if identity[:2] != fields[:2] or identity[2].split('.fc')[0] != fields[2]:
        raise ValueError('Intelligence package version differs from canonical recipe')
    archive = subprocess.check_output(['rpm2cpio', str(rpm)])

    def read(path):
        return subprocess.run(['cpio', '-i', '--quiet', '--to-stdout', './'+path],
                              input=archive, capture_output=True, check=True).stdout

    verify_payloads(repo, read)
    if not read('usr/libexec/greyward-intelligence/tetragon').startswith(b'\x7fELF'):
        raise ValueError('Missing native behavioral sensor')
    names = subprocess.check_output(['rpm', '-qpl', str(rpm)], text=True).splitlines()
    if not any(p.startswith('/usr/libexec/greyward-intelligence/bpf/') and p.endswith('.o') for p in names):
        raise ValueError('Missing pinned BPF programs')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--rpm', type=Path, required=True)
    args = parser.parse_args()
    verify(args.repo, args.rpm)
    print('INTELLIGENCE_INPUT_VALIDATION=PASS')
