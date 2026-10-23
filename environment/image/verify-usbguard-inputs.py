#!/usr/bin/env python3
"""Refuse stale packaged USB approval inputs before complete ISO staging."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


SOURCES = {
    # Required for both source builds and installed-RPM imports: a migrated
    # desktop can work while the same RPM's fresh-enrollment generator is stale.
    'ordinary-role': {
        'security-center/packaging/application-security/desktop/ordinary-policy.py':
            '/usr/share/greyward-application-security/desktop/ordinary-policy.py',
        'security-center/packaging/application-security/desktop/verify.py':
            '/usr/share/greyward-application-security/desktop/verify.py',
    },
    'dms': {'packaging/greyward-dms/verify.py': '/usr/libexec/greyward-dms-verify'},
    'context': {
        'security-center/security-context/greyward_security_context/usbguard.py':
            '/usr/lib/greyward-security-context/greyward_security_context/usbguard.py',
        'security-center/security-context/greyward_security_context/usbguard_session.py':
            '/usr/lib/greyward-security-context/greyward_security_context/usbguard_session.py',
    },
    'application-security': {
        'security-center/packaging/application-security/authentication/assemble.py':
            '/usr/share/greyward-application-security/authentication/assemble.py',
        'security-center/data/greyward-security-status.svg':
            '/usr/share/greyward-application-security/authentication/greyward-security-status.svg',
        'security-center/packaging/application-security/desktop/materialize.py':
            '/usr/share/greyward-application-security/desktop/materialize.py',
    },
    'enrollment': {
        'packaging/greyward-enrollment/migrate-dms-shell.py': '/usr/libexec/greyward-migrate-protected-dms-shell',
        **{'environment/production/selinux/' + name: '/usr/share/greyward-application-security/enrollment/policy/' + name.replace('-', '_')
           for name in ('greyward-application-usbguard-approval.te', 'greyward-application-usbguard-approval.fc',
                        'greyward-application-auth.te', 'greyward-application-auth.fc')},
    },
}


def rpm_file(package, installed_path):
    producer = subprocess.Popen(['rpm2cpio', str(package)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        result = subprocess.run(['cpio', '-i', '--quiet', '--to-stdout', '.' + installed_path],
                                stdin=producer.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        producer.stdout.close()
        _, error = producer.communicate(timeout=60)
        if result.returncode or producer.returncode:
            raise ValueError('Cannot inspect RPM payload: ' + installed_path)
        return result.stdout
    finally:
        if producer.poll() is None:
            producer.kill()
            producer.communicate()


def normalized(value):
    return value.replace(b'\r\n', b'\n')


def verify(repo, package, kind, read=rpm_file, manifest=None):
    for source, installed in SOURCES[kind].items():
        expected = (repo / source).read_bytes()
        actual = read(package, installed)
        if not actual or normalized(actual) != normalized(expected):
            raise ValueError('Stale or missing USB approval payload; rebuild ' + kind + ': ' + installed)
    if kind == 'dms':
        release = json.loads((manifest or repo / 'environment/production/dms-release.json').read_text())['releaseId']
        receipt = json.loads(read(package, '/usr/lib/greyward/dms/' + release + '/release.json'))
        for key, source in [('usbguardApprovalSourceSha256', 'usbguard-approval.go'),
                            ('usbguardAuthApprovalSourceSha256', 'usbguard-approval-execute.go')]:
            # Older reviewed builds recorded CRLF checkout bytes. Bind the
            # receipt to exactly the canonical LF or CRLF representation;
            # neither missing evidence nor actual source drift is accepted.
            content = normalized((repo / 'packaging/greyward-dms' / source).read_bytes())
            expected = {hashlib.sha256(value).hexdigest() for value in
                        (content, content.replace(b'\n', b'\r\n'))}
            if receipt.get(key) not in expected:
                raise ValueError('Stale or missing USB approval helper source receipt: ' + key)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--rpm', type=Path, required=True)
    parser.add_argument('--kind', choices=sorted(SOURCES), required=True)
    parser.add_argument('--dms-manifest', type=Path)
    args = parser.parse_args()
    verify(args.repo, args.rpm, args.kind, manifest=args.dms_manifest)
    print('USB approval packaged inputs match canonical source: ' + args.kind)
