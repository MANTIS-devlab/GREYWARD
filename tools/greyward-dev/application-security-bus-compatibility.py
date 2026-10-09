#!/usr/bin/python3
"""Bounded installed bus/read/negative-request checks; never authorize or launch.

No grant, preview approval, authentication, policy or service changes. Invalid
operation references are generated locally and cannot select a real review.
Portal chooser compatibility is exercised separately by the existing probe.
"""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import subprocess

BUS = 'systems.mantis.greyward.ApplicationSecurity1'
OBJECT = '/systems/mantis/greyward/ApplicationSecurity1'


def call(bus, path, method, signature=None, *arguments, user=False):
    command = ['/usr/bin/busctl', '--user' if user else '--system', '--timeout=8',
               'call', bus, path, bus, method]
    if signature:
        command += [signature, *map(str, arguments)]
    return subprocess.run(command, capture_output=True, text=True, timeout=10)


def decoded(result):
    result.check_returncode()
    if not result.stdout.startswith('s '):
        raise RuntimeError('Expected typed JSON projection')
    return json.loads(json.loads(result.stdout[2:]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--portal-app', help='Installed system Flatpak for a transient chooser probe')
    args = parser.parse_args()
    if os.getuid() == 0:
        raise RuntimeError('Run in the ordinary enrolled user context')
    if args.portal_app and not re.fullmatch(r'[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2,}', args.portal_app):
        raise RuntimeError('Invalid Flatpak identifier')
    before = decoded(call(BUS, OBJECT, 'ListAccessGrants'))
    coverage = decoded(call(BUS, OBJECT, 'GetCoverage'))
    admin = decoded(call(BUS, OBJECT, 'GetAdministrationState'))
    context_bus = 'systems.mantis.greyward.SecurityContext1'
    context_path = '/systems/mantis/greyward/SecurityContext1'
    context = decoded(call(context_bus, context_path, 'GetApplicationCoverage', user=True))
    context_admin = decoded(call(context_bus, context_path, 'GetAdministrationState', user=True))
    operation = 'operation_' + secrets.token_hex(32)
    grant = 'grant_' + secrets.token_hex(32)
    cases = [
        ('extra_forwarded_identity', 'GetCoverage', 's',
         json.dumps({'uid': os.getuid(), 'pid': os.getpid(),
                     'app_id': 'com.collaboraoffice.Office', 'request_handle': '/forged'})),
        ('unimplemented_portal_authority', 'ReviewPortalRequest', 's', 'com.collaboraoffice.Office'),
        ('unknown_review_apply', 'ApplyPolicyChange', 'sb', operation, 'false'),
        ('unknown_review_read', 'GetOperation', 's', operation),
        ('unreviewed_launch', 'PrepareLaunch', 'ssas', grant, '/usr/bin/true', '0'),
    ]
    rejected = {}
    for name, method, signature, *arguments in cases:
        result = call(BUS, OBJECT, method, signature, *arguments)
        rejected[name] = result.returncode != 0
        if result.returncode == 0:
            raise RuntimeError('Unsupported authority request unexpectedly succeeded: ' + name)
    portal = None
    if args.portal_app:
        source = Path(__file__).with_name('application-security-first-use-proof.py').read_text()
        code = ('namespace = {"__name__": "greyward_portal_probe"}\n'
                'exec(compile(' + repr(source) + ', "first-use-proof.py", "exec"), namespace)\n'
                'namespace["portal_request"](' + repr(str(Path.home())) + ')\n')
        result = subprocess.run(['/usr/bin/flatpak', 'run', '--system',
                                 '--command=/usr/bin/python3', args.portal_app, '-c', code],
                                capture_output=True, text=True, timeout=20)
        result.check_returncode()
        portal = json.loads(result.stdout)
    after = decoded(call(BUS, OBJECT, 'ListAccessGrants'))
    if before != after:
        raise RuntimeError('Grant projection changed during negative request checks')
    print(json.dumps({'schema': 'greyward.session-bus-compatibility/v1',
                      'coverage': coverage, 'context_coverage': context,
                      'administration': admin, 'context_administration': context_admin,
                      'rejected_requests': rejected, 'grants_unchanged': True,
                      'stock_flatpak_chooser': portal,
                      'portal_origin_binding': 'NOT IMPLEMENTED',
                      'protected_flatpak_review': 'NOT IMPLEMENTED'}, indent=2))


if __name__ == '__main__':
    main()
