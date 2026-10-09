#!/usr/bin/python3
"""Test existing root-owned preview identity without approving any operation.

Only an O_PATH metadata preview of a disposable ordinary directory is created.
No registration, labels, grant or authentication is applied. This proves the
native review actor boundary, NOT Flatpak proxy/request recipient association.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

import dbus

BUS = 'systems.mantis.greyward.ApplicationSecurity1'
OBJECT = '/systems/mantis/greyward/ApplicationSecurity1'


def connection():
    bus = dbus.bus.BusConnection('unix:path=/run/dbus/system_bus_socket')
    proxy = dbus.Interface(bus.get_object(BUS, OBJECT, introspect=False), BUS)
    return bus, proxy


def preview(proxy, directory, revision):
    fd = os.open(directory, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        result = json.loads(str(proxy.PreviewResourceRegistration(
            dbus.types.UnixFd(fd), 'CUSTOM', 'Disposable bus review check',
            dbus.UInt64(revision), signature='hsst', timeout=8)))
        if result.get('kind') != 'REGISTRATION':
            raise RuntimeError('Unexpected typed registration preview')
        return result['preview']
    finally:
        os.close(fd)


def foreign(method, reference):
    arguments = ['/usr/bin/busctl', '--system', '--timeout=8', 'call', BUS, OBJECT, BUS,
                 method, 'sb' if method == 'ApplyPolicyChange' else 's', reference]
    if method == 'ApplyPolicyChange':
        arguments.append('false')
    result = subprocess.run(arguments, capture_output=True, timeout=10)
    if result.returncode == 0:
        raise RuntimeError('Foreign process acquired an existing review: ' + method)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exited-owner', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if os.getuid() == 0:
        raise RuntimeError('Run as the enrolled ordinary user')
    bus, proxy = connection()
    coverage = json.loads(str(proxy.GetCoverage(timeout=8)))
    revision = coverage['protection']['policy_revision']
    if args.exited_owner:
        result = preview(proxy, args.exited_owner, revision)
        print(result['operation_ref'])
        bus.close()
        return
    before = str(proxy.ListAccessGrants(timeout=8))
    # /tmp is tmpfs on Fedora and is intentionally ineligible for persistent
    # resource registration. Use an empty disposable directory on home Btrfs.
    with tempfile.TemporaryDirectory(prefix='.greyward-bus-review-', dir=Path.home()) as directory:
        try:
            preview(proxy, directory, max(0, revision - 1))
        except dbus.DBusException:
            pass
        else:
            raise RuntimeError('Stale policy revision was accepted')
        result = preview(proxy, directory, revision)
        reference = result['operation_ref']
        try:
            own = json.loads(str(proxy.GetOperation(reference, signature='s', timeout=8)))
            if own['operation_ref'] != reference or own['outcome'] != 'PENDING':
                raise RuntimeError('Owner could not read the pending review')
            for method in ['GetOperation', 'ApplyPolicyChange']:
                foreign(method, reference)
        finally:
            cancelled = json.loads(str(proxy.CancelOperation(reference, signature='s', timeout=8)))
            if cancelled['operation_ref'] != reference or cancelled['outcome'] != 'CANCELLED':
                raise RuntimeError('Owner cancellation failed')
        child = subprocess.run([sys.executable, str(Path(__file__).resolve()),
                                '--exited-owner', directory],
                               capture_output=True, text=True, timeout=12)
        child.check_returncode()
        exited_ref = child.stdout.strip()
        for method in ['GetOperation', 'ApplyPolicyChange']:
            foreign(method, exited_ref)
        changed = preview(proxy, directory, revision)['operation_ref']
        Path(directory, 'synthetic-change').write_text('not a secret\n')
        # Revalidation fails before authorization. Interactive auth is explicitly
        # disabled; this cannot approve/register the disposable directory.
        proxy.ApplyPolicyChange(changed, False, signature='sb', timeout=8)
        deadline = time.monotonic() + 8
        while True:
            changed_result = json.loads(str(proxy.GetOperation(changed, signature='s', timeout=8)))
            if changed_result['outcome'] not in ['PENDING', 'RUNNING']:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError('Changed selection did not settle within deadline')
            time.sleep(0.1)
        if (changed_result['outcome'] != 'FAILED'
                or changed_result['committed_revision'] is not None
                or changed_result['verified_readback']):
            raise RuntimeError('Changed selection was not refused before commit')
    if before != str(proxy.ListAccessGrants(timeout=8)):
        raise RuntimeError('Grant projection changed')
    print(json.dumps({'schema': 'greyward.session-bus-review-check/v1',
                      'stale_revision_rejected': True, 'live_owner_can_read': True,
                      'other_process_read_and_apply_rejected': True,
                      'exited_owner_read_and_apply_rejected': True,
                      'changed_selection_result': changed_result,
                      'owner_cancel': cancelled, 'owner_operation': own,
                      'grants_unchanged': True, 'authorization_performed': False,
                      'flatpak_request_recipient_binding': 'NOT IMPLEMENTED'}, indent=2))
    bus.close()


if __name__ == '__main__':
    main()
