#!/usr/bin/python3 -I
"""Read the live ordinary-role bus boundary, without accessing process memory.

Explicit development readback; never installs policy or changes enrollment.
Run as root. Compare baseline and corrected decisions without denying normal
DBus traffic or generically prohibiting descriptor passing.
"""
import argparse
import json
import os
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-denied', action='store_true')
    args = parser.parse_args()
    if os.getuid() or Path('/sys/fs/selinux/enforce').read_text().strip() != '1':
        raise RuntimeError('Root and SELinux Enforcing required')
    sys.path.insert(0, '/usr/lib/greyward/application-security/desktop')
    from verify import kernel_decision
    import setools
    policy = setools.SELinuxPolicy()
    recorded = json.loads(Path('/usr/lib/greyward/application-security/desktop/ordinary.json').read_text())
    ordinary = sorted(str(t) for t in policy.lookup_typeattr('greyward_as_ordinary').expand())
    if ordinary != sorted(recorded['ordinary']):
        raise RuntimeError('Ordinary role closure changed')
    bus = 'greyward_guard_u:greyward_guard_r:greyward_guard_dbusd_t:s0'
    results = {}
    sequence = None
    for domain in ordinary:
        context = f'greyward_guard_u:greyward_guard_r:{domain}:s0'
        allowed, current = kernel_decision(context, bus, 'process', ['ptrace'])
        if sequence is not None and sequence != current:
            raise RuntimeError('Policy changed during readback')
        sequence = current
        results[domain] = bool(allowed)
    adjacent = {}
    guard = 'greyward_guard_u:greyward_guard_r:greyward_guard_t:s0'
    for cls, rights in [('dbus', ['send_msg']), ('fd', ['use']),
                       ('unix_stream_socket', ['connectto', 'read', 'write']),
                       ('process', ['getattr'])]:
        allowed, current = kernel_decision(guard, bus, cls, rights)
        if current != sequence:
            raise RuntimeError('Policy changed during readback')
        adjacent[cls] = allowed
    print(json.dumps({'schema': 'greyward.session-bus-kernel-check/v1',
                      'ordinary_domains': len(ordinary), 'inspection_allowed': results,
                      'adjacent_allowed_masks': adjacent, 'policy_sequence': sequence}, indent=2))
    if args.expect_denied and any(results.values()):
        raise RuntimeError('An admitted ordinary domain can inspect the session bus')


if __name__ == '__main__':
    main()
