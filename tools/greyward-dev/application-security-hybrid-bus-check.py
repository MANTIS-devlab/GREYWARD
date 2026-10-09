#!/usr/bin/python3
"""Non-mutating check of a same-UID session broker's inspection boundary.

Never attach with ptrace, read/write process memory, or copy a valid descriptor.
The intentionally invalid descriptor probes pidfd_getfd's preceding attach-mode
authorization check. This is development evidence, never grant authorization.
"""
import argparse
import ctypes
import errno
import json
import os
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pid', type=int, help='Live broker PID discovered by Codex')
    parser.add_argument('--expect-denied', action='store_true',
                        help='Fail unless both inspection checks are denied')
    args = parser.parse_args()
    if os.getuid() == 0 or os.uname().machine != 'x86_64' or args.pid <= 1:
        parser.error('Run as the enrolled user on x86_64, against a live broker')
    pidfd = os.pidfd_open(args.pid)
    try:
        proc = Path('/proc') / str(args.pid)
        before = (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19]
        uid = (proc / 'status').read_text().split('Uid:')[1].splitlines()[0].split()
        if uid != [str(os.getuid())] * 4 or (proc / 'exe').resolve() != Path('/usr/bin/dbus-broker'):
            parser.error('Target is not the same-UID packaged session broker')
        context = (proc / 'attr/current').read_text().strip('\x00\n')
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
        # Linux x86_64 __NR_pidfd_getfd. fd=-1 is never a valid target handle.
        value = libc.syscall(ctypes.c_long(438), ctypes.c_int(pidfd),
                             ctypes.c_int(-1), ctypes.c_uint(0))
        code = ctypes.get_errno() if value == -1 else 0
        if value != -1:
            os.close(value)
            raise RuntimeError('Invalid-descriptor probe returned an unexpected handle')
        try:
            memory = os.open(proc / 'mem', os.O_RDONLY | os.O_CLOEXEC)
        except PermissionError:
            opened = False
        else:
            opened = True
            os.close(memory)  # No read, mmap or seek.
        after = (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19]
        if before != after or (proc / 'attr/current').read_text().strip('\x00\n') != context:
            raise RuntimeError('Target identity changed; discard the result')
        print(json.dumps({
            'schema': 'greyward.hybrid-session-bus-boundary/v1',
            'pid': args.pid, 'start_ticks': before,
            'caller_context': Path('/proc/self/attr/current').read_text().strip('\x00\n'),
            'target_context': context, 'pidfd_getfd_errno': code,
            'attach_check': 'ALLOWED' if code == errno.EBADF else
                            'DENIED' if code == errno.EPERM else 'UNKNOWN',
            'memory_read_descriptor_opened': opened,
            'bytes_read': 0, 'bytes_written': 0, 'valid_descriptors_copied': 0,
            'bridge_gate': 'BLOCKED' if opened or code == errno.EBADF else 'UNPROVEN'
        }, indent=2))
        if args.expect_denied and (opened or code != errno.EPERM):
            raise RuntimeError('Session bus inspection boundary failed')
    finally:
        os.close(pidfd)


if __name__ == '__main__':
    main()
