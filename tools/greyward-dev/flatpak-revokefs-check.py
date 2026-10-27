#!/usr/bin/python3
"""Run as an ordinary desktop user: exercise Flatpak staging, never deploy apps.

Requires Fedora's PyGObject and revokefs-fuse. Requests only a noninteractive
scratch pull, receives its descriptor, mounts it and creates/renames/removes one
symlink. Always unmounts and cancels that same connection's scratch pull.
This is a compatibility check, not application-install acceptance.
"""
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

from gi.repository import Gio, GLib


def main():
    if os.geteuid() == 0:
        raise RuntimeError('Run in the ordinary graphical user session, not as root')
    bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
    interface = 'org.freedesktop.Flatpak.SystemHelper'
    path = '/org/freedesktop/Flatpak/SystemHelper'
    reply, descriptors = bus.call_with_unix_fd_list_sync(
        interface, path, interface, 'GetRevokefsFd',
        GLib.Variant('(us)', (1, '')), GLib.VariantType.new('(hs)'),
        Gio.DBusCallFlags.NONE, 10000, None, None)
    index, source = reply.unpack()
    descriptor = descriptors.get(index)
    mount = None
    mounted = False
    try:
        assert stat.S_ISSOCK(os.fstat(descriptor).st_mode)
        mount = Path(tempfile.mkdtemp(prefix='greyward-revokefs-check-',
                                     dir=os.environ['XDG_RUNTIME_DIR']))
        subprocess.run(['/usr/libexec/revokefs-fuse', '-o', 'uid=' + str(os.getuid()),
                        '--socket=' + str(descriptor), source, str(mount)],
                       pass_fds=(descriptor,), check=True, timeout=10)
        mounted = True
        os.symlink('probe-target', mount / 'tmplink.greyward')
        assert os.readlink(mount / 'tmplink.greyward') == 'probe-target'
        os.rename(mount / 'tmplink.greyward', mount / 'final-link')
        (mount / 'final-link').unlink()
        print(json.dumps({'descriptor_received': True, 'symlink_staging': True}))
    finally:
        try:
            if mounted:
                subprocess.run(['fusermount3', '-u', str(mount)],
                               check=True, timeout=10)
        finally:
            bus.call_sync(interface, path, interface, 'CancelPull',
                          GLib.Variant('(uss)', (1, '', source)), None,
                          Gio.DBusCallFlags.NONE, 10000, None)
            os.close(descriptor)
            if mount is not None:
                mount.rmdir()


if __name__ == '__main__':
    main()
