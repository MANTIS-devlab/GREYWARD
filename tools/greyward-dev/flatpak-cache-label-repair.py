#!/usr/bin/python3 -I
"""Explicit development repair of imported public icon caches, never home policy.

Only singly linked, user-owned icon-paintable.png files with the historical
var_lib_t label are eligible. Protected labels, aliases, application data and
other cache files are left alone. No secret contents are read.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import pwd
import stat


def repair(home, uid):
    root = Path(home) / '.var/app'
    changed = []
    visited = 0
    library = ctypes.CDLL('libselinux.so.1')
    libc = ctypes.CDLL(None)

    def walk(directory, prefix, depth):
        nonlocal visited
        if depth > 8:
            return
        for name in os.listdir(directory):
            visited += 1
            if visited > 20000:
                raise RuntimeError('Cache metadata limit exceeded')
            try:
                handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
            except OSError:
                continue
            try:
                info = os.fstat(handle)
                if info.st_uid != uid or info.st_dev != root_device:
                    continue
                label = os.getxattr(handle, 'security.selinux').rstrip(b'\0')
                label_type = label.split(b':')[2]
                if stat.S_ISDIR(info.st_mode):
                    # Never traverse a registered protected directory.
                    if label_type == b'user_home_t':
                        walk(handle, prefix / name, depth + 1)
                    continue
                if name != 'icon-paintable.png' or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 5 * 1024 * 1024 or label_type != b'var_lib_t':
                    continue
                expected = ctypes.c_char_p()
                if library.matchpathcon(os.fsencode(prefix/name), info.st_mode, ctypes.byref(expected)):
                    raise RuntimeError('Default cache label unavailable')
                try:
                    replacement = expected.value
                    if replacement.split(b':')[2] != b'user_home_t':
                        continue
                    changed.append({'path':str(prefix/name), 'device':info.st_dev,
                                    'inode':info.st_ino, 'previous':label.decode()})
                    os.setxattr(handle, 'security.selinux', replacement)
                finally:
                    libc.free(expected)
            finally:
                os.close(handle)

    handle = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        root_device = os.fstat(handle).st_dev
        for app in os.listdir(handle):
            try:
                app_handle = os.open(app, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=handle)
            except OSError:
                continue
            try:
                cache = os.open('cache', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=app_handle)
                try:
                    if os.fstat(cache).st_uid == uid and os.getxattr(cache, 'security.selinux').split(b':')[2] == b'user_home_t':
                        # This public catalogue format has an application-named
                        # cache and entry directory. Do not crawl browser caches.
                        catalog = os.open(app, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=cache)
                        try:
                            entries = os.open('entry', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=catalog)
                            try:
                                if os.fstat(entries).st_uid == uid and os.getxattr(entries, 'security.selinux').split(b':')[2] == b'user_home_t':
                                    walk(entries, root/app/'cache'/app/'entry', 0)
                            finally:
                                os.close(entries)
                        finally:
                            os.close(catalog)
                finally:
                    os.close(cache)
            except FileNotFoundError:
                pass
            finally:
                os.close(app_handle)
    finally:
        os.close(handle)
    return changed


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--uid', type=int, required=True)
    options = parser.parse_args()
    if os.getuid() or options.uid < 1000:
        raise RuntimeError('Explicit root development repair for a normal local user required')
    records = repair(pwd.getpwuid(options.uid).pw_dir, options.uid)
    print(json.dumps({'schema':'greyward.public-cache-repair/v1', 'records':records}))
