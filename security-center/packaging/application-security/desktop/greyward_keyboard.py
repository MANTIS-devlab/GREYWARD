#!/usr/bin/python3
"""Validated per-user XKB settings shared by Labwc and the protected seat."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess

SYSTEM_DEFAULT = Path('/etc/greyward/keyboard-default.env')
DEFAULTS = {
    'XKB_DEFAULT_MODEL': 'pc105',
    'XKB_DEFAULT_LAYOUT': 'us',
    'XKB_DEFAULT_VARIANT': '',
    'XKB_DEFAULT_OPTIONS': '',
}
DEFAULT_NAME = '50-greyward-default-keyboard.env'
OVERRIDE_NAME = '95-greyward-user-keyboard.env'
ALLOWED_KEYS = frozenset(DEFAULTS)
LAYOUTS = re.compile(r'^[A-Za-z0-9_-]+(?:,[A-Za-z0-9_-]+)*$')
VARIANTS = re.compile(r'^(?:[A-Za-z0-9_-]+)?(?:,(?:[A-Za-z0-9_-]+)?)*$')
MODEL = re.compile(r'^[A-Za-z0-9_-]+$')
OPTIONS = re.compile(r'^[A-Za-z0-9_:,.-]*$')


def validate(values, require_layout=True):
    """Return normalized XKB values, rejecting any env or config injection."""
    result = dict(DEFAULTS)
    for key, value in values.items():
        if key not in ALLOWED_KEYS or not isinstance(value, str) or len(value) > 256:
            raise ValueError('Unsupported keyboard setting')
        result[key] = value.strip()
    if require_layout and not LAYOUTS.fullmatch(result['XKB_DEFAULT_LAYOUT']):
        raise ValueError('Invalid XKB layout')
    if result['XKB_DEFAULT_VARIANT'] and not VARIANTS.fullmatch(result['XKB_DEFAULT_VARIANT']):
        raise ValueError('Invalid XKB variant')
    if not MODEL.fullmatch(result['XKB_DEFAULT_MODEL']):
        raise ValueError('Invalid XKB model')
    if not OPTIONS.fullmatch(result['XKB_DEFAULT_OPTIONS']):
        raise ValueError('Invalid XKB options')
    return result


def parse_environment(data):
    """Parse only the four XKB assignments; never source or execute the file."""
    if isinstance(data, bytes):
        data = data.decode('utf-8')
    if not isinstance(data, str) or len(data.encode('utf-8')) > 2048:
        raise ValueError('Keyboard configuration is too large')
    values = {}
    for line in data.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition('=')
        if not separator or key not in ALLOWED_KEYS or key in values:
            raise ValueError('Unexpected keyboard configuration line')
        values[key] = value.strip()
    if 'XKB_DEFAULT_LAYOUT' not in values:
        raise ValueError('Keyboard layout is missing')
    return validate(values)


def serialize_environment(values):
    settings = validate(values)
    return ''.join(f'{key}={settings[key]}\n' for key in (
        'XKB_DEFAULT_MODEL', 'XKB_DEFAULT_LAYOUT',
        'XKB_DEFAULT_VARIANT', 'XKB_DEFAULT_OPTIONS'))


def validate_keymap(values):
    """Require libxkbcommon to compile the exact settings before using them."""
    settings = validate(values)

    class RuleNames(ctypes.Structure):
        _fields_ = [(name, ctypes.c_char_p) for name in
                    ('rules', 'model', 'layout', 'variant', 'options')]

    library = ctypes.CDLL('libxkbcommon.so.0')
    library.xkb_context_new.argtypes = [ctypes.c_int]
    library.xkb_context_new.restype = ctypes.c_void_p
    library.xkb_context_unref.argtypes = [ctypes.c_void_p]
    library.xkb_keymap_new_from_names.argtypes = [ctypes.c_void_p, ctypes.POINTER(RuleNames), ctypes.c_int]
    library.xkb_keymap_new_from_names.restype = ctypes.c_void_p
    library.xkb_keymap_unref.argtypes = [ctypes.c_void_p]
    context = library.xkb_context_new(0)
    if not context:
        raise ValueError('Could not initialize the XKB compiler')
    names = RuleNames(None, settings['XKB_DEFAULT_MODEL'].encode(),
                      settings['XKB_DEFAULT_LAYOUT'].encode(),
                      settings['XKB_DEFAULT_VARIANT'].encode(),
                      settings['XKB_DEFAULT_OPTIONS'].encode())
    try:
        keymap = library.xkb_keymap_new_from_names(context, ctypes.byref(names), 0)
        if not keymap:
            raise ValueError('The selected XKB keyboard layout is not available')
        library.xkb_keymap_unref(keymap)
    finally:
        library.xkb_context_unref(context)
    return settings


def parse_localectl_status(text):
    """Read Anaconda's persisted X11 selection from localed's C-locale output."""
    found = {}
    labels = {
        'X11 Model': 'XKB_DEFAULT_MODEL',
        'X11 Layout': 'XKB_DEFAULT_LAYOUT',
        'X11 Variant': 'XKB_DEFAULT_VARIANT',
        'X11 Options': 'XKB_DEFAULT_OPTIONS',
    }
    for line in text.splitlines():
        label, separator, value = line.strip().partition(':')
        if separator and label in labels and value.strip():
            found[labels[label]] = value.strip()
    if not found.get('XKB_DEFAULT_LAYOUT'):
        keymap = next((line.partition(':')[2].strip() for line in text.splitlines()
                       if line.strip().startswith('VC Keymap:')), '')
        # Common vconsole aliases have an unambiguous XKB counterpart.
        aliases = {'us': 'us', 'fr': 'fr', 'de': 'de', 'gb': 'gb', 'uk': 'gb',
                   'es': 'es', 'it': 'it', 'be': 'be', 'ca': 'ca'}
        found['XKB_DEFAULT_LAYOUT'] = aliases.get(keymap, DEFAULTS['XKB_DEFAULT_LAYOUT'])
    return validate(found)


def installed_defaults():
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
    try:
        result = subprocess.run(['/usr/bin/localectl', '--no-pager', 'status'],
                                check=True, capture_output=True, text=True,
                                timeout=5, env=env)
        return parse_localectl_status(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        return dict(DEFAULTS)


def _read_fd(fd, expected_uid, maximum=2048):
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid or
            info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size > maximum):
        raise ValueError('Unsafe keyboard configuration file')
    data = bytearray()
    while len(data) <= maximum:
        chunk = os.read(fd, min(1024, maximum + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    if len(data) > maximum:
        raise ValueError('Keyboard configuration is too large')
    return bytes(data)


def _open_directory(parent_fd, name, owner):
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                 dir_fd=parent_fd)
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
        os.close(fd)
        raise ValueError('Unsafe keyboard configuration directory')
    return fd


def _read_home_file(home, uid, filename):
    """Open a fixed per-user settings file without following path aliases."""
    fds = []
    try:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        fds.append(fd)
        for name, owner in [('home', 0), (Path(home).name, uid),
                            ('.config', uid), ('labwc', uid), ('environment.d', uid)]:
            fd = _open_directory(fd, name, owner)
            fds.append(fd)
        file_fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                          dir_fd=fds[-1])
        try:
            return _read_fd(file_fd, uid)
        finally:
            os.close(file_fd)
    except FileNotFoundError:
        return None
    finally:
        for fd in reversed(fds):
            os.close(fd)


def _read_system_default(path=SYSTEM_DEFAULT):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return dict(DEFAULTS)
    try:
        data = _read_fd(fd, 0)
        return parse_environment(data)
    except (OSError, ValueError):
        return dict(DEFAULTS)
    finally:
        os.close(fd)


def user_environment(home, uid, system_default=SYSTEM_DEFAULT):
    """Return validated settings without reading arbitrary user configuration."""
    result = _read_system_default(system_default)
    try:
        result = validate(result)
    except (OSError, ValueError):
        result = dict(DEFAULTS)
    for filename in (DEFAULT_NAME, OVERRIDE_NAME):
        try:
            raw = _read_home_file(home, uid, filename)
            if raw is not None:
                candidate = dict(result)
                candidate.update(parse_environment(raw))
                result = validate(candidate)
        except (OSError, ValueError):
            # A damaged or hostile preference must not block the protected seat.
            continue
    return result


def protected_environment(home, uid, system_default=SYSTEM_DEFAULT):
    """Return the fixed, validated keyboard settings for the protected Labwc."""
    return user_environment(home, uid, system_default)


def _open_checked_directory(path, owner, group):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError('Keyboard settings path must be absolute')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    current = Path('/')
    try:
        for part in path.parts[1:]:
            current /= part
            expected_owner = owner if owner and current.is_relative_to(Path('/home') / path.parts[2]) else 0
            try:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  dir_fd=fd)
            except FileNotFoundError:
                os.mkdir(part, 0o700 if expected_owner else 0o755, dir_fd=fd)
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  dir_fd=fd)
                os.fchown(next_fd, expected_owner, group if expected_owner else 0)
            info = os.fstat(next_fd)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_owner or info.st_mode & 0o022:
                os.close(next_fd)
                raise ValueError('Keyboard settings directory has unsafe ownership or mode')
            os.close(fd)
            fd = next_fd
        return fd
    except Exception:
        os.close(fd)
        raise


def _ensure_directory(path, owner, group):
    fd = _open_checked_directory(path, owner, group)
    os.close(fd)


def _atomic_write(path, data, owner, group, mode, preserve=False):
    path = Path(path)
    _ensure_directory(path.parent, owner, group)
    if preserve:
        try:
            info = path.lstat()
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISREG(info.st_mode) or info.st_uid != owner:
                raise ValueError('Existing keyboard configuration is unsafe')
            return False
    directory_fd = _open_checked_directory(path.parent, owner, group)
    temporary = f'.greyward-keyboard-{os.getpid()}-{secrets.token_hex(6)}'
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     mode, dir_fd=directory_fd)
        try:
            os.fchown(fd, owner, group)
            os.fchmod(fd, mode)
            offset = 0
            while offset < len(data):
                offset += os.write(fd, data[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(temporary, path.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    except Exception:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(directory_fd)
    return True


def seed_user(username):
    if os.geteuid() != 0:
        raise PermissionError('Seeding keyboard defaults requires root')
    import pwd
    account = pwd.getpwnam(username)
    if not 1000 <= account.pw_uid < 60000 or account.pw_dir != f'/home/{username}':
        raise ValueError('Unsupported local user account')
    defaults = installed_defaults()
    encoded = serialize_environment(defaults).encode('utf-8')
    _atomic_write(SYSTEM_DEFAULT, encoded, 0, 0, 0o644)
    _atomic_write(Path('/etc/skel/.config/labwc/environment.d') / DEFAULT_NAME,
                  encoded, 0, 0, 0o644)
    _atomic_write(Path(account.pw_dir) / '.config/labwc/environment.d' / DEFAULT_NAME,
                  encoded, account.pw_uid, account.pw_gid, 0o600, preserve=True)


def apply_user(layout, variant, model, options):
    uid = os.getuid()
    if os.geteuid() != uid or uid == 0:
        raise PermissionError('Keyboard preferences must be saved by the signed-in user')
    home = Path(os.environ.get('HOME', ''))
    if not home.is_absolute() or home == Path('/') or home.stat().st_uid != uid:
        raise ValueError('Signed-in user home is unavailable')
    requested = any(value.strip() for value in (layout, variant, model, options))
    supplied = {
        'XKB_DEFAULT_LAYOUT': layout,
        'XKB_DEFAULT_VARIANT': variant,
        'XKB_DEFAULT_MODEL': model or DEFAULTS['XKB_DEFAULT_MODEL'],
        'XKB_DEFAULT_OPTIONS': options,
    }
    if not requested:
        directory = home / '.config/labwc/environment.d'
        _ensure_directory(directory, uid, os.getgid())
        try:
            info = (directory / OVERRIDE_NAME).lstat()
        except FileNotFoundError:
            return
        if info.st_uid != uid:
            raise ValueError('Existing keyboard preference is not user-owned')
        (directory / OVERRIDE_NAME).unlink()
        return
    if not layout.strip():
        defaults = protected_environment(home, uid)
        supplied['XKB_DEFAULT_LAYOUT'] = defaults['XKB_DEFAULT_LAYOUT']
        supplied['XKB_DEFAULT_MODEL'] = supplied['XKB_DEFAULT_MODEL'] or defaults['XKB_DEFAULT_MODEL']
    encoded = serialize_environment(validate_keymap(supplied)).encode('utf-8')
    _atomic_write(home / '.config/labwc/environment.d' / OVERRIDE_NAME,
                  encoded, uid, os.getgid(), 0o600)


def exec_with_keyboard_environment(argv):
    """Start the normal session launcher with only the validated XKB values added."""
    if not argv:
        raise ValueError('A session command is required')
    if os.geteuid() == 0:
        raise PermissionError('The desktop session must start as the signed-in user')
    import pwd
    account = pwd.getpwuid(os.getuid())
    home = Path(os.environ.get('HOME', ''))
    if (not home.is_absolute() or home != Path(account.pw_dir) or
            home.stat().st_uid != os.getuid() or home != Path('/home') / account.pw_name):
        raise ValueError('Signed-in user home is unavailable')
    env = os.environ.copy()
    env.update(user_environment(str(home), os.getuid()))
    os.execvpe(argv[0], argv, env)


def main():
    parser = argparse.ArgumentParser(description='Manage the signed-in user keyboard layout.')
    sub = parser.add_subparsers(dest='command', required=True)
    seed = sub.add_parser('seed')
    seed.add_argument('username')
    apply = sub.add_parser('apply')
    apply.add_argument('layout')
    apply.add_argument('variant')
    apply.add_argument('model')
    apply.add_argument('options')
    start = sub.add_parser('exec')
    start.add_argument('argv', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command == 'seed':
        seed_user(args.username)
    elif args.command == 'apply':
        apply_user(args.layout, args.variant, args.model, args.options)
    else:
        argv = args.argv[1:] if args.argv[:1] == ['--'] else args.argv
        exec_with_keyboard_environment(argv)


if __name__ == '__main__':
    main()
