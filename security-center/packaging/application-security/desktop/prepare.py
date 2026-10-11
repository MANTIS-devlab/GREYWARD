#!/usr/bin/python3 -I
"""Explicit development assembly of matched protected-desktop inputs.

Does not enroll a user, change PAM/mappings or stop a session. The resulting
manifest is immutable packaging input, never positive live coverage evidence.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import re

BASE = Path('/usr/lib/greyward/application-security/desktop')
ACTIVE_BASE = Path('/usr/lib/greyward/application-security/desktop')
STATE = Path('/run/greyward-application-security')
LABWC = 'bd5f5ddec12c066e0893a0a4874cbc5d55e157d5b93d3ebe6cd2bdc7b863ba64'
THEME = Path('/usr/share/greyward/defaults/labwc/Greyward')


def selected_dms():
    """Use the package's complete verifier, never discovery or a claimed path."""
    result = subprocess.run(['/usr/libexec/greyward-dms-verify'], check=True,
                            capture_output=True, text=True, timeout=30)
    root = Path(result.stdout.strip())
    if root.parent != Path('/usr/lib/greyward/dms') or not re.fullmatch(r'v\d+\.\d+\.\d+-\d+', root.name):
        raise RuntimeError('Invalid verified DMS selection')
    return root


def trusted_root_file(path):
    """Require a root-owned file beneath a non-writable, non-symlink path."""
    for item in [path, *path.parents]:
        meta = item.lstat()
        if item.is_symlink() or meta.st_uid or meta.st_mode & 0o022:
            raise RuntimeError('Untrusted compositor receipt')


def compositor_digest(enrollment_path=None, active_base=None):
    """Read a packaged receipt or migrate the compositor from a verified install."""
    enrollment_path = enrollment_path or Path('/usr/share/greyward-application-security/enrollment/inputs.json')
    active_base = active_base or ACTIVE_BASE
    if enrollment_path.exists() or enrollment_path.is_symlink():
        trusted_root_file(enrollment_path)
        data = json.loads(enrollment_path.read_text())
        if data.get('schema') != 'greyward.enrollment-inputs/v1' or data.get('labwcCommit') != '12987307a5de32db5acbb3f59d41277373ab969e' or not re.fullmatch(r'[0-9a-f]{64}', data.get('labwcSha256', '')):
            raise RuntimeError('Invalid compositor build receipt')
        return data['labwcSha256']

    # Older enrolled systems predate the package receipt. Reuse the compositor
    # only when the current protected desktop's root-owned manifest records its
    # exact bytes and expected source commit. This keeps migration pinned to the
    # running installation without accepting an arbitrary host Labwc binary.
    manifest_path = active_base / 'desktop.json'
    labwc_path = active_base / 'bin/labwc'
    if not manifest_path.exists():
        if active_base.exists():
            raise RuntimeError('Existing protected compositor receipt missing')
        return LABWC
    trusted_root_file(manifest_path)
    trusted_root_file(labwc_path)
    data = json.loads(manifest_path.read_text())
    digest = data.get('files', {}).get('bin/labwc', '')
    if (data.get('schema') != 'greyward.protected-desktop/v1'
            or data.get('source', {}).get('labwc') != '12987307a5de32db5acbb3f59d41277373ab969e'
            or not re.fullmatch(r'[0-9a-f]{64}', digest)
            or hashlib.sha256(labwc_path.read_bytes()).hexdigest() != digest):
        raise RuntimeError('Existing protected compositor receipt mismatch')
    return digest


def run(*command):
    subprocess.run(command, check=True, timeout=15)


def copy_theme(source, data_home):
    """Keep canonical decorations inside the immutable display closure.

    The protected compositor must not load user-writable theme code/assets.
    XDG_DATA_HOME replaces the user's data directory, so include all canonical
    buttons alongside themerc in Labwc's actual theme lookup layout.
    """
    for parent in [source, *source.parents]:
        meta = parent.lstat()
        if not parent.is_dir() or parent.is_symlink() or meta.st_uid or meta.st_mode & 0o022:
            raise RuntimeError('Root-owned canonical theme required')
    assets = list(source.iterdir())
    if not any(path.name == 'themerc' for path in assets):
        raise RuntimeError('Canonical theme configuration missing')
    target = data_home / 'themes/Greyward/labwc'
    target.mkdir(mode=0o755, parents=True)
    for path in assets:
        meta = path.lstat()
        if path.is_symlink() or not path.is_file() or meta.st_uid or meta.st_mode & 0o022 or meta.st_size > 65536 or not (path.name == 'themerc' or path.suffix == '.svg'):
            raise RuntimeError('Unsafe canonical theme asset')
        shutil.copyfile(path, target / path.name)
        (target / path.name).chmod(0o444)


def prepare(source, labwc, account_name, materialize_runtime=True):
    if os.getuid() != 0 or os.geteuid() != 0 or BASE.exists():
        raise RuntimeError('New root preparation required')
    account = [line.split(':') for line in Path('/etc/passwd').read_text().splitlines()
               if line.split(':', 1)[0] == account_name]
    if len(account) != 1:
        raise RuntimeError('Exactly one local account required')
    name, _, uid, gid, _, home, shell = account[0]
    uid, gid = int(uid), int(gid)
    if not 1000 <= uid < 60000 or home != '/home/' + name or shell not in ['/usr/bin/zsh', '/bin/bash', '/usr/bin/bash']:
        raise RuntimeError('Unsupported local account')
    expected_labwc = compositor_digest()
    if hashlib.sha256(labwc.read_bytes()).hexdigest() != expected_labwc:
        raise RuntimeError('Matched compositor required')
    dms = selected_dms()
    for parent in [source, *source.parents]:
        meta = parent.lstat()
        if not parent.is_dir() or parent.is_symlink() or meta.st_uid or meta.st_mode & 0o022:
            raise RuntimeError('Root-private source snapshot required')
    BASE.mkdir(mode=0o755, parents=True)
    (BASE / 'bin').mkdir(mode=0o755)
    for component in ['session.py', 'verify.py', 'authentication.py', 'materialize.py']:
        shutil.copyfile(source / component, BASE / component)
        (BASE / component).chmod(0o444)
    for original, target, label in [
        (labwc, 'labwc', 'greyward_as_display_exec_t'),
        (Path('/usr/bin/python3.14'), 'auth-python', 'greyward_as_auth_exec_t'),
        (Path('/usr/bin/dbus-daemon'), 'auth-dbus', 'greyward_as_auth_exec_t'),
        (Path('/usr/bin/qs'), 'qs', 'greyward_as_auth_exec_t'),
        (dms / 'bin/dms', 'dms', 'greyward_as_auth_exec_t'),
    ]:
        shutil.copyfile(original, BASE / 'bin' / target)
        if target == 'labwc' and hashlib.sha256((BASE / 'bin' / target).read_bytes()).hexdigest() != expected_labwc:
            raise RuntimeError('Compositor copy changed')
        (BASE / 'bin' / target).chmod(0o555)
        run('/usr/bin/chcon', '-t', label, str(BASE / 'bin' / target))
    # Root reassembles the auth shell from the verified installed DMS closure.
    run('/usr/bin/python3', '-I', str(source.parent / 'authentication/assemble.py'),
        '--source', str(dms / 'shell'), '--receipt', str(dms / 'release.json'),
        '--output', str(BASE / 'authentication-input'))
    shutil.move(BASE / 'authentication-input/shell', BASE / 'shell')
    run('/usr/bin/chcon', '-R', '-t', 'greyward_as_auth_runtime_t', str(BASE / 'shell'))
    run('/usr/bin/chcon', '-t', 'greyward_as_auth_runtime_t', str(BASE / 'authentication.py'))
    # The current compiled role/attribute receipt is copied from the root-owned
    # admission assembler; activation separately checks the current kernel.
    shutil.copyfile(source / 'ordinary.json', BASE / 'ordinary.json')
    (BASE / 'ordinary.json').chmod(0o444)
    (BASE / 'labwc').mkdir(mode=0o755)
    shutil.copyfile(source / 'rc.xml', BASE / 'labwc/rc.xml')
    rc = (BASE / 'labwc/rc.xml').read_text().replace('/usr/local/bin/greyward-session-lock', '/usr/bin/greyward-guard lock')
    (BASE / 'labwc/rc.xml').write_text(rc)
    (BASE / 'labwc/rc.xml').chmod(0o444)
    copy_theme(THEME, BASE / 'labwc')
    # UWSM's ordinary proxy finalizes startup after root admission. The trusted
    # compositor never launches desktop applications or owns their services.
    (BASE / 'labwc/autostart').write_text('#!/bin/sh\nexit 0\n')
    (BASE / 'labwc/autostart').chmod(0o555)
    # Copies from staging may inherit var_lib_t. These immutable configuration
    # and theme assets are static system data, not writable service state.
    run('/usr/bin/chcon', '-R', '-t', 'usr_t', str(BASE / 'labwc'))
    run('/usr/bin/chcon', '-t', 'bin_t', str(BASE / 'labwc/autostart'))
    import sys
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(source))
    from materialize import materialize
    if materialize_runtime:
        materialize(uid, gid)
    from ctypes import CDLL, c_char_p, byref
    seuser, serange = c_char_p(), c_char_p()
    if CDLL('libselinux.so.1').getseuserbyname(name.encode(), byref(seuser), byref(serange)) != 0:
        raise RuntimeError('Prior mapping unavailable')
    previous = {'seuser': seuser.value.decode(), 'range': serange.value.decode()}
    CDLL(None).free(seuser); CDLL(None).free(serange)
    manifest = {'schema': 'greyward.protected-desktop/v1',
                'source': {'labwc': '12987307a5de32db5acbb3f59d41277373ab969e', 'dms': dms.name},
                'accounts': {str(uid): {'name': name, 'gid': gid, 'home': home, 'previousMapping': previous}},
                'files': {}}
    for path in sorted(BASE.rglob('*')):
        if path.is_symlink():
            raise RuntimeError('No alias input')
        if path.is_file() and '__pycache__' not in path.parts:
            os.chown(path, 0, 0)
            path.chmod(0o555 if path.parent == BASE / 'bin' or path.name == 'autostart' else 0o444)
            manifest['files'][path.relative_to(BASE).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    (BASE / 'desktop.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (BASE / 'desktop.json').chmod(0o444)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--labwc', type=Path, required=True)
    parser.add_argument('--account', required=True)
    parser.add_argument('--output', type=Path, default=BASE)
    parser.add_argument('--no-materialize', action='store_true', help='Stage inputs without touching active authentication runtime')
    options = parser.parse_args()
    BASE = options.output
    for parent in BASE.parent.parents:
        meta = parent.lstat()
        if parent.is_symlink() or meta.st_uid or meta.st_mode & 0o022:
            raise RuntimeError('Root-owned output ancestry required')
    prepare(options.source, options.labwc, options.account, not options.no_materialize)
