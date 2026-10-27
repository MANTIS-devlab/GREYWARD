#!/usr/bin/python3 -I
"""Explicit quiescent compositor update; preserve the protected account/auth inputs."""
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

ENROLLMENT = Path('/usr/share/greyward-application-security/enrollment')
COMPOSITOR = Path('/usr/libexec/greyward-protected-labwc')
MIGRATION = Path('/usr/libexec/greyward-migrate-protected-dms-shell')


def recover_quiescent_console(migration, accounts):
    """Undo a killed guardian's tty label only after the whole seat is absent.

    A forced activation logout can kill the guardian before its finally block.
    Leaving the protected tty label then prevents greetd's ordinary shell from
    reaching login.py, which would detach its console descriptors. Never grant
    ordinary tty access or relabel a live protected seat to work around this.
    """
    state = subprocess.run(
        ['/usr/bin/systemctl', 'show', 'greetd.service', '--value', '-p', 'ActiveState'],
        check=True, capture_output=True, text=True, timeout=10).stdout.strip()
    if state != 'inactive':
        raise RuntimeError('Stopped login service required for console recovery')
    migration.ensure_quiescent(accounts)
    if any(Path('/run/greyward-application-security').glob('seat-*.json')):
        raise RuntimeError('Seat receipt remains; refusing console recovery')
    for process in Path('/proc').iterdir():
        if not process.name.isdigit():
            continue
        try:
            context = (process / 'attr/current').read_text().strip('\0\n')
        except (FileNotFoundError, ProcessLookupError):
            continue
        if context in (
                'greyward_guard_u:greyward_guard_r:greyward_as_display_t:s0',
                'system_u:system_r:greyward_as_auth_t:s0'):
            raise RuntimeError('Protected worker remains; refusing console recovery')
    console = Path('/dev/tty1')
    metadata = console.lstat()
    if (not stat.S_ISCHR(metadata.st_mode) or metadata.st_uid != 0
            or metadata.st_rdev != os.makedev(4, 1)):
        raise RuntimeError('Fixed root-owned VT console required')
    expected = subprocess.run(
        ['/usr/sbin/matchpathcon', '-n', str(console)], check=True,
        capture_output=True, text=True, timeout=10).stdout.strip()
    if expected != 'system_u:object_r:tty_device_t:s0':
        raise RuntimeError('Unexpected canonical console label')
    current = os.getxattr(console, 'security.selinux', follow_symlinks=False).decode().strip('\0')
    if current == expected:
        return False
    if current != 'system_u:object_r:greyward_as_seat_tty_t:s0':
        raise RuntimeError('Unexpected console label; refusing recovery')
    # Recheck immediately before restoring only the canonical device label.
    migration.ensure_quiescent(accounts)
    os.setxattr(console, 'security.selinux', expected.encode(), follow_symlinks=False)
    if os.getxattr(console, 'security.selinux', follow_symlinks=False).decode().strip('\0') != expected:
        raise RuntimeError('Console recovery readback failed')
    return True


def updated_receipts(desktop_bytes, admin_bytes, inputs, binary, patch):
    desktop, admin = json.loads(desktop_bytes), json.loads(admin_bytes)
    digest = lambda data: hashlib.sha256(data).hexdigest()
    if (inputs.get('schema') != 'greyward.enrollment-inputs/v1'
            or inputs.get('labwcCommit') != desktop.get('source', {}).get('labwc')
            or inputs.get('labwcSha256') != digest(binary)
            or inputs.get('screenshotPatchSha256') != digest(patch)
            or desktop.get('schema') != 'greyward.protected-desktop/v1'
            or admin.get('schema') != 'greyward.administration/v1'
            or admin.get('desktop') != digest(desktop_bytes)):
        raise RuntimeError('Compositor/package/linked receipt mismatch')
    desktop['files']['bin/labwc'] = digest(binary)
    desktop['source']['screenshotPatchSha256'] = digest(patch)
    refreshed = (json.dumps(desktop, indent=2) + '\n').encode()
    admin['desktop'] = digest(refreshed)
    return refreshed, (json.dumps(admin, indent=2) + '\n').encode()


def main():
    import fcntl
    if os.getuid() != 0 or os.geteuid() != 0:
        raise RuntimeError('Explicit trusted root migration required')
    for path in (MIGRATION, *MIGRATION.parents):
        metadata = path.lstat()
        if path.is_symlink() or metadata.st_uid or metadata.st_mode & 0o022:
            raise RuntimeError('Immutable migration module required')
    if not stat.S_ISREG(MIGRATION.stat().st_mode):
        raise RuntimeError('Migration module must be a regular file')
    loader = importlib.machinery.SourceFileLoader('protected_migration', str(MIGRATION))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    migration = importlib.util.module_from_spec(spec)
    loader.exec_module(migration)
    migration.trusted_file(MIGRATION)
    def run(*args, **kwargs):
        return subprocess.run(args, check=True, capture_output=True, text=True, timeout=60, **kwargs)
    if run('/usr/sbin/getenforce').stdout.strip() != 'Enforcing':
        raise RuntimeError('SELinux must remain enforcing')
    if run('/usr/bin/systemctl', 'show', 'greetd.service', '--value', '-p', 'ActiveState').stdout.strip() != 'inactive':
        raise RuntimeError('Stop the login service in the approved activation window first')
    lock_fd = os.open(migration.LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    metadata = os.fstat(lock_fd)
    if metadata.st_uid or metadata.st_nlink != 1 or metadata.st_mode & 0o022:
        os.close(lock_fd)
        raise RuntimeError('Trusted migration lock required')
    work = None
    changed = False
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        base, admin = migration.BASE, migration.ADMIN
        desktop_path, admin_path = base / 'desktop.json', admin / 'manifest.json'
        desktop_bytes = migration.trusted_file(desktop_path)
        admin_bytes = migration.trusted_file(admin_path)
        desktop = json.loads(desktop_bytes)
        migration.trusted_tree(base, desktop)
        migration.verify_admin_tree(json.loads(admin_bytes), admin)
        accounts = [account['name'] for account in desktop['accounts'].values()]
        migration.ensure_quiescent(accounts)
        inputs = json.loads(migration.trusted_file(ENROLLMENT / 'inputs.json'))
        candidate = migration.trusted_file(COMPOSITOR)
        patch = migration.trusted_file(ENROLLMENT / 'patches/labwc-screenshot.patch')
        updated_desktop, updated_admin = updated_receipts(desktop_bytes, admin_bytes, inputs, candidate, patch)
        previous_binary = migration.trusted_file(base / 'bin/labwc')
        policy = ENROLLMENT / 'policy/greyward_application_display.pp'
        migration.trusted_file(policy)
        work = Path(tempfile.mkdtemp(prefix='.screenshot-migration-', dir=base.parent))
        # Extract the exact active module before any kernel/file modification.
        run('/usr/sbin/semodule', '-X', '400', '--cil', '-E', 'greyward_application_display', cwd=work)
        previous_policy = work / 'greyward_application_display.cil'
        migration.trusted_file(previous_policy)
        migration.ensure_quiescent(accounts)
        recover_quiescent_console(migration, accounts)
        changed = True
        run('/usr/sbin/semodule', '-i', str(policy))
        migration.atomic_write(base / 'bin/labwc', candidate, 0o555, base / 'bin/labwc')
        migration.atomic_write(desktop_path, updated_desktop, 0o444, desktop_path)
        migration.atomic_write(admin_path, updated_admin, 0o444, admin_path)
        migration.trusted_tree(base, json.loads(migration.trusted_file(desktop_path)))
        migration.verify_admin_tree(json.loads(migration.trusted_file(admin_path)), admin)
        if json.loads(migration.trusted_file(admin_path))['desktop'] != migration.digest(migration.trusted_file(desktop_path)):
            raise RuntimeError('Linked Administration receipt mismatch')
        print('Protected compositor and display policy updated; account/authentication files preserved. Login validation pending.')
    except Exception:
        if changed:
            migration.atomic_write(base / 'bin/labwc', previous_binary, 0o555, base / 'bin/labwc')
            migration.atomic_write(desktop_path, desktop_bytes, 0o444, desktop_path)
            migration.atomic_write(admin_path, admin_bytes, 0o444, admin_path)
            run('/usr/sbin/semodule', '-i', str(previous_policy))
        raise
    finally:
        if work is not None:
            shutil.rmtree(work)
        os.close(lock_fd)


if __name__ == '__main__':
    main()
