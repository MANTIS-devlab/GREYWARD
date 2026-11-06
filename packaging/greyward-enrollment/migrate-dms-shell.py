#!/usr/bin/python3 -I
"""Refresh an enrolled protected desktop from its verified selected DMS RPM.

This is an explicit root migration. It refuses to touch a running protected
desktop, validates the current immutable receipts and the selected DMS release,
then updates the copied DMS executable, authentication shell, protected login
inputs, seat verifier and dependent receipts as one rollback-capable operation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shutil
import stat
import subprocess
import tempfile

BASE = Path('/usr/lib/greyward/application-security/desktop')
ADMIN = Path('/usr/lib/greyward/application-security/administration')
ASSEMBLER = Path('/usr/share/greyward-application-security/authentication/assemble.py')
DESKTOP_SOURCE = Path('/usr/share/greyward-application-security/desktop')
SELECTOR = Path('/etc/greyward/dms-release')
VERIFY = Path('/usr/libexec/greyward-dms-verify')
LOCK = Path('/run/lock/greyward-protected-dms-migration.lock')
USBGUARD_POLICY = Path('/usr/share/greyward-application-security/enrollment/policy/greyward_application_usbguard_approval.pp')
USBGUARD_HELPERS = (
    Path('/usr/libexec/greyward-usbguard-approval'),
    Path('/usr/libexec/greyward-usbguard-auth-approval'),
)
AUTH_RUNTIME_ROOT = Path('/run/greyward-application-security')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def trusted_file(path, maximum=128 * 1024 * 1024):
    path = Path(path)
    for parent in (path, *path.parents):
        metadata = parent.lstat()
        if parent.is_symlink() or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise RuntimeError(f'Untrusted root-owned path: {parent}')
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > maximum:
        raise RuntimeError(f'Unsafe regular file required: {path}')
    return path.read_bytes()


def trusted_tree(root, manifest):
    root = Path(root)
    metadata = root.lstat()
    if root.is_symlink() or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise RuntimeError('Protected desktop directory is not immutable')
    files = manifest.get('files')
    if not isinstance(files, dict) or not files:
        raise RuntimeError('Protected desktop file receipt is missing')
    for name, expected in files.items():
        relative = PurePosixPath(name)
        if relative.is_absolute() or '..' in relative.parts or not re.fullmatch(r'[0-9a-f]{64}', expected):
            raise RuntimeError('Invalid protected desktop file receipt')
        actual = digest(trusted_file(root.joinpath(*relative.parts)))
        if actual != expected:
            raise RuntimeError(f'Protected desktop receipt mismatch: {name}')
    return files


def update_desktop_manifest(manifest, release_id, binary_digest, shell_root,
                            authentication, authentication_worker, materialize,
                            keyboard_json, keyboard_config, session, verifier):
    updated = json.loads(json.dumps(manifest))
    updated.setdefault('source', {})['dms'] = release_id
    files = updated['files']
    for name in list(files):
        if name.startswith('shell/'):
            del files[name]
    for path in sorted(Path(shell_root).rglob('*')):
        if path.is_symlink():
            raise RuntimeError('DMS authentication shell contains an alias')
        if path.is_file():
            relative = path.relative_to(shell_root).as_posix()
            files['shell/' + relative] = digest(path.read_bytes())
    files['bin/dms'] = binary_digest
    files['authentication-input/authentication.json'] = digest(authentication)
    files['authentication.py'] = digest(authentication_worker)
    files['materialize.py'] = digest(materialize)
    files['keyboard.json'] = digest(keyboard_json)
    files['keyboard_config.py'] = digest(keyboard_config)
    files['session.py'] = digest(session)
    files['verify.py'] = digest(verifier)
    return updated


def update_admin_manifest(manifest, new_desktop):
    updated = json.loads(json.dumps(manifest))
    # The caller verifies the existing desktop file tree and Administration
    # files/tools independently before reaching this function. A stale but
    # well-formed cross-reference can therefore be repaired during migration
    # without accepting unverified content or rebuilding the admin boundary.
    if (updated.get('schema') != 'greyward.administration/v1'
            or not isinstance(updated.get('desktop'), str)
            or not re.fullmatch(r'[0-9a-f]{64}', updated['desktop'])):
        raise RuntimeError('Administration receipt is invalid')
    updated['desktop'] = digest(new_desktop)
    return updated


def update_verifier_manifest(manifest, verifier, *, session_only=False):
    """Bind a refreshed seat verifier into the immutable desktop receipt."""
    updated = json.loads(json.dumps(manifest))
    if (updated.get('schema') != 'greyward.protected-desktop/v1'
            or not isinstance(updated.get('files'), dict)):
        raise RuntimeError('Protected desktop receipt is invalid')
    updated['files']['session.py' if session_only else 'verify.py'] = digest(verifier)
    return updated


def payload_matches_current(desktop, release_id, binary_digest, shell_root,
                            authentication, authentication_worker, materialize,
                            keyboard_json, keyboard_config, session, verifier):
    """Return true only when DMS and protected login/verifier inputs match."""
    files = desktop.get('files', {})
    current_shell = {name[len('shell/'):]: expected for name, expected in files.items()
                     if name.startswith('shell/')}
    assembled_shell = {path.relative_to(shell_root).as_posix(): digest(path.read_bytes())
                       for path in Path(shell_root).rglob('*') if path.is_file()}
    return (desktop.get('source', {}).get('dms') == release_id
            and files.get('bin/dms') == binary_digest
            and files.get('authentication-input/authentication.json') == digest(authentication)
            and files.get('authentication.py') == digest(authentication_worker)
            and files.get('materialize.py') == digest(materialize)
            and files.get('keyboard.json') == digest(keyboard_json)
            and files.get('keyboard_config.py') == digest(keyboard_config)
            and files.get('session.py') == digest(session)
            and files.get('verify.py') == digest(verifier)
            and current_shell == assembled_shell)


def verify_admin_tree(manifest, root):
    if not isinstance(manifest.get('files'), dict) or not isinstance(manifest.get('tools'), dict):
        raise RuntimeError('Invalid Administration receipt')
    for name, expected in manifest['files'].items():
        if '/' in name or name in ('.', '..') or not re.fullmatch(r'[0-9a-f]{64}', expected):
            raise RuntimeError('Invalid Administration file receipt')
        if digest(trusted_file(Path(root) / name)) != expected:
            raise RuntimeError(f'Administration receipt mismatch: {name}')
    for name, expected in manifest['tools'].items():
        if not Path(name).is_absolute() or not re.fullmatch(r'[0-9a-f]{64}', expected):
            raise RuntimeError('Invalid Administration tool receipt')
        if digest(trusted_file(name)) != expected:
            raise RuntimeError(f'Administration tool receipt mismatch: {name}')


def selected_dms():
    result = subprocess.run([str(VERIFY)], check=True, capture_output=True, text=True, timeout=30)
    root = Path(result.stdout.strip())
    if (root.parent != Path('/usr/lib/greyward/dms')
            or not re.fullmatch(r'v\d+\.\d+\.\d+-\d+', root.name)):
        raise RuntimeError('Invalid verified DMS selection')
    if root != root.resolve():
        raise RuntimeError('DMS selection contains an alias')
    trusted_file(root / 'release.json')
    trusted_file(root / 'bin/dms')
    return root


def _owned_runtime_directory(path, owner_uid):
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    if (path.is_symlink() or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != owner_uid or metadata.st_mode & 0o022):
        raise RuntimeError(f'Unsafe protected authentication runtime directory: {path}')
    return True


def _label_runtime_endpoint(path, owner_uid, expected_type):
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if (path.is_symlink() or not expected_type(metadata.st_mode)
            or metadata.st_uid != owner_uid or metadata.st_mode & 0o077
            or (stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1)):
        raise RuntimeError(f'Unsafe protected authentication runtime endpoint: {path}')
    subprocess.run(['/usr/sbin/restorecon', str(path)], check=True, timeout=10)
    subprocess.run(['/usr/sbin/matchpathcon', '-V', str(path)], check=True, timeout=10)


def label_existing_usbguard_runtime(runtime, owner_uid):
    """Repair stale labels left by sessions that predate the USB IPC policy."""
    if not _owned_runtime_directory(runtime.parent, 0):
        return
    if not _owned_runtime_directory(runtime, owner_uid):
        return
    metadata = runtime / 'usbguard-approval'
    if _owned_runtime_directory(metadata, owner_uid):
        _label_runtime_endpoint(metadata / 'readiness.json', owner_uid, stat.S_ISREG)
        subprocess.run(['/usr/sbin/restorecon', str(metadata)], check=True, timeout=10)
        subprocess.run(['/usr/sbin/matchpathcon', '-V', str(metadata)], check=True, timeout=10)

    quickshell = runtime / 'quickshell'
    if not _owned_runtime_directory(quickshell, owner_uid):
        return
    by_id = quickshell / 'by-id'
    if not _owned_runtime_directory(by_id, owner_uid):
        return
    for instance in sorted(by_id.iterdir()):
        if instance.is_symlink():
            raise RuntimeError(f'Unsafe protected authentication runtime directory: {instance}')
        if not stat.S_ISDIR(instance.lstat().st_mode):
            continue
        if not _owned_runtime_directory(instance, owner_uid):
            continue
        _label_runtime_endpoint(instance / 'instance.lock', owner_uid, stat.S_ISREG)
        _label_runtime_endpoint(instance / 'ipc.sock', owner_uid, stat.S_ISSOCK)


def activate_usbguard_approval_policy(accounts):
    """Load the fixed USB IPC policy and repair executable/runtime labels."""
    trusted_file(USBGUARD_POLICY)
    subprocess.run(['/usr/sbin/semodule', '-i', str(USBGUARD_POLICY)],
                   check=True, timeout=60)
    for helper in USBGUARD_HELPERS:
        trusted_file(helper)
        metadata = helper.stat()
        if (metadata.st_uid != 0 or metadata.st_gid != 0
                or metadata.st_mode & 0o022 or not metadata.st_mode & 0o111):
            raise RuntimeError(f'USB approval helper is not a protected root-owned executable: {helper.name}')
        subprocess.run(['/usr/sbin/restorecon', str(helper)], check=True, timeout=10)
        subprocess.run(['/usr/sbin/matchpathcon', '-V', str(helper)],
                       check=True, timeout=10)
    for account in sorted(accounts):
        try:
            owner_uid = pwd.getpwnam(account).pw_uid
        except KeyError as error:
            raise RuntimeError(f'Protected desktop account is missing: {account}') from error
        if owner_uid < 1000:
            raise RuntimeError(f'Invalid protected desktop account UID: {account}')
        runtime = AUTH_RUNTIME_ROOT / f'auth-{owner_uid}' / 'runtime'
        label_existing_usbguard_runtime(runtime, owner_uid)


def ended_session_locator(values, sid):
    """Ignore a logind tombstone only when both kernel owners are absent."""
    if (values.get('State') != 'closing' or values.get('Active') != 'no'
            or not re.fullmatch(r'[0-9]+', values.get('User', ''))
            or not re.fullmatch(r'[1-9][0-9]*', values.get('Leader', ''))
            or not re.fullmatch(r'[A-Za-z0-9]+', sid)
            or values.get('Scope') != f'session-{sid}.scope'):
        return False
    uid, leader = int(values['User']), int(values['Leader'])
    if uid < 1000:
        return False
    try:
        if (Path(f'/proc/{leader}').exists()
                or Path(f'/sys/fs/cgroup/user.slice/user-{uid}.slice/session-{sid}.scope').exists()):
            return False
        result = subprocess.run(['/usr/bin/systemctl', 'show', values['Scope'],
                                 '-p', 'ActiveState', '--value'],
                                check=True, capture_output=True, text=True, timeout=3)
        return result.stdout.strip() == 'inactive'
    except (OSError, subprocess.SubprocessError):
        return False


def ensure_quiescent(accounts):
    sessions = subprocess.run(['/usr/bin/loginctl', 'list-sessions', '--no-legend', '--no-pager'],
                              check=True, capture_output=True, text=True, timeout=5)
    for line in sessions.stdout.splitlines():
        fields = line.split()
        if not fields:
            continue
        result = subprocess.run(['/usr/bin/loginctl', 'show-session', fields[0],
                                 '-p', 'Name', '-p', 'Class', '-p', 'Seat', '-p', 'Remote',
                                 '-p', 'User', '-p', 'State', '-p', 'Active', '-p', 'Scope', '-p', 'Leader'],
                                check=True, capture_output=True, text=True, timeout=3)
        values = dict(item.split('=', 1) for item in result.stdout.splitlines() if '=' in item)
        if (values.get('Name') in accounts and values.get('Class') in {'user', 'user-early'}
                and values.get('Seat') == 'seat0' and values.get('Remote') == 'no'
                and not ended_session_locator(values, fields[0])):
            raise RuntimeError('Log out of the protected desktop first; protected desktop files are unchanged')

    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            executable = (entry / 'exe').resolve()
        except (FileNotFoundError, PermissionError, OSError):
            continue
        try:
            executable.relative_to(BASE / 'bin')
        except ValueError:
            continue
        raise RuntimeError('A protected desktop process is still running; protected desktop files are unchanged')


def atomic_write(path, data, mode, reference):
    path = Path(path)
    temporary = path.with_name('.' + path.name + '.migration-' + str(os.getpid()))
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temporary, 0, 0)
        os.chmod(temporary, mode)
        subprocess.run(['/usr/bin/chcon', '--reference', str(reference), str(temporary)],
                       check=True, timeout=5)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def copy_metadata(source, target):
    shutil.copyfile(source, target)
    os.chown(target, 0, 0)
    os.chmod(target, 0o444)


def migrate_verifier_only(base=BASE, admin=ADMIN,
                          desktop_source=DESKTOP_SOURCE, *, session_only=False):
    """Refresh only verify.py and its two receipts, with a quiescent rollback."""
    import fcntl
    fixed_input = 'session.py' if session_only else 'verify.py'
    label = 'session guardian' if session_only else 'seat verifier'
    base, admin, desktop_source = map(Path, (base, admin, desktop_source))
    lock_fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    work = None
    commit_started = False
    try:
        metadata = os.fstat(lock_fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                or metadata.st_nlink != 1 or metadata.st_mode & 0o077):
            raise RuntimeError('Unsafe migration lock')
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        desktop_path = base / 'desktop.json'
        admin_path = admin / 'manifest.json'
        desktop_bytes = trusted_file(desktop_path, 1024 * 1024)
        desktop = json.loads(desktop_bytes)
        if desktop.get('schema') != 'greyward.protected-desktop/v1':
            raise RuntimeError('Existing protected desktop receipt is unsupported')
        trusted_tree(base, desktop)
        if fixed_input not in desktop['files']:
            raise RuntimeError('Protected verifier is missing from its receipt')
        accounts = {item.get('name') for item in desktop.get('accounts', {}).values()
                    if isinstance(item, dict) and isinstance(item.get('name'), str)}
        if not accounts:
            raise RuntimeError('Protected desktop account receipt is missing')
        ensure_quiescent(accounts)

        admin_bytes = trusted_file(admin_path, 1024 * 1024)
        admin_manifest = json.loads(admin_bytes)
        verify_admin_tree(admin_manifest, admin)
        verifier_source = desktop_source / fixed_input
        verifier_bytes = trusted_file(verifier_source, 128 * 1024)
        compile(verifier_bytes, str(verifier_source), 'exec')
        previous_verifier = trusted_file(base / fixed_input, 128 * 1024)
        if digest(verifier_bytes) == digest(previous_verifier):
            return f'Protected {label} already matches the verified source.'

        new_desktop = update_verifier_manifest(desktop, verifier_bytes, session_only=session_only)
        new_desktop_bytes = (json.dumps(new_desktop, indent=2) + '\n').encode()
        new_admin = update_admin_manifest(admin_manifest, new_desktop_bytes)
        new_admin_bytes = (json.dumps(new_admin, indent=2) + '\n').encode()
        work = Path(tempfile.mkdtemp(prefix='.verifier-migration-', dir=base.parent))
        os.chown(work, 0, 0)
        os.chmod(work, 0o700)
        ensure_quiescent(accounts)

        commit_started = True
        atomic_write(base / fixed_input, verifier_bytes, 0o444, base / fixed_input)
        atomic_write(desktop_path, new_desktop_bytes, 0o444, desktop_path)
        atomic_write(admin_path, new_admin_bytes, 0o444, admin_path)

        refreshed = json.loads(trusted_file(desktop_path, 1024 * 1024))
        trusted_tree(base, refreshed)
        refreshed_admin = json.loads(trusted_file(admin_path, 1024 * 1024))
        verify_admin_tree(refreshed_admin, admin)
        if refreshed_admin.get('desktop') != digest(trusted_file(desktop_path, 1024 * 1024)):
            raise RuntimeError('Administration receipt did not refresh')
        return f'Protected {label} and dependent receipts refreshed. Log in again to use the update.'
    except Exception:
        if commit_started:
            atomic_write(base / fixed_input, previous_verifier, 0o444, base / fixed_input)
            atomic_write(base / 'desktop.json', desktop_bytes, 0o444, base / 'desktop.json')
            atomic_write(admin / 'manifest.json', admin_bytes, 0o444,
                         admin / 'manifest.json')
        raise
    finally:
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)
        os.close(lock_fd)


def migrate(assembler=ASSEMBLER, base=BASE, admin=ADMIN,
            desktop_source=DESKTOP_SOURCE):
    import fcntl

    if os.getuid() != 0 or os.geteuid() != 0:
        raise RuntimeError('Run this migration as root')
    base, admin, assembler, desktop_source = map(Path, (base, admin, assembler, desktop_source))
    lock_fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        lock_metadata = os.fstat(lock_fd)
        if (not stat.S_ISREG(lock_metadata.st_mode) or lock_metadata.st_uid != 0
                or lock_metadata.st_nlink != 1 or lock_metadata.st_mode & 0o077):
            raise RuntimeError('Unsafe migration lock')
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        desktop_path = base / 'desktop.json'
        desktop_bytes = trusted_file(desktop_path, 1024 * 1024)
        desktop = json.loads(desktop_bytes)
        if desktop.get('schema') != 'greyward.protected-desktop/v1':
            raise RuntimeError('Existing protected desktop receipt is unsupported')
        trusted_tree(base, desktop)
        accounts = {item.get('name') for item in desktop.get('accounts', {}).values()
                    if isinstance(item, dict) and isinstance(item.get('name'), str)}
        if not accounts:
            raise RuntimeError('Protected desktop account receipt is missing')
        ensure_quiescent(accounts)

        admin_path = admin / 'manifest.json'
        admin_bytes = trusted_file(admin_path, 1024 * 1024)
        admin_manifest = json.loads(admin_bytes)
        verify_admin_tree(admin_manifest, admin)
        dms = selected_dms()
        if not assembler.is_file() or assembler.is_symlink():
            raise RuntimeError('Trusted authentication assembler is missing')
        trusted_file(assembler, 1024 * 1024)
        materialize_source = desktop_source / 'materialize.py'
        materialize_bytes = trusted_file(materialize_source, 128 * 1024)
        subprocess.run(['/usr/bin/python3', '-I', str(materialize_source),
                        '--check-release', dms.name], check=True, capture_output=True, timeout=5)
        authentication_source = desktop_source / 'authentication.py'
        authentication_worker_bytes = trusted_file(authentication_source, 128 * 1024)
        session_source = desktop_source / 'session.py'
        session_bytes = trusted_file(session_source, 128 * 1024)
        keyboard_config_source = desktop_source / 'keyboard_config.py'
        keyboard_config_bytes = trusted_file(keyboard_config_source, 128 * 1024)
        keyboard_result = subprocess.run(
            ['/usr/bin/python3', '-I', str(keyboard_config_source), '--print-installed-json'],
            check=True, capture_output=True, timeout=5)
        keyboard_json_bytes = keyboard_result.stdout
        keyboard_data = json.loads(keyboard_json_bytes)
        # Validate against the just-read root-owned systemd-localed source.
        namespace = {'__name__': 'greyward_keyboard_config'}
        exec(compile(keyboard_config_bytes, str(keyboard_config_source), 'exec'), namespace)
        keyboard_data = namespace['validate_settings'](keyboard_data)
        keyboard_json_bytes = namespace['canonical_json'](keyboard_data)
        verifier_source = desktop_source / 'verify.py'
        verifier_bytes = trusted_file(verifier_source, 128 * 1024)

        work = Path(tempfile.mkdtemp(prefix='.dms-migration-', dir=base.parent))
        os.chown(work, 0, 0)
        os.chmod(work, 0o700)
        try:
            assembled = work / 'assembled'
            subprocess.run(['/usr/bin/python3', '-I', str(assembler),
                            '--source', str(dms / 'shell'),
                            '--receipt', str(dms / 'release.json'),
                            '--output', str(assembled)], check=True, timeout=60)
            new_shell = assembled / 'shell'
            auth_path = assembled / 'authentication.json'
            if new_shell.is_symlink() or not new_shell.is_dir() or auth_path.is_symlink():
                raise RuntimeError('Authentication shell assembly produced unsafe output')
            for path in sorted(new_shell.rglob('*'), reverse=True):
                if path.is_symlink():
                    raise RuntimeError('Authentication shell assembly produced an alias')
                if path.is_dir():
                    path.chmod(0o555)
                    os.chown(path, 0, 0)
                elif path.is_file():
                    path.chmod(0o444)
                    os.chown(path, 0, 0)
            new_shell.chmod(0o555)
            os.chown(new_shell, 0, 0)

            # Existing installations do not rerun first-boot enrollment after
            # an RPM upgrade. Apply the updated policy and executable labels as
            # part of this explicit, quiescent protected-session migration.
            activate_usbguard_approval_policy(accounts)

            new_binary = work / 'dms'
            copy_metadata(dms / 'bin/dms', new_binary)
            new_binary.chmod(0o555)
            auth_bytes = auth_path.read_bytes()
            new_binary_digest = digest(new_binary.read_bytes())
            if payload_matches_current(desktop, dms.name, new_binary_digest, new_shell,
                                       auth_bytes, authentication_worker_bytes,
                                       materialize_bytes, keyboard_json_bytes,
                                       keyboard_config_bytes, session_bytes,
                                       verifier_bytes):
                return f'Protected desktop already matches {dms.name} and its verified authentication and session inputs.'

            subprocess.run(['/usr/bin/chcon', '-R', '-t', 'greyward_as_auth_runtime_t', str(new_shell)],
                           check=True, timeout=15)
            subprocess.run(['/usr/bin/chcon', '-t', 'greyward_as_auth_exec_t', str(new_binary)],
                           check=True, timeout=5)
            new_desktop = update_desktop_manifest(desktop, dms.name, new_binary_digest,
                                                  new_shell, auth_bytes,
                                                  authentication_worker_bytes,
                                                  materialize_bytes, keyboard_json_bytes,
                                                  keyboard_config_bytes, session_bytes,
                                                  verifier_bytes)
            new_desktop_bytes = (json.dumps(new_desktop, indent=2) + '\n').encode()
            new_admin = update_admin_manifest(admin_manifest, new_desktop_bytes)
            new_admin_bytes = (json.dumps(new_admin, indent=2) + '\n').encode()

            old_shell = base / 'shell'
            backup = work / 'previous-shell'
            shutil.copytree(old_shell, backup, symlinks=True)
            for path in backup.rglob('*'):
                if path.is_symlink():
                    raise RuntimeError('Existing shell contains an alias; refusing migration')
                os.chown(path, 0, 0, follow_symlinks=False)
            backup.chmod(0o700)
            old_binary = work / 'previous-dms'
            shutil.copyfile(base / 'bin/dms', old_binary)
            previous_auth = trusted_file(base / 'authentication-input/authentication.json', 1024 * 1024)
            previous_authentication_worker = trusted_file(base / 'authentication.py', 128 * 1024)
            previous_materialize = trusted_file(base / 'materialize.py', 128 * 1024)
            previous_keyboard_json = (trusted_file(base / 'keyboard.json', 4096)
                                      if (base / 'keyboard.json').exists() else None)
            previous_keyboard_config = (trusted_file(base / 'keyboard_config.py', 128 * 1024)
                                        if (base / 'keyboard_config.py').exists() else None)
            previous_session = trusted_file(base / 'session.py', 128 * 1024)
            previous_verifier = trusted_file(base / 'verify.py', 128 * 1024)

            commit_started = True
            atomic_write(base / 'bin/dms', new_binary.read_bytes(), 0o555, base / 'bin/dms')
            subprocess.run(['/usr/bin/chcon', '-t', 'greyward_as_auth_exec_t', str(base / 'bin/dms')],
                           check=True, timeout=5)
            old_shell.rename(work / 'old-shell')
            new_shell.rename(old_shell)
            os.chown(old_shell, 0, 0)
            os.chmod(old_shell, 0o555)
            atomic_write(base / 'authentication-input/authentication.json', auth_bytes, 0o444,
                         base / 'authentication-input/authentication.json')
            atomic_write(base / 'authentication.py', authentication_worker_bytes, 0o444,
                         base / 'authentication.py')
            atomic_write(base / 'materialize.py', materialize_bytes, 0o444,
                         base / 'materialize.py')
            atomic_write(base / 'keyboard.json', keyboard_json_bytes, 0o444,
                         base / 'session.py')
            atomic_write(base / 'keyboard_config.py', keyboard_config_bytes, 0o444,
                         base / 'session.py')
            atomic_write(base / 'session.py', session_bytes, 0o444,
                         base / 'session.py')
            atomic_write(base / 'verify.py', verifier_bytes, 0o444,
                         base / 'verify.py')
            atomic_write(desktop_path, new_desktop_bytes, 0o444, desktop_path)
            atomic_write(admin_path, new_admin_bytes, 0o444, admin_path)

            refreshed = json.loads(trusted_file(desktop_path, 1024 * 1024))
            trusted_tree(base, refreshed)
            refreshed_admin = json.loads(trusted_file(admin_path, 1024 * 1024))
            verify_admin_tree(refreshed_admin, admin)
            if refreshed_admin.get('desktop') != digest(trusted_file(desktop_path, 1024 * 1024)):
                raise RuntimeError('Administration receipt did not refresh')
            return f'Protected desktop migrated to {dms.name} with refreshed authentication and session inputs. Log in again to load the update.'
        except Exception:
            # The currently selected shell is restored from the verified backup
            # if a filesystem operation or final receipt check fails.
            previous_shell = work / 'previous-shell'
            if locals().get('commit_started'):
                failed_shell = work / 'failed-shell'
                current_shell = base / 'shell'
                if current_shell.exists():
                    current_shell.rename(failed_shell)
                shutil.copytree(previous_shell, current_shell)
                os.chown(current_shell, 0, 0)
                subprocess.run(['/usr/bin/chcon', '-R', '-t', 'greyward_as_auth_runtime_t', str(current_shell)],
                               check=False, timeout=15)
            previous_binary = work / 'previous-dms'
            if locals().get('commit_started') and previous_binary.exists():
                atomic_write(base / 'bin/dms', previous_binary.read_bytes(), 0o555, base / 'bin/dms')
                subprocess.run(['/usr/bin/chcon', '-t', 'greyward_as_auth_exec_t', str(base / 'bin/dms')],
                               check=False, timeout=5)
            if locals().get('commit_started'):
                atomic_write(base / 'authentication-input/authentication.json', previous_auth, 0o444,
                             base / 'authentication-input/authentication.json')
                atomic_write(base / 'authentication.py', previous_authentication_worker, 0o444,
                             base / 'authentication.py')
                atomic_write(base / 'materialize.py', previous_materialize, 0o444,
                             base / 'materialize.py')
                for path, previous in ((base / 'keyboard.json', previous_keyboard_json),
                                       (base / 'keyboard_config.py', previous_keyboard_config)):
                    if previous is None:
                        try:
                            path.unlink()
                        except FileNotFoundError:
                            pass
                    else:
                        atomic_write(path, previous, 0o444, path)
                atomic_write(base / 'session.py', previous_session, 0o444,
                             base / 'session.py')
                atomic_write(base / 'verify.py', previous_verifier, 0o444,
                             base / 'verify.py')
                atomic_write(desktop_path, desktop_bytes, 0o444, desktop_path)
                atomic_write(admin_path, admin_bytes, 0o444, admin_path)
            raise
        finally:
            shutil.rmtree(work, ignore_errors=True)
    finally:
        os.close(lock_fd)


def refresh_installed_broker():
    """An upgrade must not leave a deleted predecessor executable serving admission.

    Called only after a successful root/quiescent migration. Fixed service names
    and executable; no caller-controlled unit or command dispatch.
    """
    found=False
    for unit in ('greyward-application-security-workflows.service',
                 'greyward-application-security.service'):
        active=subprocess.run(['/usr/bin/systemctl','is-active','--quiet',unit],check=False)
        if active.returncode!=0:
            continue
        found=True
        subprocess.run(['/usr/bin/systemctl','restart',unit],check=True,timeout=40)
        pid=subprocess.check_output(['/usr/bin/systemctl','show',unit,'-p','MainPID','--value'],text=True,timeout=5).strip()
        if not pid.isdecimal() or int(pid)<=1 or not os.path.samefile('/proc/'+pid+'/exe','/usr/libexec/greyward-application-security'):
            raise RuntimeError('Admission broker is not running the installed executable')
    if not found:
        raise RuntimeError('Application Security broker is not active after migration')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assembler', type=Path, default=ASSEMBLER,
                        help='installed trusted assembler; development migration only')
    parser.add_argument('--refresh-session-only', action='store_true',
                        help='refresh only the protected session guardian and its receipts')
    parser.add_argument('--refresh-verifier-only', action='store_true',
                        help='refresh only the protected-seat verifier and its receipts')
    parser.add_argument('--desktop-source', type=Path, default=DESKTOP_SOURCE,
                        help='trusted root-owned desktop input directory')
    options = parser.parse_args()
    if options.refresh_session_only and options.refresh_verifier_only:
        parser.error('Choose exactly one protected input to refresh')
    try:
        if options.refresh_session_only:
            result=migrate_verifier_only(desktop_source=options.desktop_source, session_only=True)
        elif options.refresh_verifier_only:
            result=migrate_verifier_only(desktop_source=options.desktop_source)
        else:
            result=migrate(options.assembler, desktop_source=options.desktop_source)
        refresh_installed_broker()
        print(result)
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        parser.exit(2, f'Protected DMS migration refused: {error}\n')


if __name__ == '__main__':
    main()
