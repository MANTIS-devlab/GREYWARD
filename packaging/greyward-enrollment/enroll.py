#!/usr/bin/python3 -I
"""Fixed installer enrollment; never runs on an active account or build host.

Package installation is inert. Preparation requires Anaconda's root receipt
and pending first-boot gate. Coverage remains the broker's live readback.
Offline rollback supports this initial transaction only, before resources or
grants exist; later state requires deliberate authenticated repair.
"""
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import stat
import subprocess
import sys

INPUT = Path('/usr/share/greyward-application-security/enrollment')
STATE = Path('/var/lib/greyward/application-security/installation')
DESKTOP = Path('/usr/lib/greyward/application-security/desktop')
ADMIN = Path('/usr/lib/greyward/application-security/administration')
ORIGIN = Path('/var/lib/greyward/installer/accounts.json')
BROKER = '/usr/libexec/greyward-application-security'
ORIGINS = Path('/var/lib/greyward/application-security/account-origins')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}


def run(*args):
    try:
        return subprocess.run(args, check=True, capture_output=True, text=True,
                              env=ENV, timeout=180).stdout.strip()
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or error.stdout or 'No diagnostic output').strip()[-4096:]
        raise RuntimeError(f'{args[0]} exited {error.returncode}: {detail}') from error


def private_directory(path):
    # Never repair the ownership/mode of an existing unsafe object silently.
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid or info.st_mode & 0o022:
            raise RuntimeError('Unsafe private-directory ancestry')
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError('Unsafe private directory: ' + str(path))


def trusted(path):
    for item in [path, *path.parents]:
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError('Untrusted installation input: ' + str(item))
    if not path.is_file() or path.stat().st_nlink != 1 or path.stat().st_size > 1048576:
        raise RuntimeError('Unsafe installation receipt')
    return path.read_bytes()


def atomic_write(path, data, mode=0o600):
    temporary = path.with_name(path.name + '.pending-' + secrets.token_hex(8))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_json(path, value):
    atomic_write(path, (json.dumps(value, indent=2) + '\n').encode())


def discard_partial_tree(path, parent):
    """Remove only a root-owned, private-directory tree created by this transaction."""
    if path.parent != parent:
        raise RuntimeError('Invalid partial assembly path')
    try:
        root = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(root.st_mode) or root.st_uid or root.st_mode & 0o022:
        raise RuntimeError('Unsafe partial enrollment assembly: ' + str(path))
    for item in path.rglob('*'):
        info = item.lstat()
        if (info.st_uid or info.st_mode & 0o022
                or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))):
            raise RuntimeError('Unsafe partial enrollment input: ' + str(item))
    shutil.rmtree(path)


def validate_preparing_transaction(accounts, receipt):
    """Permit retry only before any account mapping or broker state was activated."""
    names = {account['name'] for account in accounts}
    previous = receipt.get('previous')
    if (receipt.get('schema') != 'greyward.installer-enrollment/v1'
            or receipt.get('phase') != 'PREPARING'
            or receipt.get('accounts') != accounts
            or receipt.get('inputs') != {}
            or not isinstance(previous, dict) or set(previous) != names):
        raise RuntimeError('Preparing enrollment receipt is incomplete; explicit repair required')
    for name, value in previous.items():
        if (not isinstance(value, dict) or set(value) != {'seuser', 'range'}
                or not all(isinstance(part, str) and part for part in value.values())):
            raise RuntimeError('Preparing enrollment mapping receipt is invalid')
        if value['seuser'] == 'greyward_guard_u':
            raise RuntimeError('Account was already enrolled before preparation')
    quiescent(accounts)
    for account in accounts:
        if mapping(account['name']) != previous[account['name']]:
            raise RuntimeError('Account mapping changed during preparation; explicit repair required')
    try:
        origins = ORIGINS.lstat()
    except FileNotFoundError as error:
        raise RuntimeError('Installer origin directory missing; explicit repair required') from error
    if (not stat.S_ISDIR(origins.st_mode) or origins.st_uid
            or stat.S_IMODE(origins.st_mode) != 0o700 or any(ORIGINS.iterdir())):
        raise RuntimeError('Installer origin state changed during preparation; explicit repair required')
    snapshot = STATE / 'previous-local-policy.txt'
    if snapshot.exists() or snapshot.is_symlink():
        info = snapshot.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or info.st_size > 1048576):
            raise RuntimeError('Previous policy snapshot is unsafe; explicit repair required')


def semanage_users():
    """Read SELinux user definitions in the stable no-heading semanage form."""
    users = {}
    for line in run('/usr/sbin/semanage', 'user', '-l', '-n').splitlines():
        fields = line.split()
        if len(fields) >= 5:
            users[fields[0]] = {
                'prefix': fields[1], 'level': fields[2], 'range': fields[3],
                'roles': set(fields[4:]),
            }
    return users


def ensure_selinux_user(name, roles, mls_range, mls_level='s0'):
    expected = {'prefix': 'user', 'level': mls_level, 'range': mls_range,
                'roles': set(roles.split())}
    actual = semanage_users().get(name)
    if actual is None:
        run('/usr/sbin/semanage', 'user', '-a', '-R', roles, '-r', mls_range,
            '-L', mls_level, name)
        actual = semanage_users().get(name)
    if actual != expected:
        raise RuntimeError('SELinux user definition changed; explicit repair required: ' + name)


def finalize_program_directories():
    """Make immutable program inputs traversable despite enrollment umask 077.

    This is deliberately limited to the assembled /usr/lib closure. Policy,
    grant storage and authentication runtime retain their private permissions.
    Validate the entire closure before changing any directory permissions.
    """
    directories = {DESKTOP.parent, DESKTOP, ADMIN}
    for root in [DESKTOP, ADMIN]:
        for parent in [root, *root.parents]:
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid or info.st_mode & 0o022:
                raise RuntimeError('Unsafe program-directory ancestry')
        for path in root.rglob('*'):
            info = path.lstat()
            if info.st_uid or info.st_mode & 0o022 or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise RuntimeError('Unsafe assembled program input')
            if stat.S_ISDIR(info.st_mode):
                directories.add(path)
    for path in sorted(directories):
        path.chmod(0o755)


def installer_accounts():
    receipt = json.loads(trusted(ORIGIN))
    if receipt.get('schema') != 'greyward.installer-accounts/v1':
        raise RuntimeError('Installer origin required')
    records = receipt.get('accounts', [])
    if not 1 <= len(records) <= 256:
        raise RuntimeError('Installer accounts missing')
    local = {}
    for line in Path('/etc/passwd').read_text().splitlines():
        fields = line.split(':')
        if len(fields) == 7:
            local[fields[0]] = fields
    seen = set()
    for record in records:
        fields = local.get(record['name'])
        if not fields or len(fields) != 7 or not 1000 <= record['uid'] < 60000 or record['uid'] in seen or not 1000 <= record['gid'] < 60000 or fields[0] != record['name'] or int(fields[2]) != record['uid'] or int(fields[3]) != record['gid'] or fields[5] != record['home'] or fields[6] not in {'/bin/bash','/usr/bin/bash','/bin/zsh','/usr/bin/zsh','/bin/sh','/usr/bin/sh'} or record['home'] != '/home/' + record['name']:
            raise RuntimeError('Installer account changed')
        # GREYWARD's supported first-boot shell setup selects packaged zsh.
        # Bind the prepared generation to that current supported shell.
        record['shell'] = fields[6]
        seen.add(record['uid'])
    return records


def quiescent(accounts):
    uids = {account['uid'] for account in accounts}
    for path in Path('/proc').iterdir():
        if path.name.isdigit():
            try:
                if path.stat().st_uid in uids:
                    raise RuntimeError('Account has live workloads; enrollment refused')
            except FileNotFoundError:
                pass


def mapping(name):
    library = ctypes.CDLL('libselinux.so.1')
    user, level = ctypes.c_char_p(), ctypes.c_char_p()
    if library.getseuserbyname(name.encode(), ctypes.byref(user), ctypes.byref(level)):
        raise RuntimeError('Mapping readback failed')
    try:
        return {'seuser': user.value.decode(), 'range': level.value.decode()}
    finally:
        ctypes.CDLL(None).free(user)
        ctypes.CDLL(None).free(level)


def check():
    receipt = json.loads(trusted(STATE / 'transaction.json'))
    if receipt['phase'] != 'PENDING_SESSION' or receipt['schema'] != 'greyward.installer-enrollment/v1':
        raise RuntimeError('Installation transaction incomplete')
    accounts = installer_accounts()
    if receipt['accounts'] != accounts:
        raise RuntimeError('Installer identities changed')
    if run('/usr/sbin/getenforce') != 'Enforcing':
        raise RuntimeError('SELinux enforcing required')
    for account in accounts:
        if mapping(account['name']) != {'seuser': 'greyward_guard_u', 'range': 's0'}:
            raise RuntimeError('Enrolled mapping readback failed')
    for path, digest in receipt['inputs'].items():
        if hashlib.sha256(trusted(Path(path))).hexdigest() != digest:
            raise RuntimeError('Enrollment inputs changed; explicit upgrade required')
    run('/usr/bin/systemctl', 'is-active', 'greyward-application-security-workflows.service')
    print('Installer enrollment prepared; live session coverage is verified at login.')


def prepare():
    if not Path('/var/lib/greyward/installer/production-pending').is_file() or Path('/etc/greyward-production-complete').exists():
        raise RuntimeError('Only the unfinished installed first-boot gate may prepare enrollment')
    accounts = installer_accounts()
    transaction_path = STATE / 'transaction.json'
    # Once the initial mapping is prepared, retries are read-only. Check this
    # phase before requiring a quiescent account: a normal user process must
    # not strand first boot after a previous attempt reached PENDING_SESSION.
    if transaction_path.exists():
        receipt = json.loads(trusted(transaction_path))
        if receipt.get('phase') == 'PENDING_SESSION':
            return check()
    quiescent(accounts)
    if run('/usr/sbin/getenforce') != 'Enforcing':
        raise RuntimeError('SELinux enforcing required')
    private_directory(STATE.parent)
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    trusted_directory = STATE.lstat()
    if STATE.is_symlink() or trusted_directory.st_uid or trusted_directory.st_mode & 0o077:
        raise RuntimeError('Unsafe transaction storage')
    if transaction_path.exists():
        receipt = json.loads(trusted(transaction_path))
        if receipt.get('phase') == 'PREPARED_INPUTS':
            return finish_preparation(accounts, receipt)
        if receipt.get('phase') == 'PREPARING':
            validate_preparing_transaction(accounts, receipt)
            return prepare_inputs(accounts, receipt, resume=True)
        return check()
    if DESKTOP.exists() or ADMIN.exists():
        raise RuntimeError('Existing enrollment needs deliberate migration, not installer activation')
    if any(mapping(a['name'])['seuser'] == 'greyward_guard_u' for a in accounts):
        raise RuntimeError('Account already enrolled')
    private_directory(ORIGINS)
    receipt = {'schema': 'greyward.installer-enrollment/v1', 'phase': 'PREPARING',
               'accounts': accounts, 'previous': {a['name']: mapping(a['name']) for a in accounts}, 'inputs': {}}
    write_json(STATE / 'transaction.json', receipt)
    return prepare_inputs(accounts, receipt)


def prepare_inputs(accounts, receipt, resume=False):
    if resume:
        # PREPARING never changes account mappings or creates origin receipts.
        # Rebuild the fixed generated trees from trusted package inputs so a
        # power loss during assembly cannot strand first boot in PREPARING.
        discard_partial_tree(STATE / 'ordinary', STATE)
        discard_partial_tree(STATE / 'source', STATE)
        discard_partial_tree(DESKTOP, DESKTOP.parent)
        discard_partial_tree(ADMIN, ADMIN.parent)
    private_directory(ORIGINS)
    export = run('/usr/sbin/semanage', 'export')
    snapshot = STATE / 'previous-local-policy.txt'
    if snapshot.exists() or snapshot.is_symlink():
        info = snapshot.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or info.st_size > 1048576):
            raise RuntimeError('Previous policy snapshot is unsafe')
    else:
        atomic_write(snapshot, export.encode())
    # No account is mapped while policy/closure inputs are assembled. The empty
    # attribute is replaced in one policy transaction with the actual closure.
    ordinary = STATE / 'greyward_ordinary.cil'
    ordinary.write_text('(typeattribute greyward_as_ordinary)\n')
    policies = sorted((INPUT / 'policy').glob('*.pp'))
    if len(policies) != 7:
        raise RuntimeError('Matched seven-module policy closure missing')
    for path in policies:
        trusted(path)
    run('/usr/sbin/semodule', '-i', str(ordinary), *(str(p) for p in policies))
    closure = STATE / 'ordinary'
    run('/usr/bin/python3', '-I', '/usr/share/greyward-application-security/desktop/ordinary-policy.py', '--output', str(closure))
    shutil.copyfile(closure / 'ordinary.cil', ordinary)
    overlays = sorted((INPUT / 'policy').glob('*.cil'))
    for path in overlays:
        trusted(path)
    run('/usr/sbin/semodule', '-i', str(ordinary), *(str(p) for p in overlays))
    # The taskbar and auth-session USBGuard helpers are installed before
    # first-boot enrollment loads their dedicated SELinux domain. Validate
    # both immutable executables, then apply and verify their file contexts.
    approval_helpers = (
        Path('/usr/libexec/greyward-usbguard-approval'),
        Path('/usr/libexec/greyward-usbguard-auth-approval'),
    )
    for approval_helper in approval_helpers:
        try:
            approval_info = approval_helper.lstat()
        except FileNotFoundError as error:
            raise RuntimeError(f'USB approval helper is missing: {approval_helper.name}') from error
        if (not stat.S_ISREG(approval_info.st_mode) or approval_info.st_uid != 0
                or approval_info.st_gid != 0 or approval_info.st_mode & 0o022
                or not approval_info.st_mode & 0o111):
            raise RuntimeError(f'USB approval helper is not the expected root-owned executable: {approval_helper.name}')
        run('/usr/sbin/restorecon', str(approval_helper))
        run('/usr/sbin/matchpathcon', '-V', str(approval_helper))
    # Production starts this root-only socket before enrollment loads the
    # session policy.  The creation-time transition cannot relabel an inode
    # that already exists, so apply the newly installed file-context rule now.
    update_socket = Path('/run/greyward-update-worker.sock')
    try:
        update_socket_info = update_socket.lstat()
    except FileNotFoundError:
        pass
    else:
        if (not stat.S_ISSOCK(update_socket_info.st_mode)
                or update_socket_info.st_uid != 0
                or update_socket_info.st_gid != 0
                or stat.S_IMODE(update_socket_info.st_mode) != 0o600):
            raise RuntimeError('Update worker socket is not the expected root-only socket')
        run('/usr/sbin/restorecon', str(update_socket))
    ensure_selinux_user('greyward_guard_u', 'greyward_guard_r', 's0')
    ensure_selinux_user('greyward_admin_u', 'greyward_admin_r sysadm_r', 's0-s0:c0.c1023')
    context = Path('/etc/selinux/targeted/contexts/users/greyward_guard_u')
    text = Path('/etc/selinux/targeted/contexts/users/user_u').read_text()
    for old, new in [('user_r:', 'greyward_guard_r:'), ('user_t:', 'greyward_guard_t:'), ('user_su_t:', 'greyward_guard_su_t:'), ('user_sudo_t:', 'greyward_guard_sudo_t:')]:
        text = text.replace(old, new)
    if context.exists() or context.is_symlink():
        info = context.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid
                or info.st_mode & 0o022 or context.read_text() != text):
            raise RuntimeError('Existing context requires deliberate migration')
    else:
        context.write_text(text)
        context.chmod(0o644)
        run('/usr/sbin/restorecon', str(context))
    source = STATE / 'source'
    shutil.copytree('/usr/share/greyward-application-security/desktop', source / 'desktop')
    shutil.copytree('/usr/share/greyward-application-security/authentication', source / 'authentication')
    shutil.copyfile(closure / 'ordinary.json', source / 'desktop/ordinary.json')
    shutil.copyfile('/usr/share/greyward/defaults/labwc/rc.xml', source / 'desktop/rc.xml')
    run('/usr/bin/python3', '-I', str(source / 'desktop/prepare.py'), '--source', str(source / 'desktop'), '--labwc', '/usr/libexec/greyward-protected-labwc', '--account', accounts[0]['name'], '--no-materialize')
    manifest = json.loads((DESKTOP / 'desktop.json').read_text())
    manifest['accounts'] = {str(a['uid']): {'name': a['name'], 'gid': a['gid'], 'home': a['home'], 'previousMapping': receipt['previous'][a['name']]} for a in accounts}
    (DESKTOP / 'desktop.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (DESKTOP / 'desktop.json').chmod(0o444)
    run('/usr/bin/python3', '-I', '/usr/share/greyward-application-security/administration/assemble.py', '--source', '/usr/share/greyward-application-security/administration', '--terminal', '/usr/libexec/greyward-admin-terminal', '--desktop', str(DESKTOP), '--output', str(ADMIN))
    finalize_program_directories()
    receipt['inputs'] = prepared_inputs()
    receipt['phase'] = 'PREPARED_INPUTS'
    write_json(STATE / 'transaction.json', receipt)
    finish_preparation(accounts, receipt)


def prepared_inputs():
    return {str(path): hashlib.sha256(trusted(path)).hexdigest()
            for path in [DESKTOP / 'desktop.json', ADMIN / 'manifest.json', INPUT / 'inputs.json']}


def finish_preparation(accounts, receipt):
    if (receipt.get('schema') != 'greyward.installer-enrollment/v1'
            or receipt.get('phase') != 'PREPARED_INPUTS'
            or receipt.get('accounts') != accounts
            or receipt.get('inputs') != prepared_inputs()):
        raise RuntimeError('Prepared enrollment inputs changed; explicit repair required')
    quiescent(accounts)
    for account in accounts:
        if mapping(account['name']) != receipt['previous'][account['name']]:
            raise RuntimeError('Mapping already changed; explicit repair required')
    private_directory(ORIGINS)
    for account in accounts:
        run(BROKER, '--prepare-installer-account', account['name'])
        wheel = subprocess.run(['/usr/bin/id', '-nG', account['name']], check=True, capture_output=True, text=True, env=ENV).stdout.split()
        if 'wheel' in wheel:
            sudoers = Path('/etc/sudoers.d') / ('greyward-administration-' + account['name'])
            if sudoers.exists():
                raise RuntimeError('Existing sudoers rule requires review')
            sudoers.write_text(account['name'] + ' ALL=(ALL) ROLE=sysadm_r TYPE=sysadm_t ALL\nDefaults:' + account['name'] + ' timestamp_timeout=2,timestamp_type=tty,use_pty,lecture=never\n')
            sudoers.chmod(0o440)
    run('/usr/sbin/visudo', '-c')
    # The ordinary shell presents no competing password form. Native DMS
    # authentication and Administration remain in the matched protected seat.
    for account in accounts:
        settings = Path(account['home']) / '.config/DankMaterialShell/settings.json'
        if settings.is_symlink() or not settings.is_file():
            raise RuntimeError('Factory DMS preferences missing')
        data = json.loads(settings.read_text())
        data.update(customPowerActionLock='/usr/bin/greyward-guard lock', loginctlLockIntegration=False)
        settings.write_text(json.dumps(data, indent=2) + '\n')
        os.chown(settings, account['uid'], account['gid'])
    quiescent(accounts)
    for account in accounts:
        run('/usr/sbin/semanage', 'login', '-a', '-s', 'greyward_guard_u', '-r', 's0', account['name'])
        run(BROKER, '--advance-account', account['name'], 'MAPPING_APPLIED')
        run(BROKER, '--advance-account', account['name'], 'PENDING_SESSION')
    run('/usr/bin/systemctl', 'disable', 'greyward-application-security.service')
    run('/usr/bin/systemctl', 'enable', '--now', 'greyward-application-security-workflows.service', 'greyward-flatpak-metadata.path')
    journal = Path('/var/lib/greyward/application-metadata')
    journal.mkdir(mode=0o700, parents=True, exist_ok=True)
    run('/usr/bin/python3', '-I', '/usr/share/greyward-application-security/administration/flatpak-metadata.py', '--journal', str(journal / 'labels.json'))
    if receipt['inputs'] != prepared_inputs():
        raise RuntimeError('Enrollment inputs changed during activation')
    receipt['phase'] = 'PENDING_SESSION'
    write_json(STATE / 'transaction.json', receipt)
    check()


def rollback():
    if 'systemd.unit=greyward-maintenance.target' not in Path('/proc/cmdline').read_text().split():
        raise RuntimeError('Use the authenticated offline maintenance console')
    receipt = json.loads(trusted(STATE / 'transaction.json'))
    quiescent(receipt['accounts'])
    db = Path('/var/lib/greyward/application-security/policy.sqlite3')
    if db.exists():
        with sqlite3.connect('file:' + str(db) + '?mode=ro', uri=True) as connection:
            for table in ['resource_intents', 'grant_intents', 'resource_label_journal']:
                if connection.execute('SELECT count(*) FROM ' + table).fetchone()[0]:
                    raise RuntimeError('Protected resources exist; initial-install rollback refused. Repair from authenticated root without erasing resource/grant state.')
    for account in receipt['accounts']:
        current = mapping(account['name'])
        if current['seuser'] == 'greyward_guard_u':
            # Fresh installer users had no explicit mapping. Removing only our
            # entry restores the original default; check before committing.
            run('/usr/sbin/semanage', 'login', '-d', account['name'])
        if mapping(account['name']) != receipt['previous'][account['name']]:
            raise RuntimeError('Prior mapping no longer matches; explicit repair required')
    receipt['phase'] = 'UNENROLLED'
    write_json(STATE / 'transaction.json', receipt)
    print('Initial account mappings restored. Policy, resource types and evidence retained. Protection is unavailable until repaired enrollment and a new session.')


if __name__ == '__main__':
    try:
        if os.getuid() or os.geteuid() or sys.argv[1:] not in [['prepare'], ['check'], ['rollback-initial']]:
            raise RuntimeError('Usage: root greyward-enrollment prepare|check|rollback-initial')
        os.umask(0o077)
        # Serialize fixed lifecycle operations; no session bus/API can select
        # arbitrary paths, commands, mappings or policy text.
        lock = os.open('/run/greyward-enrollment.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        {'prepare': prepare, 'check': check, 'rollback-initial': rollback}[sys.argv[1]]()
    except Exception as error:
        print('GREYWARD enrollment failed; login remains gated: ' + str(error), file=sys.stderr)
        sys.exit(1)
