#!/usr/bin/python3 -I
"""Recreate only fixed authentication runtime for a root-admitted account."""
import os,json,subprocess
from pathlib import Path
STATE=Path('/run/greyward-application-security')
def run(*command):
    subprocess.run(command,check=True,timeout=15)
def prepare_enforcement(uid):
    base=Path('/var/lib/greyward/application-security/enforcement')
    for directory in [base, base/f'uid-{uid}', base/f'uid-{uid}/content']:
        directory.mkdir(mode=0o700,exist_ok=True)
        meta=directory.lstat()
        if directory.is_symlink() or not directory.is_dir() or meta.st_uid or meta.st_mode & 0o077:
            raise RuntimeError('Unsafe enforcement storage')
    configuration=Path('/etc/selinux/semanage.conf')
    meta=configuration.lstat()
    if configuration.is_symlink() or meta.st_uid or meta.st_mode & 0o022:
        raise RuntimeError('Unsafe compiler input')
    text=configuration.read_text()
    active=[line.strip() for line in text.splitlines() if line.strip().startswith('expand-check=')]
    if active not in [['expand-check=0'],['expand-check=1']]:
        raise RuntimeError('Unsupported compiler configuration')
    text='\n'.join('expand-check=1' if line.strip().startswith('expand-check=') else line for line in text.splitlines())+'\n'
    target=base/f'uid-{uid}/semanage.conf'
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600) if not target.exists() else None
    if fd is not None:
        with os.fdopen(fd,'w') as output:
            output.write(text); output.flush(); os.fsync(output.fileno())
    meta=target.lstat()
    if target.is_symlink() or meta.st_uid or meta.st_nlink!=1 or meta.st_mode & 0o777!=0o600 or target.read_text()!=text:
        raise RuntimeError('Enforcement compiler input changed')

def materialize(uid,gid):
    if os.getuid()!=0 or os.geteuid()!=0:
        raise RuntimeError('Root preparation required')
    prepare_enforcement(uid)
    STATE.mkdir(mode=0o711, exist_ok=True)
    STATE.chmod(0o711)
    auth = STATE / f'auth-{uid}'
    auth.mkdir(mode=0o711, exist_ok=True)
    auth.chmod(0o711)
    if auth.is_symlink() or auth.stat().st_uid != 0:
        raise RuntimeError('Unsafe authentication root')
    for directory in ['home', 'runtime', 'config', 'state', 'cache']:
        (auth / directory).mkdir(mode=0o700, exist_ok=True)
        if (auth / directory).is_symlink() or (auth / directory).stat().st_uid not in (0,uid):
            raise RuntimeError('Unsafe authentication directory')
        os.chown(auth / directory, uid, gid)
    (auth / 'config/DankMaterialShell').mkdir(mode=0o755, exist_ok=True)
    (auth / 'config/DankMaterialShell').chmod(0o755)
    if (auth / 'config/DankMaterialShell').is_symlink():
        raise RuntimeError('Unsafe authentication settings directory')
    for name in ['config/DankMaterialShell/settings.json','session-bus.conf']:
        target=auth/name
        if target.exists() and (target.is_symlink() or target.stat().st_uid != 0 or target.stat().st_nlink != 1):
            raise RuntimeError('Unsafe authentication input')
    settings = json.loads(Path('/etc/skel/.config/DankMaterialShell/settings.json').read_text())
    settings.update({'customPowerActionLock': '', 'loginctlLockIntegration': True,
        'lockAtStartup': False, 'lockBeforeSuspend': False, 'fadeToLockEnabled': False,
        'fadeToDpmsEnabled': False, 'lockScreenPowerOffMonitorsOnLock': False,
        'lockScreenVideoEnabled': False, 'lockPamExternallyManaged': True,
        'lockPamPath': '/etc/pam.d/greyward-dms-lock', 'enableFprint': False, 'enableU2f': False,
        'lockScreenNotificationMode': 0, 'lockScreenShowMediaPlayer': False})
    for key in ['acMonitorTimeout', 'acLockTimeout', 'acPostLockMonitorTimeout',
                'batteryMonitorTimeout', 'batteryLockTimeout', 'batteryPostLockMonitorTimeout',
                'acSuspendTimeout', 'batterySuspendTimeout']:
        settings[key] = 0
    (auth / 'config/DankMaterialShell/settings.json').write_text(json.dumps(settings))
    (auth / 'config/DankMaterialShell/settings.json').chmod(0o444)
    (auth / 'session-bus.conf').write_text(f'<busconfig><type>session</type><listen>unix:path={auth}/runtime/bus</listen><auth>EXTERNAL</auth><policy context="default"><allow user="{uid}"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>')
    (auth / 'session-bus.conf').chmod(0o444)
    administration = auth / 'runtime/administration-state.json'
    if administration.exists() and (administration.is_symlink() or administration.stat().st_uid != 0 or administration.stat().st_nlink != 1):
        raise RuntimeError('Unsafe administration status')
    administration.write_text(json.dumps({'active':False,'validUntilMs':0}))
    administration.chmod(0o644)
    run('/usr/bin/chcon', '-R', '-t', 'greyward_as_auth_runtime_t', str(auth))
