#!/usr/bin/python3 -I
"""Recreate only fixed authentication runtime for a root-admitted account."""
import os,json,subprocess,re
from pathlib import Path
STATE=Path('/run/greyward-application-security')
DMS_AUTH_SETTINGS_CONFIG_VERSION=18

def authentication_settings(template, config_version=DMS_AUTH_SETTINGS_CONFIG_VERSION):
    """Seed the private agent from current factory defaults, not a v0 profile.

    The reviewed profiles pin schema 18 for 1.6 and schema 42 for the 2.0
    candidate. This prevents replaying migrations against read-only protected
    settings at every login. These are package-selected versions, not user
    configuration or permission to activate an incomplete candidate.
    """
    if type(config_version) is not int or config_version not in (18, 42):
        raise RuntimeError('Unreviewed authentication settings schema')
    settings=dict(template)
    settings.update({'configVersion':config_version,
        'customPowerActionLock': '', 'loginctlLockIntegration': True,
        'lockAtStartup': False, 'lockBeforeSuspend': False, 'fadeToLockEnabled': False,
        'fadeToDpmsEnabled': False, 'lockScreenPowerOffMonitorsOnLock': False,
        'lockScreenVideoEnabled': False,
        'lockScreenWallpaperPath': '/usr/share/backgrounds/greyward/greyward-wallpaper-black-art-4k.jpg',
        'lockScreenWallpaperFillMode': 'Fill', 'lockPamExternallyManaged': True,
        'lockPamPath': '/etc/pam.d/greyward-dms-lock', 'enableFprint': False, 'enableU2f': False,
        'lockScreenNotificationMode': 0, 'lockScreenShowMediaPlayer': False})
    if config_version == 42:
        # Native 2.0 widgets replace the old show/media/notification flags.
        # Keep one quiet, readable lock form on every protected output.
        common = {'displayPreferences': ['all'], 'syncPositionAcrossScreens': True,
                  'autoPosition': True}
        settings.update({'clockFormat': '24h', 'lockScreenFontFamily': 'Inter',
            'lockScreenWidgetInstances': [
                {'id': 'lock_clock', 'widgetType': 'desktopClock', 'enabled': True,
                 'config': {**common, 'style': 'digital', 'twoTone': False,
                            'showDate': True, 'showDigitalSeconds': False,
                            'colorMode': 'default', 'transparency': 0}},
                {'id': 'lock_auth', 'widgetType': 'lockAuth', 'enabled': True,
                 'config': {**common, 'style': 'pill', 'profileVisibility': 'never',
                            'passwordVisibility': 'always'}}]})
    for key in ['acMonitorTimeout', 'acLockTimeout', 'acPostLockMonitorTimeout',
                'batteryMonitorTimeout', 'batteryLockTimeout', 'batteryPostLockMonitorTimeout',
                'acSuspendTimeout', 'batterySuspendTimeout']:
        settings[key]=0
    return settings

def authentication_profile(release):
    # The caller supplies the verified root-owned desktop generation, never an
    # environment value or user JSON. Unknown layouts fail before any write.
    if isinstance(release, str) and re.fullmatch(r'v1\.6\.2-\d+', release):
        return ('DankMaterialShell', None, 18)
    if release == 'v2.0.0-7':
        return ('dms', 'dms20', 42)
    raise RuntimeError('Unreviewed authentication runtime release')


def authentication_environment(auth, release):
    _name, namespace, _schema = authentication_profile(release)
    return {f'XDG_{name.upper()}_HOME': str(auth / name / namespace if namespace else auth / name)
            for name in (('config', 'state', 'cache', 'data') if namespace else ('config', 'state', 'cache'))}


def run(*command):
    subprocess.run(command,check=True,timeout=15)

def prepare_usb_metadata(auth, uid, gid):
    """Prepare only the dedicated atomic availability projection directory."""
    metadata = auth / 'runtime/usbguard-approval'
    metadata.mkdir(mode=0o700, exist_ok=True)
    info = metadata.lstat()
    if metadata.is_symlink() or not metadata.is_dir() or info.st_uid not in (0, uid) or info.st_mode & 0o077:
        raise RuntimeError('Unsafe USB approval metadata directory')
    os.chown(metadata, uid, gid)
    run('/usr/bin/chcon', '-t', 'greyward_usbguard_auth_readiness_dir_t', str(metadata))
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

def materialize(uid,gid,release="v1.6.2-26"):
    if os.getuid()!=0 or os.geteuid()!=0:
        raise RuntimeError('Root preparation required')
    profile_name, namespace, schema = authentication_profile(release)
    prepare_enforcement(uid)
    STATE.mkdir(mode=0o711, exist_ok=True)
    STATE.chmod(0o711)
    auth = STATE / f'auth-{uid}'
    auth.mkdir(mode=0o711, exist_ok=True)
    auth.chmod(0o711)
    if auth.is_symlink() or auth.stat().st_uid != 0:
        raise RuntimeError('Unsafe authentication root')
    for directory in ['home', 'runtime', 'config', 'state', 'cache'] + (['data'] if namespace else []):
        (auth / directory).mkdir(mode=0o700, exist_ok=True)
        if (auth / directory).is_symlink() or (auth / directory).stat().st_uid not in (0,uid):
            raise RuntimeError('Unsafe authentication directory')
        os.chown(auth / directory, uid, gid)
    environment = authentication_environment(auth, release)
    if namespace:
        # Root-prepared versioned roots keep the unmodified 2.0 CLI's automatic
        # legacy migration away from immutable 1.6 input. Preserve that input
        # for rollback; do not create compatibility symlinks or merge profiles.
        for key, value in environment.items():
            directory = Path(value)
            directory.mkdir(mode=0o755 if key == 'XDG_CONFIG_HOME' else 0o700, exist_ok=True)
            info = directory.lstat()
            if directory.is_symlink() or not directory.is_dir() or info.st_uid not in (0,uid):
                raise RuntimeError('Unsafe versioned authentication directory')
            os.chown(directory, 0 if key == 'XDG_CONFIG_HOME' else uid, 0 if key == 'XDG_CONFIG_HOME' else gid)
            directory.chmod(0o755 if key == 'XDG_CONFIG_HOME' else 0o700)
    profile = Path(environment['XDG_CONFIG_HOME']) / profile_name
    if profile.is_symlink():
        raise RuntimeError('Unsafe authentication settings directory')
    profile.mkdir(mode=0o755, exist_ok=True)
    if profile.stat().st_uid != 0:
        raise RuntimeError('Unsafe authentication settings directory')
    profile.chmod(0o755)
    for target in [profile / 'settings.json', profile / 'clsettings.json', auth / 'session-bus.conf']:
        if target.is_symlink() or (target.exists() and (target.stat().st_uid != 0 or target.stat().st_nlink != 1)):
            raise RuntimeError('Unsafe authentication input')
    settings = authentication_settings(
        json.loads(Path('/etc/skel/.config/DankMaterialShell/settings.json').read_text()), schema)
    (profile / 'settings.json').write_text(json.dumps(settings))
    (profile / 'settings.json').chmod(0o444)
    # Both versions start with the native clipboard collector disabled.
    (profile / 'clsettings.json').write_text(json.dumps({'disabled':True}))
    (profile / 'clsettings.json').chmod(0o444)
    (auth / 'session-bus.conf').write_text(f'<busconfig><type>session</type><listen>unix:path={auth}/runtime/bus</listen><auth>EXTERNAL</auth><policy context="default"><allow user="{uid}"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>')
    (auth / 'session-bus.conf').chmod(0o444)
    administration = auth / 'runtime/administration-state.json'
    if administration.exists() and (administration.is_symlink() or administration.stat().st_uid != 0 or administration.stat().st_nlink != 1):
        raise RuntimeError('Unsafe administration status')
    administration.write_text(json.dumps({'active':False,'validUntilMs':0}))
    administration.chmod(0o644)
    run('/usr/bin/chcon', '-R', '-t', 'greyward_as_auth_runtime_t', str(auth))
    # The taskbar client sees only availability metadata, never auth state.
    # A dedicated parent preserves its type across atomic file replacement.
    prepare_usb_metadata(auth, uid, gid)
