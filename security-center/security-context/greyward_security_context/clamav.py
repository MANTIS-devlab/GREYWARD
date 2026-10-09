"""Bounded ClamAV result mapping; a non-confirmed scan is never CLEAN."""
import datetime as dt
import re
import subprocess
from pathlib import Path

MEDIA_ROOTS=(Path('/media'),Path('/run/media'),Path('/mnt'))
DATABASE_DIRS=(Path('/var/lib/clamav'),Path('/var/lib/clamav/updates'))
MAX_DATABASE_AGE=7*24*60*60
FRESHCLAM_SERVICES=('clamav-freshclam.service','freshclam.service')

def permitted(path, uid=None):
    candidate=Path(path)
    if not candidate.is_absolute():
        return False
    # The legacy ScanPath D-Bus method is still reachable by the desktop
    # service.  Do not resolve a user-controlled alias before checking it:
    # doing so would let a link inside an approved tree redirect the scanner
    # to an otherwise unrelated object.  The newer File Security path has the
    # same no-symlink contract; keep both entry points aligned.
    try:
        current=Path(candidate.anchor)
        for part in candidate.parts[1:]:
            current /= part
            if current.is_symlink():
                return False
        resolved=candidate.resolve(strict=True)
        if not resolved.is_file():
            return False
        return uid is None or resolved.stat().st_uid == uid
    except (OSError, RuntimeError):
        return False

def result_for(result, source_present=True):
    if not source_present:
        return {'state':'SOURCE_REMOVED','detail':'The scan source was removed before completion.'}
    output=(result.stdout or '')
    if result.returncode == 0 and output.rstrip().endswith(': OK'):
        return {'state':'CLEAN','detail':'No known threats found; this does not prove the source is safe.'}
    if result.returncode == 1 and output.rstrip().endswith(' FOUND'):
        match=re.search(r':\s*([^:\n]+?)\s+FOUND\s*$',output.rstrip())
        detection=(match.group(1).strip() if match else 'Known threat')[:160]
        return {'state':'THREAT','detail':f'ClamAV detected {detection}.','detection_name':detection}
    return {'state':'UNAVAILABLE','detail':'ClamAV could not complete the requested scan.'}

def scan(path, timeout=60, uid=None):
    try:
        target=Path(path).resolve(strict=True)
    except (OSError, RuntimeError):
        return {'state':'SOURCE_REMOVED','detail':'The scan source was removed before scanning began.'}
    if not permitted(path, uid):
        return {'state':'ERROR','detail':'Only your removable media or Downloads files can be scanned.'}
    try:
        # The hardened Fedora guest rejects clamd's file-descriptor passing
        # control message under SELinux.  Run the packaged ClamAV scanner in
        # the privileged D-Bus boundary instead; this remains a real ClamAV
        # scan while avoiding a raw clamd control channel.
        result=subprocess.run(['clamscan','--no-summary','--',str(target)],capture_output=True,text=True,timeout=timeout,check=False)
    except FileNotFoundError:
        return {'state':'UNAVAILABLE','detail':'ClamAV scanner is unavailable.'}
    except subprocess.TimeoutExpired:
        return {'state':'TIMEOUT','detail':'Scan timed out before a result was available.'}
    return result_for(result, target.exists())

def _version(binary):
    try: result=subprocess.run([binary,'--version'],capture_output=True,text=True,timeout=3,check=False)
    except (OSError,subprocess.SubprocessError): return None
    if result.returncode != 0: return None
    match=re.search(r'ClamAV\s+([0-9][^\s/]*)',(result.stdout or '')+(result.stderr or ''))
    return match.group(1) if match else None

def _database_files():
    files=[]
    for directory in DATABASE_DIRS:
        try: files.extend(item for item in directory.iterdir() if item.is_file() and item.suffix in {'.cvd','.cld','.cud'})
        except FileNotFoundError: pass
    return files

def _freshclam_service_state():
    """Return the packaged updater lifecycle state without starting it."""
    for service in FRESHCLAM_SERVICES:
        try:
            result=subprocess.run(['systemctl','is-active','--quiet',service],capture_output=True,text=True,timeout=2,check=False)
        except (OSError,subprocess.SubprocessError):
            continue
        if result.returncode == 0:
            return 'ACTIVE'
    return 'INACTIVE'


def _update_failure(lines):
    """Only report failures since the last successful freshclam run."""
    latest_success=-1
    for index,line in enumerate(lines):
        if re.search(r'\b(updated|database updated|daily\.cvd updated)\b',line,re.I):
            latest_success=index
    recent=lines[latest_success+1:]
    return next((line.strip()[-240:] for line in reversed(recent) if re.search(r'\b(ERROR|WARNING|FAILED)\b',line,re.I)),None)


def unavailable_status(detail="The system scanner status could not be verified."):
    return {'engine_version': None, 'database_timestamp': None,
            'database_age_seconds': None, 'last_successful_update': None,
            'update_failure_state': None, 'database_version': None,
            'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(),
            'update_service_state': 'UNKNOWN', 'status': 'UNAVAILABLE',
            'engine_state': 'UNKNOWN', 'definitions_state': 'UNKNOWN',
            'scanner_state': 'UNKNOWN', 'scan_activity': 'UNKNOWN',
            'realtime_protection': 'NOT_PROVIDED', 'detail': detail}


def status():
    """System-side metadata only. Availability does not imply real-time scanning."""
    now = dt.datetime.now(dt.timezone.utc)
    try:
        files = _database_files()
        stamps = [(item, item.stat().st_mtime) for item in files]
    except OSError:
        return unavailable_status("ClamAV definition metadata could not be inspected.")
    latest, newest = max(stamps, key=lambda item: item[1], default=(None, None))
    timestamp = dt.datetime.fromtimestamp(newest, dt.timezone.utc).replace(microsecond=0) if newest is not None else None
    age = int(max(0, now.timestamp() - newest)) if newest is not None else None
    engine = _version('clamscan')
    updater = _freshclam_service_state()
    try:
        with Path('/var/log/freshclam.log').open('rb') as log:
            log.seek(0, 2)
            log.seek(max(0, log.tell() - 65536))
            lines = log.read(65536).decode('utf-8', errors='replace').splitlines()[-2048:]
    except OSError:
        lines = []
    failure = _update_failure(lines)
    state, detail = 'CURRENT', 'Definitions are current. Scans run on demand; real-time protection is not provided.'
    definitions = 'CURRENT'
    if newest is None:
        state, definitions = 'UNAVAILABLE', 'MISSING'
        detail = 'ClamAV definitions are missing; updater activity does not establish scanner readiness.'
    elif newest > now.timestamp() + 300:
        state, definitions = 'ERROR', 'UNKNOWN'
        detail = 'Definition timestamps conflict with the system clock.'
    elif age > MAX_DATABASE_AGE:
        state, definitions = 'OUTDATED', 'OUTDATED'
        detail = 'ClamAV definitions are outdated; an active updater does not confirm a refresh.'
    elif failure:
        state = 'ERROR'
        detail = 'The definition updater reported a failure; scanner readiness requires review.'
    if not engine:
        state = 'UNAVAILABLE'
        detail = 'The ClamAV scanner engine could not be verified.'
    stamp = timestamp.isoformat().replace('+00:00', 'Z') if timestamp else None
    return {'observed_at': now.isoformat(), 'engine_version': engine, 'engine_state': 'AVAILABLE' if engine else 'UNKNOWN',
            'database_timestamp': stamp, 'database_age_seconds': age,
            'last_successful_update': None, 'update_failure_state': failure,
            'database_version': latest.name if latest else None, 'definitions_state': definitions,
            'update_service_state': updater, 'status': state, 'detail': detail,
            'scanner_state': 'AVAILABLE' if state == 'CURRENT' else 'UNAVAILABLE',
            'scan_activity': 'UNKNOWN', 'realtime_protection': 'NOT_PROVIDED'}


def system_status():
    """Fail closed when the matched system provider is absent or malformed."""
    import json
    try:
        import dbus
        proxy = dbus.Interface(dbus.SystemBus().get_object(
            'systems.mantis.greyward.ClamAvScan1', '/systems/mantis/greyward/ClamAvScan1'),
            'systems.mantis.greyward.ClamAvScan1')
        raw = str(proxy.GetClamAvStatus(timeout=10))
        if len(raw.encode('utf-8')) > 8192:
            return unavailable_status()
        value = json.loads(raw)
        if (not isinstance(value, dict) or value.get('status') not in {'CURRENT', 'OUTDATED', 'UNAVAILABLE', 'ERROR'}
                or value.get('realtime_protection') != 'NOT_PROVIDED'
                or (value['status'] == 'CURRENT' and
                    (not value.get('engine_version') or value.get('definitions_state') != 'CURRENT'
                     or type(value.get('database_age_seconds')) is not int
                     or not 0 <= value['database_age_seconds'] <= MAX_DATABASE_AGE))):
            return unavailable_status()
        observed = dt.datetime.fromisoformat(value.get('observed_at', '').replace('Z', '+00:00'))
        age = (dt.datetime.now(dt.timezone.utc) - observed).total_seconds()
        if not 0 <= age <= 30:
            return unavailable_status()
        return value
    except Exception:
        return unavailable_status()
