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
    match=re.search(r'ClamAV\s+([0-9][^\s/]*)',(result.stdout or '')+(result.stderr or ''))
    return match.group(1) if match else None

def _database_files():
    files=[]
    for directory in DATABASE_DIRS:
        try: files.extend(item for item in directory.iterdir() if item.is_file() and item.suffix in {'.cvd','.cld','.cud'})
        except OSError: pass
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
        if re.search(r'\b(updated|database updated|daily\.cvd updated|freshclam daemon started)\b',line,re.I):
            latest_success=index
    recent=lines[latest_success+1:]
    return next((line.strip()[-240:] for line in reversed(recent) if re.search(r'\b(ERROR|WARNING|FAILED)\b',line,re.I)),None)


def status():
    """Report the packaged ClamAV engine/update lifecycle; never update here."""
    files=_database_files(); newest=max((item.stat().st_mtime for item in files),default=None)
    now=dt.datetime.now(dt.timezone.utc); timestamp=dt.datetime.fromtimestamp(newest,dt.timezone.utc).replace(microsecond=0) if newest else None
    age=int(max(0,now.timestamp()-newest)) if newest else None; latest=max(files,key=lambda item:item.stat().st_mtime) if files else None
    try: lines=Path('/var/log/freshclam.log').read_text(encoding='utf-8',errors='replace').splitlines()
    except OSError: lines=[]
    failure=_update_failure(lines); updater=_freshclam_service_state(); engine=_version('clamscan')
    if age is None:
        state='INITIALIZING' if updater == 'ACTIVE' else 'UNAVAILABLE'
        detail='ClamAV definitions are initializing through the packaged freshclam service.' if state == 'INITIALIZING' else 'ClamAV definitions are unavailable; enable clamav-freshclam.service and wait for its first update.'
    elif age > MAX_DATABASE_AGE:
        state='UPDATING' if updater == 'ACTIVE' else 'OUTDATED'
        detail='ClamAV definitions are being refreshed.' if state == 'UPDATING' else 'ClamAV definitions are outdated; the packaged freshclam service is not active.'
    elif failure:
        state='UPDATING' if updater == 'ACTIVE' else 'OUTDATED'
        detail=failure
    elif not engine:
        state='UNAVAILABLE'; detail='The ClamAV scanner engine is unavailable.'
    else:
        state='CURRENT'; detail='ClamAV definitions are current.'
    return {'engine_version':engine,'database_timestamp':timestamp.isoformat().replace('+00:00','Z') if timestamp else None,'database_age_seconds':age,'last_successful_update':timestamp.isoformat().replace('+00:00','Z') if timestamp else None,'update_failure_state':failure,'database_version':latest.name if latest else None,'update_service_state':updater,'status':state,'detail':detail}
