"""Bounded ClamAV result mapping; a non-confirmed scan is never CLEAN."""
import datetime as dt
import hashlib
import os
import stat
import re
import subprocess
import copy
import threading
import time
from pathlib import Path

MEDIA_ROOTS=(Path('/media'),Path('/run/media'),Path('/mnt'))
DATABASE_DIRS=(Path('/var/lib/clamav'),Path('/var/lib/clamav/updates'))
MAX_DATABASE_AGE=7*24*60*60
STATUS_CACHE_SECONDS = 5
_status_lock = threading.Lock()
_status_cache = None
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
    # Compatibility entry point. The context-menu UI uses asynchronous StartScan.
    from .file_security import _open_readonly_nofollow, _hash_descriptor, _safe_path, _reject_protected_scan
    from . import scan_cache
    if not permitted(path, uid):
        return {'state':'ERROR','detail':'Select a readable regular file owned by your account.'}
    try:
        target = _safe_path(path, owner_uid=uid)
    except (OSError, ValueError):
        return {'state':'ERROR','detail':'The selected file is not available to ordinary scanning.'}
    info = status()
    if info.get('status') != 'CURRENT':
        return {'state':'UNAVAILABLE','detail':'Current ClamAV definitions are required.'}
    descriptor = None
    before = scan_cache.fingerprint(target)
    try:
        descriptor = _open_readonly_nofollow(target, scan_uid=uid, scan_access=True)
        metadata = os.fstat(descriptor)
        _reject_protected_scan(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or (uid is not None and metadata.st_uid != uid):
            return {'state':'ERROR','detail':'The selected file changed before scanning.'}
        result = subprocess.run(['clamscan','--no-summary','--alert-exceeds-max=yes',
            '--follow-file-symlinks=2','--max-filesize=256M','--max-scansize=512M',
            '--',f'/proc/self/fd/{descriptor}'], pass_fds=(descriptor,),
            capture_output=True,text=True,timeout=timeout,check=False)
        value = result_for(result, target.exists())
        if 'Heuristics.Limits.Exceeded' in str(value.get('detection_name', '')):
            value = {'state':'PARTIAL','detail':'A scanner resource limit prevented a complete scan.'}
        after = scan_cache.fingerprint(target)
        if not before or before != after or status().get('database_version') != info.get('database_version'):
            return {'state':'PARTIAL','detail':'The file or definitions changed during scanning. Scan again.'}
        value['_receipt'] = {'fingerprint': before, 'database_version': info.get('database_version'), 'generation': scan_cache.generation(info)}
        if value.get('state') == 'THREAT':
            size, digest = _hash_descriptor(descriptor)
            value['_receipt'].update(file_size=size, file_hash=digest)
        return value
    except FileNotFoundError:
        return {'state':'SOURCE_REMOVED','detail':'The scan source was removed before completion.'}
    except subprocess.TimeoutExpired:
        return {'state':'TIMEOUT','detail':'Scan timed out before a result was available.'}
    except OSError:
        return {'state':'UNAVAILABLE','detail':'ClamAV could not inspect the selected file.'}
    finally:
        if descriptor is not None:
            os.close(descriptor)


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
        if re.search(r'\b(updated|database updated|up.to.date)\b',line,re.I):
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


def database_metadata():
    """Read bounded CVD/CLD headers, not copy timestamps, for definition age.

    Freshclam verifies the database before publishing it. This is metadata
    parsing, not an independent cryptographic verification of those archives.
    """
    entries = {}
    for path in sorted(_database_files()):
        if path.stem not in {'daily', 'main', 'bytecode'}:
            continue
        with path.open('rb') as stream:
            fields = stream.read(512).decode('ascii', errors='strict').strip().split(':')
        if len(fields) < 9 or fields[0] != 'ClamAV-VDB':
            raise ValueError('Invalid ClamAV database header')
        version, published = int(fields[2]), int(fields[8])
        if version <= 0 or published <= 0:
            raise ValueError('Invalid ClamAV database version')
        metadata = path.stat()
        entry = (version, published, metadata.st_size, metadata.st_mtime_ns)
        if path.stem not in entries or version > entries[path.stem][0]:
            entries[path.stem] = entry
    if not {'daily', 'main'} <= entries.keys():
        return None, None
    # Include all installed DB generations so bytecode/main updates also
    # invalidate an earlier scan, even when the daily version is unchanged.
    identity = ';'.join(f'{name}:{value}' for name, value in sorted(entries.items()))
    generation = hashlib.sha256(identity.encode()).hexdigest()
    return entries['daily'][1], 'daily-' + str(entries['daily'][0]) + '-' + generation[:24]


def _updater_failure():
    try:
        result = subprocess.run(['journalctl', '-u', 'clamav-freshclam.service',
            '-n', '64', '--no-pager', '-o', 'cat'], capture_output=True, text=True, timeout=2, check=False)
        if result.returncode == 0:
            return _update_failure(result.stdout.splitlines())
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def status():
    """Verified metadata, separate from updater health and scan coverage."""
    now = dt.datetime.now(dt.timezone.utc)
    try:
        published, generation = database_metadata()
    except (OSError, ValueError, UnicodeError):
        return unavailable_status("ClamAV definition metadata could not be verified.")
    age = max(0, int(now.timestamp() - published)) if published else None
    engine = _version('clamscan')
    updater = _freshclam_service_state()
    failure = _updater_failure()
    state, definitions = 'CURRENT', 'CURRENT'
    detail = 'Definitions are current. Selected and arriving files can be scanned; this is not real-time access blocking.'
    if published is None:
        state, definitions = 'UNAVAILABLE', 'MISSING'
        detail = 'Definitions are missing. Automatic updating will retry; no completed scan is implied.'
    elif published > now.timestamp() + 300:
        state, definitions = 'ERROR', 'UNKNOWN'
        detail = 'Definition publication time conflicts with the system clock.'
    elif age > MAX_DATABASE_AGE:
        state, definitions = 'OUTDATED', 'OUTDATED'
        detail = 'Definitions are outdated. Earlier scan results require a fresh scan after updating.'
    elif failure or updater != 'ACTIVE':
        detail = 'Installed definitions remain current; automatic updating needs attention and will retry.'
    if not engine:
        state = 'UNAVAILABLE'
        detail = 'The ClamAV scanner engine could not be verified.'
    timestamp = dt.datetime.fromtimestamp(published, dt.timezone.utc).isoformat() if published else None
    return {'observed_at': now.isoformat(), 'engine_version': engine,
            'engine_state': 'AVAILABLE' if engine else 'UNKNOWN',
            'database_timestamp': timestamp, 'database_age_seconds': age,
            'last_successful_update': None, 'update_failure_state': failure,
            'database_version': generation, 'definitions_state': definitions,
            'update_service_state': updater, 'status': state, 'detail': detail,
            'scanner_state': 'AVAILABLE' if state == 'CURRENT' else 'UNAVAILABLE',
            'scan_activity': 'UNKNOWN', 'realtime_protection': 'NOT_PROVIDED'}


def cached_status():
    """Share probes, retaining timestamps and invalidating on DB replacement."""
    global _status_cache
    try:
        key = []
        for p in _database_files():
            info = p.stat()
            key.append((str(p), info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns))
        key = tuple(sorted(key))
    except OSError:
        return unavailable_status('ClamAV definition metadata could not be verified.')
    with _status_lock:
        current = time.monotonic()
        if _status_cache and _status_cache[1] == key and 0 <= current - _status_cache[0] < STATUS_CACHE_SECONDS:
            value = copy.deepcopy(_status_cache[2])
            published = value.get('database_timestamp')
            if published and value.get('status') == 'CURRENT':
                try:
                    published = dt.datetime.fromisoformat(published.replace('Z', '+00:00')).timestamp()
                    wall_now = dt.datetime.now(dt.timezone.utc).timestamp()
                    age = max(0, int(wall_now - published))
                    if published <= wall_now + 300 and age <= MAX_DATABASE_AGE:
                        value['database_age_seconds'] = age
                        return value
                except (TypeError, ValueError):
                    pass
                # A clock/expiry boundary also invalidates an otherwise young
                # monotonic cache; never extend the definitions' validity.
            else:
                return value
        value = status()
        _status_cache = (time.monotonic(), key, copy.deepcopy(value))
        return value


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
