"""One readable scan-result projection; no scanner policy or remediation."""
import datetime as dt
import html
from pathlib import Path

STYLES = {
    'CLEAN': ('#A7D8B7', 'No threats detected', 'clean'),
    'PARTIAL': ('#E9C484', 'Scan incomplete', 'review'),
    'FAILED': ('#E9C484', 'Scan did not finish', 'review'),
    'UNAVAILABLE': ('#E9C484', 'Scanner unavailable', 'review'),
    'CANCELLED': ('#BDCADA', 'Scan cancelled', 'neutral'),
    'EMPTY': ('#BDCADA', 'No files inspected', 'neutral'),
    'THREAT': ('#F0A3AA', 'Threat detected', 'threat'),
}


def count(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 10000000 else None


def subject(value):
    # Do not let a filename inject markup, extra lines or bidi controls.
    name = Path(str(value or 'Selected files')).name
    return ''.join(c if c.isprintable() else ' ' for c in name)[:100] or 'Selected files'


def appearance(notice):
    """Only fixed styles are trusted; every variable string is escaped."""
    state = notice.get('scan_status')
    if notice.get('kind') not in {'scan-result', 'malware'} or state not in STYLES:
        return None
    color, label, artwork = STYLES[state]
    caption = str(notice.get('scan_caption') or ('Review this finding in File security' if state == 'THREAT' else 'View the result in File security'))
    body = f'<font color="{color}" size="5"><b>{label}</b></font><br/><font size="4">{html.escape(caption)}</font>'
    # A fixed revision changes Qt's image-cache key without restarting DMS.
    return body, 'file:///usr/share/greyward-security-center/scan-notifications/greyward-scan-' + artwork + '.svg?design=2'


def results(files, current=None):
    if files.get('state') != 'AVAILABLE':
        return []
    current = current or dt.datetime.now(dt.timezone.utc)
    scans = files.get('recent_scans') if isinstance(files.get('recent_scans'), list) else []
    scans = [files.get('latest_scan') or {}, *scans[:8]]
    seen, notices = set(), []
    for scan in scans:
        if not isinstance(scan, dict):
            continue
        reference = str(scan.get('operation_id') or '')
        if not reference or reference in seen:
            continue
        seen.add(reference)
        scope = scan.get('scope') if isinstance(scan.get('scope'), dict) else {}
        if scope.get('background') or count(scan.get('detection_count')) != 0:
            continue  # background success stays silent; existing finding notices own threats
        try:
            ended = dt.datetime.fromisoformat(str(scan.get('ended_at') or '').replace('Z', '+00:00'))
            if ended.tzinfo is None or not 0 <= (current - ended).total_seconds() < 60:
                continue
        except (TypeError, ValueError):
            continue
        state = scan.get('state')
        inspected = count(scan.get('files_inspected'))
        errors, skipped = count(scan.get('error_count')), count(scan.get('skipped_count'))
        if state == 'COMPLETED' and (errors is None or skipped is None or inspected is None or errors or skipped):
            status, title, severity = 'PARTIAL', 'Scan incomplete', 'WARNING'
        elif state == 'COMPLETED' and inspected == 0:
            status, title, severity = 'EMPTY', 'Scan finished', 'INFO'
        elif state == 'COMPLETED':
            status, title, severity = 'CLEAN', 'Scan complete', 'INFO'
            if inspected is not None:
                title += ' · ' + str(inspected) + (' file' if inspected == 1 else ' files')
        elif state == 'CANCELLED':
            status, title, severity = 'CANCELLED', 'Scan cancelled', 'INFO'
        elif state in {'FAILED', 'PARTIAL', 'INTERRUPTED', 'TIMEOUT'}:
            status, title, severity = ('PARTIAL' if state == 'PARTIAL' else 'FAILED'), 'Scan incomplete', 'WARNING'
        else:
            continue
        name = subject(scope.get('label'))
        caption = (str(inspected) + (' file checked' if inspected == 1 else ' files checked')) if status == 'CLEAN' else {
            'PARTIAL': 'Some files could not be checked', 'FAILED': 'The scan could not be completed',
            'CANCELLED': 'No complete result was recorded', 'EMPTY': 'The selection contained no scannable files'
        }.get(status, 'View the result in File security')
        notices.append({'id': 'scan-result:' + reference, 'kind': 'scan-result', 'severity': severity,
            'title': title, 'detail': STYLES[status][1] + ' · ' + name, 'route': 'files',
            'actions': [{'id': 'open', 'label': 'View scan'}], 'timeout_ms': 8000 if severity == 'INFO' else 12000,
            'scan_status': status, 'scan_subject': name, 'notification_title': name, 'scan_caption': caption})
    return notices
