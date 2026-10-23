"""Session-local transitions; no audio/video, media contents."""
import datetime as dt
import hashlib
import json
import os
import threading
from pathlib import Path

from .shell_experience import item

DAY = 86400


def mapping(value):
    return value if isinstance(value, dict) else {}


def recent(value, current, seconds=900):
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            return False
        observed = parsed.timestamp()
        return 0 <= current - observed <= seconds
    except (ValueError, TypeError, OverflowError):
        return False


class NoticePreferences:
    def __init__(self, path=None):
        self.path = path or Path(os.environ.get('XDG_CONFIG_HOME', Path.home() / '.config')) / 'greyward/security-notifications.json'
        self.lock = threading.Lock()

    def read(self):
        with self.lock:
            try:
                value = json.loads(self.path.read_text(encoding='utf-8'))
                enabled = isinstance(value, dict) and value.get('sensor_start') is True
            except (OSError, ValueError):
                enabled = False
        return {'sensor_start': enabled}

    def set_sensor_start(self, enabled):
        if type(enabled) is not bool:
            raise ValueError('sensor_start must be a boolean')
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_suffix('.tmp')
            temporary.write_text(json.dumps({'sensor_start': enabled}), encoding='utf-8')
            temporary.chmod(0o600)
            os.replace(temporary, self.path)
        return self.read()


class SensorStarts:
    def __init__(self):
        self.active = None
        self.pending = {}
        self.sequence = 0

    def collect(self, capsule, enabled, current):
        signals = [s for s in capsule.get('signals', [])[:64] if s.get('category') == 'ACTIVE_SENSOR']
        # Loss of the observation source is not a stop/start transition.
        if not signals or any(s.get('state') not in {'ACTIVE', 'INACTIVE'} for s in signals):
            self.pending.clear()
            return []
        active = {str(s['signal_id']): s for s in signals if s.get('category') == 'ACTIVE_SENSOR' and s.get('state') == 'ACTIVE' and s.get('signal_id')}
        started = set(active) - self.active if self.active is not None else set()
        self.active = set(active)
        self.pending = {k: v for k, v in self.pending.items() if k in active and v[0] > current}
        if not enabled:
            self.pending.clear()
            return []
        for key in sorted(started):
            self.sequence += 1
            camera = key.startswith('camera')
            label = 'Camera' if camera else 'Microphone'
            app = str(active[key].get('application') or 'Unidentified application')[:120]
            identity = hashlib.sha256(key.encode()).hexdigest()[:20]
            self.pending[key] = (current + 15, item(f'sensor-start:{identity}:{self.sequence}', 'sensor-start', 'INFO',
                label + ' started', app + ' is using your ' + label.lower() + '.', 'privacy', timeout_ms=6000))
        return [v[1] for v in self.pending.values()]


def update_notices(snapshot, current, boot_id):
    """Require fresh, successful provider evidence, not a check-button response."""
    if not isinstance(snapshot, dict) or snapshot.get('schema') != 'org.greyward.update/v1':
        return []
    notices = []
    transaction = mapping(snapshot.get('transaction'))
    if transaction.get('phase') == 'READY_TO_RESTART' and transaction.get('restart_required') == 'REQUIRED' and boot_id and transaction.get('boot_id') == boot_id:
        notices.append(item('updates-restart', 'update-notice', 'INFO', 'Restart required',
            'Update Center has prepared updates. Restart when convenient to finish installing them.', 'updates', reminder_seconds=DAY))
    if not recent(snapshot.get('generated_at'), current) or snapshot.get('snapshot_error'):
        return notices
    if transaction.get('phase') not in {None, 'IDLE', 'COMPLETE', 'FAILED', 'CANCELLED'}:
        return notices
    count = 0
    records = snapshot.get('records')
    if not isinstance(records, list):
        return notices
    providers = mapping(snapshot.get('providers'))
    for record in records[:10000]:
        if not isinstance(record, dict):
            continue
        provider = mapping(providers.get(record.get('provider')))
        health = mapping(record.get('provider_health'))
        if (record.get('update_available') is True and record.get('security_relevance') == 'SECURITY_FIX'
                and not mapping(record.get('metadata')).get('compatibility_hold')
                and provider.get('state') == 'AVAILABLE' and health.get('state') == 'AVAILABLE'
                and recent(provider.get('last_successful_at'), current)
                and recent(record.get('observed_at'), current)):
            count += 1
    if count:
        notices.append(item('updates-security', 'update-notice', 'INFO', 'Security updates available',
            f'Update Center verified {count} available security update(s). Review them when convenient.', 'updates', reminder_seconds=DAY))
    return notices
