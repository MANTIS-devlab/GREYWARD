"""Event-driven, metadata-only PipeWire privacy activity observer.

The observer keeps one PipeWire monitor process for the life of the graphical
session. It never opens media streams and never falls back to periodic graph
scrapes: a missing monitor is an explicit unavailable state.
"""
import json
import os
import subprocess
import threading
import time

SENSOR_CLASSES = {'Stream/Input/Audio': 'MICROPHONE', 'Stream/Input/Video': 'CAMERA'}
UNATTRIBUTABLE = {'pipewire', 'wireplumber', 'xdg-desktop-portal', 'xdg-desktop-portal-wlr', 'xdg-desktop-portal-hyprland'}
SCREEN_MARKERS = {'screen', 'screencast', 'screen-cast', 'desktop', 'monitor'}


def app_name(props, clients):
    candidate = props.get('application.name') or props.get('application.process.binary')
    if not candidate and props.get('client.id') in clients:
        client = clients[props['client.id']]
        candidate = client.get('application.name') or client.get('application.process.binary')
    if not candidate or str(candidate).lower() in UNATTRIBUTABLE:
        return None
    return str(candidate)[:80]


def _screen_share(props):
    values = []
    for key in ('media.role', 'media.name', 'node.name', 'application.name', 'application.process.binary'):
        value = str(props.get(key) or '').lower()
        if value:
            values.append(value)
    return any(marker in value for marker in SCREEN_MARKERS for value in values)


def observe_activity(payload):
    """Return normalized capture sensors and confirmed screen-cast streams."""
    clients = {item.get('id'): item.get('info', {}).get('props', {}) for item in payload if item.get('type') == 'PipeWire:Interface:Client'}
    nodes = {item.get('id'): item.get('info', {}) for item in payload if item.get('type') == 'PipeWire:Interface:Node'}
    linked = set()
    screen_streams = []
    for item in payload:
        if item.get('type') != 'PipeWire:Interface:Link':
            continue
        link = item.get('info', {})
        if link.get('state') != 'active':
            continue
        target = nodes.get(link.get('input-node-id'), {})
        source = nodes.get(link.get('output-node-id'), {}).get('props', {})
        props = target.get('props', {})
        if target.get('state') != 'running':
            continue
        kind = SENSOR_CLASSES.get(props.get('media.class'))
        if kind == 'MICROPHONE':
            if source.get('media.class') != 'Audio/Source':
                continue
            if source.get('stream.monitor') in (True, 'true') or props.get('stream.capture.sink') in (True, 'true'):
                continue
        elif kind == 'CAMERA':
            if source.get('media.class') != 'Video/Source':
                continue
            if _screen_share(props) or _screen_share(source):
                application = app_name(props, clients)
                screen_streams.append({'application': application, 'attribution': 'RELIABLE' if application else 'AMBIGUOUS'})
                continue
        else:
            continue
        linked.add(link.get('input-node-id'))
    sensors = []
    for item in payload:
        props = item.get('info', {}).get('props', {})
        kind = SENSOR_CLASSES.get(props.get('media.class'))
        if not kind or item.get('id') not in linked:
            continue
        application = app_name(props, clients)
        sensors.append({'kind': kind, 'application': application, 'attribution': 'RELIABLE' if application else 'AMBIGUOUS'})
    unique = {}
    for sensor in sensors:
        unique[(sensor['kind'], sensor['application'] or '')] = sensor
    shares = {}
    for stream in screen_streams:
        shares[stream['application'] or 'ambiguous'] = stream
    return {'sensors': list(unique.values())[:8], 'screen_shares': list(shares.values())[:8]}


def observe(payload):
    """Compatibility helper used by pure parser tests."""
    return observe_activity(payload)['sensors']


class PipeWireMonitor:
    """Persistent ``pw-dump --monitor`` reader with bounded JSON framing."""
    def __init__(self):
        self._lock = threading.Lock()
        self._objects = {}
        self._error = 'PipeWire monitor has not produced an initial graph.'
        self._observed_at = None
        self._process = None
        self._callback = None

    def start(self, callback):
        if self._process is not None:
            return
        self._callback = callback
        try:
            self._process = subprocess.Popen(['pw-dump', '--monitor'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        except OSError:
            self._error = 'PipeWire monitor is unavailable.'
            callback()
            return
        threading.Thread(target=self._read, daemon=True).start()

    def stop(self):
        if self._process and self._process.poll() is None:
            self._process.terminate()

    def _apply(self, value):
        entries = value if isinstance(value, list) else [value]
        changed = False
        with self._lock:
            for item in entries:
                if not isinstance(item, dict) or 'id' not in item:
                    continue
                key = item['id']
                if item.get('info') is None and key in self._objects:
                    self._objects.pop(key, None)
                    changed = True
                elif self._objects.get(key) != item:
                    self._objects[key] = item
                    changed = True
            if changed:
                self._error = None
                self._observed_at = time.monotonic()
        if changed and self._callback:
            self._callback()

    def _read(self):
        decoder = json.JSONDecoder()
        buffer = ''
        try:
            while self._process and self._process.stdout:
                chunk = os.read(self._process.stdout.fileno(), 4096)
                if not chunk:
                    break
                buffer += chunk.decode('utf-8', errors='replace')
                while buffer:
                    stripped = buffer.lstrip()
                    if not stripped:
                        buffer = ''
                        break
                    try:
                        value, end = decoder.raw_decode(stripped)
                    except json.JSONDecodeError:
                        starts = [index for index in (stripped.find('{'), stripped.find('[')) if index >= 0]
                        start = min(starts) if starts else -1
                        buffer = stripped if start == 0 else (stripped[start:] if start > 0 else '')
                        break
                    self._apply(value)
                    buffer = stripped[end:]
        finally:
            with self._lock:
                self._error = 'PipeWire monitor stopped.'
            if self._callback:
                self._callback()

    def snapshot(self):
        with self._lock:
            payload = list(self._objects.values())
            error = self._error
            observed_at = self._observed_at
        activity = observe_activity(payload) if not error else {'sensors': [], 'screen_shares': []}
        return activity, error, observed_at
