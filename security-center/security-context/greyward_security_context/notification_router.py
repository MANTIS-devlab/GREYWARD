"""GREYWARD's single notification publisher, using the existing DMS server."""
import html
import json
import os
import subprocess
from pathlib import Path
from .clamav import MEDIA_ROOTS

APP_ID = 'systems.mantis.greyward.securitycenter'
APP_NAME = 'GREYWARD Security Center'
ICON = 'greyward-security-status'


def scan_context(path):
    candidate = Path(path).resolve()
    if any(candidate.is_relative_to(root.resolve()) for root in MEDIA_ROOTS): return 'REMOVABLE_MEDIA'
    return 'HIGH_RISK_PATH' if 'downloads' in {part.lower() for part in candidate.parts} else 'FILE'


class NotificationRouter:
    def __init__(self, bus, dispatch, state_path=None):
        self.bus, self.dispatch = bus, dispatch
        self.path = state_path or Path(os.environ.get('XDG_RUNTIME_DIR', '/tmp')) / 'greyward-security-notification-delivery.json'
        self.records, self.owner, self.proxy = {}, '', None
        self._closing = set()
        try:
            value = json.loads(self.path.read_text())
            self.records = value.get('records', {})
            self.owner = value.get('owner', '')
        except (OSError, ValueError): pass
        bus.add_signal_receiver(self._action, signal_name='ActionInvoked', dbus_interface='org.freedesktop.Notifications', bus_name='org.freedesktop.Notifications')
        bus.add_signal_receiver(self._closed, signal_name='NotificationClosed', dbus_interface='org.freedesktop.Notifications', bus_name='org.freedesktop.Notifications')

    def _save(self):
        try:
            temporary = self.path.with_suffix('.tmp')
            temporary.write_text(json.dumps({'owner': self.owner, 'records': self.records}, separators=(',', ':')))
            temporary.chmod(0o600)
            os.replace(temporary, self.path)
        except OSError: pass

    def _connect(self):
        import dbus
        try:
            owner = str(self.bus.get_name_owner('org.freedesktop.Notifications'))
            if self.proxy is None or owner != self.owner:
                if owner != self.owner:
                    for record in self.records.values(): record['notification_id'] = 0
                self.owner = owner
                self.proxy = dbus.Interface(self.bus.get_object(owner, '/org/freedesktop/Notifications'), 'org.freedesktop.Notifications')
            return True
        except dbus.DBusException:
            self.proxy = None
            return False

    def _action(self, notification_id, action_id):
        for key, record in tuple(self.records.items()):
            if record.get('notification_id') != int(notification_id): continue
            current = record.get('item', {})
            allowed = {x['id'] for x in current.get('actions', [])} | {'open', 'default'}
            if str(action_id) in allowed:
                self.dispatch(current, 'open' if str(action_id) == 'default' else str(action_id))
            break

    def _closed(self, notification_id, reason):
        notification_id = int(notification_id)
        if notification_id in self._closing:
            self._closing.discard(notification_id)
            return
        for record in self.records.values():
            if record.get('notification_id') == notification_id:
                record['notification_id'] = 0
                if int(reason) in (1, 2): record['acknowledged'] = True
        self._save()

    def reconcile(self, items):
        import dbus
        if not self._connect(): return
        active = {x['id']: x for x in items}
        for key in set(self.records) - set(active):
            record = self.records.pop(key)
            notification_id = record.get('notification_id', 0)
            if notification_id:
                try:
                    self._closing.add(notification_id)
                    self.proxy.CloseNotification(dbus.UInt32(notification_id), timeout=3)
                except dbus.DBusException: pass
        for key, current in active.items():
            record = self.records.get(key, {})
            old = record.get('item', {})
            record['item'] = current
            self.records[key] = record
            if record.get('acknowledged') and not (current.get('severity') == 'CRITICAL' and old.get('severity') != 'CRITICAL'): continue
            signature = json.dumps(current, sort_keys=True)
            if record.get('signature') == signature and record.get('notification_id'): continue
            escalated = current.get('severity') == 'CRITICAL' and old.get('severity') != 'CRITICAL'
            quiet = bool(record.get('signature')) and not escalated
            actions = []
            for action in current.get('actions', []): actions.extend([action['id'], action['label']])
            if not actions: actions = ['open', 'Review']
            hints = {'desktop-entry': dbus.String(APP_ID), 'urgency': dbus.Byte(2 if current['severity'] == 'CRITICAL' else 1),
                     'category': dbus.String('device' if current['kind'] == 'usb' else 'system'),
                     'suppress-sound': dbus.Boolean(quiet), 'x-greyward-quiet': dbus.Boolean(quiet),
                     'x-greyward-severity': dbus.String(current['severity'])}
            try:
                returned = self.proxy.Notify(APP_NAME, dbus.UInt32(record.get('notification_id', 0)), ICON,
                    current.get('notification_title', current['title']), html.escape(current.get('notification_detail', current['detail'])), dbus.Array(actions, signature='s'),
                    dbus.Dictionary(hints, signature='sv'), dbus.Int32(current.get('timeout_ms', 10000)), timeout=4)
                record.update(notification_id=int(returned), signature=signature, acknowledged=False)
            except dbus.DBusException:
                self.proxy = None
                break
        self._save()


def open_route(route):
    if route not in {'overview', 'devices', 'privacy', 'network', 'threats', 'files', 'updates'}: return
    subprocess.Popen(['/usr/bin/greyward-security-center-route', route], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
