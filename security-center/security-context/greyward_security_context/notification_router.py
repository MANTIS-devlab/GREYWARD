"""GREYWARD's single notification publisher, using the existing DMS server."""
import html
import json
import os
import re
import subprocess
import time
from pathlib import Path
from .clamav import MEDIA_ROOTS
from .scan_notices import appearance as scan_appearance

APP_ID = 'systems.mantis.greyward.securitycenter'
APP_NAME = 'GREYWARD Security Center'
ICON = 'greyward-security-status'
MAX_WARNING_STABILITY_SECONDS = 300.0


def scan_context(path):
    candidate = Path(path).resolve()
    if any(candidate.is_relative_to(root.resolve()) for root in MEDIA_ROOTS): return 'REMOVABLE_MEDIA'
    return 'HIGH_RISK_PATH' if 'downloads' in {part.lower() for part in candidate.parts} else 'FILE'


class NotificationRouter:
    def __init__(self, bus, dispatch, state_path=None):
        self.bus, self.dispatch = bus, dispatch
        self.path = state_path or Path(os.environ.get('XDG_RUNTIME_DIR', '/tmp')) / 'greyward-security-notification-delivery.json'
        self.records, self.owner, self.proxy = {}, '', None
        self.completed_scans = {}
        self._closing = set()
        self._warning_since = {}
        self.reminder_path = Path(os.environ.get('XDG_STATE_HOME', Path.home() / '.local/state')) / 'greyward/notification-reminders.json' if state_path is None else self.path.with_name('reminders.json')
        try:
            self.reminders = json.loads(self.reminder_path.read_text())
            if not isinstance(self.reminders, dict): self.reminders = {}
        except (OSError, ValueError): self.reminders = {}
        try:
            value = json.loads(self.path.read_text())
            self.records = value.get('records', {})
            saved = value.get('completed_scans', {})
            if isinstance(saved, dict):
                self.completed_scans = dict(sorted(((k,v) for k,v in saved.items() if isinstance(k,str) and len(k)<128 and isinstance(v,(int,float)) and 0 <= time.time()-v < 86400), key=lambda pair:pair[1])[-128:])
            self.owner = value.get('owner', '')
        except (OSError, ValueError): pass
        bus.add_signal_receiver(self._action, signal_name='ActionInvoked', dbus_interface='org.freedesktop.Notifications', bus_name='org.freedesktop.Notifications')
        bus.add_signal_receiver(self._closed, signal_name='NotificationClosed', dbus_interface='org.freedesktop.Notifications', bus_name='org.freedesktop.Notifications')

    def _save(self):
        try:
            temporary = self.path.with_suffix('.tmp')
            temporary.write_text(json.dumps({'owner': self.owner, 'records': self.records, 'completed_scans': self.completed_scans}, separators=(',', ':')))
            temporary.chmod(0o600)
            os.replace(temporary, self.path)
        except OSError: pass

    def _save_reminders(self):
        try:
            self.reminder_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.reminder_path.with_suffix('.tmp')
            temporary.write_text(json.dumps(self.reminders, separators=(',', ':')))
            temporary.chmod(0o600)
            os.replace(temporary, self.reminder_path)
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
            if str(action_id) == 'dismiss' and current.get('kind') == 'application-security':
                record['acknowledged'] = True
                if self.proxy is not None:
                    try: self.proxy.CloseNotification(notification_id, timeout=3)
                    except Exception: pass
                record['notification_id'] = 0
                self._save()
                break
            # USB approval requires a Polkit prompt associated with the active
            # protected DMS session. A notification callback runs in the
            # long-lived user service, so it must never invoke a stale trust
            # action from that sessionless process.
            allowed = {'open', 'default'}
            if current.get('kind') != 'usb':
                allowed.update(x['id'] for x in current.get('actions', []))
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

    def eligible_items(self, items):
        """Return the one alert projection shared by the shell and desktop."""
        now = time.monotonic()
        observed = {item['id']: item for item in items}
        for key in set(self._warning_since) - set(observed):
            self._warning_since.pop(key, None)
        eligible = []
        for item in items:
            stability = item.get('notification_stability_seconds', 0)
            deferred_warning = (item.get('severity') == 'WARNING' and
                                isinstance(stability, (int, float)) and
                                not isinstance(stability, bool) and
                                0 < stability <= MAX_WARNING_STABILITY_SECONDS)
            if not deferred_warning:
                self._warning_since.pop(item['id'], None)
                eligible.append(item)
                continue
            since = self._warning_since.setdefault(item['id'], now)
            if now - since >= stability:
                eligible.append(item)
        return eligible

    def reconcile(self, items):
        import dbus
        if not self._connect(): return
        observed = {x['id']: x for x in items}
        for key in set(self.records) - set(observed):
            record = self.records.pop(key)
            notification_id = record.get('notification_id', 0)
            if notification_id:
                try:
                    self._closing.add(notification_id)
                    self.proxy.CloseNotification(dbus.UInt32(notification_id), timeout=3)
                except dbus.DBusException: pass
        for key, current in observed.items():
            record = self.records.get(key, {})
            old = record.get('item', {})
            record['item'] = current
            self.records[key] = record
            if current.get('kind') == 'scan-result' and key in self.completed_scans:
                continue
            reminder = key in {'updates-security', 'updates-restart'} and current.get('reminder_seconds') == 86400
            delivered = self.reminders.get(key)
            # Persist only two category timestamps, never application activity.
            # A new login/provider flap cannot bypass the daily reminder limit.
            if reminder and isinstance(delivered, (int, float)) and time.time() - delivered < 86400:
                continue
            if not reminder and record.get('acknowledged') and not (current.get('severity') == 'CRITICAL' and old.get('severity') != 'CRITICAL'): continue
            signature = json.dumps(current, sort_keys=True)
            if not reminder and record.get('signature') == signature and record.get('notification_id'): continue
            escalated = current.get('severity') == 'CRITICAL' and old.get('severity') != 'CRITICAL'
            quiet = bool(record.get('signature')) and not escalated and not reminder
            actions = []
            if current.get('kind') == 'usb':
                # The taskbar widget owns the active-session trust action.
                # Notifications can only open the device review page.
                actions = ['open', 'Review']
            else:
                for action in current.get('actions', []): actions.extend([action['id'], action['label']])
            if not actions: actions = ['open', 'Review']
            hints = {'desktop-entry': dbus.String(APP_ID), 'urgency': dbus.Byte(2 if current['severity'] == 'CRITICAL' else 1),
                     'category': dbus.String('device' if current['kind'] == 'usb' else 'system'),
                     'suppress-sound': dbus.Boolean(quiet), 'x-greyward-quiet': dbus.Boolean(quiet),
                     'x-greyward-severity': dbus.String(current['severity'])}
            if current.get('kind') == 'behavioral':
                hints['x-greyward-threat-score'] = dbus.Int32(current.get('behavioral_score',0))
                hints['x-greyward-threat-class'] = dbus.String(current.get('behavioral_class','UNKNOWN'))
                gauge=str(current.get('icon',''))
                if re.fullmatch(r'greyward-intelligence-(?:[0-9]{1,2}|100)',gauge):
                    hints['image-path'] = dbus.String('/usr/share/icons/hicolor/scalable/apps/'+gauge+'.svg')
            styled_scan = scan_appearance(current)
            body = html.escape(current.get('notification_detail', current['detail']))
            if styled_scan:
                body, scan_icon = styled_scan
                hints['x-greyward-scan-state'] = dbus.String(current['scan_status'])
            try:
                returned = self.proxy.Notify(APP_NAME, dbus.UInt32(record.get('notification_id', 0)),
                    scan_icon if styled_scan else ICON,
                    current.get('notification_title', current['title']), body, dbus.Array(actions, signature='s'),
                    dbus.Dictionary(hints, signature='sv'), dbus.Int32(current.get('timeout_ms', 10000)), timeout=4)
                record.update(notification_id=int(returned), signature=signature, acknowledged=False)
                if current.get('kind') == 'scan-result':
                    self.completed_scans[key] = time.time()
                    self.completed_scans = dict(sorted(self.completed_scans.items(), key=lambda pair:pair[1])[-128:])
                if reminder:
                    self.reminders[key] = time.time()
                    self._save_reminders()
            except dbus.DBusException:
                self.proxy = None
                break
        self._save()


def open_route(route, resource_ref=None):
    if route == 'intelligence':route='history' # old saved notices remain navigable
    if route not in {'overview', 'devices', 'privacy', 'network', 'threats', 'files', 'updates', 'evidence', 'activity', 'history', 'protected-data', 'intelligence'}: return
    command = ['/usr/bin/greyward-security-center-route', route]
    if route in {'history','activity'} and resource_ref is not None:
        if not re.fullmatch(r'incident-[a-f0-9]{24}', str(resource_ref)): return
        command.append(resource_ref)
    elif resource_ref is not None:
        if route != 'protected-data' or not re.fullmatch(r'resource_[0-9a-f]{64}', str(resource_ref)): return
        command.append(resource_ref)
    subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
