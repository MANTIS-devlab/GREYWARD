"""Lifecycle coordinator inside the existing unprivileged session service."""
import copy
import json
import threading
import time
import logging
from pathlib import Path

import dbus
from gi.repository import GLib

from .notification_router import NotificationRouter, open_route
from .shell_experience import build_experience, RANK
from .usbguard import USB_SERVICE, DEVICES_INTERFACE
from .security_notices import NoticePreferences, SensorStarts, update_notices


class ShellRuntime:
    def __init__(self, service, bus):
        self.service = service
        self.lock = threading.Lock()
        self.bus = bus
        self.operations = {}
        self.snapshot = {"schema": "greyward.security.experience/v1", "revision": 0, "posture": "UNAVAILABLE", "label": "Connecting", "reason": "Reading security status", "severity": "INFO", "items": [], "activity": [], "details": []}
        self.running = False
        self.dirty = True
        self.invalidate_pending = False
        self.last_full = 0
        self.shell, self.files, self.network = {}, {}, {}
        self.router = NotificationRouter(bus, self.dispatch)
        system = dbus.SystemBus()
        self.notice_preferences = NoticePreferences()
        self.sensor_starts = SensorStarts()
        self.update_snapshot = {}
        self.next_update_check = 0
        self.update_check_deadline = 0
        self.boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        for member in ('DevicePresenceChanged', 'DevicePolicyChanged', 'DevicePolicyApplied'):
            system.add_signal_receiver(self.invalidate, signal_name=member, dbus_interface=DEVICES_INTERFACE, bus_name=USB_SERVICE)
        system.add_signal_receiver(self.invalidate, signal_name='NameOwnerChanged', dbus_interface='org.freedesktop.DBus', arg0=USB_SERVICE)
        system.add_signal_receiver(self.invalidate, signal_name='FileSecurityChanged', dbus_interface='systems.mantis.greyward.ClamAvScan1', bus_name='systems.mantis.greyward.ClamAvScan1')
        self.timer = GLib.timeout_add_seconds(2, self.tick)
        self.tick()

    def invalidate(self, *args):
        self.dirty = True
        if not getattr(self, 'invalidate_pending', False):
            self.invalidate_pending = True
            GLib.idle_add(self._tick_once)

    def _tick_once(self):
        self.invalidate_pending = False
        self.tick()
        return False

    def read(self):
        with self.lock: return copy.deepcopy(self.snapshot)

    def tick(self):
        if not self.running:
            self.running = True
            threading.Thread(target=self._collect, daemon=True).start()
        return True

    def _collect(self):
        try:
            invalidated = self.dirty
            full = invalidated or time.monotonic() - self.last_full >= 10
            self.dirty = False
            if invalidated:
                # Cache locks may be held by a bounded provider read. Never
                # wait for them in a D-Bus action or provider-signal callback.
                self.service._invalidate_caches()
            if full:
                workflows = getattr(self.service, 'application_workflows', None)
                if workflows is not None:
                    workflows.reconcile_access_events()
                self.service.reconcile_history()
                self.shell = json.loads(self.service.GetShellSummary())
                self.files = json.loads(self.service.GetFileSecuritySummary())
                from .user_bus import network_summary
                self.network = network_summary()
                self._read_updates()
                self.last_full = time.monotonic()
            capsule = json.loads(self.service.GetPrivacyCapsule())
            devices, error = self.service.usb.devices()
            connected = {x.get('connection_ref') for x in devices} if not error else None
            for ref, op in tuple(self.operations.items()):
                if connected is not None and ref not in connected:
                    self.operations.pop(ref, None)
                elif op.get('expires_at', float('inf')) < time.monotonic():
                    self.operations.pop(ref, None)
                elif op.get('state') == 'INDETERMINATE' and connected is not None:
                    device = next(x for x in devices if x.get('connection_ref') == ref)
                    if device.get('authorized') and (op.get('mode') == 'once' or device.get('trusted')):
                        op.update(state='COMPLETE', detail='Device permission confirmed.', expires_at=time.monotonic() + 5)
            previous = self.read().get('items', []) or [record.get('item', {}) for record in self.router.records.values()]
            workflows = getattr(self.service, 'application_workflows', None)
            blocks = workflows.recent_access_blocks() if workflows is not None else []
            value = build_experience(self.shell, capsule, devices, error, self.files, self.network, self.operations, previous, blocks)
            notices = update_notices(self.update_snapshot, time.time(), self.boot_id)
            notices.extend(self.sensor_starts.collect(capsule, self.notice_preferences.read()['sensor_start'], time.monotonic()))
            # Informational starts/updates do not change protection posture.
            value['notices'] = notices
            value['operations'] = [{k: v for k, v in op.items() if k != 'expires_at'} for op in self.operations.values()]
            GLib.idle_add(self._publish, value, full)
        except Exception:
            logging.exception('Security shell collection failed')
            # Preserve the last confirmed snapshot only until its own deadline.
            # A failed provider does not fabricate a resolved condition.
            GLib.idle_add(self._failed)

    def _read_updates(self):
        # Reuse Update Center, never run package tools in the notification
        # collector. Metadata checks are at most every 15 minutes, with bounded
        # polling while its initial asynchronous refresh is completing.
        current = time.monotonic()
        try:
            proxy = dbus.Interface(self.bus.get_object('org.greyward.Update1', '/org/greyward/Update1'), 'org.greyward.Update1')
            if current >= self.next_update_check:
                self.next_update_check = current + 900
                self.update_check_deadline = current + 60
            if current < self.update_check_deadline:
                snapshot = json.loads(str(proxy.GetSnapshot(timeout=3)))
                self.update_snapshot = snapshot if isinstance(snapshot, dict) else {}
                if not self.update_snapshot.get('snapshot_refreshing'):
                    self.update_check_deadline = 0
            else:
                self.update_snapshot['transaction'] = json.loads(str(proxy.GetTransactionStatus(timeout=3)))
        except (dbus.DBusException, ValueError):
            self.update_snapshot = {}

    def _failed(self):
        self.running = False
        self.dirty = True
        return False

    def _publish(self, value, heartbeat, release_collector=True):
        # One server-side gate drives both the DMS alert surface and native
        # notifications. Keep the full live items in the presentation so
        # posture stays current while short warning flaps remain quiet.
        combined = value.get('items', []) + value.get('notices', [])
        notification_items = self.router.eligible_items(sorted(combined, key=lambda entry: RANK.get(entry.get('severity'), 4)))
        value['notification_items'] = notification_items
        with self.lock:
            old = {k: v for k, v in self.snapshot.items() if k not in {'revision', 'fresh_until', 'display_fresh_until'}}
            shape = {k: v for k, v in value.items() if k not in {'revision', 'fresh_until', 'display_fresh_until'}}
            changed = old != shape
            value['revision'] = self.snapshot.get('revision', 0) + int(changed)
            self.snapshot = value
        if changed or heartbeat:
            self.service.ShellSummaryChanged(value['revision'])
            self.router.reconcile(notification_items)
        if release_collector:
            self.running = False
        return False

    def trust(self, reference, mode):
        if mode not in {'once', 'always'}:
            return {'ok': False, 'state': 'INVALID', 'detail': 'Unknown trust action.'}
        return {'ok': False, 'state': 'SESSION_REQUIRED',
                'detail': 'This background request cannot show the USB approval prompt. Use Trust once or Trust always in the GREYWARD taskbar; the device remains blocked until approved.'}

    def dispatch(self, current, selected):
        if selected in {'trust_once', 'trust_always'}:
            self.trust(current.get('connection_ref', ''), selected.removeprefix('trust_'))
        elif selected == 'clear_clipboard':
            self.service.ClearClipboard(current['id'])
            self.invalidate()
        elif selected == 'open':
            open_route(current.get('route', 'overview'), current.get('resource_ref'))
