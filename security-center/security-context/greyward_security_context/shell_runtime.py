"""Lifecycle coordinator inside the existing unprivileged session service."""
import copy
import json
import threading
import time
import logging

import dbus
from gi.repository import GLib

from .notification_router import NotificationRouter, open_route
from .shell_experience import build_experience
from .usbguard import UsbGuardAdapter, UsbGuardError, USB_SERVICE, DEVICES_INTERFACE


class ShellRuntime:
    def __init__(self, service, bus):
        self.service = service
        self.lock = threading.Lock()
        self.bus = bus
        self.operations = {}
        self.snapshot = {"schema": "greyward.security.experience/v1", "revision": 0, "posture": "UNAVAILABLE", "label": "Connecting", "reason": "Reading security status", "severity": "INFO", "items": [], "activity": [], "details": []}
        self.running = False
        self.dirty = True
        self.last_full = 0
        self.shell, self.files, self.network = {}, {}, {}
        self.router = NotificationRouter(bus, self.dispatch)
        system = dbus.SystemBus()
        for member in ('DevicePresenceChanged', 'DevicePolicyChanged', 'DevicePolicyApplied'):
            system.add_signal_receiver(self.invalidate, signal_name=member, dbus_interface=DEVICES_INTERFACE, bus_name=USB_SERVICE)
        system.add_signal_receiver(self.invalidate, signal_name='NameOwnerChanged', dbus_interface='org.freedesktop.DBus', arg0=USB_SERVICE)
        system.add_signal_receiver(self.invalidate, signal_name='FileSecurityChanged', dbus_interface='systems.mantis.greyward.ClamAvScan1', bus_name='systems.mantis.greyward.ClamAvScan1')
        self.timer = GLib.timeout_add_seconds(2, self.tick)
        self.tick()

    def invalidate(self, *args):
        self.dirty = True
        GLib.idle_add(self._tick_once)

    def _tick_once(self):
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
                self.shell = json.loads(self.service.GetShellSummary())
                self.files = json.loads(self.service.GetFileSecuritySummary())
                from .user_bus import network_summary
                self.network = network_summary()
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
            value = build_experience(self.shell, capsule, devices, error, self.files, self.network, self.operations, previous)
            value['operations'] = [{k: v for k, v in op.items() if k != 'expires_at'} for op in self.operations.values()]
            GLib.idle_add(self._publish, value, full)
        except Exception:
            logging.exception('Security shell collection failed')
            # Preserve the last confirmed snapshot only until its own deadline.
            # A failed provider does not fabricate a resolved condition.
            GLib.idle_add(self._failed)

    def _failed(self):
        self.running = False
        self.dirty = True
        return False

    def _publish(self, value, heartbeat, release_collector=True):
        with self.lock:
            old = {k: v for k, v in self.snapshot.items() if k not in {'revision', 'fresh_until'}}
            shape = {k: v for k, v in value.items() if k != 'fresh_until'}
            changed = old != shape
            value['revision'] = self.snapshot.get('revision', 0) + int(changed)
            self.snapshot = value
        if changed or heartbeat:
            self.service.ShellSummaryChanged(value['revision'])
            self.router.reconcile(value['items'])
        if release_collector:
            self.running = False
        return False

    def trust(self, reference, mode):
        if mode not in {'once', 'always'}:
            return {'ok': False, 'state': 'INVALID', 'detail': 'Unknown trust action.'}
        current = self.read()
        wanted = 'trust_' + mode
        device = next((x for x in current.get('items', []) if x.get('connection_ref') == reference), None)
        old = self.operations.get(reference)
        if old and old.get('state') in {'PENDING', 'VERIFYING', 'INDETERMINATE'}:
            return {'ok': True, 'state': old['state'], 'operation_id': old['operation_id']}
        if not device or wanted not in {x['id'] for x in device.get('actions', [])}:
            return {'ok': False, 'state': 'STALE', 'detail': 'This device action is no longer available.'}
        operation_id = reference + ':' + str(time.monotonic_ns())
        self.operations[reference] = {'connection_ref': reference, 'operation_id': operation_id, 'mode': mode, 'state': 'PENDING', 'detail': 'Waiting for authorization…'}
        # Publish acknowledgement before entering USBGuard: its upstream Polkit
        # check can hold its D-Bus bridge while the authorization dialog is open.
        current.pop('revision', None)
        for event in current.get('items', []):
            if event.get('connection_ref') == reference:
                event.update(actions=[], operation='PENDING', detail='Waiting for authorization…')
                event['notification_detail'] = event['title'] + ': Waiting for authorization…'
        current['operations'] = copy.deepcopy(list(self.operations.values()))
        self._publish(current, False, release_collector=False)
        self.invalidate()
        threading.Thread(target=self._trust_worker, args=(reference, mode, operation_id), daemon=True).start()
        return {'ok': True, 'state': 'PENDING', 'operation_id': operation_id}

    def _trust_worker(self, reference, mode, operation_id):
        result = {'state': 'FAILED', 'detail': 'Device approval could not be confirmed.'}
        try:
            adapter = UsbGuardAdapter(dbus.SystemBus(private=True))
        except dbus.DBusException:
            GLib.idle_add(self._finish_trust, reference, operation_id, {'state': 'UNAVAILABLE', 'detail': 'USBGuard is unavailable.'})
            return
        try:
            device = next((x for x in adapter.list_devices() if x['connection_ref'] == reference), None)
            if not device:
                result = {'state': 'REMOVED', 'detail': 'The device was removed.'}
            else:
                if mode == 'always': adapter.always_allow(device['device_id'])
                else: adapter.allow_once(device['device_id'])
                result = {'state': 'VERIFYING', 'detail': 'Checking device permission…'}
        except UsbGuardError as error:
            result = {'state': error.state, 'detail': str(error)}
        try:
            confirmed = next((x for x in adapter.list_devices() if x['connection_ref'] == reference), None)
            if not confirmed: result = {'state': 'REMOVED', 'detail': 'The device was removed.'}
            elif confirmed.get('authorized') and (mode == 'once' or confirmed.get('trusted')):
                result = {'state': 'COMPLETE', 'detail': 'Device trusted.' if mode == 'always' else 'Allowed until disconnected.'}
            elif result['state'] == 'VERIFYING': result = {'state': 'FAILED', 'detail': 'USBGuard did not confirm the requested permission.'}
        except UsbGuardError:
            result = {'state': 'INDETERMINATE', 'detail': 'Device state is unavailable. Waiting for USBGuard.'}
        GLib.idle_add(self._finish_trust, reference, operation_id, result)

    def _finish_trust(self, reference, operation_id, result):
        old = self.operations.get(reference)
        if old and old['operation_id'] == operation_id:
            old.update(result)
            if result['state'] in {'COMPLETE', 'REMOVED'}: old['expires_at'] = time.monotonic() + 5
        self.invalidate()
        return False

    def dispatch(self, current, selected):
        if selected in {'trust_once', 'trust_always'}:
            self.trust(current.get('connection_ref', ''), selected.removeprefix('trust_'))
        elif selected == 'clear_clipboard':
            self.service.ClearClipboard(current['id'])
            self.invalidate()
        elif selected == 'open':
            open_route(current.get('route', 'overview'))
