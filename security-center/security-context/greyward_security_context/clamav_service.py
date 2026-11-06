#!/usr/bin/python3
"""Single-purpose system scan boundary; no shell, policy, or raw clamd access."""
import json
import grp
import pwd
import time
import threading
from concurrent.futures import ThreadPoolExecutor
import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib
from greyward_security_context.clamav import cached_status as clamav_status
from greyward_security_context.file_security import FileSecurityManager
from greyward_security_context.telemetry import TelemetryError

BUS_NAME='systems.mantis.greyward.ClamAvScan1'
OBJECT_PATH='/systems/mantis/greyward/ClamAvScan1'

class ClamAvScan(dbus.service.Object):
    def __init__(self, bus, path):
        super().__init__(bus, path)
        self.manager = FileSecurityManager()
        self.manager.on_change = lambda: GLib.idle_add(self._changed)
        self._read_workers = ThreadPoolExecutor(max_workers=3, thread_name_prefix='scan-read')
        self._read_slots = threading.BoundedSemaphore(8)
        self._legacy_slot = threading.BoundedSemaphore(1)

    def _defer(self, work, reply, *, legacy=False):
        # At most one compatibility waiter; the other workers serve properties.
        if legacy and not self._legacy_slot.acquire(blocking=False):
            reply(json.dumps({'state': 'BUSY', 'validity': 'UNKNOWN'}))
            return
        if not self._read_slots.acquire(blocking=False):
            if legacy:
                self._legacy_slot.release()
            reply(json.dumps({'state': 'BUSY', 'validity': 'UNKNOWN'}))
            return
        def run():
            try:
                value = work()
            except Exception:
                value = {'state': 'UNAVAILABLE', 'validity': 'UNKNOWN', 'detail': 'The scanner read could not complete.'}
            finally:
                self._read_slots.release()
                if legacy:
                    self._legacy_slot.release()
            def deliver():
                reply(json.dumps(value, sort_keys=True, separators=(',', ':')))
                return False
            GLib.idle_add(deliver)
        self._read_workers.submit(run)

    def _legacy_scan(self, path, uid):
        operation = self.manager.start('FILE', [path], owner_uid=uid)
        reference = operation['operation_id']
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            value = self.manager.status(reference, owner_uid=uid) or {}
            if value.get('state') not in {'QUEUED', 'SCANNING', 'FINALIZING'}:
                receipt = self.manager.scan_info(path, owner_uid=uid)
                if receipt.get('validity') == 'VALID':
                    return {'state': receipt['state'], 'detail': receipt['detail']}
                return {'state': 'PARTIAL', 'detail': 'The scan did not produce a current complete receipt.'}
            time.sleep(.25)
        self.manager.cancel(reference, owner_uid=uid)
        return {'state': 'TIMEOUT', 'detail': 'The compatibility scan timed out.'}

    def _changed(self):
        self.FileSecurityChanged()
        return False

    @dbus.service.signal(BUS_NAME, signature='')
    def FileSecurityChanged(self):
        pass

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='s', sender_keyword='sender', async_callbacks=('reply', 'failure'))
    def ScanPath(self, path, reply, failure, sender=None):
        uid = self._uid(sender)
        self._defer(lambda: self._legacy_scan(path, uid), reply, legacy=True)

    def _uid(self, sender):
        if not sender:
            raise PermissionError("The scan caller could not be identified.")
        try:
            uid = self.connection.get_unix_user(sender)
        except Exception as error:
            raise PermissionError("The scan caller could not be identified.") from error
        if isinstance(uid, bool) or not isinstance(uid, int) or uid < 0:
            raise PermissionError("The scan caller could not be identified.")
        return int(uid)

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='s', sender_keyword='sender', async_callbacks=('reply', 'failure'))
    def StartScan(self, payload, reply, failure, sender=None):
        uid = self._uid(sender)
        if len(payload) > 262144:
            reply(json.dumps({'state': 'FAILED', 'detail': 'Scan request is too large.'}))
            return
        self._defer(lambda: self._start_scan(payload, uid), reply)

    def _start_scan(self, payload, uid):
        try:
            request = json.loads(payload)
            if not isinstance(request, dict):
                raise ValueError('Scan request must be an object.')
            mode = str(request.get('mode') or '').upper()
            if mode != 'SYSTEM':
                value = self.manager.start(mode, request.get('paths') or [], owner_uid=uid, background=request.get("background") is True)
            else:
                account = pwd.getpwuid(uid)
                wheel = grp.getgrnam('wheel')
                if uid != 0 and account.pw_gid != wheel.gr_gid and account.pw_name not in wheel.gr_mem:
                    raise PermissionError("System scanning requires an administrator.")
                value = self.manager.start(mode, [], owner_uid=uid, authorized_system=True)
            return value
        except (OSError, ValueError, TypeError, PermissionError, RuntimeError, json.JSONDecodeError) as error:
            return {'state': 'FAILED', 'detail': str(error)[:320]}

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='s', sender_keyword='sender')
    def GetScanStatus(self, operation_id, sender=None):
        value = self.manager.status(operation_id, owner_uid=self._uid(sender))
        return json.dumps(value or {'state': 'UNAVAILABLE', 'detail': 'Scan history is unavailable.'}, sort_keys=True, separators=(',', ':'))

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='s', sender_keyword='sender')
    def ListFileDetections(self, payload, sender=None):
        try:
            request = json.loads(payload) if payload else {}
            state = request.get('state') if isinstance(request, dict) else None
            limit = request.get('limit', 128) if isinstance(request, dict) else 128
            value = {'schema': 'greyward.file-security.detections/v1', 'state': 'AVAILABLE', 'detections': self.manager.detections(state=state, limit=limit, owner_uid=self._uid(sender))}
        except (TypeError, ValueError, json.JSONDecodeError, TelemetryError) as error:
            value = {'schema': 'greyward.file-security.detections/v1', 'state': 'UNAVAILABLE', 'detections': [], 'detail': str(error)[:240]}
        return json.dumps(value, sort_keys=True, separators=(',', ':'))

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='s', sender_keyword='sender', async_callbacks=('reply', 'failure'))
    def GetFileScanInfo(self, path, reply, failure, sender=None):
        uid = self._uid(sender)
        self._defer(lambda: self.manager.scan_info(str(path), owner_uid=uid), reply)

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='s', sender_keyword='sender', async_callbacks=('reply', 'failure'))
    def GetFileScanInfoBatch(self, payload, reply, failure, sender=None):
        uid = self._uid(sender)
        try:
            if len(payload) > 131072:
                raise ValueError
            paths = json.loads(payload)
            if not isinstance(paths, list) or not 1 <= len(paths) <= 32:
                raise ValueError
        except (ValueError, TypeError):
            reply(json.dumps({'state': 'UNAVAILABLE', 'items': []}))
            return
        self._defer(lambda: {'state': 'AVAILABLE', 'items': self.manager.scan_infos(paths, owner_uid=uid)}, reply)

    @dbus.service.method(BUS_NAME, in_signature='', out_signature='s', async_callbacks=('reply', 'failure'))
    def GetClamAvStatus(self, reply, failure):
        self._defer(clamav_status, reply)

    @dbus.service.method(BUS_NAME, in_signature='', out_signature='s', sender_keyword='sender', async_callbacks=('reply', 'failure'))
    def GetFileSecuritySummary(self, reply, failure, sender=None):
        uid = self._uid(sender)
        self._defer(lambda: self._summary(uid), reply)

    def _summary(self, uid):
        try:
            scans = self.manager.reconcile_interrupted_scans(32, owner_uid=uid)
            active = next((item for item in scans if item.get('state') in {'QUEUED', 'SCANNING', 'FINALIZING'}), None)
            value = {'schema': 'greyward.file-security/v1', 'state': 'AVAILABLE', 'active_scan': active, 'latest_scan': scans[0] if scans else None, 'recent_scans': scans[:8], 'detections': self.manager.detections(limit=128, owner_uid=uid), 'activity': self.manager.activity(128, owner_uid=uid), 'clamav': clamav_status()}
        except (OSError, TelemetryError) as error:
            value = {'schema': 'greyward.file-security/v1', 'state': 'UNAVAILABLE', 'active_scan': None, 'latest_scan': None, 'detections': [], 'activity': [], 'detail': str(error)[:240]}
        return value

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='s', sender_keyword='sender')
    def CancelScan(self, operation_id, sender=None):
        value = self.manager.cancel(operation_id, owner_uid=self._uid(sender))
        return json.dumps(value or {'state': 'UNAVAILABLE', 'detail': 'Scan cancellation is unavailable.'}, sort_keys=True, separators=(',', ':'))

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='s', sender_keyword='sender')
    def QuarantineDetection(self, detection_id, sender=None):
        try:
            return json.dumps(self.manager.prepare_quarantine(detection_id, actor_uid=self._uid(sender)), sort_keys=True, separators=(',', ':'))
        except (OSError, ValueError, PermissionError, TelemetryError) as error:
            return json.dumps({'state': 'QUARANTINE_FAILED', 'detail': str(error)[:320]}, separators=(',', ':'))

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='s', sender_keyword='sender')
    def CompleteQuarantine(self, detection_id, sender=None):
        try:
            return json.dumps(self.manager.complete_quarantine(detection_id, actor_uid=self._uid(sender)), sort_keys=True, separators=(',', ':'))
        except (OSError, ValueError, PermissionError, TelemetryError) as error:
            return json.dumps(self.manager.fail_quarantine(detection_id, str(error), actor_uid=self._uid(sender)), sort_keys=True, separators=(',', ':'))

    @dbus.service.method(BUS_NAME, in_signature='ss', out_signature='s', sender_keyword='sender')
    def FailQuarantine(self, detection_id, detail, sender=None):
        try:
            return json.dumps(self.manager.fail_quarantine(detection_id, detail, actor_uid=self._uid(sender)), sort_keys=True, separators=(',', ':'))
        except (OSError, ValueError, PermissionError, TelemetryError) as error:
            return json.dumps({'state': 'QUARANTINE_FAILED', 'detail': str(error)[:320]}, separators=(',', ':'))

    @dbus.service.method(BUS_NAME, in_signature='ss', out_signature='s', sender_keyword='sender')
    def RestoreDetection(self, detection_id, destination, sender=None):
        try:
            return json.dumps(self.manager.prepare_restore(detection_id, destination or None, actor_uid=self._uid(sender)), sort_keys=True, separators=(',', ':'))
        except (OSError, ValueError, PermissionError, TelemetryError) as error:
            return json.dumps({'state': 'RESTORE_FAILED', 'detail': str(error)[:320]}, separators=(',', ':'))

    @dbus.service.method(BUS_NAME, in_signature='ss', out_signature='s', sender_keyword='sender')
    def CompleteRestore(self, detection_id, destination, sender=None):
        try:
            return json.dumps(self.manager.complete_restore(detection_id, destination, actor_uid=self._uid(sender)), sort_keys=True, separators=(',', ':'))
        except (OSError, ValueError, PermissionError, TelemetryError) as error:
            return json.dumps(self.manager.fail_restore(detection_id, str(error), actor_uid=self._uid(sender)), sort_keys=True, separators=(',', ':'))

    @dbus.service.method(BUS_NAME, in_signature='ss', out_signature='s', sender_keyword='sender')
    def FailRestore(self, detection_id, detail, sender=None):
        try:
            return json.dumps(self.manager.fail_restore(detection_id, detail, actor_uid=self._uid(sender)), sort_keys=True, separators=(',', ':'))
        except (OSError, ValueError, PermissionError, TelemetryError) as error:
            return json.dumps({'state': 'RESTORE_FAILED', 'detail': str(error)[:320]}, separators=(',', ':'))

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='s', sender_keyword='sender')
    def DeleteDetection(self, detection_id, sender=None):
        try:
            return json.dumps(self.manager.delete_detection(detection_id, actor_uid=self._uid(sender)), sort_keys=True, separators=(',', ':'))
        except (OSError, ValueError, PermissionError, TelemetryError) as error:
            return json.dumps({'state': 'DELETE_FAILED', 'detail': str(error)[:320]}, separators=(',', ':'))

def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus=dbus.SystemBus()
    name=dbus.service.BusName(BUS_NAME,bus=bus)
    service=ClamAvScan(bus,OBJECT_PATH)
    GLib.MainLoop().run()

if __name__=='__main__': main()
