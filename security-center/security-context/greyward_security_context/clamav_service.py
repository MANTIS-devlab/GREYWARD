#!/usr/bin/python3
"""Single-purpose system scan boundary; no shell, policy, or raw clamd access."""
import json
import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib
from greyward_security_context.clamav import scan, status as clamav_status
from greyward_security_context.file_security import FileSecurityManager
from greyward_security_context.telemetry import TelemetryError

BUS_NAME='systems.mantis.greyward.ClamAvScan1'
OBJECT_PATH='/systems/mantis/greyward/ClamAvScan1'

class ClamAvScan(dbus.service.Object):
    def __init__(self, bus, path):
        super().__init__(bus, path)
        self.manager = FileSecurityManager()
        self.manager.on_change = lambda: GLib.idle_add(self._changed)

    def _changed(self):
        self.FileSecurityChanged()
        return False

    @dbus.service.signal(BUS_NAME, signature='')
    def FileSecurityChanged(self):
        pass

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='s', sender_keyword='sender')
    def ScanPath(self, path, sender=None):
        try:
            uid=self.connection.get_unix_user(sender)
            value=scan(path, uid=uid)
            self.manager.record_legacy_result(path,value)
        except Exception:
            value={'state':'ERROR','detail':'ClamAV could not process the requested source.'}
        return json.dumps(value,sort_keys=True,separators=(',',':'))

    def _uid(self, sender):
        return self.connection.get_unix_user(sender)

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='s', sender_keyword='sender')
    def StartScan(self, payload, sender=None):
        try:
            request = json.loads(payload)
            mode = str(request.get('mode') or '').upper()
            uid = self._uid(sender)
            if mode != 'SYSTEM':
                value = self.manager.start(mode, request.get('paths') or [], owner_uid=uid)
            else:
                # The system D-Bus policy limits this interface to the
                # explicitly authorized desktop-admin group for V1.
                value = self.manager.start(mode, [], owner_uid=uid, authorized_system=True)
            return json.dumps(value, sort_keys=True, separators=(',', ':'))
        except (OSError, ValueError, TypeError, PermissionError, RuntimeError, json.JSONDecodeError) as error:
            return json.dumps({'state': 'FAILED', 'detail': str(error)[:320]}, separators=(',', ':'))

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='s')
    def GetScanStatus(self, operation_id):
        value = self.manager.status(operation_id)
        return json.dumps(value or {'state': 'UNAVAILABLE', 'detail': 'Scan history is unavailable.'}, sort_keys=True, separators=(',', ':'))

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='s')
    def ListFileDetections(self, payload):
        try:
            request = json.loads(payload) if payload else {}
            state = request.get('state') if isinstance(request, dict) else None
            limit = request.get('limit', 128) if isinstance(request, dict) else 128
            value = {'schema': 'greyward.file-security.detections/v1', 'state': 'AVAILABLE', 'detections': self.manager.detections(state=state, limit=limit)}
        except (TypeError, ValueError, json.JSONDecodeError, TelemetryError) as error:
            value = {'schema': 'greyward.file-security.detections/v1', 'state': 'UNAVAILABLE', 'detections': [], 'detail': str(error)[:240]}
        return json.dumps(value, sort_keys=True, separators=(',', ':'))

    @dbus.service.method(BUS_NAME, in_signature='', out_signature='s')
    def GetFileSecuritySummary(self):
        try:
            scans = self.manager.reconcile_interrupted_scans(32)
            active = next((item for item in scans if item.get('state') in {'QUEUED', 'SCANNING', 'FINALIZING'}), None)
            value = {'schema': 'greyward.file-security/v1', 'state': 'AVAILABLE', 'active_scan': active, 'latest_scan': scans[0] if scans else None, 'detections': self.manager.detections(limit=128), 'activity': self.manager.activity(128), 'clamav': clamav_status()}
        except (OSError, TelemetryError) as error:
            value = {'schema': 'greyward.file-security/v1', 'state': 'UNAVAILABLE', 'active_scan': None, 'latest_scan': None, 'detections': [], 'activity': [], 'detail': str(error)[:240]}
        return json.dumps(value, sort_keys=True, separators=(',', ':'))

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='s')
    def CancelScan(self, operation_id):
        value = self.manager.cancel(operation_id)
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
