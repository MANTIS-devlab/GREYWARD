"""Session 10 extensions for the existing Security Context user-bus service."""
import json
from pathlib import Path
import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib
from greyward_security_context.provenance import _file_ref, provenance, sanitize_copy
from greyward_security_context.safe_open import SafeOpenError, redact_error
from greyward_security_context.user_bus import BUS_NAME, SecurityContext, SensorContext, UsbContext, now, stamp

class Session10SecurityContext(SecurityContext):
 @dbus.service.method(BUS_NAME, in_signature="s", out_signature="s")
 def GetProvenance(self,path):
  summary=json.loads(self.GetSummary())
  return json.dumps(provenance(path,summary.get("recent_events",[])),sort_keys=True,separators=(",",":"))
 @dbus.service.method(BUS_NAME, in_signature="s", out_signature="s")
 def SanitizeCopy(self,path):
  ref="unknown"
  try:
   ref=_file_ref(Path(path).resolve()); result=sanitize_copy(path)
  except (SafeOpenError,OSError) as error:
   self.usb.events.append({"event_id":"sanitize-failed-"+ref,"kind":"SANITIZATION_RESULT","notification":"HISTORY_ONLY","occurred_at":stamp(now()),"title":"Sanitized copy refused","detail":redact_error(error),"source":"security-context/provenance","state":"FAILED","file_ref":ref})
   self._record_file_security_event("SANITIZATION_RESULT","SANITIZE","FAILURE",ref,{"message":redact_error(error)})
   return json.dumps({"ok":False,"state":"FAILED","detail":redact_error(error)},separators=(",",":"))
  self.usb.events.append({"event_id":"sanitize-"+ref,"kind":"SANITIZATION_RESULT","notification":"HISTORY_ONLY","occurred_at":stamp(now()),"title":"Sanitized copy created","detail":result["method"],"source":"security-context/provenance","state":"SANITIZED","file_ref":ref})
  self._record_file_security_event("SANITIZATION_RESULT","SANITIZE","SUCCESS",ref,{"message":result["method"]})
  return json.dumps(result,separators=(",",":"))

def main():
 dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
 bus=dbus.SessionBus(); name=dbus.service.BusName(BUS_NAME,bus=bus)
 service=Session10SecurityContext(bus,UsbContext(),SensorContext()); service.start_shell_runtime(bus); GLib.MainLoop().run()
if __name__=="__main__": main()

