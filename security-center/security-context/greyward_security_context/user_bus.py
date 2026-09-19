#!/usr/bin/python3
"""Unprivileged normalized Security Context session-bus service."""
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
try:
 from pwd import getpwuid
except ImportError:
 getpwuid = None
import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib
from greyward_security_context.usbguard import UsbGuardAdapter, UsbGuardError
from greyward_security_context.clamav import permitted, status as clamav_status
from greyward_security_context.sensors import PipeWireMonitor
from greyward_security_context.persistence import PersistenceMonitor
from greyward_security_context.summaries import weekly_summary
from greyward_security_context.provenance import _file_ref
from greyward_security_context.safe_open import SafeOpenError, launch as launch_safe_open, monitor as monitor_safe_open, redact_error
from greyward_security_context.notification_router import scan_context
from greyward_security_context.shell_summary import build_shell_summary
from greyward_security_context.privacy_capsule import PrivacyCapsule
from greyward_security_context.telemetry import QUERY_SCHEMA, TelemetryError, TelemetryStore, derive_device_identity, event as telemetry_event, import_root_spool, record_event, user_store
from greyward_security_context.aggregation import build_security_digest
from greyward_security_context.file_security import FileSecurityManager, _open_readonly_nofollow, _unlink_verified_source, file_activity_items
from greyward_security_context.network_location import country_resolution_for_destination
BUS_NAME="systems.mantis.greyward.SecurityContext1"; OBJECT_PATH="/systems/mantis/greyward/SecurityContext1"; STATE_PATH=Path("/run/greyward-security-context/opensnitch-summary.json"); SCHEMA="greyward.security.context/v1"
NETWORK_STATE_PATH=Path("/run/greyward-security-context/network-protection.json"); NETWORK_SCHEMA="greyward.security.network/v1"
SECURE_DNS_STATE_PATH=Path("/run/greyward-secure-dns/state.json")
SECURE_DNS_BUS="systems.mantis.greyward.SecureDns1"; SECURE_DNS_OBJECT="/systems/mantis/greyward/SecureDns1"; SECURE_DNS_INTERFACE="systems.mantis.greyward.SecureDns1"
TRANSACTION_PATH=Path(os.environ.get("XDG_STATE_HOME",Path.home()/".local/state"))/"greyward-update-center"/"transaction.json"
PROFILE_HELPER_CANDIDATES=(Path("/usr/libexec/greyward-security-profile"),Path("/usr/bin/greyward-security-profile"))
PROFILE_CALL_LOCK=threading.Lock()
DBUS_CALL_TIMEOUT=8
CAPSULE_REFRESH_SECONDS=2
FILE_SECURITY_DBUS_TIMEOUT=30
AUTHORITATIVE_POSTURE_CACHE_SECONDS=5
SUMMARY_CACHE_SECONDS=2
NETWORK_HEALTH_CACHE_SECONDS=5
RECENT_POLICY_RULES={}
_AUTHORITATIVE_POSTURE_CACHE=None
_AUTHORITATIVE_POSTURE_CACHE_LOCK=threading.Lock()
_NETWORK_HEALTH_CACHE=None
_NETWORK_HEALTH_CACHE_LOCK=threading.Lock()

def _write_shell_summary_cache(encoded):
 try:
  runtime=Path(os.environ.get("XDG_RUNTIME_DIR", "/tmp"))
  runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
  target=runtime/"greyward-security-shell-summary.json"
  temporary=runtime/(f".greyward-security-shell-summary.{os.getpid()}.tmp")
  temporary.write_text(encoded,encoding="utf-8")
  os.chmod(temporary,0o600)
  os.replace(temporary,target)
  os.chmod(target,0o600)
 except OSError:
  try: temporary.unlink()
  except (NameError,OSError): pass
def _invalidate_shared_caches():
 global _AUTHORITATIVE_POSTURE_CACHE, _NETWORK_HEALTH_CACHE
 with _AUTHORITATIVE_POSTURE_CACHE_LOCK:
  _AUTHORITATIVE_POSTURE_CACHE=None
 with _NETWORK_HEALTH_CACHE_LOCK:
  _NETWORK_HEALTH_CACHE=None
def now(): return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
def stamp(value): return value.isoformat().replace("+00:00","Z")
def authoritative_posture():
 global _AUTHORITATIVE_POSTURE_CACHE
 with _AUTHORITATIVE_POSTURE_CACHE_LOCK:
  current=time.monotonic()
  if _AUTHORITATIVE_POSTURE_CACHE and current - _AUTHORITATIVE_POSTURE_CACHE[0] < AUTHORITATIVE_POSTURE_CACHE_SECONDS:
   return dict(_AUTHORITATIVE_POSTURE_CACHE[1]) if _AUTHORITATIVE_POSTURE_CACHE[1] else None
  posture=None
  try:
   result=subprocess.run(["/usr/bin/greyward-security-center","--print-posture"],capture_output=True,text=True,timeout=8,check=True)
   payload=json.loads(result.stdout)
   summary=payload.get("posture") or {}
   metrics=payload.get("metrics") or {}
   state=str(summary.get("state") or "").upper()
   if state in {"SECURE","PROTECTED","REVIEW NEEDED","UNAVAILABLE"}:
    review_count=max(0,int(metrics.get("review_needed",0)))
    unavailable_count=max(0,int(metrics.get("unavailable",0)))
    observed_at=dt.datetime.now(dt.timezone.utc)
    posture={"state":state,"review_count":review_count,"unavailable_count":unavailable_count,"attention_count":review_count+unavailable_count,"detail":"Posture evaluated by GREYWARD Security Center.","observed_at":stamp(observed_at),"fresh_until":stamp(observed_at+dt.timedelta(seconds=AUTHORITATIVE_POSTURE_CACHE_SECONDS))}
  except (OSError,ValueError,subprocess.SubprocessError,TypeError):
   posture=None
  _AUTHORITATIVE_POSTURE_CACHE=(current,posture)
  return dict(posture) if posture else None
def apply_authoritative_posture(value):
 posture=authoritative_posture()
 if not posture:
  current=now()
  value["state"]="UNAVAILABLE"
  value["review_count"]=0
  value["unavailable_count"]=1
  value["attention_count"]=1
  value["live_states"]=[{"kind":"POSTURE","state":"UNAVAILABLE","detail":"The authoritative Security Center posture could not be read.","observed_at":stamp(current)}]
  value["fresh_until"]=stamp(current)
  return value
 source_states=value.get("live_states",[])
 source_unavailable=any(item.get("state")=="UNAVAILABLE" for item in source_states)
 source_review=bool(value.get("review_count",0)) or any(item.get("state")=="REVIEW NEEDED" for item in source_states)
 if source_unavailable:
  value["state"]="UNAVAILABLE"
 elif source_review and posture["state"]=="SECURE":
  value["state"]="REVIEW NEEDED"
 else:
  value["state"]=posture["state"]
 value["review_count"]=max(int(value.get("review_count",0)),posture["review_count"])
 value["unavailable_count"]=max(int(value.get("unavailable_count",0)),posture.get("unavailable_count",0))
 value["attention_count"]=max(int(value.get("review_count",0))+int(value.get("unavailable_count",0)),posture.get("attention_count",0))
 value["live_states"]=[item for item in source_states if item.get("kind")!="POSTURE"]
 value["live_states"].append({"kind":"POSTURE","state":value["state"],"detail":posture["detail"],"observed_at":posture.get("observed_at",stamp(now()))})
 if posture.get("fresh_until"): value["fresh_until"]=posture["fresh_until"]
 return value
def unavailable_summary():
 current=now(); return {"schema":SCHEMA,"state":"UNAVAILABLE","generated_at":stamp(current),"fresh_until":stamp(current),"review_count":0,"unavailable_count":1,"attention_count":1,"live_states":[{"kind":"PROTECTED","state":"UNAVAILABLE","detail":"OpenSnitch Security Context state is unavailable.","observed_at":stamp(current)}],"recent_events":[]}
def unavailable_network_summary(detail="OpenSnitch application protection is unavailable."):
 current=now(); return {"schema":NETWORK_SCHEMA,"generated_at":stamp(current),"fresh_until":stamp(current),"opensnitch":{"state":"UNAVAILABLE","detail":detail,"version":None,"last_seen":None,"stats":{},"health":{"state":"UNAVAILABLE","daemon":"UNKNOWN","control_plane":"UNKNOWN","event_stream":"UNKNOWN"},"capabilities":{"installed":bool(shutil.which("opensnitchd")),"activity":False,"rules":False,"rule_mutation":"UNAVAILABLE","interactive_prompts":"DEFERRED"}},"applications":[],"activity":[],"rules":[]}
def unavailable_network_activity(detail="OpenSnitch application activity is unavailable."):
 current=now(); return {"schema":"greyward.security.network.activity/v1","state":"UNAVAILABLE","detail":detail,"session_id":None,"generated_at":stamp(current),"fresh_until":stamp(current),"next_sequence":0,"reset":True,"summary":{"window_seconds":1800,"total":0,"allowed":0,"blocked":0,"unknown":0,"buckets":[]},"events":[]}
def _service_active(name):
 try:
  result=subprocess.run(["systemctl","--system","is-active","--quiet",name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2,check=False)
  return result.returncode == 0
 except (OSError,subprocess.SubprocessError):
  return False
def _probe_network_link():
 """Confirm both local OpenSnitch services before reporting stale data as down."""
 return all(_network_service_health())
def _network_service_health():
 global _NETWORK_HEALTH_CACHE
 with _NETWORK_HEALTH_CACHE_LOCK:
  current=time.monotonic()
  if _NETWORK_HEALTH_CACHE and current-_NETWORK_HEALTH_CACHE[0] < NETWORK_HEALTH_CACHE_SECONDS:
   return _NETWORK_HEALTH_CACHE[1]
  value=(_service_active("opensnitch.service"),_service_active("greyward-opensnitch-control-plane.service"))
  _NETWORK_HEALTH_CACHE=(current,value)
  return value
def _apply_idle_health(value):
 opensnitch=value.get("opensnitch") or {}
 if opensnitch.get("last_seen") or str(opensnitch.get("state") or "").upper() not in {"","UNAVAILABLE","DEGRADED"}:
  return value
 daemon_active,control_active=_network_service_health()
 ready=daemon_active and control_active
 opensnitch["health"]={"state":"IDLE" if ready else "UNAVAILABLE","daemon":"ACTIVE" if daemon_active else "INACTIVE","control_plane":"ACTIVE" if control_active else "INACTIVE","event_stream":"EMPTY","detail":"Link ready; no application traffic has been observed yet." if ready else "OpenSnitch health could not be confirmed."}
 if ready:
  opensnitch["state"]="OPERATING"
  opensnitch["detail"]="OpenSnitch is connected and idle. No application connections have been observed yet."
  capabilities=opensnitch.setdefault("capabilities",{})
  capabilities.update({"activity":True,"rules":True,"rule_mutation":"TYPED_POLICY"})
 value["opensnitch"]=opensnitch
 return value
def _normalize_network_capabilities(value):
 opensnitch=value.setdefault("opensnitch",{})
 state=str(opensnitch.get("state") or "UNAVAILABLE").upper()
 health=opensnitch.setdefault("health",{})
 capabilities=opensnitch.setdefault("capabilities",{})
 capabilities["installed"]=bool(capabilities.get("installed", opensnitch.get("version")) or shutil.which("opensnitchd"))
 if state == "OPERATING":
  capabilities.update({"installed":True,"activity":True,"rules":True,"rule_mutation":"TYPED_POLICY"})
  health.setdefault("healthy", True)
  health.setdefault("freshness", "FRESH")
 elif state != "OPERATING":
  capabilities.update({"activity":False,"rules":False,"rule_mutation":"UNAVAILABLE"})
 health.setdefault("healthy", state == "OPERATING")
 health.setdefault("freshness", "FRESH" if state == "OPERATING" else "STALE")
 if state == "UNAVAILABLE":
  health.update({"healthy":False,"freshness":"STALE"})
 return value
def network_summary():
 try:
  value=json.loads(NETWORK_STATE_PATH.read_text(encoding="utf-8"))
 except (OSError,json.JSONDecodeError):
  return _apply_idle_health(unavailable_network_summary())
 if not isinstance(value,dict) or value.get("schema") != NETWORK_SCHEMA or not isinstance(value.get("opensnitch"),dict):
  return _apply_idle_health(unavailable_network_summary("GREYWARD received an unsupported OpenSnitch network state."))
 value=_apply_idle_health(value)
 last_seen=((value.get("opensnitch") or {}).get("last_seen"))
 if last_seen:
  try:
   age=(now()-dt.datetime.fromisoformat(str(last_seen).replace("Z","+00:00"))).total_seconds()
   if age > 30:
    if _probe_network_link():
     value["opensnitch"]["state"]="OPERATING"; value["opensnitch"]["detail"]="OpenSnitch is reachable; its heartbeat is stale, but application protection remains available."
     value["opensnitch"].setdefault("health",{}).update({"state":"ACTIVE","daemon":"ACTIVE","control_plane":"ACTIVE","event_stream":"STALE","freshness":"STALE","healthy":True,"detail":"OpenSnitch and the GREYWARD control plane answered the liveness probe; the daemon heartbeat is stale."})
    elif age > 120:
     value["opensnitch"]["state"]="UNAVAILABLE"; value["opensnitch"]["detail"]="OpenSnitch has not reported for more than two minutes and its liveness probe failed. Application protection state is unavailable."
     value["opensnitch"].setdefault("health",{}).update({"state":"UNAVAILABLE","daemon":"INACTIVE","control_plane":"INACTIVE","event_stream":"STALE","freshness":"STALE","healthy":False,"detail":"The OpenSnitch and GREYWARD control-plane liveness probe failed after the heartbeat became stale."})
    else:
     value["opensnitch"]["state"]="DEGRADED"; value["opensnitch"]["detail"]="OpenSnitch heartbeat is stale and its liveness probe did not confirm the link yet. Recent activity may be delayed."
     value["opensnitch"].setdefault("health",{}).update({"state":"DEGRADED","event_stream":"STALE","freshness":"STALE","healthy":False,"detail":"The OpenSnitch and GREYWARD control-plane liveness probe failed; recent activity may be delayed."})
  except (TypeError,ValueError):
   if _probe_network_link():
    value["opensnitch"]["state"]="OPERATING"; value["opensnitch"]["detail"]="OpenSnitch is reachable, but its heartbeat timestamp could not be verified."
    value["opensnitch"].setdefault("health",{}).update({"state":"ACTIVE","daemon":"ACTIVE","control_plane":"ACTIVE","event_stream":"STALE","freshness":"STALE","healthy":True,"detail":"The liveness probe answered; heartbeat freshness is unavailable."})
   else:
    value["opensnitch"]["state"]="UNAVAILABLE"; value["opensnitch"]["detail"]="OpenSnitch freshness could not be verified and its liveness probe failed."
    value["opensnitch"].setdefault("health",{}).update({"state":"UNAVAILABLE","daemon":"INACTIVE","control_plane":"INACTIVE","event_stream":"STALE","freshness":"STALE","healthy":False})
 return _normalize_network_capabilities(_merge_policy_rules(value))
def _with_network_location(value):
 event=dict(value)
 destination=dict(event.get("destination") or {})
 existing_code=str(destination.get("country_code") or "").strip().upper()
 if not (len(existing_code) == 2 and existing_code.isalpha()):
  existing_code=""
 resolution=country_resolution_for_destination(destination.get("ip"),destination.get("host"))
 country_code=existing_code or str(resolution.get("country_code") or "")
 if country_code:
  destination["country_code"]=country_code
  confidence=str(destination.get("country_confidence") or resolution.get("confidence") or "MEDIUM").upper()
  destination["country_confidence"]=confidence if confidence in ("HIGH","MEDIUM","LOW","VERY_LOW") else "MEDIUM"
  converged=destination.get("country_converged", resolution.get("converged", False))
  if isinstance(converged,str): converged=converged.strip().lower() in ("1","true","yes")
  destination["country_converged"]=bool(converged)
  try: source_count=int(destination.get("country_source_count") or resolution.get("source_count") or 0)
  except (TypeError,ValueError): source_count=0
  destination["country_source_count"]=max(0,source_count)
  destination["country_source"]=str(destination.get("country_source") or resolution.get("source") or "LOCAL")
 else:
  for key in ("country_code", "country_confidence", "country_converged", "country_source_count", "country_source"):
   destination.pop(key,None)
 event["destination"]=destination
 return event
def network_activity(since_sequence=0,limit=256):
 value=network_summary()
 if not isinstance(value,dict) or value.get("schema") != NETWORK_SCHEMA or not isinstance(value.get("opensnitch"),dict):
  return unavailable_network_activity("GREYWARD received an unsupported OpenSnitch network state.")
 try: since=max(0,int(since_sequence))
 except (TypeError,ValueError): since=0
 try: limit=max(1,min(256,int(limit)))
 except (TypeError,ValueError): limit=256
 events=value.get("activity") if isinstance(value.get("activity"),list) else []
 events=[event for event in events if isinstance(event,dict) and isinstance(event.get("sequence"),int)]
 ordered=events
 oldest=min((event["sequence"] for event in events),default=0)
 reset=since == 0 or bool(oldest and since < oldest - 1)
 selected=ordered[:limit] if reset else [event for event in ordered if event["sequence"] > since][:limit]
 selected=[_with_network_location(event) for event in selected]
 summary=value.get("activity_summary") if isinstance(value.get("activity_summary"),dict) else {"window_seconds":1800,"total":len(events),"allowed":0,"blocked":0,"unknown":0,"buckets":[]}
 opensnitch=value.get("opensnitch") or {}
 return {"schema":"greyward.security.network.activity/v1","state":opensnitch.get("state","UNAVAILABLE"),"detail":opensnitch.get("detail","Application activity is unavailable."),"session_id":value.get("activity_session_id"),"generated_at":value.get("generated_at",stamp(now())),"fresh_until":value.get("fresh_until",stamp(now())),"next_sequence":int(value.get("activity_next_sequence",0) or 0),"reset":reset,"summary":summary,"rule_mutation":(opensnitch.get("capabilities") or {}).get("rule_mutation","UNAVAILABLE"),"events":selected}
def telemetry_query(payload):
 try:
  filters=json.loads(payload) if isinstance(payload,str) else payload
  if not isinstance(filters,dict): raise TelemetryError("Telemetry query must be an object.")
  store=user_store(); import_root_spool(store); return store.query(filters)
 except (TelemetryError,TypeError,ValueError,json.JSONDecodeError) as error:
  return {"schema":QUERY_SCHEMA,"generated_at":stamp(now()),"events":[],"truncated":False,"source_state":{"source":"greyward-sqlite-history","state":"UNAVAILABLE","reason":str(error)[:160]}}
def telemetry_related(payload):
 try:
  request=json.loads(payload) if isinstance(payload,str) else payload
  if not isinstance(request,dict) or not isinstance(request.get("event_id"),str): raise TelemetryError("A telemetry event ID is required.")
  event_id=request["event_id"]
  options=request.get("options") or {}
  limit=options.get("limit",128) if isinstance(options,dict) else 128
  store=user_store(); import_root_spool(store); return store.related(event_id,limit)
 except (TelemetryError,TypeError,ValueError,json.JSONDecodeError) as error:
  return {"schema":QUERY_SCHEMA,"generated_at":stamp(now()),"seed_event_id":str(event_id)[:96],"events":[],"source_state":{"source":"greyward-sqlite-history","state":"UNAVAILABLE","reason":str(error)[:160]}}
def _secure_dns_call(method,payload=None):
 try:
  proxy=dbus.Interface(dbus.SystemBus().get_object(SECURE_DNS_BUS,SECURE_DNS_OBJECT),SECURE_DNS_INTERFACE)
  call=proxy.get_dbus_method(method,SECURE_DNS_INTERFACE)
  raw=call(timeout=DBUS_CALL_TIMEOUT) if payload is None else call(str(payload),timeout=DBUS_CALL_TIMEOUT)
  return json.loads(str(raw))
 except (OSError,TypeError,ValueError,json.JSONDecodeError,dbus.DBusException): return None
def _secure_dns_state_file():
 value={}
 try: value=json.loads(SECURE_DNS_STATE_PATH.read_text(encoding="utf-8"))
 except (OSError,json.JSONDecodeError): pass
 if not isinstance(value,dict): value={}
 value.setdefault("schema","greyward.secure-dns/v1"); value.setdefault("desired_policy","Automatic"); value.setdefault("effective_policy","Unavailable"); value.setdefault("effective_owner","None"); value.setdefault("effective_transport","None"); value.setdefault("provider","quad9"); value.setdefault("encryption","Unknown"); value.setdefault("validation","Unknown"); value.setdefault("degradation_reason","ResolverUnreachable"); value.setdefault("runtime_mutation","DISABLED_READ_ONLY")
 return value
def secure_dns_state():
  value=_secure_dns_call("GetState")
  if isinstance(value,dict):
   return value
  value=_secure_dns_state_file()
  if not _service_active("greyward-secure-dns.service"):
   value.update({"effective_policy":"Unavailable","effective_owner":"None","effective_transport":"None","encryption":"Unavailable","validation":"Unavailable","degradation_reason":"ServiceUnavailable","runtime_mutation":"DISABLED_READ_ONLY"})
  return value
def _profile_helper():
 override=os.environ.get("GREYWARD_SECURITY_PROFILE_HELPER")
 candidates=([Path(override)] if override else [])+list(PROFILE_HELPER_CANDIDATES)
 return next((item for item in candidates if item.is_file() and os.access(item,os.X_OK)),None)
def _profile_call(operation,profile=None):
 with PROFILE_CALL_LOCK:
  helper=_profile_helper()
  if helper is None: return {"ok":False,"state":"UNAVAILABLE","profile":None,"available":False,"detail":"GREYWARD privacy profile control is unavailable."}
  args=[str(helper),operation]
  if profile is not None: args.append(str(profile))
  try: result=subprocess.run(args,capture_output=True,text=True,timeout=15,check=False)
  except (OSError,subprocess.SubprocessError): return {"ok":False,"state":"UNAVAILABLE","profile":None,"available":False,"detail":"GREYWARD privacy profile control is unavailable."}
  try: value=json.loads(result.stdout.strip())
  except (TypeError,json.JSONDecodeError): return {"ok":False,"state":"REFUSED","profile":None,"available":True,"detail":"Privacy profile control returned an invalid result."}
  if not isinstance(value,dict): return {"ok":False,"state":"REFUSED","profile":None,"available":True,"detail":"Privacy profile control returned an invalid result."}
  value["available"]=True
  value["detail"]=str(value.get("detail") or "")[:240]
  return value
def _update_transaction():
 try: value=json.loads(TRANSACTION_PATH.read_text(encoding="utf-8"))
 except (OSError,json.JSONDecodeError): return {"phase":"IDLE"}
 if not isinstance(value,dict): return {"phase":"IDLE"}
 phase=str(value.get("phase") or "IDLE").upper()
 if phase in {"RESTARTING","READY_TO_RESTART"}:
  try: boot_id=Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
  except OSError: boot_id=""
  if value.get("boot_id") and boot_id and value.get("boot_id") != boot_id:
   value.update({"phase":"COMPLETE","restart_required":"UNKNOWN","error":None,"finished_at":stamp(now()),"updated_at":stamp(now())})
  elif phase == "RESTARTING":
   try: age=(now()-dt.datetime.fromisoformat(str(value.get("updated_at") or "").replace("Z","+00:00"))).total_seconds()
   except (TypeError,ValueError,OverflowError): age=0
   if age > 900: value.update({"phase":"COMPLETE","restart_required":"UNKNOWN","error":None,"finished_at":stamp(now()),"updated_at":stamp(now())})
 return value
def _validated_network_rule(value):
 if not isinstance(value,dict): raise ValueError("A typed network rule is required.")
 path=str(value.get("application") or "")
 action=str(value.get("action") or "").lower()
 duration=str(value.get("duration") or "always").lower()
 if not path.startswith("/") or "\x00" in path or len(path)>240: raise ValueError("A valid absolute application path is required.")
 if action not in {"allow","block","deny","reject"}: raise ValueError("Unsupported network action.")
 if duration not in {"once","until_restart","until restart","always"}: raise ValueError("Unsupported network duration.")
 destination=value.get("destination") or {}
 if not isinstance(destination,dict): raise ValueError("Destination scope is invalid.")
 host=str(destination.get("host") or "").strip().lower()
 ip=str(destination.get("ip") or "").strip()
 port=destination.get("port")
 if host and (len(host)>160 or not re.fullmatch(r"[a-z0-9._-]+",host)):
  raise ValueError("Destination domain is invalid.")
 if ip:
  try: ipaddress.ip_address(ip)
  except ValueError as error: raise ValueError("Destination IP is invalid.") from error
 if port not in (None, "", 0):
  try: port=int(port)
  except (TypeError,ValueError) as error: raise ValueError("Destination port is invalid.") from error
  if not 1<=port<=65535: raise ValueError("Destination port must be between 1 and 65535.")
 else: port=None
 return {"application":path,"action":"allow" if action=="allow" else "deny","duration":"until restart" if duration in {"until_restart","until restart"} else duration,"destination":{"host":host or None,"ip":ip or None,"port":port}}
def _policy_helper(args):
 method="SetRule" if args and args[0]=="set-rule" else "SetThreatException" if args and args[0]=="set-threat-exception" else "RemoveRule"
 if method in {"SetRule", "SetThreatException"}:
  payload={"application":args[args.index("--path")+1],"action":args[args.index("--action")+1],"duration":args[args.index("--duration")+1]}
  destination={}
  for key,field in (("--host","host"),("--ip","ip"),("--port","port")):
   if key in args: destination[field]=int(args[args.index(key)+1]) if field=="port" else args[args.index(key)+1]
  if destination: payload["destination"]=destination
  value=json.dumps(payload,separators=(",",":"))
 else:
  value=args[args.index("--rule-id")+1]
 try:
  result=dbus.SystemBus().call_blocking("systems.mantis.greyward.OpenSnitchPolicy1","/systems/mantis/greyward/OpenSnitchPolicy1","systems.mantis.greyward.OpenSnitchPolicy1",method,"s",(value,),timeout=DBUS_CALL_TIMEOUT)
 except (dbus.DBusException,AttributeError,TypeError):
  return {"ok":False,"state":"UNAVAILABLE","detail":"The GREYWARD network policy service is unavailable."}
 try: return json.loads(str(result))
 except json.JSONDecodeError: return {"ok":False,"state":"REFUSED","detail":"The network policy service returned an invalid result."}
def _policy_rules():
 rules=[]
 for attempt in range(3):
  try:
   result=json.loads(str(dbus.SystemBus().call_blocking("systems.mantis.greyward.OpenSnitchPolicy1","/systems/mantis/greyward/OpenSnitchPolicy1","systems.mantis.greyward.OpenSnitchPolicy1","ListRules","",(),timeout=DBUS_CALL_TIMEOUT)))
   if result.get("ok") is True: rules=result.get("rules",[])
  except (dbus.DBusException,AttributeError,TypeError,json.JSONDecodeError): pass
  if attempt < 2: time.sleep(0.1)
 return rules
def _merge_policy_rules(value):
 rules=[item for item in value.get("rules",[]) if isinstance(item,dict) and item.get("source")!="GREYWARD"]
 policy_rules=_policy_rules()
 policy_ids={item.get("id") for item in policy_rules if isinstance(item,dict)}
 for rule_id in tuple(RECENT_POLICY_RULES):
  if rule_id in policy_ids: RECENT_POLICY_RULES.pop(rule_id,None)
 rules.extend(policy_rules)
 rules.extend(RECENT_POLICY_RULES.values())
 value["rules"]=rules[-128:]
 return value
def _recent_policy_rule(value,rule_id):
 destination=value["destination"]
 return {"id":rule_id,"name":f"GREYWARD {Path(value['application']).name}","action":"ALLOW" if value["action"]=="allow" else "DENY","duration":value["duration"].upper().replace(" ","_"),"scope":{"application":value["application"],"destination":destination if any(destination.values()) else None},"source":"GREYWARD","mutable":True,"enabled":True}
class UsbContext:
 def __init__(self): self.adapter=UsbGuardAdapter(); self.events=[]; self.blocked=set(); self.telemetry=user_store(); import_root_spool(self.telemetry)
 def devices(self):
  cached=getattr(self,"_device_cache",None)
  if cached and time.monotonic()-cached[0]<2: return cached[1]
  try: result=(self.adapter.list_devices(),None)
  except UsbGuardError as error: result=([],str(error))
  self._device_cache=(time.monotonic(),result)
  return result
 def device_overview(self,raw_devices=None,devices_error=None):
  raw,error=(self.devices() if raw_devices is None else (raw_devices,devices_error))
  if error: return {"source_state":"UNAVAILABLE","reason":error,"devices":[]}
  try: previous={item.get("identity_id"):item for item in self.telemetry.list_devices().get("devices",[]) if item.get("identity_id")}
  except (TelemetryError,OSError): previous={}
  observations=[]; current_ids=set(); uncertain=[]
  for item in raw:
   if not str(item.get("device_class") or "").startswith("EXTERNAL_"): continue
   identity,confidence=derive_device_identity(item.get("identity_metadata") or {})
   if not identity:
    uncertain.append({"identity_id":None,"identity_confidence":"LOW","name":item.get("name") or "External device","device_class":item.get("device_class") or "EXTERNAL_UNKNOWN","trusted":item.get("trusted",False),"reviewed":False,"connected":True,"state":item.get("state") or "UNKNOWN","first_seen":stamp(now()),"last_seen":stamp(now())})
    continue
   observed=stamp(now()); current_ids.add(identity)
   observation={"identity_id":identity,"identity_confidence":confidence,"name":item.get("name") or "External device","device_class":item.get("device_class") or "EXTERNAL_UNKNOWN","trusted":item.get("trusted",False),"state":item.get("state") or "UNKNOWN","observed_at":observed}
   observations.append(observation)
   old=previous.get(identity)
   if not old or not old.get("connected"):
    record_event(telemetry_event(event_id=f"device-{identity}-connected-{observed}",occurred_at=observed,component="greyward-usb",source="usbguard/dbus",category="DEVICES",event_type="DEVICE_CONNECTED",action="CONNECT",outcome="SUCCESS",severity="NOTICE",assessment="NOTEWORTHY" if not item.get("trusted") else "NORMAL",details={"device_class":observation["device_class"],"identity_confidence":confidence},quality={"source_state":"AVAILABLE","attribution":"EXACT","confidence":confidence.lower()},retention_class="semantic"),self.telemetry)
  try: result=self.telemetry.sync_devices(observations)
  except (TelemetryError,OSError): return {"source_state":"UNAVAILABLE","reason":"Device history is unavailable.","devices":[]}
  for old_id,old in previous.items():
   if old.get("connected") and old_id not in current_ids:
    observed=stamp(now())
    record_event(telemetry_event(event_id=f"device-{old_id}-disconnected-{observed}",occurred_at=observed,component="greyward-usb",source="usbguard/dbus",category="DEVICES",event_type="DEVICE_DISCONNECTED",action="DISCONNECT",outcome="SUCCESS",severity="INFO",assessment="NOTEWORTHY",details={"device_class":old.get("device_class")},quality={"source_state":"AVAILABLE","attribution":"EXACT","confidence":"EXACT"},retention_class="semantic"),self.telemetry)
  result["devices"] = uncertain + result.get("devices", [])
  return result
 def events_for(self,devices):
  active={item["device_id"] for item in devices if item["state"] in ("BLOCK","REJECT")}
  self.events=[event for event in self.events if event.get("kind") != "USB_DEVICE_BLOCKED" or event.get("event_id", "").removeprefix("usbguard-") in active]
  for item in devices:
   if item["device_id"] not in active or item["device_id"] in self.blocked: continue
   event_id="usbguard-"+item["device_id"]; self.events=[event for event in self.events if event["event_id"]!=event_id]
   self.events.append({"event_id":event_id,"kind":"USB_DEVICE_BLOCKED","notification":"ACTION_REQUIRED","occurred_at":stamp(now()),"title":"USB device blocked","detail":f"{item['name']} is blocked. Review it in Security Center.","source":"usbguard/dbus"})
  self.blocked=active
 def record_scan(self,value,file_ref=None,scan_context="FILE"):
  context=scan_context if scan_context in {"FILE","REMOVABLE_MEDIA","HIGH_RISK_PATH"} else "FILE"
  threat=value.get("state")=="THREAT"; detection=value.get("detection_name") or "Known threat"
  event={"event_id":"clamav-"+value["state"]+"-"+context+"-"+stamp(now()),"kind":"USB_SCAN_RESULT","notification":"HISTORY_ONLY","occurred_at":stamp(now()),"title":"Removable media threat detected" if context=="REMOVABLE_MEDIA" and threat else ("File threat detected" if threat else "File scan result"),"detail":value["detail"],"source":"clamav/fd-scan","state":value["state"],"scan_context":context}
  if file_ref: event["file_ref"]=file_ref
  self.events=(self.events+[event])[-64:]
 def summary(self):
  try: value=json.loads(STATE_PATH.read_text(encoding="utf-8"))
  except (OSError,json.JSONDecodeError): value=unavailable_summary()
  devices,error=self.devices(); blocked=[item for item in devices if item["state"] in ("BLOCK","REJECT")]; current=now()
  device_state=self.device_overview(raw_devices=devices,devices_error=error)
  if error: value["live_states"].append({"kind":"REVIEW NEEDED","state":"UNAVAILABLE","detail":"USBGuard state is unavailable.","observed_at":stamp(current)})
  elif blocked:
   value["state"]="REVIEW NEEDED"; value["review_count"]=int(value.get("review_count",0))+len(blocked); value["live_states"].append({"kind":"REVIEW NEEDED","state":"REVIEW NEEDED","detail":f"{len(blocked)} USB device(s) are blocked pending review.","observed_at":stamp(current)})
  if not error: self.events_for(devices)
  for event in value.get("recent_events",[]):
   if event.get("kind")=="USB_SCAN_RESULT" and not event.get("scan_context"):
    event["scan_context"]="REMOVABLE_MEDIA" if "removable" in str(event.get("title","")).lower() else "FILE"
    event["notification"]="HISTORY_ONLY"
  value["recent_events"]=(value.get("recent_events",[])+self.events)[-64:]; value["generated_at"]=stamp(current); value["fresh_until"]=stamp(current+dt.timedelta(minutes=2));
  if any(item.get("state") == "UNAVAILABLE" for item in value.get("live_states", [])): value["state"]="UNAVAILABLE"
  value["usb"]={"state":"UNAVAILABLE" if error else ("BLOCKED" if blocked else "CLEAR"),"blocked_count":len(blocked),"device_state":device_state}
  return value
class SensorContext:
 def __init__(self): self.active={}; self.events=[]; self.last_sensors=[]; self.last_screen_shares=[]; self.last_error="PipeWire monitor has not started."; self.last_observed=None; self.monitor=PipeWireMonitor()
 def start(self,callback): self.monitor.start(callback)
 def observe(self):
  activity,error,_observed=self.monitor.snapshot(); self.last_sensors=list(activity["sensors"]); self.last_screen_shares=list(activity["screen_shares"]); self.last_error=error; self.last_observed=now(); return self.last_sensors,self.last_error,self.last_observed
 def augment(self,value):
  sensors,error,current=self.observe(); next_active={(item["kind"],item.get("application") or ""):item for item in sensors}
  for key,item in next_active.items():
   if key in self.active: continue
   name=item["application"] or "An application"; label="microphone" if item["kind"]=="MICROPHONE" else "camera"
   self.events.append({"event_id":"sensor-start-"+item["kind"]+"-"+(item["application"] or "ambiguous")+"-"+stamp(current),"kind":item["kind"]+"_STARTED","notification":"ONGOING_STATE","occurred_at":stamp(current),"title":label.capitalize()+" in use","detail":name+" is using your "+label+"." if item["application"] else "An application is using your "+label+".","source":"pipewire/metadata"})
  for key,item in self.active.items():
   if key in next_active: continue
   label="microphone" if item["kind"]=="MICROPHONE" else "camera"
   self.events.append({"event_id":"sensor-stop-"+item["kind"]+"-"+(item.get("application") or "ambiguous")+"-"+stamp(current),"kind":item["kind"]+"_STOPPED","notification":"HISTORY_ONLY","occurred_at":stamp(current),"title":label.capitalize()+" no longer in use","detail":"Sensor use ended.","source":"pipewire/metadata"})
  self.active=next_active; self.events=self.events[-64:]
  if error: value["live_states"].append({"kind":"REVIEW NEEDED","state":"UNAVAILABLE","detail":"PipeWire sensor context is unavailable.","observed_at":stamp(current)})
  for item in sensors:
   label="microphone" if item["kind"]=="MICROPHONE" else "camera"; name=item["application"] or "An application"
   value["live_states"].append({"kind":item["kind"],"state":"ACTIVE","detail":name+" is using your "+label+"." if item["application"] else "An application is using your "+label+"; attribution="+item["attribution"]+".","observed_at":stamp(current)})
  if any(item.get("state") == "UNAVAILABLE" for item in value.get("live_states", [])): value["state"]="UNAVAILABLE"
  value["recent_events"]=(value.get("recent_events",[])+self.events)[-64:]
  return value

class PortalContext:
 def __init__(self,bus,callback):
  self.bus=bus; self.callback=callback; self.available=False
  bus.add_signal_receiver(self._owner_changed,signal_name="NameOwnerChanged",dbus_interface="org.freedesktop.DBus",arg0="org.freedesktop.portal.Desktop")
  bus.add_signal_receiver(self._session_closed,signal_name="Closed",dbus_interface="org.freedesktop.portal.Session",bus_name="org.freedesktop.portal.Desktop")
  self._refresh()
 def _refresh(self):
  try: available=bool(self.bus.name_has_owner("org.freedesktop.portal.Desktop"))
  except dbus.DBusException: available=False
  if available != self.available:
   self.available=available; self.callback()
 def _owner_changed(self,*_args): self._refresh()
 def _session_closed(self,*_args): self.callback()

class ClipboardObserver:
 def __init__(self,callback): self.callback=callback; self.process=None; self.thread=None; self.available=False; self._initial=True
 def start(self):
  if not os.environ.get("WAYLAND_DISPLAY") or shutil.which("wl-paste") is None: return False
  try:
   self.process=subprocess.Popen(["wl-paste","--type","text/plain","--watch",sys.executable,"-m","greyward_security_context.clipboard_watch"],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
  except (OSError,subprocess.SubprocessError): return False
  self.available=True; self.thread=threading.Thread(target=self._read,daemon=True); self.thread.start(); return True
 def _read(self):
  if self.process is None or self.process.stdout is None: return
  for line in self.process.stdout:
   try: value=json.loads(line)
   except (TypeError,json.JSONDecodeError): continue
   if self._initial: self._initial=False; continue
   self.callback(value.get("category") if isinstance(value,dict) else None)
 def stop(self):
  if self.process is not None and self.process.poll() is None: self.process.terminate()
  self.process=None

class SecurityContext(dbus.service.Object):
 def __init__(self,bus,usb,sensors,persistence=None):
  super().__init__(bus,OBJECT_PATH); self.usb=usb; self.sensors=sensors; self.persistence=persistence or PersistenceMonitor(); self.safe_open_processes={}; self.file_security=FileSecurityManager(); self.privacy_capsule=PrivacyCapsule(); self._capsule_lock=threading.Lock(); self._summary_cache=None; self._summary_cache_at=0.0; self._summary_cache_lock=threading.Lock(); self.clipboard_category=None; self.clipboard_observed_at=None; self._network_notification_seen=set(); self._network_notification_initialized=False; self._network_notification_deadlines={}; self.clipboard_observer=ClipboardObserver(lambda category: GLib.idle_add(self._on_clipboard_category,category)); self.portal=PortalContext(bus,lambda: GLib.idle_add(self._on_privacy_source_changed)); self.sensors.start(lambda: GLib.idle_add(self._on_privacy_source_changed)); self.clipboard_observer.start()

 def _invalidate_caches(self):
  if hasattr(self,"usb"): self.usb._device_cache=None
  with self._summary_cache_lock:
   self._summary_cache=None; self._summary_cache_at=0.0
  _invalidate_shared_caches()

 def _on_clipboard_category(self,category):
  self.clipboard_category=str(category)[:48] if category else None; self.clipboard_observed_at=now(); self.refresh_privacy_capsule(); return False

 def poll_network_threats(self):
  try: events=network_summary().get("activity",[])
  except Exception: return True
  threat_events=[item for item in events if isinstance(item,dict) and item.get("decision")=="BLOCKED" and isinstance(item.get("threat"),dict)]
  if not self._network_notification_initialized:
   self._network_notification_seen={str(item.get("event_id")) for item in threat_events if item.get("event_id")}; self._network_notification_initialized=True; return True
  current=time.monotonic()
  for event in reversed(threat_events):
   event_id=str(event.get("event_id") or "")
   if not event_id or event_id in self._network_notification_seen: continue
   self._network_notification_seen.add(event_id); threat=event.get("threat") or {}; destination=event.get("destination") or {}
   key="|".join((str(event.get("application") or ""),str(threat.get("ip") or destination.get("ip") or ""),str(threat.get("port") or destination.get("port") or "")))
   if current < self._network_notification_deadlines.get(key,0.0): continue
   if notify_network_threat(event): self._network_notification_deadlines[key]=current+300
  if len(self._network_notification_seen)>256: self._network_notification_seen=set(list(self._network_notification_seen)[-128:])
  self._network_notification_deadlines={key:value for key,value in self._network_notification_deadlines.items() if value>current-300}
  return True

 def _on_privacy_source_changed(self):
  self.refresh_privacy_capsule()
  if hasattr(self,"shell_runtime"): self.shell_runtime.invalidate()
  return False

 def _capsule_signal(self,signal_id,category,capability,state,title,detail=None,application=None,device=None,actions=None,reason=None,fresh_seconds=30):
  current=now(); value={"signal_id":signal_id,"category":category,"capability":capability,"state":state,"title":title,"observed_at":stamp(current),"fresh_until":stamp(current+dt.timedelta(seconds=fresh_seconds))}
  if detail: value["detail"]=str(detail)[:240]
  if application: value["application"]=str(application)[:80]
  if device: value["device"]=str(device)[:120]
  if actions: value["actions"]=list(actions)[:2]
  if reason: value["reason"]=str(reason)[:160]
  return value

 def _capsule_fixture_inputs(self):
  """Read an explicit development-only capsule fixture, when configured.

  The fixture is deliberately opt-in through the user service environment and
  is intended for visual QA only.  It never becomes a production provider and
  remains outside telemetry, SQLite, and the normal capsule sources.
  """
  fixture_path=os.environ.get("GREYWARD_PRIVACY_CAPSULE_FIXTURE")
  if not fixture_path: return None
  try: value=json.loads(Path(fixture_path).read_text(encoding="utf-8"))
  except (OSError,json.JSONDecodeError): return ([],now())
  if not isinstance(value,dict) or not isinstance(value.get("signals"),list): return ([],now())
  signals=[]
  for item in value["signals"][:16]:
   if not isinstance(item,dict): continue
   try: fresh_seconds=int(item.get("fresh_seconds",30))
   except (TypeError,ValueError): fresh_seconds=30
   signals.append(self._capsule_signal(
    str(item.get("signal_id") or "fixture")[:96],
    str(item.get("category") or "ACTIVE_SENSOR")[:64],
    str(item.get("capability") or "SUPPORTED")[:32],
    str(item.get("state") or "INACTIVE")[:32],
    str(item.get("title") or "Privacy activity")[:120],
    detail=item.get("detail"), application=item.get("application"),
    device=item.get("device"), actions=item.get("actions"),
    reason=item.get("reason"), fresh_seconds=fresh_seconds))
  return signals,now()

 def _capsule_inputs(self):
  fixture=self._capsule_fixture_inputs()
  if fixture is not None: return fixture
  current=now(); signals=[]
  sensor_error=self.sensors.last_error
  observed=self.sensors.last_sensors
  for kind,label in (("MICROPHONE","Microphone"),("CAMERA","Camera")):
   items=[item for item in observed if item.get("kind")==kind]
   if sensor_error:
    signals.append(self._capsule_signal(kind.lower(),"ACTIVE_SENSOR","SUPPORTED","UNAVAILABLE",f"{label} activity unavailable",detail="PipeWire sensor context is unavailable.",reason=str(sensor_error)))
   elif not items:
    signals.append(self._capsule_signal(kind.lower(),"ACTIVE_SENSOR","SUPPORTED","INACTIVE",f"{label} inactive"))
   else:
    for item in items[:8]:
     app=item.get("application") or "Unknown application"; identity=f"{kind.lower()}:{item.get('application') or 'ambiguous'}"
     signals.append(self._capsule_signal(identity,"ACTIVE_SENSOR","SUPPORTED","ACTIVE",f"{label} in use",detail=f"{app} is using your {label.lower()}.",application=item.get("application"),actions=["open_privacy"]))

  shares=self.sensors.last_screen_shares
  if sensor_error:
   signals.append(self._capsule_signal("screen-share","SCREEN_SHARE","SUPPORTED","UNAVAILABLE","Screen sharing activity unavailable",reason=str(sensor_error)))
  elif not self.portal.available:
   signals.append(self._capsule_signal("screen-share","SCREEN_SHARE","SUPPORTED","UNAVAILABLE","Screen sharing portal unavailable",reason="PORTAL_OWNER_UNAVAILABLE"))
  elif not shares:
   signals.append(self._capsule_signal("screen-share","SCREEN_SHARE","SUPPORTED","INACTIVE","Screen sharing inactive"))
  else:
   for item in shares[:8]:
    application=item.get("application") or "Unknown application"
    identity="screen-share:"+(item.get("application") or "ambiguous")
    signals.append(self._capsule_signal(identity,"SCREEN_SHARE","SUPPORTED","ACTIVE","Screen sharing active",detail=f"{application} is sharing a screen.",application=item.get("application"),actions=["open_privacy"]))
  if self.clipboard_observer.available:
   if self.clipboard_category:
    signals.append(self._capsule_signal("clipboard","SENSITIVE_DATA","SUPPORTED","ACTIVE","Sensitive clipboard detected",detail=f"Category: {self.clipboard_category}.",actions=["clear_clipboard","open_privacy"],fresh_seconds=30))
   else:
    signals.append(self._capsule_signal("clipboard","SENSITIVE_DATA","SUPPORTED","INACTIVE","Sensitive clipboard inactive"))
  else:
   signals.append(self._capsule_signal("clipboard","SENSITIVE_DATA","DEFERRED","DEFERRED","Sensitive clipboard unavailable",reason="REQUIRES_TEXT_ONLY_CLIPBOARD_OBSERVER"))

  try: devices,device_error=self.usb.devices()
  except Exception as error: devices,device_error=[],str(error)
  if device_error:
   signals.append(self._capsule_signal("usb","USB_DEVICE","SUPPORTED","UNAVAILABLE","USB activity unavailable",reason=str(device_error)))
  else:
   external=[item for item in devices if str(item.get("device_class") or "").startswith("EXTERNAL_")]
   if not external: signals.append(self._capsule_signal("usb","USB_DEVICE","SUPPORTED","INACTIVE","No new USB device"))
   for item in external[:8]:
    device_id=str(item.get("device_id") or item.get("name") or "external")[:80]
    state="ACTIVE" if str(item.get("state") or "").upper() in {"BLOCK","REJECT"} else "INFO"
    signals.append(self._capsule_signal(f"usb:{device_id}","USB_DEVICE","SUPPORTED",state,"USB device connected",detail=str(item.get("name") or "External device")[:160],device=item.get("name"),actions=["open_devices"]))

  dns=secure_dns_state(); desired=str(dns.get("desired_policy") or "Automatic"); effective=str(dns.get("effective_policy") or "Unavailable"); reason=dns.get("degradation_reason")
  strict=desired in {"Privacy","Strict","Custom"}; degraded=effective in {"Unavailable","Disconnected"} or (strict and effective in {"CompatibilityFallback","NetworkDefault"})
  if degraded:
   signals.append(self._capsule_signal("secure-dns","DEGRADED_PROTECTION","SUPPORTED","DEGRADED","Secure DNS degraded",detail=f"Effective state: {effective}.",reason=reason or "Protection policy is degraded.",actions=["open_network"]))
  else:
   signals.append(self._capsule_signal("secure-dns","DEGRADED_PROTECTION","SUPPORTED","INACTIVE","Secure DNS operating"))

  # OpenSnitch currently exposes activity but not application RX/TX counters.
  # Do not turn connection counts into a throughput claim.
  signals.append(self._capsule_signal("network-load","UNUSUAL_ACTIVITY","DEFERRED","DEFERRED","Network load unavailable",reason="REQUIRES_DEDICATED_NETWORK_ACCOUNTING"))
  return signals, current

 def refresh_privacy_capsule(self):
  try:
   self.sensors.observe()
   signals,current=self._capsule_inputs()
   with self._capsule_lock:
    changed=self.privacy_capsule.update(signals,current)
   if changed: self.PrivacyCapsuleChanged(self.privacy_capsule.revision)
  except Exception:
   # A failed optional source must not take down the existing user-bus API.
   return True
  return True

 def _user_home(self):
  if getpwuid is None: raise PermissionError("The requesting user's home is unavailable.")
  try: return Path(getpwuid(os.getuid()).pw_dir).resolve()
  except (KeyError,OSError) as error: raise PermissionError("The requesting user's home is unavailable.") from error

 def _remove_quarantine_source(self,pending):
   uid=os.getuid(); source=Path(str(pending.get("source_path") or "")); expected=str(pending.get("file_hash") or "")
   if not source.is_absolute() or not source.is_file(): raise ValueError("The detected source is no longer a regular file.")
   try:
    resolved=source.resolve(strict=True)
   except (OSError,RuntimeError) as error:
    raise ValueError("The detected source is no longer a regular file.") from error
   if resolved != source or source.is_symlink(): raise ValueError("Symlinks are not valid quarantine sources.")
   _unlink_verified_source(source, expected or None, uid)

 def _open_restore_parent(self, destination, uid):
  """Open the user-home destination parent without following aliases."""
  home=self._user_home()
  try:
   resolved=destination.resolve(strict=False)
   resolved.relative_to(home)
   relative=destination.relative_to(home)
  except (OSError,RuntimeError,ValueError) as error:
   raise PermissionError("Restore destinations must be inside the requesting user's home.") from error
  parts=relative.parts
  if len(parts)<1 or any(part in {".",".."} for part in parts):
   raise PermissionError("Restore destinations must be inside the requesting user's home.")
  nofollow=getattr(os,"O_NOFOLLOW",0); directory=getattr(os,"O_DIRECTORY",0)
  if not nofollow or not directory or os.open not in getattr(os,"supports_dir_fd",set()):
   raise OSError("The platform cannot safely create a restore destination.")
  flags=os.O_RDONLY|directory|nofollow
  parent_fd=os.open(str(home),flags)
  try:
   if os.fstat(parent_fd).st_uid != uid:
    raise PermissionError("The requesting user's home is not owned by that user.")
   for part in parts[:-1]:
    try:
     child_fd=os.open(part,flags,dir_fd=parent_fd)
    except FileNotFoundError:
     os.mkdir(part,0o700,dir_fd=parent_fd)
     child_fd=os.open(part,flags,dir_fd=parent_fd)
    metadata=os.fstat(child_fd)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid:
     os.close(child_fd)
     raise PermissionError("The restore destination contains an unsafe directory.")
    os.close(parent_fd)
    parent_fd=child_fd
   return parent_fd,parts[-1]
  except BaseException:
   try: os.close(parent_fd)
   except OSError: pass
   raise

 @staticmethod
 def _create_restore_temp(parent_fd):
  flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0)
  for _ in range(8):
   name=".greyward-restore-"+uuid.uuid4().hex
   try: return os.open(name,flags,0o600,dir_fd=parent_fd),name
   except FileExistsError: continue
  raise FileExistsError("A temporary restore destination could not be allocated.")

 def _create_restore_copy(self,pending):
  uid=os.getuid(); transfer=Path(str(pending.get("transfer_path") or "")); destination=Path(str(pending.get("destination") or "")); expected=str(pending.get("file_hash") or "")
  transfer_root=Path("/run/greyward-file-security") / str(uid)
  if not transfer.is_file() or transfer.is_symlink() or transfer.parent != transfer_root: raise ValueError("The prepared restore object is unavailable.")
  parent_fd,final_name=self._open_restore_parent(destination,uid)
  source_fd=-1; descriptor=-1; temporary=None
  try:
   source_fd=_open_readonly_nofollow(transfer)
   source_metadata=os.fstat(source_fd)
   if not stat.S_ISREG(source_metadata.st_mode) or source_metadata.st_uid != uid:
    raise PermissionError("The prepared restore object is unavailable.")
   descriptor,temporary=self._create_restore_temp(parent_fd)
   digest=hashlib.sha256()
   with os.fdopen(descriptor,"wb") as output, os.fdopen(source_fd,"rb") as source:
    descriptor=-1; source_fd=-1
    for chunk in iter(lambda: source.read(1024*1024),b""): output.write(chunk); digest.update(chunk)
    output.flush(); os.fsync(output.fileno())
   if expected and digest.hexdigest()!=expected: raise ValueError("The staged restore object changed during copy.")
   os.link(temporary,final_name,src_dir_fd=parent_fd,dst_dir_fd=parent_fd,follow_symlinks=False)
   os.unlink(temporary,dir_fd=parent_fd)
   temporary=None
   metadata=os.stat(final_name,dir_fd=parent_fd,follow_symlinks=False)
   if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != uid:
    raise PermissionError("The restored file could not be assigned to the requesting user.")
   return str(destination)
  finally:
   if source_fd>=0:
    try: os.close(source_fd)
    except OSError: pass
   if descriptor>=0:
    try: os.close(descriptor)
    except OSError: pass
   if temporary:
    try: os.unlink(temporary,dir_fd=parent_fd)
    except FileNotFoundError: pass
   try: os.close(parent_fd)
   except OSError: pass

 def _merge_file_activity(self,value):
  activity=list(value.get("activity") or []) if isinstance(value,dict) else []
  try:
   own=user_store().query({"category":"FILE_SECURITY","limit":128})
   activity.extend(file_activity_items(own.get("events",[]),128))
  except (OSError,TelemetryError,TypeError,ValueError): pass
  unique={str(item.get("event_id")):item for item in activity if isinstance(item,dict) and item.get("event_id")}
  value["activity"]=sorted(unique.values(),key=lambda item:(str(item.get("occurred_at") or ""),str(item.get("event_id") or "")),reverse=True)[:128]
  return value
 def augment_persistence(self,value):
  import hashlib
  self.persistence.scan()
  for change in self.persistence.recent_changes():
   fingerprint=change["category"]+"|"+change["id"]+"|"+change["change"]+"|"+str(change['observed_at'])
   value.setdefault("recent_events",[]).append({"event_id":"persistence-"+hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:24],"kind":"PERSISTENCE_CHANGE_DETECTED","notification":"ACTION_REQUIRED","occurred_at":stamp(now()),"title":change["title"],"detail":change["detail"],"source":"user-startup-surfaces","category":change["category"]})
  value["recent_events"] = value.get("recent_events",[])[-64:]
  return value
 @dbus.service.method(BUS_NAME,in_signature="",out_signature="s")
 def GetSummary(self):
  with self._summary_cache_lock:
   current=time.monotonic()
   if self._summary_cache and current-self._summary_cache_at < SUMMARY_CACHE_SECONDS:
    return self._summary_cache
   value=apply_authoritative_posture(self.augment_persistence(self.sensors.augment(self.usb.summary())))
   try: value["clamav"]=clamav_status()
   except Exception as error: value["clamav"]={"engine_version":None,"database_timestamp":None,"database_age_seconds":None,"last_successful_update":None,"update_failure_state":str(error)[:240],"database_version":None,"status":"UNAVAILABLE"}
   encoded=json.dumps(value,sort_keys=True,separators=(",",":")); runtime=Path(os.environ.get("XDG_RUNTIME_DIR","/tmp")); (runtime/"greyward-security-context-summary.json").write_text(encoded,encoding="utf-8"); self._summary_cache=encoded; self._summary_cache_at=current; return encoded
 @dbus.service.method(BUS_NAME,in_signature="",out_signature="s")
 def GetShellSummary(self):
  try:
   try: summary=json.loads(self.GetSummary())
   except (TypeError,json.JSONDecodeError): summary=unavailable_summary()
   summary_observed_at=now()
   try: network=network_summary()
   except Exception: network=unavailable_network_summary()
   clamav=summary.get("clamav") if isinstance(summary,dict) else None
   profile=_profile_call("--read")
   store=user_store(); import_root_spool(store)
   digest=build_security_digest(summary,network=network,device_state=summary.get("usb",{}).get("device_state") if isinstance(summary,dict) else None,store=store,now_value=summary_observed_at)
   try: dns=secure_dns_state()
   except Exception: dns={}
   value=build_shell_summary(summary,network,clamav,profile,_update_transaction(),now_value=summary_observed_at,security_digest=digest,secure_dns=dns)
  except Exception:
   # Keep the shell contract callable when an optional provider, state file,
   # or bounded history store is unavailable. The returned projection is
   # explicitly unavailable instead of turning the D-Bus call into a
   # transient transport failure.
   value=build_shell_summary(unavailable_summary(),unavailable_network_summary(),{"status":"UNAVAILABLE"},{"available":False,"profile":None},{},now_value=now(),secure_dns={})
  encoded=json.dumps(value,sort_keys=True,separators=(",",":"))
  _write_shell_summary_cache(encoded)
  return encoded
 @dbus.service.signal(BUS_NAME,signature="t")
 def ShellSummaryChanged(self,revision): pass
 @dbus.service.method(BUS_NAME,in_signature="",out_signature="s")
 def GetShellPresentation(self):
  return json.dumps(self.shell_runtime.read(),sort_keys=True,separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="ss",out_signature="s")
 def RequestUsbTrust(self,connection_ref,mode):
  return json.dumps(self.shell_runtime.trust(str(connection_ref),str(mode)),separators=(",",":"))
 def start_shell_runtime(self,bus):
  from greyward_security_context.shell_runtime import ShellRuntime
  self.shell_runtime=ShellRuntime(self,bus)
 @dbus.service.signal(BUS_NAME,signature="t")
 def PrivacyCapsuleChanged(self,revision): pass
 @dbus.service.method(BUS_NAME,in_signature="",out_signature="s")
 def GetPrivacyCapsule(self):
  self.refresh_privacy_capsule()
  with self._capsule_lock:
   return json.dumps(self.privacy_capsule.snapshot(),sort_keys=True,separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="s",out_signature="s")
 def ClearClipboard(self,event_id):
  with self._capsule_lock: snapshot=self.privacy_capsule.snapshot()
  current=next((item for item in snapshot.get("signals",[]) if item.get("signal_id")=="clipboard" and item.get("state")=="ACTIVE"),None)
  if current is None or (event_id and str(event_id)!=str(current.get("event_id"))):
   return json.dumps({"ok":False,"state":"STALE","detail":"The sensitive clipboard event is no longer current."},separators=(",",":"))
  if shutil.which("wl-copy") is None:
   return json.dumps({"ok":False,"state":"UNAVAILABLE","detail":"The Wayland clipboard action is unavailable."},separators=(",",":"))
  try: result=subprocess.run(["wl-copy","--clear"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=4,check=False)
  except (OSError,subprocess.SubprocessError): result=None
  if result is None or result.returncode != 0:
   return json.dumps({"ok":False,"state":"FAILED","detail":"The clipboard could not be cleared."},separators=(",",":"))
  self.clipboard_category=None; self.clipboard_observed_at=now(); self.refresh_privacy_capsule()
  return json.dumps({"ok":True,"state":"CLEARED","detail":"Clipboard cleared."},separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="",out_signature="s")
 def GetClamAvStatus(self):
  try: value=clamav_status()
  except Exception as error: value={"engine_version":None,"database_timestamp":None,"database_age_seconds":None,"last_successful_update":None,"update_failure_state":str(error)[:240],"database_version":None,"status":"UNAVAILABLE"}
  return json.dumps(value,sort_keys=True,separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="",out_signature="s")
 def GetWeeklySummary(self):
  value=self.augment_persistence(self.sensors.augment(self.usb.summary()))
  return json.dumps(weekly_summary(value.get("recent_events",[])),sort_keys=True,separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="",out_signature="s")
 def Refresh(self):
  self._invalidate_caches()
  return self.GetSummary()
 @dbus.service.method(BUS_NAME,in_signature="",out_signature="s")
 def GetNetworkProtection(self):
  value=network_summary(); value["secure_dns"]=secure_dns_state(); return json.dumps(value,sort_keys=True,separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="",out_signature="s")
 def GetThreatProtection(self):
  value=network_summary()
  threat=value.get("threat_intel") if isinstance(value,dict) else None
  if not isinstance(threat,dict): threat={"enabled":False,"provider":"feodo-recommended","state":"ERROR","indicator_count":0,"recent_blocked_connections":[],"exceptions":[]}
  return json.dumps(threat,sort_keys=True,separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="s",out_signature="s")
 def SetThreatProtectionEnabled(self,payload):
  try: enabled=json.loads(payload)
  except (TypeError,json.JSONDecodeError): return json.dumps({"ok":False,"state":"INVALID","detail":"Threat protection enablement must be boolean."},separators=(",",":"))
  if not isinstance(enabled,bool): return json.dumps({"ok":False,"state":"INVALID","detail":"Threat protection enablement must be boolean."},separators=(",",":"))
  try:
   result=dbus.SystemBus().call_blocking("systems.mantis.greyward.OpenSnitchPolicy1","/systems/mantis/greyward/OpenSnitchPolicy1","systems.mantis.greyward.OpenSnitchPolicy1","SetThreatIntelEnabled","s",(json.dumps(enabled),),timeout=DBUS_CALL_TIMEOUT)
   value=json.loads(str(result))
  except (dbus.DBusException,AttributeError,TypeError,json.JSONDecodeError):
   value={"ok":False,"state":"UNAVAILABLE","detail":"The GREYWARD threat policy service is unavailable."}
  if value.get("ok") is True: self._invalidate_caches()
  return json.dumps(value,sort_keys=True,separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="tu",out_signature="s")
 def GetNetworkActivity(self,since_sequence,limit):
  return json.dumps(network_activity(since_sequence,limit),sort_keys=True,separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="s",out_signature="s")
 def GetSecurityCenterDigest(self,payload):
  try: options=json.loads(payload) if isinstance(payload,str) and payload else {}
  except json.JSONDecodeError: options={}
  summary=json.loads(self.GetSummary()); network=network_summary(); devices=self.usb.device_overview()
  store=user_store(); import_root_spool(store)
  return json.dumps(build_security_digest(summary,network=network,device_state=devices,store=store,now_value=now()),sort_keys=True,separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="s",out_signature="s")
 def GetNetworkHistory(self,payload):
  try:
   filters=json.loads(payload) if isinstance(payload,str) else payload
   if not isinstance(filters,dict): raise TelemetryError("Network history query must be an object.")
   filters.update({"category":"NETWORK","limit":min(int(filters.get("limit",128)),256)})
   store=user_store(); import_root_spool(store)
   result=store.query(filters)
   result["events"]=[_with_network_location(event) for event in result.get("events",[]) if isinstance(event,dict)]
   return json.dumps(result,sort_keys=True,separators=(",",":"))
  except (TelemetryError,TypeError,ValueError,json.JSONDecodeError) as error:
   return json.dumps({"schema":QUERY_SCHEMA,"events":[],"truncated":False,"source_state":{"state":"UNAVAILABLE","reason":str(error)[:160]}},separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="",out_signature="s")
 def GetDeviceOverview(self):
  state=self.usb.device_overview()
  store=user_store(); import_root_spool(store)
  digest=build_security_digest(device_state=state,store=store,now_value=now())
  state["summary"]=digest.get("devices",{})
  return json.dumps(state,sort_keys=True,separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="s",out_signature="s")
 def GetCapabilityHistory(self,payload):
  try:
   filters=json.loads(payload) if isinstance(payload,str) else payload
   if not isinstance(filters,dict): raise TelemetryError("Capability history query must be an object.")
   filters["limit"]=min(int(filters.get("limit",64)),128)
   if filters.get("capability"):
    filters["component"]=str(filters.pop("capability"))[:96]
   store=user_store(); import_root_spool(store); return json.dumps(store.query(filters),sort_keys=True,separators=(",",":"))
  except (TelemetryError,TypeError,ValueError,json.JSONDecodeError) as error:
   return json.dumps({"schema":QUERY_SCHEMA,"events":[],"truncated":False,"source_state":{"state":"UNAVAILABLE","reason":str(error)[:160]}},separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="s",out_signature="s")
 def QueryTelemetry(self,payload):
  return json.dumps(telemetry_query(payload),sort_keys=True,separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="s",out_signature="s")
 def GetRelatedTelemetry(self,payload):
  return json.dumps(telemetry_related(payload),sort_keys=True,separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="s",out_signature="s")
 def StartScan(self,payload):
  try:
   request=json.loads(payload) if isinstance(payload,str) else payload
   if not isinstance(request,dict): raise ValueError("Scan request must be an object.")
   mode=str(request.get("mode") or "").upper()
   proxy=dbus.Interface(dbus.SystemBus().get_object("systems.mantis.greyward.ClamAvScan1","/systems/mantis/greyward/ClamAvScan1"),"systems.mantis.greyward.ClamAvScan1")
   return proxy.StartScan(json.dumps(request,separators=(",",":")),timeout=FILE_SECURITY_DBUS_TIMEOUT)
  except (ValueError,TypeError,json.JSONDecodeError,PermissionError,RuntimeError,dbus.DBusException,TelemetryError) as error:
   return json.dumps({"state":"FAILED","detail":str(error)[:320]},separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="s",out_signature="s")
 def GetScanStatus(self,operation_id):
  value=None
  try:
   proxy=dbus.Interface(dbus.SystemBus().get_object("systems.mantis.greyward.ClamAvScan1","/systems/mantis/greyward/ClamAvScan1"),"systems.mantis.greyward.ClamAvScan1")
   return proxy.GetScanStatus(operation_id,timeout=FILE_SECURITY_DBUS_TIMEOUT)
  except dbus.DBusException: value=self.file_security.status(operation_id)
  return json.dumps(value or {"state":"UNAVAILABLE","detail":"Scan history is unavailable."},sort_keys=True,separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="s",out_signature="s")
 def CancelScan(self,operation_id):
  value=None
  try:
   proxy=dbus.Interface(dbus.SystemBus().get_object("systems.mantis.greyward.ClamAvScan1","/systems/mantis/greyward/ClamAvScan1"),"systems.mantis.greyward.ClamAvScan1")
   return proxy.CancelScan(operation_id,timeout=FILE_SECURITY_DBUS_TIMEOUT)
  except dbus.DBusException: value=self.file_security.cancel(operation_id)
  return json.dumps(value or {"state":"UNAVAILABLE","detail":"Scan cancellation is unavailable."},sort_keys=True,separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="s",out_signature="s")
 def ListFileDetections(self,payload):
  try:
   request=json.loads(payload) if isinstance(payload,str) and payload else {}
   if not isinstance(request,dict): raise ValueError("Detection query must be an object.")
   try:
    proxy=dbus.Interface(dbus.SystemBus().get_object("systems.mantis.greyward.ClamAvScan1","/systems/mantis/greyward/ClamAvScan1"),"systems.mantis.greyward.ClamAvScan1")
    return proxy.ListFileDetections(json.dumps(request,separators=(",",":")),timeout=FILE_SECURITY_DBUS_TIMEOUT)
   except dbus.DBusException:
    pass
   return json.dumps({"schema":"greyward.file-security.detections/v1","state":"AVAILABLE","detections":self.file_security.detections(state=request.get("state"),limit=request.get("limit",128))},sort_keys=True,separators=(",",":"))
  except (ValueError,TypeError,json.JSONDecodeError,TelemetryError) as error:
   return json.dumps({"schema":"greyward.file-security.detections/v1","state":"UNAVAILABLE","detections":[],"detail":str(error)[:240]},separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="",out_signature="s")
 def GetFileSecuritySummary(self):
  try:
   try:
    proxy=dbus.Interface(dbus.SystemBus().get_object("systems.mantis.greyward.ClamAvScan1","/systems/mantis/greyward/ClamAvScan1"),"systems.mantis.greyward.ClamAvScan1")
    value=json.loads(str(proxy.GetFileSecuritySummary(timeout=FILE_SECURITY_DBUS_TIMEOUT)))
    return json.dumps(self._merge_file_activity(value),sort_keys=True,separators=(",",":"))
   except dbus.DBusException:
    pass
   scans=self.file_security.reconcile_interrupted_scans(32)
   detections=self.file_security.detections(limit=128)
   active=next((item for item in scans if item.get("state") in {"QUEUED","SCANNING","FINALIZING"}),None)
   return json.dumps(self._merge_file_activity({"schema":"greyward.file-security/v1","state":"UNAVAILABLE","active_scan":None,"latest_scan":scans[0] if scans else None,"detections":detections,"clamav":clamav_status()}),sort_keys=True,separators=(",",":"))
  except (TelemetryError,OSError,TypeError,ValueError,json.JSONDecodeError) as error:
   return json.dumps({"schema":"greyward.file-security/v1","state":"UNAVAILABLE","active_scan":None,"latest_scan":None,"detections":[],"detail":str(error)[:240]},separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="s",out_signature="s")
 def QuarantineDetection(self,detection_id):
  try:
   proxy=dbus.Interface(dbus.SystemBus().get_object("systems.mantis.greyward.ClamAvScan1","/systems/mantis/greyward/ClamAvScan1"),"systems.mantis.greyward.ClamAvScan1")
   pending=json.loads(str(proxy.QuarantineDetection(detection_id,timeout=FILE_SECURITY_DBUS_TIMEOUT)))
   if pending.get("state")!="QUARANTINE_PENDING": return json.dumps(pending,separators=(",",":"))
   try:
    self._remove_quarantine_source(pending)
   except (OSError,ValueError,PermissionError) as error:
    return proxy.FailQuarantine(detection_id,str(error)[:320],timeout=FILE_SECURITY_DBUS_TIMEOUT)
   return proxy.CompleteQuarantine(detection_id,timeout=FILE_SECURITY_DBUS_TIMEOUT)
  except (OSError,ValueError,PermissionError,TelemetryError,dbus.DBusException,TypeError,json.JSONDecodeError) as error:
   return json.dumps({"state":"QUARANTINE_FAILED","detail":str(error)[:320]},separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="s",out_signature="s")
 def RestoreDetection(self,payload):
  try:
   request=json.loads(payload) if isinstance(payload,str) else payload
   if not isinstance(request,dict) or not request.get("detection_id"): raise ValueError("A detection ID is required.")
   proxy=dbus.Interface(dbus.SystemBus().get_object("systems.mantis.greyward.ClamAvScan1","/systems/mantis/greyward/ClamAvScan1"),"systems.mantis.greyward.ClamAvScan1")
   detection_id=str(request["detection_id"]); pending=json.loads(str(proxy.RestoreDetection(detection_id,str(request.get("destination") or ""),timeout=FILE_SECURITY_DBUS_TIMEOUT)))
   if pending.get("state")!="RESTORE_PENDING": return json.dumps(pending,separators=(",",":"))
   try:
    destination=self._create_restore_copy(pending)
   except (OSError,ValueError,PermissionError) as error:
    return proxy.FailRestore(detection_id,str(error)[:320],timeout=FILE_SECURITY_DBUS_TIMEOUT)
   return proxy.CompleteRestore(detection_id,destination,timeout=FILE_SECURITY_DBUS_TIMEOUT)
  except (OSError,ValueError,TypeError,json.JSONDecodeError,PermissionError,TelemetryError,dbus.DBusException) as error:
   return json.dumps({"state":"RESTORE_FAILED","detail":str(error)[:320]},separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="s",out_signature="s")
 def DeleteDetection(self,detection_id):
  try:
   proxy=dbus.Interface(dbus.SystemBus().get_object("systems.mantis.greyward.ClamAvScan1","/systems/mantis/greyward/ClamAvScan1"),"systems.mantis.greyward.ClamAvScan1")
   return proxy.DeleteDetection(detection_id,timeout=FILE_SECURITY_DBUS_TIMEOUT)
  except (OSError,ValueError,PermissionError,TelemetryError,dbus.DBusException) as error:
   return json.dumps({"state":"DELETE_FAILED","detail":str(error)[:320]},separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="",out_signature="s")
 def GetSecureDnsState(self): return json.dumps(secure_dns_state(),sort_keys=True,separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="s",out_signature="s")
 def SetSecureDnsMode(self,mode): return json.dumps(_secure_dns_call("SetMode",mode) or {"ok":False,"state":"UNAVAILABLE","detail":"Secure DNS policy service is unavailable."},sort_keys=True,separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="s",out_signature="s")
 def SetSecureDnsProvider(self,provider): return json.dumps(_secure_dns_call("SetProvider",provider) or {"ok":False,"state":"UNAVAILABLE","detail":"Secure DNS policy service is unavailable."},sort_keys=True,separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="",out_signature="s")
 def RetrySecureDns(self): return json.dumps(_secure_dns_call("RetrySecureDns") or {"ok":False,"state":"UNAVAILABLE","detail":"Secure DNS policy service is unavailable."},sort_keys=True,separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="s",out_signature="s")
 def SetPrivacyProfile(self,profile):
  target=str(profile or "").strip().upper()
  if target not in {"STANDARD","PRIVATE","TRAVEL"}:
   return json.dumps({"ok":False,"state":"INVALID","profile":None,"detail":"Only Standard, Private, or Travel profiles are supported."},separators=(",",":"))
  value=_profile_call("--set",target)
  if value.get("ok") is True and str(value.get("profile") or "").upper()==target: self._invalidate_caches()
  return json.dumps(value,sort_keys=True,separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="s",out_signature="s")
 def NetworkSetRule(self,payload):
  try: value=_validated_network_rule(json.loads(payload))
  except (TypeError,ValueError,json.JSONDecodeError) as error: return json.dumps({"ok":False,"state":"INVALID","detail":str(error)[:240]},separators=(",",":"))
  args=["set-rule","--path",value["application"],"--action",value["action"],"--duration",value["duration"]]
  destination=value["destination"]
  if destination["host"]: args.extend(["--host",destination["host"]])
  if destination["ip"]: args.extend(["--ip",destination["ip"]])
  if destination["port"]: args.extend(["--port",str(destination["port"])])
  result=_policy_helper(args)
  if result.get("ok") is True and result.get("rule_id"):
   RECENT_POLICY_RULES[result["rule_id"]]=_recent_policy_rule(value,result["rule_id"])
   self._invalidate_caches()
  return json.dumps(result,separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="s",out_signature="s")
 def NetworkSetThreatException(self,payload):
  try: value=_validated_network_rule(json.loads(payload))
  except (TypeError,ValueError,json.JSONDecodeError) as error: return json.dumps({"ok":False,"state":"INVALID","detail":str(error)[:240]},separators=(",",":"))
  destination=value["destination"]
  if value["action"] != "allow" or value["duration"] != "always" or destination["host"] or not destination["ip"] or not destination["port"]:
   return json.dumps({"ok":False,"state":"INVALID","detail":"A Feodo exception requires exact application, IP, and port scope."},separators=(",",":"))
  args=["set-threat-exception","--path",value["application"],"--action","allow","--duration","always","--ip",destination["ip"],"--port",str(destination["port"])]
  result=_policy_helper(args)
  if result.get("ok") is True and result.get("rule_id"):
   RECENT_POLICY_RULES.pop(result["rule_id"],None); self._invalidate_caches()
  return json.dumps(result,separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="s",out_signature="s")
 def NetworkRemoveRule(self,rule_id):
  if not isinstance(rule_id,str) or not re.fullmatch(r"greyward-[a-f0-9]{20}",rule_id):
   return json.dumps({"ok":False,"state":"INVALID","detail":"Only a GREYWARD-owned rule can be removed."},separators=(",",":"))
  result=_policy_helper(["remove-rule","--rule-id",rule_id])
  if result.get("ok") is True:
   RECENT_POLICY_RULES.pop(rule_id,None)
   self._invalidate_caches()
  return json.dumps(result,separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="s",out_signature="s")
 def NetworkPromptDecision(self,payload):
  return json.dumps({"ok":False,"state":"DEFERRED","detail":"Interactive OpenSnitch decisions are not enabled until the end-to-end prompt lifecycle is validated."},separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="",out_signature="s")
 def ListUsbDevices(self):
  devices,error=self.usb.devices(); safe=[]
  for item in devices:
   value=dict(item); value.pop("identity_metadata",None); safe.append(value)
  return json.dumps({"schema":SCHEMA,"devices":safe,"error":error},sort_keys=True,separators=(",",":"))
 def action(self,method,*args):
  try:
   rule_id=method(*args)
   self._invalidate_caches()
   return json.dumps({"ok":True,"rule_id":rule_id},separators=(",",":"))
  except UsbGuardError as error: return json.dumps({"ok":False,"message":str(error)},separators=(",",":"))
 @dbus.service.method(BUS_NAME,in_signature="s",out_signature="s")
 def UsbAllowOnce(self,device_id): return self._request_legacy_usb(device_id,"once")
 @dbus.service.method(BUS_NAME,in_signature="s",out_signature="s")
 def UsbAlwaysAllow(self,device_id): return self._request_legacy_usb(device_id,"always")
 def _request_legacy_usb(self,device_id,mode):
  devices,error=self.usb.devices()
  device=next((x for x in devices if x["device_id"]==str(device_id)),None)
  if error or not device: return json.dumps({"ok":False,"state":"UNAVAILABLE" if error else "REMOVED","detail":error or "Device is no longer connected."})
  return self.RequestUsbTrust(device["connection_ref"],mode)
 @dbus.service.method(BUS_NAME,in_signature="s",out_signature="s")
 def UsbKeepBlocked(self,device_id): return self.action(self.usb.adapter.keep_blocked,device_id)
 @dbus.service.method(BUS_NAME,in_signature="ss",out_signature="s")
 def UsbRevokeTrust(self,device_id,rule_id): return self.action(self.usb.adapter.revoke,device_id,rule_id)
 def _safe_open_event(self,event_id,title,detail,file_ref=None,outcome="SUCCESS"):
  self.usb.events=[event for event in self.usb.events if event["event_id"]!=event_id]
  event={"event_id":event_id,"kind":"SAFE_OPEN_RESULT","notification":"HISTORY_ONLY","occurred_at":stamp(now()),"title":title,"detail":detail[:320],"source":"safe-open/bwrap"}
  if file_ref: event["file_ref"]=file_ref
  self.usb.events.append(event)
  self._record_file_security_event("SAFE_OPEN_RESULT", "OPEN", outcome, file_ref, {"message":detail[:320]})
 def _record_file_security_event(self,event_type,action,outcome,file_ref=None,details=None):
  record_event(telemetry_event(component="greyward-file-security",source="security-context",category="FILE_SECURITY",event_type=event_type,action=action,outcome=outcome,severity="NOTICE" if outcome=="SUCCESS" else "ERROR",assessment="NOTEWORTHY" if outcome=="SUCCESS" else "FAILED",correlation={"file_ref":file_ref} if file_ref else {},details={"result":outcome,**(details or {})},quality={"source_state":"AVAILABLE","attribution":"EXACT","confidence":"EXACT"},retention_class="semantic"),self.usb.telemetry)
 def _safe_open_finished(self,event_id,code):
  entry=self.safe_open_processes.pop(event_id,None)
  file_ref=entry[1] if entry else None
  outcome="SUCCESS" if code == 0 else "FAILURE"
  title="Safe Open context exited" if outcome == "SUCCESS" else "Safe Open context failed"
  detail="The disposable restricted context exited and its temporary namespace was cleaned up." if outcome == "SUCCESS" else "The disposable restricted context exited without opening the file successfully."
  self._safe_open_event(event_id,title,detail,file_ref,outcome)
 @dbus.service.method(BUS_NAME,in_signature="s",out_signature="s")
 def SafeOpen(self,path):
  try:
   process,selected=launch_safe_open(path)
  except SafeOpenError as error:
   ref=_file_ref(Path(path).resolve())
   event_id="safe-open-failed-"+uuid.uuid4().hex
   self._safe_open_event(event_id,"Safe Open refused",redact_error(error),ref,outcome="FAILURE")
   return json.dumps({"ok":False,"state":"FAILED","detail":redact_error(error)},separators=(",",":"))
  ref=_file_ref(Path(selected).resolve())
  event_id="safe-open-"+uuid.uuid4().hex
  self.safe_open_processes[event_id]=(process,ref)
  self._safe_open_event(event_id,"Safe Open launched","The selected file was opened in a disposable restricted context with read-only file access and no network.",ref)
  monitor_safe_open(process,lambda code:self._safe_open_finished(event_id,code))
  return json.dumps({"ok":True,"state":"LAUNCHED","detail":"Safe Open launched in a disposable restricted context."},separators=(",",":"))
 def scan_high_risk_path(self,path):
  try:
   if not permitted(path, os.getuid()): return {"state":"ERROR","detail":"Only regular files owned by your user can be scanned."}
   proxy=dbus.Interface(dbus.SystemBus().get_object("systems.mantis.greyward.ClamAvScan1","/systems/mantis/greyward/ClamAvScan1"),"systems.mantis.greyward.ClamAvScan1")
   return json.loads(proxy.ScanPath(path,timeout=FILE_SECURITY_DBUS_TIMEOUT))
  except FileNotFoundError: return {"state":"SOURCE_REMOVED","detail":"The scan source was removed before scanning began."}
  except dbus.DBusException: return {"state":"UNAVAILABLE","detail":"ClamAV scanning is unavailable."}
 @dbus.service.method(BUS_NAME,in_signature="s",out_signature="s")
 def ScanHighRiskPath(self,path):
  value=self.scan_high_risk_path(path)
  self.usb.record_scan(value,_file_ref(Path(path).resolve()),scan_context(path))
  if hasattr(self,"shell_runtime"): self.shell_runtime.invalidate()
  return json.dumps(value,separators=(",",":"))
def main():
 dbus.mainloop.glib.DBusGMainLoop(set_as_default=True); bus=dbus.SessionBus(); name=dbus.service.BusName(BUS_NAME,bus=bus); service=SecurityContext(bus,UsbContext(),SensorContext()); service.start_shell_runtime(bus); GLib.MainLoop().run()
if __name__=="__main__": main()
