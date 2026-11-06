#!/usr/bin/python3
"""Read-only, kernel-UID-scoped intelligence provider. Never enforces policy."""
import json
import os
import re
import logging
from pathlib import Path
import subprocess
import threading
import time
import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib
from .sensor_health import ProbeTracker
from .intelligence import Intelligence, SCHEMA, retained_sensor_file, rotation_successor, elapsed, attested_policy_links

BUS='systems.mantis.greyward.Intelligence1'
OBJECT='/systems/mantis/greyward/Intelligence1'
STATE=Path('/var/lib/greyward/intelligence')
RAW=STATE/'sensor/events.jsonl'

class Provider(dbus.service.Object):
    def __init__(self,bus):
        super().__init__(bus,OBJECT)
        self.buckets={}
        self.engine=Intelligence(STATE/'evidence.sqlite3')
        self.engine.db.execute('PRAGMA max_page_count=8192')
        threading.Thread(target=self.collect,name='behavioral-evidence',daemon=True).start()

    @dbus.service.method(BUS,in_signature='s',out_signature='s',sender_keyword='sender')
    def GetSnapshot(self,payload,sender=None):
        try:
            if not sender:raise PermissionError
            uid=int(self.connection.get_unix_user(sender))
            now=time.monotonic();tokens,previous=self.buckets.get(uid,(20,now));tokens=min(20,tokens+(now-previous)*2)
            if tokens<1:raise ValueError('Read rate limited')
            self.buckets[uid]=(tokens-1,now)
            if len(self.buckets)>256:self.buckets.pop(next(iter(self.buckets)))
            if len(payload)>4096:raise ValueError
            options=json.loads(payload or '{}')
            if not isinstance(options,dict):raise ValueError
            return json.dumps(self.engine.snapshot(uid,options),separators=(',',':'))
        except (OSError,ValueError,TypeError,PermissionError,dbus.DBusException):
            return json.dumps({'schema':SCHEMA,'sensor':{'state':'UNAVAILABLE'},'events':[],'incidents':[]})

    def collect(self):
        stream=None;inode=None;position=0;next_health=0;probes=ProbeTracker();healthy_probes=0;previous_matches=0;caught_up=False
        while True:
            try:
                now=time.monotonic()
                if now>=next_health:
                    cursor=self.engine.metadata('journal_cursor') or int((time.time()-30)*1000000)
                    warnings=subprocess.run(['/usr/bin/journalctl','-u','greyward-intelligence-sensor.service','--since','@'+str(cursor/1000000),'-n','40','-o','json','--no-pager'],capture_output=True,text=True,timeout=3)
                    newest=cursor
                    for line in warnings.stdout.splitlines():
                        if not line.startswith('{'):continue
                        record=json.loads(line);seen=int(record.get('__REALTIME_TIMESTAMP',0));newest=max(newest,seen)
                        if seen>cursor and re.search(r'\b(lost|dropped|throttl\w*)\b|ring.*full',record.get('MESSAGE',''),re.I):
                            self.engine.record_gap('Kernel sensor reported lost or throttled events.')
                    if newest>cursor:self.engine.metadata('journal_cursor',newest)
                    active=subprocess.run(['/usr/bin/systemctl','is-active','--quiet','greyward-intelligence-sensor.service'],timeout=3,check=False).returncode==0
                    pid=int(subprocess.check_output(['/usr/bin/systemctl','show','--value','-p','MainPID','greyward-intelligence-sensor.service'],text=True,timeout=3).strip() or '0')
                    links=attested_policy_links(pid,self.engine.boot)
                    probe_status=probes.status(elapsed())
                    verified=probe_status['probe_state']=='VERIFIED'
                    healthy_probes=healthy_probes+1 if verified and caught_up and probes.matches>previous_matches else 0
                    previous_matches=probes.matches
                    recent_gap=elapsed()-self.engine.last_gap_elapsed<30
                    complete=verified and all(links.values()) and caught_up and healthy_probes>=2 and not recent_gap
                    state='ACTIVE' if complete else 'STARTING' if probes.sent<2 else 'DEGRADED'
                    reasons=[]
                    if not verified:reasons.append('execution/export round-trip not verified')
                    if not all(links.values()):reasons.append('selected policy attachments not verified')
                    if not caught_up:reasons.append('export reader catching up')
                    if recent_gap:reasons.append('recent telemetry loss')
                    if verified and healthy_probes<2:reasons.append('confirming consecutive healthy checks')
                    detail='Current execution/export probes and selected policy attachments are verified.' if complete else '; '.join(reasons)+'.'
                    self.engine.set_health(state if active else 'UNAVAILABLE',detail if active else 'Kernel sensor is not running; behavioral coverage is unavailable.',policy_links=links,reader_caught_up=caught_up,recent_loss=recent_gap,**probe_status)
                    probe=subprocess.Popen(['/usr/bin/true'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                    probes.issue(probe.pid,elapsed());probe.wait(timeout=2)
                    next_health=now+15
                if stream is None:
                    stream=RAW.open('rb');inode=os.fstat(stream.fileno()).st_ino
                    cursor=self.engine.metadata('sensor_cursor')
                    previous_boot=self.engine.metadata('source_boot')
                    if previous_boot!=self.engine.boot:
                        stream.seek(0,2);position=stream.tell()
                        self.engine.metadata('source_boot',self.engine.boot)
                        self.engine.metadata('sensor_cursor',{'inode':inode,'offset':position})
                    elif isinstance(cursor,dict) and cursor.get('inode')==inode:
                        position=int(cursor.get('offset',0))
                        if position>os.fstat(stream.fileno()).st_size:
                            self.engine.record_gap('Sensor export was truncated; some records may be missing.')
                            position=0
                        stream.seek(position)
                    elif isinstance(cursor,dict):
                        retained=retained_sensor_file(RAW,cursor.get('inode'))
                        if retained:
                            stream.close();stream=retained.open('rb');inode=os.fstat(stream.fileno()).st_ino
                            position=int(cursor.get('offset',0))
                            if position>os.fstat(stream.fileno()).st_size:
                                self.engine.record_gap('Retained sensor export was truncated.');position=0
                            stream.seek(position)
                        else:self.engine.record_gap('Sensor log rotated beyond retained history during downtime; an interval may be missing.')
                processed=0;partial=False
                while processed<256:
                    before=stream.tell();line=stream.readline(65537)
                    if not line:break
                    position=stream.tell();processed+=1
                    if len(line)<=65536 and not line.endswith(b'\n'):
                        stream.seek(before);position=before;partial=True;break
                    if len(line)>65536:
                        self.engine.record_gap('Incomplete or oversized sensor record; coverage is uncertain.')
                        continue
                    try:
                        decoded=json.loads(line)
                        probes.observe(decoded,elapsed())
                        self.engine.ingest(decoded,commit=False)
                    except (ValueError,TypeError,KeyError,OverflowError):
                        self.engine.record_gap('Invalid sensor record rejected.')
                caught_up=processed<256 and not partial
                if processed:self.engine.metadata('sensor_cursor',{'inode':inode,'offset':position})
                try:
                    current=RAW.stat()
                    if current.st_ino!=inode and (not line or partial):
                        if partial:self.engine.record_gap('A rotated export ended in an incomplete record.')
                        successor=rotation_successor(RAW,inode)
                        if successor is None:
                            self.engine.record_gap('Export rotation overtook ingestion; some records may be missing.')
                            successor=RAW
                        stream.close();stream=successor.open('rb');inode=os.fstat(stream.fileno()).st_ino;position=0
                        self.engine.metadata('sensor_cursor',{'inode':inode,'offset':0})
                    elif current.st_ino==inode and current.st_size<position:
                        self.engine.record_gap('Sensor export was truncated; some records may be missing.')
                        self.engine.metadata('sensor_cursor',{'inode':inode,'offset':0})
                        stream.close();stream=None;position=0
                except OSError:pass
                time.sleep(0.1 if processed==256 else 1)
            except Exception:
                logging.exception('Behavioral export reader failed; retained cursor will be retried')
                self.engine.set_health('UNAVAILABLE','Evidence ingestion failed; no healthy coverage is claimed.')
                if stream:stream.close()
                stream=None;time.sleep(5)

def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus=dbus.SystemBus();name=dbus.service.BusName(BUS,bus=bus)
    service=Provider(bus)
    GLib.MainLoop().run()

if __name__=='__main__':main()
