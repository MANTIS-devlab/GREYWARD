"""Explainable local behavioral evidence. No enforcement or command execution."""
from __future__ import annotations
import datetime as dt
import hashlib
import ipaddress
import statistics
import json
import os
from pathlib import Path
import sqlite3
import threading
import time
import stat
import re
from .process_identity import instance_key, event_time

SCHEMA = 'greyward.intelligence/v1'
VERSION = 'rules-4'
def elapsed():
    return time.clock_gettime(time.CLOCK_BOOTTIME) if hasattr(time,'CLOCK_BOOTTIME') else time.monotonic()
EVALUATED_SINCE = time.time()
MAX_EVENTS = 5000
MAX_INCIDENTS = 256
MAX_PROCESS = 4096
WINDOW = 600
SHELLS = {'sh','bash','dash','zsh','fish','python','python3','node','perl','ruby'}
PRIVILEGE_BROKERS = {'/usr/bin/sudo','/usr/bin/su','/usr/bin/pkexec','/usr/sbin/runuser','/usr/bin/runuser','/usr/lib/polkit-1/polkit-agent-helper-1','/usr/bin/unix_chkpwd','/usr/bin/passwd','/usr/bin/chfn','/usr/bin/chsh'}

def expected_fuse_helper(binary,parent_binary,known_parent,untrusted):
    # Expected desktop FUSE elevation is not a blanket trust grant to descendants.
    fuse='/usr/bin/fusermount3'
    portal_parents={'/usr/libexec/xdg-document-portal','/usr/libexec/gvfsd-fuse'}
    direct=binary==fuse and parent_binary in portal_parents and not untrusted
    mount=binary in {'/bin/mount','/usr/bin/mount'} and known_parent and known_parent.get('expected_fuse') and parent_binary==fuse
    if not (direct or mount):return False
    try:
        for name in ([fuse,parent_binary] if direct else [fuse,binary]):
            path=Path(name).resolve(strict=True);info=path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:return False
            if name==fuse and not info.st_mode&stat.S_ISUID:return False
            if any(p.stat().st_uid!=0 or p.stat().st_mode&0o022 for p in path.parents):return False
        return True
    except OSError:return False



def protected_system_executable(name, *, setuid=False):
    """Expected-helper checks are evidence classification, never permission grants."""
    try:
        path=Path(name).resolve(strict=True);info=path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or not info.st_mode&0o111:return False
        if setuid and not info.st_mode&stat.S_ISUID:return False
        return all(p.stat().st_uid==0 and not p.stat().st_mode&0o022 for p in path.parents)
    except OSError:return False

def expected_boot_helper(binary,parent_binary,known_parent,untrusted,pid):
    # Fedora's user boot-success unit uses a fixed setuid helper. systemd may
    # first exec its own retained FD in the SAME child PID. Recognize only the
    # observed exact exec-ID chain, never a process name or arbitrary /proc FD.
    if binary not in {'/usr/sbin/grub2-set-bootflag','/usr/bin/grub2-set-bootflag'} or untrusted or not known_parent:return False
    manager='/usr/lib/systemd/systemd'
    direct=parent_binary==manager and known_parent['binary']==manager
    trampoline=bool(known_parent.get('systemd_spawn') and known_parent.get('pid')==pid and re.fullmatch(r'/proc/self/fd/[0-9]+',parent_binary))
    return bool((direct or trampoline) and protected_system_executable(manager) and protected_system_executable(binary,setuid=True))


def text(value, limit=240):
    return ''.join(c for c in str(value or '') if c.isprintable())[:limit]

def stamp():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='milliseconds')

def unusual(binary):
    parts = Path(binary).parts
    return binary.startswith(('/tmp/','/var/tmp/','/dev/shm/','/memfd:')) or 'Downloads' in parts or 'Desktop' in parts or '(deleted)' in binary

def classification(score, decision='UNKNOWN', evaluated=True):
    if not evaluated:return 'UNKNOWN'
    if score >= 75:return 'HIGH_THREAT'
    if score >= 35:return 'SUSPICIOUS'
    return 'POLICY_BLOCKED' if decision == 'BLOCKED' else 'NORMAL'

def factor(code, points, explanation, domain):
    return {'code':code,'points':points,'explanation':explanation,'domain':domain}

def attested_policy_links(pid, boot, path=Path('/var/lib/greyward/intelligence/sensor/attachment.json')):
    """Read the sensor's fixed startup receipt without granting BPF to the provider."""
    try:
        value=json.loads(path.read_text())
        valid=pid>0 and value.get('pid')==pid and value.get('boot')==boot
        return {name:valid and value.get('links',{}).get(name) is True for name in ('persistence','outbound')}
    except (OSError,ValueError,TypeError,AttributeError):
        return {'persistence':False,'outbound':False}

def retained_sensor_file(raw, inode):
    """Find the exact retained inode; never guess a cursor by filename."""
    try:
        for path in [raw,*raw.parent.glob(raw.stem+'-*'+raw.suffix)]:
            if not path.is_symlink() and path.stat().st_ino==inode:return path
    except OSError:pass
    return None

def rotation_successor(raw, inode):
    """Drain retained backups oldest first, then the current export."""
    try:
        backups=sorted((p for p in raw.parent.glob(raw.stem+'-*'+raw.suffix) if not p.is_symlink()),key=lambda p:(p.stat().st_mtime_ns,p.name))
        for index,path in enumerate(backups):
            if path.stat().st_ino==inode:return backups[index+1] if index+1<len(backups) else raw
    except OSError:pass
    return None

class Intelligence:
    def __init__(self, path, boot=None):
        self.path=Path(path);self.path.parent.mkdir(parents=True,exist_ok=True)
        self.boot=boot or Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        self.lock=threading.RLock()
        self.db=sqlite3.connect(self.path,check_same_thread=False)
        self.db.row_factory=sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=NORMAL')
        self.db.execute('PRAGMA journal_size_limit=4194304')
        self.db.executescript('''CREATE TABLE IF NOT EXISTS evidence (
          id TEXT PRIMARY KEY, uid INTEGER NOT NULL, occurred REAL NOT NULL, incident TEXT, body TEXT NOT NULL);
          CREATE INDEX IF NOT EXISTS evidence_owner_time ON evidence(uid,occurred DESC);
          CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY,uid INTEGER NOT NULL,updated REAL NOT NULL,body TEXT NOT NULL);
          CREATE INDEX IF NOT EXISTS incident_owner_time ON incidents(uid,updated DESC);
          CREATE INDEX IF NOT EXISTS evidence_process_instance ON evidence(uid,json_extract(body,'$.process_key'),occurred DESC);
          CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);''')
        os.chmod(self.path,0o600)
        self.processes={};self.incidents={};self.latest={}
        for row in self.db.execute('SELECT body FROM incidents ORDER BY updated DESC LIMIT ?', (MAX_INCIDENTS,)):
            value=json.loads(row[0]);self.incidents[value['id']]=value
            self.latest.setdefault((value['owner_uid'],value['root_exec_id']),value['id'])
        self.health={'state':'STARTING','provider':'Tetragon','rules':VERSION,'dropped':0,
            'coverage':['process execution','process exit','selected persistence write attempts','outbound connection attempts'],
            'enforcement':'Existing SELinux, Application Guard and OpenSnitch policies only',
            'loss_visibility':'Export throttling and daemon warnings; kernel ring loss is not independently proven absent.'}
        previous_loss=self.metadata('sensor_loss') or {}
        if previous_loss.get('boot')==self.boot:self.health['dropped']=int(previous_loss.get('count',0))
        self.since=time.time();self.received=0;self.last_prune=0;self.health_checked_at=elapsed()
        gaps=self.metadata('coverage_gaps') or []
        self.gaps=[g for g in gaps if isinstance(g,dict)][-64:]
        self.last_gap_elapsed=max((g.get('elapsed',-1000000) for g in self.gaps if g.get('boot')==self.boot),default=-1000000)

    def metadata(self,key,value=None):
        with self.lock:
            if value is not None:
                self.db.execute('INSERT OR REPLACE INTO metadata VALUES(?,?)',(key,json.dumps(value)));self.db.commit()
            row=self.db.execute('SELECT value FROM metadata WHERE key=?',(key,)).fetchone()
            return json.loads(row[0]) if row else None

    def set_health(self,state,detail='',**extra):
        with self.lock:
            self.health.update(state=state,detail=text(detail),observed_at=stamp(),**extra)
            self.health_checked_at=elapsed()
            if 'dropped' in extra:self.metadata('sensor_loss',{'boot':self.boot,'count':self.health['dropped']})

    def record_gap(self,reason,count=1):
        with self.lock:
            self.last_gap_elapsed=elapsed()
            self.health['dropped']+=max(1,int(count))
            self.gaps.append({'boot':self.boot,'at':stamp(),'elapsed':self.last_gap_elapsed,'reason':text(reason),'count':max(1,int(count))})
            self.gaps=self.gaps[-64:]
            self.metadata('coverage_gaps',self.gaps)
            self.set_health('DEGRADED',reason,dropped=self.health['dropped'])

    def _root(self,node):
        # Only observed exact exec IDs connect a chain. Never join by a PID or name.
        selected=node;walker=node
        for _ in range(12):
            parent=self.processes.get(walker.get('parent'))
            if not parent or parent['uid']!=node['uid'] or not 0<=node['seen']-parent['seen']<=WINDOW:break
            correlated=self.processes.get(parent.get('correlation_root'))
            if correlated and 0<=node['seen']-correlated['seen']<=WINDOW:selected=correlated
            elif unusual(parent['binary']):selected=parent
            walker=parent
        return selected

    def _write_evidence(self,value,observed,commit):
        # Keep system execution identities in the bounded ancestry map, but do
        # not let ordinary daemon bookkeeping evict users' investigation history.
        # Root descendants attributed to an ordinary actor already carry that
        # actor's UID and are retained, as are unknown/suspicious system events.
        if (value['uid'] < 1000 and value.get('classification') == 'NORMAL'
                and value.get('score') == 0 and not value.get('incident_id')):
            return False
        cursor=self.db.execute('INSERT OR IGNORE INTO evidence VALUES(?,?,?,?,?)',(value['event_id'],value['uid'],observed,value.get('incident_id'),json.dumps(value)))
        if not cursor.rowcount:return False
        self.received+=1
        if self.received % 128 == 0 or observed-self.last_prune>30:
            self.db.execute('''DELETE FROM evidence WHERE occurred<? OR id NOT IN (
                SELECT id FROM (SELECT id,incident,occurred,
                    row_number() OVER (PARTITION BY uid ORDER BY (incident IS NOT NULL) DESC,occurred DESC) AS owner_rank
                    FROM evidence)
                ORDER BY owner_rank,(incident IS NOT NULL) DESC,occurred DESC LIMIT ?)''',
                (time.time()-7*86400,MAX_EVENTS))
            self.db.execute('DELETE FROM incidents WHERE updated<? OR id NOT IN (SELECT id FROM incidents ORDER BY updated DESC LIMIT ?)',(time.time()-7*86400,MAX_INCIDENTS))
            # Count/age bounds alone do not bound unusually long UTF-8 paths.
            # Reclaim old records well before the independent 32 MiB page cap.
            used=(self.db.execute('PRAGMA page_count').fetchone()[0]-self.db.execute('PRAGMA freelist_count').fetchone()[0])*self.db.execute('PRAGMA page_size').fetchone()[0]
            if used>16*1024*1024:
                self.db.execute('DELETE FROM evidence WHERE id IN (SELECT id FROM evidence ORDER BY occurred LIMIT 1250)')
                self.db.execute('DELETE FROM incidents WHERE id IN (SELECT id FROM incidents ORDER BY updated LIMIT 64)')
            self.last_prune=observed
        if commit:self.db.commit()
        return True

    def ingest(self, raw, now=None, *, commit=True):
        if now is None:
            try:now=dt.datetime.fromisoformat(str(raw.get('time','')).replace('Z','+00:00')).timestamp()
            except (ValueError,TypeError,AttributeError):now=time.time()
        if not isinstance(raw,dict):return None
        with self.lock:
            if 'rate_limit_info' in raw or 'process_throttle' in raw:
                dropped=(raw.get('rate_limit_info') or {}).get('number_of_dropped_process_events',1)
                self.record_gap('Sensor throttling: some activity was not evaluated.',int(dropped or 1))
                return None
            kind=next((k for k in ('process_exec','process_exit','process_kprobe') if isinstance(raw.get(k),dict)),None)
            if not kind:return None
            data=raw[kind];process=data.get('process') or {};parent=data.get('parent') or {}
            eid=text(process.get('exec_id'),256);binary=text(process.get('binary'),512)
            uid=process.get('uid');pid=process.get('pid')
            if not eid or not binary or isinstance(uid,bool) or not isinstance(uid,int) or uid<0:return None
            if 'procFS' in str(process.get('flags','')):return None # pre-existing processes are context, not new executions
            if any(flag in str(process.get('flags','')).lower() for flag in ('taskwalk','truncfilename')):
                value={'event_id':'behavior-'+hashlib.sha256((self.boot+'|'+eid+'|'+kind+'|'+str(raw.get('time'))).encode()).hexdigest()[:32],
                    'uid':uid,'occurred_at':text(raw.get('time') or stamp(),64),'kind':kind,'title':'Process attribution incomplete',
                    'binary':binary,'pid':pid,'exec_id':None,'parent_exec_id':None,'decision':'UNKNOWN','score':None,
                    'classification':'UNKNOWN','confidence':'UNKNOWN','attribution':'PARTIAL','factors':[],
                    'incident_id':None,'source':'TETRAGON_KERNEL','rules':VERSION,'evaluated_at':stamp()}
                self._write_evidence(value,now,commit)
                return value
            parent_id=text(process.get('parent_exec_id') or parent.get('exec_id'),256)
            actual_uid=uid;known_parent=self.processes.get(parent_id)
            if known_parent and known_parent['uid']>=1000 and actual_uid in {0,known_parent.get('actual_uid',known_parent['uid'])}:
                uid=known_parent['uid'] # exact observed root descendant of this actor; never another ordinary UID
            broker=binary in PRIVILEGE_BROKERS or parent.get('binary') in PRIVILEGE_BROKERS
            authorized=broker or bool(known_parent and known_parent.get('authorized_privilege'))
            node={'id':eid,'uid':uid,'actual_uid':actual_uid,'authorized_privilege':authorized,'pid':pid if isinstance(pid,int) else None,'binary':binary,'parent':parent_id,'seen':now}
            previous=self.processes.get(eid)
            if previous:node={**previous,'seen':previous['seen']}
            # An initially unavailable /proc identity must not become a
            # permanent negative cache for a still-running process. Retry only
            # on fresh observations, at most once per five seconds/instance.
            if not previous or (not node.get('process_key') and now-node.get('_identity_checked',0)>=5):
                node['process_key']=instance_key(node['pid'],exec_id=eid)
                node['_identity_checked']=now

            if kind=='process_exec':
                node['systemd_spawn']=bool(actual_uid>=1000 and re.fullmatch(r'/proc/self/fd/[0-9]+',binary)
                    and parent.get('binary')=='/usr/lib/systemd/systemd' and parent.get('uid')==actual_uid
                    and parent.get('exec_id')==parent_id and isinstance(pid,int) and parent.get('pid')!=pid
                    and protected_system_executable('/usr/lib/systemd/systemd'))
                self.processes[eid]=node
            else:self.processes[eid]=node
            if len(self.processes)>MAX_PROCESS:
                self.processes.pop(next(iter(self.processes)))
            # Replay may restore exact process context, but must not count the
            # same network observation twice or mutate an existing incident.
            replay_label={'process_exec':'Process executed','process_exit':'Process exited'}.get(kind)
            if kind=='process_kprobe':
                replay_label={'greyward-persistence':'Persistence write permission requested','greyward-outbound':'Outbound connection attempted'}.get(text(data.get('policy_name') or data.get('function_name')))
            if replay_label:
                replay_id='behavior-'+hashlib.sha256((self.boot+'|'+eid+'|'+kind+'|'+(str(raw.get('time')) if kind=='process_kprobe' else '')+'|'+replay_label).encode()).hexdigest()[:32]
                if self.db.execute('SELECT 1 FROM evidence WHERE id=?',(replay_id,)).fetchone():return None
            root=self._root(node)
            pair=(uid,root['id']);incident=self.incidents.get(self.latest.get(pair))
            if incident and not 0<=now-incident['_updated']<=WINDOW:incident=None
            incident_id=incident['id'] if incident else 'incident-'+hashlib.sha256((self.boot+'|'+str(uid)+'|'+root['id']+'|'+str(now)).encode()).hexdigest()[:24]
            if incident is None:
                incident={'id':incident_id,'owner_uid':uid,'root_exec_id':root['id'],'application':Path(root['binary']).name,
                    'score':0,'classification':'NORMAL','confidence':'MEDIUM','factors':[], 'timeline':[], 'chain':[],
                    'first_seen':text(raw.get('time') or stamp(),64),'last_seen':text(raw.get('time') or stamp(),64),
                    'decision':'UNKNOWN','response':'Observed only; no automatic behavioral blocking.','rules':VERSION,
                    'state':'ACTIVE','_updated':now}
            factors=[];label='Process executed';action='OBSERVED';destination=None;expected=False
            parent_binary=text(parent.get('binary') or self.processes.get(parent_id,{}).get('binary'),512)
            untrusted=unusual(node['binary']) or unusual(root['binary'])
            if kind=='process_exec':
                if unusual(binary):factors.append(factor('UNUSUAL_LOCATION',10,'Execution from a temporary or incoming-files location; context alone does not establish a threat.','execution'))
                document_parent=parent_binary.startswith('/usr/lib') and any(x in parent_binary.lower() for x in ('writer','sheets','slides','pdfcraft'))
                if Path(binary).name in SHELLS and (unusual(parent_binary) or document_parent):
                    factors.append(factor('UNEXPECTED_INTERPRETER',35,'An observed temporary/document process started a command interpreter.','execution'))
                expected_fuse=expected_fuse_helper(binary,parent_binary,known_parent,untrusted)
                expected_boot=expected_boot_helper(binary,parent_binary,known_parent,untrusted,pid)
                expected=expected_fuse or expected_boot
                self.processes[eid]['expected_fuse']=bool(expected_fuse and binary=='/usr/bin/fusermount3')
                if actual_uid==0 and uid>=1000 and not authorized and not expected:
                    factors.append(factor('PRIVILEGE_TRANSITION',40,'A non-system parent started a root process outside the known privilege brokers. This may still be legitimate.','privilege'))
            elif kind=='process_exit':
                label='Process exited'
                if eid in self.processes:self.processes[eid]['exited']=True
            else:
                policy=text(data.get('policy_name') or data.get('function_name'))
                if policy=='greyward-persistence':
                    label='Persistence write permission requested'
                    # A kernel permission hook is an attempt, not proof a file changed.
                    if untrusted or incident['score']>=35:factors.append(factor('PERSISTENCE_ATTEMPT',35,'This execution chain requested write access to a selected startup/persistence path. Success is not established.','persistence'))
                elif policy=='greyward-outbound':
                    label='Outbound connection attempted'
                    for argument in data.get('args',[]):
                        if not isinstance(argument,dict):continue
                        address=argument.get('sockaddr_arg') or {}
                        try:
                            ip=str(ipaddress.ip_address(address.get('addr','')))
                            port=int(address.get('port',0))
                            destination={'ip':ip,'port':port if 0<port<=65535 else None}
                            break
                        except (ValueError,TypeError):continue
                    addresses=[a.get('sockaddr_arg',{}).get('addr') for a in data.get('args',[]) if isinstance(a,dict)]
                    public=None
                    for address in addresses:
                        try:
                            if address and ipaddress.ip_address(address).is_global:public=address;break
                        except ValueError:continue
                    if public and (untrusted or incident['score']>=35):
                        factors.append(factor('OUTBOUND_AFTER_EXECUTION',15,'The same exact execution chain attempted a public outbound connection. OpenSnitch remains the decision owner.','network'))
                        samples=incident.setdefault('_connections',{});samples.setdefault(public,[]).append(now)
                        samples[public]=samples[public][-8:]
                        if len(samples)>8:samples.pop(next(iter(samples)))
                        times=samples[public];intervals=[b-a for a,b in zip(times,times[1:])]
                        if any(f['code'] in {'UNEXPECTED_INTERPRETER','PERSISTENCE_ATTEMPT','PRIVILEGE_TRANSITION'} for f in incident['factors']) and len(times)>=6 and times[-1]-times[0]>=60 and min(intervals)>0 and max(intervals)-min(intervals)<=statistics.median(intervals)*.1:
                            factors.append(factor('REGULAR_COMMUNICATION',20,'At least six regularly spaced public connection attempts occurred in this already unusual execution chain. This is a pattern indicator, not proof of command and control.','network'))
                else:return None
            event_id='behavior-'+hashlib.sha256((self.boot+'|'+eid+'|'+kind+'|'+(str(raw.get('time')) if kind=='process_kprobe' else '')+'|'+label).encode()).hexdigest()[:32]
            for f in factors:f['evidence']={'event_id':event_id,'occurred_at':text(raw.get('time') or stamp(),64),'binary':binary,'pid':node['pid']}
            codes={f['code'] for f in incident['factors']}
            incident['factors'] += [f for f in factors if f['code'] not in codes]
            score=min(100,sum(f['points'] for f in incident['factors']))
            # High severity needs independent behavioral domains, not repeated denials.
            if len({f['domain'] for f in incident['factors'] if f['points']>=15})<2:score=min(score,74)
            if score>=35:self.processes[eid]['correlation_root']=root['id']
            incident.update(score=score,classification=classification(score),last_seen=text(raw.get('time') or stamp(),64),_updated=now)
            if not any(p['id']==eid for p in incident['chain']):incident['chain'].append({k:node[k] for k in ('id','binary','pid','parent')})
            incident['chain']=incident['chain'][-16:]
            evidence={'event_id':event_id,'uid':uid,'occurred_at':incident['last_seen'],'kind':kind,'title':label,'binary':binary,'pid':node['pid'],
                'exec_id':eid,'parent_exec_id':parent_id,'euid':actual_uid,'decision':action,'score':score,'classification':classification(score),
                'evaluated_at':stamp(),'confidence':'MEDIUM' if score>=35 else 'HIGH','attribution':'EXACT_EXEC_ID','factors':factors,'incident_id':incident_id if score>=35 else None,'source':'TETRAGON_KERNEL','rules':VERSION,
                'channel':'NETWORK' if label=='Outbound connection attempted' else 'SYSTEM','destination':destination,
                'process_key':node.get('process_key'),'parent_binary':parent_binary,
                'expected_operation':('Boot status maintenance' if expected_boot else 'Desktop filesystem mounting') if kind=='process_exec' and expected else None}
            if self.db.execute('SELECT 1 FROM evidence WHERE id=?',(event_id,)).fetchone():return None
            if uid < 1000 and score == 0:
                # The ancestry map still contains the observation. Do not let
                # routine daemons churn the in-memory incident/correlation cache.
                return evidence
            incident['timeline'].append({k:evidence[k] for k in ('event_id','occurred_at','title','binary','pid','decision','score')})
            incident['total_events']=incident.get('total_events',0)+1
            incident['timeline_truncated']=incident['total_events']>32
            incident['timeline']=incident['timeline'][-32:]
            self.incidents[incident_id]=incident;self.latest[pair]=incident_id
            if len(self.incidents)>MAX_INCIDENTS:
                removed=self.incidents.pop(min(self.incidents,key=lambda k:self.incidents[k]['_updated']))
                old_pair=(removed['owner_uid'],removed['root_exec_id'])
                if self.latest.get(old_pair)==removed['id']:self.latest.pop(old_pair,None)
            if score>=35:self.db.execute('INSERT OR REPLACE INTO incidents VALUES(?,?,?,?)',(incident_id,uid,now,json.dumps(incident)))
            self._write_evidence(evidence,now,commit)
            return evidence

    def snapshot(self,uid,request=None):
        request=request if isinstance(request,dict) else {}
        limit=max(1,min(120,int(request.get('limit',60))))
        offset=max(0,min(MAX_EVENTS,int(request.get('offset',0))))
        allowed={'UNKNOWN','NORMAL','POLICY_BLOCKED','SUSPICIOUS','HIGH_THREAT'}
        selected=request.get('classification');where='uid=?';params=[int(uid)]
        channel=request.get('channel')
        network="(json_extract(body,'$.channel')='NETWORK' OR (json_extract(body,'$.kind')='process_kprobe' AND json_extract(body,'$.title')='Outbound connection attempted'))"
        if channel=='NETWORK':where+=' AND '+network
        elif channel=='SYSTEM':where+=' AND NOT COALESCE('+network+',0)'
        minimum=request.get('min_score')
        if isinstance(minimum,int) and not isinstance(minimum,bool) and minimum>0:
            where+=" AND json_extract(body,'$.score')>=?";params.append(min(100,minimum))
        wanted=request.get('incident_id')
        if wanted:where+=' AND incident=?';params.append(str(wanted))
        ordering="json_extract(body,'$.score') DESC,occurred DESC" if request.get('sort')=='severity' else 'occurred DESC'
        if selected in allowed:
            where+=" AND json_extract(body,'$.classification')=?";params.append(selected)
        with self.lock:
            events=[json.loads(r[0]) for r in self.db.execute('SELECT body FROM evidence WHERE '+where+' ORDER BY '+ordering+' LIMIT ? OFFSET ?',(*params,limit,offset))]
            incidents=[json.loads(r[0]) for r in self.db.execute('SELECT body FROM incidents WHERE uid=? ORDER BY updated DESC LIMIT ?',(int(uid),MAX_INCIDENTS))]
            for i in incidents:
                i['state']='QUIET' if time.time()-i.pop('_updated',0)>WINDOW else 'ACTIVE'
                i.pop('owner_uid',None);i.pop('_connections',None)
            wanted=request.get('incident_id')
            if wanted:incidents=[i for i in incidents if i['id']==wanted]
            assessments={}
            keys=request.get('process_keys',[])
            if isinstance(keys,list):
                for key in list(dict.fromkeys(k for k in keys if isinstance(k,str) and re.fullmatch('[0-9a-f]{40}',k)))[:64]:
                    rows=self.db.execute("SELECT body FROM evidence WHERE uid=? AND json_extract(body,'$.process_key')=? ORDER BY occurred DESC LIMIT 8",(int(uid),key))
                    assessments[key]=[json.loads(r[0]) for r in rows]
                    # Each event carries the incident score at that instant.
                    # Retain the contributing factors as of that event, not
                    # later incident factors or another user's evidence.
                    for assessment in assessments[key]:
                        related=next((i for i in incidents if i['id']==assessment.get('incident_id')),None)
                        if related:
                            at=event_time(assessment.get('occurred_at'))
                            assessment['factors']=[f for f in related.get('factors',[]) if event_time((f.get('evidence') or {}).get('occurred_at')) is not None and at is not None and event_time(f['evidence']['occurred_at'])<=at]

            health=dict(self.health)
            span=self.db.execute('SELECT count(*),min(occurred),max(occurred) FROM evidence WHERE uid=?',(int(uid),)).fetchone()
            retention={'records':span[0], 'oldest_observed_at':span[1], 'newest_observed_at':span[2],
                'maximum_age_days':7, 'global_record_target':MAX_EVENTS,
                'policy':'Bounded, incident-first and fair per owner; seven days is an upper bound, not guaranteed coverage.'}
            if elapsed()-self.health_checked_at>45:health.update(state='UNAVAILABLE',detail='The evidence heartbeat is stale; displayed records are historical.')
            return {'schema':SCHEMA,'generated_at':stamp(),'sensor':health,'retention':retention,'incidents':incidents[:60],
                'process_assessments':assessments,'events':events,'next_offset':offset+limit if len(events)==limit else None,
                'evaluated_since':self.since,'score_meaning':'Severity index, not probability of compromise.',
                'response_policy':'No heuristic-score blocking or process termination.'}

def network_risk_priority(score):
    """Six inspection levels, not a probability or a firewall decision."""
    if type(score) is not int or not 0 <= score <= 100:
        return None
    if score == 0: return 1
    if score < 20: return 2
    if score < 50: return 3
    if score < 70: return 4
    if score < 90: return 5
    return 6


def network_assessment(event, process=None, sensor=None, reputation=None, pattern=None):
    """Evaluate independent evidence families; never infer a firewall decision.

    The strongest family sets the base. Independently suspicious behavioral
    evidence can add at most 20 points. Repetition, missing data and policy
    denials add none. Factor weights are not a probability or an additive list.
    """
    from . import feodo
    from .network_patterns import SOURCES
    from types import SimpleNamespace
    unknown={'classification':'UNKNOWN','score':None,'confidence':'UNKNOWN','factors':[],
             'incident_id':None,'scope':'UNASSESSED','evaluated_at':stamp(),'rules':VERSION,
             'risk_score':None,'risk_scale':6}
    if event_time(event.get('occurred_at')) is None or event.get('source') not in SOURCES:return unknown
    destination=event.get('destination') or {}
    protocol=str(event.get('protocol') or '').lower()
    port=destination.get('port',event.get('port'))
    decision=event.get('decision',event.get('outcome'))
    try:
        address=ipaddress.ip_address(destination.get('ip') or '')
        assessed=protocol in {'tcp','tcp6','udp','udp6'} and type(port) is int and 1<=port<=65535 and decision in {'ALLOWED','BLOCKED'}
    except ValueError:
        address=None;assessed=False
    if not assessed:return {**unknown,'detail':'Incomplete connection metadata; the firewall decision remains authoritative.'}
    reputation=reputation or {}
    fresh=event_time(reputation.get('last_successful_update'))
    feed_available=reputation.get('state') in {'READY','EMPTY'} and fresh is not None and 0<=time.time()-fresh<=86400
    indicator=feodo.matching_indicator(SimpleNamespace(dst_ip=str(address),dst_port=port),reputation) if feed_available else None
    coverage={'reputation':'FRESH' if feed_available else 'UNAVAILABLE',
              'reputation_provider':'Feodo recommended IP/port indicators',
              'reputation_indicators':len(reputation.get('indicators') or []) if feed_available else 0,
              'domain_reputation':'NOT_IMPLEMENTED','process':'NOT_LINKED'}
    factors=[];families=[]
    if indicator:
        factors.append(factor('KNOWN_DESTINATION',70,'The destination IP and port match the current local Feodo recommended command-and-control indicator list. A match warrants investigation; it is not proof that this application is compromised.','reputation'))
        families.append(('reputation',70))
    if pattern:
        factors.append(pattern);families.append(('network-pattern',pattern['points']))
    process_score=process.get('score') if isinstance(process,dict) else None
    process_factors=process.get('factors',[]) if isinstance(process,dict) else []
    # A stale score without retained explanations is not elevated evidence.
    linked=type(process_score) is int and 0<=process_score<=100 and (process_score==0 or bool(process_factors))
    if linked:
        coverage['process']='KERNEL_PROCESS_INSTANCE'
        factors.extend(process_factors)
        families.append(('process',process_score))
    score=max((v for _,v in families),default=0)
    independent_process=linked and process_score>=35 and any(f.get('domain') in {'execution','persistence','privilege'} and f.get('points',0)>=15 for f in process_factors)
    supporting=sum((bool(indicator),bool(pattern),bool(independent_process)))
    support=20 if supporting>=2 else 0
    score=min(100,score+support)
    # Deduplicate retained factors; repeated events never increase weights.
    factors=list({f['code']:f for f in factors if isinstance(f,dict) and f.get('code')}.values())
    application_pattern=bool(pattern and pattern.get('attribution')=='APPLICATION_ACTIVITY')
    scope='APPLICATION_ACTIVITY' if application_pattern else 'PROCESS_INSTANCE' if linked else 'APPLICATION_ACTIVITY' if pattern else 'NETWORK_REPUTATION' if indicator else 'CONNECTION_METADATA'
    confidence='HIGH' if indicator else 'MEDIUM' if pattern or (linked and process_score>0) else 'LOW'
    grade='HIGH_THREAT' if score>=70 else 'SUSPICIOUS' if score>=20 else 'POLICY_BLOCKED' if decision=='BLOCKED' else 'NORMAL'
    detail=('Current local Feodo IP/port match. ' if indicator else
            'No match in the current, limited Feodo IP/port list. ' if feed_available else 'Destination reputation is unavailable or stale. ')
    detail+=('Related behavior is linked by verified kernel process instance. ' if linked else 'No exact process behavior is linked. ')
    if pattern:detail+='Service-discovery pattern found in recorded connections; authorized scanning remains a possible explanation. '
    if support:detail+='The strongest evidence weight is increased by 20 for independent corroborating evidence; overlapping scan patterns count once. '
    detail+='Domain reputation and traffic contents are not inspected. Low priority is not proof of safety.'
    return {**unknown,'score':score,'risk_score':network_risk_priority(score),'classification':grade,
            'confidence':confidence,'factors':factors,'scope':scope,'coverage':coverage,
            'incident_id':process.get('incident_id') if linked else None,
            'attribution':'APPLICATION_ACTIVITY' if application_pattern else 'KERNEL_PROCESS_INSTANCE' if linked else pattern.get('attribution') if pattern else 'CONNECTION_METADATA',
            'score_components':{'strongest_evidence':max((v for _,v in families),default=0),'independent_support':support},
            'detail':detail}
