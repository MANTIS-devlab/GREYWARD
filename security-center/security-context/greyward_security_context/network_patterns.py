"""Bounded retrospective network-pattern evaluation. No probes or external lookups.

The firewall remains the sole decision authority. Patterns describe observed
application activity, not verified malicious intent. A refresh never adds state.
"""
import hashlib
import ipaddress
import re
from collections import deque, Counter
from .process_identity import event_time

SOURCES = {'opensnitch','opensnitch-statistics','greyward-policy','opensnitch-stats','opensnitch-notification'}
MAX_RECORDS = 4096
WINDOW = 60
SERVICE_PORTS = {21,22,23,135,139,445,1433,2375,3306,3389,5432,5900,6379,9200,27017}

def normalized(event):
    if not isinstance(event,dict) or event.get('source') not in SOURCES:
        return None
    destination=event.get('destination') or {}
    if not isinstance(destination,dict):return None
    when=event_time(event.get('occurred_at'))
    port=destination.get('port',event.get('port'))
    protocol=str(event.get('protocol') or '').lower().removesuffix('6')
    decision=event.get('decision',event.get('outcome'))
    try:address=ipaddress.ip_address(destination.get('ip') or '')
    except ValueError:return None
    if when is None or protocol not in {'tcp','udp'} or type(port) is not int or not 1<=port<=65535 or decision not in {'ALLOWED','BLOCKED'}:return None
    if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or address.is_reserved:return None
    details=event.get('details') or {}
    executable=event.get('executable') or details.get('executable')
    key=event.get('process_key') or details.get('process_key')
    # Name/domain/PID alone cannot connect actors. Historical records without
    # a verified instance or executable are deliberately left uncorrelated.
    uid=event.get('actor_uid')
    actor=('instance',key,uid) if isinstance(key,str) and re.fullmatch('[0-9a-f]{40}',key) else ('application',executable,uid) if isinstance(executable,str) and executable.startswith('/') and type(uid) is int and uid>=0 else None
    if actor is None:return None
    actors=[actor]
    if isinstance(executable,str) and executable.startswith('/') and type(uid) is int and uid>=0:
        application=('application',executable,uid)
        if application not in actors:actors.append(application)
    ident=event.get('event_id') or hashlib.sha256(repr((actor,when,str(address),port,protocol,decision)).encode()).hexdigest()
    return {'event_id':ident,'time':when,'actor':actor,'actors':actors,'address':str(address),'port':port,'protocol':protocol,
            'subnet':str(ipaddress.ip_network(str(address)+('/24' if address.version==4 else '/64'),strict=False))}

def evaluate(events):
    """Return factors per observation, using only evidence at/before its time.

    One scan family contributes once even if both patterns match. Web/CDN/DNS
    fan-out, retries, Tor and high connection counts alone add no risk.
    """
    unique={}
    for event in list(events)[-MAX_RECORDS:]:
        value=normalized(event)
        if value:unique[value['event_id']]=value
    ordered=sorted(unique.values(),key=lambda e:(e['time'],e['event_id']))
    windows={}; result={}
    for e in ordered:
        if e['protocol']!='tcp':continue
        # Evaluate both scopes: intermittent identity availability and separate
        # short-lived processes must not split one application/UID pattern.
        keys=[]
        for actor in e['actors']:
            keys.append(('vertical',actor,e['address']))
            if e['port'] in SERVICE_PORTS:keys.append(('horizontal',actor,e['subnet'],e['port']))
        factors=[]
        for group in keys:
            queue,counts=windows.setdefault(group,(deque(),Counter()))
            while queue and queue[0][0]<e['time']-WINDOW:
                _,old=queue.popleft();counts[old]-=1
                if not counts[old]:del counts[old]
            item=e['port'] if group[0]=='vertical' else e['address']
            queue.append((e['time'],item));counts[item]+=1
            threshold=12 if group[0]=='vertical' else 16
            if len(counts)<threshold:continue
            code='SERVICE_PORT_SWEEP' if group[0]=='vertical' else 'SERVICE_HOST_SWEEP'
            description=(f"{len(counts)} distinct TCP service ports on one destination" if group[0]=='vertical' else f"{len(counts)} destinations in one local network prefix on TCP port {e['port']}")
            application_scope=group[1][0]=='application'
            if application_scope:description+=' across observed instances of the same application and user'
            factors.append({'code':code,'points':35,'domain':'network-pattern','family':'scan',
                'explanation':description+' within 60 seconds. This resembles service discovery; an authorized scanner may be legitimate.',
                'observations':len(queue),'distinct_targets':len(counts),'window_seconds':WINDOW,
                'attribution':'APPLICATION_ACTIVITY' if application_scope else 'KERNEL_PROCESS_INSTANCE',
                'first_observed_at':queue[0][0],'last_observed_at':e['time']})
        if factors:result[e['event_id']]=max(factors,key=lambda f:(f['distinct_targets'],f['attribution']=='KERNEL_PROCESS_INSTANCE'))
    return result
