"""Decorate firewall decisions without replacing their outcome or guessing process identity."""
import copy
import datetime as dt
import time
from types import SimpleNamespace
from . import intelligence_client, feodo
from .intelligence import network_assessment
from .network_patterns import evaluate
_cache={}

def decorate(events, observations=None, context_partial=False):
    patterns=evaluate(observations if observations is not None else events)
    keys=tuple(sorted({e.get('process_key') or (e.get('details') or {}).get('process_key') for e in events if e.get('process_key') or (e.get('details') or {}).get('process_key')}))[:64]
    now=time.monotonic()
    cached=_cache.get(keys)
    if cached and now-cached[0]<5: value=cached[1]
    else:
        value=intelligence_client.snapshot({'process_keys':list(keys),'limit':1})
        _cache.clear();_cache[keys]=(now,value)
    reputation=feodo.load_snapshot()
    try:
        fresh=dt.datetime.fromisoformat(reputation.get('last_successful_update','').replace('Z','+00:00')).timestamp()
        if time.time()-fresh>86400: reputation={**reputation,'state':'STALE'}
    except (ValueError,TypeError): reputation={**reputation,'state':'UNAVAILABLE'}
    result=[]
    for item in events:
        event=copy.deepcopy(item)
        key=event.get('process_key') or (event.get('details') or {}).get('process_key')
        observed=(value.get('process_assessments') or {}).get(key,[])
        process=max(observed,key=lambda p:p.get('score') if isinstance(p.get('score'),int) else -1,default=None)
        destination=event.get('destination') or {}
        indicator=feodo.matching_indicator(SimpleNamespace(dst_ip=destination.get('ip'),dst_port=destination.get('port')),reputation) if reputation.get('state') in {'READY','EMPTY'} else None
        if indicator: event['threat']={'provider':'feodo-recommended','ip':destination.get('ip')}
        event['behavioral']=network_assessment(event,process,value.get('sensor'),reputation,patterns.get(event.get('event_id')))
        event['behavioral']['sensor_state']=(value.get('sensor') or {}).get('state','UNAVAILABLE')
        event['behavioral']['context_partial']=bool(context_partial)
        event['behavioral']['sensor_detail']=(value.get('sensor') or {}).get('detail','')
        event['behavioral']['historical_gaps']=(value.get('sensor') or {}).get('dropped',0)
        result.append(event)
    return result
