"""Read-only correlation notices through the existing DMS publisher."""
import time
from .shell_experience import item

def incident_notices(snapshot, enabled=True):
    if not enabled:return []
    if snapshot.get('sensor',{}).get('state')=='STARTING':return [] # initial probes are not a failure alert
    if snapshot.get('sensor',{}).get('state') not in {'ACTIVE','DEGRADED'}:
        return [item('intelligence-unavailable','provider','WARNING','Behavioral observation unavailable','The local sensor cannot confirm behavioral coverage. Existing security controls are separate.','history',notification_stability_seconds=30)]
    notices=[]
    for incident in snapshot.get('incidents',[])[:16]:
        if incident.get('state')!='ACTIVE' or incident.get('classification') not in {'SUSPICIOUS','HIGH_THREAT'}:continue
        score=incident.get('score')
        if not isinstance(score,int) or not 35<=score<=100:continue
        critical=incident['classification']=='HIGH_THREAT'
        reasons=[f.get('explanation','') for f in incident.get('factors',[]) if f.get('points',0)>=15]
        detail=f"{score}/100 severity · {incident.get('confidence','UNKNOWN')} confidence · {incident.get('application','Process')} · {len(incident.get('timeline',[]))} correlated observations. " + (reasons[-1] if reasons else 'Review the observed evidence.')
        route='history'
        value=item('behavioral:'+incident['id'],'behavioral','CRITICAL' if critical else 'WARNING',
            f'{score}/100 · '+('High behavioral threat' if critical else 'Suspicious behavior'),detail,route,timeout_ms=0 if critical else 10000)
        value.update(incident_ref=incident['id'],behavioral_score=score,behavioral_class=incident['classification'],
            icon='greyward-intelligence-'+str(score),notification_detail=detail+' Policy outcome: not established by this sensor. No behavioral block was performed.')
        notices.append(value)
    return notices
