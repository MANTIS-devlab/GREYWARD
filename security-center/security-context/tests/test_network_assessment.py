"""Deterministic private fixtures: never submitted to the live evidence store."""
import datetime as dt
import json
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, mock
from greyward_security_context import network_intelligence as n
from greyward_security_context.network_patterns import evaluate
from greyward_security_context.intelligence import network_assessment, Intelligence
from greyward_security_context.sensor_health import ProbeTracker

NOW=dt.datetime.now(dt.timezone.utc)
def event(i,ip='192.168.77.2',port=443,**kw):
 return {'event_id':str(i),'source':'opensnitch-statistics','decision':'ALLOWED','occurred_at':(NOW+dt.timedelta(seconds=i/10)).isoformat(),'protocol':'tcp','executable':'/usr/bin/test-client','actor_uid':1000,'process_key':'a'*40,'destination':{'ip':ip,'port':port},**kw}
def feed(ip='9.9.9.9',age=0):
 return {'state':'READY','last_successful_update':(dt.datetime.now(dt.timezone.utc)-dt.timedelta(seconds=age)).isoformat(),'indicators':[{'ip':ip,'port':443}]}

class NetworkAssessment(TestCase):
 def setUp(self):n._cache.clear()
 def decorated(self,events,**kwargs):
  with mock.patch.object(n.intelligence_client,'snapshot',return_value={'sensor':{'state':'DEGRADED','dropped':20323}}),mock.patch.object(n.feodo,'load_snapshot',return_value=feed()):
   return n.decorate(events,**kwargs)
 def test_policy_denials_privacy_tools_ports_retries_and_web_fanout_are_not_threats(self):
  for app in ('/usr/bin/brave','/usr/bin/tor','/usr/bin/curl'):
   events=[event(i,ip=f'192.168.77.{i+1}',port=443,executable=app,decision='BLOCKED') for i in range(80)]
   events += [event(i+100,port=9001,executable=app,decision='BLOCKED') for i in range(200)]
   result=self.decorated(events)
   self.assertTrue(all(e['behavioral']['risk_score']==1 and e['behavioral']['classification']=='POLICY_BLOCKED' for e in result))
 def test_vertical_sweep_reaches_inspection_level_and_is_refresh_stable(self):
  events=[event(i,port=2000+i) for i in range(20)]
  result=self.decorated(events)
  self.assertEqual(result[-1]['behavioral']['risk_score'],3)
  self.assertEqual(result[-1]['behavioral']['factors'][0]['distinct_targets'],20)
  self.assertEqual(result[-1]['decision'],'ALLOWED')
  self.assertEqual(self.decorated([events[-1]],observations=events)[0]['behavioral']['score'],35)
  self.assertEqual(evaluate(events),evaluate(events+events))
 def test_sweeps_are_time_bounded_instance_scoped_and_ipv6_aware(self):
  events=[event(i,ip=f'fd42::{i+1:x}',port=22) for i in range(20)]
  self.assertEqual(self.decorated(events)[-1]['behavioral']['risk_score'],3)
  grouped=evaluate([{**e,'process_key':f'{i:040x}'} for i,e in enumerate(events)])
  self.assertEqual(grouped[events[-1]['event_id']]['attribution'],'APPLICATION_ACTIVITY')
  self.assertFalse(evaluate([{**e,'process_key':f'{i:040x}','actor_uid':None} for i,e in enumerate(events)]))
  slow=[{**e,'occurred_at':(NOW+dt.timedelta(seconds=i*61)).isoformat()} for i,e in enumerate(events)]
  self.assertFalse(evaluate(slow))
  self.assertFalse(evaluate([event(i,ip='127.0.0.1',port=i+1) for i in range(40)]))
 def test_application_scope_never_claims_a_kernel_join_or_crosses_users(self):
  events=[event(i,port=i+1,process_key=None) for i in range(20)]
  value=self.decorated(events)[-1]['behavioral']
  self.assertEqual(value['attribution'],'APPLICATION_ACTIVITY');self.assertEqual(value['scope'],'APPLICATION_ACTIVITY')
  self.assertFalse(evaluate([{**e,'actor_uid':i} for i,e in enumerate(events)]))
  self.assertFalse(evaluate([{**e,'actor_uid':None} for e in events]))
 def test_fresh_exact_ip_port_indicator_supports_high_priority_and_stale_tags_do_not(self):
  e=event(1,ip='9.9.9.9')
  value=network_assessment(e,reputation=feed())
  self.assertEqual(value['risk_score'],5);self.assertEqual(value['confidence'],'HIGH')
  for reputation in (feed(age=90000),{'state':'READY'},feed('1.1.1.1')):
   e['threat']={'provider':'feodo-recommended','ip':'9.9.9.9'}
   self.assertEqual(network_assessment(e,reputation=reputation)['risk_score'],1)
  e['destination']['port']=80
  self.assertEqual(network_assessment(e,reputation=feed())['risk_score'],1)
 def test_independent_support_is_capped_and_scan_families_do_not_double_count(self):
  e=event(1,ip='9.9.9.9')
  process={'score':40,'factors':[{'code':'PRIVILEGE','points':40,'domain':'privilege'}]}
  value=network_assessment(e,process,reputation=feed())
  self.assertEqual(value['risk_score'],6);self.assertEqual(value['score'],90)
  scan={'code':'SERVICE_HOST_SWEEP','points':35,'domain':'network-pattern','attribution':'APPLICATION_ACTIVITY'}
  self.assertEqual(network_assessment(e,process,pattern=scan)['score'],60)
  self.assertEqual(network_assessment(e,{'score':10,'factors':[{'code':'UNUSUAL','points':10,'domain':'context'}]},pattern=scan)['score'],35)
 def test_missing_metadata_stays_unknown_and_health_does_not_inflate_risk(self):
  for state in ('ACTIVE','DEGRADED','UNAVAILABLE'):
   e=event(0)
   v=network_assessment(e,sensor={'state':state,'dropped':20323})
   self.assertEqual(v['risk_score'],1);self.assertEqual(v['confidence'],'LOW')
  self.assertIsNone(network_assessment({**e,'protocol':None})['risk_score'])
 def test_real_protobuf_ingestion_through_decoration_preserves_identity_and_decision(self):
  from greyward_security_context.control_plane import NetworkState
  from greyward_security_context.proto.v1_8_0 import ui_pb2
  state=NetworkState()
  with mock.patch('greyward_security_context.control_plane.record_event'),mock.patch('greyward_security_context.control_plane.instance_key',return_value='a'*40):
   for i in range(20):
    c=ui_pb2.Connection(process_path='/usr/bin/test-client',process_id=123,user_id=1000,dst_ip='192.168.77.2',dst_port=2000+i,protocol='tcp')
    stats=ui_pb2.Statistics(daemon_version='1.8.0',events=[ui_pb2.Event(connection=c,rule=ui_pb2.Rule(action='allow'),time=event(i)['occurred_at'])])
    state.pinged(stats)
  assessed=self.decorated(state.activity)
  self.assertEqual(assessed[-1]['behavioral']['risk_score'],3)
  self.assertEqual(assessed[-1]['pid'],123);self.assertEqual(assessed[-1]['decision'],'ALLOWED')
 def test_coalescence_never_transfers_key_to_an_unverified_or_reused_pid(self):
  from greyward_security_context.control_plane import NetworkState
  from greyward_security_context.proto.v1_8_0 import ui_pb2
  state=NetworkState();c=ui_pb2.Connection(process_path='/usr/bin/test-client',process_id=123,user_id=1000,dst_ip='192.168.77.2',dst_port=443,protocol='tcp')
  with mock.patch('greyward_security_context.control_plane.record_event'),mock.patch('greyward_security_context.control_plane.instance_key',side_effect=['a'*40,None,None]):
   state._record(c,'allow','greyward-policy',event(0)['occurred_at'])
   state._record(c,'allow','opensnitch-statistics',event(1)['occurred_at'])
   self.assertEqual(len(state.activity),1);self.assertIsNone(state.activity[0]['process_key'])
   c.process_id=124;state._record(c,'allow','opensnitch-statistics',event(2)['occurred_at'])
   self.assertIsNone(state.activity[-1]['process_key']);self.assertEqual(len(state.activity),2)
 def test_probe_tracker_keeps_outstanding_probes_and_rejects_old_pid_records(self):
  tracker=ProbeTracker();tracker.issue(20,100);tracker.issue(21,115)
  record={'time':dt.datetime.now(dt.timezone.utc).isoformat(),'process_exec':{'process':{'pid':20,'uid':0,'binary':'/usr/bin/true'}}}
  with mock.patch('time.time',return_value=time.time()):
   record['time']=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(seconds=16)).isoformat()
   self.assertTrue(tracker.observe(record,116))
  self.assertEqual(tracker.status(130)['probe_state'],'VERIFIED')
  self.assertEqual(tracker.status(160)['probe_state'],'MISSING')
  tracker.issue(20,170)
  self.assertFalse(tracker.observe(record,171))

 def test_network_api_uses_complete_buffer_before_pagination(self):
  from greyward_security_context import user_bus
  events=[{**event(i,port=2000+i),'sequence':i+1} for i in range(20)]
  value={'schema':user_bus.NETWORK_SCHEMA,'opensnitch':{'state':'ACTIVE'},'activity':events,'activity_next_sequence':20}
  with mock.patch.object(user_bus,'network_summary',return_value=value),mock.patch.object(user_bus,'_with_network_location',side_effect=lambda e:e),mock.patch.object(n.intelligence_client,'snapshot',return_value={'sensor':{'state':'ACTIVE'}}),mock.patch.object(n.feodo,'load_snapshot',return_value=feed()):
   result=user_bus.network_activity(19,1)
  self.assertEqual(len(result['events']),1)
  self.assertEqual(result['events'][0]['behavioral']['risk_score'],3)
 def test_real_engine_retains_explanations_for_later_network_process_assessment(self):
  import base64,os
  from greyward_security_context.process_identity import instance_key
  with tempfile.TemporaryDirectory() as root:
   engine=Intelligence(Path(root)/'db',boot='private-fixture')
   key=instance_key(os.getpid(),occurred_at=dt.datetime.now(dt.timezone.utc).isoformat())
   self.assertIsNotNone(key)
   def raw(name,binary,parent=None,kind='process_exec',policy=None,offset=0):
    eid=base64.b64encode(f'fixture:{time.clock_gettime_ns(time.CLOCK_BOOTTIME)}:{os.getpid()}'.encode()).decode()
    proc={'exec_id':eid,'pid':os.getpid(),'uid':1000,'binary':binary}
    if parent:proc['parent_exec_id']=parent
    data={'process':proc}
    if policy:data['policy_name']=policy
    return {kind:data,'time':(NOW+dt.timedelta(seconds=offset)).isoformat()},eid
   first,parent=raw('parent','/tmp/private-fixture');engine.ingest(first)
   second,child=raw('child','/usr/bin/sh',parent,offset=1);engine.ingest(second)
   later={**second,'time':(NOW+dt.timedelta(seconds=2)).isoformat(),'process_exit':second['process_exec']};later.pop('process_exec');engine.ingest(later)
   engine.set_health('ACTIVE','Fixture only')
   snapshot=engine.snapshot(1000,{'process_keys':[key],'limit':1})
   retained=max(snapshot['process_assessments'][key],key=lambda e:e['score'])
   self.assertTrue(retained['factors']);self.assertEqual(retained['score'],45)
   with mock.patch.object(n.intelligence_client,'snapshot',return_value=snapshot),mock.patch.object(n.feodo,'load_snapshot',return_value=feed()):
    value=n.decorate([event(3,process_key=key)])[0]['behavioral']
   self.assertEqual(value['risk_score'],3);self.assertTrue(value['factors'])
   self.assertNotIn('1000',json.dumps(engine.snapshot(1001,{'process_keys':[key]})))
   engine.db.close()

 def test_transient_process_identity_failure_is_retried_without_pid_only_guessing(self):
  with tempfile.TemporaryDirectory() as root:
   engine=Intelligence(Path(root)/'db',boot='fixture')
   raw={'process_exec':{'process':{'exec_id':'fixture-exact-exec','pid':123,'uid':1000,'binary':'/usr/bin/client'}},'time':NOW.isoformat()}
   with mock.patch('greyward_security_context.intelligence.instance_key',side_effect=[None,'a'*40]) as identity:
    self.assertIsNone(engine.ingest(raw,now=100)['process_key'])
    live={'process_kprobe':{**raw['process_exec'],'policy_name':'greyward-outbound'},'time':(NOW+dt.timedelta(seconds=1)).isoformat()}
    self.assertIsNone(engine.ingest(live,now=101)['process_key'])
    live['time']=(NOW+dt.timedelta(seconds=6)).isoformat()
    self.assertEqual(engine.ingest(live,now=106)['process_key'],'a'*40)
    self.assertEqual(engine.processes['fixture-exact-exec']['process_key'],'a'*40)
    self.assertEqual(identity.call_count,2)
    identity.assert_called_with(123,exec_id='fixture-exact-exec')
   engine.db.close()

 def test_session_bus_direct_script_import_contract(self):
  import runpy
  from greyward_security_context import user_bus
  result=runpy.run_path(user_bus.__file__,run_name='greyward-private-import-check')
  self.assertIn('network_activity',result)
 def test_degraded_health_does_not_hide_a_verified_zero_score_process(self):
  value=network_assessment(event(0),{'score':0,'factors':[]},{'state':'DEGRADED'})
  self.assertEqual(value['scope'],'PROCESS_INSTANCE')
  self.assertEqual(value['risk_score'],1)
  self.assertEqual(value['confidence'],'LOW')
 def test_distinct_source_ports_are_not_coalesced_into_the_same_flow(self):
  from greyward_security_context.control_plane import NetworkState
  from greyward_security_context.proto.v1_8_0 import ui_pb2
  state=NetworkState();c=ui_pb2.Connection(process_path='/usr/bin/test-client',process_id=123,user_id=1000,src_ip='192.168.77.1',src_port=50000,dst_ip='192.168.77.2',dst_port=443,protocol='tcp')
  with mock.patch('greyward_security_context.control_plane.record_event'),mock.patch('greyward_security_context.control_plane.instance_key',return_value=None):
   state._record(c,'allow','greyward-policy',event(0)['occurred_at'])
   c.src_port=50001;state._record(c,'allow','opensnitch-statistics',event(1)['occurred_at'])
  self.assertEqual(len(state.activity),2)
  self.assertNotEqual(state.activity[0]['connection_key'],state.activity[1]['connection_key'])

 def test_intermittent_process_keys_do_not_split_one_real_application_sweep(self):
  events=[event(i,port=26000+i,process_key='a'*40 if i<9 else None) for i in range(16)]
  patterns=evaluate(events)
  self.assertEqual(patterns[events[-1]['event_id']]['distinct_targets'],16)
  self.assertEqual(patterns[events[-1]['event_id']]['attribution'],'APPLICATION_ACTIVITY')
  value=self.decorated(events)[-1]['behavioral']
  self.assertEqual(value['risk_score'],3);self.assertEqual(value['scope'],'APPLICATION_ACTIVITY')
  self.assertIn('same application and user',value['factors'][0]['explanation'])
  self.assertFalse(evaluate([{**e,'actor_uid':1000+i} for i,e in enumerate(events)]))
