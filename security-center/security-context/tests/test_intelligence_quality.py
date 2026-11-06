import base64
import datetime as dt
import os
from pathlib import Path
import tempfile
import time
from unittest import TestCase, mock, skipUnless
from greyward_security_context.intelligence import Intelligence, expected_fuse_helper, expected_boot_helper, network_assessment
from greyward_security_context.process_identity import instance_key, event_time

class IntelligenceQuality(TestCase):
 def test_network_six_level_priority_has_real_evidence_and_preserves_decisions(self):
  from greyward_security_context.intelligence import network_risk_priority
  for score,expected in ((0,1),(1,2),(19,2),(20,3),(49,3),(50,4),(69,4),(70,5),(89,5),(90,6),(100,6)):
   self.assertEqual(network_risk_priority(score),expected)
  for score in (None,-1,101,True,'40'):
   self.assertIsNone(network_risk_priority(score))
  for decision in ('ALLOWED','BLOCKED'):
   event={'source':'opensnitch-statistics','decision':decision,'occurred_at':'2026-11-06T09:00:00Z','protocol':'tcp','destination':{'ip':'8.8.8.8','port':443}}
   self.assertEqual(network_assessment(event)['risk_score'],1)
   process={'score':35,'factors':[{'code':'CHAIN','points':35,'domain':'execution'}]}
   self.assertEqual(network_assessment(event,process,{'state':'ACTIVE'})['risk_score'],3)
   event['threat']={'provider':'feodo-recommended','ip':'8.8.8.8'}
   self.assertEqual(network_assessment(event)['risk_score'],1) # unverified stored tags are not fresh intelligence
   self.assertEqual(event['decision'],decision)
  self.assertIsNone(network_assessment({'source':'unknown'})['risk_score'])
 def test_connection_metadata_is_scored_without_inventing_reputation_or_process_coverage(self):
  event={'source':'opensnitch-statistics','decision':'ALLOWED','occurred_at':'2026-11-06T09:00:00Z','protocol':'tcp6','destination':{'ip':'2001:4860:4860::8888','port':443}}
  value=network_assessment(event)
  self.assertEqual(value['risk_score'],1);self.assertEqual(value['confidence'],'LOW')
  self.assertEqual(value['scope'],'CONNECTION_METADATA');self.assertIn('reputation is unavailable',value['detail'])
  self.assertFalse(value['factors']);self.assertIsNone(value['incident_id'])
  for port in (80,445,9001,49152):
   event['destination']['port']=port
   self.assertEqual(network_assessment(event)['risk_score'],1) # port alone is not suspicious behavior
  event['destination']['ip']='192.168.1.1'
  self.assertEqual(network_assessment(event)['risk_score'],1)
  event['destination']['ip']='not-an-ip'
  self.assertIsNone(network_assessment(event)['risk_score'])
  self.assertEqual(event['decision'],'ALLOWED')
 @skipUnless(hasattr(os,"pidfd_open"),"Kernel pidfd identity")
 def test_process_instance_liveness_uid_and_birth_reject_reuse(self):
  pid=os.getpid();now=dt.datetime.now(dt.timezone.utc).isoformat()
  key=instance_key(pid,occurred_at=now,expected_uid=os.getuid())
  self.assertRegex(key,r'^[a-f0-9]{40}$')
  self.assertEqual(key,instance_key(pid,exec_id=base64.b64encode(f'node:{time.clock_gettime_ns(time.CLOCK_BOOTTIME)}:{pid}'.encode()).decode()))
  self.assertIsNone(instance_key(pid,occurred_at='2000-01-01T00:00:00Z'))
  self.assertIsNone(instance_key(pid,occurred_at=now,expected_uid=os.getuid()+1))
  self.assertIsNone(instance_key(pid,exec_id=base64.b64encode(f'node:1:{pid}'.encode()).decode()))
 def test_actual_firewall_sources_and_scope_do_not_change_decision(self):
  for source in ('opensnitch-statistics','greyward-policy'):
   event={'source':source,'decision':'ALLOWED','occurred_at':'2026-10-29T12:00:00Z','protocol':'tcp','destination':{'ip':'1.1.1.1','port':443}}
   value=network_assessment(event,reputation={'state':'READY'})
   self.assertEqual(value['score'],0);self.assertEqual(value['scope'],'CONNECTION_METADATA')
   self.assertEqual(event['decision'],'ALLOWED')
   self.assertEqual(network_assessment(event,reputation={'state':'STALE'})['confidence'],'LOW')
   process={'score':35,'factors':[{'code':'CHAIN','points':35,'domain':'execution'}],'incident_id':'case'}
   value=network_assessment(event,process,{'state':'UNAVAILABLE'})
   self.assertEqual(value['score'],35);self.assertEqual(value['attribution'],'KERNEL_PROCESS_INSTANCE')
   self.assertEqual(network_assessment(event,{'score':35,'factors':[]})['score'],0)
 def test_expected_fuse_is_specific_not_a_descendant_whitelist(self):
  info=mock.Mock(st_uid=0,st_mode=0o104755)
  with mock.patch('pathlib.Path.resolve',lambda p,**kw:p),mock.patch('pathlib.Path.stat',return_value=info):
   self.assertTrue(expected_fuse_helper('/usr/bin/fusermount3','/usr/libexec/xdg-document-portal',None,False))
   self.assertTrue(expected_fuse_helper('/bin/mount','/usr/bin/fusermount3',{'expected_fuse':True},False))
   self.assertFalse(expected_fuse_helper('/usr/bin/bash','/usr/bin/fusermount3',{'expected_fuse':True},False))
   self.assertFalse(expected_fuse_helper('/usr/bin/fusermount3','/tmp/xdg-document-portal',None,False))
   self.assertFalse(expected_fuse_helper('/usr/bin/fusermount3','/usr/libexec/xdg-document-portal',None,True))
  info.st_mode=0o104777
  with mock.patch('pathlib.Path.resolve',lambda p,**kw:p),mock.patch('pathlib.Path.stat',return_value=info):
   self.assertFalse(expected_fuse_helper('/usr/bin/fusermount3','/usr/libexec/xdg-document-portal',None,False))
 def test_gap_history_survives_operational_recovery_and_restart(self):
  with tempfile.TemporaryDirectory() as root:
   engine=Intelligence(Path(root)/'db',boot='fixture');engine.record_gap('Fixture loss',2)
   self.assertEqual(engine.snapshot(1000)['sensor']['state'],'DEGRADED')
   engine.set_health('ACTIVE','Current probes verified')
   self.assertEqual(engine.snapshot(1000)['sensor']['dropped'],2)
   engine.db.close();engine=Intelligence(Path(root)/'db',boot='fixture')
   self.assertEqual(engine.snapshot(1000)['sensor']['dropped'],2)
   self.assertEqual(len(engine.gaps),1);engine.db.close()
 def test_key_lookup_is_uid_scoped_and_minimum_precedes_limit(self):
  with tempfile.TemporaryDirectory() as root:
   engine=Intelligence(Path(root)/'db',boot='fixture')
   import json
   for uid,score in [(1000,35),(1001,99),(1000,0)]:
    event={'uid':uid,'score':score,'process_key':'a'*40,'secret':str(uid)}
    engine.db.execute('INSERT INTO evidence VALUES(?,?,?,?,?)',(str(uid)+str(score),uid,time.time()+uid+score,None,json.dumps(event)))
   value=engine.snapshot(1000,{'process_keys':['a'*40],'min_score':1,'limit':1,'owner_uid':1001})
   self.assertEqual(value['events'][0]['score'],35)
   self.assertNotIn('1001',json.dumps(value));self.assertEqual(len(value['process_assessments']['a'*40]),2)
   engine.db.close()

 def test_decoration_keeps_outcomes_and_exact_instance_scope(self):
  from greyward_security_context import network_intelligence as n
  n._cache.clear()
  event={'event_id':'one','source':'opensnitch-statistics','occurred_at':'2026-10-29T12:00:00Z','decision':'ALLOWED','protocol':'tcp','destination':{'ip':'1.1.1.1','port':443},'process_key':'a'*40}
  feed={'state':'READY','last_successful_update':dt.datetime.now(dt.timezone.utc).isoformat(),'indicators':[{'ip':'2.2.2.2','port':443}]}
  with mock.patch.object(n.feodo,'load_snapshot',return_value=feed),mock.patch.object(n.intelligence_client,'snapshot',return_value={'sensor':{'state':'ACTIVE'},'process_assessments':{'a'*40:[{'score':None,'classification':'UNKNOWN'},{'score':10,'classification':'NORMAL','factors':[{'code':'CONTEXT','points':10,'domain':'context'}]}]}}) as query:
   value=n.decorate([event])[0]
   self.assertEqual(value['decision'],'ALLOWED');self.assertEqual(value['behavioral']['score'],10)
   self.assertEqual(value['behavioral']['scope'],'PROCESS_INSTANCE')
   n.decorate([event]);query.assert_called_once()
  n._cache.clear()
  with mock.patch.object(n.feodo,'load_snapshot',return_value=feed),mock.patch.object(n.intelligence_client,'snapshot',return_value={'sensor':{'state':'UNAVAILABLE'}}):
   value=n.decorate([{**event,'destination':{'ip':'2.2.2.2','port':443}}])[0]
   self.assertEqual(value['decision'],'ALLOWED');self.assertEqual(value['behavioral']['score'],70)

 @skipUnless(os.name=="posix","Direct packaged Unix entrypoint")
 def test_control_plane_direct_entrypoint_remains_executable(self):
  import subprocess,sys
  from greyward_security_context import control_plane
  result=subprocess.run([sys.executable,control_plane.__file__,'--help'],env={**os.environ,'PYTHONPATH':str(Path(control_plane.__file__).parents[1])},capture_output=True,text=True,timeout=10)
  self.assertEqual(result.returncode,0,result.stderr)
  self.assertIn('serve,set-rule,remove-rule',result.stdout)

 def test_only_validated_opaque_instance_key_survives_network_history_projection(self):
  from greyward_security_context.telemetry import event
  def record(key):return event(component='test',source='test',category='NETWORK',event_type='CONNECTION_ATTEMPT',action='CONNECT',outcome='ALLOWED',details={'process_key':key,'pid':123,'arguments':'private','rule_name':'allow'})
  self.assertEqual(record('a'*40)['details'],{'rule_name':'allow','process_key':'a'*40})
  self.assertEqual(record('../private')['details'],{'rule_name':'allow'})
 def test_initial_probes_do_not_raise_a_failure_toast(self):
  from greyward_security_context.intelligence_notices import incident_notices
  self.assertEqual(incident_notices({'sensor':{'state':'STARTING'}}),[])
  self.assertTrue(incident_notices({'sensor':{'state':'UNAVAILABLE'}}))

 def test_boot_helper_requires_exact_systemd_spawn_and_protected_executable(self):
  from greyward_security_context import intelligence as m
  parent={'binary':'/proc/self/fd/9','pid':42,'systemd_spawn':True}
  with mock.patch.object(m,'protected_system_executable',return_value=True):
   self.assertTrue(expected_boot_helper('/usr/sbin/grub2-set-bootflag','/proc/self/fd/9',parent,False,42))
   for binary,pb,kp,untrusted,pid in [
    ('/tmp/grub2-set-bootflag','/proc/self/fd/9',parent,False,42),
    ('/usr/sbin/grub2-set-bootflag','/proc/self/fd/9',parent,True,42),
    ('/usr/sbin/grub2-set-bootflag','/proc/self/fd/9',parent,False,43),
    ('/usr/sbin/grub2-set-bootflag','/proc/self/fd/9',{'pid':42},False,42),
    ('/usr/bin/bash','/proc/self/fd/9',parent,False,42),
   ]:self.assertFalse(expected_boot_helper(binary,pb,kp,untrusted,pid))
  with mock.patch.object(m,'protected_system_executable',return_value=False):
   self.assertFalse(expected_boot_helper('/usr/sbin/grub2-set-bootflag','/proc/self/fd/9',parent,False,42))
 def test_real_boot_helper_chain_does_not_trust_its_descendants(self):
  from greyward_security_context import intelligence as m
  def raw(eid,pid,binary,uid,parent):
   return {'process_exec':{'process':{'exec_id':eid,'pid':pid,'binary':binary,'uid':uid,'parent_exec_id':parent['exec_id']},'parent':parent}}
  manager={'exec_id':'manager','binary':'/usr/lib/systemd/systemd','pid':50,'uid':1000}
  trampoline={'exec_id':'trampoline','binary':'/proc/self/fd/9','pid':51,'uid':1000}
  with tempfile.TemporaryDirectory() as root,mock.patch.object(m,'protected_system_executable',return_value=True):
   engine=Intelligence(Path(root)/'db',boot='fixture')
   engine.ingest(raw('trampoline',51,'/proc/self/fd/9',1000,manager),now=100)
   value=engine.ingest(raw('helper',51,'/usr/sbin/grub2-set-bootflag',0,trampoline),now=101)
   self.assertEqual(value['score'],0);self.assertEqual(value['expected_operation'],'Boot status maintenance')
   self.assertFalse(engine.processes['helper']['authorized_privilege'])
   child=engine.ingest(raw('child',52,'/usr/bin/bash',0,{'exec_id':'helper','binary':'/usr/sbin/grub2-set-bootflag'}),now=102)
   self.assertEqual(child['score'],40);self.assertIn('PRIVILEGE_TRANSITION',[f['code'] for f in child['factors']])
   engine.db.close()
 def test_boot_helper_rejects_writable_setuid_or_non_setuid_file(self):
  from greyward_security_context import intelligence as m
  for mode in (0o104777,0o100755,0o100644):
   info=mock.Mock(st_uid=0,st_mode=mode)
   with mock.patch('pathlib.Path.resolve',lambda p,**kw:p),mock.patch('pathlib.Path.stat',return_value=info):
    self.assertFalse(m.protected_system_executable('/usr/sbin/grub2-set-bootflag',setuid=True))
