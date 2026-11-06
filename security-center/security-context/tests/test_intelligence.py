import json
import tempfile
import time
import unittest
from pathlib import Path
from greyward_security_context.intelligence import Intelligence, classification, network_assessment

def event(eid,binary,uid=1000,parent=None,kind='process_exec',policy=None):
    process={'exec_id':eid,'pid':1234,'uid':uid,'binary':binary,'arguments':'secret-password-should-never-be-retained'}
    if parent:process['parent_exec_id']=parent
    data={'process':process}
    if policy:data['policy_name']=policy
    return {kind:data,'time':str(time.time_ns())}

class IntelligenceTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.engine=Intelligence(Path(self.directory.name)/'evidence.sqlite3',boot='test-boot')
        self.addCleanup(self.engine.db.close)
    def test_policy_denial_and_unknown_are_distinct_from_behavior(self):
        self.assertEqual(classification(0,'BLOCKED'),'POLICY_BLOCKED')
        self.assertEqual(classification(0,'ALLOWED'),'NORMAL')
        self.assertEqual(classification(90,evaluated=False),'UNKNOWN')
        value=network_assessment({'decision':'BLOCKED','source':'opensnitch','occurred_at':'2020-01-01T00:00:00Z'})
        self.assertEqual(value['classification'],'UNKNOWN');self.assertIsNone(value['score'])
    def test_temporary_execution_alone_is_not_an_alert_and_arguments_not_retained(self):
        value=self.engine.ingest(event('one','/tmp/downloaded-app'))
        self.assertEqual(value['classification'],'NORMAL')
        self.assertEqual(self.engine.snapshot(1000)['incidents'],[])
        self.assertNotIn('secret-password',json.dumps(self.engine.snapshot(1000)))
    def test_exact_chain_independent_factors_and_dedup(self):
        self.engine.ingest(event('parent','/tmp/tool'))
        self.engine.ingest(event('child','/usr/bin/sh',parent='parent'))
        self.engine.ingest(event('writer','/usr/bin/python3',parent='child'))
        value=self.engine.ingest(event('writer','/usr/bin/python3',kind='process_kprobe',policy='greyward-persistence'))
        self.assertEqual(value['classification'],'HIGH_THREAT')
        incident=self.engine.snapshot(1000)['incidents'][0]
        self.assertEqual(incident['score'],80)
        self.assertEqual(len(incident['chain']),3)
        self.engine.ingest(event('writer','/usr/bin/python3',kind='process_kprobe',policy='greyward-persistence'))
        self.assertEqual(self.engine.snapshot(1000)['incidents'][0]['score'],80)
    def test_same_pid_is_not_an_execution_identity(self):
        self.engine.ingest(event('one','/tmp/one'))
        value=self.engine.ingest(event('two','/usr/bin/sh'))
        self.assertEqual(value['score'],0);self.assertIsNone(value['incident_id'])
    def test_uid_scope_before_limit_and_query_payload_cannot_override(self):
        self.engine.ingest(event('one','/tmp/one',1000))
        self.engine.ingest(event('two','/tmp/private-other-user',1001))
        view=self.engine.snapshot(1000,{'owner_uid':1001,'limit':1})
        self.assertEqual(len(view['events']),1)
        self.assertNotIn('private-other-user',json.dumps(view))
    def test_channel_filter_precedes_limit_and_preserves_uid_and_destination(self):
        self.engine.ingest(event('one','/usr/bin/curl'))
        request=event('one','/usr/bin/curl',kind='process_kprobe',policy='greyward-outbound')
        request['process_kprobe']['args']=[{'sockaddr_arg':{'addr':'1.1.1.1','port':443}}]
        self.engine.ingest(request)
        self.engine.ingest(event('other','/tmp/private-other-user',1001))
        system=self.engine.snapshot(1000,{'channel':'SYSTEM','limit':1})
        network=self.engine.snapshot(1000,{'channel':'NETWORK','limit':1})
        self.assertEqual(system['events'][0]['channel'],'SYSTEM')
        self.assertEqual(network['events'][0]['channel'],'NETWORK')
        self.assertEqual(network['events'][0]['destination'],{'ip':'1.1.1.1','port':443})
        self.assertNotIn('private-other-user',json.dumps(system)+json.dumps(network))
        self.assertEqual(self.engine.snapshot(1000,{'incident_id':'incident-'+'a'*24})['events'],[])

    def test_restart_preserves_own_incident_and_does_not_invent_ancestry(self):
        self.engine.ingest(event('parent','/tmp/tool'))
        self.engine.ingest(event('child','/usr/bin/sh',parent='parent'))
        other=Intelligence(self.engine.path,boot='test-boot');self.addCleanup(other.db.close)
        self.assertEqual(len(other.snapshot(1000)['incidents']),1)
        value=other.ingest(event('new','/usr/bin/sh',parent='missing-parent'))
        self.assertEqual(value['score'],0)
    def test_normal_system_churn_keeps_ancestry_without_filling_user_evidence(self):
        self.engine.ingest(event('ordinary', '/usr/bin/editor'))
        for i in range(80):
            self.engine.ingest(event('system-' + str(i), '/usr/bin/true', uid=0))
        self.assertEqual(self.engine.snapshot(0)['events'], [])
        self.assertIn('system-79', self.engine.processes)
        self.assertEqual(len(self.engine.snapshot(1000)['events']), 1)
        suspicious = event('root-suspicious', '/tmp/unexpected', uid=0)
        self.engine.ingest(suspicious)
        # Suspicious system evidence must remain available to its owner.
        self.assertTrue(self.engine.snapshot(0)['events'])

    def test_retention_is_fair_and_reports_actual_owner_span(self):
        from unittest.mock import patch
        self.engine.ingest(event('quiet-owner', '/usr/bin/editor', uid=1000))
        with patch('greyward_security_context.intelligence.MAX_EVENTS', 12):
            for i in range(24):
                self.engine.last_prune = 0
                self.engine.ingest(event('busy-owner-' + str(i), '/usr/bin/editor', uid=1001))
        quiet = self.engine.snapshot(1000)
        self.assertEqual(len(quiet['events']), 1)
        self.assertEqual(quiet['retention']['records'], 1)
        self.assertIsNotNone(quiet['retention']['oldest_observed_at'])

    def test_throttle_is_degraded_not_healthy(self):
        self.engine.ingest({'rate_limit_info':{'number_of_dropped_process_events':27}})
        view=self.engine.snapshot(1000);self.assertEqual(view['sensor']['state'],'DEGRADED')
        self.assertEqual(view['sensor']['dropped'],27)
    def test_procfs_initial_inventory_is_not_new_activity(self):
        value=event('old','/tmp/old');value['process_exec']['process']['flags']='procFS'
        self.assertIsNone(self.engine.ingest(value))
        self.assertEqual(self.engine.snapshot(1000)['events'],[])

    def test_base_event_replay_and_local_connections_do_not_escalate(self):
        self.engine.ingest(event('parent','/tmp/tool'))
        self.engine.ingest(event('parent','/tmp/tool'))
        self.assertEqual(len(self.engine.snapshot(1000)['events']),1)
        value=event('parent','/tmp/tool',kind='process_kprobe',policy='greyward-outbound')
        value['process_kprobe']['args']=[{'sockaddr_arg':{'addr':'127.0.0.1'}}]
        self.assertEqual(self.engine.ingest(value)['score'],10)
    def test_regular_public_communication_needs_an_unusual_chain(self):
        base=time.time()
        self.engine.ingest(event('parent','/tmp/tool'),now=base)
        self.engine.ingest(event('child','/usr/bin/sh',parent='parent'),now=base+1)
        for index in range(6):
            value=event('child','/usr/bin/sh',kind='process_kprobe',policy='greyward-outbound')
            value['process_kprobe']['args']=[{'sockaddr_arg':{'addr':'1.1.1.1'}}]
            self.engine.ingest(value,now=base+10+index*15)
        incident=self.engine.snapshot(1000)['incidents'][0]
        self.assertEqual(incident['score'],80)
        self.assertEqual(incident['confidence'],'MEDIUM')
        self.assertIn('REGULAR_COMMUNICATION',[f['code'] for f in incident['factors']])

    def test_rotation_recovers_retained_inode_and_drains_every_backup_before_current(self):
        import os
        from greyward_security_context.intelligence import retained_sensor_file, rotation_successor
        root=Path(self.directory.name);raw=root/'events.jsonl';raw.write_text('one')
        inode=raw.stat().st_ino;first=root/'events-first.jsonl';raw.rename(first);raw.write_text('two')
        self.assertEqual(retained_sensor_file(raw,inode),first)
        self.assertEqual(rotation_successor(raw,inode),raw)
        second=root/'events-second.jsonl';raw.rename(second);os.utime(second,ns=(time.time_ns()+1000000,time.time_ns()+1000000));raw.write_text('three')
        self.assertEqual(rotation_successor(raw,inode),second)
        self.assertEqual(rotation_successor(raw,second.stat().st_ino),raw)
        first.unlink()
        self.assertIsNone(retained_sensor_file(raw,inode))
        self.assertIsNone(rotation_successor(raw,inode))

    def test_ambiguous_kernel_cache_attribution_is_neutral(self):
        value=event('ambiguous','/tmp/candidate');value['process_exec']['process']['flags']='taskWalk'
        result=self.engine.ingest(value)
        self.assertEqual(result['classification'],'UNKNOWN')
        self.assertIsNone(result['score'])
        self.assertIsNone(result['incident_id'])
        self.assertEqual(self.engine.snapshot(1000)['incidents'],[])

    def test_stale_worker_heartbeat_never_claims_active_coverage(self):
        self.engine.set_health('ACTIVE','fixture')
        self.engine.health_checked_at-=60
        self.assertEqual(self.engine.snapshot(1000)['sensor']['state'],'UNAVAILABLE')

    def test_document_interpreter_lineage_survives_without_a_temporary_binary(self):
        value=event('shell','/usr/bin/sh');value['process_exec']['parent']={'exec_id':'document','uid':1000,'binary':'/usr/lib/greyward-office/writer/writer'}
        self.assertEqual(self.engine.ingest(value)['score'],35)
        self.engine.ingest(event('child','/usr/bin/python3',parent='shell'))
        result=self.engine.ingest(event('child','/usr/bin/python3',kind='process_kprobe',policy='greyward-persistence'))
        self.assertEqual(result['score'],70)
        self.assertEqual(len(self.engine.snapshot(1000)['incidents']),1)

    def test_privilege_transition_follows_exact_actor_without_crossing_other_users(self):
        self.engine.ingest(event('actor','/usr/bin/bash',1000))
        value=event('root-child','/usr/bin/custom-helper',0,parent='actor');value['process_exec']['parent']={'exec_id':'actor','uid':1000,'binary':'/usr/bin/bash'}
        result=self.engine.ingest(value)
        self.assertEqual(result['uid'],1000);self.assertEqual(result['euid'],0)
        self.assertEqual(result['classification'],'SUSPICIOUS')
        foreign=event('different-user','/usr/bin/bash',1001,parent='root-child')
        self.engine.ingest(foreign)
        self.assertNotIn('different-user',json.dumps(self.engine.snapshot(1000)))
    def test_known_privilege_broker_is_not_a_behavioral_anomaly(self):
        self.engine.ingest(event('actor','/usr/bin/bash',1000))
        value=event('sudo','/usr/bin/sudo',0,parent='actor');value['process_exec']['parent']={'exec_id':'actor','uid':1000,'binary':'/usr/bin/bash'}
        result=self.engine.ingest(value)
        self.assertEqual(result['uid'],1000);self.assertEqual(result['score'],0)

    def test_new_episode_keeps_prior_incident_history(self):
        base=time.time();self.engine.ingest(event('actor','/tmp/tool'),now=base)
        self.engine.ingest(event('shell','/usr/bin/sh',parent='actor'),now=base+1)
        first=self.engine.snapshot(1000)['incidents'][0]['id']
        self.engine.ingest(event('shell','/usr/bin/sh',kind='process_kprobe',policy='greyward-persistence'),now=base+700)
        # The new episode is evaluated independently; the first case is retained.
        ids=[i['id'] for i in self.engine.snapshot(1000)['incidents']]
        self.assertIn(first,ids)
        row=self.engine.db.execute('SELECT body FROM evidence ORDER BY occurred DESC LIMIT 1').fetchone()
        self.assertNotEqual(json.loads(row[0]).get('incident_id'),first)

    def test_sync_intelligence_client_never_attaches_workers_to_the_shared_glib_loop(self):
        import inspect
        from greyward_security_context import intelligence_client
        source=inspect.getsource(intelligence_client.snapshot)
        self.assertIn('mainloop=dbus.mainloop.NULL_MAIN_LOOP',source)

    def test_classification_filter_and_severity_sort_are_applied_before_pagination(self):
        self.engine.ingest(event('ordinary','/usr/bin/true'))
        self.engine.ingest(event('actor','/tmp/tool'))
        self.engine.ingest(event('shell','/usr/bin/sh',parent='actor'))
        view=self.engine.snapshot(1000,{'classification':'SUSPICIOUS','limit':1})
        self.assertEqual(len(view['events']),1)
        self.assertEqual(view['events'][0]['classification'],'SUSPICIOUS')
        self.assertEqual(self.engine.snapshot(1000,{'sort':'severity','limit':1})['events'][0]['score'],45)

    def test_attachment_receipt_must_match_actual_daemon_and_current_boot(self):
        from greyward_security_context.intelligence import attested_policy_links
        p=Path(self.directory.name)/'receipt.json'
        self.assertFalse(any(attested_policy_links(123,'boot',p).values()))
        p.write_text(json.dumps({'pid':123,'boot':'boot','links':{'persistence':True,'outbound':True}}))
        self.assertTrue(all(attested_policy_links(123,'boot',p).values()))
        self.assertFalse(any(attested_policy_links(124,'boot',p).values()))
        self.assertFalse(any(attested_policy_links(123,'other-boot',p).values()))
        self.assertFalse(any(attested_policy_links(0,'boot',p).values()))

    def test_replayed_network_record_never_counts_again_in_a_correlated_pattern(self):
        self.engine.ingest(event('actor','/tmp/tool'))
        self.engine.ingest(event('shell','/usr/bin/sh',parent='actor'))
        e=event('shell','/usr/bin/sh',kind='process_kprobe',policy='greyward-outbound')
        e['process_kprobe']['args']=[{'sockaddr_arg':{'addr':'1.1.1.1'}}]
        self.engine.ingest(e)
        for _ in range(10):self.assertIsNone(self.engine.ingest(e))
        incident=self.engine.snapshot(1000)['incidents'][0]
        internal=self.engine.incidents[incident['id']]
        self.assertEqual(len(internal['_connections']['1.1.1.1']),1)

    def test_large_valid_path_metadata_is_evicted_before_the_hard_database_quota(self):
        self.engine.db.execute('PRAGMA max_page_count=8192')
        long_path='/tmp/'+'/'.join(['\U00010000'*55]*8)+'/tool'
        for n in range(3500):self.engine.ingest(event('long-'+str(n),long_path+str(n)))
        count=self.engine.db.execute('SELECT count(*) FROM evidence').fetchone()[0]
        self.assertLess(count,3500)
        used=(self.engine.db.execute('PRAGMA page_count').fetchone()[0]-self.engine.db.execute('PRAGMA freelist_count').fetchone()[0])*4096
        self.assertLess(used,32*1024*1024)
