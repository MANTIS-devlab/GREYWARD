import copy
import json
import os
import unittest
from unittest.mock import Mock, patch
from greyward_security_context.application_workflows import (
    ApplicationSecurityWorkflows, validate_preview, validate_operation,
)
from greyward_security_context.application_security import ApplicationReadError

OP = "operation_" + "a" * 64
RESOURCE = "resource_" + "b" * 64
PREVIEW = {"kind": "GRANT", "preview": {"grant_ref": "grant_" + "c" * 64,
    "tool_profile": "openssh-key-inspection/v1",
    "review": {"operation_ref": OP, "installation_ref": "installation_" + "d" * 64,
    "generation": "e" * 64, "resource_refs": [RESOURCE],
    "risks": ["RAW_CREDENTIAL_ACCESS", "IN_PROCESS_EXTENSIONS_SHARE_ACCESS"],
    "expected_revision": 2, "expires_after_ms": 10000}}}
RESULT = {"operation_ref": OP, "outcome": "COMPLETED", "committed_revision": 3,
          "verified_readback": True, "failure": None}

class WorkflowTests(unittest.TestCase):
    def test_administration_uses_fixed_handoff_and_truthful_status(self):
        self.transport.call.return_value = json.dumps({'schema':'greyward.administration/v1','available':False,'active':False,'authentication_window_seconds':120})
        self.assertFalse(self.api.administration_state()['available'])
        self.transport.call.assert_called_with('GetAdministrationState','',())
        self.transport.call.return_value = False
        with self.assertRaises(ApplicationReadError): self.api.open_administration()
        self.transport.call.return_value = True
        self.assertEqual(self.api.open_administration(),{'opened':True})
        self.transport.call.assert_called_with('RequestAdministration','as',(['-i'],))
        for invalid in [{'schema':'greyward.administration/v1','available':'true','active':False,'authentication_window_seconds':120}, {'available':True}]:
            self.transport.call.return_value=json.dumps(invalid)
            with self.assertRaises(ApplicationReadError): self.api.administration_state()
    def test_broker_restart_discards_leases_without_replaying_mutations(self):
        self.review()
        self.api.launches['launch_'+'f'*64] = ((1002,10,123),90,False)
        self.api.published.add(OP)
        self.transport.call.side_effect = ApplicationReadError('BROKER_CHANGED')
        with self.assertRaises(ApplicationReadError):
            self.api.operation((1002,10,123), OP, 'ApplyPolicyChange')
        self.assertFalse(self.api.owners or self.api.launches or self.api.published)
        self.transport.reset_owner.assert_called_once()
        self.assertEqual(self.transport.call.call_count, 2)
        with self.assertRaises(ApplicationReadError):
            self.api.operation((1002,10,123), OP, 'ApplyPolicyChange')
        self.assertEqual(self.transport.call.call_count, 2)

    def test_read_recovers_on_next_call_after_root_owner_change(self):
        reply=json.dumps({'schema':'greyward.application-security/v1',
            'policy_revision':1,'enforcement_health':'UNKNOWN','grants':[]})
        self.transport.call.side_effect=[ApplicationReadError('BROKER_CHANGED'),reply]
        with self.assertRaises(ApplicationReadError): self.api.grants()
        self.assertEqual(self.api.grants()['enforcement_health'],'UNKNOWN')
        self.transport.reset_owner.assert_called_once()

    def test_workflow_capabilities_are_typed_and_legacy_never_enables_controls(self):
        reply = {"schema": "greyward.application-security/v1", "policy_revision": 1,
                 "enforcement_health": "UNKNOWN", "grants": []}
        self.transport.call.return_value = json.dumps(reply)
        self.assertEqual(self.api.grants()["capabilities"], {"isolation": False, "policy_changes": False})
        reply["capabilities"] = {"isolation": True, "policy_changes": False}
        self.transport.call.return_value = json.dumps(reply)
        self.assertTrue(self.api.grants()["capabilities"]["isolation"])
        for malformed in [{"isolation": "true", "policy_changes": False},
                          {"isolation": True}, {"isolation": True, "policy_changes": False, "extra": True}]:
            reply["capabilities"] = malformed
            self.transport.call.return_value = json.dumps(reply)
            with self.assertRaises(ApplicationReadError): self.api.grants()
    def setUp(self):
        self.uid = patch.object(os, "getuid", return_value=1002, create=True)
        self.uid.start(); self.addCleanup(self.uid.stop)
        self.time = 0
        self.transport = Mock()
        self.transport.call.return_value = json.dumps(PREVIEW)
        self.record = Mock()
        self.api = ApplicationSecurityWorkflows(self.transport, lambda: self.time, self.record)

    def review(self):
        return self.api.preview((1002, 10, 123), "PreviewPolicyChange", "sast", ("/usr/bin/cat", [RESOURCE], 2))

    def test_access_event_ingestion_requires_kernel_denial_and_unknown_attribution(self):
        item = {"sequence": 1, "event_id": "appsec-denial-" + "a" * 64,
                "resource_ref": RESOURCE, "action": "READ", "decision": "DENIED", "attribution": "UNKNOWN"}
        reply = {"schema": "greyward.application-security/v1", "source_state": "AVAILABLE",
                 "cursor": 1, "truncated": False, "events": [item]}
        with patch('greyward_security_context.telemetry.user_store'), patch('greyward_security_context.telemetry.record_event', return_value=True) as record:
            self.transport.call.return_value = json.dumps(reply)
            self.api.reconcile_access_events()
            value = record.call_args.args[0]
            self.assertEqual(value['event_type'], 'SENSITIVE_ACCESS_BLOCKED')
            self.assertEqual(value['decision'], 'DENIED')
            self.assertIsNone(value['application'])
            self.assertNotIn('path', json.dumps(value))
            self.assertEqual(self.api.event_cursor, 1)
            self.assertEqual(self.api.recent_access_blocks()[0]['count'], 1)
            record.reset_mock()
            reply['events'] = [dict(item, sequence=2, attribution='EXACT')]; reply['cursor'] = 2
            self.transport.call.return_value = json.dumps(reply)
            self.api.reconcile_access_events()
            record.assert_not_called()
            self.assertEqual(self.api.event_source, 'UNAVAILABLE')
            self.assertEqual(self.api.event_cursor, 1)
            self.time = 301
            self.assertEqual(self.api.recent_access_blocks(), [])

    def test_bounded_historical_process_context_never_becomes_application_identity(self):
        item = {"sequence": 1, "event_id": "appsec-denial-" + "a" * 64,
                "resource_ref": RESOURCE, "action": "READ", "decision": "DENIED", "attribution": "UNKNOWN",
                "process": {"pid": 42, "executable_name": "python3", "source": "KERNEL_AUDIT"},
                "occurred_at_ms": 123456, "policy_revision": 6}
        reply = {"schema": "greyward.application-security/v1", "source_state": "AVAILABLE",
                 "cursor": 1, "truncated": False, "events": [item]}
        with patch('greyward_security_context.telemetry.user_store'), patch('greyward_security_context.telemetry.record_event', return_value=True) as record:
            self.transport.call.return_value = json.dumps(reply)
            self.api.reconcile_access_events()
            value = record.call_args.args[0]
            self.assertIsNone(value['application'])
            self.assertEqual(value['quality']['attribution'], 'UNKNOWN')
            self.assertEqual(value['details']['observed_process']['executable_name'], 'python3')
            self.assertEqual(value['occurred_at'], '1970-01-01T00:02:03Z')
            for change in [{'pid': True}, {'executable_name': '/private/key'}, {'source': 'USER_CLAIM'}]:
                record.reset_mock()
                reply['cursor'] = 2
                reply['events'] = [dict(item, sequence=2, process=dict(item['process'], **change))]
                self.transport.call.return_value = json.dumps(reply)
                self.api.reconcile_access_events()
                record.assert_not_called()
                self.assertEqual(self.api.event_cursor, 1)
                self.assertEqual(self.api.event_source, 'UNAVAILABLE')

    def test_peer_pid_and_start_time_bind_review_and_apply(self):
        self.review(); self.transport.call.return_value = json.dumps(RESULT)
        for actor in [(1002, 11, 123), (1002, 10, 124), (1001, 10, 123)]:
            with self.assertRaises(ApplicationReadError): self.api.operation(actor, OP, "ApplyPolicyChange")
        self.assertEqual(self.transport.call.call_count, 1)
        result = self.api.operation((1002, 10, 123), OP, "ApplyPolicyChange")
        self.assertTrue(result["verified_readback"])
        self.transport.call.assert_called_with("ApplyPolicyChange", "sb", (OP, True))
        self.api.operation((1002, 10, 123), OP)
        self.record.assert_called_once()

    def test_expiry_is_not_renewed_by_polling_and_pending_is_not_success(self):
        self.review(); self.time = 11
        with self.assertRaises(ApplicationReadError): self.api.operation((1002, 10, 123), OP, "ApplyPolicyChange")
        result = dict(RESULT, outcome="PENDING", committed_revision=None, verified_readback=False)
        self.transport.call.return_value = json.dumps(result)
        self.assertFalse(self.api.operation((1002, 10, 123), OP)["verified_readback"])
        self.record.assert_not_called()

    def test_missing_disclosure_and_forged_completion_are_rejected(self):
        for profile in (None, "arbitrary", "openssh-key-inspection/v2"):
            invalid = copy.deepcopy(PREVIEW)
            invalid["preview"]["tool_profile"] = profile
            with self.assertRaises(ApplicationReadError): validate_preview(invalid, 1002)
        value = copy.deepcopy(PREVIEW); value["preview"]["review"]["risks"] = []
        with self.assertRaises(ApplicationReadError): validate_preview(value, 1002)
        for fields in [{"verified_readback": False}, {"committed_revision": None}, {"failure": "READBACK_FAILED"}, {"operation_ref": "operation_" + "f" * 64}]:
            with self.assertRaises(ApplicationReadError): validate_operation(dict(RESULT, **fields), OP)

    def test_registration_has_no_effective_protection_badge(self):
        value = {"kind": "REGISTRATION", "preview": {"operation_ref": OP, "expected_revision": 2,
            "expires_after_ms": 10000, "resource": {"resource_ref": RESOURCE, "owner_uid": 1002,
            "category": "CUSTOM", "label": "Synthetic directory", "coverage": "UNKNOWN", "policy_revision": 3}}}
        validate_preview(value, 1002)
        value["preview"]["resource"]["coverage"] = "PROTECTED"
        with self.assertRaises(ApplicationReadError): validate_preview(value, 1002)

    def test_history_failure_does_not_change_verified_kernel_result(self):
        self.review(); self.transport.call.return_value = json.dumps(RESULT)
        for failure in [OSError("fixture full"), ImportError("history unavailable")]:
            self.record.side_effect = failure
            self.assertTrue(self.api.operation((1002, 10, 123), OP)["verified_readback"])
    def test_launch_preparation_remains_peer_bound_and_expires(self):
        reference="launch_"+"f"*64
        self.transport.call.return_value=reference
        actor=(1002,10,123)
        review=self.api.prepare_launch(actor,"held-descriptor")
        self.assertEqual(review["enforcement_health"],"UNKNOWN")
        self.transport.call.assert_called_with("PrepareGraphicalLaunch","has",("held-descriptor",[]))
        for other in [(1002,11,123),(1002,10,124)]:
            with self.assertRaises(ApplicationReadError): self.api.start_launch(other,reference)
        self.time=91
        with self.assertRaises(ApplicationReadError): self.api.start_launch(actor,reference)
        self.assertEqual(self.transport.call.call_count,1)
    def test_document_selection_uses_descriptor_and_fixed_handler_method(self):
        self.transport.call.return_value="launch_"+"f"*64
        self.api.prepare_launch((1002,10,123),"held-descriptor",handler="/usr/bin/cat",arguments=("/run/guard-document",))
        self.transport.call.assert_called_with("PrepareSelectedDocumentLaunch","hsasb",("held-descriptor","/usr/bin/cat",["/run/guard-document"],True))
