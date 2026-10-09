import datetime as dt
import unittest
from greyward_security_context.shell_experience import build_experience


class ShellExperienceTests(unittest.TestCase):
    def test_sensitive_denial_review_targets_resource_without_allow_action(self):
        reference = 'resource_' + 'a' * 64
        value = self.render(access_blocks=[{'resource_ref': reference, 'count': 2}])
        block = next(item for item in value['items'] if item['kind'] == 'application-security')
        self.assertEqual(block['route'], 'protected-data')
        self.assertEqual(block['resource_ref'], reference)
        self.assertEqual([action['id'] for action in block['actions']], ['open', 'dismiss'])

    def test_shared_center_checks_and_current_file_status_prevent_duplicate_warnings(self):
        checks = [{"check_id": "network.active-connection", "state": "SECURE"},
                  {"check_id": "devices.usbguard.posture", "state": "PROTECTED", "accepted_deviation": True}]
        value = self.render(shell={"posture": {"state": "PROTECTED"}, "evaluated_checks": checks,
                                   "firewall": {"state": "UNAVAILABLE"}, "malware": {"state": "UNAVAILABLE"}},
                            usb_error="Detailed device read unavailable",
                            files={"state": "AVAILABLE", "clamav": {"status": "CURRENT"}})
        self.assertEqual(value["items"], [])
        self.assertEqual(value["label"], "Protected")
        self.assertIn({"label": "Device protection", "value": "Reviewed exception"}, value["details"])

    def test_shared_check_failure_routes_to_existing_review_and_missing_check_is_not_success(self):
        value = self.render(shell={"evaluated_checks": [
            {"check_id": "network.active-connection", "state": "REVIEW_NEEDED"}]})
        self.assertEqual({item["id"] for item in value["items"]}, {"firewall-unavailable", "usb-unavailable"})
        self.assertTrue(all(item["route"] == "evidence" for item in value["items"]))
        self.assertTrue(all(item["check_id"] for item in value["items"]))

    def test_file_security_failure_is_not_hidden_by_positive_system_posture(self):
        value = self.render(shell={"posture": {"state": "PROTECTED"}, "malware": {"state": "CURRENT"}},
                            files={"state": "AVAILABLE", "clamav": {"status": "OUTDATED", "detail": "Definitions expired"}})
        self.assertEqual(value["items"][0]["id"], "definitions")
        self.assertEqual(value["items"][0]["detail"], "Definitions expired")
        self.assertEqual(value["label"], "Review needed")

    def test_initial_definition_download_is_visible_without_false_protected_claim(self):
        value = self.render(shell={'posture': {'state': 'SECURE'}, 'malware': {'state': 'INITIALIZING'}})
        self.assertEqual(value['items'], [])
        self.assertEqual(value['label'], 'Preparing protection')
        self.assertEqual(value['activity'][0]['route'], 'files')
        self.assertIn('not yet confirmed', value['activity'][0]['detail'])
        value = self.render(shell={'posture': {'state': 'SECURE'}, 'malware': {'state': 'INITIALIZING'},
                                   'notification_events': [{'event_id': 'persistence-change', 'title': 'Startup changed'}]})
        self.assertEqual(value['items'][0]['severity'], 'INFO')
        self.assertEqual(value['label'], 'Preparing protection')
        for state in ('UNAVAILABLE', 'OUTDATED', 'UPDATING'):
            value = self.render(shell={'posture': {'state': 'SECURE'}, 'malware': {'state': state}})
            self.assertEqual(value['items'][0]['id'], 'definitions')
            self.assertEqual(value['severity'], 'WARNING')

    def render(self, **kwargs):
        values = dict(shell={'posture': {'state': 'SECURE'}}, capsule={}, devices=[], usb_error=None, files={}, network={})
        values.update(kwargs)
        return build_experience(**values)

    def device(self, **kwargs):
        return dict({'connection_ref': 'attachment-1', 'name': 'Storage', 'state': 'BLOCK', 'can_persist': True, 'device_class': 'EXTERNAL_STORAGE'}, **kwargs)

    def test_negative_display_lease_never_renews_action_evidence(self):
        import datetime as dt
        now = dt.datetime(2026, 10, 8, 12, 0, tzinfo=dt.timezone.utc)
        deadline = "2026-10-08T11:59:59Z"
        value = self.render(shell={"posture": {"state": "UNAVAILABLE"}, "fresh_until": deadline,
                                  "capabilities": {"privacy_profile_change": False}},
                            usb_error="Provider cannot be read", now_value=now)
        self.assertEqual(value['fresh_until'], deadline)
        self.assertEqual(value['display_fresh_until'], "2026-10-08T12:00:30Z")
        self.assertEqual(value['posture'], 'UNAVAILABLE')
        self.assertNotEqual(value['label'], 'Protected')
        self.assertFalse(value['capabilities']['privacy_profile_change'])
        self.assertTrue(any(item['id'] == 'usb-unavailable' for item in value['items']))

    def test_positive_display_uses_original_evidence_expiry(self):
        deadline = "2026-10-08T11:59:59Z"
        value = self.render(shell={"posture": {"state": "PROTECTED"}, "fresh_until": deadline})
        self.assertEqual(value['display_fresh_until'], deadline)
        self.assertEqual(value['fresh_until'], deadline)

    def test_missing_detection_is_history_but_unknown_source_remains_reviewable(self):
        records = [{'detection_id': 'gone', 'state': 'DETECTED', 'source_status': 'MISSING'},
                   {'detection_id': 'unknown', 'state': 'DETECTED', 'source_status': 'UNKNOWN'}]
        value = self.render(files={'detections': records})
        ids = [item['id'] for item in value['items']]
        self.assertNotIn('detection:gone', ids)
        self.assertIn('detection:unknown', ids)

    def test_normal_is_compact_and_does_not_invent_activity(self):
        value = self.render()
        self.assertEqual((value['label'], value['items'], value['activity']), ('Protected', [], []))

    def test_confirmed_denial_is_context_with_review_and_dismiss_only(self):
        value = self.render(access_blocks=[{'resource_ref': 'resource_' + 'a' * 64, 'count': 3}])
        block = value['items'][0]
        self.assertEqual(block['title'], 'Sensitive access blocked')
        self.assertEqual(block['severity'], 'INFO')
        self.assertEqual([a['id'] for a in block['actions']], ['open', 'dismiss'])
        self.assertEqual(block['route'], 'protected-data')
        self.assertIn('identity is unknown', block['detail'])

    def test_sensor_activity_does_not_raise_severity(self):
        value = self.render(capsule={'signals': [{'signal_id': 'microphone:1', 'category': 'ACTIVE_SENSOR', 'state': 'ACTIVE', 'application': 'Recorder'}]})
        self.assertEqual(value['severity'], 'INFO')
        self.assertEqual(value['activity'][0]['detail'], 'Recorder')
        self.assertEqual(value['items'], [])

    def test_usb_lifetime_and_supported_actions(self):
        value = self.render(devices=[self.device()])
        self.assertEqual([a['id'] for a in value['items'][0]['actions']], ['trust_once', 'trust_always'])
        allowed = {**self.device(), 'state': 'ALLOW', 'authorized': True, 'trusted': False}
        value = self.render(devices=[allowed])
        self.assertEqual(value['items'], [])
        self.assertEqual(value['activity'][0]['detail'], 'Allowed for this connection')
        self.assertEqual(self.render(devices=[{**allowed, 'device_class': 'INTERNAL_OR_UNSUPPORTED'}])['activity'][0]['kind'], 'usb')
        self.assertEqual(self.render(devices=[])['activity'], [])
        blocked = {**self.device(), 'can_persist': False}
        self.assertEqual(len(self.render(devices=[blocked])['items'][0]['actions']), 1)

    def test_simultaneous_microphones_group_without_losing_attribution(self):
        signal = {'category': 'ACTIVE_SENSOR', 'state': 'ACTIVE'}
        value = self.render(capsule={'signals': [{**signal, 'signal_id': 'microphone:1', 'application': 'Recorder'}, {**signal, 'signal_id': 'microphone:2', 'application': 'Meeting'}]})
        self.assertEqual(len(value['activity']), 1)
        self.assertEqual(value['activity'][0]['members'], ['Recorder', 'Meeting'])
        self.assertEqual(value['items'], [])

    def test_controller_and_provider_failure_are_not_devices(self):
        self.assertEqual(self.render(devices=[self.device(controller=True)])['items'], [])
        value = self.render(usb_error='offline')
        self.assertEqual(value['items'][0]['id'], 'usb-unavailable')
        self.assertEqual(value['items'][0]['actions'], [])

    def test_operation_hides_mutation_until_readback(self):
        for state in ['PENDING', 'VERIFYING', 'INDETERMINATE']:
            value = self.render(devices=[self.device()], operations={'attachment-1': {'state': state, 'detail': 'Waiting'}})
            self.assertEqual(value['items'][0]['actions'], [])
            self.assertEqual(value['items'][0]['detail'], 'Waiting')

    def test_provider_loss_preserves_last_warning_without_action_or_false_resolution(self):
        previous = self.render(devices=[self.device()], files={'detections': [{'detection_id': 'd1', 'state': 'DETECTED'}]})['items']
        unknown = self.render(usb_error='offline', files={'state': 'UNAVAILABLE'}, previous_items=previous)
        retained = [entry for entry in unknown['items'] if entry.get('stale')]
        self.assertEqual(len(retained), 2)
        self.assertTrue(all(not entry['actions'] for entry in retained))
        self.assertEqual(self.render(previous_items=retained)['items'], [])

    def test_informational_outcome_does_not_claim_protection_failure(self):
        value = self.render(shell={'posture': {'state': 'SECURE'}, 'notification_events': [{'event_id': 'persistence-change', 'title': 'Startup changed'}]})
        self.assertEqual(value['severity'], 'INFO')
        self.assertEqual(value['reason'], 'Protection is operating')

    def test_firewall_loss_and_recovery(self):
        value = self.render(shell={'firewall': {'state': 'UNAVAILABLE'}})
        self.assertEqual(value['items'][0]['id'], 'firewall-unavailable')
        self.assertEqual(self.render(shell={'firewall': {'state': 'PUBLIC'}})['items'], [])

    def test_initial_threat_feed_does_not_raise_attention(self):
        value = self.render(network={'threat_intel': {'enabled': True, 'state': 'INITIALIZING'}})
        self.assertEqual(value['items'], [])

    def test_priority_preserves_privacy_and_resolution(self):
        args = dict(devices=[self.device()], files={'detections': [{'detection_id': 'd1', 'state': 'DETECTED', 'original_path': '/home/test/sample'}]}, network={'threat_intel': {'enabled': True, 'state': 'ERROR'}}, capsule={'signals': [{'signal_id': 'camera:1', 'category': 'ACTIVE_SENSOR', 'state': 'ACTIVE'}]})
        value = self.render(**args)
        self.assertEqual([x['severity'] for x in value['items']], ['CRITICAL', 'ACTION', 'WARNING'])
        self.assertEqual(value['activity'][0]['kind'], 'camera')
        args['files']['detections'][0]['state'] = 'QUARANTINED'
        self.assertEqual(self.render(**args)['severity'], 'ACTION')

    def test_contained_network_threat_is_bounded_and_aggregated(self):
        event = {'decision': 'BLOCKED', 'threat': {'ip': '192.0.2.1'}, 'application': 'Test', 'occurred_at': dt.datetime.now(dt.timezone.utc).isoformat()}
        value = self.render(network={'activity': [event, event]})
        self.assertEqual(len(value['items']), 1)
        self.assertEqual(value['items'][0]['severity'], 'INFO')
        event['occurred_at'] = '2000-01-01T00:00:00Z'
        self.assertEqual(self.render(network={'activity': [event]})['items'], [])
