import datetime as dt
import unittest
from greyward_security_context.shell_experience import build_experience


class ShellExperienceTests(unittest.TestCase):
    def render(self, **kwargs):
        values = dict(shell={'posture': {'state': 'SECURE'}}, capsule={}, devices=[], usb_error=None, files={}, network={})
        values.update(kwargs)
        return build_experience(**values)

    def device(self, **kwargs):
        return dict({'connection_ref': 'attachment-1', 'name': 'Storage', 'state': 'BLOCK', 'can_persist': True, 'device_class': 'EXTERNAL_STORAGE'}, **kwargs)

    def test_normal_is_compact_and_does_not_invent_activity(self):
        value = self.render()
        self.assertEqual((value['label'], value['items'], value['activity']), ('Protected', [], []))

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
