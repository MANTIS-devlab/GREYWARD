import copy
import datetime as dt
import tempfile
import unittest
from pathlib import Path

from greyward_security_context.security_notices import NoticePreferences, SensorStarts, update_notices

NOW = 1792771200
STAMP = dt.datetime.fromtimestamp(NOW, dt.timezone.utc).isoformat()


class UpdateTests(unittest.TestCase):
    def snapshot(self):
        health = {'state': 'AVAILABLE', 'last_successful_at': STAMP}
        return {'schema': 'org.greyward.update/v1', 'generated_at': STAMP,
                'providers': {'DNF5': health}, 'transaction': {'phase': 'IDLE'},
                'records': [{'provider': 'DNF5', 'provider_health': health, 'observed_at': STAMP,
                             'update_available': True, 'security_relevance': 'SECURITY_FIX'}]}

    def test_only_fresh_verified_security_updates_notify(self):
        original = self.snapshot()
        self.assertEqual(update_notices(original, NOW, 'boot')[0]['reminder_seconds'], 86400)
        variants = []
        for key, value in [('update_available', False), ('security_relevance', 'UNKNOWN'), ('observed_at', 'invalid'), ('metadata', {'compatibility_hold': True})]:
            candidate = copy.deepcopy(original)
            candidate['records'][0][key] = value
            variants.append(candidate)
        for state in ('CHECKING', 'DEGRADED', 'UNAVAILABLE'):
            candidate = copy.deepcopy(original)
            candidate['providers']['DNF5']['state'] = state
            variants.append(candidate)
        for value in ({}, {**original, 'snapshot_error': 'failed'}, {**original, 'generated_at': 'invalid'},
                      {**original, 'transaction': {'phase': 'APPLYING'}}, *variants):
            self.assertEqual(update_notices(value, NOW, 'boot'), [])
        self.assertEqual(update_notices(original, NOW + 901, 'boot'), [])
        self.assertEqual(update_notices(original, NOW - 1, 'boot'), [])

    def test_restart_requires_ready_transaction_and_current_boot(self):
        value = self.snapshot()
        value['records'] = []
        value['transaction'] = {'phase': 'READY_TO_RESTART', 'restart_required': 'REQUIRED', 'boot_id': 'boot'}
        self.assertEqual(update_notices(value, NOW, 'boot')[0]['id'], 'updates-restart')
        self.assertEqual(update_notices(value, NOW, 'different-boot'), [])
        for state in ('UNKNOWN', 'NOT_REQUIRED'):
            value['transaction']['restart_required'] = state
            self.assertEqual(update_notices(value, NOW, 'boot'), [])
        value['transaction'].update(phase='FAILED', restart_required='REQUIRED')
        self.assertEqual(update_notices(value, NOW, 'boot'), [])

    def test_malformed_optional_provider_does_not_break_other_notifications(self):
        original = self.snapshot()
        for field in ('records', 'transaction', 'providers'):
            for value in (None, 'invalid', 12, [None]):
                candidate = {**original, field: value}
                self.assertIsInstance(update_notices(candidate, NOW, 'boot'), list)
        for field in ('provider_health', 'metadata'):
            candidate = copy.deepcopy(original)
            candidate['records'][0][field] = 'invalid'
            self.assertIsInstance(update_notices(candidate, NOW, 'boot'), list)


def sensor(app='Browser', kind='microphone', state='ACTIVE'):
    return {'signal_id': kind + ':' + app, 'application': app, 'category': 'ACTIVE_SENSOR', 'state': state}


class SensorTests(unittest.TestCase):
    def test_optional_once_per_application_and_use_with_no_refresh_duplicates(self):
        starts = SensorStarts()
        self.assertEqual(starts.collect({'signals': [sensor(state='INACTIVE')]}, True, 0), [])
        first = starts.collect({'signals': [sensor()]}, True, 1)
        self.assertEqual(len(first), 1)
        self.assertEqual(starts.collect({'signals': [sensor()]}, True, 3), first)
        self.assertEqual(starts.collect({'signals': [sensor()]}, True, 17), [])
        self.assertEqual(starts.collect({'signals': [sensor(state='INACTIVE')]}, True, 18), [])
        second = starts.collect({'signals': [sensor()]}, True, 19)
        self.assertNotEqual(second[0]['id'], first[0]['id'])
        both = starts.collect({'signals': [sensor(), sensor('Recorder', 'camera')]}, True, 20)
        self.assertEqual(len(both), 2)
        self.assertIn('Recorder', both[1]['detail'])

    def test_initial_rehydration_preference_enable_and_provider_recovery_do_not_replay(self):
        starts = SensorStarts()
        active = {'signals': [sensor()]}
        self.assertEqual(starts.collect(active, False, 0), [])
        self.assertEqual(starts.collect(active, True, 1), [])
        self.assertEqual(starts.collect({'signals': [sensor(state='UNAVAILABLE')]}, True, 2), [])
        self.assertEqual(starts.collect({'signals': []}, True, 2.5), [])
        self.assertEqual(starts.collect(active, True, 3), [])
        self.assertEqual(SensorStarts().collect({'signals': []}, True, 0), [])
        starts.collect({'signals': [sensor(state='INACTIVE')]}, True, 4)
        self.assertEqual(len(starts.collect(active, True, 5)), 1)
        self.assertEqual(starts.collect({'signals': [sensor(state='STALE')]}, True, 6), [])
        self.assertEqual(starts.collect(active, True, 7), [])

    def test_preferences_default_off_persist_and_reject_non_boolean(self):
        with tempfile.TemporaryDirectory() as directory:
            prefs = NoticePreferences(Path(directory) / 'nested/settings.json')
            self.assertEqual(prefs.read(), {'sensor_start': False})
            self.assertEqual(prefs.set_sensor_start(True), {'sensor_start': True})
            self.assertEqual(NoticePreferences(prefs.path).read(), {'sensor_start': True})
            for value in (1, 'true', None, {}):
                with self.assertRaises(ValueError): prefs.set_sensor_start(value)
