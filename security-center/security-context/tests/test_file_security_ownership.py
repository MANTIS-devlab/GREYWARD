"""The system scanner must scope records before projection or side effects."""
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from greyward_security_context.file_security import FileSecurityManager
from greyward_security_context.telemetry import TelemetryStore


class ScanOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = TelemetryStore(Path(self.directory.name) / 'events.sqlite3')
        self.manager = FileSecurityManager(self.store)
        for owner, name in ((1000, 'mine'), (1001, 'foreign'), (None, 'historical')):
            self.store.create_file_scan({'operation_id': name, 'owner_uid': owner,
                'mode': 'FILE', 'scope': {'path': '/home/private/' + name}, 'state': 'SCANNING'})
            self.store.upsert_file_detection({'detection_id': 'det-' + name,
                'operation_id': name, 'original_path': '/home/private/' + name,
                'state': 'QUARANTINED', 'last_error': 'private path', 'file_hash': name})
            self.store.record_file_action('det-' + name, 'RESTORE', 'FAILED', '/private/staging/' + name)
            self.manager._emit(name, 'FILE_DETECTION', 'DETECTED', '/private/' + name, 'WARNING')

        connection = self.store._connect()
        with connection:
            connection.execute("UPDATE file_scan_operations SET started_at='2099-01-01T00:00:00Z' WHERE owner_uid IS NULL OR owner_uid != 1000")
            connection.execute("UPDATE file_detections SET updated_at='2099-01-01T00:00:00Z' WHERE operation_id != 'mine'")
        connection.close()

    def test_guessed_foreign_and_historical_ids_are_indistinguishable_from_absent(self):
        token = threading.Event()
        self.manager._cancel['foreign'] = token
        with patch.object(self.manager, '_mark_interrupted_if_orphaned') as reconcile:
            for name in ('foreign', 'historical', 'absent'):
                self.assertIsNone(self.manager.status(name, owner_uid=1000))
                self.assertIsNone(self.manager.cancel(name, owner_uid=1000))
            reconcile.assert_not_called()
        self.assertFalse(token.is_set())
        self.assertEqual(self.store.get_file_scan('foreign')['state'], 'SCANNING')

    def test_ownership_persists_and_nested_results_remain_private(self):
        recovered = FileSecurityManager(TelemetryStore(self.store.path))
        mine = recovered.status('mine', owner_uid=1000)
        self.assertEqual(mine['owner_uid'], 1000)
        self.assertEqual([d['detection_id'] for d in mine['detections']], ['det-mine'])
        self.assertEqual([d['detection_id'] for d in recovered.detections(owner_uid=1000)], ['det-mine'])
        encoded = str(recovered.activity(owner_uid=1000))
        self.assertNotIn('foreign', encoded)
        self.assertNotIn('historical', encoded)
        self.assertIn('mine', encoded)

    def test_owner_filter_is_applied_before_limit_and_reconciliation(self):
        self.assertEqual(self.store.list_file_scans(1, owner_uid=1000)[0]['operation_id'], 'mine')
        self.assertEqual(self.store.list_file_detections(limit=1, owner_uid=1000)[0]['detection_id'], 'det-mine')
        with patch.object(self.manager, '_mark_interrupted_if_orphaned') as reconcile:
            self.manager.reconcile_interrupted_scans(1, owner_uid=1000)
            reconcile.assert_called_once_with('mine')

    def test_idempotent_remediation_does_not_return_foreign_record(self):
        for action in ('prepare_quarantine', 'complete_quarantine', 'prepare_restore',
                       'delete_detection'):
            with self.subTest(action=action), self.assertRaises(ValueError):
                getattr(self.manager, action)('det-foreign', actor_uid=1000)
        # The owner retains legitimate idempotent access.
        self.assertEqual(self.manager.prepare_quarantine('det-mine', actor_uid=1000)['state'], 'QUARANTINED')

    def test_missing_owner_is_not_inferred_from_current_filesystem(self):
        original_stat = Path.stat

        def guarded_stat(path, *args, **kwargs):
            # Python 3.12's mkdir(exist_ok=True) stats the SQLite directory.
            # Only consulting the protected scan target would infer ownership.
            if path == Path('/home/private') or Path('/home/private') in path.parents:
                raise AssertionError('must not infer ownership')
            return original_stat(path, *args, **kwargs)

        with patch.object(Path, 'stat', guarded_stat):
            self.assertIsNone(self.manager.status('historical', owner_uid=1000))
