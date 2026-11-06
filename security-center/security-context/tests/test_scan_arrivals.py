import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from greyward_security_context.arrival_scanner import ArrivalQueue, ArrivalScanner, identity
from greyward_security_context.scan_cache import fingerprint, lookup, save
from greyward_security_context.telemetry import TelemetryStore


class ArrivalTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.uid = self.root.stat().st_uid
        self.path = self.root / 'arriving.txt'
        self.path.write_text('fixture')
        self.queue = ArrivalQueue(self.root / 'queue.sqlite3', self.uid)
        self.addCleanup(self.queue.connection.close)

    def test_partial_download_settle_and_restart(self):
        partial = self.root / 'file.crdownload'
        partial.write_text('unfinished')
        self.queue.observe(partial, 'generation', 0)
        self.queue.observe(self.path, 'generation', 0)
        self.assertEqual(self.queue.ready(7, {self.root}), [])
        self.assertEqual(self.queue.ready(9, {self.root}), [str(self.path)])
        other = ArrivalQueue(self.queue.path, self.uid)
        self.addCleanup(other.connection.close)
        self.assertEqual(other.ready(9, {self.root}), [str(self.path)])

    def test_changed_file_restarts_settle_and_definition_changes_rescan(self):
        self.queue.observe(self.path, 'one', 0)
        self.path.write_text('more data')
        self.assertEqual(self.queue.ready(9, {self.root}), [])
        self.assertEqual(self.queue.ready(18, {self.root}), [str(self.path)])
        self.queue.finished([str(self.path)], True, 18)
        self.queue.observe(self.path, 'one', 19)
        self.assertEqual(self.queue.ready(30, {self.root}), [])
        self.queue.observe(self.path, 'two', 31)
        self.assertEqual(self.queue.ready(40, {self.root}), [str(self.path)])

    def test_failure_backoff_disconnect_and_inflight_recovery(self):
        self.queue.observe(self.path, 'one', 0)
        self.queue.finished([str(self.path)], False, 10)
        self.assertEqual(self.queue.ready(30, {self.root}), [])
        self.assertEqual(self.queue.ready(80, {self.root}), [str(self.path)])
        self.queue.inflight('operation', [str(self.path)])
        recovered = ArrivalQueue(self.queue.path, self.uid)
        self.addCleanup(recovered.connection.close)
        self.assertEqual(recovered.inflight(), ('operation', [str(self.path)]))
        recovered.clear_inflight()
        self.assertEqual(self.queue.inflight(), (None, []))
        self.assertEqual(self.queue.ready(90, set()), [])
        self.assertEqual(self.queue.connection.execute('SELECT count(*) FROM arrivals').fetchone()[0], 0)

    def test_large_or_foreign_file_not_queued(self):
        with patch('greyward_security_context.arrival_scanner.MAX_FILE_BYTES', 1):
            self.assertIsNone(identity(self.path, self.uid))
        self.assertIsNone(identity(self.path, self.uid + 1))
        self.assertIsNone(identity(self.root / 'unrepresentable-\udcff', self.uid))

    def test_terminal_limit_stays_partial_and_waits_for_content_or_definitions(self):
        self.queue.observe(self.path, 'one', 0)
        self.queue.finished([str(self.path)], False, 10, terminal=True)
        self.assertEqual(self.queue.ready(1000000, {self.root}), [])
        self.queue.observe(self.path, 'one', 20)
        self.assertEqual(self.queue.ready(1000000, {self.root}), [])
        self.path.write_text('changed content')
        self.queue.observe(self.path, 'one', 30)
        self.assertEqual(self.queue.ready(40, {self.root}), [str(self.path)])
        self.queue.finished([str(self.path)], False, 40, terminal=True)
        self.queue.definitions_changed('two')
        self.assertEqual(self.queue.ready(60, {self.root}), [str(self.path)])

    def test_usb_backlog_cannot_starve_a_home_arrival(self):
        usb, deferred, home = (self.root / name for name in ('usb', 'deferred', 'home'))
        for path in (usb, deferred, home):
            path.write_text('fixture')
        with patch('greyward_security_context.arrival_scanner.MAX_QUEUE', 1):
            self.assertTrue(self.queue.observe(usb, 'one', 0, priority=0))
            self.assertFalse(self.queue.observe(deferred, 'one', 0, priority=0))
            self.assertTrue(self.queue.observe(home, 'one', 0, priority=1))
        self.assertEqual(self.queue.ready(20, {self.root})[0], str(home))

    def test_saturated_walk_retains_its_cursor_until_capacity_is_available(self):
        from types import SimpleNamespace
        scanner = ArrivalScanner()
        scanner.GLib = SimpleNamespace(idle_add=lambda *_: None)
        scanner._fixed_roots = set()
        scanner._walk({self.root}, self.queue, 'one')
        seen = set()
        with patch('greyward_security_context.arrival_scanner.MAX_QUEUE', 1):
            # The selected tree includes the queue DB; use an explicit fixture
            # iterator to exercise backpressure rather than scan SQLite files.
            other = self.root / 'second'
            other.write_text('fixture')
            scanner._walks[self.root] = (1, 0, iter([(self.path, self.path.stat()), (other, other.stat())]))
            for _ in range(3):
                scanner._walk_step({self.root}, self.queue, 'one')
                rows = self.queue.connection.execute('SELECT path FROM arrivals WHERE done=0').fetchall()
                seen.update(row[0] for row in rows)
                self.queue.finished([row[0] for row in rows], True, 20)
        self.assertEqual(seen, {str(self.path), str(other)})
        self.assertNotIn(self.root, scanner._walks)

    def test_live_usb_arrival_promoted_without_reconciliation_demotion(self):
        older = self.root / 'older-usb-file'
        older.write_text('fixture')
        self.queue.observe(older, 'one', 0, priority=0)
        self.queue.observe(self.path, 'one', 1, priority=0)
        self.queue.observe(self.path, 'one', 2, priority=1)
        self.queue.observe(self.path, 'one', 3, priority=0)
        self.assertEqual(self.queue.ready(20, {self.root})[0], str(self.path))

    def test_root_monitors_start_before_a_persisted_scan_finishes(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        scanner = ArrivalScanner()
        scanner._fixed_roots = {self.root}
        scanner.volumes = SimpleNamespace(get_mounts=lambda: [])
        scanner._watch = Mock()
        fake = SimpleNamespace(SystemBus=lambda: SimpleNamespace(get_object=lambda *_: None),
            Interface=lambda *_: SimpleNamespace(GetManagedObjects=lambda **_: {}),
            DBusException=RuntimeError)
        with patch.dict(sys.modules, {'dbus': fake}):
            scanner._refresh_mounts()
        scanner._watch.assert_called_once_with(self.root)
        self.assertTrue(scanner._wake.is_set())

    def test_periodic_walk_does_not_consume_a_live_arrival(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        scanner = ArrivalScanner()
        scanner._roots = scanner._fixed_roots = {self.root}
        scanner._events = {self.path}
        scanner._wake.set()
        scanner._walk = Mock()
        scanner._walk_step = Mock()
        queue = Mock()
        queue.inflight.return_value = (None, [])
        queue.ready.return_value = []
        queue.pending.return_value = 0
        proxy = SimpleNamespace(GetClamAvStatus=lambda **_: '{"status":"CURRENT","engine_version":"1","database_version":"2"}')
        fake = SimpleNamespace(SystemBus=lambda **_: SimpleNamespace(get_object=lambda *_, **__: None),
            Interface=lambda *_: proxy, DBusException=RuntimeError)
        with patch.dict(sys.modules, {'dbus': fake}), \
                patch('greyward_security_context.arrival_scanner.os.getuid', return_value=self.uid, create=True), \
                patch('greyward_security_context.arrival_scanner.ArrivalQueue', return_value=queue), \
                patch('greyward_security_context.arrival_scanner.time.sleep', side_effect=SystemExit):
            with self.assertRaises(SystemExit):
                scanner._worker()
        scanner._walk.assert_called_once()
        queue.observe.assert_called_once_with(self.path, 'scope-1|1|2', unittest.mock.ANY, priority=1)


class ReceiptTests(unittest.TestCase):
    def test_engine_limit_is_never_a_valid_scan_and_only_stable_limit_is_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'file'
            path.write_text('test')
            store = TelemetryStore(root / 'history.sqlite3')
            before = fingerprint(path)
            save(store, 1000, path, before, before, 'one', 'PARTIAL', 'operation', '2026-10-30T12:00:00Z', reason='ENGINE_LIMIT')
            value = lookup(store, 1000, path, 'one', True)
            self.assertEqual(value['validity'], 'UNKNOWN')
            self.assertEqual(value['retry_policy'], 'ON_CHANGE')
            self.assertNotIn('retry_policy', lookup(store, 1000, path, 'two', True))
            path.write_text('changed')
            self.assertNotIn('retry_policy', lookup(store, 1000, path, 'one', True))

    def test_changes_definitions_failed_scans_and_owners_invalidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # Keep the metadata database out of the selection fingerprint.
            selection = root / 'selection'
            selection.mkdir()
            source = selection / 'file.txt'
            source.write_text('one')
            store = TelemetryStore(root / 'events.sqlite3')
            before = fingerprint(selection)
            save(store, 1000, selection, before, before, 'one', 'CLEAN', 'operation', '2026-10-29T10:00:00Z')
            self.assertEqual(lookup(store, 1000, selection, 'one', True)['validity'], 'VALID')
            self.assertEqual(lookup(store, 1001, selection, 'one', True)['state'], 'NOT_SCANNED')
            self.assertEqual(lookup(store, 1000, selection, 'two', True)['validity'], 'DEFINITIONS_CHANGED')
            source.write_text('two')
            self.assertEqual(lookup(store, 1000, selection, 'one', True)['validity'], 'CHANGED')
            save(store, 1000, selection, before, fingerprint(selection), 'one', 'CLEAN', 'operation', '2026-10-29T10:00:00Z')
            self.assertEqual(lookup(store, 1000, selection, 'one', True)['state'], 'PARTIAL')

    def test_unbounded_or_inaccessible_tree_never_gets_a_valid_badge(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'one').write_text('one')
            with patch('greyward_security_context.scan_cache.MAX_TREE_ENTRIES', 1):
                self.assertIsNone(fingerprint(root))
            with patch.object(Path, 'lstat', side_effect=PermissionError):
                self.assertIsNone(fingerprint(root))
