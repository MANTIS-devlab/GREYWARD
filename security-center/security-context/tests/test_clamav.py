import subprocess
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1]))
from greyward_security_context.clamav import result_for

class ClamAvResultTests(unittest.TestCase):
    def test_fd_delivery_failure_never_becomes_clean(self):
        result=subprocess.CompletedProcess(['clamdscan'], 0, '/proc/self/fd/3: no reply from clamd\n', '')
        self.assertEqual(result_for(result)['state'], 'UNAVAILABLE')
    def test_removed_source_never_becomes_clean(self):
        result=subprocess.CompletedProcess(['clamdscan'], 0, '/gone: OK\\n', '')
        self.assertEqual(result_for(result, source_present=False)['state'], 'SOURCE_REMOVED')
    def test_timeout_is_typed(self):
        import greyward_security_context.clamav as clamav
        from unittest.mock import patch
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired(['clamdscan'], 1)):
            with patch.object(clamav, 'permitted', return_value=True), patch('greyward_security_context.file_security._safe_path', return_value=Path(__file__)), patch.object(clamav, 'status', return_value={'status':'CURRENT','database_version':'fixture'}), patch('greyward_security_context.file_security._open_readonly_nofollow', side_effect=subprocess.TimeoutExpired(['clamscan'], 1)):
                self.assertEqual(clamav.scan(__file__, timeout=0.001)['state'], 'TIMEOUT')
    def test_explicit_ok_is_clean(self):
        result=subprocess.CompletedProcess(['clamdscan'], 0, '/safe: OK\n', '')
        self.assertEqual(result_for(result)['state'], 'CLEAN')
    def test_explicit_found_is_threat(self):
        result=subprocess.CompletedProcess(['clamdscan'], 1, '/eicar: Eicar-Signature FOUND\n', '')
        self.assertEqual(result_for(result)['state'], 'THREAT')

    def test_missing_definitions_do_not_become_ready_from_updater_activity(self):
        import greyward_security_context.clamav as clamav
        from unittest.mock import patch
        with patch.object(clamav, '_database_files', return_value=[]), patch.object(clamav, '_freshclam_service_state', return_value='ACTIVE'), patch.object(clamav, '_version', return_value='1'):
            value = clamav.status()
        self.assertEqual(value['status'], 'UNAVAILABLE')
        self.assertEqual(value['definitions_state'], 'MISSING')

    def test_missing_definitions_report_unavailable_when_updater_is_inactive(self):
        import greyward_security_context.clamav as clamav
        from unittest.mock import patch
        with patch.object(clamav, '_database_files', return_value=[]), patch.object(clamav, '_freshclam_service_state', return_value='INACTIVE'), patch.object(clamav, '_version', return_value='1'):
            value = clamav.status()
        self.assertEqual(value['status'], 'UNAVAILABLE')

    def test_status_uses_definition_publication_not_copy_timestamp(self):
        import datetime as dt
        import tempfile
        from unittest.mock import patch
        import greyward_security_context.clamav as clamav
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            daily, main = root / 'daily.cld', root / 'main.cvd'
            now = int(dt.datetime.now().timestamp())
            def header(path, published, version=1):
                path.write_text(f'ClamAV-VDB:fixture:{version}:10:90:X:X:publisher:{published}'.ljust(512))
            header(main, now - 86400 * 365)
            header(daily, now)
            with patch.object(clamav, '_database_files', return_value=[daily, main]), patch.object(clamav, '_version', return_value='1'), patch.object(clamav, '_updater_failure', return_value=None), patch.object(clamav, '_freshclam_service_state', return_value='ACTIVE'):
                value = clamav.status()
                self.assertEqual(value['status'], 'CURRENT')
                self.assertEqual(value['realtime_protection'], 'NOT_PROVIDED')
                self.assertIsNone(value['last_successful_update'])
                generation = value['database_version']
                header(daily, now, 2)
                self.assertNotEqual(clamav.status()['database_version'], generation)
                with patch.object(clamav, '_updater_failure', return_value='ERROR: offline'):
                    self.assertEqual(clamav.status()['status'], 'CURRENT')
                    self.assertTrue(clamav.status()['update_failure_state'])
                header(daily, now - clamav.MAX_DATABASE_AGE - 60)
                self.assertEqual(clamav.status()['status'], 'OUTDATED')
                header(daily, now + 600)
                self.assertEqual(clamav.status()['status'], 'ERROR')
                daily.write_text('malformed')
                self.assertEqual(clamav.status()['status'], 'UNAVAILABLE')

    def test_cached_status_shares_probes_but_not_replaced_definitions_or_timestamps(self):
        import tempfile
        import greyward_security_context.clamav as clamav
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / 'daily.cvd'
            database.write_text('one')
            with patch.object(clamav, '_status_cache', None), \
                 patch.object(clamav, '_database_files', return_value=[database]), \
                 patch.object(clamav, 'status', side_effect=lambda: {'status': 'CURRENT', 'observed_at': 'original'}) as raw:
                for _ in range(64):
                    value = clamav.cached_status()
                    self.assertEqual(value['observed_at'], 'original')
                    value['status'] = 'mutated by caller'
                self.assertEqual(raw.call_count, 1)
                database.write_text('replacement definitions')
                self.assertEqual(clamav.cached_status()['status'], 'CURRENT')
                self.assertEqual(raw.call_count, 2)
                with patch.object(clamav.time, 'monotonic', return_value=10**12):
                    clamav.cached_status()
                self.assertEqual(raw.call_count, 3)

    def test_updater_restart_does_not_erase_an_unresolved_failure(self):
        import greyward_security_context.clamav as clamav
        self.assertEqual(clamav._update_failure(['ERROR: update failed', 'freshclam daemon started']), 'ERROR: update failed')
        self.assertIsNone(clamav._update_failure(['ERROR: update failed', 'daily.cvd updated']))

    def test_cached_current_does_not_cross_definition_expiry_after_clock_change(self):
        import datetime as dt
        import greyward_security_context.clamav as clamav
        from unittest.mock import patch
        actual_datetime = dt.datetime
        initial = actual_datetime(2026, 10, 30, tzinfo=dt.timezone.utc)
        class Clock(actual_datetime):
            current = initial
            @classmethod
            def now(cls, tz=None):
                return cls.current
        with patch.object(clamav, '_status_cache', None), \
             patch.object(clamav, '_database_files', return_value=[]), \
             patch.object(clamav.dt, 'datetime', Clock), \
             patch.object(clamav, 'status', side_effect=[
                {'status':'CURRENT', 'database_timestamp':initial.isoformat()}, {'status':'OUTDATED'}]) as raw:
            self.assertEqual(clamav.cached_status()['status'], 'CURRENT')
            Clock.current = initial + dt.timedelta(seconds=clamav.MAX_DATABASE_AGE+1)
            self.assertEqual(clamav.cached_status()['status'], 'OUTDATED')
            self.assertEqual(raw.call_count, 2)

    def test_permission_denied_is_not_initialization(self):
        from unittest.mock import patch
        import greyward_security_context.clamav as clamav
        with patch.object(clamav, '_database_files', side_effect=PermissionError()):
            value = clamav.status()
        self.assertEqual(value['status'], 'UNAVAILABLE')
        self.assertEqual(value['definitions_state'], 'UNKNOWN')

    def test_system_status_rejects_stale_conflicting_or_missing_provider(self):
        import datetime as dt
        import json
        from types import SimpleNamespace
        from unittest.mock import Mock, patch
        import greyward_security_context.clamav as clamav
        evidence = clamav.unavailable_status()
        evidence.update(status='CURRENT', engine_version='1.4.6', definitions_state='CURRENT', database_age_seconds=5)
        proxy = Mock()
        fake = SimpleNamespace(SystemBus=lambda: SimpleNamespace(get_object=lambda *a: object()), Interface=lambda *a: proxy)
        with patch.dict(sys.modules, {'dbus': fake}):
            proxy.GetClamAvStatus.return_value = json.dumps(evidence)
            self.assertEqual(clamav.system_status()['status'], 'CURRENT')
            for change in [{'engine_version': None}, {'database_age_seconds': None}, {'observed_at': (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=60)).isoformat()}]:
                proxy.GetClamAvStatus.return_value = json.dumps(dict(evidence, **change))
                self.assertEqual(clamav.system_status()['status'], 'UNAVAILABLE')
            proxy.GetClamAvStatus.side_effect = RuntimeError('transport denied')
            self.assertEqual(clamav.system_status()['status'], 'UNAVAILABLE')

    def test_symlink_source_is_not_permitted(self):
        import tempfile
        from pathlib import Path
        import greyward_security_context.clamav as clamav
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            source = root / 'source.txt'
            alias = root / 'alias.txt'
            source.write_text('fixture', encoding='utf-8')
            try:
                alias.symlink_to(source)
            except (OSError, NotImplementedError):
                self.skipTest('symlink creation is unavailable on this host')
            self.assertFalse(clamav.permitted(alias, source.stat().st_uid))

if __name__ == '__main__': unittest.main()
