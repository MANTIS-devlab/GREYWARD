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
            with patch.object(clamav, 'permitted', return_value=True):
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

    def test_status_metadata_is_on_demand_and_never_realtime(self):
        import datetime as dt
        import tempfile
        from unittest.mock import patch
        import greyward_security_context.clamav as clamav
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / 'daily.cld'
            database.write_text('synthetic metadata fixture')
            with patch.object(clamav, '_database_files', return_value=[database]), patch.object(clamav, '_version', return_value='1.4.6'), patch.object(clamav, '_freshclam_service_state', return_value='ACTIVE'), patch.object(clamav, '_update_failure', return_value=None):
                value = clamav.status()
                self.assertEqual(value['status'], 'CURRENT')
                self.assertEqual(value['engine_state'], 'AVAILABLE')
                self.assertEqual(value['realtime_protection'], 'NOT_PROVIDED')
                self.assertEqual(value['scan_activity'], 'UNKNOWN')
                self.assertIsNone(value['last_successful_update'])
                with patch.object(clamav, '_version', return_value=None):
                    self.assertEqual(clamav.status()['status'], 'UNAVAILABLE')
                with patch.object(clamav, '_update_failure', return_value='ERROR'):
                    self.assertEqual(clamav.status()['status'], 'ERROR')
                import os
                old = dt.datetime.now().timestamp() - clamav.MAX_DATABASE_AGE - 60
                os.utime(database, (old, old))
                self.assertEqual(clamav.status()['status'], 'OUTDATED')
                future = dt.datetime.now().timestamp() + 600
                os.utime(database, (future, future))
                self.assertEqual(clamav.status()['status'], 'ERROR')

    def test_updater_restart_does_not_erase_an_unresolved_failure(self):
        import greyward_security_context.clamav as clamav
        self.assertEqual(clamav._update_failure(['ERROR: update failed', 'freshclam daemon started']), 'ERROR: update failed')
        self.assertIsNone(clamav._update_failure(['ERROR: update failed', 'daily.cvd updated']))

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
