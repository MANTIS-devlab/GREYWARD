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

    def test_missing_definitions_report_initializing_when_packaged_updater_is_active(self):
        import greyward_security_context.clamav as clamav
        from unittest.mock import patch
        with patch.object(clamav, '_database_files', return_value=[]), patch.object(clamav, '_freshclam_service_state', return_value='ACTIVE'), patch.object(clamav, '_version', return_value='1'):
            value = clamav.status()
        self.assertEqual(value['status'], 'INITIALIZING')
        self.assertIn('packaged freshclam', value['detail'])

    def test_missing_definitions_report_unavailable_when_updater_is_inactive(self):
        import greyward_security_context.clamav as clamav
        from unittest.mock import patch
        with patch.object(clamav, '_database_files', return_value=[]), patch.object(clamav, '_freshclam_service_state', return_value='INACTIVE'), patch.object(clamav, '_version', return_value='1'):
            value = clamav.status()
        self.assertEqual(value['status'], 'UNAVAILABLE')

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
