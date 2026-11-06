"""Native tests use a real downloaded MMDB copy, never queried user endpoints."""
import datetime as dt
import gzip
import os
from pathlib import Path
import tempfile
import unittest
import urllib.error
from unittest.mock import Mock


@unittest.skipUnless(os.environ.get('GREYWARD_GEOIP_TEST_DB'), 'explicit native real-MMDB fixture')
class GeoipUpdateTests(unittest.TestCase):
    def test_monthly_skip_interruption_corruption_and_next_month_delay(self):
        from greyward_security_context.geoip_update import update, DATABASE
        payload = gzip.compress(Path(os.environ['GREYWARD_GEOIP_TEST_DB']).read_bytes())
        download = Mock(return_value=payload)
        today = dt.datetime.now(dt.timezone.utc).date()
        with tempfile.TemporaryDirectory() as directory:
            first = update(directory, today=today, download=download)
            self.assertTrue(first['downloaded'])
            original = (Path(directory)/DATABASE).read_bytes()
            second = update(directory, today=today, download=download)
            self.assertFalse(second['downloaded']); self.assertEqual(download.call_count, 1)
            future = (today.replace(day=28) + dt.timedelta(days=5)).replace(day=1)
            download.side_effect = urllib.error.URLError('offline fixture')
            with self.assertRaises(urllib.error.URLError):
                update(directory, today=future, download=download)
            self.assertEqual((Path(directory)/DATABASE).read_bytes(), original)
            download.side_effect = None; download.return_value = gzip.compress(b'not an MMDB')
            with self.assertRaises((ValueError, RuntimeError)):
                update(directory, today=future, download=download)
            self.assertEqual((Path(directory)/DATABASE).read_bytes(), original)
            self.assertFalse(list(Path(directory).glob('.country-*')))
            download.side_effect = urllib.error.HTTPError('https://download.db-ip.com', 404, 'not ready', {}, None)
            delayed = update(directory, today=future, download=download)
            self.assertFalse(delayed['downloaded']); self.assertEqual(delayed['month'], first['month'])

    def test_bounded_decompression_never_replaces_the_last_good_database(self):
        from greyward_security_context import geoip_update as module
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)/module.DATABASE; target.write_bytes(b'last good fixture')
            with patch.object(module, 'MAX_DATABASE', 64):
                with self.assertRaisesRegex(ValueError, 'size limit'):
                    module.update(directory, download=lambda month: gzip.compress(b'x'*100))
            self.assertEqual(target.read_bytes(), b'last good fixture')
            self.assertFalse(list(Path(directory).glob('.country-*')))
