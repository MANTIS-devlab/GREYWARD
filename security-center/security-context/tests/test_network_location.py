import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

from greyward_security_context import network_location


class NetworkLocationTests(unittest.TestCase):
    def setUp(self):
        self.fake_mmdb = patch.object(network_location, "maxminddb", SimpleNamespace(open_database=lambda p: SimpleNamespace(get=lambda ip: {"country":{"iso_code":"FR"}}, close=lambda: None)))
        self.fake_mmdb.start(); self.addCleanup(self.fake_mmdb.stop)
        self.addCleanup(network_location._readers.clear)
        network_location._readers.clear()
        network_location.country_code_for_ip.cache_clear()
        network_location.country_resolution_for_ip.cache_clear()
        network_location._geofeed_entries.cache_clear()

    def tearDown(self):
        network_location.country_code_for_ip.cache_clear()
        network_location.country_resolution_for_ip.cache_clear()
        network_location._geofeed_entries.cache_clear()

    def test_uses_local_mmdblookup_result_for_public_ip(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "country.mmdb"
            database.touch()
            completed = type("Completed", (), {"returncode": 0, "stdout": 'country: { iso_code: "FR" }'})()
            with patch.dict(os.environ, {"GREYWARD_GEOIP_DB": str(database), "GREYWARD_GEOIP_DB_SECONDARY": "/nonexistent-greyward-fixture", "GREYWARD_GEOIP_LEGACY_DB": "/nonexistent-greyward-fixture", "GREYWARD_GEOFEED_DB": "/nonexistent-greyward-fixture"}), patch.object(network_location.subprocess, "run", return_value=completed) as run:
                self.assertEqual(network_location.country_code_for_ip("8.8.8.8"), "FR")
            run.assert_not_called()

    def test_does_not_lookup_private_or_malformed_addresses(self):
        with patch.object(network_location.subprocess, "run") as run:
            self.assertEqual(network_location.country_code_for_ip("192.168.1.8"), "")
            self.assertEqual(network_location.country_code_for_ip("not-an-ip"), "")
        run.assert_not_called()

    def test_ipv6_mapped_ipv4_and_special_ranges(self):
        for value in ('::1', 'fe80::1', 'fc00::1', 'ff02::1', '192.0.2.1', '2001:db8::1', '224.0.0.1', '127.0.0.1', '::ffff:192.168.1.2'):
            self.assertIsNone(network_location._public_address(value))
        self.assertEqual(network_location._public_address('::ffff:8.8.8.8'), '8.8.8.8')
        self.assertEqual(network_location._public_address('2001:4860:4860::8888'), '2001:4860:4860::8888')

    def test_one_reader_reused_and_atomically_replaced_without_subprocesses(self):
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / 'country.mmdb'
            database.write_bytes(b'first')
            old = Mock(); old.get.return_value = {'country': {'iso_code': 'FR'}}
            new = Mock(); new.get.return_value = {'country': {'iso_code': 'DE'}}
            with patch.object(network_location.maxminddb, 'open_database', side_effect=[old, new]) as opened, patch.object(network_location.subprocess, 'run') as run:
                for _ in range(200):
                    self.assertEqual(network_location._country_from_mmdb('2001:4860:4860::8888', database), 'FR')
                replacement = database.with_suffix('.new'); replacement.write_bytes(b'second')
                replacement.replace(database)
                self.assertEqual(network_location._country_from_mmdb('8.8.8.8', database), 'DE')
                self.assertEqual(opened.call_count, 2)
                old.close.assert_called_once()
                run.assert_not_called()

    def test_missing_local_database_is_unknown_without_network_fallback(self):
        with patch.dict(os.environ, {"GREYWARD_GEOIP_DB_SECONDARY": "/nonexistent-greyward-fixture", "GREYWARD_GEOIP_LEGACY_DB": "/nonexistent-greyward-fixture", "GREYWARD_GEOFEED_DB": "/nonexistent-greyward-fixture"}), patch.object(network_location, "_database_path", return_value=None), patch.object(network_location.subprocess, "run") as run:
            self.assertEqual(network_location.country_code_for_ip("8.8.8.8"), "")
        run.assert_not_called()

    def test_converged_local_sources_have_high_confidence(self):
        with tempfile.TemporaryDirectory() as directory:
            primary = Path(directory) / "primary.mmdb"
            secondary = Path(directory) / "secondary.mmdb"
            feed = Path(directory) / "geofeed.csv"
            primary.touch()
            secondary.touch()
            feed.write_text("8.8.8.0/24,FR,,,\n", encoding="utf-8")
            completed = type("Completed", (), {"returncode": 0, "stdout": 'country: { iso_code: "FR" }'})()
            environment = {
                "GREYWARD_GEOIP_DB": str(primary),
                "GREYWARD_GEOIP_DB_SECONDARY": str(secondary),
                "GREYWARD_GEOFEED_DB": str(feed),
            }
            with patch.dict(os.environ, environment), patch.object(network_location.subprocess, "run", return_value=completed):
                resolution = network_location.country_resolution_for_ip("8.8.8.8")
            self.assertEqual(resolution["country_code"], "FR")
            self.assertEqual(resolution["confidence"], "HIGH")
            self.assertTrue(resolution["converged"])
            self.assertEqual(resolution["source_count"], 3)

    def test_disagreement_keeps_deterministic_country_with_low_confidence(self):
        with tempfile.TemporaryDirectory() as directory:
            primary = Path(directory) / "primary.mmdb"
            secondary = Path(directory) / "secondary.mmdb"
            feed = Path(directory) / "geofeed.csv"
            primary.touch()
            secondary.touch()
            feed.write_text("8.8.8.0/24,US,,,\n", encoding="utf-8")
            results = iter((
                type("Completed", (), {"returncode": 0, "stdout": 'country: { iso_code: "FR" }'})(),
                type("Completed", (), {"returncode": 0, "stdout": 'country: { iso_code: "US" }'})(),
            ))
            environment = {
                "GREYWARD_GEOIP_DB": str(primary),
                "GREYWARD_GEOIP_DB_SECONDARY": str(secondary),
                "GREYWARD_GEOFEED_DB": str(feed),
            }
            with patch.dict(os.environ, environment), patch.object(network_location.subprocess, "run", side_effect=lambda *args, **kwargs: next(results)):
                resolution = network_location.country_resolution_for_ip("8.8.8.8")
            self.assertEqual(resolution["country_code"], "FR")
            self.assertEqual(resolution["confidence"], "LOW")
            self.assertFalse(resolution["converged"])
            self.assertEqual(resolution["source_count"], 3)

    def test_geofeed_can_supply_country_when_geoip_is_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            feed = Path(directory) / "geofeed.csv"
            feed.write_text("8.8.0.0/16,DE,,,\n8.8.8.0/24,FR,,,\n", encoding="utf-8")
            environment = {
                "GREYWARD_GEOIP_DB": "/nonexistent-greyward-fixture",
                "GREYWARD_GEOIP_DB_SECONDARY": "/nonexistent-greyward-fixture",
                "GREYWARD_GEOFEED_DB": str(feed),
            }
            with patch.dict(os.environ, environment), patch.object(network_location.subprocess, "run") as run:
                resolution = network_location.country_resolution_for_ip("8.8.8.8")
            self.assertEqual(resolution["country_code"], "FR")
            self.assertEqual(resolution["confidence"], "MEDIUM")
            self.assertTrue(resolution["converged"])
            run.assert_not_called()

    def test_packaged_legacy_geoip_supplies_country_when_mmdb_is_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "GeoIP.dat"
            database.touch()
            completed = type("Completed", (), {"returncode": 0, "stdout": "GeoIP Country Edition: FR, France"})()
            environment = {
                "GREYWARD_GEOIP_DB": "/nonexistent-greyward-fixture",
                "GREYWARD_GEOIP_DB_SECONDARY": "/nonexistent-greyward-fixture",
                "GREYWARD_GEOIP_LEGACY_DB": str(database),
                "GREYWARD_GEOFEED_DB": "/nonexistent-greyward-fixture",
            }
            with patch.dict(os.environ, environment), patch.object(network_location.subprocess, "run", return_value=completed) as run:
                resolution = network_location.country_resolution_for_ip("8.8.8.8")
            self.assertEqual(resolution["country_code"], "FR")
            self.assertEqual(run.call_args.args[0][0], "geoiplookup")
            self.assertEqual(resolution['confidence'], 'LOW')
            self.assertEqual(resolution['availability'], 'AVAILABLE')

    def test_domain_suffix_never_supplies_endpoint_country_without_ip_data(self):
        with patch.dict(os.environ, {"GREYWARD_GEOIP_DB": "/nonexistent-greyward-fixture", "GREYWARD_GEOIP_DB_SECONDARY": "/nonexistent-greyward-fixture", "GREYWARD_GEOIP_LEGACY_DB": "/nonexistent-greyward-fixture", "GREYWARD_GEOFEED_DB": "/nonexistent-greyward-fixture"}):
            resolution = network_location.country_resolution_for_destination("8.8.8.8", "updates.example.fr")
            generic = network_location.country_resolution_for_destination("8.8.8.8", "updates.example.com")
            uk = network_location.country_resolution_for_destination("8.8.8.8", "mirror.example.co.uk")
        self.assertEqual(resolution["country_code"], "")
        self.assertEqual(resolution["source"], "NONE")
        self.assertEqual(resolution["confidence"], "NONE")
        self.assertEqual(generic["country_code"], "")
        self.assertEqual(uk["country_code"], "")

    def test_stale_local_file_is_only_a_weak_hint_and_replacement_invalidates_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            feed = Path(directory) / 'geofeed.csv'
            feed.write_text('8.8.8.0/24,FR,,,\n')
            os.utime(feed, (0, 0))
            with patch.dict(os.environ, {'GREYWARD_GEOIP_DB': '/missing', 'GREYWARD_GEOIP_DB_SECONDARY': '/missing',
                                       'GREYWARD_GEOIP_LEGACY_DB': '/missing', 'GREYWARD_GEOFEED_DB': str(feed)}):
                stale = network_location.country_resolution_for_ip('8.8.8.8')
                self.assertEqual(stale['availability'], 'STALE')
                self.assertEqual(stale['confidence'], 'VERY_LOW')
                self.assertGreater(stale['sources'][-1]['age_days'], 180)
                feed.write_text('8.8.8.0/24,DE,,,\n')
                fresh = network_location.country_resolution_for_ip('8.8.8.8')
                self.assertEqual(fresh['country_code'], 'DE')
                self.assertEqual(fresh['availability'], 'AVAILABLE')


if __name__ == "__main__":
    unittest.main()
