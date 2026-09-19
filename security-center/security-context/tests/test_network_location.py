import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from greyward_security_context import network_location


class NetworkLocationTests(unittest.TestCase):
    def setUp(self):
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
            with patch.dict(os.environ, {"GREYWARD_GEOIP_DB": str(database), "GREYWARD_GEOIP_DB_SECONDARY": "", "GREYWARD_GEOIP_LEGACY_DB": "", "GREYWARD_GEOFEED_DB": ""}), patch.object(network_location.subprocess, "run", return_value=completed) as run:
                self.assertEqual(network_location.country_code_for_ip("8.8.8.8"), "FR")
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0][-2:], ["country", "iso_code"])

    def test_does_not_lookup_private_or_malformed_addresses(self):
        with patch.object(network_location.subprocess, "run") as run:
            self.assertEqual(network_location.country_code_for_ip("192.168.1.8"), "")
            self.assertEqual(network_location.country_code_for_ip("not-an-ip"), "")
        run.assert_not_called()

    def test_missing_local_database_is_unknown_without_network_fallback(self):
        with patch.dict(os.environ, {"GREYWARD_GEOIP_DB_SECONDARY": "", "GREYWARD_GEOIP_LEGACY_DB": "", "GREYWARD_GEOFEED_DB": ""}), patch.object(network_location, "_database_path", return_value=None), patch.object(network_location.subprocess, "run") as run:
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
            self.assertEqual(resolution["country_code"], "US")
            self.assertEqual(resolution["confidence"], "LOW")
            self.assertFalse(resolution["converged"])
            self.assertEqual(resolution["source_count"], 3)

    def test_geofeed_can_supply_country_when_geoip_is_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            feed = Path(directory) / "geofeed.csv"
            feed.write_text("8.8.0.0/16,DE,,,\n8.8.8.0/24,FR,,,\n", encoding="utf-8")
            environment = {
                "GREYWARD_GEOIP_DB": "",
                "GREYWARD_GEOIP_DB_SECONDARY": "",
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
                "GREYWARD_GEOIP_DB": "",
                "GREYWARD_GEOIP_DB_SECONDARY": "",
                "GREYWARD_GEOIP_LEGACY_DB": str(database),
                "GREYWARD_GEOFEED_DB": "",
            }
            with patch.dict(os.environ, environment), patch.object(network_location.subprocess, "run", return_value=completed) as run:
                resolution = network_location.country_resolution_for_ip("8.8.8.8")
            self.assertEqual(resolution["country_code"], "FR")
            self.assertEqual(resolution["confidence"], "MEDIUM")
            self.assertEqual(run.call_args.args[0][0], "geoiplookup")

    def test_domain_suffix_is_a_last_resort_hint_only(self):
        with patch.dict(os.environ, {"GREYWARD_GEOIP_DB": "", "GREYWARD_GEOIP_DB_SECONDARY": "", "GREYWARD_GEOIP_LEGACY_DB": "", "GREYWARD_GEOFEED_DB": ""}):
            resolution = network_location.country_resolution_for_destination("8.8.8.8", "updates.example.fr")
            generic = network_location.country_resolution_for_destination("8.8.8.8", "updates.example.com")
            uk = network_location.country_resolution_for_destination("8.8.8.8", "mirror.example.co.uk")
        self.assertEqual(resolution["country_code"], "FR")
        self.assertEqual(resolution["source"], "DOMAIN_SUFFIX")
        self.assertEqual(resolution["confidence"], "VERY_LOW")
        self.assertEqual(generic["country_code"], "")
        self.assertEqual(uk["country_code"], "GB")


if __name__ == "__main__":
    unittest.main()
