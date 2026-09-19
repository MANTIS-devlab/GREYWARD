import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from greyward_security_context import feodo

try:
    from greyward_security_context.control_plane import NetworkState, select_policy_rule
except ModuleNotFoundError as error:
    if error.name in {"grpc", "dbus", "gi"}:
        NetworkState = None
    else:
        raise


class FeodoSnapshotTests(unittest.TestCase):
    def test_missing_snapshot_is_initializing_not_an_error(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / "missing-feodo-snapshot.json"
            with patch("greyward_security_context.feodo.SNAPSHOT_PATH", snapshot):
                value = feodo.load_snapshot()
            self.assertEqual(value["state"], "INITIALIZING")
            self.assertIsNone(value["last_successful_update"])

    def test_normalizes_exact_ip_port_and_accepts_empty_feed(self):
        self.assertEqual(
            feodo.normalize_feed([{"ip_address": "203.0.113.10", "port": 443, "malware": "QakBot"}]),
            [{"ip": "203.0.113.10", "port": 443, "malware": "QakBot"}],
        )
        self.assertEqual(feodo.normalize_feed([]), [])
        with self.assertRaises(ValueError):
            feodo.normalize_feed([{"ip_address": "not-an-ip", "port": 443}])
        with self.assertRaises(ValueError):
            feodo.normalize_feed([{"ip_address": "203.0.113.10", "port": 0}])

    def test_failure_preserves_last_known_good_and_empty_is_success(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "feodo-snapshot.json"
            path.write_text(json.dumps({
                "schema": feodo.SNAPSHOT_SCHEMA,
                "provider": feodo.FEODO_PROVIDER,
                "state": "READY",
                "last_successful_update": "2026-09-06T10:00:00Z",
                "indicators": [{"ip": "203.0.113.10", "port": 443, "malware": "QakBot"}],
            }), encoding="utf-8")
            stale = feodo.update_feed(lambda: (_ for _ in ()).throw(OSError("offline")), path)
            self.assertEqual(stale["state"], "STALE")
            self.assertEqual(stale["indicators"][0]["ip"], "203.0.113.10")
            empty = feodo.update_feed(lambda: b"[]", path)
            self.assertEqual(empty["state"], "EMPTY")
            self.assertEqual(empty["indicator_count"], 0)


@unittest.skipIf(NetworkState is None, "OpenSnitch runtime dependencies are unavailable on this host")
class FeodoPolicyTests(unittest.TestCase):
    def connection(self, path="/usr/bin/example-app"):
        return SimpleNamespace(process_path=path, dst_host="c2.example", dst_ip="203.0.113.10", dst_port=443, protocol="tcp")

    def event(self, event_id):
        return {
            "event_id": event_id,
            "application": "Example App",
            "decision": "BLOCKED",
            "destination": {"ip": "203.0.113.10", "port": 443},
            "threat": {"ip": "203.0.113.10", "port": 443, "malware": "QakBot"},
        }

    def test_explicit_tiers_threat_beats_normal_allow_and_exception_wins(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "opensnitch-policy.json"
            snapshot = root / "feodo-snapshot.json"
            policy.write_text(json.dumps({
                "default_action": "allow", "default_duration": "once", "interactive_prompts": False,
                "dns_policy": {"enforce": True, "ports": [53, 853]},
                "threat_intel": {"enabled": True, "provider": "feodo-recommended"},
                "rules": [{"path": "/usr/bin/example-app", "ip": "203.0.113.10", "port": 443, "action": "allow", "duration": "always"}],
            }), encoding="utf-8")
            snapshot.write_text(json.dumps({
                "schema": feodo.SNAPSHOT_SCHEMA, "provider": feodo.FEODO_PROVIDER, "state": "READY",
                "last_successful_update": "2026-09-06T10:00:00Z", "indicators": [{"ip": "203.0.113.10", "port": 443, "malware": "QakBot"}],
            }), encoding="utf-8")
            with patch("greyward_security_context.control_plane.POLICY_PATH", policy), patch("greyward_security_context.feodo.SNAPSHOT_PATH", snapshot):
                action, _, selected = select_policy_rule(self.connection())
                self.assertEqual((action, selected["tier"], selected["malware"]), ("deny", "THREAT", "QakBot"))
                policy.write_text(json.dumps({
                    "default_action": "allow", "default_duration": "once", "interactive_prompts": False,
                    "dns_policy": {"enforce": True, "ports": [53, 853]},
                    "threat_intel": {"enabled": True, "provider": "feodo-recommended"},
                    "rules": [{"path": "/usr/bin/example-app", "ip": "203.0.113.10", "port": 443, "action": "allow", "duration": "always", "tier": "THREAT_EXCEPTION"}],
                }), encoding="utf-8")
                action, _, selected = select_policy_rule(self.connection())
                self.assertEqual((action, selected["tier"]), ("allow", "THREAT_EXCEPTION"))
                action, _, selected = select_policy_rule(self.connection("/usr/bin/other-app"))
                self.assertEqual((action, selected["tier"]), ("deny", "THREAT"))

    def test_threat_activity_is_coalesced_but_retries_remain_visible(self):
        state = NetworkState()
        connection = self.connection()
        threat = {"tier": "THREAT", "ip": "203.0.113.10", "port": 443, "malware": "QakBot", "indicator_id": "203.0.113.10:443"}
        state._record(connection, "deny", "greyward-policy", "2026-09-06T10:00:00Z", "GREYWARD Feodo known malicious C2", threat)
        state._record(connection, "deny", "opensnitch-statistics", "2026-09-06T10:00:01Z", "GREYWARD Feodo known malicious C2")
        state._record(connection, "deny", "greyward-policy", "2026-09-06T10:01:00Z", "GREYWARD Feodo known malicious C2", threat)
        self.assertEqual(len(state.activity), 2)
        self.assertEqual(state.activity[-1]["threat"]["malware"], "QakBot")

    def test_disabled_threat_protection_leaves_normal_allow_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "opensnitch-policy.json"
            snapshot = root / "feodo-snapshot.json"
            policy.write_text(json.dumps({
                "default_action": "allow", "default_duration": "once", "interactive_prompts": False,
                "dns_policy": {"enforce": True, "ports": [53, 853]},
                "threat_intel": {"enabled": False, "provider": "feodo-recommended"},
                "rules": [{"path": "/usr/bin/example-app", "ip": "203.0.113.10", "port": 443, "action": "allow", "duration": "always"}],
            }), encoding="utf-8")
            snapshot.write_text(json.dumps({
                "schema": feodo.SNAPSHOT_SCHEMA, "provider": feodo.FEODO_PROVIDER, "state": "READY",
                "last_successful_update": "2026-09-06T10:00:00Z", "indicators": [{"ip": "203.0.113.10", "port": 443}],
            }), encoding="utf-8")
            with patch("greyward_security_context.control_plane.POLICY_PATH", policy), patch("greyward_security_context.feodo.SNAPSHOT_PATH", snapshot):
                action, _duration, selected = select_policy_rule(self.connection())
        self.assertEqual(action, "allow")
        self.assertEqual(selected["path"], "/usr/bin/example-app")



if __name__ == "__main__":
    unittest.main()
