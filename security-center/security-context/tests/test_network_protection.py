import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


try:
    from greyward_security_context.control_plane import NetworkState, _active_vpn_dns_addresses, select_policy_rule
    import greyward_security_context.user_bus as user_bus
except ModuleNotFoundError as error:  # Fedora package dependencies are not present on the Windows authoring host.
    if error.name in {"grpc", "dbus", "gi"}:
        NetworkState = None
    else:
        raise


@unittest.skipIf(NetworkState is None, "OpenSnitch runtime dependencies are unavailable on this host")
class NetworkProtectionTests(unittest.TestCase):
    def test_threat_policy_mutation_requires_explicit_wheel_bus_authorization(self):
        config = Path(__file__).parents[1] / "dbus" / "systems.mantis.greyward.OpenSnitchPolicy1.conf"
        text = config.read_text(encoding="utf-8")
        self.assertIn('<policy group="wheel"><allow send_destination="systems.mantis.greyward.OpenSnitchPolicy1" send_interface="systems.mantis.greyward.OpenSnitchPolicy1"/></policy>', text)
        default_policy = text.split('<policy context="default">', 1)[1].split('</policy>', 1)[0]
        self.assertIn('send_member="Introspect"', default_policy)
        self.assertIn('send_member="ListRules"', default_policy)
        self.assertIn('send_member="SetRule"', default_policy)
        self.assertIn('send_member="SetThreatException"', default_policy)
        self.assertIn('send_member="SetThreatIntelEnabled"', default_policy)

    def test_secure_dns_policy_allows_introspection_but_denies_mutation(self):
        config = Path(__file__).parents[1] / "dbus" / "systems.mantis.greyward.SecureDns1.conf"
        default_policy = config.read_text(encoding="utf-8").split('<policy context="default">', 1)[1].split('</policy>', 1)[0]
        self.assertIn('send_member="Introspect"', default_policy)
        self.assertIn('send_member="GetState"', default_policy)
        for member in ("SetMode", "SetProvider", "RetrySecureDns"):
            self.assertIn(f'send_member="{member}"', default_policy)

    def test_managed_dns_denies_direct_app_queries_and_allows_scoped_exception(self):
        connection = SimpleNamespace(process_path="/usr/bin/example-app", dst_host="1.1.1.1", dst_ip="1.1.1.1", dst_port=53, protocol="udp")
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "opensnitch-policy.json"
            policy.write_text(json.dumps({
                "default_action": "allow",
                "default_duration": "once",
                "interactive_prompts": False,
                "dns_policy": {"enforce": True, "ports": [53, 853]},
                "rules": [],
            }), encoding="utf-8")
            with patch("greyward_security_context.control_plane.POLICY_PATH", policy):
                action, _duration, selected = select_policy_rule(connection)
                self.assertEqual(action, "deny")
                self.assertEqual(selected["path"], "*")
                policy.write_text(json.dumps({
                    "default_action": "allow",
                    "default_duration": "once",
                    "interactive_prompts": False,
                    "dns_policy": {"enforce": True, "ports": [53, 853]},
                    "rules": [{"path": "/usr/bin/example-app", "port": 53, "action": "allow", "duration": "always"}],
                }), encoding="utf-8")
                action, _duration, selected = select_policy_rule(connection)
        self.assertEqual(action, "allow")
        self.assertEqual(selected["path"], "/usr/bin/example-app")

    def test_local_resolver_stub_is_allowed_without_upstream_dns_bypass(self):
        connection = SimpleNamespace(
            process_path="/usr/bin/brave",
            dst_host="safebrowsing.brave.com",
            dst_ip="127.0.0.53",
            dst_port=53,
            protocol="udp",
        )
        action, _duration, selected = select_policy_rule(connection)
        self.assertEqual(action, "allow")
        self.assertEqual(selected["name"], "GREYWARD local resolver stub")

    def test_vpn_dns_exception_requires_active_vpn_dns_server(self):
        connection = SimpleNamespace(
            process_path="/usr/lib/systemd/systemd-resolved",
            dst_host="vpn-dns",
            dst_ip="10.2.0.1",
            dst_port=53,
            protocol="udp",
        )
        with patch("greyward_security_context.control_plane._active_vpn_dns_addresses", return_value=set()):
            action, _duration, selected = select_policy_rule(connection)
        self.assertEqual(action, "deny")
        self.assertEqual(selected["name"], "GREYWARD deny direct DNS outside managed resolver")

        with patch("greyward_security_context.control_plane._active_vpn_dns_addresses", return_value={"10.2.0.1"}):
            action, _duration, selected = select_policy_rule(connection)
        self.assertEqual(action, "allow")
        self.assertEqual(selected["name"], "GREYWARD active VPN resolver upstream")

    def test_vpn_dns_exception_does_not_allow_unrelated_dns_server(self):
        connection = SimpleNamespace(
            process_path="/usr/lib/systemd/systemd-resolved",
            dst_host="unrelated-dns",
            dst_ip="1.1.1.1",
            dst_port=53,
            protocol="udp",
        )
        with patch("greyward_security_context.control_plane._active_vpn_dns_addresses", return_value={"10.2.0.1"}):
            action, _duration, selected = select_policy_rule(connection)
        self.assertEqual(action, "deny")
        self.assertEqual(selected["name"], "GREYWARD deny direct DNS outside managed resolver")

    def test_active_vpn_dns_addresses_come_only_from_connected_vpn_devices(self):
        results = [
            SimpleNamespace(
                returncode=0,
                stdout="eth0:802-3-ethernet:connected\nproton0:wireguard:connected\nlo:loopback:connected\n",
            ),
            SimpleNamespace(
                returncode=0,
                stdout="IP4.DNS[1]:10.2.0.1\nIP6.DNS[1]:2a07\\:b944\\:\\:2\\:1\n",
            ),
        ]
        with patch("greyward_security_context.control_plane.subprocess.run", side_effect=results) as run:
            addresses = _active_vpn_dns_addresses()
        self.assertEqual(addresses, {"10.2.0.1", "2a07:b944::2:1"})
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[1].args[0][-1], "proton0")

    def test_active_vpn_dns_addresses_include_externally_managed_tunnels(self):
        results = [
            SimpleNamespace(
                returncode=0,
                stdout="eth0:ethernet:connected\ntun0:tun:connected (externally)\n",
            ),
            SimpleNamespace(returncode=0, stdout="IP4.DNS[1]:10.96.0.1\n"),
        ]
        with patch("greyward_security_context.control_plane.subprocess.run", side_effect=results):
            self.assertEqual(_active_vpn_dns_addresses(), {"10.96.0.1"})

    def test_active_vpn_dns_addresses_are_empty_without_a_connected_vpn(self):
        result = SimpleNamespace(returncode=0, stdout="eth0:802-3-ethernet:connected\n")
        with patch("greyward_security_context.control_plane.subprocess.run", return_value=result) as run:
            self.assertEqual(_active_vpn_dns_addresses(), set())
        run.assert_called_once()

    def test_ping_normalizes_application_destination_and_decision(self):
        connection = SimpleNamespace(
            process_path="/usr/bin/curl",
            dst_host="example.test",
            dst_ip="192.0.2.10",
            dst_port=443,
            protocol="tcp",
        )
        event = SimpleNamespace(
            connection=connection,
            rule=SimpleNamespace(action="allow", name="curl-allow"),
            time="2026-08-24T12:00:00Z",
        )
        stats = SimpleNamespace(
            daemon_version="1.8.0",
            connections=1,
            accepted=1,
            dropped=0,
            rule_hits=1,
            rule_misses=0,
            rules=1,
            events=[event],
        )
        state = NetworkState()
        state.pinged(stats)
        snapshot = state.snapshot()
        self.assertEqual(snapshot["opensnitch"]["state"], "OPERATING")
        self.assertEqual(snapshot["activity"][0]["decision"], "ALLOWED")
        self.assertEqual(snapshot["activity"][0]["application"], "curl")
        self.assertEqual(snapshot["activity"][0]["destination"]["host"], "example.test")

    def test_idle_link_is_operating_without_activity(self):
        state = NetworkState()
        state.connected = True
        state.last_seen = datetime.now(timezone.utc)
        snapshot = state.snapshot()
        self.assertEqual(snapshot["opensnitch"]["state"], "OPERATING")
        self.assertEqual(snapshot["opensnitch"]["health"]["state"], "IDLE")
        self.assertEqual(snapshot["opensnitch"]["health"]["event_stream"], "EMPTY")

    def test_stale_heartbeat_is_degraded_not_secure(self):
        state = NetworkState()
        state.connected = True
        state.last_seen = datetime.now(timezone.utc) - timedelta(minutes=5)
        snapshot = state.snapshot()
        self.assertEqual(snapshot["opensnitch"]["state"], "DEGRADED")
        self.assertTrue(snapshot["opensnitch"]["capabilities"]["installed"])
        self.assertFalse(snapshot["opensnitch"]["capabilities"]["activity"])
        self.assertFalse(snapshot["opensnitch"]["health"]["healthy"])

    def test_degraded_without_heartbeat_is_probed(self):
        now = datetime.now(timezone.utc)
        value = {
            "schema": "greyward.security.network/v1",
            "opensnitch": {"state": "DEGRADED", "detail": "stale", "health": {"state": "DEGRADED"}},
        }
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "network-protection.json"
            state_path.write_text(json.dumps(value), encoding="utf-8")
            with patch.object(user_bus, "NETWORK_STATE_PATH", state_path), patch.object(user_bus, "_probe_network_link", return_value=True), patch.object(user_bus, "now", return_value=now):
                snapshot = user_bus.network_summary()
        self.assertEqual(snapshot["opensnitch"]["state"], "OPERATING")
        self.assertIn("connected and idle", snapshot["opensnitch"]["detail"])

    def test_recent_stale_reachable_link_stays_operating(self):
        now = datetime.now(timezone.utc)
        value = {
            "schema": "greyward.security.network/v1",
            "opensnitch": {
                "state": "OPERATING",
                "detail": "stale",
                "last_seen": (now - timedelta(seconds=60)).isoformat().replace("+00:00", "Z"),
                "health": {"state": "ACTIVE"},
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "network-protection.json"
            state_path.write_text(json.dumps(value), encoding="utf-8")
            with patch.object(user_bus, "NETWORK_STATE_PATH", state_path), patch.object(user_bus, "_probe_network_link", return_value=True), patch.object(user_bus, "now", return_value=now):
                snapshot = user_bus.network_summary()
        self.assertEqual(snapshot["opensnitch"]["state"], "OPERATING")
        self.assertEqual(snapshot["opensnitch"]["health"]["state"], "ACTIVE")

    def test_recent_stale_unreachable_link_is_degraded(self):
        now = datetime.now(timezone.utc)
        value = {
            "schema": "greyward.security.network/v1",
            "opensnitch": {
                "state": "OPERATING",
                "detail": "stale",
                "last_seen": (now - timedelta(seconds=60)).isoformat().replace("+00:00", "Z"),
                "health": {"state": "ACTIVE"},
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "network-protection.json"
            state_path.write_text(json.dumps(value), encoding="utf-8")
            with patch.object(user_bus, "NETWORK_STATE_PATH", state_path), patch.object(user_bus, "_probe_network_link", return_value=False), patch.object(user_bus, "now", return_value=now):
                snapshot = user_bus.network_summary()
        self.assertEqual(snapshot["opensnitch"]["state"], "DEGRADED")
        self.assertEqual(snapshot["opensnitch"]["health"]["state"], "DEGRADED")
        self.assertIn("liveness probe failed", snapshot["opensnitch"]["health"]["detail"])

    def test_stale_but_reachable_link_stays_operating(self):
        now = datetime.now(timezone.utc)
        value = {
            "schema": "greyward.security.network/v1",
            "opensnitch": {
                "state": "DEGRADED",
                "detail": "stale",
                "last_seen": (now - timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
                "health": {"state": "DEGRADED"},
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "network-protection.json"
            state_path.write_text(json.dumps(value), encoding="utf-8")
            with patch.object(user_bus, "NETWORK_STATE_PATH", state_path), patch.object(user_bus, "_probe_network_link", return_value=True), patch.object(user_bus, "now", return_value=now):
                snapshot = user_bus.network_summary()
        self.assertEqual(snapshot["opensnitch"]["state"], "OPERATING")
        self.assertEqual(snapshot["opensnitch"]["health"]["state"], "ACTIVE")

    def test_stale_unreachable_link_becomes_unavailable(self):
        now = datetime.now(timezone.utc)
        value = {
            "schema": "greyward.security.network/v1",
            "opensnitch": {
                "state": "DEGRADED",
                "detail": "stale",
                "last_seen": (now - timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
                "health": {"state": "DEGRADED"},
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "network-protection.json"
            state_path.write_text(json.dumps(value), encoding="utf-8")
            with patch.object(user_bus, "NETWORK_STATE_PATH", state_path), patch.object(user_bus, "_probe_network_link", return_value=False), patch.object(user_bus, "now", return_value=now):
                snapshot = user_bus.network_summary()
        self.assertEqual(snapshot["opensnitch"]["state"], "UNAVAILABLE")
        self.assertIn("liveness probe failed", snapshot["opensnitch"]["detail"])
    def test_policy_projection_is_bounded_and_separate_from_upstream_rules(self):
        state = NetworkState()
        state.connected = True
        state.last_seen = datetime.now(timezone.utc)
        state.rules = [{
            "id": "rule-upstream",
            "name": "upstream",
            "source": "OPENSNITCH",
            "action": "ALLOW",
            "duration": "ALWAYS",
            "enabled": True,
            "scope": {"application": "/usr/bin/curl", "destination": None},
            "mutable": False,
        }]
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "opensnitch-policy.json"
            policy.write_text(json.dumps({"default_action": "allow", "default_duration": "once", "rules": [{"path": "/usr/bin/python3", "action": "deny", "duration": "always"}]}), encoding="utf-8")
            with patch("greyward_security_context.control_plane.POLICY_PATH", policy):
                rules = state.snapshot()["rules"]
        self.assertTrue(any(item["source"] == "GREYWARD" and item["mutable"] for item in rules))
        self.assertTrue(any(item["source"] == "OPENSNITCH" and not item["mutable"] for item in rules))

    def test_activity_response_returns_initial_batch_and_incremental_delta(self):
        state = NetworkState()
        for index in range(2):
            state._record(SimpleNamespace(
                process_path="/usr/bin/curl",
                dst_host=f"example-{index}.test",
                dst_ip="192.0.2.10",
                dst_port=443,
                protocol="tcp",
            ), "allow")
        initial = state.activity_response(0, 256)
        self.assertTrue(initial["reset"])
        self.assertEqual(len(initial["events"]), 2)
        cursor = initial["next_sequence"]
        state._record(SimpleNamespace(
            process_path="/usr/bin/python3",
            dst_host="updates.example.test",
            dst_ip="192.0.2.11",
            dst_port=443,
            protocol="tcp",
        ), "deny")
        delta = state.activity_response(cursor, 256)
        self.assertFalse(delta["reset"])
        self.assertEqual(len(delta["events"]), 1)
        self.assertEqual(delta["events"][0]["decision"], "BLOCKED")
        self.assertEqual(delta["summary"]["blocked"], 1)

    def test_activity_retention_is_bounded(self):
        state = NetworkState()
        for index in range(4100):
            state._record(SimpleNamespace(
                process_path="/usr/bin/curl",
                dst_host=f"example-{index}.test",
                dst_ip="192.0.2.10",
                dst_port=443,
                protocol="tcp",
            ), "allow")
        snapshot = state.snapshot()
        self.assertEqual(len(snapshot["activity"]), 4096)
        self.assertEqual(snapshot["activity_summary"]["total"], 4096)
        self.assertEqual(len(snapshot["activity_summary"]["buckets"]), 30)

    def test_secure_dns_stopped_does_not_reuse_secure_cached_state(self):
        secure_state = {"effective_policy": "SecureProvider", "effective_transport": "DoT", "encryption": "Enabled", "validation": "Enabled"}
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "secure-dns.json"
            state_path.write_text(json.dumps(secure_state), encoding="utf-8")
            with patch.object(user_bus, "SECURE_DNS_STATE_PATH", state_path), patch.object(user_bus, "_secure_dns_call", return_value=None), patch.object(user_bus, "_service_active", return_value=False):
                snapshot = user_bus.secure_dns_state()
        self.assertEqual(snapshot["effective_policy"], "Unavailable")
        self.assertEqual(snapshot["degradation_reason"], "ServiceUnavailable")

    def test_security_context_native_dbus_proxies_are_typed_and_bounded(self):
        source = (Path(__file__).parents[1] / "greyward_security_context" / "user_bus.py").read_text(encoding="utf-8")
        self.assertNotIn('["gdbus", "call", "--system"', source)
        self.assertIn("DBUS_CALL_TIMEOUT=8", source)
        self.assertIn("timeout=DBUS_CALL_TIMEOUT", source)
        self.assertIn("timeout=FILE_SECURITY_DBUS_TIMEOUT", source)

    def test_unavailable_network_keeps_installed_capability_separate_from_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "missing-network.json"
            with patch.object(user_bus, "NETWORK_STATE_PATH", state_path), patch.object(user_bus, "_service_active", return_value=False), patch.object(user_bus, "_NETWORK_HEALTH_CACHE", None), patch.object(user_bus.shutil, "which", return_value="/usr/bin/opensnitchd"):
                snapshot = user_bus.network_summary()
        self.assertEqual(snapshot["opensnitch"]["state"], "UNAVAILABLE")
        self.assertTrue(snapshot["opensnitch"]["capabilities"]["installed"])
        self.assertFalse(snapshot["opensnitch"]["capabilities"]["activity"])


if __name__ == "__main__":
    unittest.main()
