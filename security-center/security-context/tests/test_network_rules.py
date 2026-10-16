"""Real model/persistence tests; no D-Bus, root or network required."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from greyward_security_context.network_rules import (
    MAX_RULES, PolicyError, PolicyStore, lifecycle, matches, migrate, normalize,
)


class NetworkRulesTests(unittest.TestCase):
    def rule(self, **changes):
        return normalize(dict(path='/usr/bin/example', **changes), 1000, current_time=100, current_boot='boot-a')

    def connection(self, **changes):
        return SimpleNamespace(**dict(dict(process_path='/usr/bin/example', user_id=1000,
                                           protocol='tcp', dst_ip='203.0.113.2', dst_host='docs.example.org', dst_port=443), **changes))

    def test_uid_executable_protocol_and_port_are_conjunctive(self):
        rule = self.rule(protocols=['tcp'], ports='443,8000-8010')
        self.assertTrue(matches(rule, self.connection(), current_time=101))
        for changes in ({'user_id': 1001}, {'process_path': '/usr/bin/other'}, {'protocol': 'udp'}, {'dst_port': 442}):
            self.assertFalse(matches(rule, self.connection(**changes), current_time=101))

    def test_domain_boundary_and_missing_hostname(self):
        rule = self.rule(destinations=[{'kind': 'domain', 'value': 'example.org'}])
        for host, expected in [('EXAMPLE.ORG.', True), ('a.example.org', True), ('notexample.org', False), ('example.org.attacker.test', False), ('', False)]:
            self.assertEqual(matches(rule, self.connection(dst_host=host)), expected)

    def test_address_alternatives_and_ipv6(self):
        rule = self.rule(destinations=[{'kind': 'network', 'value': '2001:db8::/32'}, {'kind': 'ip', 'value': '203.0.113.2'}])
        self.assertTrue(matches(rule, self.connection()))
        self.assertTrue(matches(rule, self.connection(dst_ip='2001:db8::1', protocol='tcp6')))
        self.assertFalse(matches(rule, self.connection(dst_ip='203.0.113.3')))

    def test_port_ranges_are_bounded_and_merged(self):
        self.assertEqual(self.rule(ports='80,81-83,82,443')['ports'], [[80, 83], [443, 443]])
        for ports in ('0', '65536', '443-80', 'abc', '1-2-3'):
            with self.assertRaises(PolicyError):
                self.rule(ports=ports)

    def test_lifetime_and_disabled_state(self):
        timed = self.rule(lifetime='15m')
        self.assertEqual(lifecycle(timed, current_time=999), 'SAVED')
        self.assertEqual(lifecycle(timed, current_time=1000), 'EXPIRED')
        boot = self.rule(lifetime='boot')
        self.assertEqual(lifecycle(boot, current_boot='boot-a'), 'SAVED')
        self.assertEqual(lifecycle(boot, current_boot='boot-b'), 'EXPIRED')
        boot['enabled'] = False
        self.assertEqual(lifecycle(boot), 'DISABLED')

    def test_edit_does_not_renew_a_timed_rule(self):
        old = self.rule(lifetime='1h')
        edited = normalize(dict(old, name='Renamed'), 1000, existing=old, current_time=200)
        self.assertEqual(edited['expires_at'], 3700)
        renewed = normalize(dict(old, renew=True), 1000, existing=old, current_time=200)
        self.assertEqual(renewed['expires_at'], 3800)

    def test_ambiguous_flatpak_path_and_bad_scope_refused(self):
        for path in ('/app/bin/editor', '../bin/editor', '/usr/../tmp/editor', '*'):
            with self.assertRaises(PolicyError):
                normalize({'path': path}, 1000)
        with self.assertRaises(PolicyError):
            self.rule(scope='another-user')

    def test_legacy_host_and_ip_remain_conjunctive(self):
        policy = migrate({'rules': [{'path': '/usr/bin/example', 'action': 'deny', 'host': 'docs.example.org', 'ip': '203.0.113.2'}]})
        rule = policy['rules'][0]
        self.assertTrue(matches(rule, self.connection()))
        self.assertFalse(matches(rule, self.connection(dst_host='other.example.org')))
        self.assertFalse(matches(rule, self.connection(dst_ip='203.0.113.3')))

    def test_legacy_order_stable_and_temporary_allow_not_permanent(self):
        policy = migrate({'rules': [
            {'path': '*', 'action': 'deny'},
            {'path': '/usr/bin/example', 'action': 'allow'},
            {'path': '/usr/bin/example', 'port': 443, 'action': 'deny'},
            {'path': '/usr/bin/other', 'action': 'allow', 'duration': 'once'},
        ]})
        self.assertEqual(policy['rules'][0]['ports'], [[443, 443]])
        self.assertEqual(policy['rules'][-1]['path'], '*')
        self.assertFalse(next(r for r in policy['rules'] if r['path'] == '/usr/bin/other')['enabled'])

    def test_policy_roundtrip_including_expired_boot_rules(self):
        original = migrate({'rules': []})
        original['rules'] = [self.rule(lifetime='boot'), self.rule(lifetime='15m')]
        self.assertEqual(migrate(original), original)

    def test_overflow_is_rejected_without_eviction(self):
        with self.assertRaises(PolicyError):
            migrate({'rules': [{'path': '/usr/bin/example', 'port': 443, 'action': 'deny'}] * (MAX_RULES + 1)})

    def test_incoming_source_and_family_validation(self):
        rule = normalize({'provider': 'incoming', 'zone': 'public', 'ports': '8443', 'source': '192.0.2.5'}, 1000)
        self.assertEqual(rule['family'], 'ipv4')
        self.assertEqual(rule['source'], '192.0.2.5/32')
        with self.assertRaises(PolicyError):
            normalize(dict(rule, family='ipv6'), 1000)
        with self.assertRaises(PolicyError):
            normalize(dict(rule, service='ssh'), 1000)
        with self.assertRaises(PolicyError):
            normalize({'provider': 'incoming', 'zone': 'public', 'service': 'ssh', 'protocols': ['udp']}, 1000)

    def test_persistence_revision_and_last_known_good(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'policy.json'
            path.write_text(json.dumps({'rules': []}))
            store = PolicyStore(path)
            with store.locked() as old:
                new = copy.deepcopy(old)
                new['rules'].append(self.rule())
                saved = store.write(new, old['revision'])
            self.assertEqual(saved['revision'], 1)
            with self.assertRaises(PolicyError):
                with store.locked():
                    store.write(old, 0)
            path.write_text('{broken')
            self.assertEqual(store.read(), saved)
            # A new process can recover the separately persisted validated backup.
            self.assertEqual(PolicyStore(path).read()['revision'], 1)

    def test_corrupt_without_backup_does_not_return_allow_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'policy.json'
            path.write_text('{broken')
            with self.assertRaises(PolicyError):
                PolicyStore(path).read()


if __name__ == '__main__':
    unittest.main()
