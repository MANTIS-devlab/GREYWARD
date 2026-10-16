import copy
import json
from pathlib import Path
import tempfile
import unittest

from greyward_security_context.network_firewall import Firewall, rich_rules
from greyward_security_context.network_rules import PolicyError, PolicyStore, normalize
from greyward_security_context.network_rule_transactions import RuleManager


class NativeRules:
    def __init__(self, runtime):
        self.runtime = runtime
        self.rules = {'external rule: preserve SSH and unrelated configuration'}
        self.additions = 0
        self.fail_add = None

    def getRichRules(self, *args, **kwargs):
        return list(self.rules)

    def addRichRule(self, *args, **kwargs):
        self.additions += 1
        if self.additions == self.fail_add:
            raise RuntimeError('Injected provider failure')
        self.rules.add(args[1] if self.runtime else args[0])

    def removeRichRule(self, *args, **kwargs):
        self.rules.remove(args[1] if self.runtime else args[0])


class FirewallTransactionsTests(unittest.TestCase):
    def setUp(self):
        self.firewall = object.__new__(Firewall)
        self.firewall.runtime = NativeRules(True)
        self.permanent = NativeRules(False)
        self.firewall.permanent = lambda zone: self.permanent
        self.firewall.catalog = lambda: {'zones': ['public'], 'services': ['ssh']}
        self.rule = normalize({'provider': 'incoming', 'zone': 'public', 'ports': '8443',
                               'source': '192.0.2.50', 'action': 'allow'}, 1000)
        self.original_runtime = set(self.firewall.runtime.rules)
        self.original_permanent = set(self.permanent.rules)

    def manager(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name)/'policy.json'
        path.write_text(json.dumps({'rules': []}))
        return RuleManager(PolicyStore(path), self.firewall)

    def test_apply_remove_and_scoped_rollback_preserve_external_rules(self):
        captured = self.firewall.capture([], [self.rule])
        self.firewall.replace([], [self.rule])
        self.assertEqual(self.firewall.observe([self.rule])[self.rule['id']], 'LOADED')
        self.firewall.restore(captured)
        self.assertEqual(self.firewall.runtime.rules, self.original_runtime)
        self.assertEqual(self.permanent.rules, self.original_permanent)

    def test_partial_native_failure_reverses_completed_steps(self):
        self.firewall.runtime.fail_add = 1
        with self.assertRaises(RuntimeError):
            self.firewall.replace([], [self.rule])
        self.assertEqual(self.firewall.runtime.rules, self.original_runtime)
        self.assertEqual(self.permanent.rules, self.original_permanent)

    def test_external_identical_rule_is_not_adopted_or_deleted(self):
        native = rich_rules(self.rule)[0]
        self.firewall.runtime.rules.add(native)
        captured = self.firewall.capture([], [self.rule])
        with self.assertRaises(PolicyError):
            self.firewall.replace([], [self.rule])
        self.firewall.restore(captured)
        self.assertIn(native, self.firewall.runtime.rules)

    def test_app_position_does_not_change_incoming_native_priority(self):
        app = normalize({'path': '/usr/bin/example'}, 1000)
        self.assertEqual(Firewall.entries([self.rule]), Firewall.entries([app, self.rule]))

    def test_existing_exposure_is_read_only_and_planes_are_distinct(self):
        self.firewall.runtime.getActiveZones = lambda **kw: {'public': {}}
        self.firewall.runtime.getServices = lambda *a, **kw: ['ssh', 'mdns']
        self.permanent.getServices = lambda **kw: ['ssh']
        self.firewall.runtime.getPorts = lambda *a, **kw: []
        self.permanent.getPorts = lambda **kw: []
        self.firewall.replace([], [self.rule])
        result = self.firewall.external([self.rule])
        rows = result['rules']
        self.assertTrue(all(r['mutable'] is False and r['owner'] == 'firewalld' for r in rows))
        ssh = next(r for r in rows if r['value'] == 'ssh')
        mdns = next(r for r in rows if r['value'] == 'mdns')
        self.assertTrue(ssh['runtime'] and ssh['permanent'])
        self.assertTrue(mdns['runtime'] and not mdns['permanent'])
        self.assertFalse(any('8443' in r['value'] for r in rows))

    def test_journal_recovers_an_interrupted_apply(self):
        manager = self.manager()
        native_before = self.firewall.capture([], [self.rule])
        with manager.store.locked() as policy:
            policy['firewall_pending'] = {'native_before': native_before}
            manager.store.write(policy, 0)
        self.firewall.replace([], [self.rule])
        restarted = RuleManager(PolicyStore(manager.store.path), self.firewall)
        restarted.recover()
        self.assertEqual(self.firewall.runtime.rules, self.original_runtime)
        self.assertEqual(self.permanent.rules, self.original_permanent)
        self.assertNotIn('firewall_pending', restarted.store.read())

    def test_failed_policy_commit_restores_native_and_policy_state(self):
        manager = self.manager()
        request = {'provider': 'incoming', 'revision': 0,
                   'commands': [{'operation': 'upsert', 'rule': self.rule}]}
        preview = manager.prepare(1000, request)
        original = manager.store.write
        calls = []
        def fail_final(policy, revision):
            calls.append(revision)
            if len(calls) == 2:
                raise OSError('Injected disk failure')
            return original(policy, revision)
        manager.store.write = fail_final
        with self.assertRaises(OSError):
            manager.apply(1000, preview['transaction'], lambda *args: None)
        self.assertEqual(self.firewall.runtime.rules, self.original_runtime)
        self.assertEqual(self.permanent.rules, self.original_permanent)
        self.assertEqual(manager.store.read()['rules'], [])
        self.assertNotIn('firewall_pending', manager.store.read())

    def test_native_change_during_review_is_refused_before_writing(self):
        manager = self.manager()
        preview = manager.prepare(1000, {'provider': 'incoming', 'revision': 0,
                                        'commands': [{'operation': 'upsert', 'rule': self.rule}]})
        self.firewall.runtime.rules.add(rich_rules(self.rule)[0])
        with self.assertRaises(PolicyError):
            manager.apply(1000, preview['transaction'], lambda *args: None)
        self.assertEqual(manager.store.read()['revision'], 0)


if __name__ == '__main__':
    unittest.main()
