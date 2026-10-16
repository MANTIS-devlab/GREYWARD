import copy
import json
from pathlib import Path
import tempfile
import time
import unittest

from greyward_security_context.network_rules import PolicyError, PolicyStore
from greyward_security_context.network_rule_transactions import RuleManager
from greyward_security_context.network_firewall import rich_rules


class RuleTransactionsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        path = Path(self.directory.name)/'policy.json'
        path.write_text(json.dumps({'rules': []}))
        self.store = PolicyStore(path)
        self.manager = RuleManager(self.store)

    def request(self, **rule):
        return {'provider': 'application', 'revision': self.store.read()['revision'],
                'commands': [{'operation': 'upsert', 'rule': dict(path='/usr/bin/example', **rule)}]}

    def approve(self, request=None):
        preview = self.manager.prepare(1000, request or self.request())
        return self.manager.apply(1000, preview['transaction'], lambda *args: None)

    def test_preview_is_non_mutating_and_apply_binds_exact_candidate(self):
        preview = self.manager.prepare(1000, self.request())
        self.assertEqual(self.store.read()['rules'], [])
        result = self.manager.apply(1000, preview['transaction'], lambda *args: None)
        self.assertEqual(result['revision'], 1)
        self.assertEqual(self.store.read()['rules'][0]['uid'], 1000)

    def test_authentication_failure_does_not_write(self):
        preview = self.manager.prepare(1000, self.request())
        def deny(*args):
            raise PolicyError('Authentication cancelled.')
        with self.assertRaises(PolicyError):
            self.manager.apply(1000, preview['transaction'], deny)
        self.assertEqual(self.store.read()['revision'], 0)

    def test_different_user_and_replay_refused(self):
        preview = self.manager.prepare(1000, self.request())
        with self.assertRaises(PolicyError):
            self.manager.apply(1001, preview['transaction'], lambda *args: None)
        self.manager.apply(1000, preview['transaction'], lambda *args: None)
        with self.assertRaises(PolicyError):
            self.manager.apply(1000, preview['transaction'], lambda *args: None)

    def test_expired_and_cancelled_reviews_refused(self):
        for expired in (True, False):
            preview = self.manager.prepare(1000, self.request())
            if expired:
                self.manager.pending[preview['transaction']]['deadline'] = time.monotonic() - 1
            else:
                self.manager.cancel(1000, preview['transaction'])
            with self.assertRaises(PolicyError):
                self.manager.apply(1000, preview['transaction'], lambda *args: None)

    def test_cancellation_during_authentication_refused(self):
        preview = self.manager.prepare(1000, self.request())
        with self.assertRaises(PolicyError):
            self.manager.apply(1000, preview['transaction'], lambda *args: self.manager.cancel(1000, preview['transaction']))
        self.assertEqual(self.store.read()['rules'], [])

    def test_stale_revision_after_authentication_is_refused(self):
        preview = self.manager.prepare(1000, self.request())
        def concurrent_change(*args):
            with self.store.locked() as policy:
                self.store.write(policy, policy['revision'])
        with self.assertRaises(PolicyError):
            self.manager.apply(1000, preview['transaction'], concurrent_change)
        self.assertEqual(self.store.read()['rules'], [])

    def test_generic_import_cannot_create_dns_or_threat_exception(self):
        for additions in ({'tier': 'THREAT_EXCEPTION'}, {'ports': '53', 'action': 'allow', 'dns_exception': True}):
            with self.assertRaises(PolicyError):
                self.manager.prepare(1000, self.request(**additions))

    def test_explicit_dns_review_is_narrow_and_warned(self):
        request = self.request(ports='53', action='allow')
        request['commands'][0]['operation'] = 'dns_exception'
        preview = self.manager.prepare(1000, request)
        self.assertTrue(any('bypasses managed DNS' in w for w in preview['warnings']))
        self.manager.apply(1000, preview['transaction'], lambda *args: None)
        self.assertTrue(self.store.read()['rules'][0]['dns_exception'])

    def test_edit_disable_move_delete_preserve_identity(self):
        self.approve()
        rule = copy.deepcopy(self.store.read()['rules'][0])
        request = self.request()
        request['commands'] = [{'operation': 'upsert', 'id': rule['id'], 'rule': dict(rule, name='Renamed')}]
        self.approve(request)
        self.assertEqual(self.store.read()['rules'][0]['id'], rule['id'])
        request = self.request()
        request['commands'] = [{'operation': 'enable', 'id': rule['id'], 'enabled': False}]
        self.approve(request)
        self.assertEqual(self.manager.listing(1000, {})['rules'][0]['state'], 'DISABLED')
        request = self.request()
        request['commands'] = [{'operation': 'delete', 'id': rule['id']}]
        self.approve(request)
        self.assertEqual(self.store.read()['rules'], [])

    def test_only_installed_incoming_catalog_is_accepted(self):
        class Provider:
            def catalog(self):
                return {'zones': ['public'], 'services': ['ssh']}
            def capture(self, before, after):
                return []
        self.manager.firewall = Provider()
        request = {'provider': 'incoming', 'revision': 0, 'commands': [{'operation': 'upsert', 'rule': {'zone': 'public', 'ports': '8443', 'source': '192.0.2.5'}}]}
        preview = self.manager.prepare(1000, request)
        rule = preview['changes'][0]['rule']
        compiled = rich_rules(rule)
        self.assertEqual(len(compiled), 2)
        self.assertTrue(all('source address="192.0.2.5/32"' in r and 'port="8443"' in r for r in compiled))
        request['commands'][0]['rule']['zone'] = 'uninstalled'
        with self.assertRaises(PolicyError):
            self.manager.prepare(1000, request)

    def test_mixed_provider_batch_is_refused(self):
        request = self.request(provider='incoming')
        with self.assertRaises(PolicyError):
            self.manager.prepare(1000, request)

    def test_undo_is_reviewed_revision_bound_and_requires_authentication(self):
        saved = self.approve()
        undo = self.manager.prepare(1000, {'provider': 'application', 'revision': saved['revision'], 'undo': saved['undo']})
        self.assertEqual(len(self.store.read()['rules']), 1)
        def deny(*args):
            raise PolicyError('Cancelled')
        with self.assertRaises(PolicyError):
            self.manager.apply(1000, undo['transaction'], deny)
        self.assertEqual(len(self.store.read()['rules']), 1)
        undo = self.manager.prepare(1000, {'provider': 'application', 'revision': saved['revision'], 'undo': saved['undo']})
        self.manager.apply(1000, undo['transaction'], lambda *args: None)
        self.assertEqual(self.store.read()['rules'], [])
        with self.assertRaises(PolicyError):
            self.manager.prepare(1000, {'provider': 'application', 'revision': self.store.read()['revision'], 'undo': saved['undo']})


if __name__ == '__main__':
    unittest.main()
