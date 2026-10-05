import contextlib
import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

try:
    from greyward_security_context import secure_dns_reconciler as dns
    from greyward_security_context import secure_dns_split as split
except ModuleNotFoundError as error:
    if str(error.name or '').startswith(('dbus', 'gi')):
        split = None
    else:
        raise


@unittest.skipIf(split is None, 'resolve1 runtime dependencies unavailable')
class SplitDnsTests(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self, domains=(('home.arpa', False),), probe_error=None):
        props = {'DNSEx': [(2, [192, 168, 1, 1], 0, '')],
                 'CurrentDNSServerEx': (2, [192, 168, 1, 1], 0, ''),
                 'Domains': list(domains), 'DefaultRoute': True,
                 'DNSOverTLS': 'no', 'DNSSEC': 'no'}
        original = copy.deepcopy(props)
        manager, bus = Mock(), Mock()
        manager.SetLinkDefaultRoute.side_effect = lambda i, v, **kw: props.update(DefaultRoute=bool(v))
        manager.SetLinkDNSOverTLS.side_effect = lambda i, v, **kw: props.update(DNSOverTLS=str(v))
        manager.SetLinkDNSSEC.side_effect = lambda i, v, **kw: props.update(DNSSEC=str(v))
        public = {'DNSEx': [], 'Domains': [], 'DNSOverTLS': 'no', 'DNSSEC': 'no'}
        def reload_scope(_bus):
            owner = split._owned_configuration()
            previous_domains = public.get('Domains', [])
            public.clear()
            public.update(DNSEx=[], Domains=previous_domains if not owner else [], DNSOverTLS='no', DNSSEC='no')
            if owner in dns.PROVIDERS:
                entries = dns._provider_dns(dns.PROVIDERS[owner])
                public.update(DNSEx=entries, Domains=[('.', True)], DNSOverTLS='yes', DNSSEC='yes', CurrentDNSServerEx=entries[0])
        with tempfile.TemporaryDirectory() as temporary, contextlib.ExitStack() as stack:
            root = Path(temporary)
            stack.enter_context(patch.object(split, 'CONFIG_PATH', root / 'scope.conf'))
            stack.enter_context(patch.object(split, 'SNAPSHOT_PATH', root / 'private.json'))
            stack.enter_context(patch.object(split, '_global', side_effect=lambda bus: public))
            stack.enter_context(patch.object(split, '_reload', side_effect=reload_scope))
            stack.enter_context(patch.object(dns.dbus, 'Interface', return_value=manager))
            stack.enter_context(patch.object(dns, '_resolved_link', side_effect=lambda *args: ('/link/2', props)))
            stack.enter_context(patch.object(dns, '_link', side_effect=lambda *args: props))
            stack.enter_context(patch.object(dns, '_probe', return_value=(True, True, probe_error)))
            yield bus, props, original, manager, public

    def reconcile(self, bus, props):
        base = {'route_domains': dns._domains(props), 'effective_policy': 'Disconnected'}
        return split.reconcile(bus, {'ifindex': 2, 'interface': 'eth0'}, props, base,
                               {'provider_order': list(dns.PROVIDERS)})

    def test_public_scope_preserves_search_and_private_dns_for_any_network(self):
        for domains in ([('mshome.net', False)], [('home.arpa', False)], [('corp.example', True)]):
            with self.fixture(domains) as (bus, props, original, manager, public):
                value = self.reconcile(bus, props)
                self.assertEqual(value['effective_policy'], 'SecureProvider')
                self.assertEqual(value['effective_transport'], 'DoT')
                self.assertEqual(props['DNSEx'], original['DNSEx'])
                self.assertEqual(props['Domains'], original['Domains'])
                self.assertFalse(props['DefaultRoute'])
                self.assertEqual(public['Domains'], [('.', True)])
                self.assertEqual(split.active_private_addresses(bus), {'192.168.1.1'})
                manager.SetLinkDNSEx.assert_not_called()
                manager.SetLinkDomains.assert_not_called()
                split.restore(bus)
                self.assertEqual(props, original)
                self.assertFalse(split.CONFIG_PATH.exists())
                self.assertFalse(split.SNAPSHOT_PATH.exists())

    def test_outage_keeps_strict_public_scope_without_dhcp_fallback(self):
        with self.fixture(probe_error='TimedOut') as (bus, props, original, manager, public):
            value = self.reconcile(bus, props)
            self.assertEqual(value['effective_policy'], 'Unavailable')
            self.assertEqual(value['degradation_reason'], 'AllProvidersUnavailable')
            self.assertTrue(split.CONFIG_PATH.exists())
            self.assertEqual(public['DNSOverTLS'], 'yes')
            self.assertFalse(props['DefaultRoute'])
            self.assertEqual(props['DNSEx'], original['DNSEx'])

    def test_scope_removal_clears_reload_retained_domain_and_allows_reentry(self):
        with self.fixture() as (bus, props, original, manager, public):
            for _ in range(2):
                self.assertEqual(self.reconcile(bus, props)['effective_policy'], 'SecureProvider')
                split.restore(bus)
                self.assertEqual(public['Domains'], [])
                self.assertEqual(public['DNSEx'], [])
                self.assertEqual(props, original)
            # Resume an interrupted removal using the owned reset marker.
            split.CONFIG_PATH.write_text(split.RESET_CONFIGURATION)
            public['Domains'] = [('.', True)]
            self.assertEqual(self.reconcile(bus, props)['effective_policy'], 'SecureProvider')

    def test_foreign_global_scope_and_foreign_file_are_never_overwritten(self):
        with self.fixture() as (bus, props, original, manager, public):
            public['DNSEx'] = [(2, [1, 1, 1, 1], 0, '')]
            value = self.reconcile(bus, props)
            self.assertEqual(value['degradation_reason'], 'SplitDnsAmbiguous')
            self.assertEqual(props, original)
            self.assertFalse(split.SNAPSHOT_PATH.exists())
            split.CONFIG_PATH.write_text('[Resolve]\nDNS=1.1.1.1\n')
            with self.assertRaises(ValueError):
                self.reconcile(bus, props)
            self.assertEqual(split.CONFIG_PATH.read_text(), '[Resolve]\nDNS=1.1.1.1\n')

    def test_network_changed_ownership_is_not_restored_or_authorized(self):
        with self.fixture() as (bus, props, original, manager, public):
            self.reconcile(bus, props)
            props['DNSEx'] = [(2, [10, 0, 0, 1], 0, '')]
            props['Domains'] = [('new.example', True)]
            changed = copy.deepcopy(props)
            self.assertEqual(split.active_private_addresses(bus), set())
            manager.reset_mock()
            split.restore(bus)
            self.assertEqual(props, changed)
            manager.SetLinkDefaultRoute.assert_not_called()

    def test_private_exception_requires_live_public_scope_and_private_route(self):
        with self.fixture() as (bus, props, original, manager, public):
            self.reconcile(bus, props)
            props['DefaultRoute'] = True
            self.assertEqual(split.active_private_addresses(bus), set())
            props['DefaultRoute'] = False
            public['Domains'] = []
            self.assertEqual(split.active_private_addresses(bus), set())

    def test_split_scope_restoration_failure_preserves_snapshot_for_retry(self):
        with self.fixture() as (bus, props, original, manager, public):
            self.reconcile(bus, props)
            manager.SetLinkDefaultRoute.side_effect = dns.dbus.DBusException('restore failed')
            with self.assertRaises(dns.dbus.DBusException):
                split.restore(bus)
            self.assertTrue(split.SNAPSHOT_PATH.exists())


if __name__ == '__main__':
    unittest.main()
