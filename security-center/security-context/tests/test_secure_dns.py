import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

try:
    from greyward_security_context.secure_dns_reconciler import PROVIDERS, _managed
except ModuleNotFoundError as error:
    if str(error.name or "").startswith(("dbus", "gi")):
        PROVIDERS = None
        _managed = None
    else:
        raise


@unittest.skipIf(_managed is None, "resolve1 runtime dependencies are unavailable on this host")
class SecureDnsOwnershipTests(unittest.TestCase):
    def state_fixture(self, domains, devices=None, probe_error=None):
        from greyward_security_context import secure_dns_reconciler as dns
        props = {'DNSEx': [(2, [172, 26, 144, 1], 0, '')],
                 'CurrentDNSServerEx': (2, [172, 26, 144, 1], 0, ''),
                 'DNSOverTLS': 'no', 'DNSSEC': 'no', 'Domains': domains, 'DefaultRoute': True}
        manager = Mock()
        def apply_dns(ifindex, entries, **kwargs):
            props['DNSEx'] = entries
            props['CurrentDNSServerEx'] = entries[0]
        manager.SetLinkDNSEx.side_effect = apply_dns
        manager.SetLinkDNSOverTLS.side_effect = lambda i, value, **kw: props.update(DNSOverTLS=value)
        manager.SetLinkDNSSEC.side_effect = lambda i, value, **kw: props.update(DNSSEC=value)
        manager.SetLinkDomains.side_effect = lambda i, value, **kw: props.update(Domains=value)
        device = {'interface': 'eth0', 'ifindex': 2, 'vpn': False}
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(dns, 'SNAPSHOT_PATH', Path(temporary) / 'snapshot.json'), \
             patch.object(dns.dbus, 'SystemBus', return_value=Mock()), \
             patch.object(dns.dbus, 'Interface', return_value=manager), \
             patch.object(dns, '_policy', return_value={'desired_policy': 'Automatic', 'provider': 'quad9', 'provider_order': list(PROVIDERS)}), \
             patch.object(dns, '_active_devices', return_value=devices or [device]), \
             patch.object(dns, '_mutation_enabled', return_value=True), \
             patch('greyward_security_context.secure_dns_split.restore'), \
             patch.object(dns, '_link', side_effect=lambda *args: props), \
             patch.object(dns, '_read', return_value={}), \
             patch.object(dns, '_write') as write, \
             patch.object(dns, '_probe', return_value=(True, True, probe_error)), \
             patch.object(dns, '_restore_link', return_value=True):
            value = dns._state()
        return value, props, manager, write

    def test_public_link_reconciles_to_verified_provider(self):
        value, props, manager, write = self.state_fixture([])
        self.assertEqual(value['effective_policy'], 'SecureProvider')
        self.assertEqual(value['effective_transport'], 'DoT')
        self.assertIsNone(value['degradation_reason'])
        self.assertEqual(value['resolver']['name'], 'dns.quad9.net')
        self.assertEqual(list(props['Domains']), [])
        self.assertEqual(write.call_args.args[1]['domains'], [])
        manager.SetLinkDomains.assert_not_called()

    def test_private_routes_multiple_links_and_vpn_are_not_overridden(self):
        for domains in ([('.', False)], [('.', True)]):
            value, props, manager, write = self.state_fixture(domains)
            self.assertEqual(value['degradation_reason'], 'SplitDnsAmbiguous')
            manager.SetLinkDNSEx.assert_not_called()
            write.assert_not_called()
        for devices, expected in (([{'interface': 'eth0', 'ifindex': 2, 'vpn': False}, {'interface': 'eth1', 'ifindex': 3, 'vpn': False}], 'Unavailable'),
                                  ([{'interface': 'tun0', 'ifindex': 4, 'vpn': True}], 'VPNOwned')):
            value, props, manager, write = self.state_fixture([('mshome.net', False)], devices)
            self.assertEqual(value['effective_policy'], expected)
            manager.SetLinkDNSEx.assert_not_called()

    def test_ordinary_local_domains_use_separate_public_scope(self):
        for domain in ('mshome.net', 'home.arpa', 'corp.example'):
            for route_only in (False, True):
                with patch('greyward_security_context.secure_dns_split.reconcile', return_value={'effective_policy': 'SecureProvider'}) as reconcile:
                    value, props, manager, write = self.state_fixture([(domain, route_only)])
                self.assertEqual(value['effective_policy'], 'SecureProvider')
                reconcile.assert_called_once()
                self.assertEqual(props['Domains'], [(domain, route_only)])
                manager.SetLinkDNSEx.assert_not_called()

    def test_probe_requires_authenticated_confidential_network_answer(self):
        from greyward_security_context import secure_dns_reconciler as dns
        manager = Mock()
        props = {'DNSOverTLS': 'yes', 'DNSSEC': 'yes'}
        with patch.object(dns, '_resolved_link', return_value=('/link/2', props)), patch.object(dns.dbus, 'Interface', return_value=manager):
            for flags in (0, (1 << 9) | (1 << 18), (1 << 23) | (1 << 9), (1 << 23) | (1 << 18)):
                manager.ResolveHostname.return_value = ([(2, 2, [1, 2, 3, 4])], 'example.com', flags)
                self.assertEqual(dns._probe(Mock(), 2)[2], 'ResolverValidationFailed')
            manager.ResolveHostname.return_value = ([(2, 2, [1, 2, 3, 4])], 'example.com', (1 << 9) | (1 << 18) | (1 << 23))
            self.assertIsNone(dns._probe(Mock(), 2)[2])

    def test_provider_failure_never_claims_secure(self):
        value, props, manager, write = self.state_fixture([], probe_error='TimedOut')
        self.assertEqual(value['effective_policy'], 'Unavailable')
        self.assertEqual(value['degradation_reason'], 'AllProvidersUnavailable')

    def test_default_provider_chain_is_ordered_and_encrypted(self):
        self.assertEqual(tuple(PROVIDERS), ("quad9", "controld", "adguard"))
        self.assertEqual(PROVIDERS["quad9"]["sni"], "dns.quad9.net")
        self.assertEqual(PROVIDERS["controld"]["sni"], "p2.freedns.controld.com")
        self.assertEqual(PROVIDERS["adguard"]["sni"], "dns.adguard-dns.com")
        self.assertTrue(all(len(PROVIDERS[key]["addresses"]) >= 2 for key in PROVIDERS))

    def test_vpn_ownership_does_not_claim_unmeasured_guarantees(self):
        value, _, _, _ = self.state_fixture([], devices=[{'interface':'tun0', 'ifindex':4, 'vpn':True}])
        self.assertEqual(value['effective_owner'], 'VPN')
        self.assertEqual(value['effective_transport'], 'VPNTunnel')
        self.assertTrue(value['tunnel_detected'])
        self.assertEqual(value['encryption'], 'Unknown')
        self.assertEqual(value['validation'], 'Unknown')
        for key in ('encryption_verification', 'kill_switch_verification', 'leak_protection_verification'):
            self.assertEqual(value[key], 'UNKNOWN')

    def test_resolve1_zero_port_does_not_hide_greyward_ownership(self):
        provider = PROVIDERS["quad9"]
        props = {
            "DNSEx": [
                (2, [9, 9, 9, 9], 0, "dns.quad9.net"),
                (2, [149, 112, 112, 112], 0, "dns.quad9.net"),
                (10, list(bytes.fromhex("262000fe0000000000000000000000fe")), 0, "dns.quad9.net"),
                (10, list(bytes.fromhex("262000fe000000000000000000000009")), 0, "dns.quad9.net"),
            ],
            "DNSOverTLS": "yes",
            "DNSSEC": "yes",
        }
        self.assertTrue(_managed(props, provider))

    def test_plain_or_mismatched_link_is_not_owned(self):
        provider = PROVIDERS["quad9"]
        props = {"DNSEx": [(2, [1, 1, 1, 1], 0, "")], "DNSOverTLS": "no", "DNSSEC": "no"}
        self.assertFalse(_managed(props, provider))


if __name__ == "__main__":
    unittest.main()
