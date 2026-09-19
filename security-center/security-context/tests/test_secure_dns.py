import sys
import unittest
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
    def test_default_provider_chain_is_ordered_and_encrypted(self):
        self.assertEqual(tuple(PROVIDERS), ("quad9", "controld", "adguard"))
        self.assertEqual(PROVIDERS["quad9"]["sni"], "dns.quad9.net")
        self.assertEqual(PROVIDERS["controld"]["sni"], "p2.freedns.controld.com")
        self.assertEqual(PROVIDERS["adguard"]["sni"], "dns.adguard-dns.com")
        self.assertTrue(all(len(PROVIDERS[key]["addresses"]) >= 2 for key in PROVIDERS))

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
