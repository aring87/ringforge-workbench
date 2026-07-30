"""Non-routable addresses are context, not destinations the sample contacted.

The SSDP case here is taken from a real detonation (UPX-packed mimikatz,
2026-07-30), where 239.255.255.250 was reported both as a contacted external IP
and as a notable URL. The sample had no network activity whatsoever.

The controls matter as much as the filters: a suppression rule that also
swallows a real C2 address is worse than the noise it removes.
"""

import unittest

from dynamic_analysis.network_capture import (
    extract_network_iocs,
    is_non_routable_ip,
    is_private_ip,
)


class AddressClassificationTests(unittest.TestCase):
    def test_multicast_and_broadcast_are_non_routable(self) -> None:
        for address in ("239.255.255.250", "224.0.0.251", "255.255.255.255", "0.0.0.0", "ff02::c"):
            self.assertTrue(is_non_routable_ip(address), address)

    def test_public_addresses_are_routable(self) -> None:
        for address in ("8.8.8.8", "185.220.101.1", "2606:4700::1111"):
            self.assertFalse(is_non_routable_ip(address), address)
            self.assertFalse(is_private_ip(address), address)

    def test_ipv6_link_local_is_private(self) -> None:
        # The previous implementation matched an IPv4 regex first, so every IPv6
        # address fell through as routable.
        self.assertTrue(is_private_ip("fe80::2f07:73c:ecb:647"))
        self.assertTrue(is_private_ip("fe80::1%12"))  # Windows zone index

    def test_unparseable_input_is_not_suppressed(self) -> None:
        # Failing open is the safe direction: hiding what cannot be parsed
        # would drop malformed but real indicators.
        self.assertFalse(is_non_routable_ip("not-an-ip"))


class SsdpNoiseTests(unittest.TestCase):
    CAPTURE = {
        "dns_queries": ["_spotify-connect._tcp.local", "c896B2E00000.local", "_googlecast._tcp.local"],
        "tls_sni": [],
        "http_requests": [{"method": "M-SEARCH", "host": "239.255.255.250:1900", "uri": "*"}],
        "connections": [],
    }

    def test_ssdp_is_not_a_contacted_external_address(self) -> None:
        iocs = extract_network_iocs(self.CAPTURE)
        self.assertEqual(iocs["external_ips"], [])
        self.assertEqual(iocs["non_routable_ips"], ["239.255.255.250"])

    def test_ssdp_url_is_not_a_notable_url(self) -> None:
        iocs = extract_network_iocs(self.CAPTURE)
        self.assertEqual(iocs["notable_urls"], [])
        # Still present in the unfiltered list, not erased.
        self.assertEqual(len(iocs["urls"]), 1)


class RealIndicatorsSurviveTests(unittest.TestCase):
    def test_public_c2_is_still_reported(self) -> None:
        iocs = extract_network_iocs({
            "dns_queries": ["evil-c2.example"],
            "tls_sni": ["evil-c2.example"],
            "http_requests": [{"method": "POST", "host": "185.220.101.1", "uri": "/gate.php"}],
            "connections": [{"dst": "185.220.101.1"}, {"dst": "192.168.56.10"}],
        })

        self.assertEqual(iocs["external_ips"], ["185.220.101.1"])
        self.assertEqual(iocs["notable_urls"], ["http://185.220.101.1/gate.php"])
        self.assertEqual(iocs["notable_domains"], ["evil-c2.example"])
        # The lab's own SIEM host is private, so it is not an external contact.
        self.assertNotIn("192.168.56.10", iocs["external_ips"])


if __name__ == "__main__":
    unittest.main()
