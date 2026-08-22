"""Non-routable addresses are context, not destinations the sample contacted.

The SSDP case here is taken from a real detonation (UPX-packed mimikatz,
2026-07-30), where 239.255.255.250 was reported both as a contacted external IP
and as a notable URL. The sample had no network activity whatsoever.

The controls matter as much as the filters: a suppression rule that also
swallows a real C2 address is worse than the noise it removes.
"""

import unittest

from dynamic_analysis.network_capture import (
    classify_domain,
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


class DomainClassificationTests(unittest.TestCase):
    """mDNS from the host LAN is not Windows background traffic.

    Both are suppressed, but reporting a Chromecast announcing itself as
    "Windows Baseline Traffic" tells the reader something untrue about where it
    came from.
    """

    CAPTURE = {
        "dns_queries": [
            "c896B2E00000.local",
            "_spotify-connect._tcp.local",
            "ctldl.windowsupdate.com",
            "evil-c2.example",
        ],
        "tls_sni": [], "http_requests": [], "connections": [],
    }

    def test_each_kind_lands_in_its_own_bucket(self) -> None:
        iocs = extract_network_iocs(self.CAPTURE)
        self.assertEqual(iocs["notable_domains"], ["evil-c2.example"])
        self.assertEqual(iocs["baseline_domains"], ["ctldl.windowsupdate.com"])
        self.assertEqual(
            sorted(iocs["local_discovery_domains"]),
            sorted(["c896B2E00000.local", "_spotify-connect._tcp.local"]),
        )

    def test_nothing_is_counted_twice(self) -> None:
        counts = extract_network_iocs(self.CAPTURE)["counts"]
        self.assertEqual(
            counts["notable_domains"] + counts["baseline_domains"] + counts["local_discovery_domains"],
            counts["domains"],
        )

    def test_bare_hostname_is_local_discovery(self) -> None:
        # The guest's own computer name, resolved via LLMNR/NetBIOS.
        self.assertEqual(classify_domain("win11"), "local_discovery")


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


class TheSimulatedInternetIsTheOtherHalfOfTheCapture(unittest.TestCase):
    """The pcap cannot see what FakeNet's diverter intercepted.

    Taken from run `4bb6b0d5` (2026-08-22), which reported **zero** notable
    domains and zero external IPs for a detonation in which the sample fetched
    a C2 hostname from a smart contract and beaconed to it over HTTPS. Both
    names sat in `fakenet_summary["dns_requests"]` the whole time; the pcap held
    three Chromecast and SSDP names and nothing else.

    An empty IOC section reads as a finding rather than as an absence, so this
    was worse than emitting nothing.
    """

    #: What the host adapter saw: local discovery chatter only.
    PCAP = {
        "dns_queries": ["_googlecast._tcp.local", "_spotify-connect._tcp.local"],
        "tls_sni": [],
        "http_requests": [],
        "connections": [],
    }

    #: What FakeNet answered, which is what the guest actually asked for.
    FAKENET = {
        "dns_requests": [
            "www.msftconnecttest.com",
            "data-seed-prebsc-1-s1.binance.org",
            "c0ffee-sink.ringforge.test",
        ],
    }

    def test_the_c2_names_survive_a_pcap_that_never_saw_them(self) -> None:
        iocs = extract_network_iocs(self.PCAP, self.FAKENET)

        self.assertIn("data-seed-prebsc-1-s1.binance.org", iocs["notable_domains"])
        self.assertIn("c0ffee-sink.ringforge.test", iocs["notable_domains"])

    def test_without_the_merge_the_run_reports_nothing(self) -> None:
        # The regression itself, kept as an executable statement of what was
        # wrong rather than a comment about it.
        self.assertEqual(extract_network_iocs(self.PCAP)["notable_domains"], [])

    def test_a_pcap_full_of_multicast_still_counts_as_blind(self) -> None:
        # The first version of this flag asked whether the pcap saw *any* name,
        # which run 4bb6b0d5 would have passed on two names of Chromecast noise.
        # What matters is whether it saw the names that mattered.
        iocs = extract_network_iocs(self.PCAP, self.FAKENET)

        self.assertTrue(iocs["pcap_blind"])
        self.assertIn("c0ffee-sink.ringforge.test", iocs["note"])

    def test_agreement_between_the_two_is_not_a_gap(self) -> None:
        pcap = dict(self.PCAP, dns_queries=["evil-c2.example"])
        iocs = extract_network_iocs(pcap, {"dns_requests": ["evil-c2.example"]})

        self.assertEqual(iocs["notable_domains"], ["evil-c2.example"])
        self.assertFalse(iocs["pcap_blind"])

    def test_sources_says_which_input_contributed(self) -> None:
        self.assertEqual(extract_network_iocs(self.PCAP, self.FAKENET)["sources"],
                         ["pcap", "fakenet"])
        self.assertEqual(extract_network_iocs(self.PCAP)["sources"], ["pcap"])

    def test_fakenet_baseline_noise_is_still_suppressed(self) -> None:
        # The control this file exists for: a merge that also promotes Windows
        # telemetry to a lead is worse than the false negative it fixes.
        iocs = extract_network_iocs(self.PCAP, self.FAKENET)

        self.assertIn("www.msftconnecttest.com", iocs["baseline_domains"])
        self.assertNotIn("www.msftconnecttest.com", iocs["notable_domains"])

    def test_neither_source_recording_is_reported_as_a_collection_gap(self) -> None:
        # Silence from both is ambiguous, and saying so is the whole point.
        iocs = extract_network_iocs(
            {"dns_queries": [], "tls_sni": [], "http_requests": [], "connections": []},
            {"dns_requests": []},
        )

        self.assertEqual(iocs["sources"], [])
        self.assertIn("absence of collection", iocs["note"])

    def test_a_missing_fakenet_summary_is_not_an_error(self) -> None:
        # FakeNet off, or its log unparsed, must cost only FakeNet's half.
        for absent in (None, {}, "not a dict"):
            iocs = extract_network_iocs(self.PCAP, absent)
            self.assertEqual(iocs["sources"], ["pcap"])


if __name__ == "__main__":
    unittest.main()
