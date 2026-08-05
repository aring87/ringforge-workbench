"""`ok` has to mean contained, and not contained has to stop the run.

A test detonation was run deliberately with the guest armed, to see whether
anything would catch it. Nothing did. Two separate failures, and the second is
the serious one.

**The check counted routes.** `level` was `ok` whenever exactly one default
route existed, regardless of where it went. VirtualBox's NAT gives the guest
10.0.2.15 with the gateway at 10.0.2.2 -- a private address, on the adapter
`vm_net.ps1 -Arm` connects -- so a guest whose only default route was the NAT
adapter reported:

    level: ok
    note:  Single egress path via Intel(R) PRO/1000 MT Desktop Adapter

That is a fully internet-connected machine described as contained, by the field
WORKFLOW tells you to read first, every time.

**And nothing enforced it.** Even when the level was not `ok`, the orchestrator
emitted a status line and launched the sample anyway. WORKFLOW says "do not
detonate anything in the armed state" and the code treated that as advice. A
containment control that only writes to a log is documentation.

Counting routes says nothing about where they go. Both halves are tested here:
the classification, and the refusal.
"""

import unittest
from unittest import mock

from dynamic_analysis import network_capture
from dynamic_analysis.network_capture import (
    is_vm_nat_gateway,
    network_isolation_status,
)

#: What `route print -4` yields, as default_route_interfaces returns it.
HOST_ONLY = {"gateway": "192.168.56.1", "interface_ip": "192.168.56.20", "metric": "25"}
VBOX_NAT = {"gateway": "10.0.2.2", "interface_ip": "10.0.2.15", "metric": "25"}
SECOND_NAT = {"gateway": "10.0.3.2", "interface_ip": "10.0.3.15", "metric": "25"}


def _status(routes, ipv6=False, contained_gateway=""):
    with mock.patch.object(network_capture, "default_route_interfaces", return_value=routes), \
         mock.patch.object(network_capture, "has_ipv6_default_route", return_value=ipv6), \
         mock.patch.object(network_capture, "list_interfaces", return_value=[]):
        return network_isolation_status(contained_gateway=contained_gateway)


class NatGatewayTests(unittest.TestCase):
    def test_virtualbox_nat_gateways_are_recognised(self) -> None:
        self.assertTrue(is_vm_nat_gateway("10.0.2.2"))
        self.assertTrue(is_vm_nat_gateway("10.0.3.2"))

    def test_a_host_only_gateway_is_not_a_nat_gateway(self) -> None:
        self.assertFalse(is_vm_nat_gateway("192.168.56.1"))
        self.assertFalse(is_vm_nat_gateway("10.0.2.1"))


class ClassificationTests(unittest.TestCase):
    def test_a_lone_nat_route_is_uncontained(self) -> None:
        # The case that got through. One route, private address, previously
        # reported as "ok" with a reassuring note.
        status = _status([VBOX_NAT])

        self.assertEqual(status["level"], "uncontained")
        self.assertFalse(status["contained"])
        self.assertEqual(status["internet_egress_count"], 1)
        self.assertIn("ARMED", status["note"])

    def test_armed_alongside_the_host_only_route_is_uncontained(self) -> None:
        # Two routes used to be a "warning", which at least said something --
        # but it said "disable an adapter", not "you are armed".
        status = _status([HOST_ONLY, VBOX_NAT])

        self.assertEqual(status["level"], "uncontained")
        self.assertEqual(status["internet_egress_count"], 1)

    def test_the_host_only_route_alone_is_contained(self) -> None:
        # The normal disarmed state must keep passing, or the control gets
        # switched off.
        status = _status([HOST_ONLY])

        self.assertEqual(status["level"], "ok")
        self.assertTrue(status["contained"])

    def test_no_route_at_all_is_contained(self) -> None:
        status = _status([])

        self.assertEqual(status["level"], "ok")
        self.assertTrue(status["isolated"])

    def test_two_ordinary_adapters_still_warn(self) -> None:
        # Neither is a NAT gateway, but FakeNet only redirects one adapter.
        other = {"gateway": "192.168.99.1", "interface_ip": "192.168.99.5", "metric": "25"}
        status = _status([HOST_ONLY, other])

        self.assertEqual(status["level"], "warning")

    def test_an_ipv6_default_route_still_warns(self) -> None:
        status = _status([HOST_ONLY], ipv6=True)

        self.assertEqual(status["level"], "warning")

    def test_a_second_nat_adapter_is_caught_too(self) -> None:
        status = _status([SECOND_NAT])

        self.assertEqual(status["level"], "uncontained")


class ConfiguredGatewayTests(unittest.TestCase):
    def test_an_unexpected_gateway_is_uncontained_when_one_is_configured(self) -> None:
        # Fail closed: a path out that is not the known one is not a verified
        # one, whatever its address looks like.
        other = {"gateway": "192.168.99.1", "interface_ip": "192.168.99.5", "metric": "25"}
        status = _status([other], contained_gateway="192.168.56.1")

        self.assertEqual(status["level"], "uncontained")
        self.assertIn("192.168.56.1", status["note"])

    def test_the_configured_gateway_passes(self) -> None:
        status = _status([HOST_ONLY], contained_gateway="192.168.56.1")

        self.assertEqual(status["level"], "ok")

    def test_without_a_configured_gateway_a_non_nat_route_still_passes(self) -> None:
        # Not everyone's isolated network is 192.168.56.x, and blocking every
        # unconfigured setup would get the override switched on permanently.
        other = {"gateway": "172.16.4.1", "interface_ip": "172.16.4.9", "metric": "25"}
        status = _status([other])

        self.assertEqual(status["level"], "ok")


if __name__ == "__main__":
    unittest.main()
