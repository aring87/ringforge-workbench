"""Microsoft's own chatter must not sit in the card that names the C2.

An AgentTesla run put aefd.nelreports.net in "Domains Requested Against
Simulated Internet" -- the alert-styled card -- directly beside
ftp.cyberflor.co. Network Error Logging is something Edge and Office report to
unprompted, and that card is the one place a false positive costs something:
it is short, and a reader learns to skim a list that cries wolf.

Three suffixes were missing, all seen in real runs of this session:

    nelreports.net       Edge and Office error reporting
    microsoft365.com     a different registrable domain from microsoft.com
    microsoft            Microsoft's brand gTLD, which only they can register
    microsoftofficehub   an app package name that reaches the resolver

The suffix match is anchored -- value == suffix, or value ends with "." +
suffix -- so a masquerade like microsoft.com.evil.ru does not qualify. That
anchoring is what makes a bare "microsoft" safe to list.
"""

import unittest

from dynamic_analysis.network_capture import (
    is_baseline_domain,
    is_windows_baseline_domain,
)


class BackgroundIsRecognisedTests(unittest.TestCase):
    """Every one of these was observed in a real run of this workbench."""

    def test_network_error_logging(self) -> None:
        self.assertTrue(is_windows_baseline_domain("aefd.nelreports.net"))

    def test_microsoft365_is_its_own_domain(self) -> None:
        # Not a subdomain of microsoft.com, so it matched nothing before.
        self.assertTrue(is_windows_baseline_domain("www.microsoft365.com"))

    def test_the_brand_gtld(self) -> None:
        self.assertTrue(
            is_windows_baseline_domain("res.public.onecdn.static.microsoft")
        )

    def test_the_office_hub_package_name(self) -> None:
        self.assertTrue(is_baseline_domain("microsoft.microsoftofficehub"))

    def test_the_ones_that_already_worked_still_do(self) -> None:
        for name in (
            "self.events.data.microsoft.com",
            "edge.microsoft.com",
            "tas02.sls.update.microsoft.com",
            "ecs.office.com",
            "www.bing.com",
        ):
            self.assertTrue(is_windows_baseline_domain(name), name)


class MasqueradesAreNotBaselineTests(unittest.TestCase):
    """The suffix match is anchored, which is what keeps this safe."""

    def test_the_c2_is_not_baseline(self) -> None:
        self.assertFalse(is_windows_baseline_domain("ftp.cyberflor.co"))

    def test_a_microsoft_prefixed_attacker_domain(self) -> None:
        self.assertFalse(is_windows_baseline_domain("microsoft.com.evil.ru"))

    def test_a_lookalike_registrable_domain(self) -> None:
        self.assertFalse(is_windows_baseline_domain("notmicrosoft.com"))
        self.assertFalse(is_windows_baseline_domain("evil-microsoft.co"))

    def test_a_package_name_used_as_a_label(self) -> None:
        self.assertFalse(is_windows_baseline_domain("microsoftofficehub.evil.ru"))


if __name__ == "__main__":
    unittest.main()
