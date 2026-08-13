"""The scoring decision for the three detectors measured on 13 Aug.

Two are folded into `process_injection`; one stays context-only. The reasoning
is recorded here because "why is this not scored" is the question a future
reader will actually have.

**Folded in, not added as categories.** The category doc is explicit that a
category must fire at most once however many events back it, "otherwise a single
chatty behaviour outvotes three quiet ones and the model is volume-driven
again", and the carver was folded in for exactly this reason: a hollow produces
the crash and the foreign image from one event. On run `d7cc5044` the same
single act -- hollowing `RegSvcs.exe` -- was visible to the crash route, the WER
route, module integrity and the ntdll pass. Scored separately, one hollow would
have outvoted persistence, C2 and a dropped payload combined.

**`strong` only in a hollowing target**, the same test the other three routes
use, and here the reason is specific: a long-running process still holding an
image that has since been patched on disk produces a legitimate timestamp
mismatch, and Windows servicing does that to something on every update -- it is
what rotted this suite's own reference dump on 11 Aug. A hollowing target is
spawned on demand and short-lived, so it cannot have outlived an update.

**The ntdll pass stays context-only**, and that is a decision rather than a
default. It has one observation, its benign rate needs a Procmon capture this
project has not taken, and its claim is *defence evasion* rather than injection
-- bolting it onto `process_injection` would be scoring a different behaviour
through the wrong category.
"""
import unittest

from dynamic_analysis.orchestrator import _evidence_categories

BASE = dict(
    memory_only_rules=[], sysmon_injections=0, unmapped_memory_crashes=0,
    hollowing_target_crashes=0, unmapped_pe_images=0,
    unmapped_pe_in_hollowing_target=0, sysmon_high=0, suspicious_tasks=0,
    suspicious_services=0, autoruns_suspicious=0, suspicious_dropped=0,
    notable_domains=0, host_domains=0, external_destinations=0,
    unusual_ports=0, suspicious_scriptblocks=0,
)


def injection(**over):
    cats = _evidence_categories(**{**BASE, **over})
    return next(c for c in cats if c["name"] == "process_injection")


class TheTwoFoldedIn(unittest.TestCase):
    def test_a_timestamp_mismatch_alone_is_present(self):
        c = injection(image_timestamp_mismatches=1)
        self.assertTrue(c["present"])
        self.assertFalse(c["strong"])

    def test_a_timestamp_mismatch_in_a_hollowing_target_is_strong(self):
        c = injection(image_timestamp_mismatches=1,
                      image_timestamp_mismatch_in_target=1)
        self.assertTrue(c["strong"])
        self.assertIn("timestamp", c["reason"].lower())

    def test_a_module_header_mismatch_alone_is_present(self):
        c = injection(module_header_mismatches=1)
        self.assertTrue(c["present"])
        self.assertFalse(c["strong"])

    def test_a_module_header_mismatch_in_a_hollowing_target_is_strong(self):
        c = injection(module_header_mismatches=1,
                      module_header_mismatch_in_target=1)
        self.assertTrue(c["strong"])

    def test_neither_fires_on_a_quiet_run(self):
        self.assertFalse(injection()["present"])
        self.assertFalse(injection()["strong"])


class OneHollowScoresOnce(unittest.TestCase):
    """The property the whole design rests on."""

    def test_all_five_routes_firing_is_still_one_category(self):
        cats = _evidence_categories(**{
            **BASE,
            "sysmon_injections": 3,
            "unmapped_memory_crashes": 1,
            "hollowing_target_crashes": 1,
            "unmapped_pe_images": 2,
            "unmapped_pe_in_hollowing_target": 1,
            "image_timestamp_mismatches": 1,
            "image_timestamp_mismatch_in_target": 1,
            "module_header_mismatches": 1,
            "module_header_mismatch_in_target": 1,
        })
        firing = [c for c in cats if c["present"]]
        self.assertEqual([c["name"] for c in firing], ["process_injection"])

    def test_run_d7cc5044_would_be_strong_from_either_new_route_alone(self):
        # The run's actual shape: the dump watcher missed the child entirely,
        # so the carver and the crash route had nothing. Only the WER route
        # saw it live, and module integrity saw it afterwards from the crash
        # dump. Either alone must carry the category.
        wer_only = injection(image_timestamp_mismatches=1,
                             image_timestamp_mismatch_in_target=1)
        mi_only = injection(module_header_mismatches=1,
                            module_header_mismatch_in_target=1)
        self.assertTrue(wer_only["strong"])
        self.assertTrue(mi_only["strong"])


class UncollectedIsNotClean(unittest.TestCase):
    """`available: false` must contribute nothing, in either direction."""

    def test_an_unavailable_pass_contributes_nothing(self):
        # The orchestrator gates on `available` before counting; this asserts
        # the category itself is not reading a stray count as evidence.
        self.assertFalse(injection(image_timestamp_mismatches=0,
                                   module_header_mismatches=0)["present"])


class TheNtdllPassIsNotScored(unittest.TestCase):
    def test_it_is_absent_from_the_evidence_categories(self):
        names = {c["name"] for c in _evidence_categories(**BASE)}
        self.assertNotIn("ntdll_unhooking", names)
        self.assertNotIn("self_unhooking", names)

    def test_the_pass_declares_itself_unscored(self):
        from dynamic_analysis.ntdll_unhooking import (
            collect_ntdll_unhooking,
            empty_ntdll_unhooking,
        )

        self.assertFalse(collect_ntdll_unhooking([], None)["scored"])
        self.assertFalse(empty_ntdll_unhooking()["scored"])


if __name__ == "__main__":
    unittest.main()
