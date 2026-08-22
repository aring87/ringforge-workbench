"""Phase 3 of `0bw`: reading the beacon, and answering it.

The request these are built against is the one observed on the wire in run
`4bb6b0d5`, not a reconstruction::

    POST / HTTP/1.1
    Authorization: 4b817807-2731-459c-bc5d-4bd914c9eb55
    Content-Type: application/x-www-form-urlencoded
    Host: c0ffee-sink.ringforge.test

    method=refresh&guid=4814CF26358FE5E4F8A1F9B0F4980910

`method=send&guid=` and `&address=` are resident in the payload's memory and
have never been seen on the wire. Provoking one is what this phase is for, so
`send` is classified by name rather than lumped in with whatever else arrives.
"""

import unittest

from dynamic_analysis.beacon_responder import (
    CAMPAIGN_GUID,
    PLANS,
    BeaconError,
    BeaconPlanner,
    classify,
    parse_beacon,
    substituted_address,
)
from dynamic_analysis.jsonrpc_answer import TRACER_ADDRESS

OBSERVED = b"method=refresh&guid=4814CF26358FE5E4F8A1F9B0F4980910"


class ReadingTheBeaconTests(unittest.TestCase):
    def test_the_observed_request_parses(self) -> None:
        parsed = parse_beacon(OBSERVED)

        self.assertTrue(parsed["parsed"])
        self.assertEqual(parsed["method"], "refresh")
        self.assertEqual(parsed["guid"], "4814CF26358FE5E4F8A1F9B0F4980910")
        self.assertEqual(classify(parsed), "refresh")

    def test_the_send_beacon_is_classified_by_name(self) -> None:
        # The one this phase exists to provoke. It must not arrive and be
        # filed under "other".
        parsed = parse_beacon(
            b"method=send&guid=4814CF26&address=" + TRACER_ADDRESS.encode())

        self.assertEqual(classify(parsed), "send")
        self.assertEqual(parsed["address"], TRACER_ADDRESS)

    def test_an_unparsable_body_is_still_a_beacon_that_arrived(self) -> None:
        # "It sent something we could not read" and "it never called" are the
        # two readings this whole investigation keeps having to separate.
        parsed = parse_beacon(b"\x00\x01\x02 not form encoded at all")

        self.assertFalse(parsed["parsed"])
        self.assertEqual(classify(parsed), "unparsed")

    def test_an_empty_body_does_not_read_as_a_valid_beacon(self) -> None:
        self.assertEqual(classify(parse_beacon(b"")), "unparsed")

    def test_an_unknown_method_is_other_rather_than_dropped(self) -> None:
        parsed = parse_beacon(b"method=harvest&guid=abc")

        self.assertEqual(classify(parsed), "other")
        self.assertEqual(parsed["method"], "harvest")

    def test_the_campaign_guid_is_recorded_for_comparison(self) -> None:
        # It travels in the Authorization header, not the body. Kept as a
        # constant so a beacon bearing a different one reads as a different
        # campaign instead of blending in.
        self.assertEqual(CAMPAIGN_GUID, "4b817807-2731-459c-bc5d-4bd914c9eb55")


class TheTracerTests(unittest.TestCase):
    """`address=` is the answer to the question the whole case turns on."""

    def test_the_tracer_coming_back_means_it_relayed_what_it_was_given(self) -> None:
        parsed = parse_beacon(b"method=send&address=" + TRACER_ADDRESS.encode())

        result = substituted_address(parsed)

        self.assertTrue(result["is_tracer"])
        self.assertTrue(result["well_formed"])

    def test_a_different_address_means_it_substituted(self) -> None:
        # The attacker's ETH wallet, index 4 of the table.
        wallet = "0x0F14fc3bfAc3726172aCd08Fe4bFb79B633E76ff"
        parsed = parse_beacon(b"method=send&address=" + wallet.encode())

        result = substituted_address(parsed)

        self.assertFalse(result["is_tracer"])
        self.assertTrue(result["well_formed"])
        self.assertEqual(result["address"], wallet)

    def test_case_does_not_decide_it(self) -> None:
        # The clipper rewrites in EIP-55 form, so the tracer can come back
        # checksummed. Comparing case-sensitively would report substitution
        # where there was none.
        parsed = parse_beacon(b"method=send&address=" + TRACER_ADDRESS.lower().encode())

        self.assertTrue(substituted_address(parsed)["is_tracer"])

    def test_a_malformed_address_is_flagged_rather_than_discarded(self) -> None:
        parsed = parse_beacon(b"method=send&address=NOT-AN-ADDRESS")

        result = substituted_address(parsed)

        self.assertTrue(result["present"])
        self.assertFalse(result["well_formed"])


class AnsweringTests(unittest.TestCase):
    def test_rotation_advances_on_each_answer(self) -> None:
        planner = BeaconPlanner()

        served = [planner.answer()["plan"] for _ in range(3)]

        self.assertEqual(served, [p.name for p in PLANS[:3]])

    def test_rotation_holds_on_the_last_plan_rather_than_cycling(self) -> None:
        # A client still asking after every hypothesis is telling you the list
        # is wrong, and cycling would bury that under repetition.
        planner = BeaconPlanner()
        for _ in range(len(PLANS) + 3):
            planner.answer()

        self.assertEqual(planner.served[-1], PLANS[-1].name)
        self.assertTrue(planner.report()["all_plans_exhausted"])

    def test_pinning_serves_one_shape_forever(self) -> None:
        # Which is what the next run needs if the beacon turns out not to retry.
        planner = BeaconPlanner(plan="json_wallets")

        self.assertEqual({planner.answer()["plan"] for _ in range(4)},
                         {"json_wallets"})

    def test_a_single_attempt_is_reported_as_rotation_not_advancing(self) -> None:
        # The reading that decides whether rotation was the right instrument at
        # all: one beacon means this run tested one shape, however many were
        # listed, and the next must pin a different one.
        planner = BeaconPlanner()
        planner.answer()

        report = planner.report()

        self.assertEqual(report["attempts"], 1)
        self.assertFalse(report["rotation_advanced"])

    def test_the_empty_plan_leads_because_it_is_the_control(self) -> None:
        # If the process outlives 36 seconds against an empty 200, then
        # FakeNet's stock HTML page was itself the problem, and nothing should
        # be read into the more elaborate shapes until that is excluded.
        self.assertEqual(PLANS[0].name, "empty")
        self.assertEqual(PLANS[0].body(TRACER_ADDRESS), "")

    def test_every_plan_carries_the_address_it_was_given(self) -> None:
        # Except the two that deliberately carry no address at all.
        addressless = {"empty", "ok"}
        for plan in PLANS:
            if plan.name in addressless:
                continue
            self.assertIn(TRACER_ADDRESS, plan.body(TRACER_ADDRESS), plan.name)

    def test_a_real_wallet_is_refused_by_shape_not_by_policy(self) -> None:
        # The address is validated; pointing this at a live wallet is a
        # deliberate act requiring a valid one, never an accident of typing.
        with self.assertRaises(BeaconError):
            BeaconPlanner(address="not-an-address")

    def test_an_unknown_plan_name_fails_loudly(self) -> None:
        # Half-arming a run is worse than not arming it: answering with the
        # wrong thing and refusing to answer look identical from outside.
        with self.assertRaises(BeaconError):
            BeaconPlanner(plan="no_such_plan")

    def test_the_report_says_whether_the_address_is_the_tracer(self) -> None:
        self.assertTrue(BeaconPlanner().report()["address_is_tracer"])


if __name__ == "__main__":
    unittest.main()
