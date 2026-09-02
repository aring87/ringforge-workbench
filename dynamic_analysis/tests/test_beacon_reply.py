"""Answering the check-in, and knowing whether the answer worked.

The client has never been replied to. It opens TLS, sends one `Packet: listinfo`
and goes quiet once that lands, so the command half of the protocol is
unobserved. Nothing on disk says what a valid reply looks like, which is why
this enumerates instead of betting a run on one shape -- the same design that
turned four failed `0bw` detonations into one successful one.

The distinction these tests exist to hold: `GUESSES` are guesses, and a sweep
of them that answers nothing proves nothing about the protocol. Only a
vocabulary taken from the payload's own strings can turn a negative into
evidence, which is what `from_commands` is for.
"""

import unittest

from dynamic_analysis.beacon_frame import decode_dictionary, parse_frame
from dynamic_analysis.beacon_reply import (
    GUESSES,
    Candidate,
    ReplyPlan,
    build_reply,
    encode_dictionary,
)


class Encoding(unittest.TestCase):
    def test_a_reply_round_trips_through_the_real_decoder(self) -> None:
        pairs = [("Packet", "ping"), ("Seq", "1")]

        parsed = parse_frame(build_reply(pairs))
        body = decode_dictionary(parsed["decompressed"])

        self.assertTrue(parsed["ok"], parsed["problems"])
        self.assertTrue(body["ok"], body["problems"])
        self.assertEqual(body["pairs"], pairs)

    def test_an_empty_reply_is_a_valid_frame(self) -> None:
        """The first candidate carries no fields at all: it tests the framing
        before any guess about vocabulary is layered on top."""
        parsed = parse_frame(build_reply([]))
        body = decode_dictionary(parsed["decompressed"])

        self.assertTrue(parsed["ok"], parsed["problems"])
        self.assertEqual(body["declared"], 0)
        self.assertEqual(body["pairs"], [])

    def test_a_large_reply_compresses_and_still_decodes(self) -> None:
        pairs = [(f"k{i}", "v" * 40) for i in range(20)]

        parsed = parse_frame(build_reply(pairs))

        self.assertTrue(parsed["compressed"])
        self.assertEqual(decode_dictionary(parsed["decompressed"])["pairs"], pairs)

    def test_the_count_is_pairs_not_strings(self) -> None:
        """Encoding the string count would double it, and the client's decoder
        would read a field count it cannot satisfy."""
        body = decode_dictionary(encode_dictionary([("a", "b"), ("c", "d")]))

        self.assertEqual(body["declared"], 2)


class Plan(unittest.TestCase):
    def test_it_walks_the_candidates_one_per_connection(self) -> None:
        plan = ReplyPlan()

        names = [plan.next_candidate().name for _ in range(len(GUESSES))]

        self.assertEqual(names, [c.name for c in GUESSES])

    def test_it_wraps_rather_than_running_out(self) -> None:
        """A run longer than the list should keep testing rather than stop, so
        a shape that works intermittently still shows up."""
        plan = ReplyPlan()
        for _ in range(len(GUESSES)):
            plan.next_candidate()

        self.assertEqual(plan.next_candidate().name, GUESSES[0].name)

    def test_an_answer_is_the_readout(self) -> None:
        plan = ReplyPlan()
        candidate = plan.next_candidate()

        plan.record(candidate, reply_bytes=55, closed_by="complete frame")

        summary = plan.summary()
        self.assertEqual(summary["answered"], [candidate.name])
        self.assertIn("command channel", summary["note"])

    def test_a_silent_sweep_of_guesses_claims_nothing(self) -> None:
        """The negative that must not be over-read: guessed candidates that go
        unanswered say nothing about the protocol."""
        plan = ReplyPlan()
        for _ in range(3):
            plan.record(plan.next_candidate(), reply_bytes=0, closed_by="closed")

        summary = plan.summary()
        self.assertEqual(summary["answered"], [])
        self.assertIn("says nothing", summary["note"])
        self.assertIn("--commands", summary["note"])

    def test_commands_from_the_payload_replace_the_guesses(self) -> None:
        plan = ReplyPlan.from_commands(["getinfo", "screenshot", "webcam"])

        self.assertEqual([c.name for c in plan.candidates],
                         ["getinfo", "screenshot", "webcam"])
        self.assertIn("string heap", plan.candidates[0].rationale)

    def test_an_empty_command_list_falls_back_rather_than_sending_nothing(self) -> None:
        plan = ReplyPlan.from_commands([])

        self.assertEqual([c.name for c in plan.candidates], [c.name for c in GUESSES])

    def test_a_candidate_builds_a_frame_the_decoder_accepts(self) -> None:
        candidate = Candidate("x", [("Packet", "x")], "because")

        parsed = parse_frame(candidate.frame())

        self.assertTrue(parsed["ok"], parsed["problems"])


if __name__ == "__main__":
    unittest.main()
