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
    DESTRUCTIVE,
    GUESSES,
    Candidate,
    CommandSpec,
    ReplyPlan,
    build_reply,
    encode_dictionary,
    parse_command_lines,
    partition,
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


class Destructive(unittest.TestCase):
    """The client acts on what it is sent, so a sweep is not a probe.

    Measured 02 Sep: it answered `Ping` on the first candidate. The recovered
    vocabulary contains `Jigsaw` beside `Encrypt` and `Decrypt`, and the guest
    disk holds the run's own outputs -- a sweep that reaches those takes the
    evidence with it. The guest is disposable; the run in progress is not.
    """

    def test_the_dangerous_names_are_withheld_by_default(self) -> None:
        plan = ReplyPlan.from_commands(["Ping", "Jigsaw", "Geo", "BSOD"])

        self.assertEqual([c.name for c in plan.candidates], ["Ping", "Geo"])
        self.assertEqual(plan.withheld, ["Jigsaw", "BSOD"])

    def test_they_are_sent_when_asked_for(self) -> None:
        plan = ReplyPlan.from_commands(
            ["Ping", "Jigsaw"], include_destructive=True
        )

        self.assertEqual([c.name for c in plan.candidates], ["Ping", "Jigsaw"])
        self.assertEqual(plan.withheld, [])

    def test_the_summary_says_what_was_not_tried(self) -> None:
        """A sweep that quietly shortened itself would read as a vocabulary
        that failed, rather than one that was never sent."""
        plan = ReplyPlan.from_commands(["Ping", "Melt"])
        plan.record(plan.next_candidate(), reply_bytes=70, closed_by="complete frame")

        summary = plan.summary()
        self.assertEqual(summary["withheld_as_destructive"], ["Melt"])
        self.assertEqual(summary["candidates_total"], 1)

    def test_partition_keeps_order(self) -> None:
        safe, held = partition(["Geo", "BSOD", "Ping", "Encrypt"])

        self.assertEqual(safe, ["Geo", "Ping"])
        self.assertEqual(held, ["BSOD", "Encrypt"])

    def test_ransom_and_wipe_names_are_all_covered(self) -> None:
        for name in ("Jigsaw", "Encrypt", "Decrypt", "Melt", "BSOD", "DDOS",
                     "Shutdown", "Kill", "ChangePassword"):
            self.assertIn(name, DESTRUCTIVE, name)

    def test_report_is_withheld_and_notify_is_not(self) -> None:
        """The crash was first blamed on `Notify`, the command in flight when
        the process died. The decompiled dispatcher names the real one:
        `Report` reads `Name`, gets null from a bare packet, and hands it to
        ProcessMonitor.Start. `Notify` reads title and content and builds a
        balloon tip."""
        self.assertIn("Report", DESTRUCTIVE)
        self.assertNotIn("Notify", DESTRUCTIVE)


class SessionSweep(unittest.TestCase):
    """One connection, many commands.

    The per-connection design was built on the client re-dialling every 17 s.
    Measured 02 Sep: once it gets a valid reply it stops reconnecting -- nine
    minutes of silence after answering `Ping` -- so a sweep that closes after
    each command gets one candidate per *run*, and the recovered vocabulary
    would need 165 restarts.
    """

    def test_a_plan_finishes(self) -> None:
        plan = ReplyPlan.from_commands(["Ping", "Geo", "PortSpy"])

        self.assertFalse(plan.exhausted())
        for _ in range(3):
            plan.next_candidate()

        self.assertTrue(plan.exhausted())

    def test_an_empty_plan_is_exhausted_but_not_empty(self) -> None:
        """`from_commands([])` falls back to the guesses rather than sending
        nothing, so exhaustion still means "the list was walked"."""
        plan = ReplyPlan.from_commands([])

        self.assertFalse(plan.exhausted())
        self.assertTrue(plan.candidates)


class Fields(unittest.TestCase):
    """A command may carry the fields its handler reads.

    The cost of getting this wrong is measured rather than hypothetical: a
    field the client reads and cannot find comes back null, and on 02 Sep a
    null `Name` ended the session and took the rest of the sweep with it.
    """

    def test_a_bare_name_still_means_a_bare_packet(self) -> None:
        """Every commands file written before fields existed must still work."""
        specs = parse_command_lines(["Ping", "Clientinfo"])

        self.assertEqual([s.name for s in specs], ["Ping", "Clientinfo"])
        self.assertIsInstance(specs[0], CommandSpec)
        self.assertEqual(specs[0].fields, ())
        self.assertEqual(specs[0].pairs(), [("Packet", "Ping")])

    def test_fields_ride_after_the_packet_name(self) -> None:
        spec = parse_command_lines(["ProcessSpy\tCommand=List"])[0]

        self.assertEqual(
            spec.pairs(), [("Packet", "ProcessSpy"), ("Command", "List")]
        )

    def test_a_value_may_contain_spaces_and_an_equals_sign(self) -> None:
        """Tab-separated for exactly this reason: Notepad takes a Content."""
        spec = parse_command_lines(["Notepad\tContent=a b = c"])[0]

        self.assertEqual(spec.fields, (("Content", "a b = c"),))

    def test_a_token_without_an_equals_sign_is_refused(self) -> None:
        """Guessing which half was meant is how a null reaches a handler."""
        with self.assertRaises(ValueError):
            parse_command_lines(["Shell\tver"])

    def test_a_trailing_note_is_kept_not_dropped(self) -> None:
        spec = parse_command_lines(["Hosts\tContent=123ratonpro\t# the magic"])[0]

        self.assertEqual(spec.fields, (("Content", "123ratonpro"),))
        self.assertEqual(spec.note, "the magic")

    def test_comments_and_blank_lines_are_skipped(self) -> None:
        specs = parse_command_lines(["# header", "", "   ", "Ping"])

        self.assertEqual([s.name for s in specs], ["Ping"])

    def test_the_frame_carries_the_fields(self) -> None:
        """End to end, because the point is what lands on the wire."""
        spec = parse_command_lines(["RegistryRequest\tAction=GetRoots"])[0]
        plan = ReplyPlan.from_specs([spec])

        frame = parse_frame(plan.next_candidate().frame())
        body = decode_dictionary(frame["decompressed"])

        self.assertTrue(body["ok"])
        self.assertEqual(
            body["pairs"],
            [("Packet", "RegistryRequest"), ("Action", "GetRoots")],
        )


class ReleasingOneHeldCommand(unittest.TestCase):
    """`--allow` exists so measuring `Report` does not mean releasing 33."""

    def _specs(self):
        return parse_command_lines(["Ping", "Report\tName=explorer"])

    def test_a_held_command_is_still_held_when_it_carries_fields(self) -> None:
        plan = ReplyPlan.from_specs(self._specs())

        self.assertEqual(plan.withheld, ["Report"])
        self.assertEqual([c.name for c in plan.candidates], ["Ping"])

    def test_allow_releases_only_what_it_names(self) -> None:
        plan = ReplyPlan.from_specs(self._specs(), allow=["Report"])

        self.assertEqual(plan.withheld, [])
        self.assertEqual(plan.released, ["Report"])
        self.assertEqual([c.name for c in plan.candidates], ["Ping", "Report"])

    def test_the_run_says_what_it_released(self) -> None:
        """A run that deliberately sent a held command must record it."""
        plan = ReplyPlan.from_specs(self._specs(), allow=["Report"])

        self.assertEqual(plan.summary()["released_deliberately"], ["Report"])

    def test_allowing_a_name_not_in_the_sweep_is_refused(self) -> None:
        """Otherwise a typo silently releases nothing and reads as success."""
        with self.assertRaises(ValueError):
            ReplyPlan.from_specs(self._specs(), allow=["Repot"])

    def test_allowing_a_name_that_was_never_held_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            ReplyPlan.from_specs(self._specs(), allow=["Ping"])

    def test_share_is_held(self) -> None:
        """It clones the running client to another address."""
        plan = ReplyPlan.from_specs(parse_command_lines(["Share\tHost=x\tPort=1"]))

        self.assertEqual(plan.withheld, ["Share"])


class TypedValues(unittest.TestCase):
    """An Integer field is four raw bytes, and this is what that cost.

    `Stuff.Unpack.GetAsInteger` is `BitConverter.ToInt32` over the value's
    bytes. Sending `Volume=50` as the two characters "50" threw
    `System.ArgumentException` out of `BitConverter.ToInt32` and ended the
    02 Sep session at the sweep's first integer field, with eleven commands --
    `Report` among them -- still unsent.
    """

    def test_an_integer_is_four_little_endian_bytes(self) -> None:
        spec = parse_command_lines(["Volume\tVolume=int:50"])[0]

        self.assertEqual(spec.fields, (("Volume", b"\x32\x00\x00\x00"),))

    def test_a_negative_integer_round_trips(self) -> None:
        spec = parse_command_lines(["X\tN=int:-1"])[0]

        self.assertEqual(spec.fields[0][1], b"\xff\xff\xff\xff")

    def test_base64_becomes_raw_bytes(self) -> None:
        spec = parse_command_lines(["PlayAudio\tAudio=b64:cmluZ2Zvcmdl"])[0]

        self.assertEqual(spec.fields, (("Audio", b"ringforge"),))

    def test_str_escapes_a_value_that_looks_like_a_tag(self) -> None:
        spec = parse_command_lines(["X\tT=str:int:literal"])[0]

        self.assertEqual(spec.fields, (("T", "int:literal"),))

    def test_an_untagged_value_is_still_text(self) -> None:
        """Every commands file written before tags existed still parses."""
        spec = parse_command_lines(["Shell\tCommand=ver"])[0]

        self.assertEqual(spec.fields, (("Command", "ver"),))

    def test_bytes_survive_the_frame(self) -> None:
        """End to end: the four bytes have to arrive as four bytes."""
        spec = parse_command_lines(["Volume\tVolume=int:50"])[0]
        plan = ReplyPlan.from_specs([spec])

        frame = parse_frame(plan.next_candidate().frame())
        body = decode_dictionary(frame["decompressed"])

        self.assertTrue(body["ok"])
        self.assertEqual(dict(body["pairs"])["Volume"], "2\x00\x00\x00")

    def test_encode_dictionary_takes_bytes_beside_text(self) -> None:
        body = encode_dictionary([("Packet", "Volume"), ("Volume", b"\x01\x00\x00\x00")])
        decoded = decode_dictionary(body)

        self.assertTrue(decoded["ok"])
        self.assertEqual(len(dict(decoded["pairs"])["Volume"]), 4)


if __name__ == "__main__":
    unittest.main()
