"""The frame read out of `stuff.dll`, and a parser that must not discard evidence.

The layout comes from `Stuff.PacketFrame.Encode`/`.Decode` disassembled on
01 Sep. **It has never been seen on the wire**: the sample attempted 212
connections to `127.0.0.1:7372` in an hour and every one died at the SYN,
because nothing was listening. So the model is IL-derived and unconfirmed, and
the first frame that ever arrives is the evidence that tests it.

That is why `parse_frame` reports rather than raises. The sample's own `Decode`
throws on a bad magic or CRC; a parser here that did the same would throw away
the first real observation of the protocol because it disagreed with a guess.
"""

import unittest
import zlib

from dynamic_analysis.beacon_frame import (
    HEADER,
    LENGTH,
    MAGIC,
    MIN_SIZE_TO_COMPRESS,
    TRAILER,
    build_frame,
    crc32,
    decode_dictionary,
    frame_length,
    parse_frame,
)


class Building(unittest.TestCase):
    def test_an_empty_frame_is_the_header_and_a_crc(self) -> None:
        frame = build_frame(b"")

        magic, payload_length, original_size, flag = HEADER.unpack(frame[:HEADER.size])
        self.assertEqual(magic, MAGIC)
        self.assertEqual(payload_length, 0)
        self.assertEqual(original_size, 0)
        self.assertEqual(flag, 0)
        self.assertEqual(len(frame), HEADER.size + TRAILER.size)

    def test_small_payloads_ship_raw(self) -> None:
        """`Stuff.PacketCompressor.Compress` returns the input untouched and
        flags 0 below 256 bytes."""
        payload = b"A" * (MIN_SIZE_TO_COMPRESS - 1)

        frame = build_frame(payload)
        parsed = parse_frame(frame)

        self.assertFalse(parsed["compressed"])
        self.assertEqual(parsed["payload"], payload)

    def test_large_payloads_deflate(self) -> None:
        payload = b"A" * (MIN_SIZE_TO_COMPRESS + 1)

        frame = build_frame(payload)
        parsed = parse_frame(frame)

        self.assertTrue(parsed["compressed"])
        self.assertEqual(parsed["original_size"], len(payload))
        self.assertEqual(parsed["decompressed"], payload)
        self.assertLess(parsed["payload_length"], len(payload))

    def test_deflate_is_raw_not_zlib_wrapped(self) -> None:
        """`DeflateStream` is raw Deflate. A zlib header would fail on the far
        side in a way that reads as a protocol mismatch rather than a framing
        one, which is an hour nobody needs to lose."""
        frame = build_frame(b"B" * 400)
        parsed = parse_frame(frame)

        self.assertEqual(zlib.decompress(parsed["payload"], -zlib.MAX_WBITS), b"B" * 400)

    def test_compression_can_be_forced_against_the_size_rule(self) -> None:
        frame = build_frame(b"tiny", compress=True)

        parsed = parse_frame(frame)

        self.assertTrue(parsed["compressed"])
        self.assertEqual(parsed["decompressed"], b"tiny")


class Parsing(unittest.TestCase):
    def test_a_good_frame_round_trips(self) -> None:
        parsed = parse_frame(build_frame(b"hello"))

        self.assertTrue(parsed["ok"])
        self.assertEqual(parsed["problems"], [])
        self.assertEqual(parsed["payload"], b"hello")

    def test_a_bad_magic_is_reported_not_raised(self) -> None:
        """The sample throws `Invalid magic` here. If the first frame this
        project ever receives has an unexpected magic, that is the finding --
        raising would discard it."""
        frame = bytearray(build_frame(b"hello"))
        frame[0:4] = (0x11223344).to_bytes(4, "little")

        parsed = parse_frame(bytes(frame))

        self.assertFalse(parsed["ok"])
        self.assertEqual(parsed["magic"], 0x11223344)
        self.assertEqual(parsed["payload"], b"hello")
        self.assertTrue(any("Invalid magic" in p for p in parsed["problems"]))

    def test_a_crc_mismatch_keeps_the_payload_and_names_the_suspect(self) -> None:
        """The polynomial is an assumption: stuff.dll builds its own table and
        its constants were never read. A mismatch should point at that rather
        than at the sample."""
        frame = bytearray(build_frame(b"hello"))
        frame[-1] ^= 0xFF

        parsed = parse_frame(bytes(frame))

        self.assertFalse(parsed["ok"])
        self.assertEqual(parsed["payload"], b"hello")
        self.assertEqual(parsed["crc_computed"], crc32(b"hello"))
        self.assertTrue(any("polynomial" in p for p in parsed["problems"]))

    def test_a_truncated_payload_says_how_short(self) -> None:
        frame = build_frame(b"hello")[:-4]

        parsed = parse_frame(frame)

        self.assertFalse(parsed["ok"])
        self.assertTrue(any("no CRC trailer" in p for p in parsed["problems"]))

    def test_a_runt_is_not_a_frame(self) -> None:
        parsed = parse_frame(b"\xef\xbe")

        self.assertFalse(parsed["ok"])
        self.assertTrue(any("short" in p for p in parsed["problems"]))

    def test_trailing_bytes_are_counted_not_dropped(self) -> None:
        """Two frames in one read is a real possibility at a 17-second interval
        with retries, and silently ignoring the second would lose it."""
        parsed = parse_frame(build_frame(b"one") + build_frame(b"two"))

        self.assertEqual(parsed["payload"], b"one")
        self.assertGreater(parsed["trailing_bytes"], 0)

    def test_a_lying_original_size_is_caught(self) -> None:
        frame = bytearray(build_frame(b"hello"))
        frame[8:12] = (999).to_bytes(4, "little", signed=True)

        parsed = parse_frame(bytes(frame))

        self.assertFalse(parsed["ok"])
        self.assertTrue(any("originalSize" in p for p in parsed["problems"]))


class Dictionary(unittest.TestCase):
    """`Stuff.PacketSerializer` over the string dictionary.

    The shape is confirmed rather than guessed: the first check-in this sample
    ever delivered, 02 Sep, declared 14 pairs, decoded 14, and consumed 388 of
    388 bytes with nothing left over.
    """

    #: The real message, rebuilt field for field.
    LISTINFO = [
        ("Packet", "listinfo"),
        ("IP", "192.168.56.20"),
        ("Group", "Started"),
        ("Country", "Unknown"),
        ("UID", "Raton_Fcm7JziU"),
        ("Username", "adam"),
        ("Machine", "WIN11"),
        ("Os", "Windows 11 Pro 64bit"),
        ("Executing", "Administrator"),
        ("AV", "Windows Defender"),
        ("Pass", ""),
        ("Version", "Free"),
        ("Clock", "21:15:51 01/09/2026"),
        ("Payload", "ce0d08be.exe"),
    ]

    @staticmethod
    def _encode(pairs):
        out = LENGTH.pack(len(pairs))
        for key, value in pairs:
            for text in (key, value):
                raw = text.encode("utf-8")
                out += LENGTH.pack(len(raw)) + raw
        return out

    def test_the_real_check_in_round_trips(self) -> None:
        decoded = decode_dictionary(self._encode(self.LISTINFO))

        self.assertTrue(decoded["ok"], decoded["problems"])
        self.assertEqual(decoded["declared"], 14)
        self.assertEqual(decoded["pairs"], self.LISTINFO)
        self.assertEqual(decoded["trailing_bytes"], 0)

    def test_an_empty_value_is_a_value(self) -> None:
        """`Pass` is empty in the real message. A decoder that treated a
        zero-length string as an end marker would stop nine fields early and
        report a shorter, entirely plausible check-in."""
        decoded = decode_dictionary(self._encode([("Pass", ""), ("Version", "Free")]))

        self.assertTrue(decoded["ok"])
        self.assertEqual(decoded["pairs"], [("Pass", ""), ("Version", "Free")])

    def test_a_miscount_is_reported_with_both_numbers(self) -> None:
        body = bytearray(self._encode([("a", "b")]))
        body[0:4] = LENGTH.pack(9)

        decoded = decode_dictionary(bytes(body))

        self.assertFalse(decoded["ok"])
        self.assertTrue(any("declared 9" in p for p in decoded["problems"]))
        self.assertEqual(decoded["pairs"], [("a", "b")])

    def test_a_length_running_past_the_end_does_not_raise(self) -> None:
        body = self._encode([("key", "value")])[:-3]

        decoded = decode_dictionary(body)

        self.assertFalse(decoded["ok"])
        self.assertTrue(any("runs past the end" in p for p in decoded["problems"]))

    def test_repeated_keys_are_kept(self) -> None:
        """A dict would drop one silently, and a protocol that repeats a key is
        saying something worth seeing."""
        decoded = decode_dictionary(self._encode([("k", "1"), ("k", "2")]))

        self.assertEqual(decoded["pairs"], [("k", "1"), ("k", "2")])

    def test_a_runt_body_is_not_a_dictionary(self) -> None:
        decoded = decode_dictionary(b"\x01\x02")

        self.assertFalse(decoded["ok"])
        self.assertTrue(any("count field" in p for p in decoded["problems"]))


class FrameLength(unittest.TestCase):
    def test_it_reads_the_total_from_a_header(self) -> None:
        frame = build_frame(b"hello")

        self.assertEqual(frame_length(frame[:HEADER.size]), len(frame))

    def test_a_short_header_is_zero(self) -> None:
        self.assertEqual(frame_length(b"\xef\xbe"), 0)

    def test_a_negative_length_is_refused(self) -> None:
        """The reader uses this to decide how much more to wait for. A negative
        length from a hostile or malformed header must not become a huge read."""
        header = HEADER.pack(MAGIC, -1, 0, 0)

        self.assertEqual(frame_length(header), 0)


if __name__ == "__main__":
    unittest.main()
