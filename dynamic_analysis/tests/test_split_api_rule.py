"""The split-API loader rule, and the proximity it always meant to require.

**Measured 17 Sep.** The rule fired on nine memory dumps of a *benign*
Microsoft-signed Windows binary, including two of `WerFault.exe`, and carried
a clean sample to Strongly Corroborated / Likely Malicious.

Its condition tested only that the fragments were *present somewhere* in the
scanned bytes. The file's own comment explains why that was believed rare --
"a normal program does not hold `kernel ` and `32.dll` as two separate UTF-16
literals" -- and that is true only because in the loader they are consecutive
literals in the .NET user-string heap. Presence alone does not survive a
50 MB process dump.

Measured, in the real artifacts:

* true positive `stage2 e139c422`, 892 KB: every fragment exactly once, inside
  a 196-byte window, `kernel ` -> `32.dll` gap of **16 bytes**
* benign `WerFault.exe` dump, 51 MB: `handle` 235 hits, `32.dll` 196,
  `protect` 158, `kernel ` 64, spread from offset 10 KB to 51 MB
* across five benign dumps the closest forward `kernel ` -> `32.dll` gap ran
  from **106,080 to 952,742 bytes**, and none had a pair within 32

So the rule now requires the library name to be split across two *adjacent*
literals. These tests use synthetic buffers rather than either real artifact:
the malicious one is live and does not belong in a repository, and the benign
dumps are 50-160 MB.
"""

from __future__ import annotations

import unittest

try:
    import yara
except ImportError:                                  # pragma: no cover
    yara = None

from ringforge.resources import local_yara_rules_dir

RULE = "RingForge_Split_API_Injection_Loader"


def w(text: str) -> bytes:
    """A UTF-16LE literal, which is the only form these fragments take."""
    return text.encode("utf-16-le")


def cluster() -> bytes:
    """The fragments as consecutive user-string literals, as the loader holds them.

    Laid out in the order and spacing measured in `stage2 e139c422`: every
    fragment once, the whole set inside a couple of hundred bytes.
    """
    parts = ["Find ", "Virtual ", "Alloc", "Write ", "Process ", "Memory",
             "Protect", "Open ", "Close ", "Handle", "kernel ", "32.dll"]
    out = bytearray()
    for part in parts:
        out += w(part) + b"\x00\x00"
    return bytes(out)


@unittest.skipIf(yara is None, "yara-python not installed")
class ProximityIsTheSignature(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        path = local_yara_rules_dir() / "ringforge_split_api_loader.yar"
        cls.rules = yara.compile(filepath=str(path))

    def hits(self, data: bytes) -> list[str]:
        return [m.rule for m in self.rules.match(data=data)]

    def test_consecutive_literals_still_match(self) -> None:
        # The true positive's shape. Losing this would be losing the rule.
        data = w("GetDelegateForFunctionPointer") + b"\x00\x00" + cluster()
        self.assertIn(RULE, self.hits(data))

    def test_the_same_fragments_scattered_do_not_match(self) -> None:
        # The false positive's shape: every fragment present, none adjacent.
        # This is what a large process dump looks like, and it used to fire.
        padding = b"\x00" * 200_000
        data = w("GetDelegateForFunctionPointer") + padding
        for part in ["Find ", "Virtual ", "Alloc", "Write ", "Process ",
                     "Memory", "Protect", "Open ", "Close ", "Handle",
                     "kernel ", "32.dll"]:
            data += w(part) + padding
        self.assertNotIn(RULE, self.hits(data))

    def test_a_far_apart_library_pair_does_not_match(self) -> None:
        # `kernel ` and `32.dll` both present, everything else clustered, but
        # the pair split by more than the window. The measured benign minimum
        # was 106,080 bytes; this is well inside that and must still be clean.
        near = ["Find ", "Virtual ", "Alloc", "Write ", "Process ", "Memory",
                "Protect", "Open ", "Close ", "Handle"]
        data = w("GetDelegateForFunctionPointer") + b"\x00\x00"
        for part in near:
            data += w(part) + b"\x00\x00"
        data += w("kernel ") + (b"\x00" * 4096) + w("32.dll")
        self.assertNotIn(RULE, self.hits(data))

    def test_the_library_pair_alone_is_not_enough(self) -> None:
        # Adjacency without the API set is not a reassembly scheme.
        data = w("GetDelegateForFunctionPointer") + b"\x00\x00"
        data += w("kernel ") + b"\x00\x00" + w("32.dll")
        self.assertNotIn(RULE, self.hits(data))

    def test_the_api_set_without_the_library_pair_is_not_enough(self) -> None:
        data = w("GetDelegateForFunctionPointer") + b"\x00\x00"
        for part in ["Virtual ", "Alloc", "Write ", "Process ", "Memory",
                     "Protect", "Open ", "Close ", "Handle"]:
            data += w(part) + b"\x00\x00"
        self.assertNotIn(RULE, self.hits(data))

    def test_ascii_fragments_do_not_match(self) -> None:
        # `wide` is not optional: these are .NET user-string literals, and
        # `Alloc` and `Handle` occur in ascii inside generated identifier
        # names, which is decoy padding rather than evidence.
        parts = ["GetDelegateForFunctionPointer", "Find ", "Virtual ", "Alloc",
                 "Write ", "Process ", "Memory", "Protect", "Open ", "Close ",
                 "Handle", "kernel ", "32.dll"]
        data = b"\x00".join(p.encode("ascii") for p in parts)
        self.assertNotIn(RULE, self.hits(data))


if __name__ == "__main__":
    unittest.main()
