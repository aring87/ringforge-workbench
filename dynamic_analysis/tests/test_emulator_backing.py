"""`Emulator.backing` must answer opens the way the machine would.

It used to take the last path component and look it up in `SysWOW64` then
`System32`, which silently repaired every malformed path the payload built.
Stage 4's host walk asks for `\\??\\C:C:\\Windows\\System32\\compact.exe` -- a
name that reaches nothing on any machine, measured against the real API by
`real_createprocess_paths.py` -- and the leaf lookup answered all twelve with
real bytes.

What that invented: stage 4 vets each candidate by reading it and declines an
empty one, so the harness's answers produced **eleven creates a real machine
would never grant**, and the single skip (`write.exe`) was not the sample being
selective but this bench having no WordPad. Fixing it took the walk to twelve
opens and **zero** creates, which was the prediction recorded before the change.

These pin the two halves that matter: a well-formed path still gets its bytes,
because stage 3's `ntdll` read is load-bearing for the whole chain, and a
malformed one gets nothing and is counted.
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import win32_emu_env as winenv  # noqa: E402
from emulate_native_stub import Emulator  # noqa: E402


class Backing(unittest.TestCase):
    """Called on an instance that was never constructed, as `restore` does."""

    def setUp(self) -> None:
        self.emu = Emulator.__new__(Emulator)
        self.emu.refused_opens = []

    def test_a_well_formed_path_gets_its_bytes(self) -> None:
        """Stage 3 reads a pristine ntdll off disk to recover clean syscall
        stubs. Answering that with end-of-file makes the run a study of the
        harness."""
        data = Emulator.backing(self.emu, r"\??\C:\Windows\System32\ntdll.dll")

        self.assertTrue(data.startswith(b"MZ"), "ntdll should still resolve")
        self.assertEqual(self.emu.refused_opens, [])

    def test_the_doubled_path_stage_4_builds_gets_nothing(self) -> None:
        """The whole point. A real machine reaches no file with this."""
        asked = r"\??\C:C:\Windows\System32\compact.exe"

        self.assertEqual(Emulator.backing(self.emu, asked), b"")
        self.assertEqual(self.emu.refused_opens, [asked])

    def test_a_bare_leaf_gets_nothing(self) -> None:
        """The old behaviour, now refused: `compact.exe` names no file."""
        self.assertEqual(Emulator.backing(self.emu, "compact.exe"), b"")
        self.assertEqual(self.emu.refused_opens, ["compact.exe"])

    def test_a_refusal_is_recorded_rather_than_silent(self) -> None:
        """A `b""` nobody counts is how the malformed walk read as a real one."""
        for path in (r"\??\C:C:\a.exe", r"\??\C:C:\b.exe", ""):
            Emulator.backing(self.emu, path)

        self.assertEqual(len(self.emu.refused_opens), 3)

    def test_it_agrees_with_the_resolver_the_creation_side_uses(self) -> None:
        """Both halves of an open-then-create must agree about what exists."""
        for path in (r"\??\C:C:\Windows\System32\compact.exe",
                     "compact.exe",
                     r"\??\C:\Windows\System32\ntdll.dll"):
            resolved = winenv.resolve_dos_path(path)
            served = Emulator.backing(self.emu, path)
            self.assertEqual(bool(served), resolved is not None, path)

    def test_an_unreadable_file_is_refused_not_raised(self) -> None:
        """Payload-controlled text reaches this; it has to answer, not throw."""
        with patch.object(Path, "read_bytes", side_effect=OSError("denied")):
            data = Emulator.backing(self.emu, r"\??\C:\Windows\System32\ntdll.dll")

        self.assertEqual(data, b"")
        self.assertEqual(len(self.emu.refused_opens), 1)


if __name__ == "__main__":
    unittest.main()
