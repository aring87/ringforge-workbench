"""The name checks, exhaustively, because they are a security boundary.

After a detonation the case folder is attacker-influenced input: it was written
by a machine that ran malware, and the host is about to build paths from its
filenames. These tests are the specification for what may cross that line.

**Backslashes are built with `chr(92)` rather than typed as escapes.** Not
style: this file is about Windows path syntax, so nearly every case contains
one, and a literal that loses a backslash in transit turns a test for traversal
into a test that a normal filename is accepted -- passing, and asserting
nothing. Constructing them removes the class.
"""

from __future__ import annotations

import unittest

from runcontrol.untrusted import (
    MAX_COMPONENT,
    check_component,
    check_relative_path,
)

B = chr(92)      # backslash
SEP = B


class NamesThatMustBeRefused(unittest.TestCase):
    def assert_refused(self, name: str, expect: str = "") -> None:
        verdict = check_component(name)
        self.assertFalse(verdict, f"{name!r} was accepted")
        if expect:
            self.assertIn(expect, verdict.reason,
                          f"{name!r} refused for {verdict.reason!r}")

    def test_traversal_is_named_as_traversal(self) -> None:
        # The reason matters, not only the outcome. `..` also trips the
        # trailing-dot rule, and a refusal that blames a trailing dot sends the
        # reader looking at the wrong thing.
        self.assert_refused("..", "traversal")
        self.assert_refused(".", "traversal")

    def test_separators_cannot_hide_inside_a_component(self) -> None:
        self.assert_refused("a" + SEP + "b", "separator")
        self.assert_refused("a/b", "separator")

    def test_a_colon_is_refused(self) -> None:
        # Two different attacks share the character: `C:name` is drive-relative,
        # and `name:stream` writes an alternate data stream that no directory
        # listing shows.
        self.assert_refused("report.json:hidden", "colon")
        self.assert_refused("C:report.json", "colon")

    def test_windows_strips_trailing_dots_and_spaces(self) -> None:
        # `evil.txt ` and `evil.txt` are the same file to the filesystem and
        # different strings to a checker.
        self.assert_refused("evil.txt ", "trailing")
        self.assert_refused("evil.txt.", "trailing")
        self.assert_refused("evil.txt  ", "trailing")

    def test_device_names_are_reserved_with_any_extension(self) -> None:
        for name in ("CON", "PRN", "AUX", "NUL", "COM1", "LPT9",
                     "con", "Con.txt", "NUL.json", "com4.dat"):
            with self.subTest(name=name):
                self.assert_refused(name, "device")

    def test_control_characters_are_refused(self) -> None:
        self.assert_refused("bell" + chr(7) + ".txt", "control")
        self.assert_refused("nul" + chr(0) + "byte", "control")
        self.assert_refused("del" + chr(127), "control")

    def test_an_overlong_name_is_refused(self) -> None:
        self.assert_refused("a" * (MAX_COMPONENT + 1), "longer than")

    def test_unnormalised_unicode_is_refused(self) -> None:
        # NFD: 'e' followed by a combining acute. Folds to the same on-disk name
        # as the NFC form, so a refusal list matched literally is walked around.
        self.assert_refused("cafe" + chr(0x301) + ".txt", "NFKC")

    def test_an_empty_name_is_refused(self) -> None:
        self.assert_refused("", "empty")

    def test_a_leading_hyphen_is_refused_as_argument_injection(self) -> None:
        # The one first-character restriction that is about security rather
        # than tidiness. The engine hands case-folder paths to capa, FLOSS,
        # `file` and YARA as command arguments; a file called `-r` or
        # `--version` arriving in a case folder is argument injection. `@` can
        # mean "response file" to a number of Windows binaries.
        for name in ("-r", "--version", "-rf.json", "@args.txt"):
            with self.subTest(name=name):
                self.assert_refused(name, "allowed set")

    def test_a_name_of_only_punctuation_is_refused(self) -> None:
        # Matches the character set and identifies nothing.
        self.assert_refused(".-_", "alphanumeric")
        self.assert_refused("...", "trailing")


class NamesThatMustBeAccepted(unittest.TestCase):
    def assert_ok(self, name: str) -> None:
        verdict = check_component(name)
        self.assertTrue(verdict, f"{name!r} refused: {verdict.reason}")

    def test_pe_section_dumps_are_accepted(self) -> None:
        # **Found by pointing the checker at a real case rather than by
        # review.** The first allow-list demanded an alphanumeric first
        # character and refused nine files this tool had written itself: the PE
        # section dumps under `extracted/`, whose names start with a dot
        # because PE section names do. A checker that rejects its own tool's
        # output degrades a case and reports it as hostile input.
        for name in (".data", ".rdata", ".reloc", ".pdata", ".text",
                     ".debug0", ".fptable", ".rsrc", "_RDATA", "_TEXT"):
            with self.subTest(name=name):
                self.assert_ok(name)

    def test_the_names_this_tool_actually_writes(self) -> None:
        # If any of these is refused the collector cannot import a real case,
        # which is the failure a security check most easily causes.
        for name in ("summary.json", "combined_verdict.json", "capa.json",
                     "yara_results.json", "floss_results.json", "iocs.csv",
                     "static_analysis", "dynamic_analysis", "api_analysis",
                     "report.html", "runlog.json", "pe_metadata.json",
                     "dynamic_registry_reads.pmc", "export.csv",
                     "procmon.pml", "dump_1234.dmp", "sample.exe.bin"):
            with self.subTest(name=name):
                self.assert_ok(name)

    def test_hyphens_underscores_at_and_plus_are_allowed(self) -> None:
        for name in ("a-b", "a_b", "a@b", "a+b", "a.b.c", "A1"):
            with self.subTest(name=name):
                self.assert_ok(name)

    def test_a_name_at_the_length_limit_is_allowed(self) -> None:
        self.assert_ok("a" * MAX_COMPONENT)


class RelativePathsAsAWhole(unittest.TestCase):
    def test_a_normal_nested_path_is_accepted(self) -> None:
        self.assertTrue(check_relative_path("static_analysis/summary.json"))
        self.assertTrue(check_relative_path("dynamic_analysis" + SEP + "report.html"))

    def test_an_absolute_path_is_refused(self) -> None:
        for path in ("/etc/passwd", SEP + "windows",
                     SEP + "windows" + SEP + "win.ini"):
            with self.subTest(path=path):
                verdict = check_relative_path(path)
                self.assertFalse(verdict)
                self.assertIn("absolute", verdict.reason)

    def test_unc_and_extended_paths_are_refused(self) -> None:
        for path in (B * 2 + "server" + SEP + "share",
                     B * 2 + "?" + SEP + "C:" + SEP + "x",
                     "//server/share"):
            with self.subTest(path=path):
                self.assertFalse(check_relative_path(path), f"{path!r} accepted")

    def test_drive_qualified_paths_are_refused(self) -> None:
        # `C:foo` is the interesting one: drive-*relative*, so it resolves
        # against the current directory on C: and lands nowhere near the
        # destination.
        for path in ("C:foo", "C:" + SEP + "Windows", "z:x"):
            with self.subTest(path=path):
                verdict = check_relative_path(path)
                self.assertFalse(verdict)
                self.assertIn("drive", verdict.reason)

    def test_traversal_anywhere_in_the_path_is_refused(self) -> None:
        for path in ("..", ".." + SEP + "x", "a" + SEP + ".." + SEP + "b",
                     "a/../../b", "good/.." + SEP + ".." + SEP + "win.ini"):
            with self.subTest(path=path):
                verdict = check_relative_path(path)
                self.assertFalse(verdict, f"{path!r} accepted")
                self.assertIn("traversal", verdict.reason)

    def test_an_empty_path_is_refused(self) -> None:
        self.assertFalse(check_relative_path(""))

    def test_a_path_of_only_separators_is_refused(self) -> None:
        self.assertFalse(check_relative_path(SEP + SEP + SEP))

    def test_repeated_separators_do_not_admit_an_empty_component(self) -> None:
        # `a//b` is a normal path with a doubled separator, not an attack. It
        # must not be refused for emptiness.
        self.assertTrue(check_relative_path("a//b"))


class TheVerdictType(unittest.TestCase):
    def test_a_verdict_is_falsey_when_it_refuses(self) -> None:
        # Callers write `if not check_component(name):`, so this is load-bearing
        # rather than cosmetic.
        self.assertFalse(bool(check_component("..")))
        self.assertTrue(bool(check_component("summary.json")))

    def test_an_acceptance_carries_no_reason(self) -> None:
        self.assertEqual("", check_component("summary.json").reason)


if __name__ == "__main__":
    unittest.main()
