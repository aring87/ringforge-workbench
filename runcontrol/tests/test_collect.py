"""Importing a case folder the guest wrote, and refusing what it should not take.

The junction test builds a **real** junction with `_winapi.CreateJunction`,
which needs no privilege, rather than mocking one. A mocked link tests the
mock: the whole question is whether the check recognises what Windows actually
creates, and `is_symlink()` alone does not -- a directory junction is a reparse
point that reports False for it. A junction to `C:\\Windows` walked as an
ordinary directory is a host copy of `C:\\Windows`.

`os.symlink` is not used: it needs a privilege this bench does not have, so a
symlink test would be a test that silently skips where it matters most.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from runcontrol.collect import Limits, collect_case

WINDOWS = sys.platform.startswith("win")

if WINDOWS:
    import _winapi


class CaseFolderFixture(unittest.TestCase):
    """A source tree shaped like a real case, and a destination beside it."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.source = self.tmp / "case"
        self.dest = self.tmp / "imported"
        (self.source / "static_analysis").mkdir(parents=True)
        (self.source / "dynamic_analysis").mkdir()
        self.write("summary.json", '{"verdict":"x"}')
        self.write("static_analysis/capa.json", "{}")
        self.write("dynamic_analysis/report.html", "<html></html>")

    def write(self, relative: str, text: str) -> Path:
        path = self.source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def collect(self, **limit_kwargs):
        limits = Limits(**limit_kwargs) if limit_kwargs else None
        return collect_case(self.source, self.dest, limits)


class AnOrdinaryCaseImportsWhole(CaseFolderFixture):
    def test_every_file_arrives(self) -> None:
        result = self.collect()
        self.assertEqual(3, result.files)
        self.assertEqual([], result.refusals)
        self.assertTrue(result.complete)
        self.assertTrue((self.dest / "summary.json").is_file())
        self.assertTrue((self.dest / "static_analysis" / "capa.json").is_file())
        self.assertTrue((self.dest / "dynamic_analysis" / "report.html").is_file())

    def test_contents_are_byte_identical(self) -> None:
        self.collect()
        self.assertEqual('{"verdict":"x"}',
                         (self.dest / "summary.json").read_text(encoding="utf-8"))

    def test_directories_are_counted(self) -> None:
        self.assertEqual(2, self.collect().directories)

    def test_the_total_is_the_sum_of_the_files(self) -> None:
        expected = sum(p.stat().st_size for p in self.source.rglob("*") if p.is_file())
        self.assertEqual(expected, self.collect().total_bytes)

    def test_a_missing_source_raises_rather_than_returning_empty(self) -> None:
        # An empty result and a missing case folder must not look alike; the
        # second is a controller bug and the first is a quiet run.
        with self.assertRaises(NotADirectoryError):
            collect_case(self.tmp / "nope", self.dest)

    def test_timestamps_are_not_carried_over(self) -> None:
        # `copyfile`, not `copy2`. Metadata written by a machine that ran
        # malware is not evidence, and a timestamp from it in a case folder is
        # actively misleading.
        old = 946684800  # 2000-01-01
        os.utime(self.source / "summary.json", (old, old))
        self.collect()
        self.assertNotEqual(old, int((self.dest / "summary.json").stat().st_mtime))


@unittest.skipUnless(WINDOWS, "junctions are a Windows construct")
class LinksAreRefusedNotFollowed(CaseFolderFixture):
    def setUp(self) -> None:
        super().setUp()
        self.secret = self.tmp / "host-only"
        self.secret.mkdir()
        (self.secret / "passwords.txt").write_text("secret", encoding="utf-8")

    def test_a_junction_out_of_the_case_is_refused(self) -> None:
        _winapi.CreateJunction(str(self.secret), str(self.source / "escape"))

        result = self.collect()

        self.assertTrue(any("junction" in r.reason for r in result.refusals),
                        f"refusals were {result.refusals}")
        self.assertFalse((self.dest / "escape").exists())

    def test_the_target_of_the_junction_does_not_leak(self) -> None:
        _winapi.CreateJunction(str(self.secret), str(self.source / "escape"))

        self.collect()

        self.assertEqual([], list(self.dest.rglob("passwords.txt")),
                         "content from outside the case reached the host copy")

    def test_the_legitimate_files_still_arrive(self) -> None:
        # A refusal must not abort the import. A case is mostly good data with
        # one bad entry far more often than it is an attack.
        _winapi.CreateJunction(str(self.secret), str(self.source / "escape"))

        result = self.collect()

        self.assertEqual(3, result.files)
        self.assertTrue((self.dest / "summary.json").is_file())

    def test_the_refusal_names_the_path_as_the_guest_wrote_it(self) -> None:
        _winapi.CreateJunction(str(self.secret), str(self.source / "escape"))
        refusal = [r for r in self.collect().refusals if "junction" in r.reason][0]
        self.assertEqual("escape", refusal.path)


class NamesTheCheckerRejects(CaseFolderFixture):
    """The collector must consult `untrusted`, not re-implement it.

    Most hostile names cannot be created on Windows at all -- the OS refuses
    `CON` and `..` -- so those belong in `test_untrusted`. What is testable
    here is that a name the checker dislikes and the filesystem allows is
    actually refused.
    """

    def test_a_name_with_a_space_is_refused(self) -> None:
        self.write("dropped file.bin", "x")
        result = self.collect()
        self.assertTrue(any(r.path == "dropped file.bin" for r in result.refusals))
        self.assertFalse((self.dest / "dropped file.bin").exists())

    def test_a_name_with_a_hash_is_refused(self) -> None:
        self.write("weird#name.json", "x")
        self.assertTrue(any("#" in r.path for r in self.collect().refusals))

    def test_a_non_ascii_name_is_refused_and_recorded(self) -> None:
        # The documented consequence of the ASCII allow-list. Recorded rather
        # than silently dropped, which is the whole point.
        self.write("caf\u00e9.json", "x")
        refusals = self.collect().refusals
        self.assertEqual(1, len(refusals))
        self.assertIn("allowed set", refusals[0].reason)

    def test_a_refused_name_does_not_stop_the_rest(self) -> None:
        self.write("bad name.bin", "x")
        self.assertEqual(3, self.collect().files)


class CapsRefuseRatherThanTruncate(CaseFolderFixture):
    def test_a_file_over_the_per_file_cap_is_skipped_whole(self) -> None:
        self.write("huge.bin", "x" * 5000)
        result = self.collect(max_file_bytes=1000)
        self.assertTrue(any("exceeds" in r.reason for r in result.refusals))
        self.assertFalse((self.dest / "huge.bin").exists(),
                         "a partial file that looks complete is the worst outcome")

    def test_the_file_count_cap_stops_and_says_so(self) -> None:
        for i in range(10):
            self.write(f"extra{i}.json", "{}")
        result = self.collect(max_files=5)
        self.assertTrue(result.truncated)
        self.assertEqual(5, result.files)
        self.assertFalse(result.complete)

    def test_the_total_size_cap_stops_and_says_so(self) -> None:
        for i in range(5):
            self.write(f"big{i}.bin", "x" * 1000)
        result = self.collect(max_total_bytes=2500)
        self.assertTrue(result.truncated)
        self.assertLessEqual(result.total_bytes, 2500)

    def test_a_truncated_import_is_never_complete(self) -> None:
        # `complete` is what a caller checks before trusting a verdict read
        # out of the imported case.
        result = self.collect(max_files=1)
        self.assertTrue(result.truncated)
        self.assertFalse(result.complete)

    def test_depth_is_capped(self) -> None:
        deep = self.source
        for level in range(8):
            deep = deep / f"level{level}"
        deep.mkdir(parents=True)
        (deep / "buried.json").write_text("{}", encoding="utf-8")

        result = self.collect(max_depth=3)

        self.assertTrue(any("deeper than" in r.reason for r in result.refusals))
        self.assertEqual([], list(self.dest.rglob("buried.json")))


class TheSummaryIsReadable(CaseFolderFixture):
    def test_it_names_the_counts_and_flags_truncation(self) -> None:
        for i in range(10):
            self.write(f"f{i}.json", "{}")
        summary = self.collect(max_files=4).summary()
        self.assertIn("4 files", summary)
        self.assertIn("TRUNCATED", summary)

    def test_a_clean_import_does_not_say_refused(self) -> None:
        self.assertNotIn("refused", self.collect().summary())


if __name__ == "__main__":
    unittest.main()
