"""Whether a dump was frozen has to survive into the report.

A process is suspended while it is dumped so the image is a snapshot rather
than a smear, but the freeze can fail -- access denied on a protected process,
or the process exits between being noticed and being frozen. The dump still
happens, and it is still worth having.

What it is not is equally trustworthy. ProcDump reads a running process over
hundreds of megabytes while it keeps writing, so the image may be internally
inconsistent and a YARA miss against it means less. That distinction was
recorded in memory_dumps.json and then rendered as a bare "False" in a wide
table, which states the mechanism and hides the consequence.
"""

import unittest

from dynamic_analysis.html_report import _memory_dump_rows, _memory_sections


def _dump(pid: int, suspended: bool | None = None) -> dict:
    dump = {
        "pid": pid,
        "name": f"p{pid}.exe",
        "offset_seconds": 25,
        "trigger": "process-spawn",
        "path": "C:\\cases\\long\\case\\dir\\memory\\p_25.dmp",
        "size_mb": 12,
    }
    if suspended is not None:
        dump["suspended"] = suspended
    return dump


class CaptureColumnTests(unittest.TestCase):
    def test_a_frozen_dump_says_so_in_words(self) -> None:
        rows = _memory_dump_rows({"dumps": [_dump(7024, suspended=True)]})

        self.assertEqual(rows[0]["capture"], "Frozen")
        # The raw boolean is replaced, not shown alongside.
        self.assertNotIn("suspended", rows[0])

    def test_an_unfrozen_dump_is_marked_smeared(self) -> None:
        rows = _memory_dump_rows({"dumps": [_dump(7024, suspended=False)]})

        self.assertEqual(rows[0]["capture"], "Live (smeared)")

    def test_an_older_result_gets_no_capture_column(self) -> None:
        # memory_dumps.json written before dumps were suspended has no such
        # field. Defaulting it would assert something about that run that was
        # never recorded.
        rows = _memory_dump_rows({"dumps": [_dump(7024)]})

        self.assertNotIn("capture", rows[0])
        self.assertNotIn("suspended", rows[0])

    def test_capture_sits_next_to_the_trigger(self) -> None:
        # Both columns say how the image was captured. Separated by size and
        # hash, the qualifier reads as an afterthought.
        columns = list(_memory_dump_rows({"dumps": [_dump(7024, suspended=True)]})[0])

        self.assertEqual(columns[columns.index("trigger") + 1], "capture")

    def test_capture_still_appears_without_a_trigger_to_anchor_it(self) -> None:
        dump = _dump(7024, suspended=False)
        dump.pop("trigger")

        self.assertEqual(_memory_dump_rows({"dumps": [dump]})[0]["capture"], "Live (smeared)")

    def test_the_path_is_still_reduced_to_a_filename(self) -> None:
        rows = _memory_dump_rows({"dumps": [_dump(7024, suspended=True)]})

        self.assertEqual(rows[0]["file"], "p_25.dmp")
        self.assertNotIn("path", rows[0])


class SmearedSectionTests(unittest.TestCase):
    def _summary(self, dumps: list[dict]) -> dict:
        return {
            "memory_dump_enabled": True,
            "memory_dump_offsets": [25],
            "memory_summary": {
                "collected": True,
                "counts": {
                    "processes_observed": len(dumps),
                    "dumps_attempted": len(dumps),
                    "dumps_succeeded": len(dumps),
                    "dumps_skipped": 0,
                    "total_mb": 12 * len(dumps),
                },
                "dumps": dumps,
            },
        }

    def test_the_caveat_appears_only_when_something_was_smeared(self) -> None:
        html = _memory_sections(self._summary([_dump(7024, suspended=False)]))

        self.assertIn("Images Captured While Running", html)
        self.assertIn("weaker evidence", html)

    def test_an_all_frozen_run_says_nothing(self) -> None:
        # Silence is the correct output here: a caveat that always renders
        # stops being read.
        html = _memory_sections(self._summary([_dump(7024, suspended=True)]))

        self.assertNotIn("Images Captured While Running", html)

    def test_an_older_result_says_nothing(self) -> None:
        html = _memory_sections(self._summary([_dump(7024)]))

        self.assertNotIn("Images Captured While Running", html)

    def test_the_caveat_counts_against_the_dumps_that_succeeded(self) -> None:
        summary = self._summary(
            [_dump(7024, suspended=False), _dump(9416, suspended=True)]
        )
        html = _memory_sections(summary)

        self.assertIn("1 of 2 dump(s)", " ".join(html.split()))


if __name__ == "__main__":
    unittest.main()
