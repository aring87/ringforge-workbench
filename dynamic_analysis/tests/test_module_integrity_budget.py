"""The module integrity pass runs within a budget and names what it skipped.

GuLoader `f306f95f4a9b` (29 Sep): 13 dumps at ~200 s each held this pass past
the host's 7,200 s run limit, and the case came home with nothing. The pass is
now budgeted, takes the latest dump of each process first, and names every
dump it did not reach. No dump is read here: `analyze` and `clock` are
injected, because what is under test is the budgeting, not the comparison.
"""

from __future__ import annotations

import unittest

from dynamic_analysis.module_integrity import (
    BUDGET_SECONDS, assess_dumps, prioritise_dumps)


def rec(path: str, pid=None) -> dict:
    return {"path": path, "pid": pid, "success": True}


class FakeClock:
    """Advances by `step` seconds each time a dump is analysed."""

    def __init__(self, step: float) -> None:
        self.now = 0.0
        self.step = step

    def __call__(self) -> float:
        return self.now

    def analyze(self, path: str) -> dict:
        self.now += self.step
        return {"dump": path, "modules": [], "error": ""}


class PrioritiseTests(unittest.TestCase):

    def test_latest_dump_of_each_process_comes_first(self) -> None:
        records = [rec("a_t3.dmp", 10), rec("a_t25.dmp", 10), rec("b_t3.dmp", 20),
                   rec("a_t55.dmp", 10), rec("b_t25.dmp", 20)]
        order = [r["path"] for r in prioritise_dumps(records)]
        self.assertEqual(order[:2], ["a_t55.dmp", "b_t25.dmp"])
        self.assertEqual(sorted(order), sorted(r["path"] for r in records))

    def test_a_crash_dump_is_its_process_latest(self) -> None:
        """Crash dumps are appended after the scheduled ones, and the crash
        image is often the only one taken after the payload was written."""
        records = [rec("x_t3.dmp", 7), rec("x_t25.dmp", 7), rec("x_crash.dmp", 7)]
        self.assertEqual(prioritise_dumps(records)[0]["path"], "x_crash.dmp")

    def test_a_record_without_a_pid_stands_alone(self) -> None:
        records = [rec("p1.dmp"), rec("p2.dmp"), rec("q.dmp", 5)]
        self.assertEqual({r["path"] for r in prioritise_dumps(records)[:3]},
                         {"p1.dmp", "p2.dmp", "q.dmp"})


class BudgetTests(unittest.TestCase):

    def test_the_measured_default(self) -> None:
        """900 s: above the slowest pass that ever finished (483 s over 177
        runs), well below the one that cost a case."""
        self.assertGreater(BUDGET_SECONDS, 483)
        self.assertLessEqual(BUDGET_SECONDS, 1800)

    def test_a_pass_inside_the_budget_is_untouched(self) -> None:
        clock = FakeClock(step=17)
        records = [rec(f"d{i}.dmp", i) for i in range(5)]
        results, budget = assess_dumps(records, 900, analyze=clock.analyze, clock=clock)
        self.assertEqual(len(results), 5)
        self.assertFalse(budget["budget_exhausted"])
        self.assertEqual(budget["dumps_not_assessed"], [])
        self.assertEqual(budget["dumps_assessed"], 5)

    def test_the_f306_shape_stops_and_names_the_rest(self) -> None:
        """13 dumps at 200 s against a 900 s budget: five assessed (the
        check falls between dumps, so the fifth starts at 800 s), eight
        named as not assessed."""
        clock = FakeClock(step=200)
        records = [rec(f"g{i:02}.dmp", 100 + i % 3) for i in range(13)]
        results, budget = assess_dumps(records, 900, analyze=clock.analyze, clock=clock)
        self.assertEqual(budget["dumps_assessed"], 5)
        self.assertEqual(len(results), 5)
        self.assertTrue(budget["budget_exhausted"])
        self.assertEqual(len(budget["dumps_not_assessed"]), 8)
        assessed = {r["dump"] for r in results}
        self.assertTrue(assessed.isdisjoint(budget["dumps_not_assessed"]))
        self.assertEqual(budget["dumps_total"], 13)
        # All three processes were reached before the budget ran out.
        latest = {r["path"] for r in prioritise_dumps(records)[:3]}
        self.assertTrue(latest <= assessed)

    def test_at_least_one_dump_is_always_assessed(self) -> None:
        clock = FakeClock(step=5000)
        results, budget = assess_dumps([rec("a.dmp", 1), rec("b.dmp", 2)], 0,
                                       analyze=clock.analyze, clock=clock)
        self.assertEqual(len(results), 1)
        self.assertEqual(len(budget["dumps_not_assessed"]), 1)

    def test_progress_is_emitted_before_each_dump(self) -> None:
        """A slow dump must not look like a hung one."""
        clock = FakeClock(step=1)
        seen: list[str] = []

        def analyze(path: str) -> dict:
            self.assertTrue(seen and path in seen[-1], "emitted after the work")
            return clock.analyze(path)

        assess_dumps([rec("a.dmp", 1), rec("b.dmp", 2)], 900,
                     analyze=analyze, clock=clock, emit=seen.append)
        self.assertEqual(len(seen), 2)

    def test_records_without_a_path_are_ignored(self) -> None:
        clock = FakeClock(step=1)
        results, budget = assess_dumps([rec("a.dmp", 1), {"pid": 2}, "junk"], 900,
                                       analyze=clock.analyze, clock=clock)
        self.assertEqual(budget["dumps_total"], 1)
        self.assertEqual(len(results), 1)


if __name__ == "__main__":
    unittest.main()
