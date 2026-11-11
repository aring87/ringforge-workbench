"""The seam nothing covered: `run_case` calling the scorer it writes summaries from.

**Every full engine run died on every sample for two days and 1,127 tests
passed.** `static_verdict_for_case` built its `benign` list and never assigned
it to the result, so the key did not exist; `engine.run_case` reads
`static["suspicious"], static["benign"]` on the line that writes `summary.json`.
`KeyError: 'benign'`, on `where.exe`, on `ping.exe`, on anything.

It survived because the tests reach `static_verdict_for_case` and `combine_case`
directly -- they test what the scorer *says*, which is the interesting part and
which is precisely why the boring seam above them was the part left uncovered.
The corpus run found it in the first sixty seconds by being the first thing to
call the real entry point.

These are contract tests over the shape that seam depends on, not a second
engine run: `run_case` on one binary costs 30-85 seconds, which does not belong
in a suite that finishes in thirty. `scripts/static_corpus.py` is where the real
thing runs.
"""

import builtins
import dis
import importlib
import inspect
import sys
import types
import unittest
from pathlib import Path

from static_triage_engine import engine
from static_triage_engine.combine_case import static_verdict_for_case


class TheSummaryWriterGetsWhatItReads(unittest.TestCase):
    """`run_case` unpacks specific keys. They have to be there."""

    #: Read off the line in `engine.run_case` that broke:
    #:     suspicious, benign = static["suspicious"], static["benign"]
    #: plus the ones the lines around it use to fill `summary.json`.
    REQUIRED = ("score", "verdict", "confidence", "severity",
                "suspicious", "benign")

    def test_every_key_run_case_unpacks_is_present(self) -> None:
        result = static_verdict_for_case(
            ".", {"sample": {"filename": "probe.exe"}}, None, None, None)

        for key in self.REQUIRED:
            with self.subTest(key=key):
                self.assertIn(key, result)

    def test_the_two_reason_lists_are_lists(self) -> None:
        # `report.py` renders both as bullet lists and indexes them.
        result = static_verdict_for_case(
            ".", {"sample": {"filename": "probe.exe"}}, None, None, None)

        self.assertIsInstance(result["suspicious"], list)
        self.assertIsInstance(result["benign"], list)

    def test_a_case_with_nothing_collected_still_answers(self) -> None:
        # The degenerate input, which is what a sample the collectors all
        # failed on looks like. It must produce a result rather than a
        # traceback -- the engine writes a summary either way.
        result = static_verdict_for_case(".", None, None, None, None)

        for key in self.REQUIRED:
            with self.subTest(key=key):
                self.assertIn(key, result)

    def test_benign_says_when_coverage_is_incomplete(self) -> None:
        # The list is not decoration. With no collectors run, every category is
        # uncollected, and a reader must not see that as a clean bill.
        result = static_verdict_for_case(
            ".", {"sample": {"filename": "probe.exe"}}, None, None, None)

        self.assertTrue(any("Coverage incomplete" in line
                            for line in result["benign"]))


class TheUnpackingLineStillLooksLikeThis(unittest.TestCase):
    """A guard on the assumption the tests above are built on.

    If `run_case` stops reading these keys the tests above are testing nothing,
    and the failure would be silent. Reading the source is crude and it is the
    only thing that catches that without a 60-second engine run.
    """

    def test_run_case_reads_suspicious_and_benign_off_the_static_verdict(self) -> None:
        source = inspect.getsource(engine.run_case)

        self.assertIn('static["suspicious"]', source)
        self.assertIn('static["benign"]', source)
        self.assertIn("static_verdict_for_case", source)



def _undefined_globals(module_name: str) -> list[tuple[str, str]]:
    """(function, name) for every global a module's code reads and nothing defines.

    A name that is read but never assigned in a function compiles to a global
    load, so the compiler accepts it and only the line that runs it fails.
    """
    if module_name.startswith("scripts."):
        # The scripts import their siblings by bare name, as they do when run.
        scripts = str(Path(__file__).resolve().parents[2] / "scripts")
        if scripts not in sys.path:
            sys.path.insert(0, scripts)
    module = importlib.import_module(module_name)
    source = Path(module.__file__).read_text(encoding="utf-8")

    def walk(code: types.CodeType):
        yield code
        for const in code.co_consts:
            if isinstance(const, types.CodeType):
                yield from walk(const)

    missing = set()
    for code in walk(compile(source, module.__file__, "exec")):
        for ins in dis.get_instructions(code):
            if (ins.opname == "LOAD_GLOBAL" and ins.argval not in vars(module)
                    and not hasattr(builtins, ins.argval)):
                missing.add((code.co_name, ins.argval))
    return sorted(missing)


class NoNameIsReadThatNothingDefines(unittest.TestCase):
    """**10 Nov: static triage had crashed on every sample with an embedded
    file since 24 Aug.** 6684981 removed the assignments to `sf_score`,
    `sf_verdict` and `sf_conf` and left three reads, in the subfile branch
    that no test reaches. 31 swept cases lost their static summary to it. The
    same scan found `ENV_TOGGLES` read bare inside an emulator method.

    Cheap where an engine run is not: it reads the bytecode, runs nothing.
    """

    MODULES = (
        "static_triage_engine.engine",
        "static_triage_engine.combine_case",
        "dynamic_analysis.orchestrator",
        "ringforge.cli",
        "runcontrol.loop",
        "runcontrol.sweep",
        "scripts.emulate_native_stub",
    )

    def test_every_global_read_is_defined(self) -> None:
        for name in self.MODULES:
            with self.subTest(module=name):
                self.assertEqual([], _undefined_globals(name))


if __name__ == "__main__":
    unittest.main()
