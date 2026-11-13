"""capa analysed every sample twice, and the second time only to print text.

`step_capa` ran `capa -j <sample>` for capa.json and then `capa <sample>` for
capa.txt: two full analyses of the same file. On small samples the second was
cheap because the first had warmed capa's rule cache, which hid the cost; on a
large binary analysis dominates and the second pass cost as much as the first.
`elevated_tracing_service` (4.5 MB) spent 1,309 s on the JSON and 1,316 s on
the text, 2,626 of a 2,792 s triage. Over the sweeps the text pass was 4.9 h of
`mal-112b`'s 14.6 h of triage and 6.9 h of `benign-wide`'s 16.2.

capa renders a saved result document when given one as input, and that text is
byte-identical to the second analysis (27 cases from four sweeps, 12 Nov). So
the sample is analysed once and capa.txt is rendered from capa.json.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from static_triage_engine import steps

CAPA = r"C:\tools\capa\capa.exe"
RESULT_DOC = '{"meta": {"version": "9.4.0"}, "rules": {}}'
RENDERED = "+------------------------+\n| md5 | 0123 |\n"


class _Fake:
    """Stands in for `run_cmd`: answers the analysis and the render."""

    def __init__(self, render_rc: int = 0, render_out: str = RENDERED) -> None:
        self.calls: list[tuple[list[str], int]] = []
        self.render_rc = render_rc
        self.render_out = render_out

    def __call__(self, cmd, cwd=None, timeout=900):
        self.calls.append((list(cmd), timeout))
        if "-j" in cmd:
            return {"cmd": cmd, "returncode": 0, "duration_sec": 12.0, "stdout": RESULT_DOC, "stderr": ""}
        return {"cmd": cmd, "returncode": self.render_rc, "duration_sec": 0.5,
                "stdout": self.render_out if self.render_rc == 0 else "", "stderr": "render failed"}


class CapaAnalysesTheSampleOnce(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.case_dir = root / "case"
        self.case_dir.mkdir()
        self.sample = root / "sample.exe"
        self.sample.write_bytes(b"MZ" + b"\0" * 64)
        self.cfg = SimpleNamespace(capa_path=None, capa_rules=root / "rules", capa_sigs=root / "sigs")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run(self, fake: _Fake) -> dict:
        with mock.patch.object(steps, "find_capa", return_value=CAPA), \
             mock.patch.object(steps, "ensure_capa_paths", return_value=None), \
             mock.patch.object(steps, "run_cmd", side_effect=fake):
            return steps.step_capa(self.sample, self.case_dir, self.cfg, capa_timeout=1800)

    def test_the_sample_is_analysed_exactly_once(self) -> None:
        fake = _Fake()
        self._run(fake)
        analyses = [cmd for cmd, _ in fake.calls if str(self.sample) in cmd]
        self.assertEqual(len(analyses), 1, fake.calls)
        self.assertIn("-j", analyses[0])

    def test_the_text_is_rendered_from_the_json(self) -> None:
        fake = _Fake()
        res = self._run(fake)
        self.assertEqual(len(fake.calls), 2)
        render_cmd, render_timeout = fake.calls[1]
        self.assertEqual(render_cmd, [CAPA, str(self.case_dir / "capa.json")])
        self.assertLessEqual(render_timeout, steps.CAPA_RENDER_TIMEOUT_SEC)
        self.assertEqual((self.case_dir / "capa.json").read_text(encoding="utf-8"), RESULT_DOC)
        self.assertEqual((self.case_dir / "capa.txt").read_text(encoding="utf-8"), RENDERED)
        self.assertEqual(res["returncode"], 0)
        self.assertEqual(res["text_pass"]["rendered_from"], "capa.json")

    def test_a_failed_render_costs_the_text_file_and_nothing_else(self) -> None:
        (self.case_dir / "capa.txt").write_text("stale text from an earlier run", encoding="utf-8")
        res = self._run(_Fake(render_rc=1))
        self.assertEqual(res["returncode"], 0)
        self.assertTrue((self.case_dir / "capa.json").exists())
        self.assertFalse((self.case_dir / "capa.txt").exists(),
                         "a stale capa.txt would pass as this run's")
        self.assertEqual(res["text_pass"]["returncode"], 1)


if __name__ == "__main__":
    unittest.main()
