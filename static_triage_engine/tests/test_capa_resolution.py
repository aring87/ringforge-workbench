"""capa was the only tool the engine looked for exclusively on `PATH`.

`find_procdump`, `find_floss`, `find_sysmon`, `find_dumpcap` and
`_default_autorunsc_path` all check `<app_root>/tools` before falling back.
`step_capa` did not: it invoked the bare string `"capa"`. So a capa shipped in
the bundle was invisible to the one step that needed it -- 35 MB in the zip,
never once invoked.

The second half is the rules. `ensure_capa_paths` raises when no external rule
directory exists, and `step_capa` treated that as "capa did not run". But the
standalone capa build **embeds its rule set** and runs perfectly well without
`-r`/`-s`; only a `pip install capa` needs them pointed at. So capability
detection was silently off for everyone who had not separately installed
`capa-rules`, and the reason given named capa rather than the rules.

Absent rules are now recorded rather than fatal, because "capa's own rules" and
"the rules I curated" are different provenance for the same field.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from static_triage_engine.steps import find_capa


class FindCapaPrefersWhatShipped(unittest.TestCase):
    def test_a_configured_path_wins(self) -> None:
        with mock.patch.object(Path, "is_file", return_value=True):
            self.assertEqual(r"C:\custom\capa.exe", find_capa(r"C:\custom\capa.exe"))

    def test_a_configured_path_that_is_not_there_is_ignored(self) -> None:
        # Otherwise a stale setting in `config.json` pins the engine to a file
        # that no longer exists, and capa reports missing while sitting in
        # tools/.
        with mock.patch("static_triage_engine.steps.app_root",
                        return_value=Path(r"C:\App")), \
             mock.patch.object(Path, "is_file", return_value=False), \
             mock.patch("shutil.which", return_value=None):
            self.assertIsNone(find_capa(r"C:\gone\capa.exe"))

    def test_tools_beside_the_executable_beats_path(self) -> None:
        root = Path(r"C:\App")
        expected = root / "tools" / "capa" / "capa.exe"

        def only_bundled(self):
            return Path(self) == expected

        with mock.patch("static_triage_engine.steps.app_root", return_value=root), \
             mock.patch.object(Path, "is_file", only_bundled), \
             mock.patch("shutil.which", return_value=r"C:\somewhere\capa.exe"):
            self.assertEqual(str(expected), find_capa())

    def test_path_is_the_fallback(self) -> None:
        with mock.patch("static_triage_engine.steps.app_root",
                        return_value=Path(r"C:\App")), \
             mock.patch.object(Path, "is_file", return_value=False), \
             mock.patch("shutil.which", side_effect=lambda n: r"C:\py\capa.exe"
                        if n == "capa" else None):
            self.assertEqual(r"C:\py\capa.exe", find_capa())

    def test_absent_everywhere_is_none_not_a_bare_string(self) -> None:
        # The old code passed the literal "capa" to the shell regardless, so a
        # missing capa produced a spawn failure rather than a reported gap.
        with mock.patch("static_triage_engine.steps.app_root",
                        return_value=Path(r"C:\App")), \
             mock.patch.object(Path, "is_file", return_value=False), \
             mock.patch("shutil.which", return_value=None):
            self.assertIsNone(find_capa())


if __name__ == "__main__":
    unittest.main()
