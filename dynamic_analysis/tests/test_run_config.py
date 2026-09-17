"""The config a headless detonation runs under, and why each default matters.

**The failure this file guards against.** For its first 102 samples the run
controller's guest agent ran `ringforge.cli scan` -- static triage -- and
never executed anything. The fix is `ringforge.cli detonate`, which needs the
same 24-key config the GUI builds out of Tk variables. If those two drift,
a corpus gathered by the controller is configured differently from every
hand-driven run it gets compared against, and nothing anywhere says so.

So these tests are mostly about *sameness*: the defaults here must be the
defaults in `gui/dynamic_window.py`, and the path fields must fall back the
way that file learned to.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from dynamic_analysis.memory_dump import (
    DEFAULT_MAX_PROCESSES,
    DEFAULT_SPAWN_REDUMP_SECONDS,
)
from dynamic_analysis.run_config import (
    DYNAMIC_SUBDIR,
    build_config,
    load_settings,
)


class WhereTheRunLands(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.case = self.tmp / "cases" / "thing"

    def test_the_orchestrator_writes_under_the_case_not_beside_it(self) -> None:
        # `combine` finds the dynamic module by this path. Putting the run
        # anywhere else produces a case whose dynamic half is invisible to
        # the thing that pools the verdict -- which reads as "did not run".
        config = build_config(Path("s.exe"), self.case, settings={})
        self.assertEqual(str(self.case / DYNAMIC_SUBDIR), config["case_dir"])
        self.assertEqual(str(self.case), config["case_home_dir"])

    def test_the_sample_path_is_carried_verbatim(self) -> None:
        config = build_config(self.tmp / "a b.exe", self.case, settings={})
        self.assertEqual(str(self.tmp / "a b.exe"), config["sample_path"])


class TheDefaultsMatchTheGui(unittest.TestCase):
    """Each of these is the fallback in `dynamic_window.py`.

    Changing one here without changing it there is the drift this file
    exists to catch.
    """

    def setUp(self) -> None:
        self.config = build_config(Path("s.exe"), Path("cases/x"), settings={})

    def test_observation_window(self) -> None:
        self.assertEqual(30, self.config["timeout_seconds"])
        self.assertEqual(30, self.config["minimum_observation_seconds"])
        self.assertEqual(120, self.config["post_exit_observation_seconds"])
        self.assertTrue(self.config["installer_observation_mode"])

    def test_adaptive_observation_is_on_with_a_600s_ceiling(self) -> None:
        # The cap has to clear the five-minute evasion sleep it exists for
        # and leave room to watch the wake; 300 could not catch that sleep.
        self.assertTrue(self.config["adaptive_observation"])
        self.assertEqual(600, self.config["max_observation_seconds"])

    def test_telemetry_that_degrades_cleanly_is_on(self) -> None:
        self.assertTrue(self.config["procmon_enabled"])
        self.assertTrue(self.config["sysmon_enabled"])
        self.assertTrue(self.config["pcap_enabled"])
        self.assertTrue(self.config["memory_dump_enabled"])
        self.assertTrue(self.config["memory_yara_enabled"])

    def test_the_traffic_diverter_is_opt_in(self) -> None:
        # FakeNet installs a diverter, so it stays off until asked for.
        self.assertFalse(self.config["fakenet_enabled"])

    def test_memory_dump_defaults_come_from_the_dump_module(self) -> None:
        self.assertEqual(DEFAULT_MAX_PROCESSES,
                         self.config["memory_dump_max_processes"])
        self.assertEqual(DEFAULT_SPAWN_REDUMP_SECONDS,
                         self.config["memory_dump_spawn_redump_seconds"])
        # Blank offsets fall through to the profile default inside the
        # orchestrator, which parses the text itself.
        self.assertEqual("", self.config["memory_dump_offsets"])


class AClearedFieldFallsBack(unittest.TestCase):
    """`or`, not `get(key, default)` -- and it was a real defect.

    A cleared field in `config.json` is a key holding `""`. `.get` returns
    that empty string and never reaches the default, so an empty Procmon
    config made the orchestrator pass `None` and Procmon ran on whatever
    filter it had saved. Clearing a field to restore the default is the
    obvious operator move, and it silently disabled the collection it was
    meant to restore.
    """

    def test_an_empty_procmon_config_falls_back_to_the_default(self) -> None:
        config = build_config(Path("s.exe"), Path("cases/x"),
                              settings={"dynamic_procmon_config_path": ""})
        self.assertTrue(config["procmon_config_path"].endswith(".pmc"),
                        config["procmon_config_path"])

    def test_a_stale_procmon_config_falls_back_too(self) -> None:
        # The case that cost two detonations. v1.12.0 moved the filters out of
        # tools/procmon-configs/ into the package, and a config.json written
        # before that move still named the old path. Procmon takes a
        # /LoadConfig pointing at a missing file, exits immediately and says
        # nothing, so the capture never starts and the run does not find out
        # until the export fails twenty-five minutes later.
        stale = str(Path("C:/projects/nope/tools/procmon-configs")
                    / "dynamic_default.pmc")
        config = build_config(Path("s.exe"), Path("cases/x"),
                              settings={"dynamic_procmon_config_path": stale})
        self.assertNotEqual(stale, config["procmon_config_path"])
        self.assertTrue(Path(config["procmon_config_path"]).is_file(),
                        config["procmon_config_path"])

    def test_a_procmon_config_that_exists_is_left_alone(self) -> None:
        # The fallback must not override a deliberate choice; a bench with a
        # custom filter has usually chosen it for a reason.
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / "mine.pmc"
            real.write_bytes(b"pmc")
            config = build_config(Path("s.exe"), Path("cases/x"),
                                  settings={"dynamic_procmon_config_path": str(real)})
            self.assertEqual(str(real), config["procmon_config_path"])

    def test_an_empty_procmon_path_falls_back_to_the_bundled_tool(self) -> None:
        config = build_config(Path("s.exe"), Path("cases/x"),
                              settings={"dynamic_procmon_path": ""})
        self.assertTrue(config["procmon_path"].endswith("Procmon64.exe"),
                        config["procmon_path"])

    def test_an_empty_fakenet_config_is_kept_empty(self) -> None:
        # The exception, and deliberate: empty means the stock config, which
        # is a choice rather than a missing value.
        config = build_config(Path("s.exe"), Path("cases/x"),
                              settings={"dynamic_fakenet_config_path": ""})
        self.assertEqual("", config["fakenet_config_path"])

    def test_a_set_path_is_honoured(self) -> None:
        config = build_config(Path("s.exe"), Path("cases/x"),
                              settings={"dynamic_procmon_path": r"D:\pm.exe"})
        self.assertEqual(r"D:\pm.exe", config["procmon_path"])


class SavedSettingsAreHonoured(unittest.TestCase):
    def test_every_setting_can_be_overridden(self) -> None:
        settings = {
            "dynamic_timeout_seconds": 240,
            "dynamic_adaptive_observation": False,
            "dynamic_max_observation_seconds": 900,
            "dynamic_sysmon_enabled": False,
            "dynamic_pcap_enabled": False,
            "dynamic_fakenet_enabled": True,
            "dynamic_memory_dump_offsets": "3,10,25,55",
            "dynamic_memory_dump_max_processes": 24,
            "dynamic_memory_dump_spawn_redump_seconds": 2,
        }
        config = build_config(Path("s.exe"), Path("cases/x"), settings=settings)
        self.assertEqual(240, config["timeout_seconds"])
        self.assertFalse(config["adaptive_observation"])
        self.assertEqual(900, config["max_observation_seconds"])
        self.assertFalse(config["sysmon_enabled"])
        self.assertFalse(config["pcap_enabled"])
        self.assertTrue(config["fakenet_enabled"])
        self.assertEqual("3,10,25,55", config["memory_dump_offsets"])
        self.assertEqual(24, config["memory_dump_max_processes"])
        self.assertEqual(2, config["memory_dump_spawn_redump_seconds"])


class LoadingSettings(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_no_config_file_is_not_an_error(self) -> None:
        # A fresh guest has no saved settings and every key has a default.
        self.assertEqual({}, load_settings(self.tmp))

    def test_a_config_file_is_read(self) -> None:
        (self.tmp / "config.json").write_text(
            json.dumps({"dynamic_timeout_seconds": 240}), encoding="utf-8")
        self.assertEqual(240, load_settings(self.tmp)["dynamic_timeout_seconds"])

    def test_a_malformed_config_raises_rather_than_reading_as_absent(self) -> None:
        # Absent means "use the defaults". Corrupt must not mean the same
        # thing, or a broken settings file quietly produces a run configured
        # differently from every other one.
        (self.tmp / "config.json").write_text("{ truncated", encoding="utf-8")
        with self.assertRaises(json.JSONDecodeError):
            load_settings(self.tmp)


if __name__ == "__main__":
    unittest.main()
