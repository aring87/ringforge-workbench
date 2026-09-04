"""The gates on starting a detonation, which could not be tested until they moved.

~150 lines in `gui/dynamic_window.py` decided whether a run may start, what
stops it, what merely warns and how each is worded -- all of it behind a
display, none of it tested. Fifth module through this pass.

**The one it was hiding.** The Procmon config check read

    if described.get("readable") and not described.get("captures_registry_reads")

so a config the parser could not read produced no warning at all. Registry
reads are dropped at capture and no later pass over the PML can recover them:
a run started against an unreadable filter, found nothing, and the silence
looked like a finding about the sample rather than about the capture.
"""

import tempfile
import unittest
from pathlib import Path

from dynamic_analysis.preflight import (
    case_matches_sample,
    check_folder_writable,
    find_autorunsc,
    observation_conflict,
    run_preflight,
)


def _bench(**files) -> Path:
    """A project root with a real sample and whatever else the test needs."""
    root = Path(tempfile.mkdtemp(prefix="ringforge_preflight_"))
    (root / "sample.exe").write_bytes(b"MZ")
    (root / "tools").mkdir()
    (root / "tools" / "autorunsc64.exe").write_bytes(b"MZ")
    for name, content in files.items():
        path = root / name.replace("__", "/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes)
                         else content.encode("utf-8"))
    return root


def _run(root: Path, **over):
    kwargs = dict(
        sample=root / "sample.exe",
        case_home=root / "case",
        dynamic_output=root / "case" / "dynamic_analysis",
        procmon_enabled=False,
        procmon_path=root / "tools" / "procmon.exe",
        procmon_config="",
        project_root=root,
        admin=True,
    )
    kwargs.update(over)
    return run_preflight(**kwargs)


def _first_lines(messages):
    return [m.splitlines()[0] for m in messages]


class TheProcmonConfig(unittest.TestCase):
    """The defect the extraction was for."""

    def test_an_unreadable_config_is_not_silence(self) -> None:
        root = _bench(**{"broken.pmc": b"\x00\x01not a procmon config"})

        result = _run(root, procmon_enabled=True,
                      procmon_path=root / "sample.exe",
                      procmon_config=str(root / "broken.pmc"))

        self.assertFalse(result.blocked)
        self.assertTrue(any("could not be read" in w for w in result.warnings),
                        f"got: {_first_lines(result.warnings)}")

    def test_the_unreadable_warning_carries_the_parser_s_reason(self) -> None:
        root = _bench(**{"broken.pmc": b"\x00\x01nope"})

        result = _run(root, procmon_enabled=True,
                      procmon_path=root / "sample.exe",
                      procmon_config=str(root / "broken.pmc"))
        warning = next(w for w in result.warnings if "could not be read" in w)

        self.assertIn("could not be read", warning)
        self.assertIn("dynamic_registry_reads.pmc", warning)

    def test_a_config_that_drops_registry_reads_still_warns(self) -> None:
        root = _bench()

        result = _run(root, procmon_enabled=True,
                      procmon_path=root / "sample.exe",
                      procmon_config=str(root / "sample.exe"),
                      describe=lambda _p: {"readable": True,
                                           "captures_registry_reads": False})

        self.assertTrue(
            any("captures no registry reads" in w for w in result.warnings))

    def test_a_good_config_says_nothing(self) -> None:
        root = _bench()

        result = _run(root, procmon_enabled=True,
                      procmon_path=root / "sample.exe",
                      procmon_config=str(root / "sample.exe"),
                      describe=lambda _p: {"readable": True,
                                           "captures_registry_reads": True})

        self.assertEqual([], [w for w in result.warnings if "Procmon" in w])

    def test_a_missing_config_file_warns_about_the_default_filter(self) -> None:
        root = _bench()

        result = _run(root, procmon_enabled=True,
                      procmon_path=root / "sample.exe",
                      procmon_config=str(root / "gone.pmc"))

        self.assertTrue(any("was not found" in w for w in result.warnings))

    def test_procmon_off_means_no_config_warnings(self) -> None:
        """The config checks used to run whether or not Procmon was enabled,
        so a run with it switched off warned about a filter that would never
        be loaded -- noise in the one dialog that has to be read."""
        root = _bench(**{"broken.pmc": b"\x00\x01nope"})

        result = _run(root, procmon_enabled=False,
                      procmon_config=str(root / "broken.pmc"))

        self.assertEqual([], [w for w in result.warnings if "Procmon" in w])


class WhatStopsARun(unittest.TestCase):
    def test_a_missing_sample_blocks(self) -> None:
        root = _bench()

        result = _run(root, sample=root / "not-there.exe")

        self.assertTrue(result.blocked)
        self.assertIn("Sample file not found", result.issues[0])

    def test_a_directory_where_a_sample_should_be_blocks(self) -> None:
        root = _bench()

        result = _run(root, sample=root / "tools")

        self.assertTrue(result.blocked)
        self.assertIn("not a file", result.issues[0])

    def test_procmon_enabled_without_the_executable_blocks(self) -> None:
        root = _bench()

        result = _run(root, procmon_enabled=True,
                      procmon_path=root / "tools" / "absent.exe")

        self.assertTrue(result.blocked)
        self.assertIn("Procmon is enabled", result.issues[0])

    def test_procmon_disabled_does_not_care_where_it_is(self) -> None:
        root = _bench()

        result = _run(root, procmon_enabled=False,
                      procmon_path=root / "tools" / "absent.exe")

        self.assertFalse(result.blocked)

    def test_an_ordinary_bench_starts(self) -> None:
        root = _bench()

        result = _run(root)

        self.assertFalse(result.blocked)
        self.assertEqual([], result.warnings)

    def test_the_output_folder_is_created_rather_than_demanded(self) -> None:
        """The probe writes; it does not test a permission bit. A case folder
        that does not exist yet is the ordinary case, not a failure."""
        root = _bench()

        result = _run(root)

        self.assertTrue((root / "case" / "dynamic_analysis").exists())
        self.assertFalse(result.blocked)

    def test_the_write_probe_leaves_nothing_behind(self) -> None:
        root = _bench()
        _run(root)

        self.assertEqual(
            [], list((root / "case").glob(".ringforge_write_test")))


class WhatOnlyWarns(unittest.TestCase):
    def test_a_missing_autorunsc_warns_and_names_where_it_looked(self) -> None:
        root = _bench()
        (root / "tools" / "autorunsc64.exe").unlink()

        result = _run(root)

        self.assertFalse(result.blocked)
        self.assertIn("Autorunsc was not found", result.warnings[0])
        self.assertIn("autorunsc64.exe", result.warnings[0])

    def test_autorunsc_is_found_under_any_spelling(self) -> None:
        for name in ("autorunsc64.exe", "Autorunsc64.exe",
                     "autorunsc.exe", "Autorunsc.exe"):
            with self.subTest(name=name):
                root = Path(tempfile.mkdtemp(prefix="ringforge_preflight_"))
                (root / "tools").mkdir()
                (root / "tools" / name).write_bytes(b"MZ")

                self.assertIsNotNone(find_autorunsc(root))

    def test_running_unelevated_warns(self) -> None:
        root = _bench()

        result = _run(root, admin=False)

        joined = " ".join(result.warnings)
        self.assertIn("not running as Administrator", joined)

    def test_nothing_here_blocks(self) -> None:
        root = _bench()
        (root / "tools" / "autorunsc64.exe").unlink()

        result = _run(root, admin=False)

        self.assertFalse(result.blocked)
        self.assertEqual(2, len(result.warnings))


class TheObservationWindows(unittest.TestCase):
    """Post-exit observation against the hard timeout, in seconds."""

    def test_settings_that_fit_say_nothing(self) -> None:
        self.assertIsNone(observation_conflict(300, 30, 60))

    def test_post_exit_longer_than_the_timeout_is_named(self) -> None:
        message = observation_conflict(60, 30, 120)

        self.assertIsNotNone(message)
        self.assertIn("longer than or equal to", message)
        self.assertIn("60 seconds", message)
        self.assertIn("120 seconds", message)

    def test_equal_counts_as_a_conflict(self) -> None:
        self.assertIsNotNone(observation_conflict(60, 10, 60))

    def test_post_exit_that_will_not_fit_after_the_minimum_is_named(self) -> None:
        message = observation_conflict(100, 80, 30)

        self.assertIsNotNone(message)
        self.assertIn("may not fully fit", message)
        self.assertIn("20 seconds", message)

    def test_no_timeout_means_no_conflict(self) -> None:
        """A run with no hard timeout cannot be cut short by one."""
        self.assertIsNone(observation_conflict(0, 30, 600))

    def test_no_post_exit_window_means_no_conflict(self) -> None:
        self.assertIsNone(observation_conflict(300, 30, 0))

    def test_a_minimum_at_or_past_the_timeout_is_left_alone(self) -> None:
        """`remaining` is zero or negative, and the first branch has already
        answered the case that matters. Pinned so the arithmetic does not
        start producing a message with a negative number in it."""
        message = observation_conflict(60, 60, 30)

        self.assertIsNone(message)


class TheCaseFolderName(unittest.TestCase):
    def test_an_exact_match_passes(self) -> None:
        self.assertTrue(case_matches_sample("payload", "payload"))

    def test_a_suffixed_case_folder_passes(self) -> None:
        self.assertTrue(case_matches_sample("payload", "payload_20260903"))

    def test_a_shortened_sample_name_passes(self) -> None:
        self.assertTrue(case_matches_sample("c14cb5b6_payload", "payload"))

    def test_an_unrelated_name_does_not(self) -> None:
        self.assertFalse(case_matches_sample("payload", "remcos"))

    def test_an_empty_side_is_not_a_mismatch(self) -> None:
        """Nothing to disagree with. Blocking here would fire on every case
        that has not been named yet."""
        self.assertTrue(case_matches_sample("", "payload"))
        self.assertTrue(case_matches_sample("payload", ""))

    def test_it_is_case_insensitive(self) -> None:
        self.assertTrue(case_matches_sample("Payload", "PAYLOAD_1"))


class TheWriteProbe(unittest.TestCase):
    def test_a_writable_folder_answers_true(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="ringforge_preflight_"))

        ok, error = check_folder_writable(root / "new" / "deeper")

        self.assertTrue(ok)
        self.assertEqual("", error)

    def test_a_path_that_cannot_be_a_folder_answers_why(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="ringforge_preflight_"))
        blocker = root / "a-file"
        blocker.write_text("not a directory", encoding="utf-8")

        ok, error = check_folder_writable(blocker / "under-a-file")

        self.assertFalse(ok)
        self.assertTrue(error)


if __name__ == "__main__":
    unittest.main()
