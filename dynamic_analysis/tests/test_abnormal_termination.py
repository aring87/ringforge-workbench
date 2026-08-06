"""Gap 4: a chain that ends by crash must not read as a clean run.

Nothing reported "the sample checked for a VM and left." The loader is the case
that wants it -- a deterministic fault at the same point across six runs, where a
deliberate anti-analysis bail is indistinguishable from a broken payload from
outside the guest. This does not try to tell those apart, because the pipeline
cannot. It refuses to let either read as benign.

Two witnesses: the Application Error 1000 events already attributed to the
sample, and any WerFault naming a sample-tree PID. The second exists because a
Windows build can fail to write the event, leaving only the WerFault spawn.
"""

import unittest

from dynamic_analysis.crash_evidence import (
    summarize_abnormal_termination,
    werfault_witnesses,
    _werfault_target_pid,
)


def _proc(child, pid, detail):
    """A spawn record shaped like `_build_process_create_record`'s output.

    ``pid`` is the **creating** process, which is what Procmon puts in the PID
    column of a process-create event. The created process's PID lives in the
    detail as `PID: <n>`. The first version of this fixture passed WerFault's own
    PID here, and `werfault_witnesses` read it back out of the same field -- so
    the test agreed with the code about something both had wrong.
    """
    return {"process_name": "regsvcs.exe", "child_process_name": child,
            "pid": pid, "detail": detail, "timestamp": "t"}


class WerFaultParsingTests(unittest.TestCase):
    def test_both_command_forms_yield_the_crashed_pid(self) -> None:
        self.assertEqual(_werfault_target_pid("WerFault.exe -u -p 3564 -s 220"), 3564)
        self.assertEqual(
            _werfault_target_pid("WerFault.exe -pss -s 408 -p 3564 -ip 3564"), 3564
        )

    def test_no_target_is_none(self) -> None:
        self.assertIsNone(_werfault_target_pid("WerFault.exe"))
        self.assertIsNone(_werfault_target_pid(""))


class WerFaultWitnessTests(unittest.TestCase):
    def test_a_werfault_naming_a_sample_pid_is_a_witness(self) -> None:
        recs = [_proc("werfault.exe", 9592,
                      "PID: 5592, Command line: WerFault.exe -u -p 9592 -s 220")]

        witnesses = werfault_witnesses(recs, descendant_pids={9592, 10956})

        self.assertEqual(len(witnesses), 1)
        self.assertEqual(witnesses[0]["crashed_pid"], 9592)

    def test_the_three_pids_are_told_apart(self) -> None:
        # The 06 Aug loader run, verbatim: RegSvcs 4264 faulted, spawned
        # WerFault 7976, and WerFault's -p names 4264. The witness used to report
        # werfault_pid 4264 -- the record's own `pid`, which is the *creating*
        # process. Same number as the crashed PID here, because the crashing
        # process is what spawned WerFault, which is exactly why it read as
        # plausible for two runs.
        recs = [_proc("werfault.exe", 4264,
                      r"PID: 7976, Command line: C:\WINDOWS\SysWOW64\WerFault.exe "
                      "-u -p 4264 -s 240")]

        witness = werfault_witnesses(recs, descendant_pids={4264})[0]

        self.assertEqual(witness["crashed_pid"], 4264)
        self.assertEqual(witness["werfault_pid"], 7976)
        self.assertEqual(witness["spawned_by_pid"], 4264)

    def test_a_pss_spawn_does_not_name_the_spawning_service(self) -> None:
        # The case that makes this more than cosmetic. A -pss WerFault is started
        # by WerSvc's svchost, so the record's `pid` is svchost's and has nothing
        # to do with the crash.
        recs = [_proc("werfault.exe", 1092,
                      "PID: 8120, Command line: WerFault.exe -pss -s 408 -p 9592 -ip 9592")]

        witness = werfault_witnesses(recs, descendant_pids={9592})[0]

        self.assertEqual(witness["crashed_pid"], 9592)
        self.assertEqual(witness["werfault_pid"], 8120)
        self.assertNotEqual(witness["werfault_pid"], witness["spawned_by_pid"])

    def test_a_werfault_for_an_unrelated_pid_is_not(self) -> None:
        recs = [_proc("werfault.exe", 5592,
                      "PID: 5592, Command line: WerFault.exe -u -p 4321 -s 220")]

        self.assertEqual(werfault_witnesses(recs, descendant_pids={9592}), [])

    def test_unresolved_lineage_keeps_every_werfault(self) -> None:
        # None means lineage could not be resolved; the same degrade the
        # findings use. Dropping the witness would hide a real crash.
        recs = [_proc("werfault.exe", 5592,
                      "PID: 5592, Command line: WerFault.exe -u -p 9592")]

        self.assertEqual(len(werfault_witnesses(recs, descendant_pids=None)), 1)

    def test_a_non_werfault_child_is_ignored(self) -> None:
        recs = [_proc("smng.exe", 10756, "PID: 10756, Command line: smng.exe")]
        self.assertEqual(werfault_witnesses(recs, descendant_pids=None), [])


class AbnormalTerminationTests(unittest.TestCase):
    def test_an_application_error_alone_is_enough(self) -> None:
        crash = {"counts": {"crashes": 1},
                 "crashes": [{"app_name": "RegSvcs.exe", "pid": 9592}]}

        result = summarize_abnormal_termination(crash, process_records=[])

        self.assertTrue(result["chain_crashed"])
        self.assertFalse(result["witnessed_only_by_werfault"])
        self.assertEqual(result["crashed_processes"][0]["process"], "RegSvcs.exe")

    def test_a_werfault_alone_is_enough(self) -> None:
        # The case the second witness exists for: a real crash with no event.
        recs = [_proc("werfault.exe", 5592,
                      "PID: 5592, Command line: WerFault.exe -u -p 9592 -s 220")]

        result = summarize_abnormal_termination(
            {"counts": {"crashes": 0}, "crashes": []},
            process_records=recs,
            descendant_pids={9592},
        )

        self.assertTrue(result["chain_crashed"])
        self.assertTrue(result["witnessed_only_by_werfault"])

    def test_a_quiet_run_with_no_crash_says_nothing(self) -> None:
        result = summarize_abnormal_termination(
            {"counts": {"crashes": 0}, "crashes": []}, process_records=[]
        )

        self.assertFalse(result["chain_crashed"])
        self.assertEqual(result["note"], "")

    def test_the_loader_run_shape(self) -> None:
        # RegSvcs.exe -> WerFault.exe, exactly as six loader runs produced, plus
        # the Application Error the crash-as-injection route also reads.
        crash = {"counts": {"crashes": 1},
                 "crashes": [{"app_name": "RegSvcs.exe", "pid": 9592}]}
        recs = [_proc("werfault.exe", 5592,
                      "PID: 5592, Command line: WerFault.exe -u -p 9592 -s 220")]

        result = summarize_abnormal_termination(
            crash, process_records=recs, descendant_pids={9592, 10956}
        )

        self.assertTrue(result["chain_crashed"])
        # Both witnesses agree, so this is not "only WerFault".
        self.assertFalse(result["witnessed_only_by_werfault"])
        self.assertEqual(result["event_crashes"], 1)
        self.assertEqual(len(result["werfault_witnesses"]), 1)
        self.assertIn("inconclusive", result["note"])

    def test_it_does_not_score(self) -> None:
        # A crash is not evidence of malice; benign software crashes. The
        # summary carries no strong/present/score fields -- it is a warning, not
        # a category.
        result = summarize_abnormal_termination(
            {"counts": {"crashes": 1}, "crashes": [{"app_name": "x.exe", "pid": 1}]},
            process_records=[],
        )

        self.assertNotIn("strong", result)
        self.assertNotIn("present", result)
        self.assertNotIn("score", result)


if __name__ == "__main__":
    unittest.main()
