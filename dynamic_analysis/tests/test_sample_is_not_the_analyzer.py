"""The sample is not the analyzer, even though it lives in the analyzer's tree.

An AgentTesla run reported zero spawned processes while the memory dumper was
recording the child the sample had just spawned -- pid 5808, parent 6980, two
dumps of it, three AgentTesla rules matched in its memory. The findings section
and the memory section disagreed about whether the sample had done anything.

ANALYZER_TOOL_COMMAND_MARKERS listed the workbench's own directory names next
to precise tool invocations like "procmon64.exe /accepteula". Samples live at
samples\\ inside that tree, exactly as the README prescribes, so every event
involving a sample carried "ringforge-workbench" in its path and was attributed
to the analyzer. The score came out at 45 on confirmed AgentTesla because its
behaviour had been filed as ours.

Two guards now. The sample's own image is never analyzer activity, checked
first so that a sample named after a tool -- evasion, not coincidence -- is
reported rather than suppressed. And the broad directory markers are consulted
only outside samples\\, so a payload dropped beside the sample is not swallowed
by the same rule.

The precise tool invocations are untouched and still match anywhere, which is
what keeps Procmon, Autoruns and report writing out of the findings.
"""

import unittest

from dynamic_analysis.findings import _is_analyzer_activity, summarize_dynamic_findings

SAMPLE = "31a762fdce1008e635a5e6486d7bc50b4bce671c9232006216e70cd8f2a4a7fb.exe"
SAMPLE_DIR = r"C:\projects\RingForge_Analyzer\ringforge-workbench\samples\31a7"
SAMPLE_PATH = rf"{SAMPLE_DIR}\{SAMPLE}"


def create(parent, path, parent_pid, detail):
    return {
        "Operation": "Process Create",
        "Process Name": parent,
        "Path": path,
        "PID": parent_pid,
        "Detail": detail,
        "Time of Day": "4:37:13.0000000 PM",
    }


class SampleIsNotAnalyzerTests(unittest.TestCase):
    def test_the_sample_is_not_analyzer_activity(self) -> None:
        self.assertFalse(
            _is_analyzer_activity(SAMPLE, SAMPLE_PATH, "", sample_name=SAMPLE)
        )

    def test_a_payload_dropped_beside_the_sample_is_not_either(self) -> None:
        self.assertFalse(
            _is_analyzer_activity(
                SAMPLE, rf"{SAMPLE_DIR}\payload.exe", "", sample_name=SAMPLE
            )
        )

    def test_a_sample_named_after_a_tool_is_still_reported(self) -> None:
        # Naming yourself procmon64.exe is evasion. The sample check runs
        # first precisely so this surfaces instead of being suppressed.
        self.assertFalse(
            _is_analyzer_activity(
                "procmon64.exe",
                rf"{SAMPLE_DIR}\procmon64.exe",
                "",
                sample_name="procmon64.exe",
            )
        )


class AnalyzerDetectionStillWorksTests(unittest.TestCase):
    def test_a_procmon_invocation_is_caught(self) -> None:
        self.assertTrue(
            _is_analyzer_activity(
                "cmd.exe",
                r"C:\rf\ringforge-workbench\tools\procmon64.exe",
                "procmon64.exe /accepteula /quiet",
                sample_name=SAMPLE,
            )
        )

    def test_a_tool_by_name_is_caught(self) -> None:
        self.assertTrue(
            _is_analyzer_activity(
                "autorunsc64.exe", r"C:\rf\tools\autorunsc64.exe", "", sample_name=SAMPLE
            )
        )

    def test_report_writing_is_caught(self) -> None:
        self.assertTrue(
            _is_analyzer_activity(
                "python.exe",
                r"C:\rf\ringforge-workbench\cases\x\reports\dynamic_report.html",
                "",
                sample_name=SAMPLE,
            )
        )

    def test_workbench_activity_outside_samples_is_caught(self) -> None:
        self.assertTrue(
            _is_analyzer_activity(
                "foo.exe",
                r"C:\rf\ringforge-workbench\dynamic_analysis\orchestrator.py",
                "",
                sample_name=SAMPLE,
            )
        )


class AgentTeslaShapeTests(unittest.TestCase):
    """The run that exposed this: the sample relaunching itself."""

    def _events(self):
        return [
            create(SAMPLE, SAMPLE_PATH, 6980, f"PID: 5808, Command line: {SAMPLE}"),
            create(
                "procmon64.exe",
                r"C:\rf\ringforge-workbench\tools\procmon64.exe",
                900,
                "PID: 901, Command line: procmon64.exe /accepteula",
            ),
        ]

    def test_the_self_spawn_is_now_a_finding(self) -> None:
        events = self._events()
        result = summarize_dynamic_findings(
            events, events, sample_pid=6980, sample_name=SAMPLE
        )

        self.assertEqual(result["counts"]["process_creates"], 1)
        self.assertEqual(result["spawned_processes"][0]["child_process_name"], SAMPLE)

    def test_the_analyzer_process_is_still_excluded(self) -> None:
        events = self._events()
        result = summarize_dynamic_findings(
            events, events, sample_pid=6980, sample_name=SAMPLE
        )

        reported = [p["process_name"] for p in result["spawned_processes"]]
        self.assertNotIn("procmon64.exe", reported)


if __name__ == "__main__":
    unittest.main()
