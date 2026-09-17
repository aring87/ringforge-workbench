"""Scheduled-task diffing, and the benign noise that banded a clean sample.

**Measured 17 Sep, on the first successful detonation the run controller ever
produced.** A Microsoft-signed Windows binary came back *Strongly
Corroborated / Likely Malicious*, score 105, on evidence that was entirely
the bench's own:

* seven tasks reported modified -- `ScheduledDefrag`, `WinSAT`,
  `AnalyzeSystem`, two `Sysmain` tasks, `SystemRestore\\SR` and a OneDrive
  startup task -- and in **every one of them `state` was the only field that
  differed**. Windows ran its own maintenance during the observation window.
* two of those seven counted as *suspicious*, one for using `rundll32` and
  one for a logon trigger with an executable under `%APPDATA%`. Both were
  true before the sample ran. OneDrive lives in `%LOCALAPPDATA%`; a Windows
  logon task has a logon trigger because that is what it is.

The sample created nothing: `new_tasks: 0`, `removed_tasks: 0`. So two
things had to change, and they are what these tests pin.

`diff_services.py` already had the right shape -- `_meaningful_service_changes`
-- which is why services scored 0 on the same run. This brings tasks in line.
"""

from __future__ import annotations

import unittest

from dynamic_analysis.diff_tasks import diff_scheduled_tasks


def task(name: str, *, path: str = "\\Microsoft\\Windows\\Test\\",
         state: str = "Ready", execute: str = "C:\\Windows\\System32\\thing.exe",
         arguments: str = "", trigger: str = "TimeTrigger",
         hidden: bool = False) -> dict:
    """One task record in the shape `snapshot_tasks.normalize_task_item` emits."""
    return {
        "task_name": name,
        "task_path": path,
        "state": state,
        "author": "Microsoft",
        "description": "",
        "uri": f"{path}{name}",
        "principal_user_id": "SYSTEM",
        "run_level": "Highest",
        "logon_type": "S4U",
        "hidden": hidden,
        "enabled": True,
        "multiple_instances": "IgnoreNew",
        "actions": [{"execute": execute, "arguments": arguments,
                     "working_directory": ""}],
        "triggers": [{"enabled": True, "start_boundary": "2026-01-01T00:00:00",
                      "end_boundary": "", "execution_time_limit": "PT4H",
                      "repetition_interval": "", "repetition_duration": "",
                      "trigger_type": trigger}],
    }


class RunningIsNotModifying(unittest.TestCase):
    """`state` is what the task is doing now, not what it will do."""

    def test_a_task_that_merely_ran_is_not_modified(self) -> None:
        before = [task("ScheduledDefrag")]
        after = [task("ScheduledDefrag", state="Running")]
        result = diff_scheduled_tasks(before, after)
        self.assertEqual(0, result["counts"]["modified_tasks"])

    def test_all_seven_of_the_real_ones_collapse(self) -> None:
        # The measured case: seven built-ins, `state` the only difference in
        # each. Every one of them was noise.
        names = ["ScheduledDefrag", "WinSAT", "AnalyzeSystem",
                 "ResPriStaticDbSync", "WsSwapAssessmentTask", "SR",
                 "OneDrive Startup Task"]
        before = [task(n) for n in names]
        after = [task(n, state="Running") for n in names]
        result = diff_scheduled_tasks(before, after)
        self.assertEqual(0, result["counts"]["modified_tasks"])
        self.assertEqual(0, result["counts"]["suspicious_new_or_modified"])

    def test_a_changed_action_is_still_a_modification(self) -> None:
        # The detection this must not weaken: an existing task repointed at
        # something else is real persistence, and the commonest way to hide it.
        before = [task("Updater")]
        after = [task("Updater", execute="C:\\Users\\Public\\evil.exe")]
        result = diff_scheduled_tasks(before, after)
        self.assertEqual(1, result["counts"]["modified_tasks"])

    def test_a_changed_action_is_caught_even_while_the_state_also_changes(self) -> None:
        # Excluding `state` must not mean excluding records that happen to
        # carry a state change alongside a real one.
        before = [task("Updater")]
        after = [task("Updater", state="Running",
                      execute="C:\\Users\\Public\\evil.exe")]
        self.assertEqual(
            1, diff_scheduled_tasks(before, after)["counts"]["modified_tasks"])


class SuspicionIsAboutWhatChanged(unittest.TestCase):
    """A task is not evidence for having always been what it is."""

    def test_a_lolbin_task_that_was_already_a_lolbin_task_is_not_suspicious(self) -> None:
        # `WsSwapAssessmentTask` uses rundll32 and shipped with Windows.
        before = [task("WsSwapAssessmentTask",
                       execute="C:\\Windows\\System32\\rundll32.exe")]
        after = [task("WsSwapAssessmentTask", hidden=True,
                      execute="C:\\Windows\\System32\\rundll32.exe")]
        result = diff_scheduled_tasks(before, after)
        modified = result["modified_tasks"][0]
        self.assertNotIn("lolbin:rundll32.exe", modified["reasons"])
        self.assertIn("lolbin:rundll32.exe", modified["pre_existing_reasons"])

    def test_a_pre_existing_logon_trigger_in_appdata_is_not_suspicious(self) -> None:
        # OneDrive: logon trigger, executable under %LOCALAPPDATA%. Both true
        # before the sample ran, and it was flagged for both.
        one_drive = dict(
            execute="C:\\Users\\adam\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
            trigger="LogonTrigger")
        before = [task("OneDrive Startup Task", **one_drive)]
        after = [task("OneDrive Startup Task", hidden=True, **one_drive)]
        modified = diff_scheduled_tasks(before, after)["modified_tasks"][0]
        self.assertEqual(["hidden_task"], modified["reasons"])
        self.assertTrue(modified["suspicious"])   # hidden IS new, and is real

    def test_a_newly_introduced_lolbin_is_suspicious(self) -> None:
        # The detection that has to survive: a benign task repointed at a
        # living-off-the-land binary.
        before = [task("Updater")]
        after = [task("Updater", execute="C:\\Windows\\System32\\powershell.exe")]
        modified = diff_scheduled_tasks(before, after)["modified_tasks"][0]
        self.assertTrue(modified["suspicious"])
        self.assertIn("lolbin:powershell.exe", modified["reasons"])

    def test_a_newly_added_logon_trigger_is_suspicious(self) -> None:
        before = [task("Updater", trigger="TimeTrigger")]
        after = [task("Updater", trigger="LogonTrigger")]
        modified = diff_scheduled_tasks(before, after)["modified_tasks"][0]
        self.assertTrue(modified["suspicious"])
        self.assertIn("logon_trigger", modified["reasons"])

    def test_a_task_moved_into_appdata_is_suspicious(self) -> None:
        before = [task("Updater")]
        after = [task("Updater",
                      execute="C:\\Users\\adam\\AppData\\Roaming\\x.exe")]
        modified = diff_scheduled_tasks(before, after)["modified_tasks"][0]
        self.assertTrue(modified["suspicious"])
        self.assertIn("execute_in_suspicious_path", modified["reasons"])


class NewTasksAreUnaffected(unittest.TestCase):
    """Nothing above may weaken the case the detector exists for."""

    def test_a_new_lolbin_task_is_still_suspicious_on_first_sight(self) -> None:
        # A new task has no before-state, so every reason is a new reason.
        after = [task("Evil", path="\\",
                      execute="C:\\Windows\\System32\\powershell.exe",
                      trigger="LogonTrigger")]
        result = diff_scheduled_tasks([], after)
        self.assertEqual(1, result["counts"]["new_tasks"])
        self.assertEqual(1, result["counts"]["suspicious_new_or_modified"])
        self.assertIn("lolbin:powershell.exe", result["new_tasks"][0]["reasons"])

    def test_a_removed_task_is_still_reported(self) -> None:
        result = diff_scheduled_tasks([task("Gone")], [])
        self.assertEqual(1, result["counts"]["removed_tasks"])


if __name__ == "__main__":
    unittest.main()
