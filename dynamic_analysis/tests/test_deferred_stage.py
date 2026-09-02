"""A run that installs persistence has a stage it will never watch.

Measured on `ce0d08be...`: it dropped 23 files, installed an `ONLOGON` task and
exited eight seconds in, and the run scored it Likely Malicious at 140 on that
alone. Correct about the installer, and silent about the resident stage that
task launches -- beaconing every 17.03 s, reporting the machine to an operator,
carrying a ransom capability. None of it was in a run.

The reason the orchestrator reports rather than acts is structural and is worth
holding: the gated capture spans a reboot and needs the host to drive a logon,
while `run_dynamic_analysis` lives inside one boot in the guest. A function that
claimed to observe the deferred stage would be lying; one that declines and
hands over the procedure is useful.

So `observed` is always False, and these tests pin that it stays stated rather
than becoming implied.
"""

import unittest

from dynamic_analysis.deferred_stage import (
    assess_deferred_stage,
    describe_for_status,
)


def _task(name, reasons, execute="C:\\Users\\a\\AppData\\Roaming\\x.exe"):
    return {
        "name": name,
        "reasons": reasons,
        "actions": [{"execute": execute, "arguments": ""}],
    }


class Detection(unittest.TestCase):
    def test_a_logon_task_is_a_deferred_stage(self) -> None:
        summary = {"added_tasks": [_task("ce0d08be...", ["logon_trigger"])]}

        result = assess_deferred_stage(task_diff_summary=summary)

        self.assertTrue(result["present"])
        self.assertEqual(result["entry_count"], 1)
        self.assertEqual(result["entries"][0]["kind"], "scheduled_task")

    def test_a_boot_task_counts_too(self) -> None:
        summary = {"added_tasks": [_task("svc", ["boot_trigger"])]}

        self.assertTrue(assess_deferred_stage(task_diff_summary=summary)["present"])

    def test_a_task_with_no_future_trigger_does_not(self) -> None:
        """An added task that runs on a schedule the run already covered, or on
        an event that has passed, is not a stage nobody watched."""
        summary = {"added_tasks": [_task("updater", ["execute_in_suspicious_path"])]}

        result = assess_deferred_stage(task_diff_summary=summary)

        self.assertFalse(result["present"])
        self.assertIn("no deferred stage", result["note"])

    def test_autoruns_entries_are_deferred_by_definition(self) -> None:
        summary = {
            "suspicious_new_entries": [
                {"entry": "Updater", "entry_location": "HKCU\\...\\Run",
                 "image_path": "C:\\Users\\a\\AppData\\x.exe"}
            ]
        }

        result = assess_deferred_stage(autoruns_diff_summary=summary)

        self.assertTrue(result["present"])
        self.assertEqual(result["entries"][0]["kind"], "autorun")

    def test_both_sources_are_counted_together(self) -> None:
        result = assess_deferred_stage(
            task_diff_summary={"added_tasks": [_task("t", ["logon_trigger"])]},
            autoruns_diff_summary={"suspicious_new_entries": [{"entry": "r"}]},
        )

        self.assertEqual(result["entry_count"], 2)

    def test_nothing_at_all_is_a_clean_statement_not_an_empty_one(self) -> None:
        """The note has to distinguish "no persistence was installed" from
        "this says nothing about what the sample could install", or a reader
        takes the absence for a guarantee."""
        result = assess_deferred_stage()

        self.assertFalse(result["present"])
        self.assertIn("not about what the sample is capable of", result["note"])


class Reporting(unittest.TestCase):
    def test_observed_is_false_and_said_out_loud(self) -> None:
        """The pipeline watches one boot. That is the whole finding, so it is a
        field rather than something inferred from an absence."""
        result = assess_deferred_stage(
            task_diff_summary={"added_tasks": [_task("t", ["logon_trigger"])]}
        )

        self.assertIn("observed", result)
        self.assertFalse(result["observed"])

    def test_a_present_gap_carries_the_procedure(self) -> None:
        result = assess_deferred_stage(
            task_diff_summary={"added_tasks": [_task("t", ["logon_trigger"])]},
            sample_name="ce0d08be.exe",
        )

        joined = " ".join(result["procedure"])
        self.assertIn("--gate-logon", joined)
        self.assertIn("vm_gated_logon.ps1", joined)
        self.assertIn("ce0d08be.exe", joined)
        self.assertIn("ready_seconds_after_boot", joined)

    def test_the_margin_check_is_in_the_procedure(self) -> None:
        """The one step that makes a gated run mean anything: the payload's
        start must be later than the capture's ready, or the run says nothing
        about the payload's first seconds."""
        result = assess_deferred_stage(
            task_diff_summary={"added_tasks": [_task("t", ["logon_trigger"])]}
        )

        self.assertTrue(
            any("must be larger" in step for step in result["procedure"])
        )

    def test_no_gap_means_no_procedure(self) -> None:
        self.assertEqual(assess_deferred_stage()["procedure"], [])

    def test_the_status_line_is_empty_when_there_is_nothing_to_say(self) -> None:
        self.assertEqual(describe_for_status(assess_deferred_stage()), "")

    def test_the_status_line_names_the_gap(self) -> None:
        line = describe_for_status(
            assess_deferred_stage(
                task_diff_summary={"added_tasks": [_task("t", ["logon_trigger"])]}
            )
        )

        self.assertIn("DEFERRED STAGE", line)
        self.assertIn("did not observe", line)


class Robustness(unittest.TestCase):
    def test_malformed_summaries_do_not_raise(self) -> None:
        """This runs at the end of a detonation. Raising here would lose the
        run's whole summary over a shape the collector got wrong."""
        for bad in (None, {}, {"added_tasks": None}, {"added_tasks": ["x"]},
                    {"added_tasks": [{"reasons": "logon_trigger"}]}):
            assess_deferred_stage(task_diff_summary=bad)

        for bad in (None, {}, {"suspicious_new_entries": None},
                    {"suspicious_new_entries": [None]}):
            assess_deferred_stage(autoruns_diff_summary=bad)

    def test_a_string_reason_is_handled_like_a_list(self) -> None:
        result = assess_deferred_stage(
            task_diff_summary={"added_tasks": [{"name": "t",
                                               "reasons": "logon_trigger"}]}
        )

        self.assertTrue(result["present"])


class ReportSection(unittest.TestCase):
    """The status line scrolls past; the report is what gets read later.

    This gap existed as a summary key and a line of console output for a day,
    which is most of the way to not existing: the measured case is a report
    whose reader had no way to know a stage was missing from it.
    """

    def _summary(self, **over):
        base = {
            "task_diff_summary": {
                "added_tasks": [_task("ce0d08be...", ["logon_trigger"])]
            }
        }
        base.update(over)
        return {"deferred_stage": assess_deferred_stage(**base)}

    def test_the_gap_reaches_the_page(self) -> None:
        from dynamic_analysis.html_report import build_dynamic_html_report

        html = build_dynamic_html_report(self._summary())

        self.assertIn("Deferred Stage", html)
        self.assertIn("did not observe what they launch", html)
        self.assertIn("card-alert", html)

    def test_the_entry_is_named_and_so_is_what_it_launches(self) -> None:
        from dynamic_analysis.html_report import build_dynamic_html_report

        html = build_dynamic_html_report(self._summary())

        self.assertIn("ce0d08be...", html)
        self.assertIn("logon_trigger", html)
        self.assertIn("x.exe", html)

    def test_the_procedure_travels_with_the_warning(self) -> None:
        """A card that says only "you have a gap" leaves the reader where the
        run left them. The steps are already in the summary; render them."""
        from dynamic_analysis.html_report import build_dynamic_html_report

        html = build_dynamic_html_report(self._summary())

        self.assertIn("vm_gated_logon.ps1", html)
        self.assertIn("must be larger", html)

    def test_it_says_it_is_not_scored(self) -> None:
        from dynamic_analysis.html_report import build_dynamic_html_report

        self.assertIn("Not scored", build_dynamic_html_report(self._summary()))

    def test_a_run_with_no_deferred_stage_grows_no_card(self) -> None:
        from dynamic_analysis.html_report import build_dynamic_html_report

        quiet = {"deferred_stage": assess_deferred_stage()}
        self.assertNotIn("Deferred Stage", build_dynamic_html_report(quiet))
        self.assertNotIn("Deferred Stage", build_dynamic_html_report({}))

    def test_the_note_keeps_its_emphasis_instead_of_its_asterisks(self) -> None:
        from dynamic_analysis.html_report import build_dynamic_html_report

        html = build_dynamic_html_report(self._summary())

        self.assertNotIn("**", html)
        self.assertIn("<b>This run did not observe what they launch.</b>", html)

    def test_a_task_name_cannot_inject_markup(self) -> None:
        """Every field here comes off the guest, named by the sample."""
        from dynamic_analysis.html_report import build_dynamic_html_report

        html = build_dynamic_html_report(
            self._summary(
                task_diff_summary={
                    "added_tasks": [_task("<script>x</script>", ["logon_trigger"])]
                }
            )
        )

        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)


if __name__ == "__main__":
    unittest.main()
