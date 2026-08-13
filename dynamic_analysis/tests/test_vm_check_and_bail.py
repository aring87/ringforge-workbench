"""Gap 4's active half: read a VM artifact, then go quiet.

The passive half refuses to let a crashed chain read as clean. This is the other
shape: a sample that checks for a hypervisor and *exits tidily* -- no crash, no
error, an empty report and a clean verdict.

Four answers, and the distinction between the first two is the point: a run that
could not have seen a check must not read like a run that saw none.

**The threshold is not calibrated and the tests say so.** Registry-read
collection has been configured for three runs and captured on one, and the
sample this exists for has never produced a read the pass could see. So these
test the *mechanism* -- that the four verdicts are reachable and that the
uncollected case is distinguishable -- and deliberately not the constant.
"""
import unittest

from dynamic_analysis.vm_artifact_reads import (
    QUIET_EVENT_THRESHOLD,
    correlate_vm_check_with_silence,
    empty_vm_check_correlation,
)

VBOX_KEY = r"HKLM\System\CurrentControlSet\Services\VBoxGuest"


def _read_event(pid=1000, path=VBOX_KEY, ts="10:00:00.1"):
    return {"process_name": "sample.exe", "pid": pid, "operation": "RegOpenKey",
            "path": path, "result": "SUCCESS", "timestamp": ts,
            "category": "registry_read"}


def _hit(pid=1000, path=VBOX_KEY, ts="10:00:00.1", specificity="vm_specific"):
    return {"timestamp": ts, "process_name": "sample.exe", "pid": pid,
            "operation": "RegOpenKey", "path": path, "result": "SUCCESS",
            "artifact_found": True, "specificity": specificity,
            "artifact": "VirtualBox guest additions service", "family": "virtualbox",
            "marker": "vboxguest"}


def _noise(n, pid=1000):
    return [{"process_name": "sample.exe", "pid": pid, "operation": "CreateFile",
             "path": rf"C:\x\{i}.tmp", "result": "SUCCESS",
             "timestamp": f"10:00:0{i%10}.5", "category": "file_create"}
            for i in range(n)]


def _reads(hits, available=True):
    return {"collection_available": available, "hits": list(hits)}


class TheFourVerdicts(unittest.TestCase):
    def test_uncollected_is_not_the_same_as_no_check(self):
        # The distinction the whole pass exists to preserve.
        uncollected = correlate_vm_check_with_silence(
            _reads([], available=False), [], {1000})
        none_seen = correlate_vm_check_with_silence(
            _reads([]), [_read_event()], {1000})

        self.assertEqual(uncollected["verdict"], "not_collected")
        self.assertFalse(uncollected["available"])
        self.assertIn("not a statement about the sample",
                      uncollected["note"].replace("Nothing here is a statement",
                                                  "not a statement"))

        self.assertEqual(none_seen["verdict"], "no_vm_check")
        self.assertTrue(none_seen["available"])

    def test_checked_then_quiet(self):
        events = [_read_event()] + _noise(2)
        r = correlate_vm_check_with_silence(_reads([_hit()]), events, {1000})
        self.assertEqual(r["verdict"], "checked_then_quiet")
        self.assertEqual(r["sample_events_after_check"], 2)
        self.assertIn("inconclusive rather than clean", r["note"])

    def test_checked_then_active(self):
        events = [_read_event()] + _noise(QUIET_EVENT_THRESHOLD + 5)
        r = correlate_vm_check_with_silence(_reads([_hit()]), events, {1000})
        self.assertEqual(r["verdict"], "checked_then_active")
        self.assertIn("did not end the run", r["note"])


class WhatCountsAsACheck(unittest.TestCase):
    def test_identity_surface_reads_are_not_a_vm_check(self):
        # SystemBiosVersion is where a VM check looks *and* where an inventory
        # agent looks. Building a bail detector on it would fire on ordinary
        # software asking what machine it is on.
        hit = _hit(specificity="identity_surface")
        r = correlate_vm_check_with_silence(_reads([hit]), [_read_event()], {1000})
        self.assertEqual(r["verdict"], "no_vm_check")

    def test_the_last_vm_specific_read_is_the_one_that_matters(self):
        early = _hit(ts="10:00:00.1", path=VBOX_KEY)
        late = _hit(ts="10:00:09.9", path=VBOX_KEY + r"\ImagePath")
        events = [_read_event(ts="10:00:00.1"),
                  *_noise(30),
                  _read_event(ts="10:00:09.9", path=VBOX_KEY + r"\ImagePath"),
                  *_noise(1)]
        r = correlate_vm_check_with_silence(_reads([early, late]), events, {1000})
        # Busy after the first read, quiet after the last: the last one decides.
        self.assertEqual(r["verdict"], "checked_then_quiet")
        self.assertEqual(r["last_check"]["timestamp"], "10:00:09.9")


class Attribution(unittest.TestCase):
    def test_only_the_samples_own_events_count_as_activity(self):
        # Windows being busy after the check is not the sample carrying on.
        events = [_read_event()] + _noise(40, pid=4242)
        r = correlate_vm_check_with_silence(_reads([_hit()]), events, {1000})
        self.assertEqual(r["verdict"], "checked_then_quiet")
        self.assertEqual(r["sample_events_after_check"], 0)
        self.assertEqual(r["events_after_check"], 40)

    def test_unresolved_lineage_counts_everything(self):
        events = [_read_event()] + _noise(40, pid=4242)
        r = correlate_vm_check_with_silence(_reads([_hit()]), events, None)
        self.assertEqual(r["verdict"], "checked_then_active")


class NothingHereScores(unittest.TestCase):
    def test_scored_is_false_and_the_threshold_says_it_is_uncalibrated(self):
        r = correlate_vm_check_with_silence(
            _reads([_hit()]), [_read_event()], {1000})
        self.assertFalse(r["scored"])
        self.assertFalse(r["threshold_calibrated"])
        self.assertEqual(r["threshold"], QUIET_EVENT_THRESHOLD)

    def test_the_empty_shape_matches(self):
        e = empty_vm_check_correlation()
        self.assertFalse(e["available"])
        self.assertFalse(e["scored"])
        self.assertEqual(e["verdict"], "not_collected")


class Degrades(unittest.TestCase):
    def test_a_hit_absent_from_the_event_stream_is_unavailable_not_quiet(self):
        # The dangerous failure: if the read cannot be located, "0 events after"
        # would read as a bail. It must report that it could not measure.
        r = correlate_vm_check_with_silence(_reads([_hit()]), _noise(5), {1000})
        self.assertFalse(r["available"])
        self.assertNotEqual(r["verdict"], "checked_then_quiet")



class ReportSection(unittest.TestCase):
    """A detector nobody reads is most of the way to not existing."""

    def _summary(self, **over):
        base = {"available": True, "scored": False, "verdict": "checked_then_quiet",
                "last_check": {"process_name": "sample.exe", "pid": 1000,
                               "artifact": "VirtualBox guest additions service",
                               "artifact_found": True},
                "sample_events_after_check": 2, "threshold": QUIET_EVENT_THRESHOLD,
                "threshold_calibrated": False, "note": "x"}
        base.update(over)
        return {"vm_check_and_bail": base}

    def test_the_warning_reaches_the_page(self):
        from dynamic_analysis.html_report import build_dynamic_html_report

        html = build_dynamic_html_report(self._summary())
        self.assertIn("VM Check, Then Silence", html)
        self.assertIn("inconclusive rather", html)
        self.assertIn("card-alert", html)

    def test_it_says_the_threshold_is_uncalibrated(self):
        from dynamic_analysis.html_report import build_dynamic_html_report

        self.assertIn("not calibrated", build_dynamic_html_report(self._summary()))

    def test_a_quiet_run_with_no_check_grows_no_card(self):
        from dynamic_analysis.html_report import build_dynamic_html_report

        self.assertNotIn("VM Check",
                         build_dynamic_html_report(self._summary(verdict="no_vm_check")))
        self.assertNotIn("VM Check", build_dynamic_html_report({}))

    def test_uncollected_renders_differently_from_active(self):
        from dynamic_analysis.html_report import _vm_check_and_bail_section

        uncollected = _vm_check_and_bail_section(
            self._summary(verdict="not_collected", available=False,
                          note="no reads captured"))
        active = _vm_check_and_bail_section(
            self._summary(verdict="checked_then_active",
                          sample_events_after_check=400))
        self.assertIn("Not Collected", uncollected)
        self.assertNotIn("card-alert", active)
        self.assertNotEqual(uncollected, active)

if __name__ == "__main__":
    unittest.main()
