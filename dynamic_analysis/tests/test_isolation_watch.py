"""The containment strip has to notice the guest being armed while it is open.

It was computed when the window was built and then left alone until the window
was closed and reopened. Arming and disarming happens on the host, with this
window sitting open the whole time, so the strip could sit on "Single egress
path" while the guest had been armed minutes earlier -- the most dangerous thing
this GUI can display, because it is reassuring and wrong.

A poll every four seconds fixes it, and the signature below is what stops the
poll from redrawing on every tick: re-packing the armed banner four times a
minute flickers and steals focus from whatever is being typed.

These tests cover the signature rather than the Tk plumbing, because the
signature is where a missed state change would actually hide.
"""

import threading
import unittest
from unittest import mock

from gui.dynamic_window import DynamicAnalysisWindow, isolation_signature


def _contained():
    return {
        "level": "ok",
        "isolated": False,
        "contained": True,
        "egress_count": 1,
        "note": "Single egress path via Ethernet 2.",
        "egress": [
            {"adapter": "Ethernet 2", "gateway": "192.168.56.1", "reaches": "contained"}
        ],
    }


def _armed():
    return {
        "level": "uncontained",
        "isolated": False,
        "egress_count": 2,
        "note": "2 adapters hold a default route.",
        "egress": [
            {"adapter": "Ethernet 2", "gateway": "192.168.56.1", "reaches": "contained"},
            {"adapter": "Ethernet", "gateway": "10.0.2.2", "reaches": "internet"},
        ],
    }


class IsolationSignatureTests(unittest.TestCase):
    def test_the_same_state_reads_the_same(self) -> None:
        # Two identical probes must not redraw. This is what keeps the banner
        # from being re-packed every four seconds forever.
        self.assertEqual(isolation_signature(_contained()), isolation_signature(_contained()))

    def test_arming_the_guest_changes_it(self) -> None:
        # The case the whole watch exists for.
        self.assertNotEqual(isolation_signature(_contained()), isolation_signature(_armed()))

    def test_disarming_changes_it_back(self) -> None:
        self.assertNotEqual(isolation_signature(_armed()), isolation_signature(_contained()))

    def test_a_second_adapter_appearing_is_a_change(self) -> None:
        # Same level and note, one more egress path. Comparing only the level
        # would miss it, and the banner names the paths.
        one = _armed()
        two = _armed()
        two["egress"] = two["egress"] + [
            {"adapter": "Ethernet 3", "gateway": "172.16.0.1", "reaches": "internet"}
        ]

        self.assertNotEqual(isolation_signature(one), isolation_signature(two))

    def test_a_gateway_changing_is_a_change(self) -> None:
        moved = _contained()
        moved["egress"] = [
            {"adapter": "Ethernet 2", "gateway": "192.168.99.1", "reaches": "contained"}
        ]

        self.assertNotEqual(isolation_signature(_contained()), isolation_signature(moved))

    def test_a_probe_failure_is_distinguishable_from_contained(self) -> None:
        failed = {"level": "unknown", "note": "route print failed", "egress_count": 0}

        self.assertNotEqual(isolation_signature(_contained()), isolation_signature(failed))

    def test_junk_does_not_raise(self) -> None:
        # The probe runs on a worker thread and its result is whatever came
        # back; a malformed status must not take the window down.
        self.assertEqual(isolation_signature(None), ("unknown",))
        self.assertEqual(isolation_signature("nope"), ("unknown",))
        isolation_signature({"egress": [None, "x"]})


class _FakeWindow:
    """Enough of the window to drive the watch without a display.

    The methods under test are ordinary functions on the class, so binding them
    to this exercises the real loop -- the scheduling, the run-in-progress gate
    and the redraw decision -- rather than a reimplementation of it.
    """

    ISOLATION_POLL_MS = DynamicAnalysisWindow.ISOLATION_POLL_MS

    def __init__(self, running=False):
        self._isolation_poll_job = None
        self._isolation_probe_active = False
        self._isolation_signature = None
        self._isolation = {}
        self.worker_thread = _AliveThread() if running else None
        self.scheduled = []
        self.cancelled = []
        self.renders = 0
        self.destroyed = False

    # -- Tk surface ----------------------------------------------------
    def after(self, delay, callback=None, *args):
        if delay == 0 and callback is not None:
            callback(*args)          # marshal-to-UI-thread, run inline
            return "immediate"
        self.scheduled.append(delay)
        return f"job{len(self.scheduled)}"

    def after_cancel(self, job):
        self.cancelled.append(job)

    def _render_isolation_label(self):
        self.renders += 1

    # -- methods under test --------------------------------------------
    _schedule_isolation_poll = DynamicAnalysisWindow._schedule_isolation_poll
    _poll_isolation = DynamicAnalysisWindow._poll_isolation
    _run_in_progress = DynamicAnalysisWindow._run_in_progress
    _apply_isolation = DynamicAnalysisWindow._apply_isolation


class _AliveThread:
    def is_alive(self):
        return True


class IsolationWatchLoopTests(unittest.TestCase):
    def _probe_returning(self, status):
        return mock.patch(
            "dynamic_analysis.network_capture.network_isolation_status",
            return_value=status,
        )

    def test_a_state_change_redraws(self) -> None:
        window = _FakeWindow()
        window._isolation_signature = isolation_signature(_contained())

        window._apply_isolation(_armed())

        self.assertEqual(window.renders, 1)
        self.assertEqual(window._isolation["level"], "uncontained")

    def test_an_unchanged_state_does_not(self) -> None:
        window = _FakeWindow()
        window._isolation_signature = isolation_signature(_contained())

        window._apply_isolation(_contained())

        self.assertEqual(window.renders, 0)

    def test_every_tick_schedules_the_next(self) -> None:
        # A watch that stops watching is worse than no watch.
        window = _FakeWindow()
        window._isolation_signature = isolation_signature(_contained())

        window._apply_isolation(_contained())

        self.assertEqual(window.scheduled, [DynamicAnalysisWindow.ISOLATION_POLL_MS])

    def test_the_probe_is_skipped_while_a_run_is_in_progress(self) -> None:
        # Procmon is capturing everything the machine does; a subprocess every
        # four seconds would put the analyzer's own queries into the sample's
        # evidence.
        window = _FakeWindow(running=True)

        with self._probe_returning(_armed()) as probe:
            window._poll_isolation()

        probe.assert_not_called()
        self.assertEqual(window.renders, 0)
        # Still rescheduled, so the watch resumes when the run ends.
        self.assertEqual(window.scheduled, [DynamicAnalysisWindow.ISOLATION_POLL_MS])

    def test_an_idle_window_probes_and_applies(self) -> None:
        window = _FakeWindow()

        with self._probe_returning(_armed()):
            window._poll_isolation()
            for thread in threading.enumerate():
                if thread.name == "ringforge-isolation-watch":
                    thread.join(timeout=5)

        self.assertEqual(window._isolation.get("level"), "uncontained")
        self.assertEqual(window.renders, 1)

    def test_probes_do_not_overlap(self) -> None:
        window = _FakeWindow()
        window._isolation_probe_active = True

        with self._probe_returning(_armed()) as probe:
            window._poll_isolation()

        probe.assert_not_called()
        self.assertEqual(window.scheduled, [DynamicAnalysisWindow.ISOLATION_POLL_MS])

    def test_a_failing_probe_still_reschedules(self) -> None:
        # Otherwise one transient failure silently ends the watch for the life
        # of the window, and the strip goes stale again without saying so.
        window = _FakeWindow()

        with mock.patch(
            "dynamic_analysis.network_capture.network_isolation_status",
            side_effect=OSError("route print failed"),
        ):
            window._poll_isolation()
            for thread in threading.enumerate():
                if thread.name == "ringforge-isolation-watch":
                    thread.join(timeout=5)

        self.assertEqual(window._isolation.get("level"), "unknown")
        self.assertEqual(window.scheduled, [DynamicAnalysisWindow.ISOLATION_POLL_MS])


if __name__ == "__main__":
    unittest.main()
