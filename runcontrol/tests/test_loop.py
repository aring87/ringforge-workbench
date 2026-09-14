"""The order of the steps, which is the whole design.

Every assertion here is about sequence rather than about outcome, because the
constraints are ordering constraints:

* containment before boot, or the sample is live and online in the gap
* power off before collect, or the host parses paths a live guest can rewrite
* restore after as well as before, or a crash leaves the next run dirty

`FakeHypervisor` records what it was asked to do, in order. It is also the
second implementation of the `Hypervisor` protocol, which is what keeps that
seam honest -- an interface with one implementation is a class with extra
steps.
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from runcontrol.guest import Guest
from runcontrol.hypervisor import Snapshot
from runcontrol.loop import Outcome, RunReport, Signals, run_one


class FakeHypervisor:
    """Records calls; optionally fails one of them."""

    def __init__(self, fail_on: str = "", running: bool = False) -> None:
        self.calls: list[tuple] = []
        self.fail_on = fail_on
        self._running = running

    def _record(self, name: str, *args) -> None:
        self.calls.append((name, *args))
        if self.fail_on == name:
            raise RuntimeError(f"{name} failed on purpose")

    # -- the protocol -------------------------------------------------------
    def vms(self):
        self._record("vms")
        return {"RingForge-Analysis": "uuid"}

    def state(self, vm):
        self._record("state", vm)
        return "running" if self._running else "poweroff"

    def snapshots(self, vm):
        self._record("snapshots", vm)
        return [Snapshot("corpus-baseline", "u1")]

    def restore(self, vm, snapshot):
        self._record("restore", vm, snapshot)
        self._running = False

    def start(self, vm, headless=True):
        self._record("start", vm, headless)
        self._running = True

    def power_off(self, vm):
        self._record("power_off", vm)
        self._running = False

    def set_link(self, vm, nic, connected):
        self._record("set_link", vm, nic, connected)

    # -- helpers for the assertions -----------------------------------------
    @property
    def names(self) -> list[str]:
        return [c[0] for c in self.calls]

    def index(self, name: str) -> int:
        return self.names.index(name)


class LoopFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.exchange = self.tmp / "exchange"
        self.exchange.mkdir()
        self.cases = self.tmp / "cases"
        self.sample = self.tmp / "thing.exe"
        self.sample.write_bytes(b"MZ not really")
        # Short, because the negative cases wait out their deadline and the
        # injected `sleep` does not actually sleep. The real defaults are 600
        # and 1800 seconds; nothing here depends on the value.
        self.guest = Guest(vm="RingForge-Analysis", baseline="corpus-baseline",
                           readiness_timeout=0.15, run_timeout=0.15)
        self.signals = Signals(self.exchange)

    def guest_cooperates(self, ready: bool = True, done: bool = True,
                         write_case: bool = True):
        """A fake `sleep` that plays the guest's part when the host waits.

        The guest writes its signals while the host is asleep, which is what
        actually happens and keeps the test free of threads.
        """
        def sleep(_seconds: float) -> None:
            if ready and not self.signals.ready.exists():
                self.signals.ready.write_text("up", encoding="utf-8")
                return
            if done and not self.signals.done.exists():
                if write_case:
                    (self.exchange / "summary.json").write_text(
                        '{"band":"No Evidence"}', encoding="utf-8")
                self.signals.done.write_text("done", encoding="utf-8")
        return sleep

    # **Not `run`.** `TestCase.run` is what the framework calls to execute a
    # test, so naming a helper that made pytest invoke it as the runner --
    # before `setUp`, with `result=` as a keyword -- and every test in the file
    # failed on a missing attribute rather than on anything it asserted.
    def detonate(self, hypervisor=None, sleep=None, **kwargs) -> RunReport:
        return run_one(self.sample, self.guest, hypervisor or FakeHypervisor(),
                       self.exchange, self.cases,
                       sleep=sleep or self.guest_cooperates(), **kwargs)


class TheOrderOfOperations(LoopFixture):
    def test_the_happy_path_completes(self) -> None:
        report = self.detonate()
        self.assertIs(Outcome.COMPLETED, report.outcome, report.error)
        self.assertTrue(report.usable)

    def test_containment_is_armed_before_the_guest_boots(self) -> None:
        # The gap between boot and arming is a window where the sample is live
        # and online, and an adapter cut inside the guest can be re-enabled by
        # anything running there with administrator rights.
        hv = FakeHypervisor()
        self.detonate(hv)
        self.assertLess(hv.index("set_link"), hv.index("start"),
                        f"containment came after boot: {hv.names}")

    def test_the_link_is_cut_not_connected(self) -> None:
        hv = FakeHypervisor()
        self.detonate(hv)
        call = next(c for c in hv.calls if c[0] == "set_link")
        self.assertEqual(("set_link", "RingForge-Analysis", 1, False), call)

    def test_the_baseline_is_restored_before_anything_else(self) -> None:
        hv = FakeHypervisor()
        self.detonate(hv)
        self.assertEqual("restore", hv.names[0])
        self.assertEqual("corpus-baseline", hv.calls[0][2])

    def test_the_guest_is_powered_off_before_collection(self) -> None:
        # Reading artifacts from a live guest races an attacker who can rewrite
        # them between the stat and the open.
        hv = FakeHypervisor()
        report = self.detonate(hv)
        collect_step = [s[0] for s in report.steps].index("collect")
        power_off_step = [s[0] for s in report.steps].index("power_off")
        self.assertLess(power_off_step, collect_step)

    def test_the_baseline_is_restored_again_afterwards(self) -> None:
        # Only reverting on the way out leaves a dirty guest when the
        # controller crashes, and the next run inherits it.
        hv = FakeHypervisor()
        self.detonate(hv)
        restores = [i for i, n in enumerate(hv.names) if n == "restore"]
        self.assertEqual(2, len(restores), f"calls were {hv.names}")
        self.assertGreater(restores[1], hv.index("start"))

    def test_the_steps_are_recorded_in_order(self) -> None:
        report = self.detonate()
        self.assertEqual(
            ["restore", "contain", "deliver", "start", "readiness", "run",
             "power_off", "collect", "restore_after"],
            [s[0] for s in report.steps])


class DeliveryAndSignals(LoopFixture):
    def test_the_sample_is_delivered_to_the_exchange(self) -> None:
        self.detonate()
        self.assertEqual(b"MZ not really",
                         (self.exchange / "thing.exe").read_bytes())

    def test_a_stale_done_signal_cannot_make_a_run_look_finished(self) -> None:
        # Left over from the previous sample, this would present as a fast,
        # quiet sample rather than as a controller bug.
        self.signals.done.write_text("stale", encoding="utf-8")
        hv = FakeHypervisor()

        report = self.detonate(hv)

        self.assertIs(Outcome.COMPLETED, report.outcome)
        # Cleared before delivery, so it was the guest's own signal that ended
        # the wait, not the stale one.
        self.assertLess([s[0] for s in report.steps].index("deliver"),
                        [s[0] for s in report.steps].index("readiness"))

    def test_the_case_is_imported_under_the_sample_stem(self) -> None:
        self.detonate()
        self.assertTrue((self.cases / "thing" / "summary.json").is_file())


class AVoidRunIsNotAQuietSample(LoopFixture):
    def test_no_readiness_is_its_own_outcome(self) -> None:
        # `logon_capture` measured an ONSTART task starting 3m51s after the
        # sample's payload: Task Scheduler throttles boot-triggered tasks, so
        # booted is not started.
        report = self.detonate(sleep=self.guest_cooperates(ready=False))
        self.assertIs(Outcome.NO_READINESS, report.outcome)
        self.assertTrue(report.outcome.void)
        self.assertFalse(report.usable)

    def test_the_error_says_nothing_was_observed(self) -> None:
        report = self.detonate(sleep=self.guest_cooperates(ready=False))
        self.assertIn("void run", report.error)
        self.assertIn("quiet sample", report.error)

    def test_nothing_is_collected_when_collection_never_came_up(self) -> None:
        report = self.detonate(sleep=self.guest_cooperates(ready=False))
        self.assertIsNone(report.collected)
        self.assertFalse((self.cases / "thing").exists())

    def test_the_guest_is_still_reverted_after_a_void_run(self) -> None:
        hv = FakeHypervisor()
        self.detonate(hv, sleep=self.guest_cooperates(ready=False))
        self.assertEqual(2, hv.names.count("restore"))


class ARunTimeoutStillCollects(LoopFixture):
    def test_a_run_that_overran_is_not_void(self) -> None:
        # Collection was up, so what happened before the window closed is real
        # evidence. Only a readiness failure means nothing was watching.
        report = self.detonate(sleep=self.guest_cooperates(done=False))
        self.assertIs(Outcome.RUN_TIMEOUT, report.outcome)
        self.assertFalse(report.outcome.void)

    def test_it_still_imports_what_the_guest_wrote(self) -> None:
        def sleep(_seconds):
            if not self.signals.ready.exists():
                self.signals.ready.write_text("up", encoding="utf-8")
                (self.exchange / "partial.json").write_text("{}", encoding="utf-8")

        report = self.detonate(sleep=sleep)
        self.assertIs(Outcome.RUN_TIMEOUT, report.outcome)
        self.assertIsNotNone(report.collected)
        self.assertTrue((self.cases / "thing" / "partial.json").is_file())


class FailuresDoNotEscape(LoopFixture):
    def test_a_hypervisor_failure_is_a_report_not_an_exception(self) -> None:
        # A sweep needs a report per sample; an exception loses the ones
        # already done.
        report = self.detonate(FakeHypervisor(fail_on="start"))
        self.assertIs(Outcome.FAILED, report.outcome)
        self.assertIn("start failed on purpose", report.error)
        self.assertTrue(report.outcome.void)

    def test_a_failure_before_containment_still_reverts(self) -> None:
        hv = FakeHypervisor(fail_on="set_link")
        self.detonate(hv)
        self.assertEqual(2, hv.names.count("restore"))

    def test_a_failing_revert_is_recorded_rather_than_swallowed(self) -> None:
        # The next run starts dirty, which the sweep has to be able to see.
        report = self.detonate(FakeHypervisor(fail_on="restore"))
        self.assertIs(Outcome.FAILED, report.outcome)
        after = [s for s in report.steps if s[0] == "restore_after"]
        self.assertTrue(after and "FAILED" in after[0][2], report.steps)


if __name__ == "__main__":
    unittest.main()
