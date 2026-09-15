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
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

WINDOWS = sys.platform.startswith("win")

from runcontrol.guest import Guest
from runcontrol.hypervisor import Snapshot
from runcontrol.loop import RUN_DIR, Outcome, RunReport, Signals, run_one


class FakeHypervisor:
    """Records calls; optionally fails one of them."""

    def __init__(self, fail_on: str = "", running: bool = False) -> None:
        self.calls: list[tuple] = []
        self.fail_on = fail_on
        self._running = running
        #: What the baseline carries. A real restore brings the snapshot's
        #: shared folders back wholesale, so the fake starts each run holding
        #: whatever the snapshot held rather than what the last run set.
        self._shares: dict[str, str] = {"ringforge": "C:/stale/from/baseline"}

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
        # Modelled from the real thing, measured 15 Sep: a restore brings the
        # snapshot's shared folders back and discards any the machine config
        # had gained since. The fake says so, or the loop's re-pointing step
        # would pass here while doing nothing on hardware.
        self._shares = {"ringforge": "C:/stale/from/baseline"}

    def start(self, vm, headless=True):
        self._record("start", vm, headless)
        self._running = True

    def power_off(self, vm):
        self._record("power_off", vm)
        self._running = False

    def set_link(self, vm, nic, connected):
        self._record("set_link", vm, nic, connected)

    def shared_folders(self, vm):
        self._record("shared_folders", vm)
        return dict(self._shares)

    def set_shared_folder(self, vm, name, host_path):
        self._record("set_shared_folder", vm, name, str(host_path))
        self._shares[name] = str(host_path)

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
        # The controller works in `exchange/current`, not the exchange root,
        # so the signals the fake guest writes have to live there too.
        self.work = self.exchange / RUN_DIR
        self.signals = Signals(self.work)

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
                    (self.work / "summary.json").write_text(
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

    def test_the_baseline_is_restored_before_anything_that_changes_it(self) -> None:
        # `state` may come first: the loop checks whether the guest is running
        # before restoring, because VirtualBox refuses to restore over a live
        # machine. What must not precede the restore is anything that *changes*
        # the guest.
        hv = FakeHypervisor()
        self.detonate(hv)
        restore_at = hv.index("restore")
        for name in hv.names[:restore_at]:
            with self.subTest(before_restore=name):
                self.assertIn(name, ("state", "power_off"),
                              f"{name} ran before the baseline was restored")
        self.assertEqual("corpus-baseline", hv.calls[restore_at][2])

    def test_a_running_guest_is_stopped_before_the_restore(self) -> None:
        # Only bites on the first run after somebody used the VM by hand -- in
        # a sweep the previous iteration's finally-block already left it off.
        # Which is exactly when a controller failing is least welcome. Found by
        # driving a real guest: "Cannot delete the current state of the running
        # machine".
        hv = FakeHypervisor(running=True)
        self.detonate(hv)
        self.assertLess(hv.index("power_off"), hv.index("restore"),
                        f"restored over a running guest: {hv.names}")

    def test_an_already_stopped_guest_is_not_powered_off_first(self) -> None:
        # A redundant poweroff is harmless but it is noise in the step record,
        # and the record is what explains a corpus entry.
        hv = FakeHypervisor(running=False)
        report = self.detonate(hv)
        before_restore = hv.names[:hv.index("restore")]
        self.assertNotIn("power_off", before_restore)
        self.assertIn("stop", [s[0] for s in report.steps])

    def test_the_share_is_repointed_after_the_restore_and_before_boot(self) -> None:
        # Measured on the real hypervisor, 15 Sep: a shared folder added to
        # the machine config is *gone* after `snapshot restore`. So the
        # exchange is snapshot state, exactly like the NIC cable, and setting
        # it once at bench setup would be undone by the loop's own first step
        # -- with the guest then looking for its delivery in whichever
        # directory the baseline happened to be taken with.
        hv = FakeHypervisor()
        self.detonate(hv)
        self.assertGreater(hv.index("set_shared_folder"), hv.index("restore"),
                           f"repointed before the restore wiped it: {hv.names}")
        self.assertLess(hv.index("set_shared_folder"), hv.index("start"),
                        f"repointed after boot: {hv.names}")

    def test_the_share_points_at_the_exchange_the_host_is_using(self) -> None:
        # The controller already knows where the exchange is; the guest should
        # see *that*, not whatever the snapshot remembers. This is what makes
        # a mismatch between the two impossible rather than merely unlikely.
        hv = FakeHypervisor()
        self.detonate(hv)
        call = next(c for c in hv.calls if c[0] == "set_shared_folder")
        self.assertEqual(("set_shared_folder", "RingForge-Analysis",
                          "ringforge", str(self.exchange)), call)
        # And by the end it has reverted, because step 10 restores the
        # baseline. That is not a defect to fix; it is the reason this is a
        # per-run step rather than a bench setup task, and asserting it here
        # keeps the next reader from "optimising" the call out of the loop.
        self.assertEqual("C:/stale/from/baseline", hv._shares["ringforge"])

    def test_an_empty_share_name_leaves_the_baseline_alone(self) -> None:
        # The opt-out, for a bench whose snapshot already carries the right
        # share and would rather the controller did not touch its config.
        guest = Guest(vm="RingForge-Analysis", baseline="corpus-baseline",
                      readiness_timeout=0.15, run_timeout=0.15, share_name="")
        hv = FakeHypervisor()
        run_one(self.sample, guest, hv, self.exchange, self.cases,
                sleep=self.guest_cooperates())
        self.assertNotIn("set_shared_folder", hv.names)

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
            ["stop", "restore", "contain", "share", "deliver", "start", "readiness",
             "run", "power_off", "collect", "restore_after"],
            [s[0] for s in report.steps])


class DeliveryAndSignals(LoopFixture):
    def test_the_sample_is_delivered_to_the_exchange(self) -> None:
        self.detonate()
        self.assertEqual(b"MZ not really",
                         (self.work / "thing.exe").read_bytes())

    def test_a_stale_done_signal_cannot_make_a_run_look_finished(self) -> None:
        # Left over from the previous sample, this would present as a fast,
        # quiet sample rather than as a controller bug.
        #
        # `prepare_work` deletes the whole working directory rather than
        # unlinking two files, which is the stronger guarantee: a stale
        # *artifact* is as misleading as a stale signal, and either imported
        # into the next case is indistinguishable from evidence.
        self.work.mkdir(parents=True, exist_ok=True)
        self.signals.done.write_text("stale", encoding="utf-8")
        (self.work / "leftover.json").write_text("{}", encoding="utf-8")
        hv = FakeHypervisor()

        report = self.detonate(hv)

        self.assertIs(Outcome.COMPLETED, report.outcome)
        self.assertEqual([], list((self.cases / "thing").glob("leftover.json")),
                         "an artifact from the previous run reached this case")
        # Cleared before delivery, so it was the guest's own signal that ended
        # the wait, not the stale one.
        self.assertLess([s[0] for s in report.steps].index("deliver"),
                        [s[0] for s in report.steps].index("readiness"))

    def test_the_case_is_imported_under_the_sample_stem(self) -> None:
        self.detonate()
        self.assertTrue((self.cases / "thing" / "summary.json").is_file())


class TheWorkingDirectory(LoopFixture):
    """Never the exchange root.

    On this bench the share the guest can see holds 4.8 GB across 12,172 files
    of accumulated history. Collecting the root would import all of it per
    sample, and the default caps are loose enough that it would do so silently.
    """

    def test_only_the_working_directory_is_collected(self) -> None:
        # Siblings in the exchange stand for that accumulated history.
        (self.exchange / "samples").mkdir()
        (self.exchange / "samples" / "other.exe").write_bytes(b"MZ")
        (self.exchange / "results").mkdir()
        (self.exchange / "results" / "old.json").write_text("{}", encoding="utf-8")

        self.detonate()

        imported = {p.name for p in (self.cases / "thing").rglob("*")}
        self.assertNotIn("other.exe", imported)
        self.assertNotIn("old.json", imported)
        self.assertIn("summary.json", imported)

    def test_the_siblings_are_left_alone(self) -> None:
        (self.exchange / "samples").mkdir()
        (self.exchange / "samples" / "other.exe").write_bytes(b"MZ")

        self.detonate()

        self.assertTrue((self.exchange / "samples" / "other.exe").is_file(),
                        "the controller deleted something outside its own dir")

    def test_the_exchange_root_is_refused(self) -> None:
        from runcontrol.loop import prepare_work
        with mock.patch("runcontrol.loop.RUN_DIR", "."):
            with self.assertRaises(ValueError) as caught:
                prepare_work(self.exchange)
        self.assertIn("exchange root", str(caught.exception))

    def test_a_junction_in_the_work_directory_is_not_followed(self) -> None:
        # Pins Python 3.12's `rmtree` behaviour, which is what `prepare_work`
        # relies on. Measured rather than assumed: a junction planted inside
        # the tree is removed as a link and its target survives. On a runtime
        # that recursed through it, clearing a guest-writable directory would
        # delete whatever the sample chose to point at.
        if not WINDOWS:
            self.skipTest("junctions are a Windows construct")
        import _winapi
        from runcontrol.loop import prepare_work

        precious = self.tmp / "precious"
        precious.mkdir()
        (precious / "keep.txt").write_text("keep", encoding="utf-8")
        self.work.mkdir(parents=True, exist_ok=True)
        _winapi.CreateJunction(str(precious), str(self.work / "trap"))

        prepare_work(self.exchange)

        self.assertTrue((precious / "keep.txt").is_file(),
                        "rmtree deleted through the junction")
        self.assertFalse((self.work / "trap").exists())


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
                (self.work / "partial.json").write_text("{}", encoding="utf-8")

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
