"""What the manifest says, which is the only durable record of a sweep.

`test_loop.py` asserts the *order* of one run. This asserts the *record* of
many, because the sweep's reason for existing is that an absent result should
be visible rather than merely missing. Every test here is about whether the
file on disk tells the truth about what was attempted -- including at the
moments a sweep actually dies: before the first sample, in the middle, and on
a bench that was broken all along.

`FakeHypervisor` is a second implementation of the `Hypervisor` protocol, as
in `test_loop`. `FakeGuestAgent` plays the guest's half: it writes the ready
and done signals, and a case folder, while the host is asleep -- which is what
really happens, and keeps the tests free of threads.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from runcontrol.guest import Guest
from runcontrol.hypervisor import Snapshot
from runcontrol.loop import RUN_DIR, Signals
from runcontrol.sweep import (
    ATTEMPTED, MANIFEST_NAME, NOT_ATTEMPTED, PENDING, SCHEMA, SKIPPED,
    Manifest, enumerate_samples, main, sha256_of, sweep,
)


class FakeHypervisor:
    """Records calls; optionally fails one, or lies about registration."""

    def __init__(self, fail_on: str = "", running: bool = False,
                 known: bool = True, on_restore=None) -> None:
        self.calls: list[tuple] = []
        self.fail_on = fail_on
        self._running = running
        self.known = known
        #: Called on the first mutating step of every run. The hook the
        #: "manifest exists before anything is detonated" test needs.
        self.on_restore = on_restore
        self._shares: dict[str, str] = {"ringforge": "C:/stale/from/baseline"}
        #: What the guest got to. 3 is a desktop session; 2 is the
        #: sign-in screen, which is what a broken autologon looks like.
        self.runlevel = 2
        #: (count, names). The authority on whether the logon
        #: happened -- the runlevel is not, see test_loop.
        self.logged_in = (1, ["adam"])

    def _record(self, name: str, *args) -> None:
        self.calls.append((name, *args))
        if self.fail_on == name:
            raise RuntimeError(f"{name} failed on purpose")

    def vms(self):
        self._record("vms")
        return {"RingForge-Analysis": "uuid"} if self.known else {}

    def state(self, vm):
        self._record("state", vm)
        return "running" if self._running else "poweroff"

    def snapshots(self, vm):
        self._record("snapshots", vm)
        return [Snapshot("corpus-baseline", "u1")]

    def restore(self, vm, snapshot):
        self._record("restore", vm, snapshot)
        self._running = False
        # See test_loop: a real restore discards shared folders the machine
        # config gained since the snapshot.
        self._shares = {"ringforge": "C:/stale/from/baseline"}
        if self.on_restore is not None:
            self.on_restore()

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

    def additions_runlevel(self, vm):
        self._record("additions_runlevel", vm)
        return self.runlevel

    def logged_in_users(self, vm):
        self._record("logged_in_users", vm)
        return self.logged_in

    def describe_runlevel(self, level):
        return {2: "at the sign-in screen, no desktop session",
                3: "a desktop session is up"}.get(level, f"runlevel {level}")

    def set_shared_folder(self, vm, name, host_path):
        self._record("set_shared_folder", vm, name, str(host_path))
        self._shares[name] = str(host_path)

    @property
    def names(self) -> list[str]:
        return [c[0] for c in self.calls]

    @property
    def runs(self) -> int:
        """How many times a guest has been booted."""
        return self.names.count("start")


class FakeGuestAgent:
    """The guest's half, played while the host waits.

    `cooperate_from` is which boot it starts answering on, counted from 1.
    Anything below that produces a run with no readiness signal -- a void run,
    which is what the retry and abort tests need and what a real guest whose
    scheduled task was throttled past the window produces.
    """

    def __init__(self, work: Path, hypervisor: FakeHypervisor, *,
                 ready: bool = True, done: bool = True,
                 write_case: bool = True, cooperate_from: int = 1) -> None:
        self.work = Path(work)
        self.hypervisor = hypervisor
        self.ready = ready
        self.done = done
        self.write_case = write_case
        self.cooperate_from = cooperate_from
        self.signals = Signals(self.work)

    def _delivered_case(self) -> str | None:
        """The case name, derived the way the real agent derives it.

        `[IO.Path]::GetFileNameWithoutExtension($sample.Name)` in
        `guest_run_agent.ps1`; `Path.stem` here. Read off the work directory
        rather than passed in, because the agent does not know what is coming
        either.
        """
        for entry in sorted(self.work.iterdir()):
            if entry.is_file() and entry.name not in (Signals.READY,
                                                      Signals.DONE):
                return entry.stem
        return None

    def sleep(self, _seconds: float) -> None:
        if self.hypervisor.runs < self.cooperate_from:
            return
        if self.ready and not self.signals.ready.exists():
            self.signals.ready.write_text("up", encoding="utf-8")
            return
        if self.done and not self.signals.done.exists():
            case = self._delivered_case()
            if self.write_case and case:
                # The guest writes `work/<case>/`, which is why the host ends
                # up with `cases/<case>/<case>/`.
                folder = self.work / case
                folder.mkdir(exist_ok=True)
                (folder / "summary.json").write_text(
                    '{"band":"No Evidence"}', encoding="utf-8")
            self.signals.done.write_text("done", encoding="utf-8")


class SweepFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.corpus = self.tmp / "corpus"
        self.corpus.mkdir()
        self.exchange = self.tmp / "exchange"
        self.exchange.mkdir()
        self.out = self.tmp / "out"
        self.work = self.exchange / RUN_DIR
        # Short, because the void cases wait out their deadline and the
        # injected sleep does not sleep. The real defaults are 600 and 1800.
        self.guest = Guest(vm="RingForge-Analysis", baseline="corpus-baseline",
                           readiness_timeout=0.05, run_timeout=0.05)

    def sample(self, name: str, body: bytes = b"MZ not really") -> Path:
        path = self.corpus / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        return path

    def sweep(self, hypervisor=None, agent=None, **kwargs):
        hv = hypervisor or FakeHypervisor()
        guest_agent = agent if agent is not None else FakeGuestAgent(
            self.work, hv)
        return sweep(self.corpus, self.guest, hv, self.exchange, self.out,
                     run_id=kwargs.pop("run_id", "sweep-test"),
                     sleep=guest_agent.sleep, **kwargs)

    def manifest(self, run_id: str = "sweep-test") -> dict:
        return json.loads((self.out / run_id / MANIFEST_NAME)
                          .read_text(encoding="utf-8"))

    def rows_by_name(self, document: dict) -> dict[str, dict]:
        return {row["name"]: row for row in document["samples"]}


class Enumeration(SweepFixture):
    def test_a_directory_is_listed_in_a_stable_order(self) -> None:
        # Two sweeps over the same corpus must attempt the same samples in the
        # same order, or comparing them is comparing two different runs.
        for name in ("c.exe", "a.exe", "b.exe"):
            self.sample(name)
        planned, _ = enumerate_samples(self.corpus)
        self.assertEqual(["a.exe", "b.exe", "c.exe"],
                         [p.name for p in planned])

    def test_subdirectories_are_ignored_unless_asked_for(self) -> None:
        self.sample("top.exe")
        self.sample("nested/deep.exe")
        planned, _ = enumerate_samples(self.corpus)
        self.assertEqual(["top.exe"], [p.name for p in planned])
        planned, _ = enumerate_samples(self.corpus, recursive=True)
        self.assertEqual({"top.exe", "deep.exe"}, {p.name for p in planned})

    def test_an_extension_filter_is_case_insensitive(self) -> None:
        self.sample("one.EXE")
        self.sample("two.dll")
        planned, _ = enumerate_samples(self.corpus, extensions=["exe"])
        self.assertEqual(["one.EXE"], [p.name for p in planned])

    def test_both_sides_of_a_case_collision_are_skipped(self) -> None:
        # `run_one` names the case from the stem, so `thing.exe` and
        # `thing.dll` both want `cases/thing` and the second overwrites the
        # first in silence. Skipping only the second would still leave a
        # corpus row whose case folder a reader cannot attribute.
        self.sample("thing.exe")
        self.sample("thing.dll")
        self.sample("other.exe")
        planned, skipped = enumerate_samples(self.corpus)
        self.assertEqual(["other.exe"], [p.name for p in planned])
        self.assertEqual({"thing.exe", "thing.dll"},
                         {p.name for p, _ in skipped})
        for _, reason in skipped:
            self.assertIn("thing", reason)
            self.assertIn("overwrite", reason)

    def test_an_unsafe_filename_is_skipped_rather_than_renamed(self) -> None:
        # A file called `-r.exe` becomes a command argument to capa, FLOSS or
        # `file` on the way back. Renaming it would put a name in the corpus
        # that is not the operator's name for the sample.
        self.sample("-r.exe")
        self.sample("fine.exe")
        planned, skipped = enumerate_samples(self.corpus)
        self.assertEqual(["fine.exe"], [p.name for p in planned])
        self.assertEqual(1, len(skipped))
        self.assertIn("unsafe filename", skipped[0][1])

    def test_a_missing_directory_is_an_error_not_an_empty_sweep(self) -> None:
        # An empty sweep over a path that does not exist is a corpus of zero
        # that looks like a corpus that produced nothing.
        with self.assertRaises(FileNotFoundError):
            enumerate_samples(self.tmp / "nowhere")

    def test_a_single_file_is_a_sweep_of_one(self) -> None:
        one = self.sample("just.exe")
        planned, skipped = enumerate_samples(one)
        self.assertEqual([one], planned)
        self.assertEqual([], skipped)


class TheManifestIsWrittenFirst(SweepFixture):
    def test_every_planned_sample_is_on_disk_before_anything_detonates(self) -> None:
        # The whole point. If the controller dies on the first sample, the
        # file already names every sample that was going to be attempted.
        for name in ("a.exe", "b.exe", "c.exe"):
            self.sample(name)
        seen: list[dict] = []
        hv = FakeHypervisor()
        hv.on_restore = lambda: seen.append(self.manifest()) or None
        self.sweep(hypervisor=hv, agent=FakeGuestAgent(self.work, hv))

        first = seen[0]
        self.assertEqual(SCHEMA, first["schema"])
        self.assertEqual({"a.exe", "b.exe", "c.exe"},
                         set(self.rows_by_name(first)))
        # Two of the three are still untouched at that moment, and the third
        # is the one being worked on.
        states = sorted(row["state"] for row in first["samples"])
        self.assertEqual([PENDING, PENDING, "running"], states)

    def test_a_sample_is_hashed_before_it_is_delivered(self) -> None:
        # The hash is how a manifest row joins to a label, and taking it from
        # the host's copy before delivery is what keeps it the operator's hash
        # rather than anything the guest touched.
        path = self.sample("a.exe", b"content that is definitely unique")
        self.sweep()
        row = self.rows_by_name(self.manifest())["a.exe"]
        self.assertEqual(sha256_of(path), row["sha256"])
        self.assertEqual(path.stat().st_size, row["size"])

    def test_the_manifest_is_replaced_atomically(self) -> None:
        # A sweep is hours long and this file is the only durable record; a
        # half-written one reads as corrupted results rather than as an
        # interrupted run.
        self.sample("a.exe")
        self.sweep()
        directory = self.out / "sweep-test"
        leftovers = [p.name for p in directory.iterdir()
                     if p.suffix == ".tmp" or p.name.endswith(".json.tmp")]
        self.assertEqual([], leftovers)
        # And it parses, which the atomic replace is what guarantees.
        self.assertEqual("completed", self.manifest()["state"])

    def test_two_sweeps_of_one_corpus_do_not_overwrite_each_other(self) -> None:
        # Measuring twice is the reason to measure at all.
        self.sample("a.exe")
        self.sweep(run_id="first")
        self.sweep(run_id="second")
        self.assertTrue((self.out / "first" / MANIFEST_NAME).is_file())
        self.assertTrue((self.out / "second" / MANIFEST_NAME).is_file())
        self.assertEqual("first", self.manifest("first")["run_id"])


class WhatARowSays(SweepFixture):
    def test_a_completed_run_is_usable_and_quotes_its_case_folder(self) -> None:
        self.sample("a.exe")
        result = self.sweep()
        self.assertEqual("completed", result.state)
        self.assertEqual(1, result.usable)

        row = self.rows_by_name(self.manifest())["a.exe"]
        self.assertEqual(ATTEMPTED, row["state"])
        self.assertEqual(1, len(row["attempts"]))
        attempt = row["attempts"][0]
        self.assertEqual("completed", attempt["outcome"])
        self.assertFalse(attempt["void"])
        self.assertTrue(attempt["usable"])
        self.assertTrue(Path(attempt["case_dir"]).is_dir())
        self.assertTrue((Path(attempt["case_dir"]) / "summary.json").is_file())

    def test_the_doubled_case_segment_is_resolved_not_guessed(self) -> None:
        # The guest writes `work/<case>/` and the host collects the whole of
        # `work/`, so the segment doubles. A manifest that quotes a path a
        # consumer will open has to quote the one that exists.
        self.sample("a.exe")
        self.sweep()
        attempt = self.rows_by_name(self.manifest())["a.exe"]["attempts"][0]
        self.assertEqual(("a", "a"), Path(attempt["case_dir"]).parts[-2:])

    def test_the_step_record_survives_into_the_manifest(self) -> None:
        # The readiness time is the number that says whether a timeout was
        # generous or lucky, and nothing else in the file carries it.
        self.sample("a.exe")
        self.sweep()
        attempt = self.rows_by_name(self.manifest())["a.exe"]["attempts"][0]
        steps = [step[0] for step in attempt["steps"]]
        self.assertEqual(
            ["stop", "restore", "contain", "share", "deliver", "start", "readiness",
             "run", "power_off", "collect", "restore_after"], steps)

    def test_a_guest_that_never_woke_up_is_void_and_not_usable(self) -> None:
        # A run that observed nothing must not read as a quiet sample. This is
        # the distinction the whole scoring model rests on, at the transport.
        self.sample("a.exe")
        hv = FakeHypervisor()
        agent = FakeGuestAgent(self.work, hv, ready=False, done=False)
        result = self.sweep(hypervisor=hv, agent=agent)
        self.assertEqual(0, result.usable)
        self.assertEqual(1, result.void)

        row = self.rows_by_name(self.manifest())["a.exe"]
        self.assertEqual(ATTEMPTED, row["state"])
        attempt = row["attempts"][0]
        self.assertEqual("no_readiness", attempt["outcome"])
        self.assertTrue(attempt["void"])
        self.assertIsNone(attempt["collected"])

    def test_a_hypervisor_failure_does_not_lose_the_samples_after_it(self) -> None:
        # An exception out of the sweep would discard the rows already done.
        for name in ("a.exe", "b.exe"):
            self.sample(name)
        hv = FakeHypervisor(fail_on="set_link")
        self.sweep(hypervisor=hv, agent=FakeGuestAgent(self.work, hv),
                   abort_after_consecutive_void=0)
        document = self.manifest()
        self.assertEqual("completed", document["state"])
        for name in ("a.exe", "b.exe"):
            row = self.rows_by_name(document)[name]
            self.assertEqual("failed", row["attempts"][0]["outcome"])
            self.assertIn("set_link failed", row["attempts"][0]["error"])

    def test_the_totals_add_up_to_the_rows(self) -> None:
        self.sample("a.exe")
        self.sample("-r.exe")
        self.sweep()
        totals = self.manifest()["totals"]
        self.assertEqual(1, totals["planned"])
        self.assertEqual(1, totals["attempted"])
        self.assertEqual(1, totals["usable"])
        self.assertEqual(1, totals["skipped"])
        self.assertEqual(0, totals["pending"])


class RetriesAreRecordedNotHidden(SweepFixture):
    def test_nothing_is_retried_by_default(self) -> None:
        # Silently retrying until something works biases the corpus towards
        # samples that happen to cooperate on a second boot.
        self.sample("a.exe")
        hv = FakeHypervisor()
        agent = FakeGuestAgent(self.work, hv, ready=False, done=False)
        self.sweep(hypervisor=hv, agent=agent)
        row = self.rows_by_name(self.manifest())["a.exe"]
        self.assertEqual(1, len(row["attempts"]))
        self.assertEqual(1, hv.runs)

    def test_a_retry_fires_only_on_a_void_outcome_and_both_tries_show(self) -> None:
        self.sample("a.exe")
        hv = FakeHypervisor()
        agent = FakeGuestAgent(self.work, hv, cooperate_from=2)
        result = self.sweep(hypervisor=hv, agent=agent, attempts=2)
        self.assertEqual(1, result.usable)

        row = self.rows_by_name(self.manifest())["a.exe"]
        self.assertEqual(2, len(row["attempts"]))
        self.assertEqual(["no_readiness", "completed"],
                         [a["outcome"] for a in row["attempts"]])
        self.assertEqual([1, 2], [a["n"] for a in row["attempts"]])

    def test_a_run_that_worked_is_not_tried_again(self) -> None:
        self.sample("a.exe")
        hv = FakeHypervisor()
        self.sweep(hypervisor=hv, agent=FakeGuestAgent(self.work, hv),
                   attempts=3)
        self.assertEqual(1, hv.runs)

    def test_the_retry_policy_is_named_in_the_manifest(self) -> None:
        # A reader should not have to know which outcomes `Outcome.void`
        # covers to interpret the corpus.
        self.sample("a.exe")
        self.sweep(attempts=2)
        policy = self.manifest()["policy"]
        self.assertEqual(2, policy["attempts"])
        self.assertEqual(["no_readiness", "failed"], policy["retry_on"])


class WhenTheBenchIsBroken(SweepFixture):
    def test_preflight_problems_refuse_the_sweep_and_say_so_per_row(self) -> None:
        # A sweep that dies on the second sample after twenty minutes on the
        # first is worse than one that will not start.
        for name in ("a.exe", "b.exe"):
            self.sample(name)
        hv = FakeHypervisor(known=False)
        result = self.sweep(hypervisor=hv, agent=FakeGuestAgent(self.work, hv))
        self.assertEqual("refused", result.state)
        self.assertEqual(0, hv.runs)

        document = self.manifest()
        self.assertEqual("refused", document["state"])
        self.assertTrue(document["preflight"])
        for row in document["samples"]:
            self.assertEqual(NOT_ATTEMPTED, row["state"])
            self.assertIn("refused to start", row["reason"])

    def test_ignoring_preflight_is_recorded_so_the_corpus_is_identifiable(self) -> None:
        self.sample("a.exe")
        hv = FakeHypervisor(running=True)
        result = self.sweep(hypervisor=hv, agent=FakeGuestAgent(self.work, hv),
                            ignore_preflight=True)
        self.assertEqual("completed", result.state)
        document = self.manifest()
        self.assertTrue(document["policy"]["preflight_ignored"])
        self.assertTrue(document["preflight"],
                        "the problems it started despite were not recorded")

    def test_consecutive_void_runs_stop_the_sweep_rather_than_fill_it(self) -> None:
        # Three samples in a row that never signalled readiness is a guest
        # problem. Continuing produces a hundred void corpus entries and eight
        # hours of nothing.
        for name in ("a.exe", "b.exe", "c.exe", "d.exe"):
            self.sample(name)
        hv = FakeHypervisor()
        agent = FakeGuestAgent(self.work, hv, ready=False, done=False)
        result = self.sweep(hypervisor=hv, agent=agent,
                            abort_after_consecutive_void=2)
        self.assertEqual("aborted", result.state)
        self.assertEqual(2, hv.runs)

        rows = self.rows_by_name(self.manifest())
        self.assertEqual(ATTEMPTED, rows["a.exe"]["state"])
        self.assertEqual(ATTEMPTED, rows["b.exe"]["state"])
        for name in ("c.exe", "d.exe"):
            self.assertEqual(NOT_ATTEMPTED, rows[name]["state"])
            self.assertIn("consecutive void", rows[name]["reason"])

    def test_a_good_run_resets_the_consecutive_count(self) -> None:
        # Otherwise a sweep with a scattering of unlucky samples aborts
        # halfway through a corpus that was fine.
        for name in ("a.exe", "b.exe", "c.exe"):
            self.sample(name)
        hv = FakeHypervisor()

        class Alternating(FakeGuestAgent):
            def sleep(self, seconds):
                if self.hypervisor.runs in (1, 3):
                    return
                super().sleep(seconds)

        result = self.sweep(hypervisor=hv, agent=Alternating(self.work, hv),
                            abort_after_consecutive_void=2)
        self.assertEqual("completed", result.state)
        self.assertEqual(3, hv.runs)


class TheDryRun(SweepFixture):
    def test_it_writes_a_full_manifest_and_never_touches_the_hypervisor(self) -> None:
        # This is how you check a corpus directory before committing a machine
        # to it for eight hours -- on a host with no VirtualBox at all, which
        # is where a corpus is usually assembled.
        self.sample("a.exe")
        self.sample("thing.exe")
        self.sample("thing.dll")
        result = sweep(self.corpus, self.guest, None, self.exchange, self.out,
                       run_id="sweep-test", dry_run=True)
        self.assertEqual("dry_run", result.state)

        document = self.manifest()
        self.assertEqual("dry_run", document["state"])
        self.assertTrue(document["policy"]["dry_run"])
        rows = self.rows_by_name(document)
        self.assertEqual(NOT_ATTEMPTED, rows["a.exe"]["state"])
        self.assertIsNotNone(rows["a.exe"]["sha256"])
        self.assertEqual(SKIPPED, rows["thing.exe"]["state"])
        self.assertEqual(SKIPPED, rows["thing.dll"]["state"])

    def test_it_reports_its_findings_through_the_command_line(self) -> None:
        self.sample("a.exe")
        code = main([str(self.corpus), "--vm", "RingForge-Analysis",
                     "--baseline", "corpus-baseline",
                     "--exchange", str(self.exchange),
                     "--out", str(self.out), "--run-id", "sweep-test",
                     "--dry-run"])
        self.assertEqual(0, code)
        self.assertEqual("dry_run", self.manifest()["state"])

    def test_the_real_hypervisor_is_constructed_destructive(self) -> None:
        # `VirtualBox` is read-only by default -- correct for a class that can
        # discard a guest. But a sweep restores a snapshot as its first act,
        # so a read-only one refuses every sample and the manifest fills with
        # `failed` rows blaming the hypervisor. This shipped broken and no
        # host-side test could see it: they all drive a fake, and `--dry-run`
        # never constructs the real one.
        import runcontrol.hypervisor as hypervisor_module

        with mock.patch.object(hypervisor_module, "VirtualBox") as ctor:
            ctor.side_effect = hypervisor_module.HypervisorError("no vbox")
            main([str(self.corpus), "--vm", "RingForge-Analysis",
                  "--baseline", "corpus-baseline",
                  "--exchange", str(self.exchange), "--out", str(self.out)])
        ctor.assert_called_once_with(destructive=True)

    def test_a_guest_that_cannot_be_described_is_a_usage_error(self) -> None:
        # Not a sweep that starts and fails on the first restore.
        code = main([str(self.corpus), "--vm", "RingForge-Analysis",
                     "--baseline", "", "--exchange", str(self.exchange),
                     "--out", str(self.out), "--dry-run"])
        self.assertEqual(2, code)


class TheFileItself(SweepFixture):
    def test_the_manifest_has_no_carriage_returns(self) -> None:
        # `write_text` rewrites `\n` to `\r\n` on Windows, and a record whose
        # bytes depend on which machine wrote it is a diff nobody reads. The
        # same trap as `docs/HANDOFF.md`, which is `-text` in `.gitattributes`
        # for this reason.
        self.sample("a.exe")
        self.sweep()
        raw = (self.out / "sweep-test" / MANIFEST_NAME).read_bytes()
        self.assertNotIn(b"\r\n", raw)

    def test_it_is_written_even_when_the_directory_does_not_exist_yet(self) -> None:
        manifest = Manifest(self.tmp / "deep" / "deeper" / MANIFEST_NAME,
                            {"schema": SCHEMA})
        manifest.save()
        self.assertTrue(manifest.path.is_file())


if __name__ == "__main__":
    unittest.main()
