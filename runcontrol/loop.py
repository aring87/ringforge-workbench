"""One sample, start to finish, with the ordering as the point.

The steps are not interesting. The *order* is, and every constraint below was
paid for somewhere else in this project:

    1. restore the named baseline      guest inert, known state
    2. cut the internet, from the host
    3. deliver the sample
    4. start the guest
    5. wait for it to signal collection is up
    6. wait for it to signal the run is done
    7. power off -- not "request shutdown"
    8. collect, from a guest that is off
    9. restore the baseline again

**Containment before boot (2 before 4).** `vm_net.ps1` runs on the host
because an adapter disabled inside the guest can be re-enabled by anything
there with administrator rights, including the sample. In a loop, any gap
between boot and arming is a window where the sample is live and online.

**Power off before collect (7 before 8).** Not a shutdown request: a sample can
refuse to shut down, and a controller that waits for a clean one hangs on
exactly the samples worth analysing. Reading artifacts from an inert guest is
what removes the race against one rewriting them mid-read.

**Restore after, as well as before (9 as well as 1).** A controller that only
reverts on the way out leaves a dirty guest when it crashes, and the next run
inherits it. Both, so a crash costs one sample rather than the sweep.

**Readiness is separate from the run (5 before 6), and its absence is a void
run rather than a quiet sample.** `logon_capture.py` measured an `ONSTART`
capture starting 3m51s *after* the sample's `ONLOGON` payload: Task Scheduler
throttles boot-triggered tasks. Booted is not started. A run whose collection
never came up has observed nothing, and that has to band as insufficient
coverage -- the same failure class as a rule set that did not compile, which
this project has already mistaken for a clean scan once.

Nothing here talks to a hypervisor directly. It takes one, so the tests drive a
fake and assert the order.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from runcontrol.collect import Collected, Limits, collect_case
from runcontrol.guest import Guest


class Outcome(str, Enum):
    """How a run ended. `str` so it lands in JSON as its own name."""

    #: Collection came up, the run finished, artifacts were imported.
    COMPLETED = "completed"

    #: The guest never signalled that collection was up. **Observed nothing.**
    NO_READINESS = "no_readiness"

    #: Collection came up; the run did not finish inside its window.
    RUN_TIMEOUT = "run_timeout"

    #: The hypervisor, the delivery or the import failed.
    FAILED = "failed"

    @property
    def void(self) -> bool:
        """Whether this run observed too little to draw a conclusion from.

        A run timeout is *not* void: collection was up and whatever happened
        before the window closed is real evidence. A readiness failure is,
        because nothing was watching.
        """
        return self in (Outcome.NO_READINESS, Outcome.FAILED)


@dataclass
class RunReport:
    """What happened, in enough detail to explain a corpus entry."""

    sample: Path
    case: str
    outcome: Outcome
    #: Every step attempted, in order, as `(step, seconds, note)`. The order is
    #: the contract, so it is recorded rather than inferred from logs.
    steps: list[tuple[str, float, str]] = field(default_factory=list)
    collected: Collected | None = None
    error: str = ""

    @property
    def usable(self) -> bool:
        return self.outcome is Outcome.COMPLETED and self.collected is not None

    def note(self, step: str, started: float, detail: str = "") -> None:
        self.steps.append((step, round(time.monotonic() - started, 2), detail))


class Signals:
    """How the guest says "collection is up" and "the run is done".

    Two files on the delivery share, written by the guest and only ever read by
    the host. Deliberately the dumbest possible channel: no service to install,
    no credentials on the host, nothing listening, and it works identically
    whether the transport is a share or a mounted disk.

    The host never *writes* these, and the guest never reads what the host
    writes except the sample and the run spec. That keeps the direction of
    trust in one line.
    """

    READY = "ringforge-ready"
    DONE = "ringforge-done"

    def __init__(self, exchange: Path) -> None:
        self.exchange = Path(exchange)

    @property
    def ready(self) -> Path:
        return self.exchange / self.READY

    @property
    def done(self) -> Path:
        return self.exchange / self.DONE

    def clear(self) -> None:
        """Remove both, before a run.

        A stale `done` from the previous sample would make the next run look
        finished before it started -- and it would look like a fast, quiet
        sample rather than like a controller bug.
        """
        for path in (self.ready, self.done):
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    def wait_for(self, path: Path, timeout: float,
                 poll: float = 2.0, sleep=time.sleep) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists():
                return True
            sleep(poll)
        return path.exists()


def run_one(sample: Path, guest: Guest, hypervisor, exchange: Path,
            case_root: Path, *, limits: Limits | None = None,
            signals: Signals | None = None, sleep=time.sleep) -> RunReport:
    """Detonate one sample and bring its case folder home.

    `exchange` is the directory both sides can see -- read-only to the guest
    for delivery, and where the guest writes its signals. `case_root` is on the
    host and receives the imported case.

    Never raises for a run that went wrong: a sweep needs a report per sample,
    and an exception would lose the ones already done.
    """
    sample = Path(sample)
    exchange = Path(exchange)
    signals = signals or Signals(exchange)
    case = sample.stem
    report = RunReport(sample=sample, case=case, outcome=Outcome.FAILED)
    started = time.monotonic()

    try:
        # 1. A known starting point, named explicitly.
        hypervisor.restore(guest.vm, guest.baseline)
        report.note("restore", started, guest.baseline)

        # 2. Containment, from the host, BEFORE the guest can run anything.
        hypervisor.set_link(guest.vm, guest.internet_nic, False)
        report.note("contain", started, f"nic{guest.internet_nic} off")

        # 3. Delivery. Signals cleared first so a stale `done` cannot make this
        #    run look finished before it began.
        signals.clear()
        exchange.mkdir(parents=True, exist_ok=True)
        delivered = exchange / sample.name
        delivered.write_bytes(sample.read_bytes())
        report.note("deliver", started, delivered.name)

        # 4. Boot.
        hypervisor.start(guest.vm, headless=True)
        report.note("start", started)

        # 5. Readiness. Its absence is a void run, not a quiet sample.
        if not signals.wait_for(signals.ready, guest.readiness_timeout,
                                sleep=sleep):
            report.outcome = Outcome.NO_READINESS
            report.error = (
                f"collection never signalled ready within "
                f"{guest.readiness_timeout:.0f}s. Nothing was observed, so this "
                f"is a void run rather than a quiet sample."
            )
            report.note("readiness", started, "TIMED OUT")
            return report
        report.note("readiness", started)

        # 6. The run itself.
        finished = signals.wait_for(signals.done, guest.run_timeout, sleep=sleep)
        report.note("run", started, "finished" if finished else "TIMED OUT")

        # 7. Off, not shutdown. A sample can refuse to shut down.
        hypervisor.power_off(guest.vm)
        report.note("power_off", started)

        # 8. Collect, from a guest that is off.
        destination = Path(case_root) / case
        report.collected = collect_case(exchange, destination, limits)
        report.note("collect", started, report.collected.summary())

        # A run that ran out of window still collected real evidence: what
        # happened before the window closed was observed.
        report.outcome = Outcome.COMPLETED if finished else Outcome.RUN_TIMEOUT
        return report

    except Exception as error:                       # noqa: BLE001
        report.outcome = Outcome.FAILED
        report.error = f"{type(error).__name__}: {error}"
        report.note("failed", started, report.error[:120])
        return report

    finally:
        # 9. Leave the guest at the baseline whatever happened, so a crash
        #    costs one sample rather than every sample after it.
        try:
            hypervisor.power_off(guest.vm)
        except Exception:
            pass
        try:
            hypervisor.restore(guest.vm, guest.baseline)
            report.note("restore_after", started, guest.baseline)
        except Exception as error:
            # Worth reporting loudly: the next run starts dirty.
            report.note("restore_after", started, f"FAILED: {error}")
