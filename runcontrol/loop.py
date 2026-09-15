"""One sample, start to finish, with the ordering as the point.

The steps are not interesting. The *order* is, and every constraint below was
paid for somewhere else in this project:

    1. restore the named baseline      guest inert, known state
    2. cut the internet, from the host
    3. point the guest's share at the exchange
    4. deliver the sample
    5. start the guest
    6. wait for it to signal collection is up
    7. wait for it to signal the run is done
    8. power off -- not "request shutdown"
    9. collect, from a guest that is off
   10. restore the baseline again

**The share is repointed every run (3), not configured once.** A snapshot
restore brings back the snapshot's shared folders wholesale -- measured on
this bench by adding one and watching a restore delete it -- so an exchange
configured at setup is reverted by the loop's own first step, and the guest
then looks for its delivery in whichever directory the baseline happened to be
taken with. Same class of fact as the cable, handled the same way.

**Containment before boot (2 before 5).** `vm_net.ps1` runs on the host
because an adapter disabled inside the guest can be re-enabled by anything
there with administrator rights, including the sample. In a loop, any gap
between boot and arming is a window where the sample is live and online.

**Power off before collect (8 before 9).** Not a shutdown request: a sample can
refuse to shut down, and a controller that waits for a clean one hangs on
exactly the samples worth analysing. Reading artifacts from an inert guest is
what removes the race against one rewriting them mid-read.

**Restore after, as well as before (10 as well as 1).** A controller that only
reverts on the way out leaves a dirty guest when it crashes, and the next run
inherits it. Both, so a crash costs one sample rather than the sweep.

**Readiness is separate from the run (6 before 7), and its absence is a void
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

import shutil

from runcontrol.collect import Collected, Limits, collect_case
from runcontrol.guest import Guest

#: The one subdirectory inside the exchange that the controller owns.
#:
#: **Never the exchange root.** On this bench the share the guest can see is
#: `C:/Users/aring/Downloads/ringforge`, which holds 4.8 GB across 12,172 files
#: of accumulated working history -- samples, scripts, results, months of runs.
#: Collecting the root would import all of it for every sample, and the default
#: caps (20,000 files, 24 GB) are loose enough that it would do so silently.
#:
#: A fixed name rather than a per-run one, so the guest agent watches one path
#: and cannot mistake a stale run for a new one: it is cleared before delivery.
RUN_DIR = "current"

#: Hypervisor states in which a guest has no running session.
#:
#: Mirrors `VirtualBox._STOPPED`, kept here rather than imported so the loop
#: does not depend on a particular hypervisor for a fact about its own
#: sequencing.
STOPPED = frozenset({"poweroff", "saved", "aborted", "aborted-saved"})


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


def prepare_work(exchange: Path) -> Path:
    """Clear and recreate the controller's working directory in the exchange.

    Cleared rather than reused, because a stale artifact from the previous
    sample imported into this one's case is indistinguishable from evidence.

    `shutil.rmtree` is safe against a junction planted by a sample on Python
    3.12 -- measured, not assumed: a junction inside the tree is removed as a
    link and its target survives. The project requires >=3.12, and
    `test_a_junction_in_the_work_directory_is_not_followed` pins it, because
    the alternative on an older runtime is deleting through it into whatever
    the sample chose to point at.
    """
    exchange = Path(exchange)
    work = exchange / RUN_DIR
    if work.resolve() == exchange.resolve():
        raise ValueError(
            f"the working directory resolved to the exchange root "
            f"({exchange}); refusing, because collecting the root would import "
            f"everything the share holds"
        )
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    return work


def ensure_stopped(hypervisor, vm: str, sleep=time.sleep,
                   timeout: float = 60.0) -> None:
    """Leave `vm` powered off, whatever state it was in.

    **VirtualBox refuses to restore over a running machine** -- *"Cannot
    delete the current state of the running machine"* -- and the loop's first
    act is a restore. In a sweep the previous iteration's `finally` already
    left the guest off, so this only bites on the *first* run after somebody
    used the VM by hand. Which is exactly when a controller failing is least
    expected and least welcome.

    Polls rather than assuming the power-off took effect: `controlvm poweroff`
    returns before the session has finished tearing down.
    """
    if hypervisor.state(vm) in STOPPED:
        return
    hypervisor.power_off(vm)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if hypervisor.state(vm) in STOPPED:
            return
        sleep(1.0)
    raise RuntimeError(
        f"{vm!r} did not stop within {timeout:.0f}s; it is "
        f"{hypervisor.state(vm)!r} and a restore would be refused"
    )


def start_with_retry(hypervisor, vm: str, *, attempts: int = 3,
                     sleep=time.sleep, delay: float = 5.0) -> int:
    """Boot the guest, retrying a launch that lost a race with teardown.

    **Measured 15 Sep, on the first try of a manual boot.** `VBoxManage
    startvm` immediately after a power-off failed inside `LaunchVMProcess`,
    and the identical command succeeded seconds later: the previous session
    had not finished releasing the machine. The loop powers off, restores and
    starts within about a second, so it sits squarely in that window.

    It is intermittent, which is exactly why it needs handling rather than
    watching. Over a hundred unattended samples an occasional launch failure
    is a `failed` row -- a void, blamed on the hypervisor, in a corpus nobody
    is sitting in front of.

    Retries only the launch. Anything still failing after `attempts` is a
    real failure and propagates, because a guest that will not boot at all is
    not something to paper over. Returns which attempt worked, so the caller
    can record that it took more than one.
    """
    last: Exception | None = None
    for attempt in range(1, max(1, attempts) + 1):
        try:
            hypervisor.start(vm, headless=True)
            return attempt
        except Exception as error:                   # noqa: BLE001
            last = error
            if attempt < attempts:
                sleep(delay)
    raise RuntimeError(
        f"{vm!r} would not start after {attempts} attempts: {last}")


def _why_no_readiness(hypervisor, vm: str) -> str:
    """Which half of the transport failed, asked of the hypervisor.

    Two questions, in order of authority. **Is anybody logged on** --
    `/VirtualBox/GuestInfo/OS/LoggedInUsers`, which the Additions maintain
    for exactly this -- decides between the logon and the agent. The
    Additions runlevel is reported alongside as colour only: it was tried as
    the primary signal on 15 Sep and got this wrong, reading the same 2 for a
    sign-in screen and for an autologon desktop with the agent running.

    Best effort and deliberately non-fatal: this runs inside the error path
    of a run that has already gone wrong, so anything unexpected comes back
    as "could not tell".
    """
    try:
        count, names = hypervisor.logged_in_users(vm)
    except Exception:                                # noqa: BLE001
        return "The guest's logon state could not be read."

    level = -1
    try:
        level = hypervisor.additions_runlevel(vm)
    except Exception:                                # noqa: BLE001
        pass

    if level == 0:
        return (
            "Guest Additions are not running in the guest, so nothing about "
            "its state is readable and the share it needs may never have "
            "mounted. That is a guest build problem, not a run problem."
        )

    if count < 0:
        return (
            "The guest did not report its logon state. Guest Additions may "
            "be too old or still starting; treat this run as undiagnosed "
            "rather than as either failure."
        )

    if count == 0:
        return (
            "Nobody is logged on to the guest, so a logon-triggered agent "
            "cannot have fired. Check autologon -- DefaultUserName, and "
            "whether the account it names still exists."
        )

    who = ", ".join(names) if names else f"{count} user(s)"
    return (
        f"The guest is logged on as {who}, so the logon worked and this is "
        f"the agent: check the scheduled task is registered against that "
        f"account, that it can see the exchange, and read "
        f"C:/ProgramData/RingForge/agent.log in the guest before the next "
        f"restore discards it."
    )


def run_one(sample: Path, guest: Guest, hypervisor, exchange: Path,
            case_root: Path, *, limits: Limits | None = None,
            signals_override: Signals | None = None,
            sleep=time.sleep) -> RunReport:
    """Detonate one sample and bring its case folder home.

    `exchange` is the directory both sides can see. The controller works only
    in `exchange/current`, which it recreates each run -- see `RUN_DIR`.
    `case_root` is on the host and receives the imported case.

    Never raises for a run that went wrong: a sweep needs a report per sample,
    and an exception would lose the ones already done.
    """
    sample = Path(sample)
    exchange = Path(exchange)
    case = sample.stem
    report = RunReport(sample=sample, case=case, outcome=Outcome.FAILED)
    started = time.monotonic()

    try:
        # 1. A known starting point, named explicitly -- and off first, because
        #    VirtualBox will not restore over a running machine.
        ensure_stopped(hypervisor, guest.vm, sleep=sleep)
        report.note("stop", started)
        hypervisor.restore(guest.vm, guest.baseline)
        report.note("restore", started, guest.baseline)

        # 2. Containment, from the host, BEFORE the guest can run anything.
        hypervisor.set_link(guest.vm, guest.internet_nic, False)
        report.note("contain", started, f"nic{guest.internet_nic} off")

        # 3. The guest's view of the exchange, re-established after the
        #    restore wiped it. Before the boot, so auto-mount has happened by
        #    the time the agent's task looks for the share.
        if guest.share_name:
            hypervisor.set_shared_folder(guest.vm, guest.share_name, exchange)
            report.note("share", started,
                        f"{guest.share_name} -> {exchange}")

        # 4. Delivery, into the controller's own subdirectory of the exchange.
        #    Recreated from empty, which clears any stale `done` signal: one
        #    left over from the previous sample would make this run look
        #    finished before it began, and present as a fast, quiet sample
        #    rather than as a controller bug.
        work = prepare_work(exchange)
        signals = signals_override or Signals(work)
        signals.clear()
        delivered = work / sample.name
        delivered.write_bytes(sample.read_bytes())
        report.note("deliver", started, delivered.name)

        # 5. Boot, retrying a launch that raced the previous teardown.
        tries = start_with_retry(hypervisor, guest.vm, sleep=sleep)
        report.note("start", started,
                    "" if tries == 1 else f"took {tries} attempts")

        # 6. Readiness. Its absence is a void run, not a quiet sample.
        if not signals.wait_for(signals.ready, guest.readiness_timeout,
                                sleep=sleep):
            report.outcome = Outcome.NO_READINESS
            # Asked *before* the guest is powered off, because it is the only
            # thing that separates "nobody ever logged on" from "a session
            # came up and the agent said nothing" -- and the closing restore
            # discards the guest's own log, so nothing inside it survives to
            # tell us. Measured 15 Sep: autologon pointed at a deleted
            # account, the guest sat at the sign-in screen at runlevel 2, and
            # the manifest said only `void`.
            report.error = (
                f"collection never signalled ready within "
                f"{guest.readiness_timeout:.0f}s. Nothing was observed, so this "
                f"is a void run rather than a quiet sample. "
                f"{_why_no_readiness(hypervisor, guest.vm)}"
            )
            report.note("readiness", started, "TIMED OUT")
            return report
        report.note("readiness", started)

        # 7. The run itself.
        finished = signals.wait_for(signals.done, guest.run_timeout, sleep=sleep)
        report.note("run", started, "finished" if finished else "TIMED OUT")

        # 8. Off, not shutdown. A sample can refuse to shut down.
        hypervisor.power_off(guest.vm)
        report.note("power_off", started)

        # 9. Collect, from a guest that is off.
        destination = Path(case_root) / case
        report.collected = collect_case(work, destination, limits)
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
        # 10. Leave the guest at the baseline whatever happened, so a crash
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
