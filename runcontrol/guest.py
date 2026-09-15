"""Which guest, which snapshot, which cable — as data rather than as globals.

**This exists so that parallel is a later config change and not a rewrite.**
The controller loops with a pool size of one, because serial is the right first
answer: two guests on one host-only adapter can see each other, so a sample
that scans its subnet finds the other analysis VM and its traffic lands in the
other run's capture attributed to the wrong sample. That is a corpus
correctness problem, not a nuisance. But nothing in the loop should *assume*
one guest, so everything a run needs to know about its guest arrives in one of
these.

The fields that are not obvious:

* `baseline` is named, never inferred. This bench's snapshot tree records what
  restoring the wrong one costs -- a parent carrying `Start=0` boot-logs on
  every restore, writes ~4 GB and blocks the capture -- and a sweep would pay
  it once per sample.
* `internet_nic` is the adapter cut *from the host* before the guest boots. An
  adapter disabled inside the guest can be re-enabled by anything running
  there with administrator rights, including the sample.
* `readiness_timeout` is separate from `run_timeout` because a guest that never
  signals collection-is-up is a **void run**, not a quiet sample.
  `logon_capture.py` measured an `ONSTART` task starting 3m51s after the
  sample's `ONLOGON` payload: Task Scheduler throttles boot-triggered tasks, so
  booted is not started and the two failures must be distinguishable.
"""

from __future__ import annotations

from dataclasses import dataclass


class GuestError(ValueError):
    """A guest descriptor that cannot be used."""


@dataclass(frozen=True)
class Guest:
    """One analysis guest, fully specified."""

    #: As the hypervisor knows it.
    vm: str

    #: The snapshot every run starts from. Required, and checked against the
    #: hypervisor before a sweep begins rather than on first restore.
    baseline: str

    #: NIC carrying the internet, cut from the host before boot. VirtualBox
    #: numbers adapters from 1.
    internet_nic: int = 1

    #: NIC on the host-only network, used to reach the guest. Left connected.
    hostonly_nic: int = 2

    #: The shared folder the guest sees the exchange through, by name. The
    #: controller repoints it at the exchange **after every restore**, because
    #: a restore brings the snapshot's shared folders back wholesale -- the
    #: same reason the cable has to be re-cut. Measured, not assumed: a share
    #: added to the machine config and then restored over is gone.
    #:
    #: The default names the share `guest_run_agent.ps1` discovers -- the
    #: one called `ringforge`, which the agent reaches as a UNC path under
    #: the VBOXSVR pseudo-host -- so moving the exchange on the *host*
    #: needs no change inside the guest. That matters: there is no
    #: remote-execution route into this VM by design, so every guest-side
    #: change costs a trip to the console.
    #:
    #: Empty opts out, leaving whatever the baseline carries.
    share_name: str = "ringforge"

    #: Seconds to wait for the guest to signal that collection is up. Generous
    #: on purpose: boot-triggered tasks are throttled, and the alternative to
    #: waiting is recording a void run.
    readiness_timeout: float = 600.0

    #: Seconds to wait for the run itself once collection is up.
    run_timeout: float = 1800.0

    def __post_init__(self) -> None:
        if not self.vm.strip():
            raise GuestError("a guest needs a VM name")
        if not self.baseline.strip():
            raise GuestError(
                f"{self.vm}: a baseline snapshot must be named. There is no "
                f"'restore current' -- restoring the wrong snapshot on this "
                f"bench costs a 4 GB boot log per sample."
            )
        for label, nic in (("internet_nic", self.internet_nic),
                           ("hostonly_nic", self.hostonly_nic)):
            if not 1 <= nic <= 8:
                raise GuestError(
                    f"{self.vm}: {label}={nic} is not a VirtualBox adapter "
                    f"number; they run 1 to 8"
                )
        if any(ch in self.share_name for ch in "/:" + chr(92)):
            raise GuestError(
                f"{self.vm}: share_name={self.share_name!r} is a name, not a "
                f"path -- it is the share name the guest sees under "
                f"the VBOXSVR pseudo-host, not a location on the host"
            )
        if self.internet_nic == self.hostonly_nic:
            raise GuestError(
                f"{self.vm}: internet_nic and hostonly_nic are both "
                f"{self.internet_nic}. Cutting the internet would cut the only "
                f"route to the guest, and containment would look armed while "
                f"the run became unreachable."
            )
        for label, value in (("readiness_timeout", self.readiness_timeout),
                             ("run_timeout", self.run_timeout)):
            if value <= 0:
                raise GuestError(f"{self.vm}: {label} must be positive")


def check_ready(guest: Guest, hypervisor) -> list[str]:
    """Problems that would stop a sweep, found before it starts.

    Returns the problems rather than raising, so a caller can report all of
    them at once. A sweep that dies on the second guest after twenty minutes of
    the first is worse than one that refuses to start.
    """
    problems: list[str] = []

    try:
        vms = hypervisor.vms()
    except Exception as error:
        return [f"cannot reach the hypervisor: {error}"]

    if guest.vm not in vms:
        problems.append(
            f"{guest.vm!r} is not registered. Known: "
            f"{', '.join(sorted(vms)) or 'none'}"
        )
        return problems

    try:
        names = {s.name for s in hypervisor.snapshots(guest.vm)}
    except Exception as error:
        problems.append(f"cannot list snapshots of {guest.vm!r}: {error}")
        return problems

    if guest.baseline not in names:
        problems.append(
            f"{guest.vm!r} has no snapshot {guest.baseline!r}. Known: "
            f"{', '.join(sorted(names)) or 'none'}"
        )

    try:
        state = hypervisor.state(guest.vm)
    except Exception as error:
        problems.append(f"cannot read the state of {guest.vm!r}: {error}")
        return problems

    if state != "poweroff":
        # Not fatal in principle -- the controller powers off before restoring
        # anyway -- but a guest that is running is a guest somebody may be
        # using, and a sweep is about to discard its state.
        problems.append(
            f"{guest.vm!r} is {state!r}, not 'poweroff'. A sweep restores the "
            f"baseline and would discard whatever is in it."
        )

    return problems
