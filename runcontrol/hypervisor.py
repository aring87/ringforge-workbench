"""Driving a guest from the host, with the destructive parts held shut.

**Two rules shape this file.**

*One.* Every operation that changes a guest -- restoring a snapshot, starting
it, cutting its network -- is refused unless the caller has explicitly asked
for a hypervisor that may do so. Reverting a snapshot discards whatever state
the guest is in, and this package will eventually be driven by a loop over a
sample directory. A dry run, a unit test or a mistyped VM name must not be able
to throw away a guest somebody was using. `VirtualBox(destructive=False)` can
read and cannot touch.

*Two.* A snapshot is named explicitly or not at all. There is no "restore
current". The snapshot tree on this bench records why:

    the parent snapshot carries Start=0, so every restore of it boot-logs
    once, writes ~4 GB and blocks the capture

A controller that restored the wrong snapshot would hit that on every sample in
a sweep, and the failure would look like collection timing out rather than like
the wrong starting point.

**Why an interface at all**, when there is one hypervisor and one VM: because
the alternative is `VBoxManage` spelled into the loop, and then Hyper-V is a
rewrite rather than a class. `Hypervisor` is the seam. `FakeHypervisor` in the
tests is the other implementation, which is what keeps the seam honest.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, Sequence

from static_triage_engine.proc import run_bounded

#: Where VirtualBox installs, mirroring the search in `scripts/vm_snapshot.ps1`
#: so the host-side Python and the host-side PowerShell agree about the tool
#: they are both driving.
_VBOX_CANDIDATES = (
    Path(r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"),
    Path(r"C:\Program Files (x86)\Oracle\VirtualBox\VBoxManage.exe"),
)


class HypervisorError(RuntimeError):
    """A hypervisor command failed, or was refused."""


class NotPermitted(HypervisorError):
    """A destructive operation was attempted on a read-only hypervisor.

    Its own class because a test asserting that the guard holds should not pass
    on an unrelated failure.
    """


@dataclass(frozen=True)
class Snapshot:
    name: str
    uuid: str


class Hypervisor(Protocol):
    """What the controller needs of a hypervisor, and nothing more.

    Deliberately small. Anything that belongs to *this* project -- which
    snapshot is the corpus baseline, how long to wait for readiness -- lives in
    the guest descriptor, not here, so a second implementation has a short list
    to satisfy.
    """

    def vms(self) -> dict[str, str]: ...
    def state(self, vm: str) -> str: ...
    def snapshots(self, vm: str) -> list[Snapshot]: ...
    def restore(self, vm: str, snapshot: str) -> None: ...
    def start(self, vm: str, headless: bool = True) -> None: ...
    def power_off(self, vm: str) -> None: ...
    def set_link(self, vm: str, nic: int, connected: bool) -> None: ...


@dataclass
class VirtualBox:
    """VirtualBox via `VBoxManage`.

    `destructive` defaults to False. Read-only use needs no argument; a caller
    that means to change a guest has to say so at construction, where it is
    visible in a review, rather than at the call site where it reads like any
    other method.
    """

    destructive: bool = False
    manage: Path | None = None
    timeout: float = 120.0
    #: Every command run, for the record a sweep has to be able to produce.
    log: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.manage = Path(self.manage) if self.manage else self._find_manage()

    @staticmethod
    def _find_manage() -> Path:
        found = shutil.which("VBoxManage")
        if found:
            return Path(found)
        for candidate in _VBOX_CANDIDATES:
            if candidate.is_file():
                return candidate
        raise HypervisorError(
            "VBoxManage.exe not found. Pass manage= explicitly, or install "
            "VirtualBox. The base package is enough -- the Extension Pack is "
            "not needed here, and is not free for commercial use."
        )

    # -- running commands ---------------------------------------------------

    def _run(self, args: Sequence[str], *, changes_guest: bool) -> str:
        if changes_guest and not self.destructive:
            raise NotPermitted(
                f"refusing to run {' '.join(args)!r}: this VirtualBox was "
                f"constructed read-only. Pass destructive=True to allow it."
            )
        command = [str(self.manage), *args]
        self.log.append(" ".join(args))
        # `run_bounded` rather than `subprocess.run`: it kills the whole tree
        # before draining, and it already suppresses the console window, so a
        # sweep driven from the GUI does not flash one per VBoxManage call.
        result = run_bounded(command, timeout=self.timeout)
        if result.get("returncode") != 0:
            raise HypervisorError(
                f"VBoxManage {' '.join(args)} failed "
                f"({result.get('returncode')}): "
                f"{(result.get('stderr') or '').strip()[:400]}"
            )
        return result.get("stdout") or ""

    # -- reading ------------------------------------------------------------

    def vms(self) -> dict[str, str]:
        """Registered VMs, name -> uuid.

        A VM name may contain a newline -- there is one on this bench -- so the
        name is taken from the quoted group rather than from the line.
        """
        out = self._run(["list", "vms"], changes_guest=False)
        found: dict[str, str] = {}
        for name, uuid in re.findall(r'"(.*?)"\s+\{([0-9a-fA-F-]+)\}', out, re.S):
            found[name.strip()] = uuid
        return found

    def state(self, vm: str) -> str:
        out = self._run(["showvminfo", vm, "--machinereadable"],
                        changes_guest=False)
        match = re.search(r'^VMState="([^"]+)"', out, re.M)
        if not match:
            raise HypervisorError(f"could not read the state of {vm!r}")
        return match.group(1)

    def snapshots(self, vm: str) -> list[Snapshot]:
        """Every snapshot, flattened. Order is VirtualBox's, depth-first.

        The tree shape is not returned on purpose: the controller pins one
        snapshot by name and has no business inferring a baseline from the
        topology. Which one is the baseline is a decision, recorded in the
        guest descriptor.
        """
        try:
            out = self._run(["snapshot", vm, "list", "--machinereadable"],
                            changes_guest=False)
        except HypervisorError as error:
            if "does not have any snapshots" in str(error).lower():
                return []
            raise
        # `--machinereadable` emits parallel SnapshotName-*/SnapshotUUID-* keys;
        # pair them by their suffix rather than by position, because a nested
        # tree does not interleave them in a fixed order.
        by_suffix: dict[str, dict[str, str]] = {}
        for key, value in re.findall(r'^(Snapshot\w+(?:-\d+)*)="([^"]*)"', out, re.M):
            kind, _, suffix = key.partition("-")
            slot = by_suffix.setdefault(suffix, {})
            slot[kind] = value
        result = []
        for suffix in sorted(by_suffix, key=lambda s: [int(p) for p in s.split("-") if p.isdigit()] or [0]):
            slot = by_suffix[suffix]
            if "SnapshotName" in slot and "SnapshotUUID" in slot:
                result.append(Snapshot(slot["SnapshotName"], slot["SnapshotUUID"]))
        return result

    def has_snapshot(self, vm: str, snapshot: str) -> bool:
        return any(s.name == snapshot or s.uuid == snapshot
                   for s in self.snapshots(vm))

    # -- changing -----------------------------------------------------------

    def restore(self, vm: str, snapshot: str) -> None:
        """Restore a named snapshot. **Discards the guest's current state.**

        Named, never `restorecurrent`: see the module docstring for the 4 GB
        boot-log this avoids.
        """
        if not snapshot:
            raise HypervisorError(
                "restore needs a snapshot name; there is deliberately no "
                "'restore current' here"
            )
        self._run(["snapshot", vm, "restore", snapshot], changes_guest=True)

    def start(self, vm: str, headless: bool = True) -> None:
        self._run(["startvm", vm, "--type", "headless" if headless else "gui"],
                  changes_guest=True)

    def power_off(self, vm: str) -> None:
        """Pull the plug. Not a shutdown request.

        A sample can refuse to shut down, and a controller that waits for a
        clean one hangs on exactly the samples worth analysing. Artifacts are
        read after this returns, which is what removes the race against a live
        guest rewriting them mid-read.
        """
        self._run(["controlvm", vm, "poweroff"], changes_guest=True)

    def set_link(self, vm: str, nic: int, connected: bool) -> None:
        """Connect or cut a NIC's virtual cable, from the host.

        The host side is the point. An adapter disabled inside the guest can be
        re-enabled by anything running there with administrator rights,
        including the sample.
        """
        self._run(["controlvm", vm, f"setlinkstate{nic}",
                   "on" if connected else "off"],
                  changes_guest=True)
