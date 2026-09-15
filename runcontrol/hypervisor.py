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
    def link_connected(self, vm: str, nic: int) -> bool: ...
    def shared_folders(self, vm: str) -> dict[str, str]: ...
    def set_shared_folder(self, vm: str, name: str,
                          host_path: str) -> None: ...
    def additions_runlevel(self, vm: str) -> int: ...
    def logged_in_users(self, vm: str) -> tuple[int, list[str]]: ...


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

    def _require_destructive(self, what: str) -> None:
        """Refuse before doing any work at all.

        `_run` guards the command itself, which is enough when the command is
        the first thing that happens. `set_link` has to read the VM's state to
        choose between `modifyvm` and `controlvm`, so without this a read-only
        caller would get a state-read failure instead of a refusal -- the wrong
        error, and one that hides the guard.
        """
        if not self.destructive:
            raise NotPermitted(
                f"refusing to {what}: this VirtualBox was constructed "
                f"read-only. Pass destructive=True to allow it."
            )

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

    #: States in which a VM has no running session to talk to.
    _STOPPED = frozenset({"poweroff", "saved", "aborted", "aborted-saved"})

    def set_link(self, vm: str, nic: int, connected: bool) -> None:
        """Connect or cut a NIC's virtual cable, from the host.

        The host side is the point. An adapter disabled inside the guest can be
        re-enabled by anything running there with administrator rights,
        including the sample.

        **Two different commands, chosen by state, and finding that out cost a
        real run.** `controlvm setlinkstate` talks to a live VM and fails with
        *"Machine is not currently running"* on a stopped one. But the loop
        arms containment *before* boot on purpose -- any gap between starting
        the guest and cutting its cable is a window where the sample is live
        and online -- so the call that matters most is the one `controlvm`
        cannot serve. `modifyvm --cableconnected` writes the setting into the
        machine config instead, where it persists into the boot.

        The `FakeHypervisor` in the tests could not have found this: it records
        calls rather than running them. It took restoring a real snapshot and
        watching the cable come back *on*, because `corpus-baseline-capa` was
        saved connected.
        """
        self._require_destructive(
            f"change the cable on {vm!r} nic{nic}")
        state = self.state(vm)
        if state in self._STOPPED:
            self._run(["modifyvm", vm,
                       f"--cableconnected{nic}", "on" if connected else "off"],
                      changes_guest=True)
        else:
            self._run(["controlvm", vm, f"setlinkstate{nic}",
                       "on" if connected else "off"],
                      changes_guest=True)

    def link_connected(self, vm: str, nic: int) -> bool:
        """Whether a NIC's cable is currently attached.

        Containment is verified rather than assumed: a restore brings back
        whatever cable state the snapshot was saved with, and a snapshot saved
        online silently un-arms a sweep.
        """
        out = self._run(["showvminfo", vm, "--machinereadable"],
                        changes_guest=False)
        match = re.search(rf'^cableconnected{nic}="([^"]+)"', out, re.M)
        if not match:
            raise HypervisorError(
                f"could not read the cable state of {vm!r} nic{nic}")
        return match.group(1) == "on"

    def shared_folders(self, vm: str) -> dict[str, str]:
        """Share name -> host path, as the machine config holds it.

        Read as well as written because a restore brings back whatever the
        snapshot was saved with, and a snapshot carrying a stale exchange
        points the guest at last month's directory while everything else
        about the run looks right.
        """
        out = self._run(["showvminfo", vm, "--machinereadable"],
                        changes_guest=False)
        names = dict(re.findall(
            r'^SharedFolderNameMachineMapping(\d+)="([^"]*)"', out, re.M))
        paths = dict(re.findall(
            r'^SharedFolderPathMachineMapping(\d+)="([^"]*)"', out, re.M))
        # VBoxManage escapes backslashes in this output; the config holds one.
        return {names[i]: paths.get(i, "").replace("\\\\", "\\")
                for i in names}

    #: What `GuestAdditionsRunLevel` means -- and **it does not mean what an
    #: earlier version of this file claimed.** That version read 2 at a
    #: sign-in screen and 3 in an interactive session, generalised from those
    #: two observations, and was wrong: measured 15 Sep, an *autologon*
    #: desktop session with the agent already running also reports **2**.
    #: Runlevel 3 appears to track VBoxTray, which an autologon session does
    #: not necessarily start, rather than tracking whether anybody is logged
    #: on.
    #:
    #: So this is colour, never the answer. `logged_in_users` is the answer.
    #: Kept because the distinction between 0 and everything else is still
    #: worth reporting: 0 means Guest Additions are not running, and then no
    #: guest-side fact is readable at all.
    RUNLEVEL = {
        0: "Guest Additions not running",
        1: "Guest Additions system services only",
        2: "Guest Additions userland up",
        3: "Guest Additions desktop services up",
    }

    def additions_runlevel(self, vm: str) -> int:
        """How far the guest got, from the host, with no guest cooperation.

        **This exists because a void run destroyed its own evidence.** The
        agent writes a guest-local log for exactly the case where it cannot
        reach the exchange -- and the loop's closing restore reverts the disk,
        taking the log with it. Worse, the failure measured 15 Sep was the
        agent never running *at all*: autologon pointed at a deleted account,
        the guest sat at the sign-in screen, and nothing inside it could
        report that because nothing inside it ran.

        The runlevel is readable from the host while the guest is still up,
        and it separates the two failures that otherwise look identical in a
        manifest: no session (autologon or the trigger) from a session that
        came up and produced no signal (the agent). Over 102 samples that is
        the difference between a diagnosable sweep and a column of `void`.

        Returns -1 when it cannot be read, rather than raising: this is
        diagnosis, and a diagnostic that can fail the run it is explaining is
        worse than no diagnostic.
        """
        try:
            out = self._run(["showvminfo", vm, "--machinereadable"],
                            changes_guest=False)
        except HypervisorError:
            return -1
        match = re.search(r"^GuestAdditionsRunLevel=(\d+)", out, re.M)
        return int(match.group(1)) if match else -1

    def describe_runlevel(self, level: int) -> str:
        return self.RUNLEVEL.get(level, f"unknown runlevel {level}")

    def logged_in_users(self, vm: str) -> tuple[int, list[str]]:
        """Who is logged on, from the host, as the guest itself reports it.

        **This replaces a wrong answer.** The first version of the void-run
        diagnostic used `GuestAdditionsRunLevel`, on the strength of reading
        2 at a sign-in screen and 3 in an interactive session. An autologon
        session then read 2 as well, with the desktop up and the agent
        running -- so the diagnostic would have said "nobody logged on, check
        autologon" about a guest that had logged on fine. A confidently wrong
        diagnostic is worse than none, which is the standard this check was
        written to, so it was replaced rather than patched.

        `/VirtualBox/GuestInfo/OS/LoggedInUsers` is what the Additions
        actually maintain for this: measured `1` and `adam` in the session
        that fooled the runlevel.

        Returns `(-1, [])` when it cannot be read -- either the Additions are
        not running or the property has never been set -- so a caller can
        tell "nobody is logged on" from "the guest is not answering".
        """
        try:
            count = self._guest_property(
                vm, "/VirtualBox/GuestInfo/OS/LoggedInUsers")
            names = self._guest_property(
                vm, "/VirtualBox/GuestInfo/OS/LoggedInUsersList")
        except HypervisorError:
            return -1, []
        if count is None:
            return -1, []
        try:
            total = int(count)
        except ValueError:
            return -1, []
        listed = [n for n in (names or "").split(",") if n.strip()]
        return total, listed

    def _guest_property(self, vm: str, key: str) -> str | None:
        """One guest property, or None when it has no value.

        `guestproperty get` prints `Value: <x>` or `No value set!`, and exits
        0 for both -- so the absence has to be parsed rather than detected
        from the return code.
        """
        out = self._run(["guestproperty", "get", vm, key],
                        changes_guest=False)
        match = re.search(r"^Value:\s*(.*)$", out.strip(), re.M)
        return match.group(1).strip() if match else None

    def set_shared_folder(self, vm: str, name: str, host_path: str) -> None:
        """Point `name` at `host_path`, replacing whatever it pointed at.

        **The exchange is snapshot state, which is the whole reason this
        exists.** Measured on this bench rather than assumed: a shared folder
        added to the machine config and then followed by
        `snapshot restore` is *gone* -- the restore brings back the
        snapshot's settings wholesale, exactly as it brings back the NIC cable
        that `set_link` has to re-arm every run. A controller that configured
        the exchange once at setup would have it silently reverted by its own
        first step, and the guest would look for a delivery in whichever
        directory the baseline was taken with.

        So the loop sets this after the restore and before the boot, and the
        exchange becomes controller configuration rather than something baked
        into a snapshot. That removes the failure where a perfectly good
        baseline carries the wrong path.

        Persistent rather than `--transient`, because it is applied while the
        guest is stopped -- transient shares need a running VM, and the point
        is to have the share present *at* boot so auto-mount happens before
        the agent's scheduled task looks for it.

        Idempotent: a share already pointing where it should is left alone,
        so a sweep does not rewrite the machine config once per sample.
        """
        self._require_destructive(
            f"repoint the shared folder {name!r} on {vm!r}")
        host_path = str(host_path)
        existing = self.shared_folders(vm)
        if existing.get(name) == host_path:
            return
        if name in existing:
            self._run(["sharedfolder", "remove", vm, "--name", name],
                      changes_guest=True)
        self._run(["sharedfolder", "add", vm, "--name", name,
                   "--hostpath", host_path, "--automount"],
                  changes_guest=True)
