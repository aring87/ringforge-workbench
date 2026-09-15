"""The destructive guard, the snapshot parser, and the pre-flight.

**These must not need VirtualBox.** A test that only runs where a hypervisor is
installed is a test that does not run in CI, and the suite spent ten days red
because three modules needed an optional extra to be collected. `_run` is
stubbed with recorded `VBoxManage` output instead.

The output fixtures are real: taken from `VBoxManage` 7.1.4 on this bench,
including a VM whose registered name contains a newline, because that is the
kind of thing a parser written against tidy examples gets wrong.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from runcontrol.guest import Guest, GuestError, check_ready
from runcontrol.hypervisor import (
    HypervisorError,
    NotPermitted,
    Snapshot,
    VirtualBox,
)

#: Real `VBoxManage list vms` output. The third entry's name really does
#: contain a newline on this bench.
LIST_VMS = (
    '"Ubuntu" {d19839d4-7669-4ada-87d2-120f315d4ec6}\n'
    '"kali" {9918eb38-aed7-4eab-b972-77001f6569e0}\n'
    '"Wazuh-Server\n" {69da6d81-e3d2-4004-90f5-5368928ed29e}\n'
    '"RingForge-Analysis" {b4be81dd-205b-4d0a-bf2b-43d0969da59a}\n'
)

SNAPSHOT_LIST = (
    'SnapshotName="tooling-baseline-5e1a31c"\n'
    'SnapshotUUID="a82d368b-4a8a-4b39-b70e-48f718c6d4fd"\n'
    'SnapshotName-1="tooling-baseline-preprocmonfix"\n'
    'SnapshotUUID-1="be35853b-5807-4d77-b50b-062842b5817b"\n'
    'SnapshotName-1-1="corpus-baseline"\n'
    'SnapshotUUID-1-1="4eb53047-a351-462d-b200-279edad7757d"\n'
    'SnapshotName-1-1-1="corpus-baseline-capa"\n'
    'SnapshotUUID-1-1-1="a7ac5475-13f0-4e3c-a9b6-c85866626b3b"\n'
)


def _vbox(outputs: dict[str, str] | None = None, **kwargs) -> VirtualBox:
    """A VirtualBox whose `_run` replays fixtures instead of shelling out."""
    vbox = VirtualBox(manage=Path("VBoxManage.exe"), **kwargs)
    outputs = outputs or {}

    real_run = VirtualBox._run

    def fake_run(self, args, *, changes_guest: bool) -> str:
        # Keep the guard: it is the thing most of these tests are about.
        if changes_guest and not self.destructive:
            return real_run(self, args, changes_guest=changes_guest)
        self.log.append(" ".join(args))
        key = args[0] if args else ""
        return outputs.get(key, "")

    vbox._run = fake_run.__get__(vbox, VirtualBox)
    return vbox


class TheDestructiveGuard(unittest.TestCase):
    """Read-only by default, because a restore discards a guest."""

    def test_restore_is_refused_by_default(self) -> None:
        with self.assertRaises(NotPermitted):
            _vbox().restore("RingForge-Analysis", "corpus-baseline")

    def test_start_is_refused_by_default(self) -> None:
        with self.assertRaises(NotPermitted):
            _vbox().start("RingForge-Analysis")

    def test_power_off_is_refused_by_default(self) -> None:
        with self.assertRaises(NotPermitted):
            _vbox().power_off("RingForge-Analysis")

    def test_cutting_the_cable_is_refused_by_default(self) -> None:
        with self.assertRaises(NotPermitted):
            _vbox().set_link("RingForge-Analysis", 1, False)

    def test_reading_is_never_refused(self) -> None:
        vbox = _vbox({"list": LIST_VMS})
        self.assertIn("RingForge-Analysis", vbox.vms())

    def test_the_refusal_names_how_to_allow_it(self) -> None:
        # A guard whose message does not say how to proceed gets worked around
        # by the next reader rather than understood.
        with self.assertRaises(NotPermitted) as caught:
            _vbox().restore("vm", "snap")
        self.assertIn("destructive=True", str(caught.exception))

    def test_nothing_was_run_when_refused(self) -> None:
        # The refusal must happen before the command, not after it.
        vbox = _vbox()
        with self.assertRaises(NotPermitted):
            vbox.restore("vm", "snap")
        self.assertEqual([], vbox.log)


class ThereIsNoRestoreCurrent(unittest.TestCase):
    def test_an_empty_snapshot_name_is_refused_even_when_destructive(self) -> None:
        # The 4 GB boot-log landmine: a parent snapshot on this bench carries
        # `Start=0`, so restoring it boot-logs once and blocks the capture. A
        # sweep must not be able to reach it by leaving the name blank.
        vbox = _vbox(destructive=True)
        with self.assertRaises(HypervisorError) as caught:
            vbox.restore("RingForge-Analysis", "")
        self.assertIn("snapshot name", str(caught.exception))
        self.assertEqual([], vbox.log)


class ParsingVBoxManage(unittest.TestCase):
    def test_a_vm_name_containing_a_newline_is_read_whole(self) -> None:
        vms = _vbox({"list": LIST_VMS}).vms()
        self.assertEqual(4, len(vms))
        self.assertIn("Wazuh-Server", vms)
        self.assertEqual("69da6d81-e3d2-4004-90f5-5368928ed29e",
                         vms["Wazuh-Server"])

    def test_every_uuid_is_paired_with_its_own_name(self) -> None:
        vms = _vbox({"list": LIST_VMS}).vms()
        self.assertEqual("b4be81dd-205b-4d0a-bf2b-43d0969da59a",
                         vms["RingForge-Analysis"])

    def test_nested_snapshots_are_flattened_with_matching_uuids(self) -> None:
        snaps = _vbox({"snapshot": SNAPSHOT_LIST}).snapshots("RingForge-Analysis")
        self.assertEqual(4, len(snaps))
        self.assertEqual(
            ["tooling-baseline-5e1a31c", "tooling-baseline-preprocmonfix",
             "corpus-baseline", "corpus-baseline-capa"],
            [s.name for s in snaps])
        # Pairing by suffix, not position: a name must carry its own uuid.
        by_name = {s.name: s.uuid for s in snaps}
        self.assertEqual("a7ac5475-13f0-4e3c-a9b6-c85866626b3b",
                         by_name["corpus-baseline-capa"])

    def test_has_snapshot_matches_name_or_uuid(self) -> None:
        vbox = _vbox({"snapshot": SNAPSHOT_LIST})
        self.assertTrue(vbox.has_snapshot("vm", "corpus-baseline"))
        self.assertTrue(vbox.has_snapshot(
            "vm", "4eb53047-a351-462d-b200-279edad7757d"))
        self.assertFalse(vbox.has_snapshot("vm", "corpus-baseline-typo"))

    def test_a_vm_with_no_snapshots_is_empty_not_an_error(self) -> None:
        vbox = VirtualBox(manage=Path("VBoxManage.exe"))

        def raise_none(self, args, *, changes_guest):
            raise HypervisorError(
                "VBoxManage snapshot vm list failed (1): "
                "This machine does not have any snapshots")

        vbox._run = raise_none.__get__(vbox, VirtualBox)
        self.assertEqual([], vbox.snapshots("vm"))

    def test_state_is_read_from_the_machinereadable_key(self) -> None:
        vbox = _vbox({"showvminfo": 'name="x"\nVMState="poweroff"\ncpus=4\n'})
        self.assertEqual("poweroff", vbox.state("x"))

    def test_an_unreadable_state_raises_rather_than_guessing(self) -> None:
        vbox = _vbox({"showvminfo": "nothing useful here\n"})
        with self.assertRaises(HypervisorError):
            vbox.state("x")


class CuttingTheCable(unittest.TestCase):
    """Two commands, chosen by state. Found by driving a real VM.

    `controlvm setlinkstate` needs a live session and fails with *"Machine is
    not currently running"* on a stopped VM -- but the loop arms containment
    **before** boot on purpose, so the call that matters most is the one
    `controlvm` cannot serve. `FakeHypervisor` records calls rather than
    running them, so it passed either way.
    """

    def test_a_stopped_vm_uses_modifyvm(self) -> None:
        vbox = _vbox({"showvminfo": 'VMState="poweroff"'}, destructive=True)
        vbox.set_link("RingForge-Analysis", 1, False)
        self.assertIn("modifyvm RingForge-Analysis --cableconnected1 off",
                      vbox.log)
        self.assertFalse([c for c in vbox.log if "setlinkstate" in c])

    def test_a_running_vm_uses_controlvm(self) -> None:
        vbox = _vbox({"showvminfo": 'VMState="running"'}, destructive=True)
        vbox.set_link("RingForge-Analysis", 1, False)
        self.assertIn("controlvm RingForge-Analysis setlinkstate1 off", vbox.log)
        self.assertFalse([c for c in vbox.log if "modifyvm" in c])

    def test_saved_and_aborted_count_as_stopped(self) -> None:
        for state in ("saved", "aborted", "aborted-saved"):
            with self.subTest(state=state):
                vbox = _vbox({"showvminfo": 'VMState="' + state + '"'},
                             destructive=True)
                vbox.set_link("v", 1, False)
                self.assertTrue([c for c in vbox.log if "modifyvm" in c])

    def test_connecting_passes_on(self) -> None:
        vbox = _vbox({"showvminfo": 'VMState="poweroff"'}, destructive=True)
        vbox.set_link("v", 2, True)
        self.assertIn("modifyvm v --cableconnected2 on", vbox.log)

    def test_the_cable_state_can_be_read_back(self) -> None:
        # Containment is verified, not assumed: a restore brings back whatever
        # cable state the snapshot was saved with, and `corpus-baseline-capa`
        # on this bench was saved **connected**.
        fixture = 'cableconnected1="off"' + chr(10) + 'cableconnected2="on"'
        vbox = _vbox({"showvminfo": fixture})
        self.assertFalse(vbox.link_connected("v", 1))
        self.assertTrue(vbox.link_connected("v", 2))

    def test_an_unreadable_cable_state_raises(self) -> None:
        vbox = _vbox({"showvminfo": "nothing here"})
        with self.assertRaises(HypervisorError):
            vbox.link_connected("v", 1)

    def test_reading_the_cable_is_not_destructive(self) -> None:
        # No NotPermitted: a read-only hypervisor must still be able to verify
        # containment, which is the whole point of having the reader.
        vbox = _vbox({"showvminfo": 'cableconnected1="on"'})
        self.assertTrue(vbox.link_connected("v", 1))


class TheGuestDescriptor(unittest.TestCase):
    def test_a_baseline_is_required(self) -> None:
        with self.assertRaises(GuestError) as caught:
            Guest(vm="RingForge-Analysis", baseline="")
        self.assertIn("baseline snapshot must be named", str(caught.exception))

    def test_a_vm_name_is_required(self) -> None:
        with self.assertRaises(GuestError):
            Guest(vm="   ", baseline="corpus-baseline")

    def test_the_two_nics_cannot_be_the_same(self) -> None:
        # Cutting the internet would cut the only route to the guest, so
        # containment would look armed while the run became unreachable.
        with self.assertRaises(GuestError) as caught:
            Guest(vm="v", baseline="b", internet_nic=1, hostonly_nic=1)
        self.assertIn("only route", str(caught.exception))

    def test_adapter_numbers_are_checked(self) -> None:
        for nic in (0, 9, -1):
            with self.subTest(nic=nic):
                with self.assertRaises(GuestError):
                    Guest(vm="v", baseline="b", internet_nic=nic)

    def test_timeouts_must_be_positive(self) -> None:
        with self.assertRaises(GuestError):
            Guest(vm="v", baseline="b", readiness_timeout=0)

    def test_a_sane_descriptor_is_accepted(self) -> None:
        guest = Guest(vm="RingForge-Analysis", baseline="corpus-baseline-capa")
        self.assertEqual(1, guest.internet_nic)
        self.assertEqual(2, guest.hostonly_nic)


class PreFlight(unittest.TestCase):
    """Every problem at once, before a sweep starts rather than during it."""

    def _hv(self, **overrides):
        hv = mock.Mock()
        hv.vms.return_value = {"RingForge-Analysis": "uuid"}
        hv.snapshots.return_value = [Snapshot("corpus-baseline", "u1")]
        hv.state.return_value = "poweroff"
        for key, value in overrides.items():
            getattr(hv, key).return_value = value
        return hv

    def test_a_good_guest_has_no_problems(self) -> None:
        guest = Guest(vm="RingForge-Analysis", baseline="corpus-baseline")
        self.assertEqual([], check_ready(guest, self._hv()))

    def test_an_unregistered_vm_is_reported_with_what_is_known(self) -> None:
        guest = Guest(vm="Typo-Analysis", baseline="corpus-baseline")
        problems = check_ready(guest, self._hv())
        self.assertEqual(1, len(problems))
        self.assertIn("not registered", problems[0])
        self.assertIn("RingForge-Analysis", problems[0])

    def test_a_missing_snapshot_is_reported_with_what_is_known(self) -> None:
        guest = Guest(vm="RingForge-Analysis", baseline="corpus-baseline-capa")
        problems = check_ready(guest, self._hv())
        self.assertTrue(any("no snapshot" in p for p in problems))
        self.assertTrue(any("corpus-baseline" in p for p in problems))

    def test_a_running_guest_is_reported_because_a_sweep_discards_it(self) -> None:
        guest = Guest(vm="RingForge-Analysis", baseline="corpus-baseline")
        problems = check_ready(guest, self._hv(state="running"))
        self.assertTrue(any("would discard" in p for p in problems))

    def test_an_unreachable_hypervisor_is_one_problem_not_a_traceback(self) -> None:
        hv = mock.Mock()
        hv.vms.side_effect = OSError("VBoxManage.exe not found")
        problems = check_ready(Guest(vm="v", baseline="b"), hv)
        self.assertEqual(1, len(problems))
        self.assertIn("cannot reach the hypervisor", problems[0])


#: Real `showvminfo --machinereadable` shared-folder lines from this bench.
#: VBoxManage doubles the backslashes on the way out; the machine config holds
#: one, so the parser has to undo it or every path it reports is wrong.
SHARED_FOLDERS = (
    r'SharedFolderNameMachineMapping1="ringforge"' + "\n"
    r'SharedFolderPathMachineMapping1="C:\\Users\\aring\\Downloads\\ringforge"'
    + "\n"
)


class TheExchangeShare(unittest.TestCase):
    """Repointing the share, which a restore undoes every single run.

    Measured on the real hypervisor 15 Sep: a shared folder added to the
    machine config is gone after `snapshot restore`. The exchange is therefore
    snapshot state, exactly like the NIC cable, and the controller has to set
    it per run rather than once at bench setup.
    """

    def test_the_path_is_unescaped(self) -> None:
        vbox = _vbox({"showvminfo": SHARED_FOLDERS})
        self.assertEqual(
            {"ringforge": r"C:\Users\aring\Downloads\ringforge"},
            vbox.shared_folders("RingForge-Analysis"))

    def test_no_shared_folders_is_an_empty_map_not_an_error(self) -> None:
        self.assertEqual({}, _vbox({"showvminfo": ""})
                         .shared_folders("RingForge-Analysis"))

    def test_repointing_is_refused_by_default(self) -> None:
        with self.assertRaises(NotPermitted):
            _vbox().set_shared_folder("RingForge-Analysis", "ringforge",
                                      r"G:\ringforge-exchange")

    def test_a_share_already_pointing_home_is_left_alone(self) -> None:
        # Idempotent, so a sweep does not rewrite the machine config once per
        # sample for no reason.
        vbox = _vbox({"showvminfo": SHARED_FOLDERS}, destructive=True)
        vbox.set_shared_folder("RingForge-Analysis", "ringforge",
                               r"C:\Users\aring\Downloads\ringforge")
        self.assertEqual([], [c for c in vbox.log if c.startswith("sharedfolder")])

    def test_repointing_removes_before_it_adds(self) -> None:
        # `sharedfolder add` does not replace an existing name, so an add
        # without the remove leaves the guest on the old path while the host
        # believes it moved.
        vbox = _vbox({"showvminfo": SHARED_FOLDERS}, destructive=True)
        vbox.set_shared_folder("RingForge-Analysis", "ringforge",
                               r"G:\ringforge-exchange")
        calls = [c for c in vbox.log if c.startswith("sharedfolder")]
        self.assertEqual(2, len(calls), calls)
        self.assertIn("remove", calls[0])
        self.assertIn("add", calls[1])
        self.assertIn(r"G:\ringforge-exchange", calls[1])
        self.assertIn("--automount", calls[1])

    def test_an_absent_share_is_only_added(self) -> None:
        vbox = _vbox({"showvminfo": ""}, destructive=True)
        vbox.set_shared_folder("RingForge-Analysis", "ringforge",
                               r"G:\ringforge-exchange")
        calls = [c for c in vbox.log if c.startswith("sharedfolder")]
        self.assertEqual(1, len(calls), calls)
        self.assertIn("add", calls[0])


if __name__ == "__main__":
    unittest.main()
