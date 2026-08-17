"""`CreateProcessInternalW` must reject a path a real one would reject.

The stub returned 1 without looking at `lpApplicationName`. That mattered:
stage 4 builds `C:C:\\Windows\\SysWOW64\\compact.exe` -- a doubled volume that
four black-box measurements show is the sample's own, not this harness's
(HANDOFF `0aq`, `0as`) -- and a real `CreateProcessW` rejects it. Succeeding
anyway is how `0af` came to record "in a working environment it takes the
first", a claim that was resting entirely on the missing check.

`resolve_dos_path` is a pure function of (string, filesystem), so these use real
files under `tmp_path` rather than whatever this host keeps in `SysWOW64` -- a
test that passes because the machine happens to have `compact.exe` is testing
the machine.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import win32_emu_env as winenv          # noqa: E402


@pytest.fixture()
def real_file(tmp_path):
    path = tmp_path / "target.exe"
    path.write_bytes(b"MZ")
    return str(path)


def test_a_real_full_path_resolves(real_file):
    assert winenv.resolve_dos_path(real_file) == real_file


def test_the_doubled_volume_stage_4_builds_is_rejected(real_file):
    """The whole reason this check exists."""
    doubled = real_file[:2] + real_file
    assert winenv.resolve_dos_path(doubled) is None


def test_the_pre_fix_shape_is_rejected():
    """What stage 4 built while `FullDllName` was a bare leaf (`0al`)."""
    assert winenv.resolve_dos_path(
        r"ntdll.dll\Windows\SysWOW64\compact.exe") is None


def test_quotes_and_the_nt_prefix_are_stripped(real_file):
    assert winenv.resolve_dos_path(f'"{real_file}"') == real_file
    assert winenv.resolve_dos_path(f"\\??\\{real_file}") == real_file


def test_drive_relative_resolves_against_the_only_drive_served(real_file):
    """A real `CreateProcessW` resolves `\\Windows\\...` against the current
    drive. This harness claims exactly one."""
    if not real_file.upper().startswith(winenv.SYSTEM_DRIVE.upper()):
        pytest.skip(f"tmp_path is not on {winenv.SYSTEM_DRIVE}")
    assert winenv.resolve_dos_path(real_file[2:]) == real_file


def test_a_bare_leaf_does_not_resolve():
    """`Emulator.backing()` resolves files by leaf, which is what silently
    repaired the malformed path for two days. Creation must not."""
    assert winenv.resolve_dos_path("compact.exe") is None


def test_well_formed_but_absent_does_not_resolve(tmp_path):
    assert winenv.resolve_dos_path(str(tmp_path / "nosuchfile.exe")) is None


@pytest.mark.parametrize("path", ["", "   ", "C:", "C:x", "\\\\server\\share\\x.exe"])
def test_malformed_paths_do_not_raise(path):
    """Payload-controlled text reaches this. It has to answer, not throw."""
    assert winenv.resolve_dos_path(path) is None
