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


def test_system32_redirects_to_syswow64_for_this_32_bit_process(tmp_path):
    """A 32-bit process asking for `System32\\x` gets `SysWOW64\\x`.

    The loader entries claim `System32` because that is what a real WOW64
    process reports (`LOADER_SYSTEM_DIR`), so every path the sample builds from
    them is a `System32` path -- and this harness runs under 64-bit Python,
    where `os.path.isfile` gets no redirection at all.
    """
    source, target = winenv.WOW64_REDIRECT
    probe = source + "kernel32.dll"
    resolved = winenv.resolve_dos_path(probe)
    assert resolved is not None, f"{probe} should redirect to {target}"
    assert resolved.lower().startswith(target.lower())


def test_system32_does_not_fall_back_to_the_64_bit_directory(monkeypatch):
    """When redirection misses there is no second chance.

    A 32-bit process cannot reach the real `System32` by that name -- that is
    what `Sysnative` is for -- so a fallback would let the emulated process open
    a file it could not open on a real machine.
    """
    source, _ = winenv.WOW64_REDIRECT
    seen: list[str] = []

    def only_the_64_bit_one_exists(path):
        seen.append(path)
        return path.lower().startswith(source)

    monkeypatch.setattr(winenv.os.path, "isfile", only_the_64_bit_one_exists)
    assert winenv.resolve_dos_path(source + "write.exe") is None
    assert not any(p.lower().startswith(source) for p in seen), \
        f"the 64-bit System32 was consulted: {seen}"


@pytest.mark.slow
@pytest.mark.skipif(sys.platform != "win32", reason="measures a Windows API")
class TestAgainstTheRealCreateProcessW:
    """The model, checked against the API it models.

    Every test above pins `resolve_dos_path` against its own intent. That is
    worth having and it is not the same as being right: `0aq`, `0as` and `0at`
    each rest on the sentence *"a real `CreateProcessW` fails on `C:C:\\...`"*,
    which eliminated two of three readings and was never measured. It is a Win32
    question, not a malware one, and this is a Windows machine.

    The same standing rule as the `slow` minidump test -- a fixture contains
    what its author thought of, so the model gets checked against what the
    operating system actually does.

    Nothing malicious runs: every call is `CREATE_SUSPENDED`, the rejected rows
    create nothing at all, and anything that starts is terminated at once.
    """

    def _agree(self, path):
        from scripts.real_createprocess_paths import real_create  # noqa: PLC0415

        started, _error = real_create(path)
        modelled = winenv.resolve_dos_path(path)
        return started, bool(modelled)

    def test_the_doubled_volume_is_rejected_by_windows_itself(self):
        """The sentence three HANDOFF sections rest on."""
        started, modelled = self._agree(r"C:C:\Windows\System32\compact.exe")
        assert not started, ("Windows accepted the doubled volume -- reading 1 "
                             "of 0aq is wrong and the stage-4 census needs "
                             "redoing against a create that succeeds")
        assert not modelled

    def test_a_real_binary_starts_so_a_table_of_failures_means_something(self):
        """Without this, a broken call and a rejected path look identical."""
        control = r"C:\Windows\SysWOW64\where.exe"
        if not winenv.os.path.isfile(control):
            pytest.skip(f"{control} is not on this host")
        started, modelled = self._agree(control)
        assert started, "the success control did not start; the probe is broken"
        assert modelled

    @pytest.mark.parametrize("path", [
        r"C:C:\Windows\System32\compact.exe",
        r"C:C:\Windows\SysWOW64\compact.exe",
        r"C:Windows\SysWOW64\compact.exe",
        r"\??\C:\Windows\SysWOW64\where.exe",
        r"\Windows\SysWOW64\where.exe",
        "compact.exe",
    ])
    def test_the_model_agrees_with_the_api(self, path):
        started, modelled = self._agree(path)
        assert started == modelled, (
            f"{path!r}: Windows {'starts' if started else 'refuses'} it, "
            f"resolve_dos_path {'resolves' if modelled else 'refuses'} it -- "
            f"every stage-4 census is measuring this harness, not a machine")
