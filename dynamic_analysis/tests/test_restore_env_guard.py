"""`Emulator.restore` must refuse a resume that denies what the state claimed.

A stored state is a function of the environment that produced it and `restore()`
does not inherit that environment. `after_handshake.state` exists only because
`RINGFORGE_EXPLORER_CHILD=1` served `notepad.exe` for the loader to inject into;
resuming it without the toggle made the harness answer FALSE to
`PostThreadMessageW` for the thread of the process it had hijacked 700 million
blocks earlier, and the payload's failure path then issued a second message that
does not occur in a correct run. The wrong answer invented behaviour, which is
this project's most expensive recurring mistake.

These exercise `_check_env` directly on synthetic state dicts: it is a pure
function of (state, environ), so none of this needs a 115 MB snapshot or an
emulator.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

from emulate_native_stub import Emulator          # noqa: E402

TOGGLE = "RINGFORGE_EXPLORER_CHILD"


def _clear(monkeypatch):
    for name in Emulator.ENV_TOGGLES:
        monkeypatch.delenv(name, raising=False)


def test_refuses_when_the_state_claimed_a_toggle_the_environment_denies(monkeypatch):
    _clear(monkeypatch)
    state = {"env_toggles": {TOGGLE: "1"}}
    with pytest.raises(EnvironmentError) as excinfo:
        Emulator._check_env(state, "after_handshake.state")
    message = str(excinfo.value)
    # The message has to name the variable and the value to set it to, because
    # the whole point is that the failure is otherwise silent.
    assert TOGGLE in message
    assert "after_handshake.state" in message
    assert f"{TOGGLE}=1" in message


def test_allows_when_the_environment_matches(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv(TOGGLE, "1")
    Emulator._check_env({"env_toggles": {TOGGLE: "1"}}, "s.state")


def test_allows_adding_a_toggle_the_state_lacked_and_says_so(monkeypatch, capsys):
    """Asymmetric on purpose.

    `after_scan.state` predates the toggle and is routinely resumed with it on --
    that is the documented route to the injection. Adding a process the state
    never referred to cannot contradict it, so this direction is allowed; it is
    only announced, because anything the run does with that process is new.
    """
    _clear(monkeypatch)
    monkeypatch.setenv(TOGGLE, "1")
    Emulator._check_env({"env_toggles": {TOGGLE: None}}, "after_scan.state")
    out = capsys.readouterr().out
    assert "NOTE" in out and TOGGLE in out


def test_pre_v4_state_is_checked_on_evidence_not_on_its_silence(monkeypatch):
    """Every state on the artifact drive was written before `env_toggles`.

    Stage 3's poll never leaves its loop unless a child of explorer is served,
    so a state carrying the injection calls is proof the toggle was on whatever
    it does or does not record.
    """
    _clear(monkeypatch)
    for evidence in Emulator._CHILD_EVIDENCE:
        with pytest.raises(EnvironmentError, match=TOGGLE):
            Emulator._check_env({"calls": {evidence: 1}}, "old.state")


def test_pre_v4_state_without_the_evidence_is_left_alone(monkeypatch):
    _clear(monkeypatch)
    # A state from before the injection was ever reached. Nothing can be
    # inferred and nothing should be claimed.
    Emulator._check_env({"calls": {"NtAllocateVirtualMemory": 12}}, "warm60M.state")
    Emulator._check_env({}, "empty.state")


def test_every_toggle_the_harness_reads_is_covered():
    """The guard is only as good as its list.

    A new `RINGFORGE_*` toggle that changes what the harness claims exists, added
    without a line here, reintroduces exactly the failure this file exists to
    prevent -- silently, and in a state written months earlier.
    """
    source = (Path(__file__).resolve().parents[2] / "scripts").glob("*.py")
    referenced = set()
    for path in source:
        referenced |= set(re.findall(r"RINGFORGE_[A-Z_]+",
                                     path.read_text(encoding="utf-8")))
    missing = referenced - set(Emulator.ENV_TOGGLES)
    assert not missing, (
        f"{sorted(missing)} is read by the harness but not in ENV_TOGGLES. If it "
        f"changes what the harness claims exists, add it; if it only changes "
        f"fidelity to what is already there, say so here and allow it.")
