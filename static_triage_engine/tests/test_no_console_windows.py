"""A windowed build must not flash a console for every child process.

Started from a terminal, a child inherits the parent's console and nothing
appears — which is why this went unnoticed for the entire life of the project.
Started from `ringforge-gui.exe`, which PyInstaller builds with no console at
all, Windows gives every console child a window of its own.

The containment watch is what made it obvious: `network_isolation_status()`
shells out every four seconds for as long as the Dynamic Analysis window is
open, so a command prompt appeared every four seconds. But the watch is not
special. Any of these calls does it, and the ones that run during a detonation
are the worst place for a stolen focus.

**This is a source scan, not a behavioural test.** Whether a window appears
depends on how the process was started, so no test running under pytest — which
has a console — can observe the failure. What *can* be checked is that every
call site asks for the flag, which is the thing that actually goes wrong when
somebody adds a forty-third subprocess call.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

#: The shipped packages. `scripts/` is bench tooling run from a terminal, and
#: `tests/` may spawn whatever it likes.
PACKAGES = ("gui", "dynamic_analysis", "static_triage_engine", "verdict", "ringforge")

#: `static_triage_engine/proc.py` defines the helper and is where the raw calls
#: legitimately live.
EXEMPT = {Path("static_triage_engine") / "proc.py"}

SPAWNERS = {"run", "Popen", "check_output", "check_call", "call"}

ROOT = Path(__file__).resolve().parents[2]


def _spawning_calls(tree: ast.AST):
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (isinstance(func, ast.Attribute)
                and func.attr in SPAWNERS
                and isinstance(func.value, ast.Name)
                and func.value.id == "subprocess"):
            yield node


class EverySubprocessCallSuppressesItsConsole(unittest.TestCase):
    def _shipped_modules(self):
        for package in PACKAGES:
            for path in sorted((ROOT / package).rglob("*.py")):
                relative = path.relative_to(ROOT)
                if "tests" in relative.parts or relative in EXEMPT:
                    continue
                yield relative, path

    def test_no_call_site_is_missing_creationflags(self) -> None:
        missing = []
        for relative, path in self._shipped_modules():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in _spawning_calls(tree):
                if not any(k.arg == "creationflags" for k in node.keywords):
                    missing.append(f"{relative}:{node.lineno}")

        self.assertEqual(
            [], missing,
            "these spawn a console window in a windowed build; pass "
            "creationflags=no_window():\n  " + "\n  ".join(missing))

    def test_the_scan_is_actually_finding_call_sites(self) -> None:
        # Without this the test above passes triumphantly on zero files the day
        # somebody renames a package. The count is a floor, not an assertion
        # about the exact number.
        found = sum(1 for _, path in self._shipped_modules()
                    for _ in _spawning_calls(ast.parse(path.read_text(encoding="utf-8"))))
        self.assertGreater(found, 30, "the scan found almost nothing; check PACKAGES")

    def test_the_flag_is_a_no_op_off_windows(self) -> None:
        # `creationflags` is Windows-only and Popen rejects a non-zero value
        # elsewhere, so the helper has to degrade to 0 rather than to a constant.
        import subprocess

        from static_triage_engine.proc import NO_WINDOW, no_window

        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            self.assertEqual(subprocess.CREATE_NO_WINDOW, NO_WINDOW)
        else:
            self.assertEqual(0, NO_WINDOW)

    def test_existing_creation_flags_are_kept(self) -> None:
        # Two call sites need CREATE_NEW_PROCESS_GROUP for cancellation. The
        # helper combines rather than replaces, and this is what says so.
        from static_triage_engine.proc import NO_WINDOW, no_window

        group = 0x00000200
        self.assertEqual(group | NO_WINDOW, no_window(group))


if __name__ == "__main__":
    unittest.main()
