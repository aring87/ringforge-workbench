"""A frozen build has two roots, and confusing them is silent.

`get_app_root()` had understood `sys.frozen` since the beginning, and so had
`gui_utils.app_root()`. Neither was the problem. The problem was that twenty-odd
other sites never called either of them and derived a root from `__file__`
instead -- every `_tools_dir()`, the Autorunsc and Sysmon defaults, the YARA
rules directory, and each window's `cases/` fallback.

Under PyInstaller `__file__` points into the unpacked code: a temporary
directory in one-file mode, `_internal/` in one-dir mode. `parents[1]` of that
is not where the operator put Procmon, so `find_procdump` would look in a
directory that could never contain it, and `memory_dump_status` would report
"ProcDump not found. Place procdump64.exe under tools/" -- accurate about the
miss, naming a `tools/` that is not the one beside their executable.

So the split is asserted here rather than the individual paths:

  * things this application does not ship -- `tools/`, `cases/`, `logs/` --
    follow the *executable*, via `app_root()`
  * things it does ship -- assets, Procmon filters, authored rules -- come from
    the *package*, via `data_root()`

The two answers are identical in a source checkout, which is why nothing caught
this for as long as every run started from one. `sys.frozen` is set here to make
them differ.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

import dynamic_analysis.fakenet_runner as fakenet_runner
import dynamic_analysis.memory_dump as memory_dump
import dynamic_analysis.network_capture as network_capture
import dynamic_analysis.orchestrator as orchestrator
import dynamic_analysis.sysmon_collector as sysmon_collector
from ringforge.resources import (
    app_root,
    asset,
    data_root,
    local_yara_rules_dir,
    procmon_configs_dir,
)
from static_triage_engine.config import get_app_root

#: A one-dir build: the executable sits here and the code is unpacked into
#: `_internal/` beside it. One-file differs only in unpacking to a temporary
#: directory, which fails the same way for the same reason.
EXE_DIR = Path(r"C:\RingForge")
EXE = EXE_DIR / "RingForge.exe"
MEIPASS = EXE_DIR / "_internal"


def frozen():
    """Run the resolvers as though PyInstaller had started them."""
    return mock.patch.multiple(
        "sys", frozen=True, executable=str(EXE), _MEIPASS=str(MEIPASS), create=True
    )


class ExternalStateFollowsTheExecutable(unittest.TestCase):
    """`app_root()` and everything that should be built on it."""

    def resolvers(self):
        return {
            "app_root": app_root(),
            "get_app_root": get_app_root(),
            "memory_dump tools": memory_dump._tools_dir(),
            "network_capture tools": network_capture._tools_dir(),
            "fakenet_runner tools": fakenet_runner._tools_dir(),
            "autorunsc": orchestrator._default_autorunsc_path(),
            "sysmon": sysmon_collector.default_sysmon_path(),
        }

    def test_every_resolver_lands_beside_the_executable(self) -> None:
        with frozen():
            for label, path in self.resolvers().items():
                with self.subTest(resolver=label):
                    self.assertTrue(
                        path == EXE_DIR or EXE_DIR in path.parents,
                        f"{label} resolved to {path}, which is not under {EXE_DIR}",
                    )

    def test_no_resolver_lands_in_the_unpacked_code(self) -> None:
        # The specific failure: `parents[1]` of a module unpacked into
        # `_internal/` is `_internal/`, which holds no `tools/` and never will.
        with frozen():
            for label, path in self.resolvers().items():
                with self.subTest(resolver=label):
                    self.assertNotIn("_internal", path.parts,
                                     f"{label} resolved into the unpacked code: {path}")

    def test_the_tools_directory_is_the_one_beside_the_executable(self) -> None:
        with frozen():
            for label, path in self.resolvers().items():
                if not label.endswith("tools"):
                    continue
                with self.subTest(resolver=label):
                    self.assertEqual(EXE_DIR / "tools", path)


class BundledDataComesFromThePackage(unittest.TestCase):
    """`data_root()` needs no frozen branch, and must not grow one."""

    def test_shipped_data_does_not_follow_the_executable(self) -> None:
        # `importlib.resources` answers for a checkout, a wheel and a bundle
        # alike. If this ever starts returning the executable's directory,
        # someone has "fixed" it into the external-state convention by mistake.
        with frozen():
            for label, path in (
                ("data_root", data_root()),
                ("asset", asset("anvil.png")),
                ("procmon configs", procmon_configs_dir()),
                ("local yara rules", local_yara_rules_dir()),
            ):
                with self.subTest(resource=label):
                    self.assertIn("_data", path.parts, f"{label}: {path}")
                    self.assertNotEqual(EXE_DIR, path)
                    self.assertNotIn(EXE_DIR, path.parents)


class TheTwoRootsAgreeInACheckout(unittest.TestCase):
    """Which is why the defect survived: unfrozen, the bug is invisible."""

    def test_shipped_data_sits_under_the_application_root(self) -> None:
        self.assertIn(app_root(), data_root().parents)

    def test_the_shipped_data_actually_exists_here(self) -> None:
        # Not a tautology: this is what fails if `_data` is emptied or moved
        # without the accessors being updated with it.
        self.assertTrue(asset("anvil.png").is_file())
        self.assertTrue(any(procmon_configs_dir().glob("*.pmc")))
        self.assertTrue(any(local_yara_rules_dir().glob("*.yar")))


if __name__ == "__main__":
    unittest.main()
