"""Prove an *installed* copy of the engine works, from outside the source tree.

Run this with the interpreter of a fresh environment that has the wheel
installed, from a directory that is not the repo:

    python -m venv /tmp/fresh
    /tmp/fresh/bin/python -m pip install dist/ringforge_workbench-*.whl
    cd /tmp && /tmp/fresh/bin/python path/to/check_installed_package.py

**Why this is not a pytest.** The suite runs from the repo root, so the repo is
on `sys.path` and every module resolves whether or not it was packaged. That is
exactly how five pipeline modules came to live in `scripts/` -- bench tooling,
not shipped -- while the engine imported them. It worked for as long as nobody
installed it. The first install outside the source tree failed on
`ModuleNotFoundError: No module named 'scripts'`.

No test can catch that from inside the directory that hides it.
"""

from __future__ import annotations

import sys
from pathlib import Path

#: Imported for their side effect of resolving. Each is a module an installed
#: copy must be able to reach without the repo on `sys.path`.
REQUIRED = (
    "static_triage_engine.engine",
    "static_triage_engine.dotnet_meta",
    "static_triage_engine.ioc_extract",
    "static_triage_engine.pe_meta",
    "static_triage_engine.dotnet_summary",
    "static_triage_engine.lief_meta",
    "static_triage_engine.static_triage_cli",
    "dynamic_analysis.html_report",
    "dynamic_analysis.preflight",
    "verdict",
    "verdict.case_artifacts",
    "verdict.case_summary",
    "ringforge.cli",
)


def main() -> int:
    import importlib

    failures: list[str] = []

    for name in REQUIRED:
        try:
            module = importlib.import_module(name)
        except Exception as error:
            failures.append(f"{name}: {type(error).__name__}: {error}")
            continue
        origin = getattr(module, "__file__", "") or ""
        # **Assert the positive.** An earlier version inferred the source tree
        # from this file's own location, which gave false failures the moment
        # the script was copied somewhere whose parent also contained the venv.
        # "Came from an installed package" has a precise definition -- it sits
        # under site-packages -- so test that instead of guessing where it did
        # not come from.
        #
        # This is expected to fail against an *editable* install, which points
        # back at the source on purpose. Run it against a built wheel.
        parts = {part.lower() for part in Path(origin).resolve().parts}
        if origin and not parts & {"site-packages", "dist-packages"}:
            failures.append(f"{name}: resolved from {origin}, which is not an "
                            f"installed package")

    for name in failures:
        print(f"  FAIL {name}")
    if failures:
        print(f"\n{len(failures)} of {len(REQUIRED)} imports did not come from "
              f"an installed package.")
        return 1

    print(f"  all {len(REQUIRED)} modules import from the installed package")
    return 0


if __name__ == "__main__":
    sys.exit(main())
