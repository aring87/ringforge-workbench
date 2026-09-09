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

No test can catch that from inside the directory that hides it. The same is
true of packaged *data*, which is why the shipped assets, Procmon configs
and authored YARA rules are checked here too.
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
    "ringforge.resources",
)

#: Data files the package ships: (accessor name, argument, glob). A glob of
#: `None` means the accessor names one file rather than a directory.
#:
#: **These are here for the same reason the imports are.** They were tracked
#: in git and resolved from the repo root, so they reached every run started
#: from a checkout and no installed copy at all -- `package-data` applies
#: only inside a package, and neither `assets/` nor `tools/` was one. A `pip
#: install` produced a workbench with no logo, no Procmon filters and none of
#: this project's own YARA rules, each absence reported as an ordinary
#: coverage gap.
REQUIRED_DATA = (
    ("asset", "anvil.png", None),
    ("procmon_configs_dir", None, "*.pmc"),
    ("local_yara_rules_dir", None, "*.yar"),
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

    # Data files, checked only once the imports have proved out -- a failure
    # here should mean "not packaged", not "could not import the accessor".
    if not failures:
        from ringforge import resources

        for accessor, argument, glob in REQUIRED_DATA:
            label = f"{accessor}({argument!r})" if argument else f"{accessor}()"
            try:
                function = getattr(resources, accessor)
                path = function(argument) if argument else function()
            except Exception as error:
                failures.append(f"{label}: {type(error).__name__}: {error}")
                continue
            if glob is None:
                if not path.is_file():
                    failures.append(f"{label}: {path} is not a file")
            elif not (path.is_dir() and any(path.glob(glob))):
                failures.append(f"{label}: no {glob} under {path}")

    for name in failures:
        print(f"  FAIL {name}")
    if failures:
        print(f"\n{len(failures)} check(s) failed across {len(REQUIRED)} imports "
              f"and {len(REQUIRED_DATA)} data files.")
        return 1

    print(f"  all {len(REQUIRED)} modules import from the installed package")
    print(f"  all {len(REQUIRED_DATA)} shipped data paths resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main())
