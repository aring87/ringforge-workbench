"""Where the data the workbench *ships* lives, as opposed to the data an
operator installs.

**Why this exists.** `assets/anvil.png`, the Procmon filter configs and the
authored YARA rules were tracked in git and resolved relative to the repo root,
which works for every run started from a checkout and for nothing else. They
reached no wheel: `[tool.setuptools.package-data]` only applies to files inside
a package, and neither `assets/` nor `tools/` is one. A `pip install` produced a
workbench with no logo, no Procmon filters and none of this project's own
detection rules, and reported each absence as an ordinary coverage gap.

**The split this draws.** `tools/` stays what it has always been: the tree
`bootstrap_tools.ps1` writes Procmon, Sysmon, Autorunsc and the downloaded rule
set into, operator-managed, beside the app root, correctly absent on a machine
that has not been bootstrapped. What is *shipped* moved in here, where it is
package data and travels with the code.

**And it is one lookup, not three.** `importlib.resources` resolves a source
checkout, an installed wheel and a PyInstaller bundle identically, so the
frozen build needs no second path convention -- the case `get_app_root()`
already handles for external state, handled once here for bundled data.
"""

from __future__ import annotations

import sys
from importlib.resources import files
from pathlib import Path

#: Filter configs the dynamic run hands to Procmon. Tracked, ours, shipped.
PROCMON_CONFIGS = "procmon-configs"

#: Rules written for this project, as distinct from `tools/yara/rules/`, which
#: `bootstrap_yara_rules.ps1` downloads and which no wheel may redistribute.
LOCAL_YARA_RULES = Path("yara") / "local"


def app_root() -> Path:
    """The root for state this application does not ship.

    `tools/` as an operator bootstraps it, `cases/`, `logs/`, `config.json`:
    things that live *beside* the application rather than inside it, and that
    are correctly absent on a machine nobody has set up.

    **Frozen, this is the directory holding the executable**, which is where an
    operator will unzip Procmon next to the thing they double-click. It is not
    where the code is: PyInstaller unpacks modules into `_MEIPASS`, so anything
    deriving a root from `__file__` lands in a temporary directory in one-file
    mode and in `_internal/` in one-dir mode. Neither ever contains `tools/`.

    Use `data_root()` for anything the package ships. The two answers differ
    only when frozen, which is exactly why both had to be named.
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]


def data_root() -> Path:
    """The root of the shipped data tree.

    `importlib.resources` gives the same answer for a source checkout, an
    installed wheel and a PyInstaller bundle, so this needs no frozen branch.
    """
    return Path(str(files("ringforge") / "_data"))


def asset(name: str) -> Path:
    """A shipped GUI asset by filename. May not exist; callers already cope."""
    return data_root() / "assets" / name


def procmon_configs_dir() -> Path:
    """The directory holding the `.pmc` filter configs."""
    return data_root() / PROCMON_CONFIGS


def local_yara_rules_dir() -> Path:
    """The authored YARA rules, the canonical side of the freshness check."""
    return data_root() / LOCAL_YARA_RULES
