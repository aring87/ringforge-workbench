"""Who produced a verdict, with what, and when.

**Why a verdict needs this.** On 03 Sep a case reported 0 YARA matches over
1,593 rule files. The rule set had failed to compile -- one rule used an
external variable the scanner did not declare -- so nothing ran, and the stored
result said "no matches" for a fortnight. The artifact recorded the *count of
files on disk* and not whether any of them compiled, so the failure was
invisible until someone re-ran it by hand.

Provenance is what turns that into a diff instead of an excavation. A verdict
that carries the analyzer version, the commit, the library versions and what
the collectors actually managed to load can be compared against a later one and
the difference explains itself.

**Everything here degrades rather than raises.** A missing git binary, an
uninstalled package or a source checkout with no metadata are all ordinary, and
none of them is a reason to fail a run. An unknown value is recorded as `null`,
which is a different fact from a value of zero -- the distinction this whole
project is built around.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Mapping

#: The document's shape, not the scoring model's. `score_model` versions how a
#: band is decided; this versions the envelope around it -- the field names, the
#: nesting, what is guaranteed present. A consumer pins this.
#:
#: Bump the minor for an added field, the major for a removed or renamed one.
SCHEMA_VERSION = "1.0"

#: Libraries whose version changes what a collector can see. `yara-python`
#: earns its place at the top of this list: a version change there moved a
#: whole rule set from compiling to not.
_TRACKED = ("yara-python", "pefile", "psutil", "PyYAML", "requests", "lief")


def _package_version(name: str) -> str | None:
    try:
        from importlib.metadata import PackageNotFoundError, version

        return version(name)
    except Exception:
        return None


def analyzer_version() -> str | None:
    """The installed package version, or `None` in a bare source checkout."""
    return _package_version("ringforge-workbench")


def git_commit(root: str | Path | None = None) -> str | None:
    """The commit the analyzer is running from, if it is a git checkout.

    Best effort by design: a wheel installed into site-packages has no git
    history and that is not an error, it is the normal case for a deployment.
    """
    root = Path(root) if root else Path(__file__).resolve().parents[1]
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5, check=False)
    except Exception:
        return None
    commit = out.stdout.strip()
    return commit if out.returncode == 0 and commit else None


def tool_versions() -> dict[str, str | None]:
    """Versions of the libraries a collector's answer depends on."""
    return {name: _package_version(name) for name in _TRACKED}


def yara_collector(yara_results: Mapping[str, Any] | None) -> dict[str, Any]:
    """What the YARA scan actually loaded, from its own record.

    **`rule_file_count` alone is the field that misled.** It counts files on
    disk; it says nothing about whether they compiled. `rules_compiled` and
    `error` are what distinguish a clean scan from one that never ran, and both
    belong beside the verdict rather than three files away.
    """
    if not isinstance(yara_results, Mapping):
        return {"collected": False}
    return {
        "collected": True,
        "engine": yara_results.get("engine"),
        "rule_file_count": yara_results.get("rule_file_count"),
        "rules_compiled": yara_results.get("rules_compiled"),
        "rules_skipped": len(yara_results.get("rules_skipped") or []),
        # A scan that errored has no result, whatever its counts say.
        "error": yara_results.get("error") or None,
    }


def analyzer_provenance(root: str | Path | None = None) -> dict[str, Any]:
    """The half of provenance that is about this program, not about a case."""
    return {
        "name": "ringforge-workbench",
        "version": analyzer_version(),
        "commit": git_commit(root),
        "tools": tool_versions(),
    }
