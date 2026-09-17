"""The dynamic run's configuration, without a window attached to it.

**Why this exists.** `run_dynamic_analysis` takes a 24-key config dict, and
until now the only thing that built one was `gui/dynamic_window.py`, out of
Tk variables. So a detonation required a human at a GUI, and the run
controller -- which exists to turn one detonation into a corpus -- could not
detonate at all. Its guest agent ran `ringforge.cli scan` and nothing else,
which is static triage: **102 samples were swept without a single one being
executed**, and the sweep was a slow remote way to do what the host already
does in 28 seconds.

This is the same mapping the GUI performs, lifted out so both sides share it.
Two rules it has to keep, or a guest run silently means something different
from a bench run:

**Identical defaults.** Every fallback below matches the Tk variable it
replaces. A guest that defaulted Sysmon off while the GUI defaulted it on
would produce a corpus whose coverage differs from every hand-driven run it
gets compared against, and nothing would say so.

**`or`, not `get(key, default)`, for the path fields.** A *cleared* field in
`config.json` is a key holding `""`, so `.get` returns the empty string and
never reaches the default. That is recorded in `dynamic_window.py` as a real
defect: an empty Procmon config path makes the orchestrator pass `None`, and
Procmon then runs on whatever filter it had saved. Clearing a field to restore
the default is the obvious operator move, and it silently disabled the
collection it was meant to restore.

Nothing here reads a GUI, opens a window, or touches the filesystem beyond
resolving default tool paths.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from dynamic_analysis.memory_dump import (
    DEFAULT_MAX_PROCESSES,
    DEFAULT_SPAWN_REDUMP_SECONDS,
)
from dynamic_analysis.procmon_config import DEFAULT_PROCMON_CONFIG_NAME
from ringforge.resources import app_root, procmon_configs_dir

#: Where the orchestrator's output goes inside a case folder. The GUI passes
#: this as `case_dir` and the case root as `case_home_dir`, so runs land at
#: `cases/<case>/dynamic_analysis/dynamic_runs/<run>/`. Matched exactly,
#: because `combine` finds the dynamic module by this path.
DYNAMIC_SUBDIR = "dynamic_analysis"


def _procmon_config(cfg: Mapping[str, Any]) -> str:
    """The Procmon filter to load, falling back when the saved one is gone.

    **A configured path that no longer exists is worse than no path at all,
    and it cost two detonations on 17 Sep.** v1.12.0 moved the Procmon
    filters out of `tools/procmon-configs/` and into the package; a
    `config.json` written before that move still named the old location.
    Procmon takes a `/LoadConfig` pointing at a missing file, exits
    immediately and says nothing -- it is a GUI app, so the launching process
    sees a clean `Popen` either way. The capture never started, and the run
    only discovered it twenty-five minutes later when the export failed on a
    backing file that was never created.

    So an absent file falls back to the packaged default rather than being
    passed through. The empty case falls back for the reason recorded in the
    module docstring; this adds the *stale* case, which looks configured and
    is not.
    """
    configured = str(cfg.get("dynamic_procmon_config_path") or "").strip()
    if configured and Path(configured).is_file():
        return configured
    return str(procmon_configs_dir() / DEFAULT_PROCMON_CONFIG_NAME)


def load_settings(root: Path | None = None) -> dict[str, Any]:
    """`config.json` as a plain dict, or empty when there is none.

    Absent is not an error: a fresh guest has no saved settings and every key
    below has a default. A *malformed* one is also not an error here -- it is
    reported by the caller that can say so usefully -- but it must not be
    mistaken for absent, or a corrupt settings file would quietly produce a
    run configured differently from every other.
    """
    root = Path(root) if root else app_root()
    path = root / "config.json"
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def build_config(
    sample: Path,
    case_home: Path,
    settings: Mapping[str, Any] | None = None,
    *,
    root: Path | None = None,
) -> dict[str, Any]:
    """The config `run_dynamic_analysis` expects, from saved settings.

    `case_home` is the case folder -- `cases/<name>` -- not the dynamic
    subdirectory; this puts the run under it the way the GUI does.
    """
    cfg: Mapping[str, Any] = settings if settings is not None else load_settings(root)
    root = Path(root) if root else app_root()
    sample = Path(sample)
    case_home = Path(case_home)

    return {
        "sample_path": str(sample),
        "case_dir": str(case_home / DYNAMIC_SUBDIR),
        "case_home_dir": str(case_home),

        "timeout_seconds": int(cfg.get("dynamic_timeout_seconds", 30)),
        "minimum_observation_seconds": int(
            cfg.get("dynamic_minimum_observation_seconds", 30)),
        "post_exit_observation_seconds": int(
            cfg.get("dynamic_post_exit_observation_seconds", 120)),
        "installer_observation_mode": bool(
            cfg.get("dynamic_installer_observation_mode", True)),
        "adaptive_observation": bool(
            cfg.get("dynamic_adaptive_observation", True)),
        "max_observation_seconds": int(
            cfg.get("dynamic_max_observation_seconds", 600)),

        # `or` on both: see the module docstring. A cleared path must fall
        # back to the default rather than disable the collector.
        "procmon_enabled": bool(cfg.get("dynamic_procmon_enabled", True)),
        "procmon_path": str(
            cfg.get("dynamic_procmon_path")
            or root / "tools" / "Procmon64.exe"),
        "procmon_config_path": _procmon_config(cfg),

        "sysmon_enabled": bool(cfg.get("dynamic_sysmon_enabled", True)),
        "pcap_enabled": bool(cfg.get("dynamic_pcap_enabled", True)),
        # Off by default and deliberately so: it installs a traffic diverter,
        # which stays opt-in.
        "fakenet_enabled": bool(cfg.get("dynamic_fakenet_enabled", False)),
        "fakenet_path": str(
            cfg.get("dynamic_fakenet_path")
            or root / "tools" / "fakenet" / "fakenet.exe"),
        # Empty means the stock config, which is a real choice rather than a
        # missing value, so this one is *not* an `or`.
        "fakenet_config_path": str(cfg.get("dynamic_fakenet_config_path", "")),

        "memory_dump_enabled": bool(cfg.get("dynamic_memory_dump_enabled", True)),
        "memory_yara_enabled": bool(cfg.get("dynamic_memory_yara_enabled", True)),
        # Blank offsets fall through to the run profile's defaults inside the
        # orchestrator, which parses the text itself.
        "memory_dump_offsets": str(cfg.get("dynamic_memory_dump_offsets", "")),
        "memory_dump_max_processes": int(
            cfg.get("dynamic_memory_dump_max_processes", DEFAULT_MAX_PROCESSES)),
        "memory_dump_spawn_redump_seconds": int(
            cfg.get("dynamic_memory_dump_spawn_redump_seconds",
                    DEFAULT_SPAWN_REDUMP_SECONDS)),
    }
