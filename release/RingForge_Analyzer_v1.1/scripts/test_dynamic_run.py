from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dynamic_analysis.orchestrator import run_dynamic_analysis


def main() -> None:
    sample_path = Path(r"C:\Windows\System32\whoami.exe")
    case_dir = PROJECT_ROOT / "cases" / "dynamic_case"

    config = {
        "sample_path": str(sample_path),
        "case_dir": str(case_dir),
        "timeout_seconds": 30,
        "procmon_enabled": True,
        "procmon_path": str(PROJECT_ROOT / "tools" / "Procmon64.exe"),
        "procmon_config_path": "",
    }

    summary = run_dynamic_analysis(config)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()