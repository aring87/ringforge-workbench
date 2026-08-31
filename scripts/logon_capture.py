"""Arm, disarm and run the logon capture. The guest-side entry point.

    .venv\\Scripts\\python.exe scripts\\logon_capture.py --arm ^
        --out C:\\logon-capture ^
        --procmon C:\\...\\tools\\rf_trace64.exe --window 300

    ... reboot, log on, wait out the window ...

    .venv\\Scripts\\python.exe scripts\\logon_capture.py --status
    .venv\\Scripts\\python.exe scripts\\logon_capture.py --disarm

`--capture` is what the scheduled task invokes and is not normally typed by
hand. See `dynamic_analysis/logon_capture.py` for why the task is `ONSTART`
rather than `ONLOGON`, and for the ordering rule that keeps it out of the run's
task diffs.

**Read `logon_capture.json` before the CSV.** `completed: false` with a reason
means the capture did not run, and `procmon_filter.captures_registry_reads`
means it could not have seen a registry read whatever it recorded. An empty
capture and a capture that never happened are different results and this refuses
to conflate them.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dynamic_analysis.logon_capture import (  # noqa: E402
    DEFAULT_WINDOW_SECONDS,
    TASK_NAME,
    arm,
    disarm,
    run_capture,
    status,
)
from dynamic_analysis.procmon_config import DEFAULT_PROCMON_CONFIG_NAME  # noqa: E402


def _default_config() -> Path:
    return (
        Path(__file__).resolve().parent.parent
        / "tools" / "procmon-configs" / DEFAULT_PROCMON_CONFIG_NAME
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--arm", action="store_true", help="register the ONSTART task")
    mode.add_argument("--disarm", action="store_true", help="remove it")
    mode.add_argument("--status", action="store_true", help="is it armed")
    mode.add_argument("--capture", action="store_true", help="run the capture (the task does this)")

    parser.add_argument("--out", help="directory for the pml, csv and manifest")
    parser.add_argument("--procmon", help="path to Procmon; do not name it procmon")
    parser.add_argument("--window", type=int, default=DEFAULT_WINDOW_SECONDS)
    parser.add_argument("--config", help=f"a .pmc; default {DEFAULT_PROCMON_CONFIG_NAME}")
    args = parser.parse_args(argv)

    if args.status:
        result = status()
        print(f"{TASK_NAME}: {'ARMED' if result['armed'] else 'not armed'}")
        if result["stdout"]:
            print(result["stdout"])
        return 0

    if args.disarm:
        result = disarm()
        print(f"{TASK_NAME}: {'removed' if result['ok'] else 'not removed'}")
        if not result["ok"] and result["stderr"]:
            print(result["stderr"], file=sys.stderr)
        return 0 if result["ok"] else 1

    if not args.out or not args.procmon:
        parser.error("--arm and --capture both need --out and --procmon")

    config = Path(args.config) if args.config else _default_config()
    if not config.exists():
        print(f"Procmon config not found: {config}", file=sys.stderr)
        return 2

    if Path(args.procmon).name.lower().startswith("procmon"):
        print(
            f"WARNING: {Path(args.procmon).name} contains 'procmon'. Samples that "
            "blocklist analysis tools by process name will see it. Use a renamed copy.",
            file=sys.stderr,
        )

    if args.capture:
        manifest = run_capture(args.out, args.procmon, args.window, config)
        print(json.dumps(manifest, indent=2))
        return 0 if manifest["completed"] else 1

    result = arm(args.out, args.procmon, args.window, config)
    print(f"{TASK_NAME}: {'armed' if result['ok'] else 'NOT armed'}")
    print(f"  runs: {result['command']}")
    if not result["ok"]:
        print(result["stderr"] or result["stdout"], file=sys.stderr)
        return 1
    print("\nReboot to start the capture. Read logon_capture.json before the CSV.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
