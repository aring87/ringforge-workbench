"""Arm, disarm and run the logon capture. The guest-side entry point.

    .venv\\Scripts\\python.exe scripts\\logon_capture.py --arm --gate-logon ^
        --out C:\\logon-capture ^
        --procmon C:\\...\\tools\\rf_trace64.exe --window 600

    ... reboot; nothing logs on; the host drives the logon once the capture
        signals, with scripts\\vm_gated_logon.ps1 ...

    .venv\\Scripts\\python.exe scripts\\logon_capture.py --status
    .venv\\Scripts\\python.exe scripts\\logon_capture.py --analyse ^
        --out C:\\logon-capture --image ce0d08be....exe
    .venv\\Scripts\\python.exe scripts\\logon_capture.py --disarm

`--analyse` runs the detonation's own passes over what was captured and writes
`logon_analysis.json`. It needs `--image` -- the persisted payload's image name,
which a detonation names in its dropped-files output -- because lineage is the
only thing separating the payload from the machine's own boot, and an ordinary
boot makes 448 VM-artifact reads of its own.

`--gate-logon` is what makes the ordering hold. It sets `AutoAdminLogon` to 0,
so the boot reaches a sign-in screen and stops: no logon session, so no
`ONLOGON` task fires, so the capture cannot be beaten to the payload however
late Task Scheduler starts it. `--ungate` puts it back, and is the whole way
back -- the stored user name and password are never touched.

Without the flag this races the payload, and the race was measured lost by
3m51s on 31 Aug.

`--capture` is what the scheduled task invokes and is not normally typed by
hand. See `dynamic_analysis/logon_capture.py` for what ONSTART was assumed to
do, what it actually does, and the ordering rule that keeps this task out of
the run's task diffs.

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
    READY_PROPERTY,
    TASK_NAME,
    arm,
    disarm,
    read_autologon,
    run_capture,
    set_autologon,
    status,
)
from dynamic_analysis.logon_analysis import analyse_logon_capture  # noqa: E402
from dynamic_analysis.procmon_config import DEFAULT_PROCMON_CONFIG_NAME  # noqa: E402
from dynamic_analysis.procmon_parser import parse_procmon_csv  # noqa: E402


def _analyse(args) -> int:
    """Run the detonation passes over a finished capture.

    Needs `--image`, and refuses without it rather than defaulting to something.
    Lineage is the only thing separating the payload from the machine's own boot
    -- 448 VM-artifact reads on an ordinary one, every one background -- so a
    run with nothing to attribute to would report Windows as the sample.
    """
    if not args.out or not args.image:
        print("--analyse needs --out and --image", file=sys.stderr)
        return 2

    out = Path(args.out)
    csv_path = Path(args.csv) if getattr(args, "csv", None) else out / "logon_capture.csv"
    if not csv_path.is_file():
        print(f"no capture CSV at {csv_path}", file=sys.stderr)
        return 2

    manifest_path = out / "logon_capture.json"
    manifest = {}
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except ValueError:
            print(f"WARNING: {manifest_path} is unreadable", file=sys.stderr)

    events = parse_procmon_csv(csv_path)
    result = analyse_logon_capture(events, args.image, manifest=manifest)

    out_path = out / "logon_analysis.json"
    out_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")

    print(f"{result['event_count']:,} events, lineage "
          f"{'resolved' if result['lineage_resolved'] else 'NOT resolved'}"
          f" ({len(result['descendant_pids'])} pids)")
    counts = result["vm_artifact_reads"]["counts"]
    print(f"  vm_specific {counts['vm_specific']}  identity {counts['identity_surface']}"
          f"  background {counts['background_artifact_reads']}")
    print(f"  vm_check_and_bail: {result['vm_check_and_bail']['verdict']}")
    for line in result["findings"].get("highlights", []):
        print(f"  {line}")
    if result["note"]:
        print(f"\n{result['note']}")
    print(f"\nwrote {out_path}")
    return 0



def _gate(args) -> int:
    """Close or open the gate, and say what the machine will do at next boot.

    Closing it is what removes the race. With `AutoAdminLogon` at 0 the boot
    stops at the sign-in screen, no logon session is created, and the sample's
    `ONLOGON` task does not fire -- so the capture can be as late as Task
    Scheduler likes and still be first.
    """
    enabled = bool(args.ungate)
    before = read_autologon()
    result = set_autologon(enabled)

    if result["error"]:
        print(f"gate: NOT changed -- {result['error']}", file=sys.stderr)
        return 1

    state = "OPEN (autologon on)" if enabled else "CLOSED (no logon at boot)"
    print(f"gate: {state}")
    print(f"  AutoAdminLogon {before['auto_admin_logon'] or '(unset)'} -> {result['now']}")

    if not enabled:
        print()
        print("The machine will boot to the sign-in screen and stop there. "
              "DefaultUserName and DefaultPassword are untouched, so --ungate "
              "is the whole way back.")
    return 0


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
    mode.add_argument("--analyse", action="store_true", help="run the passes over a finished capture")
    mode.add_argument("--gate", action="store_true", help="close the gate: AutoAdminLogon 0")
    mode.add_argument("--ungate", action="store_true", help="open it again: AutoAdminLogon 1")

    parser.add_argument(
        "--gate-logon", action="store_true",
        help="with --arm: close the gate too, so the boot reaches no logon",
    )

    parser.add_argument("--out", help="directory for the pml, csv and manifest")
    parser.add_argument("--procmon", help="path to Procmon; do not name it procmon")
    parser.add_argument("--window", type=int, default=DEFAULT_WINDOW_SECONDS)
    parser.add_argument("--config", help=f"a .pmc; default {DEFAULT_PROCMON_CONFIG_NAME}")
    parser.add_argument("--image", help="the persisted payload's image name, for --analyse")
    parser.add_argument("--csv", help="a capture CSV; default <out>/logon_capture.csv")
    args = parser.parse_args(argv)

    if args.analyse:
        return _analyse(args)

    if args.gate or args.ungate:
        return _gate(args)

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

    result = arm(args.out, args.procmon, args.window, config, gate_logon=args.gate_logon)
    print(f"{TASK_NAME}: {'armed' if result['ok'] else 'NOT armed'}")
    print(f"  runs: {result['command']}")
    if not result["ok"]:
        print(result["stderr"] or result["stdout"], file=sys.stderr)
        return 1

    gate = result.get("gate") or {}
    if args.gate_logon:
        if not gate.get("changed"):
            print(f"  gate: NOT CLOSED -- {gate.get('error') or 'unknown'}", file=sys.stderr)
            print("  The boot would reach a logon and the payload would start "
                  "before the capture. Fix this before rebooting.", file=sys.stderr)
            return 1
        print(f"  gate: CLOSED (AutoAdminLogon {gate['previous'] or '(unset)'} -> 0)")
        print()
        print("Reboot. Nothing will log on, so no ONLOGON task fires -- the "
              f"sample's included. The capture signals {READY_PROPERTY} once "
              "its backing file is confirmed, and scripts/vm_gated_logon.ps1 "
              "on the host types the credentials from there.")
        return 0

    print()
    print("Reboot to start the capture. Read logon_capture.json before the CSV.")
    print("WARNING: the gate is open, so this races the payload to the logon -- "
          "and lost by 3m51s the last time. Use --gate-logon unless you mean "
          "to race it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
