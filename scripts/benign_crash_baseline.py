"""The WER image-timestamp check, measured against this host's real crashes.

The benign rate for this detector cannot come from a benign detonation, and
noticing that saves a VM run. The check only evaluates processes that *crashed*
-- it reads `app_timestamp` off Application Error 1000 -- so ordinary software
running normally produces `checked: 0` and says nothing at all. The question is
not "what does it do on benign software", it is **"given a benign crash, does
the running image disagree with the file?"**

Which is answerable here and now: Windows keeps every Application Error event
this machine has recorded, and essentially all of them are ordinary software
falling over. That is a benign crash corpus nobody had to produce.

**The one expected false positive is worth predicting before looking**, because
it is the failure mode that decided the scoring gate: a process that was running
when Windows Update replaced its binary will report a mismatch, correctly and
benignly. If those turn up here they are the signal working, not failing -- and
they are precisely why `strong` requires the process to be one loaders hollow,
since a hollowing target is spawned on demand and cannot outlive an update.

    ..\\.venv\\Scripts\\python.exe benign_crash_baseline.py --days 90
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dynamic_analysis.crash_evidence import (
    APPLICATION_ERROR_EVENT_ID,
    check_image_timestamp,
    is_hollowing_target,
    parse_crash_event,
    summarize_image_timestamps,
)
from dynamic_analysis.sysmon_collector import parse_rendered_xml


def query(days: int, limit: int) -> list[dict]:
    """Every Application Error 1000 in the window, straight from the log."""
    ms = days * 24 * 60 * 60 * 1000
    xpath = (
        f"*[System[EventID={APPLICATION_ERROR_EVENT_ID} and "
        f"TimeCreated[timediff(@SystemTime) <= {ms}]]]"
    )
    cmd = ["wevtutil", "qe", "Application", f"/q:{xpath}",
           "/f:RenderedXml", f"/c:{limit}", "/rd:true"]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if out.returncode != 0:
        print(f"wevtutil failed: {out.stderr.strip()[:200]}")
        return []
    events = parse_rendered_xml(out.stdout or "")
    return [e for e in events if e.get("event_id") == APPLICATION_ERROR_EVENT_ID]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--days", type=int, default=90)
    ap.add_argument("--limit", type=int, default=400)
    args = ap.parse_args()

    events = query(args.days, args.limit)
    print(f"{len(events)} Application Error 1000 event(s) in the last {args.days} days\n")
    if not events:
        print("No benign crash corpus on this host. Nothing measured -- which is "
              "a statement about this machine, not about the detector.")
        return 1

    records = [parse_crash_event(e) for e in events]
    summary = summarize_image_timestamps(records)
    counts = summary["counts"]

    processes = Counter(r.get("app_name", "") for r in records)
    print("crashing processes:")
    for name, n in processes.most_common(12):
        print(f"    {name or '<blank>':<40} {n}")

    print()
    print("=" * 72)
    print("the WER image-timestamp check against benign crashes")
    print("=" * 72)
    for key in ("checked", "comparable", "mismatch",
                "mismatch_in_hollowing_target", "no_reference", "unparsable"):
        print(f"  {key:<34} {counts[key]}")

    comparable = counts["comparable"]
    if comparable:
        rate = counts["mismatch"] / comparable
        print()
        print(f"  benign mismatch rate           {counts['mismatch']}/{comparable}"
              f"  ({rate:.1%})")
        print(f"  in a hollowing target          "
              f"{counts['mismatch_in_hollowing_target']}   <-- the branch that scores")

    if summary["mismatches"]:
        print()
        print("every benign mismatch, named -- check each against Windows servicing:")
        for m in summary["mismatches"]:
            flag = "  [HOLLOWING TARGET]" if m["hollowing_target"] else ""
            print(f"    {m['process']:<34} running {m['recorded']} "
                  f"file {m['on_disk']}{flag}")

    if counts["no_reference"]:
        print()
        print(f"  {counts['no_reference']} crash(es) named a binary that is no longer "
              f"on disk -- counted, never read as agreement:")
        for name in summary["no_reference_processes"][:10]:
            print(f"    {name}")

    out = Path(os.environ.get("TEMP", ".")) / "benign_crash_baseline.json"
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"\nwritten to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
