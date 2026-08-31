"""VM-artifact registry reads out of a Procmon CSV, without loading it into memory.

`parse_procmon_csv` builds the whole event list before anything looks at it,
which is right for a normal run -- an orchestrated detonation exports a few tens
of megabytes -- and wrong for a boot log. The 31 Aug logon observation of
`ce0d08be...` produced a 4.2 GB `.pmb`, a 1.67 GB `.pml` and a **703 MB CSV even
with the registry-read filter applied**, because boot logging has no
capture-time filter and an hour of one machine's registry traffic is most of
what it holds. Several million rows as dicts is several gigabytes of guest RAM,
so the pass that answers the question has to stream.

    .venv\\Scripts\\python.exe scripts\\vm_reads_from_csv.py --csv C:\\temp\\logon_export.csv

Same classification as `collect_vm_artifact_reads`, deliberately: it calls
`classify_vm_artifact_path` rather than reimplementing the marker match, so a
marker added to `VM_ARTIFACT_MARKERS` is picked up here too and the two passes
cannot drift into disagreeing about what a VM artifact is.

**No lineage.** Every process is reported, with its name and PID, because that
is the question a boot log is being read for -- a logon-triggered payload has no
parent in the run and lineage would exclude the one process worth seeing. Read
the process column; Windows reads most of these keys itself.
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dynamic_analysis.procmon_parser import normalize_procmon_row
from dynamic_analysis.vm_artifact_reads import (
    classify_vm_artifact_path,
    is_registry_read,
)

#: Procmon writes a UTF-8 BOM and its CSV rows can carry embedded newlines in
#: `Detail`, so the file is opened the way `parse_procmon_csv` opens it.
_ENCODING = "utf-8-sig"

#: Rows between progress lines. A 703 MB export takes minutes to walk and a pass
#: that prints nothing until it finishes is indistinguishable from a hang -- the
#: same complaint this project already recorded against the headless CSV export.
_PROGRESS_EVERY = 1_000_000


def scan(csv_path: Path, progress: bool = True) -> dict[str, object]:
    rows = 0
    registry_reads = 0
    hits: list[dict[str, str | int | None]] = []
    seen: set[tuple[int | None, str]] = set()
    by_specificity: Counter[str] = Counter()
    by_process: Counter[str] = Counter()

    with csv_path.open("r", encoding=_ENCODING, newline="") as handle:
        for row in csv.DictReader(handle):
            rows += 1
            if progress and rows % _PROGRESS_EVERY == 0:
                print(f"  ...{rows:,} rows, {len(hits)} artifact reads", file=sys.stderr)

            event = normalize_procmon_row(row)
            if not is_registry_read(event):
                continue
            registry_reads += 1

            classified = classify_vm_artifact_path(event["path"])
            if classified is None:
                continue

            # One row per process per path, as `collect_vm_artifact_reads` does:
            # a sample that polls a key in a loop is one check, not a hundred.
            key = (event["pid"], str(event["path"]).lower())
            if key in seen:
                continue
            seen.add(key)

            by_specificity[classified["specificity"]] += 1
            by_process[event["process_name"]] += 1
            hits.append(
                {
                    "timestamp": event["timestamp"],
                    "pid": event["pid"],
                    "process_name": event["process_name"],
                    "operation": event["operation"],
                    "result": event["result"],
                    "path": event["path"],
                    **classified,
                }
            )

    return {
        "rows": rows,
        "registry_reads": registry_reads,
        "hits": hits,
        "by_specificity": dict(by_specificity),
        "by_process": dict(by_process),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--csv", required=True, help="a Procmon CSV export")
    parser.add_argument(
        "--process",
        help="only report reads by processes whose name contains this, case-insensitive",
    )
    parser.add_argument("--quiet", action="store_true", help="no progress lines")
    args = parser.parse_args(argv)

    csv_path = Path(args.csv)
    if not csv_path.is_file():
        print(f"not a file: {csv_path}", file=sys.stderr)
        return 2

    result = scan(csv_path, progress=not args.quiet)
    hits = result["hits"]
    if args.process:
        needle = args.process.lower()
        hits = [h for h in hits if needle in str(h["process_name"]).lower()]

    print(f"\n{result['rows']:,} rows, {result['registry_reads']:,} registry reads")
    print(f"{len(result['hits'])} VM-artifact reads: {result['by_specificity'] or '{}'}")

    vm_specific = [h for h in hits if h["specificity"] == "vm_specific"]
    if vm_specific:
        print(f"\n{len(vm_specific)} VM-SPECIFIC -- a key that only exists on a VM:\n")
        for hit in vm_specific:
            print(f"  {hit['process_name']} ({hit['pid']})  {hit['result']}")
            print(f"    {hit['artifact']} [{hit['family']}]  {hit['path']}")
    else:
        print("\nNo vm_specific read. Nothing asked a question only a VM can answer.")

    identity = [h for h in hits if h["specificity"] == "identity_surface"]
    if identity:
        print(f"\n{len(identity)} identity-surface -- read by VM checks and by inventory alike:\n")
        for hit in identity:
            print(f"  {hit['process_name']} ({hit['pid']})  {hit['result']}  {hit['path']}")

    if result["by_process"]:
        print("\nby process:")
        for name, count in sorted(result["by_process"].items(), key=lambda kv: -kv[1]):
            print(f"  {count:5}  {name}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
