"""Read what Sysmon recorded this boot, and attribute it to a persisted payload.

    .venv\\Scripts\\python.exe scripts\\sysmon_since_boot.py ^
        --out C:\\logon-capture --image PlatformRuntime.exe

**This starts nothing.** Sysmon's driver is boot-start and its service
auto-start, so it was already recording before the logon that launched the
payload -- on every run this project has ever done, including the two
`ce0d08be...` detonations. The events are in the channel; this reads them.

That is what makes it the one collector with no ordering problem. The Procmon
logon capture has to be armed before a boot and then win a race against an
`ONLOGON` task, and the first attempt at that lost by 3m51s. Nothing here can
be late, because nothing here has to start.

**What it cannot see is reads.** There is no registry-read or file-read event
in Sysmon, at any configuration. An absence in this output is not evidence that
the payload read nothing -- that is what the Procmon capture is still for, and
`reads_covered: false` is in every manifest so the two cannot be confused.

`--image` is required and is refused by default rather than defaulted, for the
same reason `--analyse` refuses it in `logon_capture.py`: an ordinary boot
starts dozens of processes and makes ~450 VM-artifact registry reads of its
own, so a window with nothing to attribute to reports Windows as the sample.
Pass `--no-image` deliberately to read the whole boot unattributed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dynamic_analysis.sysmon_collector import (  # noqa: E402
    collect_since_boot,
    sysmon_status,
)


def _print_report(status: dict, summary: dict) -> None:
    boot = status.get("boot_time", {})
    print(f"boot        {boot.get('since_utc') or 'UNKNOWN'}"
          f"  (source {boot.get('source') or '-'},"
          f" uptime {boot.get('uptime_seconds', 0)}s)")
    if boot.get("note"):
        print(f"  ! {boot['note']}")

    if not status.get("success"):
        print(f"\ncollection FAILED: {status.get('error') or 'unknown'}")
        if status.get("diagnosis"):
            print(f"  {status['diagnosis']}")
        return

    print(f"events      {status.get('event_count', 0):,}"
          f"  ({status.get('first_event', '')} .. {status.get('last_event', '')})")
    if status.get("truncated"):
        print(f"  ! {status['truncation_note']}")
    if status.get("diagnosis"):
        print(f"  ! {status['diagnosis']}")

    payload = status.get("payload", {})
    if payload.get("seen"):
        offset = payload.get("seconds_after_boot")
        print(f"payload     {payload['image']} started {payload['first_seen']}"
              f"  ({offset}s after boot)"
              f"  {payload['process_creates']} process create(s),"
              f" pids {payload['pids']}")
    else:
        print(f"payload     {payload.get('image') or '(none given)'}: NOT SEEN")
    if status.get("lineage_note"):
        print(f"  ! {status['lineage_note']}")

    counts = summary.get("counts") or {}
    if counts:
        ordered = sorted(counts.items(), key=lambda item: -item[1])
        print("counts      " + "  ".join(f"{name}={count}" for name, count in ordered[:12]))

    for label, key in (("dns", "dns_queries"), ("network", "network_targets"),
                       ("pipes", "named_pipes")):
        values = summary.get(key) or []
        if values:
            extra = f"  (+{len(values) - 12} more)" if len(values) > 12 else ""
            print(f"{label:<11} " + ", ".join(str(v) for v in values[:12]) + extra)

    highlights = summary.get("highlights") or []
    if highlights:
        print(f"highlights  {len(highlights)} attributed to the payload")
        for item in highlights[:20]:
            print(f"  [{item.get('severity', '?')}] {item.get('title', '')}"
                  f"  {item.get('detail', '')}".rstrip())
    else:
        print("highlights  none attributed to the payload")

    # Kept visible for the reason the summary keeps them: "nothing happened"
    # and "it happened and was somebody else's" are different results.
    other = summary.get("other_process_events_excluded", 0)
    if other:
        print(f"            ({other} high-signal events by processes outside "
              "the payload tree)")

    print("\nreads       NOT COVERED -- Sysmon has no read event. "
          "An absence here says nothing about what the payload read.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, help="directory for the evtx and json")
    parser.add_argument("--image", default="", help="the persisted payload's image name")
    parser.add_argument(
        "--no-image", action="store_true",
        help="read the whole boot with no attribution, deliberately",
    )
    parser.add_argument("--max-events", type=int, default=20000)
    args = parser.parse_args(argv)

    if not args.image and not args.no_image:
        parser.error(
            "--image is required: an ordinary boot starts dozens of processes "
            "and a window with nothing to attribute to reports Windows as the "
            "sample. Pass --no-image to read it unattributed anyway."
        )

    preflight = sysmon_status()
    if not preflight.get("available"):
        print(f"Sysmon is not collectable here: {preflight.get('note', '')}", file=sys.stderr)
        return 2

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    events, summary, status = collect_since_boot(
        out / "sysmon_boot.evtx",
        image_name=args.image,
        max_events=args.max_events,
    )

    manifest = {"status": status, "summary": summary, "event_count": len(events)}
    manifest_path = out / "sysmon_boot.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, default=str), encoding="utf-8"
    )

    _print_report(status, summary)
    print(f"\nwrote {manifest_path}")
    return 0 if status.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
