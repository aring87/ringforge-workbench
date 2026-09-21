r"""Re-test the rule that takes `process_injection` to strong on one image.

`orchestrator.py` makes the category **strong** on `unmapped_pe_images > 0`.
One image is enough, and the benign basis behind it is stated in that file as
what it is: *"16 ordinary processes on one host, zero unmapped PE images"*,
with the author's own warning that the zero "does not by itself carry `strong`
on any unmapped image anywhere".

`benign-102-v2` is the first corpus large enough to test it, and it disagrees.
All three samples that reached **Strongly Corroborated** were driven by this
rule and all three are legitimate signed software:

    Docker-Desktop-Installer      105    4 unmapped images
    OverwolfUpdater               110    3 unmapped images
    old_OverwolfUpdater           110    3 unmapped images

What the images actually are
----------------------------

The Overwolf pair carved successfully and could be identified. Both produced
**one** distinct image, byte-identical across two different binaries, two
processes and two addresses:

    Newtonsoft.Json 13.0.1.25517 -- "Json.NET is a popular high-performance
    JSON framework", Copyright (c) James Newton-King 2008

The most widely used library in the .NET ecosystem, loaded from a byte array.
`layout: "file"` is the tell: an assembly loaded via `Assembly.Load(byte[])`
is never section-mapped, so it cannot look mapped to the carver. The existing
exclusions do not cover it -- `framework_assembly` catches what ships *with*
.NET by module name, `resource_only` catches images with no code, and an
application's own bundled third-party dependency is neither.

Two things this measures
------------------------

* **dedup** -- one image seen in four dumps is counted four times. The same
  image at the same address with the same `carved_sha256` is one image. This
  does not change `> 0`, so it changes no verdict; it changes what the
  evidence line claims, which is the part a reader acts on.
* **bundled assemblies** -- a .NET image in file layout whose carved bytes
  carry a recognisable assembly identity is a dependency, not a payload.

**WHAT THIS CANNOT TELL YOU, AND IT MATTERS MOST**
--------------------------------------------------

`capability_sweep.py` accepts a change only if detection rises while the
benign rate does not. **That test cannot be run here.** `pe_carve` needs
memory dumps, so it needs a *detonation*, and the only detonated corpus on
this bench is the benign one. The malware corpora under
`Downloads\ringforge\cases` are static cases with no dynamic runs in them.

So this prints a benign rate and no lift. A benign rate alone is exactly the
evidence that produced the rule being questioned -- 16 processes, zero images
-- and half an argument twice does not make a whole one. **Nothing should be
changed on the strength of this file.** What it establishes is that the
current rule misfires on ordinary .NET software and roughly how often; what
would justify a change is the same measurement over a detonated malware
corpus, which does not exist yet.

    .venv\\Scripts\\python.exe scripts\\injection_sweep.py

Nothing here edits the rule.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

#: Every detonated corpus on this bench. Add malware here the day one exists
#: -- that is the missing half, and the reason this file refuses to conclude.
_DETONATED = {
    "benign-102-v2": r"G:\ringforge-runs\benign-102-v2\cases",
}

#: Assembly names that identify a carved image as a dependency rather than a
#: payload. Deliberately short and evidence-backed: every member here was
#: found in a carved image from this corpus, not imagined.
_BUNDLED_MARKERS = (
    b"Newtonsoft.Json",
)


def carve_summaries(root: Path):
    """Every dynamic run under a corpus, with its carve counts and images."""
    for summary in sorted(Path(root).rglob("dynamic_run_summary.json")):
        try:
            document = json.loads(summary.read_text(encoding="utf-8-sig"))
        except Exception:                             # noqa: BLE001
            continue
        carve = document.get("pe_carve_summary") or {}
        if not carve.get("counts"):
            continue
        # `<case>/dynamic_analysis/dynamic_runs/<run>/metadata/<this>`
        yield summary.parents[4], carve


def identify(case_home: Path, image: dict) -> str:
    """What a carved image is, when its bytes are still on disk.

    Returns one of `bundled`, `unidentified`, or `gone`. **`gone` is not a
    bookkeeping detail**: two of the four cases that carved anything came home
    with an empty `carved\\` directory while every JSON beside it survived, so
    the evidence for the highest-severity finding this pipeline produces is
    sometimes absent by the time anyone looks.
    """
    name = str(image.get("carved_file") or "")
    if not name:
        return "gone"
    hits = glob.glob(str(case_home / "**" / "carved" / name), recursive=True)
    if not hits:
        return "gone"
    try:
        raw = Path(hits[0]).read_bytes()
    except OSError:
        return "gone"
    if any(marker in raw for marker in _BUNDLED_MARKERS):
        return "bundled"
    return "unidentified"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.parse_args(argv)

    for label, root in _DETONATED.items():
        if not Path(root).is_dir():
            print(f"{label}: not on this host ({root})")
            continue

        runs = 0
        fires = 0                 # runs the shipped rule calls strong
        after_dedup = 0           # ... counting one image once
        after_bundled = 0         # ... and setting bundled dependencies aside
        detail = []

        for case_home, carve in carve_summaries(Path(root)):
            runs += 1
            counts = carve.get("counts") or {}
            images = carve.get("images") or []
            unmapped = [i for i in images
                        if i.get("classification") == "unmapped"]
            reported = int(counts.get("unmapped_images", 0) or 0)
            if reported <= 0:
                continue

            fires += 1
            distinct = {(i.get("carved_sha256"), i.get("virtual_address"))
                        for i in unmapped}
            if distinct:
                after_dedup += 1

            kinds = [identify(case_home, i) for i in unmapped]
            remaining = {
                key for key, kind in zip(
                    [(i.get("carved_sha256"), i.get("virtual_address"))
                     for i in unmapped], kinds)
                if kind != "bundled"
            }
            if remaining:
                after_bundled += 1

            detail.append((case_home.name, reported, len(distinct),
                           kinds.count("bundled"), kinds.count("gone"),
                           kinds.count("unidentified")))

        print(f"=== {label}: {runs} detonated run(s)")
        if not runs:
            continue
        print(f"{'case':40s} {'counted':>8} {'distinct':>9} "
              f"{'bundled':>8} {'gone':>6} {'unknown':>8}")
        for row in detail:
            print(f"{row[0][:40]:40s} {row[1]:8d} {row[2]:9d} "
                  f"{row[3]:8d} {row[4]:6d} {row[5]:8d}")

        def rate(n):
            return 100.0 * n / runs if runs else 0.0

        print()
        print(f"{'rule':44s} {'fires':>6} {'benign rate':>12}")
        print(f"{'shipped: unmapped_images > 0':44s} {fires:6d} "
              f"{rate(fires):11.1f}%")
        print(f"{'deduplicated by (sha256, address)':44s} {after_dedup:6d} "
              f"{rate(after_dedup):11.1f}%")
        print(f"{'... and bundled assemblies set aside':44s} "
              f"{after_bundled:6d} {rate(after_bundled):11.1f}%")

        # The last figure is an upper bound, not a measurement. A case whose
        # carved bytes are gone cannot be shown to be a dependency, so it
        # counts against the change it might have supported.
        unprovable = sum(1 for row in detail if row[4] and not row[3])
        if unprovable:
            print()
            print(f"  {unprovable} of the {fires} firing case(s) carved "
                  f"nothing that survived, so they cannot be identified "
                  f"either way.")
            print(f"  The {rate(after_bundled):.1f}% is therefore a ceiling: "
                  f"it counts every unidentifiable case as a real finding, "
                  f"and the floor is "
                  f"{rate(max(0, after_bundled - unprovable)):.1f}%.")
        print()

    print("NO LIFT IS PRINTED, AND THAT IS THE POINT.")
    print("  pe_carve needs memory dumps, so it needs a detonation, and the")
    print("  only detonated corpus here is benign. A benign rate on its own is")
    print("  what produced the rule being questioned -- 16 processes, zero")
    print("  images. Nothing should change until the same measurement exists")
    print("  over a detonated malware corpus.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
