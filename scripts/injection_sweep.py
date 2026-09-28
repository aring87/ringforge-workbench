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

**The malware half, 28 Sep -- and the answer is keep the shipped rule**
----------------------------------------------------------------------

Until `mal-112b` this printed a benign rate and refused to print a lift,
because a benign rate alone is what produced the rule being questioned. With
89 benign and 82 malware detonations:

    shipped: unmapped_images > 0            4.5%   29.3%    6.5x
    deduplicated by (sha256, address)       4.5%   29.3%    6.5x
    ... and bundled assemblies set aside    2.2%   28.0%   12.5x

**The lift says ship the bundled exclusion; the verdicts say do not.**
Re-scoring copies of the three cases it touches, with a control that
reproduced each stored band first: both Overwolf updaters stay **Strongly
Corroborated** (110 -> 75; four other categories hold the band), and
malware `5b95fac31cea` -- **RedLine** -- falls **Corroborated 70 -> Single
Observation 35**, losing its only strong signal. RedLine bundles
Newtonsoft.Json exactly as Overwolf does, so a bundled Json.NET image is
not a benign tell. The benign false positives this file was written about
are no longer carried by this rule alone, and the one verdict the change
moves is a stealer's.

Dedup changes no verdict; it only makes the evidence line count true images.

The denominator is every run with a `dynamic_run_summary.json`. **28 of the
109 usable `mal-112b` cases have none** -- 17 lost the dynamic module to
Procmon's 120 s `/SaveAs` export limit, 8 would not execute, 2 are DLLs the
orchestrator refuses, 1 an SSL error -- and 9 of 98 benign are ARM64 builds
that never ran. They are not detonations and are not counted.

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

#: Every detonated corpus on this bench, by side. The malware half arrived 28
#: Sep: `mal-112b`, 109 usable of 112, plus sample 1 run on its own as
#: `mal-112b-s1` after a Bitdefender path block voided it in the sweep. The
#: diagnostic runs (`vidar-diag-*`, `remcos-diag-*`, `rehearsal-*`) repeat
#: samples already counted here and are deliberately left out.
_BENIGN_DETONATED = {
    "benign-102-v2": r"G:\ringforge-runs\benign-102-v2\cases",
}
_MALWARE_DETONATED = {
    "mal-112b": r"G:\ringforge-runs\mal-112b\cases",
    "mal-112b-s1": r"G:\ringforge-runs\mal-112b-s1\cases",
}

#: Assembly names that identify a carved image as a dependency rather than a
#: payload. Deliberately short and evidence-backed: every member here was
#: found in a carved image from this corpus, not imagined.
_BUNDLED_MARKERS = (
    b"Newtonsoft.Json",
)


def carve_summaries(root: Path):
    """Every dynamic run under a corpus, with its carve counts and images.

    **Every run that detonated, including the ones the carver had nothing
    from.** An empty `pe_carve_summary` means no dump was carved, so the rule
    cannot fire -- that is a detonation that did not fire, and it belongs in
    the denominator. This used to skip them, which dropped 8 of 89 benign and
    7 of 82 malware detonations and inflated both rates. A case with no
    `dynamic_run_summary.json` at all never detonated (static-only) and is
    not a detonation of any kind, so it is correctly absent.
    """
    for summary in sorted(Path(root).rglob("dynamic_run_summary.json")):
        try:
            document = json.loads(summary.read_text(encoding="utf-8-sig"))
        except Exception:                             # noqa: BLE001
            continue
        carve = document.get("pe_carve_summary") or {}
        # `<case>/dynamic_analysis/dynamic_runs/<run>/metadata/<this>`
        yield summary.parents[4], carve


def identify(case_home: Path, image: dict) -> str:
    """What a carved image is, when its bytes are still on disk.

    Returns one of `bundled`, `unidentified`, or `gone`. **`gone` is not a
    bookkeeping detail**: two of the four cases that carved anything came home
    with an empty `carved\\` directory while every JSON beside it survived, so
    the evidence for the highest-severity finding this pipeline produces is
    sometimes absent by the time anyone looks.

    **Why, established 22 Sep:** MAX_PATH on the *destination*, not antivirus.
    A carved image's name is long -- process, pid, trigger and hex address --
    and it sits at the deepest point of a tree whose case name is repeated by
    the doubled `cases/<case>/<case>/` segment. Every one of the 92 files the
    corpus lost had a destination path at or past 260 characters, and every
    file it kept was under. Fixed by `_extended()` in `runcontrol/collect.py`,
    so a later corpus does not lose them; `benign-102-v2` cannot be repaired,
    because the files were never copied and the exchange is wiped per sample.
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


def measure(root: Path) -> dict:
    """The three rule variants over one corpus, with per-case detail."""
    runs = 0
    fires = 0                 # runs the shipped rule calls strong
    after_dedup = 0           # ... counting one image once
    after_bundled = 0         # ... and setting bundled dependencies aside
    detail = []

    for case_home, carve in carve_summaries(root):
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

    # A case whose carved bytes are gone cannot be shown to be a dependency,
    # so it counts against the change it might have supported.
    unprovable = sum(1 for row in detail if row[4] and not row[3])
    return {"runs": runs, "fires": fires, "after_dedup": after_dedup,
            "after_bundled": after_bundled, "unprovable": unprovable,
            "detail": detail}


def _pool(results: list[dict]) -> dict:
    keys = ("runs", "fires", "after_dedup", "after_bundled", "unprovable")
    return {k: sum(r[k] for r in results) for k in keys}


def _pct(n: int, d: int) -> float:
    return 100.0 * n / d if d else 0.0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.parse_args(argv)

    sides: dict[str, list[dict]] = {"benign": [], "malware": []}
    for side, corpora in (("benign", _BENIGN_DETONATED),
                          ("malware", _MALWARE_DETONATED)):
        for label, root in corpora.items():
            if not Path(root).is_dir():
                print(f"{label}: not on this host ({root})")
                continue
            result = measure(Path(root))
            sides[side].append(result)

            print(f"=== {label} ({side}): {result['runs']} detonated run(s), "
                  f"{result['fires']} firing")
            if result["detail"]:
                print(f"{'case':40s} {'counted':>8} {'distinct':>9} "
                      f"{'bundled':>8} {'gone':>6} {'unknown':>8}")
                for row in result["detail"]:
                    print(f"{row[0][:40]:40s} {row[1]:8d} {row[2]:9d} "
                          f"{row[3]:8d} {row[4]:6d} {row[5]:8d}")
            print()

    benign, malware = _pool(sides["benign"]), _pool(sides["malware"])
    if not benign["runs"] or not malware["runs"]:
        print("NO LIFT: one side has no detonated runs on this host. A rate")
        print("  on one side alone is what produced the rule being questioned.")
        return 0

    print(f"=== lift: {benign['runs']} benign against {malware['runs']} "
          f"malware detonations")
    print(f"{'rule':40s} {'benign':>13} {'malware':>14} {'lift':>7}")
    for label, key in (("shipped: unmapped_images > 0", "fires"),
                       ("deduplicated by (sha256, address)", "after_dedup"),
                       ("... and bundled assemblies set aside",
                        "after_bundled")):
        b, m = benign[key], malware[key]
        rb, rm = _pct(b, benign["runs"]), _pct(m, malware["runs"])
        lift = f"{rm / rb:.1f}x" if rb else "inf"
        print(f"{label:40s} {b:3d} {rb:7.1f}%  {m:4d} {rm:7.1f}% {lift:>7}")

    # The bundled figures are bounds, not measurements, on both sides: a
    # firing case whose carved bytes are gone can be shown to be neither a
    # dependency nor a payload, so it is counted as still firing.
    for side, pooled in (("benign", benign), ("malware", malware)):
        if pooled["unprovable"]:
            print(f"  {side}: {pooled['unprovable']} firing case(s) carved "
                  f"nothing that survived and cannot be identified either "
                  f"way; the bundled row counts them as still firing.")
    print()
    print("Nothing here edits the rule. A change is justified only if the")
    print("benign rate falls while the malware rate holds -- read both columns.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
