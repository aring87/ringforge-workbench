"""Did the guest actually have a module hashing to `0xe11da208`?

The crash that has ended eleven detonations is gated on a module lookup:
`mov dword [esi+0x6d8], 0x32dfd514` runs **only** when a lookup for module hash
`0xe11da208` -- `crc32("sbiedll.dll")`, Sandboxie's injected DLL -- succeeds.
Under emulation the lookup fails and the run survives; on the guest the constant
was stored anyway. 931 loaded-module names from the guest matched nothing.

That leaves one bit unmeasured, and it is measurable from a Procmon capture
rather than from another inference at the bench: **the complete `Load Image`
list for the sample's own processes**, which is what the loader list the sample
walks is actually made of. An inventory taken at another moment, or scoped to
the machine rather than to `RegSvcs.exe`, would miss a DLL injected into that
process and then unloaded -- and `sbiedll.dll` is precisely a DLL that other
software injects.

    ..\\.venv\\Scripts\\python.exe crash_gate_check.py <procmon.csv>
    ..\\.venv\\Scripts\\python.exe crash_gate_check.py <procmon.csv> --process RegSvcs.exe

Hashes every image loaded into the sample's processes, in load order, and says
whether any of them is the one the gate wants. Both shipped Procmon configs
include `Load Image`, so a run captured with either can answer this.

**If something matches**, the gate was right, the guest genuinely had it, and
the question becomes what put it there -- including the possibility that it is
the analysis tooling. **If nothing matches**, the gate is not what this project
thinks it is, and "broken build" and "deliberate bail" both stay live with one
more route closed.
"""
from __future__ import annotations

import argparse
import sys
from collections import OrderedDict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dynamic_analysis.procmon_parser import parse_procmon_csv  # noqa: E402

#: The gate. `crc32("sbiedll.dll")` under the sample's variant.
WANTED = 0xE11DA208

#: Everything else this project has cracked or is still carrying, so a capture
#: that answers the main question also reports on the rest for free.
KNOWN = {
    0xE11DA208: "sbiedll.dll (the crash gate)",
    0x9CB95240: "sharedintapp.exe (Parallels)",
    0x0B4E1AE2: "ntdll.dll",
    0xADEDAB08: "kernel32.dll",
    0xC810589C: "user32.dll",
}


def crc(name: bytes) -> int:
    """CRC-32/MPEG-2: init 0xFFFFFFFF, non-reflected, poly 0x04C11DB7, final NOT."""
    value = 0xFFFFFFFF
    for byte in name:
        value ^= byte << 24
        for _ in range(8):
            value = ((value << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if value & 0x80000000 \
                else (value << 1) & 0xFFFFFFFF
    return (~value) & 0xFFFFFFFF


def variants(basename: str):
    """The forms the sample might hash. It lowercases before hashing, and this
    project has been caught out twice by assuming a single form -- once by
    hashing filenames when the answer was a bare stem, once by hashing stems
    when the answer was a fixed-length substring."""
    stem = basename.rsplit(".", 1)[0]
    for text in OrderedDict.fromkeys((basename.lower(), stem.lower())):
        yield text, text.encode()
        yield f"{text} (utf-16le)", text.encode("utf-16-le")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", help="Procmon CSV from the run")
    ap.add_argument("--process", action="append", default=[],
                    help="process name to scope to; repeatable. Default: every "
                         "process that loaded an image")
    args = ap.parse_args(argv)

    # Self-check first. A cracker validated only by finding something will
    # always find something.
    assert crc(b"ntdll.dll") == 0x0B4E1AE2, "crc is wrong; every line below is noise"
    assert crc(b"sbiedll.dll") == WANTED, "crc does not reproduce the gate value"
    print(f"crc self-check: ntdll.dll {crc(b'ntdll.dll'):#010x}, "
          f"sbiedll.dll {crc(b'sbiedll.dll'):#010x}  (both as recorded)\n")

    events = parse_procmon_csv(args.csv)
    loads = [e for e in events if e["category"] == "image_load"]
    if not loads:
        print("*** VOID: no `Load Image` events in this capture.")
        print("    Either the run collected none, or the Procmon filter dropped "
              "them. Check with")
        print("    `python -m dynamic_analysis.procmon_config <config.pmc>` "
              "before reading anything into it.")
        return 2

    wanted_procs = {p.lower() for p in args.process}
    scoped = [e for e in loads
              if not wanted_procs or e["process_name"].lower() in wanted_procs]
    procs = sorted({e["process_name"] for e in scoped})
    print(f"{len(loads):,} Load Image event(s), {len(scoped):,} in scope "
          f"across {len(procs)} process(es): {', '.join(procs) or 'none'}\n")

    hits, seen, forms = [], OrderedDict(), 0
    for event in scoped:
        basename = event["path"].rsplit("\\", 1)[-1]
        if not basename:
            continue
        key = (event["process_name"], basename.lower())
        if key in seen:
            continue
        seen[key] = event
        for label, blob in variants(basename):
            forms += 1
            value = crc(blob)
            if value == WANTED:
                hits.append((event, label, value))

    # Counted from the names actually hashed. The first version reported
    # `len(variants('x'))`, which is the count for a dummy string with no
    # extension -- two, where a real filename gives four. A number that is
    # wrong only for the inputs you did not use is the kind this file keeps
    # having to retract.
    print(f"{len(seen)} distinct (process, image) pair(s) hashed, "
          f"{forms} form(s) in total.\n")

    print(f"DOES ANYTHING HASH TO {WANTED:#010x}?")
    if hits:
        for event, label, value in hits:
            print(f"   *** MATCH: {event['process_name']} loaded "
                  f"{event['path']} as {label!r}")
        print("\n   The gate was right and the guest had it. What put it there "
              "is the next question --")
        print("   including the possibility that it is this pipeline's own "
              "tooling, which has")
        print("   contaminated two detectors already (`WerFault.exe`, "
              "`procdump64.exe`).")
    else:
        print("   No. Nothing loaded into the scoped processes hashes to it, "
              "in any form tried.")
        print("   The lookup should have failed on the guest as it does under "
              "emulation, and the")
        print("   crash still needs another explanation. **This is a negative "
              "with a bound, not a")
        print("   proof**: an image loaded and unloaded between Procmon's "
              "capture window and the")
        print("   check would not appear here.")

    other = {v: n for v, n in KNOWN.items() if v != WANTED}
    found = []
    for (proc, base), event in seen.items():
        for _, blob in variants(base):
            value = crc(blob)
            if value in other:
                found.append((proc, base, value, other[value]))
    if found:
        print("\nPOSITIVE CONTROLS (known hashes seen in this capture):")
        for proc, base, value, name in sorted(set(found)):
            print(f"   {value:#010x}  {name:32} loaded by {proc}")
        print("   These confirm the hash and the capture agree; a run with "
              "none of them is suspect.")
    else:
        print("\n*** No known hash matched either, not even `ntdll.dll`. "
              "Treat the negative above as")
        print("    unproven until that is explained -- it is the positive "
              "control for this check.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
