"""Is the guest's executing stage 3 the same bytes as the bench's?

The crash chain has four links and they are mutually inconsistent. Both ends are
measured on the guest -- the cookie held the poison (`0bf`, the fault's register
file) and the loader list has nothing hashing to `0xe11da208` (`0bf`,
`guest_ldr_walk.py`). **Both middle links are claims derived from the bench
artifact**, not from the guest:

* *"only `rva 0x1605f` writes that value"* -- `0bb`'s 23-site census swept
  `stage3_alloc_at540M_dc038cc7`;
* *"that store is gated on a module hashing to `0xe11da208`"* -- same artifact,
  same disassembly.

And the guest ran from `PRIVATE COMMIT RWX`, `0x1010000 + 0x46000` (`0ba`) --
memory it could rewrite at will, which is exactly the case where "the image says
X" and "the process did X" come apart. `0ax` checked three bytes of it, found
the poison at the same three rvas, and concluded guest and artifact are the same
bytes. Three matching dwords out of 284,641 is not that claim.

    ..\\.venv\\Scripts\\python.exe guest_image_diff.py

Diffs the two byte for byte, clusters the differences into runs, and re-derives
**from the guest's own bytes** the two things the middle links assert: every
instruction referencing `+0x6d8`, and the disassembly of the gate block. A
difference at a site that matters is the mechanism; no difference hardens the
contradiction and moves the suspicion to the gate's *condition*.
"""
from __future__ import annotations

import argparse
import collections
import math
import re
import struct
import sys
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs, x86_const

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from dotnet_meta import XOR_SUFFIX, xor_unwrap  # noqa: E402
from dynamic_analysis import minidump  # noqa: E402

DUMP = r"C:\Users\aring\Downloads\ringforge\outputs\RegSvcs.exe.5272.dmp"
ARTIFACT = r"G:\ringforge-artifacts\422e30ed_stage2\stage3_alloc_at540M_dc038cc7.xor9"

GUEST_BASE, GUEST_SIZE = 0x01010000, 0x46000
POISON = 0x32DFD514

#: The gate block, from `0bb`. Disassembled from both images and compared.
GATE_FROM, GATE_TO = 0x1601B, 0x1606F

#: What `0bb` derived from the bench artifact, so a disagreement is loud.
BENCH_SITE_COUNT = 23
BENCH_STORES = (0x1605F, 0x26C91)

#: Runs of difference closer than this are reported as one.
CLUSTER_GAP = 16


def entropy(data: bytes) -> float:
    """Shannon entropy per byte. Ciphertext sits near 8, x86 code well below."""
    if not data:
        return 0.0
    counts = collections.Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def load_bench(path: Path) -> bytes:
    raw = path.read_bytes()
    return xor_unwrap(raw) if path.suffix == XOR_SUFFIX else raw


def load_guest(dump: minidump.Minidump) -> bytes | None:
    """The whole region, or None if the dump does not hold all of it.

    A partial read here would produce differences that are gaps in the dump
    rather than differences in the memory, which is the one way this comparison
    could invent a finding.
    """
    for va, file_offset, size in dump.memory_ranges():
        if va <= GUEST_BASE and va + size >= GUEST_BASE + GUEST_SIZE:
            start = file_offset + (GUEST_BASE - va)
            return bytes(dump._data[start:start + GUEST_SIZE])
    return None


def sites(image: bytes, base: int) -> list:
    """Every instruction referencing displacement +0x6d8, `0bb`'s method.

    Anchors on the displacement bytes and decodes backwards. The displacement
    must lie *inside* the instruction, not end it -- a store carrying an imm32
    runs four bytes past its own displacement, which is how the first version
    of this dropped the gate store itself.
    """
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    found = []
    for match in re.finditer(rb"\xd8\x06\x00\x00", image, re.S):
        offset = match.start()
        for back in range(2, 12):
            start = offset - back
            if start < 0:
                continue
            for ins in md.disasm(image[start:start + 16], base + start, count=1):
                if not (ins.address <= base + offset
                        and ins.address + ins.size >= base + offset + 4):
                    continue
                if any(op.type == x86_const.X86_OP_MEM and op.mem.disp == 0x6D8
                       for op in ins.operands):
                    found.append((ins.address - base, ins.mnemonic, ins.op_str))
                break
    return found


def disassemble(image: bytes, base: int, start: int, end: int) -> list[str]:
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    return [f"{ins.address - base:#07x}  {ins.mnemonic:<7} {ins.op_str}"
            for ins in md.disasm(image[start:end], base + start)]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dump", default=DUMP)
    ap.add_argument("--artifact", default=ARTIFACT)
    args = ap.parse_args(argv)

    dump = minidump.parse(Path(args.dump))
    guest = load_guest(dump)
    if guest is None:
        print(f"*** VOID: the dump does not hold all of "
              f"{GUEST_BASE:#x}+{GUEST_SIZE:#x}. A partial\n    comparison "
              f"would report the gaps as differences.")
        return 2
    bench = load_bench(Path(args.artifact))

    overlap = min(len(guest), len(bench))
    print(f"guest  {len(guest):,} bytes at {GUEST_BASE:#x} (from the dump)")
    print(f"bench  {len(bench):,} bytes (stage3_alloc_at540M)")
    print(f"comparing the first {overlap:,} bytes\n")

    differing = [i for i in range(overlap) if guest[i] != bench[i]]
    print(f"BYTES THAT DIFFER: {len(differing):,} of {overlap:,} "
          f"({100.0 * len(differing) / overlap:.4f}%)")

    clusters: list[list[int]] = []
    for index in differing:
        if clusters and index - clusters[-1][-1] <= CLUSTER_GAP:
            clusters[-1].append(index)
        else:
            clusters.append([index])
    print(f"IN {len(clusters)} RUN(S)\n")
    for run in clusters[:40]:
        start, stop = run[0], run[-1] + 1
        print(f"   rva {start:#07x}..{stop:#07x}  ({stop - start} bytes)")
        print(f"      bench {bench[start:stop][:24].hex(' ')}")
        print(f"      guest {guest[start:stop][:24].hex(' ')}")
    if len(clusters) > 40:
        print(f"   ... {len(clusters) - 40} more runs")

    # -- middle link 1: the store census, from the guest's bytes --------------
    guest_sites = sites(guest, GUEST_BASE)
    bench_sites = sites(bench, GUEST_BASE)
    guest_stores = tuple(rva for rva, mnem, ops in guest_sites
                         if ops.startswith("dword ptr [") or mnem == "mov"
                         and ops.split(",")[0].strip().startswith("dword ptr ["))
    print(f"\nMIDDLE LINK 1 -- every reference to +0x6d8, from the GUEST's bytes")
    print(f"   guest: {len(guest_sites)} sites     bench: {len(bench_sites)} "
          f"sites     (0bb recorded {BENCH_SITE_COUNT})")
    guest_rvas = {rva for rva, _m, _o in guest_sites}
    bench_rvas = {rva for rva, _m, _o in bench_sites}
    only_guest = sorted(guest_rvas - bench_rvas)
    only_bench = sorted(bench_rvas - guest_rvas)
    for rva in only_guest:
        entry = next(s for s in guest_sites if s[0] == rva)
        print(f"   *** ONLY IN THE GUEST: rva {rva:#07x}  {entry[1]} {entry[2]}")
    for rva in only_bench:
        print(f"   *** only in the bench: rva {rva:#07x}")
    if not only_guest and not only_bench:
        print("   Identical site sets. The guest's image holds the same "
              "references, so the")
        print("   'only rva 0x1605f writes it' link is now a statement about "
              "the guest too.")

    stores = [(rva, m, o) for rva, m, o in guest_sites
              if o.replace(" ", "").startswith("dwordptr[")]
    print(f"\n   stores into the field, in the guest's image: {len(stores)}")
    for rva, mnem, ops in stores:
        mark = "  <- the gate" if rva == BENCH_STORES[0] else ""
        print(f"      rva {rva:#07x}  {mnem} {ops}{mark}")

    # -- middle link 2: the gate block, from the guest's bytes ---------------
    print(f"\nMIDDLE LINK 2 -- the gate block "
          f"({GATE_FROM:#x}..{GATE_TO:#x}), from the GUEST's bytes")
    guest_code = disassemble(guest, GUEST_BASE, GATE_FROM, GATE_TO)
    bench_code = disassemble(bench, GUEST_BASE, GATE_FROM, GATE_TO)
    for line in guest_code:
        print(f"   {line}")
    if guest_code == bench_code:
        print("\n   Byte-identical to the bench. The gate's condition and its "
              "store are the same")
        print("   instructions the guest executed.")
    else:
        print("\n   *** THE GATE BLOCK DIFFERS FROM THE BENCH. This is the "
              "mechanism.")
        for line in bench_code:
            print(f"   bench: {line}")

    # -- and the poison, wherever it is in the guest's copy -------------------
    needle = struct.pack("<I", POISON)
    where = [m.start() for m in re.finditer(re.escape(needle), guest)]
    print(f"\nOccurrences of {POISON:#010x} in the guest's image: "
          f"{', '.join(hex(w) for w in where)}")

    # Are the differing runs ciphertext on one side? Stage 3 decrypts itself as
    # it runs -- 45 hash call sites at 47M blocks, 65 by 380M -- so an image
    # captured earlier is the same image less far through its own unpacking,
    # which is a completely different thing from a modified image.
    print("\nWHAT THE RUNS ARE:")
    for run in clusters:
        start, stop = run[0], run[-1] + 1
        g = entropy(guest[start:stop])
        b = entropy(bench[start:stop])
        verdict = ("guest still ENCRYPTED here" if g > b + 1.0 else
                   "bench still encrypted here" if b > g + 1.0 else
                   "*** neither looks like ciphertext -- a real modification")
        print(f"   rva {start:#07x}..{stop:#07x}  entropy guest {g:.2f} / "
              f"bench {b:.2f}   {verdict}")

    print("\nVERDICT:")
    if not differing:
        print("   The guest executed the bench's bytes exactly. Both middle "
              "links hold on the")
        print("   guest, so the contradiction is not explained by "
              "self-modification, and the")
        print("   remaining suspect is the gate's CONDITION -- "
              "get_module_base_by_hash returning")
        print("   non-zero for a reason other than a name match.")
    elif only_guest or guest_code != bench_code:
        print("   The differences reach code the chain depends on. Read the "
              "runs above against")
        print("   the site list -- the mechanism is in there.")
    else:
        ciphertext = all(entropy(guest[r[0]:r[-1] + 1])
                         > entropy(bench[r[0]:r[-1] + 1]) + 1.0
                         for r in clusters)
        if ciphertext:
            print("   Every differing run is ciphertext on the GUEST and "
                  "plaintext on the bench, so")
            print("   this is the same image caught earlier in its own "
                  "decryption -- not a modified")
            print("   one. Everything the chain rests on is byte-identical, so "
                  "both middle links")
            print("   hold on the guest and self-modification does not explain "
                  "the store.")
        else:
            print("   The images differ, but not at any site the chain rests "
                  "on. At least one run is")
            print("   not explained by decryption progress, which is worth "
                  "chasing on its own.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
