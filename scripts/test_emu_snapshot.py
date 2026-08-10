"""Equivalence check for the emulator's snapshot/restore.

A restore that is subtly wrong would corrupt every diagnostic built on it while
still looking entirely plausible, so this compares two paths that must agree:
run straight to N instructions, versus restore a snapshot taken at M and resume
for N-M. It checks the instruction pointer, all sixteen saved registers, the
block count and a SHA-256 over every mapped region.

It has already earned its place. The first version of the restore reproduced
memory and registers bit-for-bit and was off by one block, because `emu_start`
re-fires the block hook for the block it resumes into and that block was already
counted before the snapshot. A single block is nothing on its own; across a
chain of snapshots it is drift that nothing else would have surfaced.

Needs a snapshot to exist first:

    python scripts/emulate_native_stub.py PAYLOAD --entry 0x2680         --blocks 60000000 --save-state warm60M.state
    python scripts/test_emu_snapshot.py PAYLOAD warm60M.state
"""
import hashlib, sys
from pathlib import Path
sys.path.insert(0, r"C:\Users\aring\dev\ringforge-workbench\scripts")
from unicorn.x86_const import UC_X86_REG_EIP
from dotnet_meta import xor_unwrap
from emulate_native_stub import Emulator

if len(sys.argv) < 3:
    raise SystemExit("usage: test_emu_snapshot.py PAYLOAD STATE [SPLIT] [TOTAL]")
PAYLOAD, STATE = sys.argv[1], sys.argv[2]
SPLIT = int(sys.argv[3]) if len(sys.argv) > 3 else 60_000_000
TOTAL = int(sys.argv[4]) if len(sys.argv) > 4 else 100_000_000
RAW = xor_unwrap(Path(PAYLOAD).read_bytes())

def fingerprint(emu):
    h = hashlib.sha256()
    for begin, end, _ in sorted(emu.mu.mem_regions()):
        h.update(begin.to_bytes(8, "little"))
        h.update(bytes(emu.mu.mem_read(begin, end - begin + 1)))
    regs = {r: emu.mu.reg_read(Emulator._reg_id(r)) for r in Emulator._REGS}
    return h.hexdigest(), regs, emu.blocks

print(f"A: straight run to {TOTAL:,} instructions...", flush=True)
a = Emulator(RAW)
a.run(0x2680, 0xFFFFFFF, count=TOTAL)
fa = fingerprint(a)

print(f"B: restore at {SPLIT:,}, resume {TOTAL - SPLIT:,}...", flush=True)
b = Emulator.restore(STATE)
b.resume(count=TOTAL - SPLIT)
fb = fingerprint(b)

print(f"\n  memory sha256   A {fa[0][:32]}\n                  B {fb[0][:32]}   {'MATCH' if fa[0]==fb[0] else 'DIFFER'}")
print(f"  blocks          A {fa[2]:,}   B {fb[2]:,}   {'MATCH' if fa[2]==fb[2] else 'DIFFER'}")
bad = [r for r in fa[1] if fa[1][r] != fb[1][r]]
print(f"  registers       {'all match' if not bad else 'DIFFER: ' + str({r: (hex(fa[1][r]), hex(fb[1][r])) for r in bad})}")
print(f"\n  verdict: {'EQUIVALENT' if fa[0]==fb[0] and fa[2]==fb[2] and not bad else 'NOT EQUIVALENT'}")

raise SystemExit(0 if fa[0] == fb[0] and fa[2] == fb[2] and not bad else 1)
