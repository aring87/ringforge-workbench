"""Decode every name hash in stage 3 *and name the function that consumes it*.

`decode_name_hashes.py` answers "what value does this site decode to". This
answers the question that should come first: **what kind of name is it?**

The population a hash was drawn from is decided by what the sample does with
it, and guessing wordlists without knowing that is how this project spent four
sweeps failing to crack `0xe11da208`. Each site has the shape

    push <key> ; push <obfuscated imm32> ; call 0x2004181 ; push eax ; call <consumer>

so the consumer is one short forward walk from the decoder call. Grouping the
45 sites by consumer splits them into populations:

    38  0x202a311    the API resolver -- export names
     4  0x2026201
     2  0x202fe41    <- 0x79dbe71d and 0x5c4ee455 ("wow64"), and nothing else
     1  0x2026181

That two-site group is the useful part. `0x5c4ee455` is known to be the bare
stem `"wow64"`, so its only co-tenant is the same kind of name, whatever kind
that is -- which is a far tighter constraint on `0x79dbe71d` than any wordlist.

Run it from `scripts/`; it warms the emulator first, so allow a couple of
minutes.
"""
import collections
import struct
import sys
from pathlib import Path

import capstone
from unicorn import UcError
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_ESP

from dotnet_meta import xor_unwrap
from emulate_native_stub import Emulator

DECODER = 0x2004181
MODULE_BY_HASH = 0x202EC01
NARROW_AND_COMPARE = 0x202FE41

PAYLOAD = (r"G:\ringforge-artifacts\422e30ed_stage2\stage3_native_e84f7824.xor9")

SCRATCH_SP = 0x2F0000
RETMAGIC = 0x00DEAD00


def main() -> int:
    raw = xor_unwrap(Path(sys.argv[1] if len(sys.argv) > 1 else PAYLOAD).read_bytes())
    emu = Emulator(raw)
    mu = emu.mu
    print("warmup:", emu.run(0x2680, 0xFFFFFFF, count=200_000_000))
    alloc_base, alloc_size = emu.allocs[0]
    blob = bytes(mu.mem_read(alloc_base, alloc_size))

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.skipdata = True
    insns = list(md.disasm(blob, alloc_base))
    index = {ins.address: n for n, ins in enumerate(insns)}

    sites = []
    window = collections.deque(maxlen=3)
    for ins in insns:
        window.append(ins)
        if len(window) == 3:
            a, b, c = window
            if (c.mnemonic == "call" and c.op_str == hex(DECODER)
                    and a.mnemonic == "push" and b.mnemonic == "push"):
                try:
                    sites.append((c.address, int(b.op_str, 16), int(a.op_str, 16)))
                except ValueError:
                    pass
    print(f"{len(sites)} decoder call sites\n")

    groups: dict[str | None, list[tuple[int, int]]] = collections.defaultdict(list)
    for addr, obf, key in sites:
        mu.reg_write(UC_X86_REG_ESP, SCRATCH_SP)
        mu.mem_write(SCRATCH_SP, struct.pack("<III", RETMAGIC, obf, key))
        try:
            mu.emu_start(DECODER, RETMAGIC, timeout=5_000_000, count=2_000_000)
            val = mu.reg_read(UC_X86_REG_EAX)
        except UcError:
            continue
        consumer = None
        n = index.get(addr)
        if n is not None:
            for ins in insns[n + 1:n + 12]:
                if ins.mnemonic == "call":
                    consumer = ins.op_str
                    break
        groups[consumer].append((addr, val))

    labels = {
        hex(MODULE_BY_HASH): "get_module_base_by_hash -- a module BaseDllName",
        hex(NARROW_AND_COMPARE): "narrows a UTF-16 name to ascii, then compares",
    }
    for consumer, members in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        note = labels.get(consumer, "")
        print(f"{consumer}  ({len(members)} sites)  {note}")
        if len(members) <= 6:                     # small groups are the interesting ones
            for addr, val in members:
                print(f"    site {addr:#010x}   hash {val:#010x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
