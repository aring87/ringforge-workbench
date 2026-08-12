"""Decode every name hash in stage 3 *and name the function that consumes it*.

`decode_name_hashes.py` answers "what value does this site decode to". This
answers the question that should come first: **what kind of name is it?**

The population a hash was drawn from is decided by what the sample does with
it, and guessing wordlists without knowing that is how this project spent four
sweeps failing to crack `0xe11da208`. Each site has the shape

    push <key> ; push <obfuscated imm32> ; call 0x2004181 ; push eax ; call <consumer>

so the consumer is one short forward walk from the decoder call. Grouping the
sites by consumer splits them into populations:

    38  0x202a311    the API resolver -- export names
    20  0x2026181    the process-name blocklist  (only in the late image)
     4  0x2026201
     2  0x202fe41    <- 0x79dbe71d and 0x5c4ee455 ("wow64"), and nothing else
     1  0x2026181

That two-site group cracked `0x79dbe71d`: `0x5c4ee455` is `"wow64"`, so its only
co-tenant is the same kind of name -- a far tighter constraint than any wordlist.

**Two traps, both of which produced wrong published conclusions.** Sites are
found by matching the instruction *encoding*, not by walking a linear capstone
disassembly -- a linear sweep desynchronises on data in the code stream and
silently drops sites. And the allocation keeps decrypting, so the image must be
taken late: 45 sites at ~47M blocks, 65 by ~380M, with all 20 blocklist
constants among the 20 that only exist late. Scanning the warmup image with a
linear sweep found neither, which is how docs/HANDOFF.md came to state that the
blocklist constants were not decoder output. They are. Use `--late`.

Run it from `scripts/`; allow a couple of minutes either way.
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
BLOCKLIST_COMPARE = 0x2026181

PAYLOAD = (r"G:\ringforge-artifacts\422e30ed_stage2\stage3_native_e84f7824.xor9")

SCRATCH_SP = 0x2F0000
RETMAGIC = 0x00DEAD00


def find_sites(blob: bytes, base: int) -> list[tuple[int, int, int]]:
    """Every `push key ; push obf ; call 0x2004181`, found by bytes.

    The first version of this walked a linear capstone disassembly with a
    3-instruction window, and **missed sites** -- linear sweeps desynchronise
    on data in the code stream and never recover in time. It reported 45 sites
    and the blocklist comparison at 0x02016643 was not among them, which is why
    docs/HANDOFF.md spent a day concluding the blocklist constants were not
    decoder output. They are.

    Matching the encoding directly cannot desynchronise: E8 rel32 whose target
    is the decoder, preceded by 68 imm32 (the obfuscated hash), preceded by
    either 6A imm8 or 68 imm32 (the key).
    """
    out = []
    for i in range(10, len(blob) - 5):
        if blob[i] != 0xE8:
            continue
        rel = struct.unpack("<i", blob[i + 1:i + 5])[0]
        if base + i + 5 + rel != DECODER:
            continue
        if blob[i - 5] != 0x68:                       # push imm32 (the hash)
            continue
        obf = struct.unpack("<I", blob[i - 4:i])[0]
        if blob[i - 7] == 0x6A:                       # push imm8 (the key)
            key = blob[i - 6]
        elif blob[i - 10] == 0x68:                    # push imm32 (the key)
            key = struct.unpack("<I", blob[i - 9:i - 5])[0]
        else:
            continue
        out.append((base + i, obf, key))
    return out


STATE = r"G:\ringforge-artifacts\422e30ed_stage2\after_scan.state"


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("payload", nargs="?", default=PAYLOAD)
    ap.add_argument("--late", action="store_true",
                    help="scan the LATE image (resumed from after_scan.state) "
                         "instead of the warmup one. The allocation keeps "
                         "decrypting: 45 sites at ~47M blocks, 65 by ~380M, and "
                         "all 20 blocklist constants live in the 20 that appear "
                         "late. Warmup-only is how they were missed.")
    ap.add_argument("--state", default=STATE)
    args = ap.parse_args()

    if args.late:
        emu = Emulator.restore(args.state)
        mu = emu.mu
        emu.repair_wow64_crash()          # without this, resume faults at eip 0
        print(f"restored at {emu.blocks:,} blocks")
        print(" ", emu.resume(count=120_000_000), f"-> {emu.blocks:,} blocks")
    else:
        raw = xor_unwrap(Path(args.payload).read_bytes())
        emu = Emulator(raw)
        mu = emu.mu
        print("warmup:", emu.run(0x2680, 0xFFFFFFF, count=200_000_000))
    alloc_base, alloc_size = emu.allocs[0]
    blob = bytes(mu.mem_read(alloc_base, alloc_size))

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.skipdata = True
    insns = list(md.disasm(blob, alloc_base))
    index = {ins.address: n for n, ins in enumerate(insns)}

    sites = find_sites(blob, alloc_base)
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
        hex(BLOCKLIST_COMPARE): "the process-name blocklist compare",
    }
    from crack_name_hashes import crc as _crc
    blocklist = {_crc(n.encode()): n for n in (
        "procmon.exe", "regmon.exe", "filemon.exe", "wireshark.exe",
        "netmon.exe", "vmwareuser.exe", "vmwareservice.exe", "vmsrvc.exe",
        "vmusrvc.exe", "sandboxiedcomlaunch.exe", "sandboxierpcss.exe",
        "python.exe", "perl.exe")}
    for h in (0x0263178B, 0x0CC39FEF, 0x57585356, 0x9CB95240,
              0xA8D123C8, 0xC72CE2D5, 0xD0C58467):
        blocklist[h] = "*** UNCRACKED ***"
    n_block = sum(1 for members in groups.values()
                  for _a, v in members if v in blocklist)
    print(f"{n_block} of the 20 blocklist constants are decoder output\n")
    for consumer, members in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        note = labels.get(consumer, "")
        print(f"{consumer}  ({len(members)} sites)  {note}")
        for addr, val in members:
            tag = blocklist.get(val)
            if tag:
                print(f"    site {addr:#010x}   hash {val:#010x}   {tag}")
            elif len(members) <= 6:
                print(f"    site {addr:#010x}   hash {val:#010x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
