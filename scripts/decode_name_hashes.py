"""Decode stage 3's obfuscated API/module name hashes, and name them.

Stage 3's unpacked code resolves everything by hash and does not even store the
hashes in the clear. Each site is

    push <key byte> ; push <obfuscated imm32> ; call 0x2004181

and the decoder XORs a 20-byte derived buffer with the key byte before returning
the real CRC-32. Reversing that decoder is unnecessary work when a live emulator
can be asked to run it: warm the image up, find every call site, and invoke the
decoder on each pair.

Naming them back is the other half, and it is free. The hash is CRC-32/MPEG-2
(init 0xFFFFFFFF, non-reflected, poly 0x04C11DB7, final NOT) over the lowercased
name, so a dictionary built from this host's own SysWOW64/System32 filenames and
export tables -- about 20,000 names -- turns the hashes back into API names
without touching the sample.

On `422e30ed...` stage 3 this recovered 43 of 45, which is the payload's
capability set obtained WITHOUT unpacking it: a direct-ntdll injection suite
(NtCreateSection / NtMapViewOfSection / NtWriteVirtualMemory /
NtSetContextThread / NtQueueApcThread), registry and file primitives, token and
privilege calls, and -- the part that names the family behaviour --
crypt32!CryptUnprotectData and CryptStringToBinaryA, which is DPAPI credential
theft.

Three hashes did not match anything on this host, and one of them, 0xe11da208,
is the module lookup that never succeeds and hangs the emulation.
"""
import collections
import struct
import sys
from pathlib import Path

import capstone
sys.path.insert(0, r"C:\Users\aring\dev\ringforge-workbench\scripts")
from unicorn import *
from unicorn.x86_const import *

from dotnet_meta import xor_unwrap
from emulate_native_stub import Emulator

DECODER = 0x2004181
ALLOC_BASE = 0x2001000

RAW = xor_unwrap(Path(
    r"G:\ringforge-artifacts\422e30ed_stage2\stage3_native_e84f7824.xor9").read_bytes())
emu = Emulator(RAW)
mu = emu.mu
print("warmup:", emu.run(0x2680, 0xFFFFFFF, count=200_000_000))
alloc_base, alloc_size = emu.allocs[0]
blob = bytes(mu.mem_read(alloc_base, alloc_size))

# find: push imm32 ; push imm32 ; call DECODER
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.skipdata = True
sites = []
window = collections.deque(maxlen=3)
for ins in md.disasm(blob, alloc_base):
    window.append(ins)
    if len(window) == 3:
        a, b, c = window
        if (c.mnemonic == "call" and c.op_str == hex(DECODER)
                and a.mnemonic == "push" and b.mnemonic == "push"):
            try:
                key = int(a.op_str, 16)
                obf = int(b.op_str, 16)
            except ValueError:
                continue
            sites.append((c.address, obf, key))
print(f"{len(sites)} decoder call sites\n")

SCRATCH_SP = 0x2f0000          # a quiet patch of stack for the synthetic calls
RETMAGIC = 0x00DEAD00
results = []
for addr, obf, key in sites:
    mu.reg_write(UC_X86_REG_ESP, SCRATCH_SP)
    mu.mem_write(SCRATCH_SP, struct.pack("<III", RETMAGIC, obf, key))
    try:
        mu.emu_start(DECODER, RETMAGIC, timeout=5_000_000, count=2_000_000)
        results.append((addr, obf, key, mu.reg_read(UC_X86_REG_EAX)))
    except UcError as e:
        results.append((addr, obf, key, None))

# CRC-32/MPEG-2, verified earlier against the emulator's own output
tab = []
for i in range(256):
    c = i << 24
    for _ in range(8):
        c = ((c << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if c & 0x80000000 else (c << 1) & 0xFFFFFFFF
    tab.append(c)


def crc(name: bytes) -> int:
    c = 0xFFFFFFFF
    for ch in name:
        c = ((c << 8) & 0xFFFFFFFF) ^ tab[((c >> 24) ^ ch) & 0xFF]
    return (~c) & 0xFFFFFFFF


# dictionary: every real module and export name on this host
import os
names = {}
for d in (r"C:\Windows\SysWOW64", r"C:\Windows\System32"):
    try:
        for f in os.listdir(d):
            if f.lower().endswith((".dll", ".exe", ".sys", ".ocx", ".drv")):
                names[crc(f.lower().encode())] = f.lower()
    except OSError:
        pass
import pefile
for dll in ("kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
            "ws2_32.dll", "wininet.dll", "shell32.dll", "ole32.dll",
            "crypt32.dll", "urlmon.dll", "psapi.dll", "shlwapi.dll"):
    p = os.path.join(r"C:\Windows\SysWOW64", dll)
    if not os.path.exists(p):
        continue
    pe = pefile.PE(p, fast_load=True)
    pe.parse_data_directories([0])
    for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if e.name:
            n = e.name.decode()
            names.setdefault(crc(n.encode()), f"{dll}!{n}")
            names.setdefault(crc(n.lower().encode()), f"{dll}!{n} (lower)")
print(f"dictionary: {len(names)} distinct name hashes\n")

named = 0
for addr, obf, key, val in results:
    if val is None:
        print(f"  {addr:#010x}  obf {obf:#010x} key {key:#04x} -> <decoder faulted>")
        continue
    hit = names.get(val)
    if hit:
        named += 1
    print(f"  {addr:#010x}  obf {obf:#010x} key {key:#04x} -> {val:#010x}"
          f"{'  == ' + hit if hit else ''}")
print(f"\n{named} of {len(results)} decoded hashes matched a real name")
