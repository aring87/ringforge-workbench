"""Emulate a carved native loader stub and take whatever it unpacks.

Written for stage 3 of `422e30ed...` on 09 Aug 2026 -- a native x86 PE32 with no
imports, recovered by decrypting stage 2's `na3PRqPuA2` resource. Static reading
stops early on that image: it is control-flow flattened the way stage 2 was, but
in machine code, with an if-else handler chain reached through a dispatcher that
finds its own context by scanning the stack for a magic cookie. Emulation walks
straight past all of that, because a decryptor does not have to be understood to
be run.

WHAT IT ESTABLISHES, and it got further than static analysis did:

* the stub needs **no imports at all** for its first ~5.8M instructions -- it
  walks the PEB and resolves everything by name from the loader module list
* it calls `NtAllocateVirtualMemory` directly (never `VirtualAlloc`) for
  `0x457e1` bytes, copies itself into that allocation and jumps into it
* the allocation then holds real code, including a statically linked CRT
  (`memset`, `strlen`, `wcslen`) and a CRC-32 table builder

WHERE IT STOPS, stated plainly because a harness that hangs and a harness that
is wrong must not look alike: after the self-relocation the unpacked code enters
an **infinite outer loop** around the CRC-32 table builder. Run to 600M basic
blocks, the allocation is byte-for-byte identical at every 20M-block snapshot --
same entropy, same non-zero count. So it is not unpacking slowly, it is not
unpacking at all. Something the relocated code checks is not satisfied by this
environment and it retries forever. The candidates, none of them tested: a
timing or tick-count check, a heap or PEB field this harness leaves zero, a
thread it expects to have started, or a genuine anti-emulation guard.

Do not read a quiet run as a clean one. Check that the allocation *changed*.

Usage:

    python scripts/emulate_native_stub.py PAYLOAD --entry 0x2680

PAYLOAD may be a `.xor9` wrapper; it is unwrapped in memory.
"""

from __future__ import annotations

import argparse
import collections
import math
import struct
from pathlib import Path

from unicorn import (UC_ARCH_X86, UC_HOOK_BLOCK, UC_HOOK_CODE,
                     UC_HOOK_MEM_UNMAPPED, UC_MODE_32, Uc, UcError)
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBP, UC_X86_REG_EIP,
                               UC_X86_REG_ESP)

import win32_emu_env as winenv
from dotnet_meta import XOR_SUFFIX, xor_unwrap

IMAGE_BASE = 0x400000
STACK, STACK_SIZE = 0x200000, 0x200000
#: Basic blocks between allocation snapshots. Low enough that the
#: did-it-actually-unpack check reports on an ordinary budget rather than only
#: on an overnight one -- a diagnostic that never fires is not a diagnostic.
SNAPSHOT_EVERY = 1_000_000


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class Emulator:
    """A stub, a synthetic process around it, and a record of what it allocated."""

    def __init__(self, raw: bytes, image_base: int = IMAGE_BASE):
        self.raw = raw
        self.base = image_base
        size = max((len(raw) + 0xFFF) & ~0xFFF, 0x46000)
        self.mu = mu = Uc(UC_ARCH_X86, UC_MODE_32)
        mu.mem_map(image_base, size)
        mu.mem_write(image_base, raw)
        mu.mem_map(STACK, STACK_SIZE)
        mu.reg_write(UC_X86_REG_ESP, STACK + STACK_SIZE // 2)
        mu.reg_write(UC_X86_REG_EBP, STACK + STACK_SIZE // 2)
        self.addr2name = winenv.setup(mu, image_base, size)

        self.next_free = winenv.HEAP_BASE + 0x1000
        self.allocs: list[list[int]] = []
        self.calls: collections.Counter = collections.Counter()
        self.unhandled: collections.Counter = collections.Counter()
        self.faults: list[tuple[int, int, int]] = []
        self.blocks = 0
        self.snapshots: list[tuple[int, float, int]] = []

        # Scoped to the stub pages. A per-instruction hook over the whole image
        # costs more than the emulation does -- it was the reason an earlier run
        # exhausted its budget inside a 2,048-iteration table build.
        for dll in (winenv.KERNEL32_BASE, winenv.NTDLL_BASE):
            mu.hook_add(UC_HOOK_CODE, self._on_stub,
                        begin=dll + winenv.STUB_RVA,
                        end=dll + winenv.STUB_RVA + 0x10 * 4000)
        mu.hook_add(UC_HOOK_BLOCK, self._on_block)
        mu.hook_add(UC_HOOK_MEM_UNMAPPED, self._on_fault)

    # -- hooks ------------------------------------------------------------

    def _on_stub(self, uc, addr, size, user):
        name = self.addr2name.get(addr)
        if name:
            self.api(name)

    def _on_block(self, uc, addr, size, user):
        self.blocks += 1
        if self.blocks % SNAPSHOT_EVERY == 0 and self.allocs:
            p, n = self.allocs[0]
            snap = bytes(uc.mem_read(p, n))
            self.snapshots.append(
                (self.blocks, entropy(snap), sum(1 for b in snap if b)))

    def _on_fault(self, uc, access, addr, size, value, user):
        self.faults.append((access, addr, uc.reg_read(UC_X86_REG_EIP)))
        return False

    # -- the API surface --------------------------------------------------

    def alloc(self, size: int) -> int:
        size = max(size, 0x1000)
        p = self.next_free
        self.next_free = (p + size + 0xFFF) & ~0xFFF
        self.allocs.append([p, size])
        return p

    def api(self, name: str) -> None:
        mu = self.mu
        esp = mu.reg_read(UC_X86_REG_ESP)
        ret = struct.unpack("<I", mu.mem_read(esp, 4))[0]

        def a(i: int) -> int:
            return struct.unpack("<I", mu.mem_read(esp + 4 + 4 * i, 4))[0]

        def wr(ptr: int, v: int) -> None:
            if ptr:
                mu.mem_write(ptr, struct.pack("<I", v))

        self.calls[name] += 1
        val, nargs = 1, 0

        if name == "VirtualAlloc":
            val, nargs = self.alloc(a(1)), 4
        elif name == "VirtualAllocEx":
            val, nargs = self.alloc(a(2)), 5
        elif name in ("NtAllocateVirtualMemory", "ZwAllocateVirtualMemory"):
            # (handle, *BaseAddress, ZeroBits, *RegionSize, Type, Protect)
            size = struct.unpack("<I", mu.mem_read(a(3), 4))[0] if a(3) else 0x1000
            p = self.alloc(size)
            wr(a(1), p)
            wr(a(3), (size + 0xFFF) & ~0xFFF)
            val, nargs = 0, 6
        elif name in ("HeapAlloc", "RtlAllocateHeap"):
            val, nargs = self.alloc(a(2)), 3
        elif name in ("LocalAlloc", "GlobalAlloc"):
            val, nargs = self.alloc(a(1)), 2
        elif name == "RtlGetProcessHeaps":
            wr(a(1), 0x00110000)
            val, nargs = 1, 2
        elif name == "GetProcessHeap":
            val, nargs = 0x00110000, 0
        elif name in ("GetCurrentProcess", "GetCurrentThread"):
            val, nargs = 0xFFFFFFFF, 0
        elif name == "VirtualProtect":
            wr(a(3), 0x40)
            val, nargs = 1, 4
        elif name in ("VirtualFree", "RtlFreeHeap", "HeapFree"):
            val, nargs = 1, 3
        elif name in ("GetModuleHandleA", "GetModuleHandleW"):
            val, nargs = self.base, 1
        elif name in ("LoadLibraryA", "LoadLibraryW"):
            val, nargs = winenv.KERNEL32_BASE, 1
        elif name == "GetProcAddress":
            val, nargs = winenv.stub_addr(winenv.KERNEL32_BASE, "Sleep"), 2
        elif name in ("RtlMoveMemory", "memcpy"):
            d, s, n = a(0), a(1), a(2)
            if 0 < n < 0x400000:
                mu.mem_write(d, bytes(mu.mem_read(s, n)))
            val, nargs = d, 3
        elif name == "memset":
            d, c, n = a(0), a(1) & 0xFF, a(2)
            if 0 < n < 0x400000:
                mu.mem_write(d, bytes([c]) * n)
            val, nargs = d, 3
        elif name == "RtlZeroMemory":
            d, n = a(0), a(1)
            if 0 < n < 0x400000:
                mu.mem_write(d, bytes(n))
            val, nargs = d, 2
        elif name in ("ExitProcess", "ExitThread"):
            mu.emu_stop()
            return
        elif name in ("GetLastError", "IsDebuggerPresent"):
            val, nargs = 0, 0
        elif name == "GetTickCount":
            val, nargs = 0x00100000, 0
        elif name == "Sleep":
            val, nargs = 1, 1
        else:
            # Counted, never silently absorbed. An API answered with a bare 1 is
            # the likeliest reason a run goes quiet or spins, so an unhandled
            # name has to be visible in the output rather than inferred later.
            self.unhandled[name] += 1

        mu.reg_write(UC_X86_REG_EAX, val)
        mu.reg_write(UC_X86_REG_EIP, ret)
        mu.reg_write(UC_X86_REG_ESP, esp + 4 + 4 * nargs)      # stdcall

    def run(self, entry: int, stop: int, count: int = 0) -> str:
        try:
            self.mu.emu_start(self.base + entry, self.base + stop,
                              timeout=0, count=count)
            return "returned or budget reached"
        except UcError as e:
            return f"{e} at eip {self.mu.reg_read(UC_X86_REG_EIP):#x}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("payload", help="a carved native PE; .xor9 is unwrapped in memory")
    ap.add_argument("--entry", type=lambda s: int(s, 0), required=True,
                    help="RVA to start at, normally the PE entry point")
    ap.add_argument("--stop", type=lambda s: int(s, 0), default=0,
                    help="RVA to stop at")
    ap.add_argument("--blocks", type=int, default=50_000_000,
                    help="instruction budget before giving up")
    ap.add_argument("--dump", metavar="DIR", help="write every allocation here")
    args = ap.parse_args(argv)

    path = Path(args.payload)
    raw = path.read_bytes()
    if path.suffix == XOR_SUFFIX:
        raw = xor_unwrap(raw)

    emu = Emulator(raw)
    print(f"image {len(raw)} bytes at {emu.base:#x}, entry {args.entry:#x}")
    print(f"stopped: {emu.run(args.entry, args.stop or 0xFFFFFFF, count=args.blocks)}")
    print(f"basic blocks: {emu.blocks}")
    print(f"api calls: {dict(emu.calls)}")
    if emu.unhandled:
        print(f"UNHANDLED apis (answered with a bare 1): {dict(emu.unhandled)}")
    if emu.faults:
        access, addr, eip = emu.faults[0]
        print(f"first fault: access {access} addr {addr:#x} eip {eip:#x}")
    print(f"allocations: {[(hex(p), hex(n)) for p, n in emu.allocs]}")

    # The check that matters: did the allocation actually move? Compare the first
    # snapshot against the state *now*, not against the last snapshot -- with a
    # single snapshot those are the same object and the comparison can only ever
    # say "unchanged", which is a check that cannot fail.
    if emu.snapshots and emu.allocs:
        p, n = emu.allocs[0]
        final = bytes(emu.mu.mem_read(p, n))
        _, e0, nz0 = emu.snapshots[0]
        e1, nz1 = entropy(final), sum(1 for b in final if b)
        moved = (round(e0, 6), nz0) != (round(e1, 6), nz1)
        print(f"allocation {p:#x} across {len(emu.snapshots)} snapshots and the "
              f"final state: entropy {e0:.3f} -> {e1:.3f}, "
              f"non-zero {nz0} -> {nz1}  "
              f"({'CHANGED -- it unpacked something' if moved else 'UNCHANGED'})")
        # "Changed at some point" and "still making progress" are different
        # claims, and only the second means waiting longer is worth anything.
        # Stage 3 moves early and then stops dead, so report the stall point
        # rather than letting one early change vouch for the whole run.
        tail = [s for s in emu.snapshots if s[2] == nz1]
        if tail and len(tail) > 1:
            since = tail[0][0]
            print(f"  last change at ~{since:,} blocks; static for the "
                  f"{emu.blocks - since:,} blocks since -- it has stalled, "
                  f"and running longer will not help")

    for p, n in emu.allocs:
        mem = bytes(emu.mu.mem_read(p, n))
        if args.dump:
            out = Path(args.dump)
            out.mkdir(parents=True, exist_ok=True)
            (out / f"alloc_{p:x}.bin").write_bytes(mem)
            print(f"wrote {out / f'alloc_{p:x}.bin'}")
        for i in range(len(mem) - 0x40):
            if mem[i:i + 2] == b"MZ":
                e = int.from_bytes(mem[i + 0x3C:i + 0x40], "little")
                if 0x40 <= e < 0x1000 and mem[i + e:i + e + 4] == b"PE\0\0":
                    print(f"*** PE in allocation {p:#x} at +{i:#x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
