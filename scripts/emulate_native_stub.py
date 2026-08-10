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

IT DOES NOT STALL, and two earlier versions of this docstring said it did. That
mistake is worth more than the tool. The loop at 0x40231f is RC4 PRGA -- i = i+1,
j = j + S[i], swap, keystream byte -- at 99 instructions per byte, with a byte
counter in its own context struct at [ctx+0x60] and a length at [ctx+0x90]. Read
that counter and it runs 3,852 -> 4,341 -> 13,670 of 13,670 and completes.
Sampled instead through a 300k-instruction window, its single exit branch reads
`taken=0 of 3,031` and looks stuck.

Both wrong calls came from watching `allocs[0]`, the NtAllocateVirtualMemory
region, while this pass writes to a *stack* buffer at 0x2ff040. The allocation
holding still was never evidence about progress. The first version of that check
could not fail at all; the second could, and was still aimed at the wrong buffer.
**A check that can fail is necessary and not sufficient -- it also has to be
pointed at the subject.** Where the subject keeps its own counter, read that.

WHAT IS ACTUALLY UNKNOWN is whether the emulation *diverges*. This harness
answers GetProcAddress with a Sleep stub for every name, claims success from
VirtualProtect, and invents a heap handle for RtlGetProcessHeaps. Any of those
can steer execution down a path the real thing would not take, silently, without
ever faulting. Log each call with arguments and return value and look for one the
code visibly rejects.

So: do not read a quiet run as a clean one, and do not read an unchanged buffer
as a stalled one either.

Usage:

    python scripts/emulate_native_stub.py PAYLOAD --entry 0x2680

PAYLOAD may be a `.xor9` wrapper; it is unwrapped in memory.
"""

from __future__ import annotations

import argparse
import collections
import json
import math
import struct
from typing import Optional
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
        #: Set to a list to record every API call with its arguments and result.
        self.log: Optional[list[dict]] = None

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

    def describe(self, value: int) -> str:
        """An argument rendered as a string when it plausibly points at one.

        This is the part of the log that earns its keep. A divergence shows up
        as the *name* the stub asked for -- a DLL, an export, a path -- and a
        column of bare hex hides exactly that.
        """
        if value < 0x1000 or value > 0xFFFFFFF0:
            return hex(value)
        try:
            raw = bytes(self.mu.mem_read(value, 64))
        except UcError:
            return hex(value)
        ascii_run = raw.split(b"\0")[0]
        if len(ascii_run) >= 4 and all(0x20 <= b < 0x7F for b in ascii_run):
            return f"{hex(value)}->{ascii_run.decode()[:40]!r}"
        if len(raw) >= 8 and raw[1] == 0 and raw[3] == 0:
            wide = raw.split(b"\0\0")[0]
            try:
                text = wide.decode("utf-16-le", "strict")
            except UnicodeDecodeError:
                return hex(value)
            if len(text) >= 3 and all(0x20 <= ord(c) < 0x7F for c in text):
                return f"{hex(value)}->{text[:40]!r}w"
        return hex(value)

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
        elif name == "RtlDosPathNameToNtPathName_U":
            # (PCWSTR Dos, PUNICODE_STRING Nt, PCWSTR *Part, PRTL_RELATIVE_NAME)
            # Prefix the DOS path with \??\ and hand back a UNICODE_STRING. The
            # buffer has to outlive the call, so it comes from the bump heap.
            dos = a(0)
            text = ""
            if dos:
                raw = bytes(mu.mem_read(dos, 520))
                end = raw.find(b"\0\0")
                text = raw[:end if end > 0 else 0].decode("utf-16-le", "replace")
            wide = ("\\??\\" + text).encode("utf-16-le") + b"\0\0"
            buf = self.alloc(len(wide) + 16)
            mu.mem_write(buf, wide)
            if a(1):
                mu.mem_write(a(1), struct.pack("<HHI", len(wide) - 2, len(wide), buf))
            if a(2):
                wr(a(2), buf)
            val, nargs = 1, 4
        elif name in ("RtlInitUnicodeString", "RtlInitAnsiString"):
            val, nargs = 0, 2
        elif name == "RtlFreeUnicodeString":
            val, nargs = 0, 1
        elif name == "RtlNtStatusToDosError":
            val, nargs = 0, 1
        elif name == "RtlGetLastWin32Error":
            val, nargs = 0, 0
        elif name == "Sleep":
            val, nargs = 1, 1
        else:
            # Counted, never silently absorbed. An API answered with a bare 1 is
            # the likeliest reason a run goes quiet or spins, so an unhandled
            # name has to be visible in the output rather than inferred later.
            self.unhandled[name] += 1

        # Log after the dispatch, because `nargs` is what says how much of the
        # stack is actually this call's. For an unhandled name nargs is 0 and
        # the arguments are unknown, so read a few speculatively and mark them:
        # those are exactly the calls whose stack discipline is also wrong, and
        # the log has to show that rather than imply four tidy arguments.
        if self.log is not None:
            speculative = name in self.unhandled
            count = 4 if speculative else nargs
            try:
                args = [self.describe(a(i)) for i in range(count)]
            except UcError:
                args = ["<unreadable>"]
            self.log.append({
                "seq": len(self.log),
                "blocks": self.blocks,
                "name": name,
                "caller": ret,
                "args": args,
                "speculative_args": speculative,
                "returned": val,
                "popped": 4 * nargs,
            })

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
    ap.add_argument("--log-api", action="store_true",
                    help="record every API call with arguments and return value")
    ap.add_argument("--log-json", metavar="FILE", help="write the API log as JSON")
    args = ap.parse_args(argv)

    path = Path(args.payload)
    raw = path.read_bytes()
    if path.suffix == XOR_SUFFIX:
        raw = xor_unwrap(raw)

    emu = Emulator(raw)
    if args.log_api or args.log_json:
        emu.log = []
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

    if emu.log is not None:
        print(f"\n{len(emu.log)} API calls, in order:")
        for e in emu.log:
            flag = "  <-- args are a GUESS, and so is the stack fixup" \
                if e["speculative_args"] else ""
            print(f"  [{e['seq']:4d}] {e['blocks']:>10,}blk  from {e['caller']:#010x}  "
                  f"{e['name']}({', '.join(e['args'])}) = {e['returned']:#x}{flag}")
        if args.log_json:
            Path(args.log_json).write_text(json.dumps(emu.log, indent=2), encoding="utf-8")
            print(f"  written to {args.log_json}")

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
        # This reports where the watched buffer last moved, and nothing more.
        # It must not be phrased as a verdict on progress: on stage 3 it went
        # quiet while an RC4 pass ran happily against a stack buffer, and two
        # write-ups called that a stall on the strength of this line.
        tail = [s for s in emu.snapshots if s[2] == nz1]
        if tail and len(tail) > 1:
            since = tail[0][0]
            print(f"  watched buffer last moved at ~{since:,} blocks, static for "
                  f"the {emu.blocks - since:,} since")
            print("  NOT a progress verdict -- the stub may be writing somewhere "
                  "this check never looks. Confirm against a counter the code "
                  "keeps itself before concluding anything.")

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
