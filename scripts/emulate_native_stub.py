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

IT IS INTERCEPTED AT THE SYSCALL BOUNDARY, not at export addresses, and that is
the only placement that works on this sample. Stage 3 reads a pristine ntdll off
disk and manually maps it, then calls `Nt*` stubs out of **its own copy** -- so a
hook on `ntdll!NtCreateFile` at its export never fires. That is exactly why the
API log went quiet at 87 calls while the sample kept running, and why it then
appeared to jump to address 0: a 32-bit process reaches the kernel through
`ntdll!Wow64Transition` and `fs:[0xC0]`, both of which the *kernel* fills in at
load and neither of which is in the file on disk. `win32_emu_env` now fills them,
points them at a gate, and the gate reads EAX for the service number against a
table parsed out of the host's own ntdll. Handlers are keyed by name, so the same
ones serve both entry points.

WHAT IS ACTUALLY UNKNOWN is whether the emulation *diverges*. This harness
answers GetProcAddress with a Sleep stub for every name, claims success from
VirtualProtect, and invents a heap handle for RtlGetProcessHeaps. Any of those
can steer execution down a path the real thing would not take, silently, without
ever faulting. Log each call with arguments and return value and look for one the
code visibly rejects.

So: do not read a quiet run as a clean one, do not read an unchanged buffer as a
stalled one, and do not read a fetch from address 0 as a crash -- with no
sentinel on the initial stack, that is also what returning from the entry
function looks like. `run` tells those two apart by ESP.

Usage:

    python scripts/emulate_native_stub.py PAYLOAD --entry 0x2680

PAYLOAD may be a `.xor9` wrapper; it is unwrapped in memory.
"""

from __future__ import annotations

import argparse
import collections
import json
import math
import pickle
import struct
import zlib
from typing import Optional
from pathlib import Path

from unicorn import (UC_ARCH_X86, UC_HOOK_BLOCK, UC_HOOK_CODE,
                     UC_HOOK_MEM_UNMAPPED, UC_HOOK_MEM_WRITE, UC_MODE_32,
                     Uc, UcError)
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBP, UC_X86_REG_EIP,
                               UC_X86_REG_ESP)

import win32_emu_env as winenv
from dotnet_meta import XOR_SUFFIX, xor_unwrap

IMAGE_BASE = 0x400000
STACK, STACK_SIZE = 0x200000, 0x200000

#: A stack for the *remote* thread a hollowing loader redirects, clear of both
#: `STACK` and the heap at `HEAP_BASE`.
#:
#: This exists because the first `NtGetContextThread` answered with the live
#: machine's registers, so the `CONTEXT` handed back carried the **loader's own**
#: `Esp`. The loader wrote that straight into the record it passed to
#: `NtSetContextThread`, which made the injected entry appear to run on a stack
#: that was really the loader's -- and the injected code then flattened the
#: loader's frames with ten million pushes. On a real machine the two threads
#: live in different processes and share nothing but the section. Answering with
#: a separate region is what makes that true here.
REMOTE_STACK, REMOTE_STACK_SIZE = 0x10000000, 0x100000
#: Basic blocks between allocation snapshots. Low enough that the
#: did-it-actually-unpack check reports on an ordinary budget rather than only
#: on an overnight one -- a diagnostic that never fires is not a diagnostic.
SNAPSHOT_EVERY = 1_000_000


def read_wide(mu, addr: int, limit: int = 520) -> str:
    """A NUL-terminated UTF-16LE string from emulated memory.

    Scanning for `b"\\0\\0"` with `bytes.find` is wrong and quietly so: in
    `...l\\0l\\0\\0\\0` the first match straddles a character boundary at an odd
    index, and the string comes back a character short with a replacement
    character on the end. Step two bytes at a time.
    """
    try:
        raw = bytes(mu.mem_read(addr, limit))
    except UcError:
        return ""
    for i in range(0, len(raw) - 1, 2):
        if raw[i] == 0 and raw[i + 1] == 0:
            return raw[:i].decode("utf-16-le", "replace")
    return raw.decode("utf-16-le", "replace")


#: Field offsets in the x86 `CONTEXT` record, which is what a hollowing loader
#: hands to `NtSetContextThread` to say where the injected code starts.
#:
#: **Read `Eip` and `Eax` both.** Loaders split roughly evenly between setting
#: `Eip` directly and setting only `Eax`, because a freshly created thread is
#: suspended at `RtlUserThreadStart`, which jumps to whatever `Eax` holds.
#: Reading one and not the other looks exactly like "it resumed into nothing".
CONTEXT_OFFSETS = {
    "ContextFlags": 0x00, "Edi": 0x9C, "Esi": 0xA0, "Ebx": 0xA4, "Edx": 0xA8,
    "Ecx": 0xAC, "Eax": 0xB0, "Ebp": 0xB4, "Eip": 0xB8, "SegCs": 0xBC,
    "EFlags": 0xC0, "Esp": 0xC4, "SegSs": 0xC8,
}
CONTEXT_SIZE = 0x2CC


def decode_context(raw: bytes) -> dict[str, int]:
    """The interesting registers out of an x86 `CONTEXT` blob.

    Pure and separate from the emulator so it can be tested without a run --
    which for this file is the difference between a unit test and twenty
    minutes. Short records are read as far as they go rather than raising: a
    loader may pass `ContextFlags` asking for a subset, and a partial record
    still names the entry point.
    """
    out: dict[str, int] = {}
    for field, off in CONTEXT_OFFSETS.items():
        if off + 4 <= len(raw):
            out[field] = struct.unpack_from("<I", raw, off)[0]
    return out


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
        (self.addr2name, self.ssn2name,
         self.transition_rva, self.ntdll_image_size) = winenv.setup(mu, image_base, size)

        self._init_observations()
        self._install_hooks()

    def _init_observations(self) -> None:
        """Every field that records what the payload did.

        In one place because `restore()` needs the same set and adding a field
        to only one of the two constructors is a bug that does not surface until
        the new handler fires -- several hundred million blocks into a run, with
        the traceback pointing at the handler rather than at the omission.
        """
        self.next_free = winenv.HEAP_BASE + 0x1000
        self.allocs: list[list[int]] = []
        self.calls: collections.Counter = collections.Counter()
        self.unhandled: collections.Counter = collections.Counter()
        #: Syscalls dispatched by service number, and numbers this ntdll has no
        #: name for -- the second is how a wrong SSN mask would announce itself.
        self.syscalls: collections.Counter = collections.Counter()
        self.unknown_ssn: collections.Counter = collections.Counter()
        #: `(blocks, base)` for each ntdll copy repaired in a resumed snapshot.
        self.patched_ntdll: list[tuple[int, int]] = []
        #: Environment variables the payload asked for, in order, and the
        #: ones actually answered -- asked-but-unknown is the interesting gap.
        self.env_queries: list[str] = []
        self.env_answers: list[tuple[str, str]] = []
        #: How many times a process list was actually handed over. Anything
        #: concluded after the first one is conditional on `winenv.PROCESS_LIST`.
        self.served_process_list = 0
        #: Named kernel objects it created or opened -- mutants especially.
        self.named_objects: list[dict] = []
        #: Processes it tried to open, whether or not the pid was one we served.
        self.remote_targets: list[dict] = []
        #: Buffers written into another process. The payoff of all of the above.
        self.remote_writes: list[dict] = []
        #: Sections, their local views, and calls that start or stop execution.
        self.sections: dict[int, int] = {}
        self.section_views: dict[int, int] = {}
        self.section_maps: list[dict] = []
        #: What the sample asked NtCreateSection for, and what it wrote
        #: into the view. The written extents are the evidence; the view
        #: itself is carved from unzeroed heap.
        #: Every CONTEXT the loader read or wrote. NtSetContextThread's
        #: record names the injected entry point, which is the only way to
        #: know where the far side would start.
        self.thread_contexts: list[dict] = []
        #: Set by main() from --snapshot-after-inject. Cleared once used.
        self.snapshot_on_resume = None
        #: ESP handed to the redirected thread, and the flag saying its
        #: stack is mapped. Zero until an injection asks for one.
        self.remote_esp = 0
        self.section_requests: list[dict] = []
        self.section_writes: list[dict] = []
        self.control_calls: list[dict] = []
        self.process_handles: dict[int, int] = {}
        self._next_handle = 0x400
        #: Emulated time the payload has *asked* to sleep away, in 100ns units.
        #: Added to the block-derived clock, so time is a function of the run
        #: rather than of the wall.
        self.clock_sleep_100ns = 0
        self.faults: list[tuple[int, int, int]] = []
        self.blocks = 0
        self._skip_block_at: Optional[int] = None
        self.snapshots: list[tuple[int, float, int]] = []
        #: Set to a list to record every API call with its arguments and result.
        self.log: Optional[list[dict]] = None
        #: Files the payload opened, in order, with the path it asked for.
        self.files: list[dict] = []

    def _install_hooks(self) -> None:
        """Attach the callbacks. Separate because a restored snapshot needs
        them re-attached -- hooks are Python objects and do not serialise."""
        mu = self.mu
        # Exports live at their real addresses inside a real mapped image, so
        # the intercept range is the module itself rather than a stub page.
        # Unicorn only invokes the hook for instructions actually executed in
        # range, and every export returns before its real body runs. A
        # per-instruction hook over everything costs more than the emulation
        # does -- that is why these are scoped.
        for dll in (winenv.KERNEL32_BASE, winenv.NTDLL_BASE):
            hi = max((a for a in self.addr2name if dll <= a < dll + 0x1000000),
                     default=dll)
            mu.hook_add(UC_HOOK_CODE, self._on_stub, begin=dll, end=hi + 0x20)
        # And the promoted EXTRA_MODULES. Their exports are real addresses in
        # their own region, so without a hook covering it every name stage 4
        # resolves there would resolve correctly and then execute the DLL's
        # actual body -- which is a worse failure than the empty headers were,
        # because it looks like it is working.
        real = [a for a in self.addr2name
                if winenv.REAL_MODULE_BASE <= a < winenv.REAL_MODULE_LIMIT]
        if real:
            mu.hook_add(UC_HOOK_CODE, self._on_stub,
                        begin=min(real), end=max(real) + 0x20)
        # The syscall boundary. This is where this payload actually operates:
        # it maps a clean ntdll and calls stubs out of its own copy, so an
        # export-address hook never sees it -- which is why the API log went
        # quiet at 87 calls while the sample kept working.
        mu.hook_add(UC_HOOK_CODE, self._on_syscall,
                    begin=winenv.SYSCALL_GATE, end=winenv.SYSCALL_GATE)
        mu.hook_add(UC_HOOK_BLOCK, self._on_block)
        mu.hook_add(UC_HOOK_MEM_UNMAPPED, self._on_fault)

    # -- snapshot / restore -----------------------------------------------

    #: Registers carried across a snapshot. The segment selectors and GDTR are
    #: not optional: FS is what makes `fs:[0x18]` reach the TEB, and a restore
    #: that forgets them faults in a way that looks like a payload bug.
    _REGS = ("EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP",
             "EFLAGS", "CS", "DS", "ES", "SS", "FS", "GS")

    @staticmethod
    def _reg_id(name: str) -> int:
        import unicorn.x86_const as c
        return getattr(c, f"UC_X86_REG_{name}")

    def snapshot(self, path: str | Path) -> None:
        """Freeze the whole emulated process to a file.

        Every diagnostic in this investigation -- single-stepping, reading a
        loop's counter, dumping API arguments -- needs the machine at a moment
        several hundred million instructions in, and re-running to get there
        costs about eleven minutes per 900M. That cost was paid five times
        before this existed.

        Regions are stored zlib-compressed, which matters because the heap is
        mapped at 128 MB and is almost entirely zero.
        """
        regions = []
        for begin, end, perms in self.mu.mem_regions():
            size = end - begin + 1
            blob = zlib.compress(bytes(self.mu.mem_read(begin, size)), 1)
            regions.append((begin, size, perms, blob))
        # File-backing bytes are re-read on restore rather than stored: they
        # come from the host and would double the snapshot for no benefit.
        files = [{k: v for k, v in f.items() if k != "data"} for f in self.files]
        state = {
            # v2 adds the syscall counters. The SSN table itself is *not*
            # stored: it is derived from the host's own ntdll and rebuilt on
            # restore, so a snapshot can never carry a stale numbering.
            "version": 3,
            "base": self.base,
            "regions": regions,
            "regs": {r: self.mu.reg_read(self._reg_id(r)) for r in self._REGS},
            "gdtr": self.mu.reg_read(self._reg_id("GDTR")),
            "addr2name": self.addr2name,
            "next_free": self.next_free,
            "allocs": self.allocs,
            "calls": dict(self.calls),
            "unhandled": dict(self.unhandled),
            "syscalls": dict(self.syscalls),
            "unknown_ssn": dict(self.unknown_ssn),
            "patched_ntdll": self.patched_ntdll,
            "env_queries": self.env_queries,
            "env_answers": self.env_answers,
            "clock_sleep_100ns": self.clock_sleep_100ns,
            "blocks": self.blocks,
            "files": files,
            "log": self.log,
            # v3. Without this a restored state cannot say where the
            # injected code starts, and the entry point has to be passed
            # in by hand from the run that captured it.
            "thread_contexts": self.thread_contexts,
        }
        Path(path).write_bytes(pickle.dumps(state, protocol=4))

    @classmethod
    def restore(cls, path: str | Path) -> "Emulator":
        """Rebuild an emulator from a snapshot, hooks and all."""
        state = pickle.loads(Path(path).read_bytes())
        # Every version this class has ever written stays readable. Bumping the
        # writer without widening this guard makes each new snapshot unloadable
        # by the code that wrote it -- which is how a state saved after an
        # eight-billion-instruction run came back "unsupported snapshot version
        # 3" and nearly cost the run twice.
        if state.get("version") not in (1, 2, 3):
            raise ValueError(f"unsupported snapshot version {state.get('version')}")
        self = cls.__new__(cls)
        self.raw = b""
        self.base = state["base"]
        self.mu = mu = Uc(UC_ARCH_X86, UC_MODE_32)
        # Defaults first, pickled values over the top. A snapshot only carries
        # the fields that existed when it was written.
        self._init_observations()
        for begin, size, perms, blob in state["regions"]:
            mu.mem_map(begin, size, perms)
            mu.mem_write(begin, zlib.decompress(blob))
        mu.reg_write(self._reg_id("GDTR"), state["gdtr"])
        for name, value in state["regs"].items():
            mu.reg_write(self._reg_id(name), value)

        self.addr2name = state["addr2name"]
        self.next_free = state["next_free"]
        self.allocs = state["allocs"]
        self.calls = collections.Counter(state["calls"])
        self.unhandled = collections.Counter(state["unhandled"])
        self.syscalls = collections.Counter(state.get("syscalls", {}))
        self.unknown_ssn = collections.Counter(state.get("unknown_ssn", {}))
        self.patched_ntdll = list(state.get("patched_ntdll", []))
        self.env_queries = list(state.get("env_queries", []))
        self.env_answers = [tuple(x) for x in state.get("env_answers", [])]
        self.clock_sleep_100ns = state.get("clock_sleep_100ns", 0)
        self.blocks = state["blocks"]
        self._skip_block_at = None
        self.faults = []
        self.snapshots = []
        self.log = state["log"]
        self.files = state["files"]
        # v3. Absent from v1 and v2 states, which stay readable -- the entry
        # point then has to be supplied by whoever captured it.
        self.thread_contexts = state.get("thread_contexts", [])
        for f in self.files:
            f["data"] = self.backing(f["path"])

        # Rebuilt rather than restored, so a state saved before the syscall
        # boundary existed comes back with it -- which is the whole point of
        # having kept `after_scan.state`.
        (self.ssn2name, self.transition_rva,
         self.ntdll_image_size) = winenv.syscall_table()
        winenv.install_syscall_gate(mu, winenv.NTDLL_BASE, self.transition_rva)
        winenv.map_kuser_shared_data(mu)
        # Same argument as the syscall gate above: rebuilt rather than restored,
        # so a state captured while every module but kernel32 and ntdll was a
        # header-only stub comes back with real export tables. Without this the
        # fix reaches fresh runs only, and every stored checkpoint -- which is
        # what stage 4 is actually run from -- would keep resolving into empty
        # headers. Idempotent, so a state that already has them is untouched.
        self.addr2name.update(winenv.map_extra_module_exports(mu))
        # A snapshot taken before the harness supplied the kernel's values holds
        # the zero the payload copied out of the loaded image, in every private
        # ntdll it had already mapped. The payload does that fixup once, so
        # resuming such a state runs fine until the first syscall out of its own
        # copy and then jumps through a null slot -- which is how `warm400M`
        # started dying at 348M blocks, at the exact address the gate exists to
        # prevent. Repairing at restore, not only in `repair_wow64_crash`, is
        # what makes every stored state resumable rather than just the crashed
        # one. Only zero slots are written, so a state that already has the
        # value is untouched, and a state with no copies yet is a no-op.
        for base in winenv.patch_ntdll_copies(
                mu, self.allocs, self.transition_rva, self.ntdll_image_size):
            self.patched_ntdll.append((self.blocks, base))
        self.advance_clock()
        self._install_hooks()
        return self

    def repair_wow64_crash(self) -> bool:
        """Resume a state captured at the jump through an empty transition slot.

        `after_scan.state` is a dead machine: `jmp dword ptr [Wow64Transition]`
        read zero and EIP is 0. Nothing else about it is damaged -- the fault
        happened *at* the jump, so the stack, the registers and every mapped
        page are exactly what the transition would have been entered with. With
        the slot now filled, sending EIP to the gate replays that jump as it
        should have gone, instead of re-running 348M blocks to reach it again.

        The guard is deliberately tight, so this can never quietly rescue an
        unrelated jump to zero: EIP must be 0, EAX's low word must be a service
        number this ntdll knows, and the return address on top of the stack must
        point at the `ret imm16` that ends a syscall stub.

        The stale-slot repair that goes with this lives in `restore`, because
        it is needed by *every* pre-gate snapshot and not only by the crashed
        one -- `warm400M` resumes past the same transition and was dying at it.
        """
        mu = self.mu
        if mu.reg_read(UC_X86_REG_EIP) != 0:
            return False
        if (mu.reg_read(UC_X86_REG_EAX) & 0xFFFF) not in self.ssn2name:
            return False
        try:
            ret = struct.unpack("<I", mu.mem_read(mu.reg_read(UC_X86_REG_ESP), 4))[0]
            if mu.mem_read(ret, 1)[0] != 0xC2:                 # ret imm16
                return False
        except UcError:
            return False
        mu.reg_write(UC_X86_REG_EIP, winenv.SYSCALL_GATE)
        return True

    def resume(self, count: int = 0) -> str:
        """Continue from wherever the machine currently is.

        `emu_start` re-fires the block hook for the block at the resume address,
        and that block was already counted when the previous run stopped inside
        it -- so a resumed run double-counts exactly one block per resume. The
        equivalence check caught it as an off-by-one against an uninterrupted
        run whose memory and registers were bit-identical, which is precisely
        the kind of small drift that would otherwise accumulate silently across
        a chain of snapshots.
        """
        self._skip_block_at = self.mu.reg_read(UC_X86_REG_EIP)
        return self.run(self._skip_block_at - self.base, 0xFFFFFFF, count=count)

    # -- hooks ------------------------------------------------------------

    def _on_stub(self, uc, addr, size, user):
        name = self.addr2name.get(addr)
        if name:
            self.api(name)

    def _on_syscall(self, uc, addr, size, user):
        """A `Nt*` stub has reached the WOW64 transition. EAX names the service.

        The stack here carries **two** return addresses, and getting that wrong
        would misread every argument: the payload's `call` pushed one, then the
        stub's own `call edx` pushed another. So the arguments start at
        `esp + 8`, not `esp + 4`. The cleanup differs for the same reason --
        the stub ends in `ret imm16` and pops its own arguments, so the gate
        must pop only the address it returns to.
        """
        ssn = uc.reg_read(UC_X86_REG_EAX) & 0xFFFF
        name = self.ssn2name.get(ssn)
        if name is None:
            self.unknown_ssn[ssn] += 1
            uc.reg_write(UC_X86_REG_EAX, 0xC0000002)           # NOT_IMPLEMENTED
            esp = uc.reg_read(UC_X86_REG_ESP)
            uc.reg_write(UC_X86_REG_EIP, struct.unpack("<I", uc.mem_read(esp, 4))[0])
            uc.reg_write(UC_X86_REG_ESP, esp + 4)
            return
        self.syscalls[name] += 1
        # An unhandled *syscall* answered with a bare 1 is STATUS_WAIT_1, which
        # reads as success against an untouched output buffer. A status saying
        # plainly that nothing happened keeps the gap visible.
        self.api(name, arg_offset=8, cleanup=4, unhandled_value=0xC0000002, ssn=ssn)

    def _on_block(self, uc, addr, size, user):
        if self._skip_block_at is not None:
            # The block we resumed into was already counted before the snapshot.
            skip, self._skip_block_at = self._skip_block_at, None
            if addr == skip:
                return
        self.blocks += 1
        if self.blocks % SNAPSHOT_EVERY == 0:
            # Piggy-backed on the existing boundary rather than run per block:
            # the clock is read far less often than it ticks, and a modulo on
            # 630M blocks is already the budget here.
            self.advance_clock()
            if self.allocs:
                p, n = self.allocs[0]
                snap = bytes(uc.mem_read(p, n))
                self.snapshots.append(
                    (self.blocks, entropy(snap), sum(1 for b in snap if b)))

    def _on_fault(self, uc, access, addr, size, value, user):
        self.faults.append((access, addr, uc.reg_read(UC_X86_REG_EIP)))
        return False

    # -- the API surface --------------------------------------------------

    def export_addr(self, name: str) -> int:
        """Address of a named export in the mapped system DLLs, or 0."""
        return next((a for a, n in self.addr2name.items() if n == name), 0)

    def backing(self, nt_path: str) -> bytes:
        """Real bytes for a file the payload opens, when the host has them.

        Stage 3 opens `\\??\\ntdll.dll` -- reading a pristine copy from disk,
        which is how a loader recovers unhooked syscall stubs. Answering that
        with end-of-file does not merely stall it, it makes the run a study of
        the harness. The host's own SysWOW64 copy is the honest answer, and it
        is the same file the sample would get.
        """
        name = nt_path.rsplit("\\", 1)[-1].lower()
        if not name:
            return b""
        for folder in (r"C:\Windows\SysWOW64", r"C:\Windows\System32"):
            candidate = Path(folder) / name
            if candidate.is_file():
                try:
                    return candidate.read_bytes()
                except OSError:
                    return b""
        return b""

    def unicode_string(self, ptr: int) -> str:
        """The text of a UNICODE_STRING -- (Length, MaximumLength, Buffer),
        with Length in *bytes* rather than characters."""
        if not ptr:
            return ""
        try:
            length, _, buf = struct.unpack("<HHI", self.mu.mem_read(ptr, 8))
            if not buf or not length or length > 0x1000:
                return ""
            return bytes(self.mu.mem_read(buf, length)).decode("utf-16-le", "replace")
        except UcError:
            return ""

    def object_name(self, obj_attrs: int) -> str:
        """The path out of an OBJECT_ATTRIBUTES; +0x08 is PUNICODE_STRING
        ObjectName."""
        if not obj_attrs:
            return ""
        try:
            return self.unicode_string(
                struct.unpack("<I", self.mu.mem_read(obj_attrs + 8, 4))[0])
        except UcError:
            return ""

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

    def elapsed_100ns(self) -> int:
        """Emulated time since start: work done, plus every sleep requested."""
        return self.blocks * winenv.NS100_PER_BLOCK + self.clock_sleep_100ns

    def advance_clock(self) -> None:
        winenv.advance_clock(self.mu, self.elapsed_100ns())

    def new_handle(self) -> int:
        """A fresh kernel handle. Multiples of 4 and clear of the file handles,
        which allocate from 0x1000 upward."""
        self._next_handle += 4
        return self._next_handle

    def _map_remote_stack(self) -> None:
        """Map the redirected thread's stack, once.

        Lazy rather than mapped at construction because a run that never reaches
        an injection should not carry a region it never touches -- snapshots
        store every mapped region, and this one would be a megabyte of zeroes in
        each of them.
        """
        if self.remote_esp:
            return
        try:
            self.mu.mem_map(REMOTE_STACK, REMOTE_STACK_SIZE)
        except UcError:
            pass                      # already mapped, e.g. in a restored state
        self.remote_esp = REMOTE_STACK + REMOTE_STACK_SIZE // 2
        print(f"  [{self.blocks:,}blk] mapped a stack for the remote thread at "
              f"{REMOTE_STACK:#x}, esp {self.remote_esp:#x}", flush=True)

    def _watch_section_view(self, base: int, size: int) -> None:
        """Record which bytes of a section view the sample actually writes.

        The view is not freshly mapped -- `alloc` carves it out of the heap that
        is already mapped and never zeroes -- so reading the view back at the end
        of a run shows stale bytes from earlier in the run mixed with whatever
        was written. A 24.8 MB view came back 97.5% non-zero at entropy 7.96 and
        looked like a written payload; it was mostly leftovers.

        Only the written extents are evidence. Coalesced, because a `rep movsb`
        of a payload arrives as one callback per byte.
        """
        spans: list[list[int]] = []
        self.section_writes.append({"base": base, "size": size, "spans": spans})

        def on_write(uc, access, address, length, value, _user):
            end = address + length
            if spans and address <= spans[-1][1] + 0x40:
                spans[-1][1] = max(spans[-1][1], end)
            else:
                spans.append([address, end])

        self.mu.hook_add(UC_HOOK_MEM_WRITE, on_write, begin=base, end=base + size - 1)

    def alloc(self, size: int) -> int:
        size = max(size, 0x1000)
        p = self.next_free
        self.next_free = (p + size + 0xFFF) & ~0xFFF
        self.allocs.append([p, size])
        return p

    def api(self, name: str, *, arg_offset: int = 4, cleanup: Optional[int] = None,
            unhandled_value: int = 1, ssn: Optional[int] = None) -> None:
        """Implement one call and return from it.

        `arg_offset` and `cleanup` are what let the same handlers serve both
        entry points. Reached at an export address it is an ordinary stdcall:
        arguments at `esp + 4`, and this pops them. Reached at the syscall gate
        the stub's own `ret imm16` pops them instead, and there is an extra
        return address in the way -- see `_on_syscall`.
        """
        mu = self.mu
        esp = mu.reg_read(UC_X86_REG_ESP)
        ret = struct.unpack("<I", mu.mem_read(esp, 4))[0]

        def a(i: int) -> int:
            return struct.unpack("<I", mu.mem_read(esp + arg_offset + 4 * i, 4))[0]

        def wr(ptr: int, v: int) -> None:
            if ptr:
                mu.mem_write(ptr, struct.pack("<I", v))

        self.calls[name] += 1
        val, nargs = unhandled_value, 0

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
            val, nargs = self.export_addr("Sleep"), 2
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
            text = read_wide(mu, a(0)) if dos else ""
            wide = ("\\??\\" + text).encode("utf-16-le") + b"\0\0"
            buf = self.alloc(len(wide) + 16)
            mu.mem_write(buf, wide)
            if a(1):
                mu.mem_write(a(1), struct.pack("<HHI", len(wide) - 2, len(wide), buf))
            if a(2):
                wr(a(2), buf)
            val, nargs = 1, 4
        elif name in ("NtCreateFile", "NtOpenFile"):
            # NtCreateFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
            #   PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG FileAttributes,
            #   ULONG Share, ULONG Disposition, ULONG Options, PVOID Ea, ULONG EaLen)
            # NtOpenFile is the same through the first four and stops at Options.
            nargs = 11 if name == "NtCreateFile" else 6
            path = self.object_name(a(2))
            handle = 0x1000 + 4 * len(self.files)
            self.files.append({"handle": handle, "path": path,
                               "access": a(1), "offset": 0,
                               "data": self.backing(path)})
            wr(a(0), handle)
            if a(3):
                mu.mem_write(a(3), struct.pack("<II", 0, 1))   # STATUS_SUCCESS, FILE_OPENED
            val = 0
        elif name == "NtReadFile":
            # (Handle, Event, Apc, ApcCtx, PIO_STATUS_BLOCK, Buffer, Length,
            #  ByteOffset, Key) -- 9 args.
            nargs = 9
            f = next((x for x in self.files if x["handle"] == a(0)), None)
            length, buf = a(6), a(5)
            offset = f["offset"] if f else 0
            if a(7):
                try:
                    offset = struct.unpack("<Q", mu.mem_read(a(7), 8))[0]
                except UcError:
                    pass
            if f is None or not f["data"] or offset >= len(f["data"]):
                if a(4):
                    mu.mem_write(a(4), struct.pack("<II", 0xC0000011, 0))
                val = 0xC0000011                              # STATUS_END_OF_FILE
            else:
                chunk = f["data"][offset:offset + length]
                if chunk and buf:
                    mu.mem_write(buf, chunk)
                f["offset"] = offset + len(chunk)
                if a(4):
                    mu.mem_write(a(4), struct.pack("<II", 0, len(chunk)))
                val = 0
        elif name == "NtQueryInformationFile":
            # (Handle, IoStatusBlock, FileInformation, Length, FileInfoClass)
            nargs = 5
            f = next((x for x in self.files if x["handle"] == a(0)), None)
            size = len(f["data"]) if f else 0
            if a(4) == 5 and a(2):                            # FileStandardInformation
                mu.mem_write(a(2), struct.pack("<QQIBB6x", size, size, 1, 0, 0))
            if a(1):
                mu.mem_write(a(1), struct.pack("<II", 0, a(3)))
            val = 0
        elif name == "NtSetInformationFile":
            if a(1):
                mu.mem_write(a(1), struct.pack("<II", 0, 0))
            val, nargs = 0, 5
        elif name == "NtQueryInformationProcess":
            # (Handle, InfoClass, Buffer, Length, *ReturnLength)
            nargs = 5
            info_class, buf = a(1), a(2)
            # The three debugger-detection classes. All three have one correct
            # answer for a machine with no debugger attached, so none of this is
            # invented -- and answering them wrong is how a harness talks a
            # sample into bailing and then gets read as the sample being dormant.
            if info_class == 0x07:                # ProcessDebugPort
                wr(buf, 0)
                wr(a(4), 4)
                val = 0
            elif info_class == 0x1E:              # ProcessDebugObjectHandle
                wr(buf, 0)
                wr(a(4), 4)
                val = 0xC0000353                  # STATUS_PORT_NOT_SET
            elif info_class == 0x1F:              # ProcessDebugFlags
                wr(buf, 1)                        # 1 == *not* being debugged
                wr(a(4), 4)
                val = 0
            else:
                self.unhandled[f"{name}(class {info_class:#x})"] += 1
                val = 0xC0000002
        elif name == "NtFreeVirtualMemory":
            # (Handle, *BaseAddress, *RegionSize, FreeType). Nothing is actually
            # released: the bump allocator never reuses an address. Worth stating
            # rather than assuming benign, since a payload that frees a block and
            # expects the next allocation to land back on it diverges here
            # quietly instead of faulting.
            val, nargs = 0, 4
        elif name == "NtQuerySystemInformation":
            # (SystemInformationClass, Buffer, Length, *ReturnLength)
            nargs = 4
            info_class, buf, length = a(0), a(1), a(2)
            if info_class == 0x23:            # SystemKernelDebuggerInformation
                # Two BOOLEANs -- KernelDebuggerEnabled, KernelDebuggerNotPresent
                # -- which is why the caller asks for exactly 2 bytes. This is an
                # anti-debug check, and the first one this chain has been seen to
                # make: it is invisible to any Win32 hook and leaves no string,
                # which is why the token and instruction sweeps over stage 3 found
                # nothing. Answered as an ordinary machine with no kernel debugger.
                if buf and length >= 2:
                    mu.mem_write(buf, b"\x00\x01")
                wr(a(3), 2)
                val = 0
            elif info_class == 0x05:          # SystemProcessInformation
                blob = winenv.system_process_information(buf)
                if not buf or length < len(blob):
                    # What a real kernel says, and the caller is built for it --
                    # it is how every process enumeration sizes its buffer.
                    wr(a(3), len(blob))
                    val = 0xC0000004          # STATUS_INFO_LENGTH_MISMATCH
                else:
                    mu.mem_write(buf, blob)
                    wr(a(3), len(blob))
                    self.served_process_list += 1
                    val = 0
            else:
                # Named by class rather than by API, so the gap says which
                # question went unanswered instead of implying the whole call is
                # unimplemented.
                self.unhandled[f"{name}(class {info_class:#x})"] += 1
                val = 0xC0000002
        elif name in ("NtOpenDirectoryObject", "NtCreateMutant", "NtOpenMutant",
                      "NtCreateEvent", "NtOpenEvent"):
            # All of these carry a name in their OBJECT_ATTRIBUTES, and the name
            # is the point. A loader's mutant is its single-instance marker and
            # is an IOC on sight -- this chain has produced none in nine
            # detonations, because it crashes before it gets here.
            nargs = {"NtOpenDirectoryObject": 3, "NtCreateMutant": 4,
                     "NtOpenMutant": 3, "NtCreateEvent": 5, "NtOpenEvent": 3}[name]
            handle = self.new_handle()
            self.named_objects.append({"call": name, "name": self.object_name(a(2)),
                                       "handle": handle, "blocks": self.blocks})
            wr(a(0), handle)
            val = 0
        elif name in ("NtOpenProcess", "NtOpenThread"):
            # (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID)
            nargs = 4
            pid = 0
            if a(3):
                try:
                    pid = struct.unpack("<I", mu.mem_read(a(3), 4))[0]
                except UcError:
                    pid = 0
            known = {p for _, p, _ in winenv.served_process_list()}
            if pid and pid not in known:
                # Refuse a pid this harness never claimed existed. The process
                # list is a fiction and it has to be a *consistent* one -- a
                # handle to a process that was not in the list it just served
                # would be a second, contradictory invention.
                self.remote_targets.append({"call": name, "pid": pid,
                                            "opened": False, "blocks": self.blocks})
                val = 0xC000000B                          # STATUS_INVALID_CID
            else:
                handle = self.new_handle()
                self.process_handles[handle] = pid
                self.remote_targets.append({"call": name, "pid": pid, "opened": True,
                                            "handle": handle, "blocks": self.blocks})
                wr(a(0), handle)
                val = 0
        elif name == "NtWriteVirtualMemory":
            # (Handle, BaseAddress, Buffer, NumberOfBytes, *NumberOfBytesWritten)
            #
            # **This is the one that matters.** Everything above exists to reach
            # it: what a loader writes into another process is the next stage,
            # and no detonation has ever caught it. The bytes are copied out
            # here and kept whether or not the write "succeeds".
            nargs = 5
            dest, src, count = a(1), a(2), a(3)
            data = b""
            if 0 < count <= 0x4000000:
                try:
                    data = bytes(mu.mem_read(src, count))
                except UcError:
                    data = b""
            self.remote_writes.append({
                "blocks": self.blocks,
                "pid": self.process_handles.get(a(0)),
                "handle": a(0), "dest": dest, "size": count, "data": data})
            if dest and data:
                # Also land it somewhere readable, so the end-of-run PE scan and
                # --dump see it like any other allocation.
                try:
                    mu.mem_write(dest, data)
                except UcError:
                    pass
            wr(a(4), len(data))
            val = 0
        elif name == "NtReadVirtualMemory":
            nargs = 5
            wr(a(4), 0)
            val = 0xC0000005                              # STATUS_ACCESS_VIOLATION
        elif name == "NtProtectVirtualMemory":
            # (Handle, *BaseAddress, *Size, NewProtect, *OldProtect)
            nargs = 5
            wr(a(4), 0x40)
            val = 0
        elif name == "NtCreateSection":
            # (PHANDLE, ACCESS, ObjAttr, PLARGE_INTEGER MaxSize, Protect,
            #  Attributes, FileHandle)
            nargs = 7
            size = 0x1000
            raw = b""
            if a(3):
                try:
                    raw = bytes(mu.mem_read(a(3), 8))
                    size = struct.unpack("<Q", raw)[0] or 0x1000
                except UcError:
                    pass
            handle = self.new_handle()
            self.sections[handle] = min(max(size, 0x1000), 0x4000000)
            # Log the size the *sample* asked for, not the clamped one. A view
            # is carved out of the already-mapped heap by `alloc`, which never
            # zeroes, so an oversized section reads back full of stale bytes
            # from earlier in the run and looks like 24 MB of written payload.
            # The requested size is what tells those apart.
            self.section_requests.append({
                "handle": handle, "raw": raw.hex(), "requested": size,
                "granted": self.sections[handle], "blocks": self.blocks})
            wr(a(0), handle)
            val = 0
        elif name == "NtMapViewOfSection":
            # (Section, Process, *Base, ZeroBits, CommitSize, *Offset, *ViewSize,
            #  InheritDisposition, AllocationType, Protect)
            #
            # Section-based injection maps the same section twice -- once here
            # and once into the target -- and copies the payload into the local
            # view with ordinary instructions. That copy raises no API call at
            # all, so the view has to be a real allocation the end-of-run scan
            # can find; nothing else would ever see the bytes.
            nargs = 10
            size = self.sections.get(a(0), 0x1000)
            existing = self.section_views.get(a(0))
            p = existing if existing else self.alloc(size)
            self.section_views[a(0)] = p
            if not existing:
                self._watch_section_view(p, size)
            wr(a(2), p)
            if a(6):
                mu.mem_write(a(6), struct.pack("<I", size))
            self.section_maps.append({
                "blocks": self.blocks, "section": a(0), "at": p, "size": size,
                "pid": self.process_handles.get(a(1))})
            val = 0
        elif name == "NtUnmapViewOfSection":
            val, nargs = 0, 2
        elif name in ("NtGetContextThread", "NtSetContextThread"):
            # (HANDLE, PCONTEXT). These went unhandled until 14 Aug, which set
            # `nargs` to 0 and left both arguments on the stack for the caller's
            # own `ret` to return into -- so **everything after the first of
            # them was unsound**, including the NtResumeThread and the 36
            # NtDelayExecution calls that followed it. Getting the arity right
            # is the fix; capturing the record is the point.
            nargs = 2
            ctx_ptr = a(1)
            if name == "NtSetContextThread":
                # The loader is saying where the injected code starts.
                try:
                    raw = bytes(mu.mem_read(ctx_ptr, CONTEXT_SIZE))
                except UcError:
                    raw = b""
                fields = decode_context(raw) if raw else {}
                self.thread_contexts.append({
                    "call": name, "blocks": self.blocks, "handle": a(0),
                    "context_at": ctx_ptr, "fields": fields})
                if fields:
                    print(f"  [{self.blocks:,}blk] {name} eip={fields.get('Eip', 0):#x} "
                          f"eax={fields.get('Eax', 0):#x} esp={fields.get('Esp', 0):#x} "
                          f"flags={fields.get('ContextFlags', 0):#x}", flush=True)
            else:
                # Describe a *remote* thread, not this one.
                #
                # The first version answered with the live machine's registers,
                # which is wrong in a way that survives a long way downstream:
                # the loader copies what it reads into the record it later hands
                # to NtSetContextThread, so the injected thread inherited the
                # loader's Esp, ran on the loader's stack, and destroyed it. The
                # value looked entirely plausible -- it was a real mapped stack
                # address -- which is exactly why it went unnoticed until the
                # loader was resumed after the injected code had run.
                self._map_remote_stack()
                if ctx_ptr:
                    blob = bytearray(CONTEXT_SIZE)
                    remote = {
                        "Esp": self.remote_esp,
                        "Ebp": self.remote_esp,
                        # Parked in ntdll, where a suspended thread waits.
                        #
                        # 0x79FF0, not 0x9FF0. The first version dropped the 7
                        # and its commit message claimed the value matched the
                        # observed park address, which it did not -- the loader
                        # parks at 0x77079ff0. It matters more than a wrong
                        # constant usually would: the loader patches this into
                        # the injected trampoline as the resume address, so the
                        # payload `ret`s straight into it when it finishes. With
                        # the digit missing that landed in a data table inside
                        # ntdll's .text and looked exactly like the payload
                        # crashing, when in fact it had completed.
                        "Eip": winenv.NTDLL_BASE + 0x79FF0,
                        "Eax": 0,
                        "ContextFlags": 0x10007,        # CONTEXT_FULL
                        "SegCs": 0x23,
                        "SegSs": 0x2B,
                    }
                    for field, value in remote.items():
                        struct.pack_into("<I", blob, CONTEXT_OFFSETS[field], value)
                    try:
                        mu.mem_write(ctx_ptr, bytes(blob))
                    except UcError:
                        pass
                self.thread_contexts.append({
                    "call": name, "blocks": self.blocks, "handle": a(0),
                    "context_at": ctx_ptr, "fields": {}})
            val = 0
        elif name in ("NtQueueApcThread", "NtResumeThread", "NtSuspendThread",
                      "NtTerminateProcess", "NtTerminateThread"):
            # Recorded and answered success. Arity matters more than behaviour:
            # these end a chain rather than feed one, and what has already been
            # captured is the finding.
            nargs = {"NtQueueApcThread": 5, "NtResumeThread": 2,
                     "NtSuspendThread": 2, "NtTerminateProcess": 2,
                     "NtTerminateThread": 2}[name]
            self.control_calls.append({"call": name, "blocks": self.blocks,
                                       "args": [a(i) for i in range(nargs)]})
            # The injection is complete here: the view is mapped and written and
            # the target's thread has been pointed at it. Everything after this
            # starts from this moment, and reaching it costs ~380M blocks from
            # `after_scan.state`. Save it once and every later experiment starts
            # in seconds instead.
            if name == "NtResumeThread" and self.snapshot_on_resume:
                path = self.snapshot_on_resume
                self.snapshot_on_resume = None      # the first resume, not each
                self.snapshot(path)
                print(f"  [{self.blocks:,}blk] snapshot after the injection -> {path}",
                      flush=True)
            val = 0
        elif name == "NtDelayExecution":
            # (Alertable, PLARGE_INTEGER Interval). Negative is a relative
            # interval in 100ns units; positive is an absolute time. The sleep
            # does not happen, but the clock moves as though it had -- otherwise
            # a payload that waits before acting waits forever and the run reads
            # as "it did nothing".
            nargs = 2
            if a(1):
                try:
                    interval = struct.unpack("<q", mu.mem_read(a(1), 8))[0]
                except UcError:
                    interval = 0
                if interval < 0:
                    self.clock_sleep_100ns += -interval
                elif interval > 0:
                    ahead = interval - (winenv._FROZEN_FILETIME + self.elapsed_100ns())
                    self.clock_sleep_100ns += max(ahead, 0)
            self.advance_clock()
            val = 0
        elif name == "NtWaitForSingleObject":
            val, nargs = 0, 3
        elif name == "NtQueryAttributesFile":
            val, nargs = 0xC0000034, 2                        # OBJECT_NAME_NOT_FOUND
        elif name == "NtClose":
            val, nargs = 0, 1
        elif name in ("RtlInitUnicodeString", "RtlInitAnsiString"):
            val, nargs = 0, 2
        elif name == "RtlFreeUnicodeString":
            val, nargs = 0, 1
        elif name == "RtlQueryEnvironmentVariable_U":
            # (Environment, PUNICODE_STRING Name, PUNICODE_STRING Value)
            nargs = 3
            var = self.unicode_string(a(1))
            self.env_queries.append(var)
            # Answered from `winenv.ENVIRONMENT`, which is invented and says so.
            # It used to return VARIABLE_NOT_FOUND on the grounds that there is
            # no environment block to answer from -- honest, and it made the
            # harness a candidate cause for the sample doing nothing. A name it
            # does not know still gets the real "absent" status, so the two
            # cases stay distinguishable.
            value = winenv.ENVIRONMENT.get(var)
            if value is None:
                val = 0xC0000100                              # VARIABLE_NOT_FOUND
            else:
                wide = value.encode("utf-16-le")
                out = a(2)
                try:
                    _, maximum, buf = struct.unpack("<HHI", mu.mem_read(out, 8))
                except UcError:
                    maximum, buf = 0, 0
                if buf and maximum >= len(wide) + 2:
                    mu.mem_write(buf, wide + b"\0\0")
                    mu.mem_write(out, struct.pack("<H", len(wide)))
                    self.env_answers.append((var, value))
                    val = 0
                else:
                    # Length is the required size on this path, which is how the
                    # caller learns how much to allocate.
                    if out:
                        mu.mem_write(out, struct.pack("<H", len(wide)))
                    val = 0xC0000023                          # BUFFER_TOO_SMALL
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
            #
            # Said at the moment it happens, not only in the summary, because
            # the damage does not surface here: with `nargs` at 0 the arguments
            # are left on the stack, and the caller's own `ret` then returns
            # into them. `RtlQueryEnvironmentVariable_U` going unhandled showed
            # up as a fetch from address 0 ten million blocks downstream, which
            # is indistinguishable from a fresh mystery unless this line is in
            # the log above it.
            if name not in self.unhandled:
                print(f"  [{self.blocks:,}blk] UNHANDLED {name} -- answered "
                      f"{unhandled_value:#x} and its arguments left on the stack; "
                      f"expect the caller to return into them", flush=True)
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
            # At the gate `ret` is the stub's own `ret imm16`, which says
            # nothing about who wanted the call. The payload's return address
            # is the next dword up, and that is the one worth recording.
            caller = ret
            if ssn is not None:
                try:
                    caller = struct.unpack("<I", mu.mem_read(esp + 4, 4))[0]
                except UcError:
                    pass
            self.log.append({
                "seq": len(self.log),
                "blocks": self.blocks,
                "name": name,
                "caller": caller,
                "args": args,
                "speculative_args": speculative,
                "returned": val,
                "popped": 4 * nargs,
                "via": "syscall" if ssn is not None else "export",
                "ssn": ssn,
            })

        mu.reg_write(UC_X86_REG_EAX, val)
        mu.reg_write(UC_X86_REG_EIP, ret)
        mu.reg_write(UC_X86_REG_ESP,
                     esp + (cleanup if cleanup is not None else 4 + 4 * nargs))

    def run(self, entry: int, stop: int, count: int = 0) -> str:
        """Run, and say what actually happened when it stops.

        A fetch from address 0 is reported as a fault by Unicorn and is not
        always one. Nothing pushes a sentinel return address onto the initial
        stack, so when the entry function finally returns it pops a zero and
        "faults" at 0 with ESP back above where it started. That is a payload
        running to completion, and calling it a crash is a real misreading --
        this sample's bail-out was recorded as a jump to address 0 for exactly
        that reason. The two are told apart by ESP, not by EIP.
        """
        try:
            self.mu.emu_start(self.base + entry, self.base + stop,
                              timeout=0, count=count)
            return "returned or budget reached"
        except UcError as e:
            eip = self.mu.reg_read(UC_X86_REG_EIP)
            esp = self.mu.reg_read(UC_X86_REG_ESP)
            if eip == 0 and esp > STACK + STACK_SIZE // 2:
                return (f"the entry function RETURNED "
                        f"(eax {self.mu.reg_read(UC_X86_REG_EAX):#x}); the fetch "
                        f"from 0 is the initial stack having no sentinel on it, "
                        f"not a fault")
            return f"{e} at eip {eip:#x}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("payload", help="a carved native PE; .xor9 is unwrapped in memory")
    ap.add_argument("--entry", type=lambda s: int(s, 0), default=0,
                    help="RVA to start at, normally the PE entry point")
    ap.add_argument("--stop", type=lambda s: int(s, 0), default=0,
                    help="RVA to stop at")
    ap.add_argument("--blocks", type=int, default=50_000_000,
                    help="instruction budget before giving up")
    ap.add_argument("--dump", metavar="DIR", help="write every allocation here")
    ap.add_argument("--snapshot-after-inject", metavar="FILE",
                    help="save state at the first NtResumeThread, so later work "
                         "starts at the injection instead of 380M blocks before it")
    ap.add_argument("--log-api", action="store_true",
                    help="record every API call with arguments and return value")
    ap.add_argument("--log-json", metavar="FILE", help="write the API log as JSON")
    ap.add_argument("--save-state", metavar="FILE",
                    help="freeze the process to FILE when the budget is reached")
    ap.add_argument("--load-state", metavar="FILE",
                    help="resume from FILE instead of starting at --entry")
    args = ap.parse_args(argv)

    path = Path(args.payload)
    raw = path.read_bytes()
    if path.suffix == XOR_SUFFIX:
        raw = xor_unwrap(raw)

    if args.load_state:
        emu = Emulator.restore(args.load_state)
        if (args.log_api or args.log_json) and emu.log is None:
            emu.log = []
        print(f"restored from {args.load_state}: "
              f"eip {emu.mu.reg_read(UC_X86_REG_EIP):#x}, {emu.blocks:,} blocks already run")
        if emu.repair_wow64_crash():
            ssn = emu.mu.reg_read(UC_X86_REG_EAX) & 0xFFFF
            print(f"  state was captured at the jump through an empty "
                  f"Wow64Transition; resuming at the gate as "
                  f"{emu.ssn2name[ssn]} (ssn {ssn:#x})")
        emu.snapshot_on_resume = args.snapshot_after_inject
        print(f"stopped: {emu.resume(count=args.blocks)}")
    else:
        emu = Emulator(raw)
        if args.log_api or args.log_json:
            emu.log = []
        emu.snapshot_on_resume = args.snapshot_after_inject
        print(f"image {len(raw)} bytes at {emu.base:#x}, entry {args.entry:#x}")
        print(f"stopped: {emu.run(args.entry, args.stop or 0xFFFFFFF, count=args.blocks)}")
    if args.save_state:
        emu.snapshot(args.save_state)
        print(f"state saved to {args.save_state} "
              f"({Path(args.save_state).stat().st_size / 1e6:.1f} MB)")
    print(f"basic blocks: {emu.blocks}")
    print(f"api calls: {dict(emu.calls)}")
    if emu.syscalls:
        print(f"of those, reached at the SYSCALL boundary: {dict(emu.syscalls)}")
    if emu.unknown_ssn:
        print(f"service numbers this ntdll has no name for: "
              f"{ {hex(k): v for k, v in emu.unknown_ssn.items()} }")
    if emu.patched_ntdll:
        print("stale Wow64Transition repaired in a resumed snapshot (never on a "
              "live run -- the payload does this itself at 0x202f457): "
              + ", ".join(f"{b:#x}" for _, b in emu.patched_ntdll))
    if emu.env_queries:
        print(f"environment variables asked for: {emu.env_queries}")
        print(f"  answered from winenv.ENVIRONMENT (INVENTED): {emu.env_answers}")
    print(f"emulated time elapsed: {emu.elapsed_100ns() / 1e7:.2f}s "
          f"({emu.clock_sleep_100ns / 1e7:.2f}s of it slept)")
    if emu.served_process_list:
        print(f"\nprocess list served {emu.served_process_list}x -- INVENTED, from "
              f"winenv.served_process_list() ({len(winenv.served_process_list())} "
              f"entries incl. {', '.join(n for n, _, _ in winenv.served_process_list()[-2:])}). "
              f"Everything "
              f"below is conditional on it.")
    if emu.named_objects:
        print("\nnamed kernel objects (a loader's mutant is an IOC):")
        for o in emu.named_objects:
            print(f"  {o['blocks']:>13,}blk  {o['call']}({o['name']!r})")
    if emu.remote_targets:
        print("\nprocesses it tried to open:")
        for t in emu.remote_targets:
            who = next((n for n, p, _ in winenv.served_process_list() if p == t["pid"]), "?")
            print(f"  {t['blocks']:>13,}blk  {t['call']} pid {t['pid']} ({who})"
                  f"  {'opened' if t['opened'] else 'REFUSED - not in the served list'}")
    if emu.thread_contexts:
        print("\nthread contexts (NtSetContextThread names the injected entry):")
        for c in emu.thread_contexts:
            f = c["fields"]
            if f:
                print(f"  {c['blocks']:>13,}blk  {c['call']} handle {c['handle']:#x}  "
                      f"eip={f.get('Eip', 0):#010x} eax={f.get('Eax', 0):#010x} "
                      f"esp={f.get('Esp', 0):#010x}")
            else:
                print(f"  {c['blocks']:>13,}blk  {c['call']} handle {c['handle']:#x}  "
                      f"(record at {c['context_at']:#x})")
    if emu.section_requests:
        print("\nsections requested (the size the sample asked for):")
        for r in emu.section_requests:
            print(f"  {r['blocks']:>13,}blk  MaximumSize raw {r['raw']} -> "
                  f"{r['requested']:#x} ({r['requested']:,} bytes), "
                  f"granted {r['granted']:#x}")
    if emu.section_writes:
        print("\nbytes actually written into section views:")
        for w in emu.section_writes:
            total = sum(e - s2 for s2, e in w["spans"])
            print(f"  view at {w['base']:#x} ({w['size']:,} bytes): "
                  f"{total:,} bytes written across {len(w['spans'])} span(s)")
            for s2, e in w["spans"][:12]:
                print(f"    {s2:#x}-{e:#x}  (+{s2 - w['base']:#x}, {e - s2:,} bytes)")
            if len(w["spans"]) > 12:
                print(f"    ... {len(w['spans']) - 12} more spans")
    if emu.section_maps:
        print("\nsection views mapped:")
        for m in emu.section_maps:
            where = f"into pid {m['pid']}" if m["pid"] else "locally"
            print(f"  {m['blocks']:>13,}blk  section {m['section']:#x} {where} "
                  f"at {m['at']:#x}, {m['size']:#x} bytes")
    if emu.control_calls:
        print("\nexecution-control calls:")
        for c in emu.control_calls:
            print(f"  {c['blocks']:>13,}blk  {c['call']}"
                  f"({', '.join(hex(x) for x in c['args'])})")
    if emu.remote_writes:
        import hashlib
        print(f"\n*** {len(emu.remote_writes)} WRITE(S) INTO ANOTHER PROCESS ***")
        for i, w in enumerate(emu.remote_writes):
            data = w["data"]
            tag = ""
            if data[:2] == b"MZ":
                e = int.from_bytes(data[0x3C:0x40], "little")
                if 0x40 <= e < 0x1000 and data[e:e + 4] == b"PE\0\0":
                    tag = "   <-- a PE. This is the next stage."
            print(f"  [{i}] {w['blocks']:,}blk  pid {w['pid']} at {w['dest']:#x}  "
                  f"{w['size']:#x} bytes  sha256 "
                  f"{hashlib.sha256(data).hexdigest()[:32]}{tag}")
            if args.dump and data:
                out = Path(args.dump)
                out.mkdir(parents=True, exist_ok=True)
                f = out / f"remote_write_{i}_pid{w['pid']}_{w['dest']:x}.bin_"
                f.write_bytes(data)
                print(f"       written to {f}")
    if emu.unhandled:
        print(f"UNHANDLED apis (answered without doing anything): {dict(emu.unhandled)}")
    if emu.faults:
        access, addr, eip = emu.faults[0]
        print(f"first fault: access {access} addr {addr:#x} eip {eip:#x}")
    print(f"allocations: {[(hex(p), hex(n)) for p, n in emu.allocs]}")
    if emu.files:
        print(f"\nfiles opened ({len(emu.files)}):")
        for f in emu.files:
            print(f"  handle {f['handle']:#x}  access {f['access']:#010x}  {f['path']!r}")

    if emu.log is not None:
        print(f"\n{len(emu.log)} API calls, in order:")
        for e in emu.log:
            flag = "  <-- args are a GUESS, and so is the stack fixup" \
                if e["speculative_args"] else ""
            how = f" ssn {e['ssn']:#x}" if e.get("ssn") is not None else ""
            print(f"  [{e['seq']:4d}] {e['blocks']:>10,}blk  from {e['caller']:#010x}{how}  "
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
