"""A minimal 32-bit Windows process image for Unicorn.

Enough PEB/TEB and a synthetic kernel32/ntdll export table for shellcode that
resolves its imports by walking the loader module list. Each fake DLL carries
its own stub area at RVA 0x2000; every export points there, and a code hook on
those addresses implements the API in Python.
"""
import collections
import struct
from unicorn import *
from unicorn.x86_const import *

TEB_ADDR, PEB_ADDR, LDR_ADDR = 0x7FFDD000, 0x7FFDF000, 0x7FFD0000
HEAP_BASE, HEAP_SIZE = 0x02000000, 0x08000000
KERNEL32_BASE, NTDLL_BASE = 0x76000000, 0x77000000
DLL_SIZE = 0x100000
STUB_RVA = 0x40000

def real_exports(path):
    """Export names from the host's own 32-bit system DLL.

    Guessing a name list is the wrong shape of work: whatever name the shellcode
    resolves has to be present, or resolution silently yields 0 and it calls it.
    The real DLL is authoritative, and it is sitting on this machine.
    """
    import pefile
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories([0])
    return [e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name]


SYSWOW64 = "C:/Windows/SysWOW64/"
DLL_EXPORTS = {
    "KERNEL32.DLL": real_exports(SYSWOW64 + "kernel32.dll"),
    "ntdll.dll": real_exports(SYSWOW64 + "ntdll.dll"),
}

EXPORTS = [
    "VirtualAlloc", "VirtualAllocEx", "VirtualFree", "VirtualProtect",
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "GetModuleHandleA",
    "GetModuleHandleW", "GetProcessHeap", "HeapAlloc", "HeapFree", "HeapReAlloc",
    "RtlAllocateHeap", "RtlFreeHeap", "RtlMoveMemory", "RtlZeroMemory",
    "memcpy", "memset", "malloc", "free",
    "ExitProcess", "ExitThread", "GetLastError", "SetLastError", "CloseHandle",
    "CreateFileA", "CreateFileW", "WriteFile", "ReadFile",
    "GetCurrentProcess", "GetCurrentProcessId", "GetCurrentThread", "Sleep",
    "GetTickCount", "QueryPerformanceCounter", "IsDebuggerPresent",
    "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "ZwAllocateVirtualMemory",
    "LocalAlloc", "GlobalAlloc", "GetSystemInfo", "FlushInstructionCache",
    "CreateThread", "WaitForSingleObject", "GetModuleFileNameA", "GetModuleFileNameW",
    "LocalFree", "GlobalFree", "lstrlenA", "lstrlenW", "lstrcmpiA",
]


GDT_ADDR, GDT_LIMIT = 0x30000, 0x1000


def _gdt_entry(base, limit, access, flags):
    v = limit & 0xFFFF
    v |= (base & 0xFFFFFF) << 16
    v |= (access & 0xFF) << 40
    v |= ((limit >> 16) & 0xF) << 48
    v |= (flags & 0xF) << 52
    v |= ((base >> 24) & 0xFF) << 56
    return struct.pack("<Q", v)


def install_gdt(mu, teb):
    """Give FS a real descriptor based at the TEB.

    `UC_X86_REG_FS_BASE` is a no-op in 32-bit mode -- it writes without error and
    `fs:[0x18]` still faults, which is the kind of silent failure worth naming.
    A segmented read needs an actual GDT.
    """
    mu.mem_map(GDT_ADDR, GDT_LIMIT)
    # flat code/data at 0, plus an FS descriptor based at the TEB
    flat_code = _gdt_entry(0, 0xFFFFF, 0x9A, 0xC)   # present, ring0, code, 32-bit, 4K
    flat_data = _gdt_entry(0, 0xFFFFF, 0x92, 0xC)   # present, ring0, data, 32-bit, 4K
    fs_desc = _gdt_entry(teb, 0xFFF, 0x92, 0x4)     # byte granular, one page
    mu.mem_write(GDT_ADDR + 8 * 1, flat_code)
    mu.mem_write(GDT_ADDR + 8 * 2, flat_data)
    mu.mem_write(GDT_ADDR + 8 * 3, fs_desc)
    mu.reg_write(UC_X86_REG_GDTR, (0, GDT_ADDR, GDT_LIMIT, 0x0))
    mu.reg_write(UC_X86_REG_CS, 1 << 3)
    for r in (UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
        mu.reg_write(r, 2 << 3)
    mu.reg_write(UC_X86_REG_FS, 3 << 3)


_STUB_INDEX = {}

def stub_addr(base, name):
    return base + STUB_RVA + 0x10 * _STUB_INDEX[base][name]


def build_fake_dll(name, base):
    exports = DLL_EXPORTS[name]
    _STUB_INDEX[base] = {fn: i for i, fn in enumerate(exports)}
    """A PE image with a real export directory, laid out flat at `base`."""
    img = bytearray(DLL_SIZE)
    img[0:2] = b"MZ"
    struct.pack_into("<I", img, 0x3C, 0x80)
    struct.pack_into("<4sHH", img, 0x80, b"PE\0\0", 0x014C, 1)
    struct.pack_into("<H", img, 0x80 + 20, 0xE0)          # SizeOfOptionalHeader
    struct.pack_into("<H", img, 0x80 + 24, 0x10B)         # PE32
    struct.pack_into("<I", img, 0x80 + 24 + 52, base)     # ImageBase
    struct.pack_into("<I", img, 0x80 + 24 + 56, DLL_SIZE)  # SizeOfImage
    struct.pack_into("<I", img, 0x80 + 24 + 92, 16)       # NumberOfRvaAndSizes
    struct.pack_into("<II", img, 0x80 + 24 + 96, 0x1000, 0x1000)   # export dir

    ordered = sorted(exports)                              # names must be sorted
    n = len(ordered)
    addr_rva, name_rva, ord_rva = 0x1100, 0x1100 + 4 * n, 0x1100 + 8 * n
    cur = 0x1100 + 10 * n   # name strings follow the three parallel arrays
    # IMAGE_EXPORT_DIRECTORY: Characteristics, TimeDateStamp, Major, Minor,
    # Name, Base, NumberOfFunctions, NumberOfNames, AddressOfFunctions,
    # AddressOfNames, AddressOfNameOrdinals
    struct.pack_into("<IIHHIIIIIII", img, 0x1000,
                     0, 0, 0, 0, 0x1080, 1, n, n, addr_rva, name_rva, ord_rva)
    img[0x1080:0x1080 + len(name)] = name.encode()
    for i, fn in enumerate(ordered):
        struct.pack_into("<I", img, addr_rva + 4 * i, STUB_RVA + 0x10 * _STUB_INDEX[base][fn])
        struct.pack_into("<I", img, name_rva + 4 * i, cur)
        struct.pack_into("<H", img, ord_rva + 2 * i, i)
        img[cur:cur + len(fn)] = fn.encode()
        cur += len(fn) + 1
    img[STUB_RVA:STUB_RVA + 0x10 * len(EXPORTS)] = b"\xc3" * (0x10 * len(EXPORTS))
    return bytes(img)


#: Modules beyond kernel32/ntdll, present so the loader list looks like a real
#: process. This is not cosmetic. Stage 3's unpacked code CRC-32s every name in
#: the list looking for one it knows, and with a three-entry list it found no
#: match and retried forever -- 2.3 billion instructions hashing
#: `kernel32.dll`, `ntdll.dll` and `stage3.exe`, the last of which was a name
#: this file invented. A short module list is a divergence, not a simplification.
EXTRA_MODULES = (
    "user32.dll", "advapi32.dll", "msvcrt.dll", "ole32.dll", "oleaut32.dll",
    "shell32.dll", "shlwapi.dll", "ws2_32.dll", "wininet.dll", "crypt32.dll",
    "gdi32.dll", "rpcrt4.dll", "sechost.dll", "combase.dll", "kernelbase.dll",
    "urlmon.dll", "psapi.dll", "version.dll", "userenv.dll", "netapi32.dll",
)
EXTRA_BASE = 0x70000000
EXTRA_STRIDE = 0x100000

#: The process image's own name. `RegSvcs.exe` is what this sample hollows, so
#: it is what the payload would see on a real run.
IMAGE_NAME = "RegSvcs.exe"


def map_real_dll(mu, path, base):
    """Map a real system DLL the way the loader would, and index its exports.

    Synthetic DLLs were adequate while the payload only resolved names. They
    stop being adequate the moment it *inspects* them: stage 3 reads a clean
    `ntdll` off disk and walks the loaded copy against it looking for hooks, and
    a 1 MB stub of mostly zeros faults as soon as it reads past the end. A real
    mapped image is both simpler and more honest -- headers and sections at
    their true RVAs, real SizeOfImage, real export table.

    Interception then happens at each export's real address rather than at a
    trampoline, so the image stays byte-correct for anything that checksums it.
    Returns {virtual address: export name}.
    """
    import pefile

    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories([0])
    size = (pe.OPTIONAL_HEADER.SizeOfImage + 0xFFF) & ~0xFFF
    mu.mem_map(base, size)
    mu.mem_write(base, pe.header)
    for section in pe.sections:
        data = section.get_data()
        if data:
            mu.mem_write(base + section.VirtualAddress, data)
    # ImageBase in the mapped copy has to agree with where it actually sits, or
    # anything doing RVA arithmetic from the header lands in the wrong place.
    mu.mem_write(base + pe.DOS_HEADER.e_lfanew + 24 + 28, struct.pack("<I", base))

    exports = {}
    for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if not (entry.name and entry.address):
            continue
        name = entry.name.decode()
        va = base + entry.address
        # In user-mode ntdll, NtXxx and ZwXxx are the *same address*, so one
        # index entry has to win. Prefer the Nt spelling: handlers key on it,
        # and picking whichever came last in the export table silently left
        # every syscall unhandled under its Zw alias.
        previous = exports.get(va)
        if previous is None or (name.startswith("Nt") and previous.startswith("Zw")):
            exports[va] = name
    return exports, size


#: Where the stand-in WOW64 transition lives. Any unused address works; this one
#: is clear of the module bases above and of the heap.
SYSCALL_GATE = 0x74A01000


def syscall_table(path=None):
    """`{service number: Nt name}` and the RVA of `Wow64Transition`.

    Read out of the real ntdll's own stubs, because that is the only place the
    numbering exists -- it is a property of the build, not of the API.

    The service number is the **low word** of the immediate in the stub's
    leading `mov eax, imm32`. 99 of this host's stubs carry a non-zero high
    word (`NtDelayExecution` is `0x60034`), which selects a wow64cpu turbo
    thunk and is not part of the number.

    Two stub shapes have to be accepted, and missing the second cost a name:

        mov eax, SSN ; mov edx, <thunk> ; call edx ; ret N
        mov eax, SSN ; call $+5 ; pop edx ; cmp byte [edx+0x14], 0x4b ; jne
                     ; call dword ptr fs:[0xC0] ; ret N ; mov edx, <thunk>
                     ; call edx ; ret N

    The second picks its transition at run time and is why `fs:[0xC0]` has to
    be filled in as well as the `Wow64Transition` slot. On this host exactly
    one export uses it -- `NtQueryInformationProcess` -- and a parse that only
    knew the first shape returned a table with one hole in it, which surfaced
    as the payload making a call to an unnamed service number.

    Two assertions, neither of which needs to know what the answer should be:
    the numbers must be unique, and they must be **contiguous from zero**. A
    kernel service table has no gaps, so a gap means a stub shape went
    unrecognised -- the same style of check as counting the bytes an
    instruction decoder could not name.
    """
    import pefile

    pe = pefile.PE(path or (SYSWOW64 + "ntdll.dll"), fast_load=True)
    pe.parse_data_directories([0])
    image = pe.get_memory_mapped_image()

    stubs, transition = {}, None
    for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if not (sym.name and sym.address):
            continue
        name = sym.name.decode()
        if name == "Wow64Transition":
            transition = sym.address
        if name.startswith("Nt"):
            stubs[name] = image[sym.address:sym.address + 0x30]
    assert transition is not None, "ntdll exports no Wow64Transition"

    # The trampoline every stub calls. Taken as the value the overwhelming
    # majority agree on rather than computed, so an odd build cannot quietly
    # shift it.
    thunks = collections.Counter(
        struct.unpack_from("<I", body, 6)[0]
        for body in stubs.values()
        if len(body) >= 12 and body[0] == 0xB8 and body[5] == 0xBA and body[10:12] == b"\xff\xd2")
    thunk_va, agreed = thunks.most_common(1)[0]
    assert agreed > 0.9 * sum(thunks.values()), \
        f"no single transition trampoline: {thunks.most_common(3)}"

    via_edx = b"\xba" + struct.pack("<I", thunk_va) + b"\xff\xd2"
    via_fs = b"\x64\xff\x15\xc0\x00\x00\x00"          # call dword ptr fs:[0xC0]

    table, collisions = {}, []
    for name, body in stubs.items():
        if len(body) < 12 or body[0] != 0xB8:
            continue
        if via_edx not in body and via_fs not in body:
            continue
        ssn = struct.unpack_from("<I", body, 1)[0] & 0xFFFF
        if table.get(ssn, name) != name:
            collisions.append((ssn, table[ssn], name))
        table[ssn] = name

    assert not collisions, f"service numbers are not unique: {collisions[:4]}"
    assert len(table) > 300, f"only {len(table)} syscall stubs parsed out of ntdll"
    gaps = sorted(set(range(max(table) + 1)) - set(table))
    assert not gaps, f"service numbers are not contiguous, so a stub shape was missed: {gaps[:8]}"
    return table, transition, pe.OPTIONAL_HEADER.SizeOfImage


def install_syscall_gate(mu, ntdll_base, transition_rva, gate=SYSCALL_GATE):
    """Give the WOW64 transition somewhere real to go.

    A 32-bit process on 64-bit Windows executes no `sysenter` of its own. Every
    `Nt*` stub loads its service number into EAX and calls through
    `ntdll!Wow64Transition`, and **the kernel fills that slot in at load** --
    along with `fs:[0xC0]`. Neither is in the file on disk. So a harness that
    maps ntdll from disk and stops there has a process whose entire syscall
    path is a jump through zero, which is precisely how stage 3 died: it built
    a clean copy of ntdll to escape user-mode hooks, called one of its own
    stubs, and went to address 0.

    Writing these two values is restoring what the loader contributes, not
    inventing an answer. Intercepting *here* rather than at export addresses is
    also the only placement that sees a payload using its own stubs -- which
    this one does, by design.
    """
    if not any(begin <= gate <= end for begin, end, _ in mu.mem_regions()):
        mu.mem_map(gate & ~0xFFF, 0x1000)
    mu.mem_write(gate, b"\xc3")     # `ret`; the hook rewrites EIP before it runs
    mu.mem_write(TEB_ADDR + 0xC0, struct.pack("<I", gate))
    mu.mem_write(ntdll_base + transition_rva, struct.pack("<I", gate))


def patch_ntdll_copies(mu, regions, transition_rva, image_size, gate=SYSCALL_GATE):
    """Fill `Wow64Transition` in every *private* copy of ntdll that is mapped.

    Filling the loaded image is unambiguous -- the loader does it. A copy the
    payload mapped itself is a judgement call, and worth stating: on real
    Windows that copy's slot is zero too, so either the sample repairs it from
    somewhere this emulation has not reached, or it depends on a detail of a
    live WOW64 process not reproduced here. What is *not* in doubt is that the
    sample jumps through the slot expecting it to work, so leaving it zero
    stops the emulation at the harness rather than at the malware.

    Detection is by exact `SizeOfImage` plus an export directory naming
    `ntdll`, not by "there is a PE here" -- the standing lesson being that a
    test which fires on anything says nothing about what it fired on. Only a
    slot that currently reads zero is written, so a copy the payload repaired
    itself is left alone and stays visible as such.
    """
    patched = []
    for begin, size in regions:
        if size < image_size:
            continue
        try:
            blob = bytes(mu.mem_read(begin, size))
        except UcError:
            continue
        for off in range(0, size - image_size + 1, 0x1000):
            if blob[off:off + 2] != b"MZ":
                continue
            e_lfanew = struct.unpack_from("<I", blob, off + 0x3C)[0]
            if not 0x40 <= e_lfanew < 0x1000 or blob[off + e_lfanew:off + e_lfanew + 4] != b"PE\0\0":
                continue
            opt = off + e_lfanew + 24
            if struct.unpack_from("<I", blob, opt + 56)[0] != image_size:
                continue
            export_rva = struct.unpack_from("<I", blob, opt + 96)[0]
            if not 0 < export_rva < image_size:
                continue
            name_rva = struct.unpack_from("<I", blob, off + export_rva + 12)[0]
            if not blob[off + name_rva:off + name_rva + 5].lower().startswith(b"ntdll"):
                continue
            if struct.unpack_from("<I", blob, off + transition_rva)[0] != 0:
                continue
            mu.mem_write(begin + off + transition_rva, struct.pack("<I", gate))
            patched.append(begin + off)
    return patched


def setup(mu, image_base, image_size):
    mu.mem_map(HEAP_BASE, HEAP_SIZE)
    mu.mem_map(TEB_ADDR & ~0xFFF, 0x2000)
    mu.mem_map(PEB_ADDR & ~0xFFF, 0x1000)
    mu.mem_map(LDR_ADDR & ~0xFFF, 0x8000)
    real_exports = {}
    sizes = {}
    for base, nm in ((KERNEL32_BASE, "KERNEL32.DLL"), (NTDLL_BASE, "ntdll.dll")):
        exports, size = map_real_dll(mu, SYSWOW64 + nm.lower(), base)
        real_exports.update(exports)
        sizes[base] = size

    mu.mem_write(TEB_ADDR + 0x18, struct.pack("<I", TEB_ADDR))
    mu.mem_write(TEB_ADDR + 0x30, struct.pack("<I", PEB_ADDR))
    mu.mem_write(PEB_ADDR + 0x02, b"\x00")                        # BeingDebugged
    mu.mem_write(PEB_ADDR + 0x08, struct.pack("<I", image_base))  # ImageBaseAddress
    mu.mem_write(PEB_ADDR + 0x0C, struct.pack("<I", LDR_ADDR))

    mods = [(image_base, image_size, IMAGE_NAME),
            (NTDLL_BASE, sizes[NTDLL_BASE], "ntdll.dll"),
            (KERNEL32_BASE, sizes[KERNEL32_BASE], "KERNEL32.DLL")]
    for i, nm in enumerate(EXTRA_MODULES):
        base = EXTRA_BASE + i * EXTRA_STRIDE
        mu.mem_map(base, 0x2000)
        # A DOS/PE header only: enough that a walker reading DllBase finds a
        # plausible image, without pretending to export anything.
        hdr = bytearray(0x2000)
        hdr[0:2] = b"MZ"
        struct.pack_into("<I", hdr, 0x3C, 0x80)
        struct.pack_into("<4sHH", hdr, 0x80, b"PE\0\0", 0x014C, 0)
        struct.pack_into("<H", hdr, 0x80 + 20, 0xE0)
        struct.pack_into("<H", hdr, 0x80 + 24, 0x10B)
        struct.pack_into("<I", hdr, 0x80 + 24 + 52, base)
        struct.pack_into("<I", hdr, 0x80 + 24 + 56, 0x2000)
        struct.pack_into("<I", hdr, 0x80 + 24 + 92, 16)
        mu.mem_write(base, bytes(hdr))
        mods.append((base, 0x2000, nm))
    # Entries are 0x100 apart from +0x100, so with a full module list they run
    # to +0x1800; the name buffer has to start beyond that, not at +0x800.
    entry_size, first, names_at = 0x100, LDR_ADDR + 0x100, LDR_ADDR + 0x4000
    assert first + len(mods) * entry_size <= names_at, "module entries overlap names"
    # The three lists are circular *through a head that lives in PEB_LDR_DATA*,
    # and that detail is load-bearing rather than cosmetic. Module walkers do not
    # count entries; they stop when the next entry's DllBase reads zero, which
    # happens naturally because the head is not an LDR_DATA_TABLE_ENTRY and the
    # bytes at head+0x18 are something else entirely (zero here). Linking the
    # last entry back to the *first* instead makes a pure ring with no sentinel,
    # and a walker looking for a module it will not find then loops forever --
    # which is exactly what hung stage 3 for 2.3 billion instructions.
    heads = {0x00: LDR_ADDR + 0x0C, 0x08: LDR_ADDR + 0x14, 0x10: LDR_ADDR + 0x1C}
    for i, (base, size, nm) in enumerate(mods):
        e = first + i * entry_size
        for off, head in heads.items():
            flink = head if i == len(mods) - 1 else first + (i + 1) * entry_size + off
            blink = head if i == 0 else first + (i - 1) * entry_size + off
            mu.mem_write(e + off, struct.pack("<II", flink, blink))
        mu.mem_write(e + 0x18, struct.pack("<III", base, base, size))
        wide = nm.encode("utf-16-le") + b"\0\0"
        nptr = names_at + i * 0x80
        mu.mem_write(nptr, wide)
        us = struct.pack("<HHI", len(nm) * 2, len(wide), nptr)
        mu.mem_write(e + 0x24, us)                    # FullDllName
        mu.mem_write(e + 0x2C, us)                    # BaseDllName
    last = first + (len(mods) - 1) * entry_size
    for off, head in heads.items():
        mu.mem_write(head, struct.pack("<II", first + off, last + off))
    # head+0x18 must read as zero for the walk to terminate there. It does
    # because nothing else is written into that range -- assert it rather than
    # trust it, since the whole termination argument rests on this byte.
    for head in heads.values():
        assert struct.unpack("<I", mu.mem_read(head + 0x18, 4))[0] == 0, \
            "list head +0x18 is non-zero; module walks will not terminate"

    install_gdt(mu, TEB_ADDR)

    syscalls, transition_rva, ntdll_image_size = syscall_table()
    install_syscall_gate(mu, NTDLL_BASE, transition_rva)

    return real_exports, syscalls, transition_rva, ntdll_image_size
