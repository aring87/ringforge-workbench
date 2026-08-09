"""A minimal 32-bit Windows process image for Unicorn.

Enough PEB/TEB and a synthetic kernel32/ntdll export table for shellcode that
resolves its imports by walking the loader module list. Each fake DLL carries
its own stub area at RVA 0x2000; every export points there, and a code hook on
those addresses implements the API in Python.
"""
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


def setup(mu, image_base, image_size):
    mu.mem_map(HEAP_BASE, HEAP_SIZE)
    mu.mem_map(TEB_ADDR & ~0xFFF, 0x2000)
    mu.mem_map(PEB_ADDR & ~0xFFF, 0x1000)
    mu.mem_map(LDR_ADDR & ~0xFFF, 0x4000)
    for base, nm in ((KERNEL32_BASE, "KERNEL32.DLL"), (NTDLL_BASE, "ntdll.dll")):
        mu.mem_map(base, DLL_SIZE)
        mu.mem_write(base, build_fake_dll(nm, base))

    mu.mem_write(TEB_ADDR + 0x18, struct.pack("<I", TEB_ADDR))
    mu.mem_write(TEB_ADDR + 0x30, struct.pack("<I", PEB_ADDR))
    mu.mem_write(PEB_ADDR + 0x02, b"\x00")                        # BeingDebugged
    mu.mem_write(PEB_ADDR + 0x08, struct.pack("<I", image_base))  # ImageBaseAddress
    mu.mem_write(PEB_ADDR + 0x0C, struct.pack("<I", LDR_ADDR))

    mods = [(image_base, image_size, "stage3.exe"),
            (NTDLL_BASE, DLL_SIZE, "ntdll.dll"),
            (KERNEL32_BASE, DLL_SIZE, "KERNEL32.DLL")]
    entry_size, first, names_at = 0x100, LDR_ADDR + 0x100, LDR_ADDR + 0x800
    for i, (base, size, nm) in enumerate(mods):
        e = first + i * entry_size
        nxt = first + ((i + 1) % len(mods)) * entry_size
        prv = first + ((i - 1) % len(mods)) * entry_size
        for off in (0x00, 0x08, 0x10):                # the three LIST_ENTRYs
            mu.mem_write(e + off, struct.pack("<II", nxt + off, prv + off))
        mu.mem_write(e + 0x18, struct.pack("<III", base, base, size))
        wide = nm.encode("utf-16-le") + b"\0\0"
        nptr = names_at + i * 0x80
        mu.mem_write(nptr, wide)
        us = struct.pack("<HHI", len(nm) * 2, len(wide), nptr)
        mu.mem_write(e + 0x24, us)                    # FullDllName
        mu.mem_write(e + 0x2C, us)                    # BaseDllName
    for off, head in ((0x0C, 0x00), (0x14, 0x08), (0x1C, 0x10)):
        last = first + (len(mods) - 1) * entry_size
        mu.mem_write(LDR_ADDR + off, struct.pack("<II", first + head, last + head))

    install_gdt(mu, TEB_ADDR)

    addr2name = {}
    for base, nm in ((KERNEL32_BASE, "KERNEL32.DLL"), (NTDLL_BASE, "ntdll.dll")):
        for fn in DLL_EXPORTS[nm]:
            addr2name[stub_addr(base, fn)] = fn
    return addr2name
