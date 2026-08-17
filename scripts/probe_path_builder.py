"""Black-box the path builder: feed it a chosen FullDllName, read what it returns.

Its body at +0x117a0 is obfuscated and does not disassemble, and inference from
the disassembly has been wrong every time on this payload. So identify it the
way you would identify any opaque function -- vary the input, record the output.

    ..\\.venv\\Scripts\\python.exe probe_path_builder.py
    ..\\.venv\\Scripts\\python.exe probe_path_builder.py "D:\\Foo\\Bar\\ntdll.dll"

Four inputs pin it (*0aq*), and the second is the one that settled whether the
doubled drive was ours: it comes out `D:D:\\Foo\\Bar\\`, so the prefix is taken
from the input and the doubling is systematic rather than a stray `C:` from
somewhere in this harness.

Stops at the builder's return -- the call lands at ~17.4M blocks, so this is a
couple of minutes rather than a full run.
"""
import struct
import sys

from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_ESP

import win32_emu_env as winenv
from emulate_native_stub import Emulator

STATE = r"G:\ringforge-artifacts\422e30ed_stage2\after_handshake.state"
INJECT_EIP, INJECT_ESP = 0x3E9F89B, 0x10080000
BUILD_CALL, BUILD_RET = 0x3EACF75, 0x3EACF7A
NTDLL_ENTRY = winenv.LDR_ADDR + 0x100 + 1 * 0x100      # index 1 == ntdll


def wide(mu, ptr, limit=0x140):
    if not ptr:
        return ""
    raw = bytes(mu.mem_read(ptr, limit))
    end = raw.find(b"\x00\x00")
    if end % 2:
        end += 1
    return raw[:end].decode("utf-16-le", "replace")


want = sys.argv[1] if len(sys.argv) > 1 else None

emu = Emulator.restore(STATE)
mu = emu.mu
mu.reg_write(UC_X86_REG_EIP, INJECT_EIP)
mu.reg_write(UC_X86_REG_ESP, INJECT_ESP)

length, maxlen, buf = struct.unpack("<HHI", mu.mem_read(NTDLL_ENTRY + 0x24, 8))
print(f"ntdll FullDllName currently {wide(mu, buf)!r} at {buf:#x}")
if want:
    blob = want.encode("utf-16-le") + b"\0\0"
    mu.mem_write(buf, blob + b"\0" * 8)
    mu.mem_write(NTDLL_ENTRY + 0x24,
                 struct.pack("<HHI", len(want) * 2, len(blob), buf))
    print(f"OVERRIDDEN to {want!r} -- an experiment on the builder, not a "
          f"claim about the machine")

state = {}


def on_call(uc, addr, size, user):
    esp = uc.reg_read(UC_X86_REG_ESP)
    state["out"] = struct.unpack("<I", uc.mem_read(esp + 8, 4))[0]
    src = struct.unpack("<I", uc.mem_read(esp + 4, 4))[0]
    print(f"\n[{emu.blocks:,}blk] builder called")
    print(f"    src = {wide(mu, src)!r}")


def on_ret(uc, addr, size, user):
    if "out" not in state:
        return
    print(f"    out = {wide(mu, state['out'])!r}")
    mu.emu_stop()


mu.hook_add(UC_HOOK_CODE, on_call, begin=BUILD_CALL, end=BUILD_CALL)
mu.hook_add(UC_HOOK_CODE, on_ret, begin=BUILD_RET, end=BUILD_RET)
emu.resume(count=1_500_000_000)
print(f"stopped at {mu.reg_read(UC_X86_REG_EIP):#x}")
