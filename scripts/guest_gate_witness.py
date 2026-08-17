"""Did the poison reach the guest's cookie? The register file says yes.

`0ax` set the condition itself: *"do not promote this to a finding without
measuring the stored value at the moment of the recovery"*. That stayed
unmeasured for a week because the bench cannot reach the guest's state -- and
the whole time the guest's registers at the fault were sitting unread in the
dump's `EXCEPTION_STREAM`.

    ..\\.venv\\Scripts\\python.exe guest_gate_witness.py [dump]

**The check that makes the register file trustworthy** is that `eip` must equal
the fault offset WER recorded independently (`0x01012c7c`), and that the
faulting instruction's own arithmetic must produce the faulting address. The
instruction at rva `0x2c7c` is `cmp al, byte ptr [esi+ecx]`, so `esi + ecx`
has to be `0x32dfd514` exactly. An x86 `CONTEXT` mis-parse -- `FloatSave` is
112 bytes and putting it wrong shifts every register onto its neighbour -- fails
both, and fails them on plausible-looking values rather than on garbage.

**What the registers show, and why it settles the cookie question.** Neither
operand of the faulting read is the poison: `esi` is a *bias* and `ecx` is a
live stack address. But `edx` holds `0x32dfd514` outright and `eax` holds
`0x32dfd514 + 0xe4`. Values of the form `poison ^ small` in more than one
register are what `x ^ cookie` produces when the cookie **is** the poison, which
is `0ax`'s model with the missing step supplied.
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dynamic_analysis import minidump  # noqa: E402

DUMP = r"C:\Users\aring\Downloads\ringforge\outputs\RegSvcs.exe.5272.dmp"
POISON = 0x32DFD514
STAGE3, STAGE3_SIZE = 0x01010000, 0x46000

#: What WER recorded for this crash, independently of the dump's own streams.
#: `0ax`: `RegSvcs.exe pid 5272 exception c0000005 fault offset 01012c7c`.
WER_FAULT_EIP = 0x01012C7C

#: The faulting instruction, rva 0x2c7c: `cmp al, byte ptr [esi + ecx]`.
FAULT_OPERANDS = ("esi", "ecx")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dump", nargs="?", default=DUMP)
    args = ap.parse_args(argv)

    path = Path(args.dump)
    dump = minidump.parse(path)
    exception = dump.exception()
    if not exception:
        print("*** VOID: no exception stream, so there is no register file "
              "to read.")
        return 2
    registers = exception.get("context")
    if not registers:
        print(f"*** VOID: exception code {exception.get('code', 0):#010x} but "
              f"no thread context.\n    warnings: {dump.warnings}")
        return 2

    print(f"{path.name}  exception {exception['code']:#010x}\n")
    for name in ("eip", "esi", "edi", "ecx", "edx", "eax", "ebx", "ebp", "esp"):
        value = registers[name]
        note = ""
        if value == POISON:
            note = "   <<<< THE POISON, exactly"
        elif POISON <= value < POISON + 0x1000:
            note = f"   <- poison + {value - POISON:#x}"
        elif STAGE3 <= value < STAGE3 + STAGE3_SIZE:
            note = f"   <- rva {value - STAGE3:#x} of stage 3"
        print(f"   {name:<4} {value:#010x}{note}")

    # -- is this register file believable? -----------------------------------
    print("\nIS THE PARSE BELIEVABLE?")
    eip_ok = registers["eip"] == WER_FAULT_EIP
    print(f"   eip == WER's recorded fault offset {WER_FAULT_EIP:#010x} : "
          f"{eip_ok}")
    total = (registers[FAULT_OPERANDS[0]] + registers[FAULT_OPERANDS[1]]) & 0xFFFFFFFF
    sum_ok = total == POISON
    print(f"   esi + ecx == the faulting address {POISON:#010x}      : "
          f"{sum_ok}   ({total:#010x})")
    if not (eip_ok and sum_ok):
        print("\n   *** VOID: the CONTEXT layout does not hold up. An x86 "
              "CONTEXT mis-parse shifts")
        print("   every register onto its neighbour and lands on plausible "
              "values, so nothing")
        print("   below may be read until this passes.")
        return 2
    print("   Both hold, and they are independent of each other, so the "
          "register file is real.")

    # -- what the operands actually are --------------------------------------
    threads = dump.threads()
    on_stack = [name for name in ("esi", "ecx", "edx", "eax")
                if any(t["stack_base"] <= registers[name] < t["stack_end"]
                       for t in threads)]
    print(f"\nTHE FAULTING READ, `cmp al, [esi+ecx]`:")
    print(f"   esi {registers['esi']:#010x}   a BIAS -- "
          f"{POISON:#010x} - {registers['ecx']:#010x}")
    print(f"   ecx {registers['ecx']:#010x}   a live stack address"
          if "ecx" in on_stack else
          f"   ecx {registers['ecx']:#010x}   not on any thread stack")
    print("   So the pointer being walked is not held in a register at all: it "
          "is split into a")
    print("   bias plus a real address, which is why no register equals the "
          "faulting address.")

    # -- the cookie ----------------------------------------------------------
    carrying = {name: registers[name] for name in registers
                if POISON <= registers[name] < POISON + 0x10000}
    print(f"\nREGISTERS CARRYING poison + small: {len(carrying)}")
    for name, value in sorted(carrying.items()):
        print(f"   {name} = {value:#010x}   = poison ^ {value ^ POISON:#x}")

    print("\nVERDICT:")
    if len(carrying) >= 2:
        print("   **The cookie held the poison.** Two or more registers hold "
              "`poison ^ small`, which")
        print("   is what `x ^ cookie` yields when the cookie is the poison and "
              "`x` is a small")
        print("   offset. 0ax's model had exactly one unmeasured step and this "
              "is it.")
        print("\n   Which closes the chain and leaves the contradiction bare:")
        print("     the cookie held 0x32dfd514")
        print("     -> only rva 0x1605f writes it (0ax: one store, census "
              "re-derived in 0bb)")
        print("     -> that store is gated on a module hashing to 0xe11da208")
        print("     -> the guest's own PEB->Ldr walk holds four entries and "
              "none of them does")
        print("        (guest_ldr_walk.py -- the list the gate itself reads, "
              "not a writer's view)")
        print("   Every link is now a measurement. They cannot all be true.")
    elif carrying:
        print("   One register carries the poison, which is consistent with the "
              "cookie holding it")
        print("   and equally consistent with a single stale value. Not enough "
              "on its own.")
    else:
        print("   No register carries the poison or anything near it, so the "
              "cookie-recovery model")
        print("   has no support here and the fault came some other way. That "
              "would retract far")
        print("   more than it settles -- check the parse again first.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
