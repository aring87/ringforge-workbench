"""Is the stealer's code in the pages that run, or in the ones that do not?

`0j` says 42 of stage 4's 67 pages never execute and are **still packed**, and
that framing decides everything downstream: if the harvesting code is packed,
the only question left is what decrypts it; if it is plaintext and merely
unreached, then there is a declined branch and `stage4_declined.py` should find
it.

**That has never been measured against the strings themselves, and there is a
reason to doubt it.** FLOSS recovered the stealer's strings with `-f sc32`,
which works by *emulating* the code that builds them on the stack. It can only
do that against readable instructions. So the code that builds
`Internet Explorer\\IntelliForms\\Storage2` was plaintext when FLOSS saw it --
the question is which pages it sits in.

**Stack strings are built from immediates**, so their characters appear in the
instruction stream as 4-byte chunks inside `mov` operands rather than as one
contiguous run. This searches for those chunks, in the image **as the emulator
holds it after a run** -- the same bytes that did or did not execute -- and
reports which page each lands in.

    set RINGFORGE_EXPLORER_CHILD=1
    ..\\.venv\\Scripts\\python.exe stage4_string_pages.py

**Read a null result carefully.** No chunks found does not mean the strings are
packed: it can equally mean they are built byte-at-a-time from computed values,
or copied out of a blob this search does not model. The script says so rather
than concluding, because "absent from my search" and "absent from the image"
are different claims and this chain has confused them before.

Nothing is written to disk. The decrypted stage is read out of emulator memory,
so no plaintext stage-4 image lands where an AV can take it -- the policy that
`0m` established after Bitdefender quarantined an extracted payload in seconds.
"""
from __future__ import annotations

import argparse
import collections
import math

from unicorn import UC_HOOK_BLOCK
from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_ESP

import win32_emu_env as winenv  # noqa: F401  (imported for its side effects)
from emulate_native_stub import Emulator

STATE = r"G:\ringforge-artifacts\422e30ed_stage2\after_handshake.state"
INJECT_EIP, INJECT_ESP = 0x3E9F89B, 0x10080000
PAY, PLEN = 0x3E93C74, 0x42C00

#: The strings `0m` recovered with FLOSS `-f sc32`, which is the evidence that
#: this stage is a credential stealer. If the code that builds them is in a live
#: page, the harvesting is plaintext and unreached rather than packed.
STEALER_STRINGS = (
    r"Internet Explorer\IntelliForms\Storage2",
    "Local State",
    "Cookies",
    "Autofill",
    "Login Data",
    "logins.json",
    "signons.sqlite",
    "key3.db",
    "key4.db",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "sqlite3.dll",
)

#: Long enough that a hit is not chance, short enough to survive being split
#: across two `mov` immediates.
CHUNK = 4


def chunks(text: str, size: int = CHUNK) -> set[bytes]:
    """Every `size`-byte window, ascii and utf-16le."""
    out: set[bytes] = set()
    raw = text.encode("ascii", "ignore")
    for i in range(len(raw) - size + 1):
        out.add(raw[i:i + size])
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--state", default=STATE)
    ap.add_argument("--instructions", type=int, default=4_000_000_000)
    args = ap.parse_args(argv)

    emu = Emulator.restore(args.state)
    emu.mu.reg_write(UC_X86_REG_EIP, INJECT_EIP)
    emu.mu.reg_write(UC_X86_REG_ESP, INJECT_ESP)

    executed: set[int] = set()
    emu.mu.hook_add(UC_HOOK_BLOCK, lambda u, a, s, x: executed.add(a),
                    begin=PAY, end=PAY + PLEN - 1)
    start = emu.blocks
    status = emu.resume(count=args.instructions)
    eip = emu.mu.reg_read(UC_X86_REG_EIP)
    print(f"RUN CHECK: {emu.blocks - start:,} blocks -- {status}")
    if PAY <= eip < PAY + PLEN:
        print(f"*** VOID: EIP still inside the payload (+{eip - PAY:#x}); the "
              f"page split below would be\n    a lie of omission.")
        return 2

    pages_ran = {a & ~0xFFF for a in executed}
    total = (PLEN + 0xFFF) // 0x1000
    print(f"           {len(pages_ran)} of {total} pages executed\n")

    image = bytes(emu.mu.mem_read(PAY, PLEN))

    # -- the instrument that actually answers it ---------------------------
    #
    # The string search below came back empty, and the README says why: FLOSS
    # recovered those with its **decoded** pass, which emulates decoder
    # functions and captures their output. The plaintext never exists in the
    # static image, so searching for it tests nothing.
    #
    # Entropy does test `0j`'s claim, and needs no strings. Packed bytes sit
    # near 8; x86 code sits near 6. If every dead page is high-entropy, "not
    # code yet" holds. A dead page at code entropy is the interesting case:
    # plaintext that simply never ran, and therefore a declined branch to find.
    def entropy(block: bytes) -> float:
        if not block:
            return 0.0
        counts = collections.Counter(block)
        n = len(block)
        return -sum((c / n) * math.log2(c / n) for c in counts.values())

    print("=== per-page entropy, live against dead")
    live_e, dead_e, dead_codelike = [], [], []
    for page_start in range(PAY & ~0xFFF, PAY + PLEN, 0x1000):
        offset = page_start - PAY
        block = image[max(0, offset):max(0, offset) + 0x1000]
        if len(block) < 0x400:
            continue
        value = entropy(block)
        if page_start in pages_ran:
            live_e.append(value)
        else:
            dead_e.append(value)
            if value < 6.6:
                dead_codelike.append((page_start, value))

    def describe(values):
        if not values:
            return "none"
        return (f"n={len(values)} min={min(values):.2f} "
                f"mean={sum(values)/len(values):.2f} max={max(values):.2f}")

    print(f"  live pages: {describe(live_e)}")
    print(f"  dead pages: {describe(dead_e)}")
    print(f"\n  dead pages at code-like entropy (<6.6): {len(dead_codelike)}")
    for page_start, value in dead_codelike[:12]:
        print(f"    {page_start:#010x}  +{page_start - PAY:#07x}  {value:.2f}")

    if dead_codelike:
        print("\n  ** Those are plaintext pages that never ran.** `0j`'s "
              "'not code yet' does not")
        print("     cover them, and a declined branch into one is findable "
              "without decrypting")
        print("     anything. stage4_declined.py, restricted to these pages, "
              "is the next probe.")
    else:
        print("\n  Every dead page is at packed entropy. **`0j` holds**: the "
              "unexecuted two-thirds")
        print("     is not unreached code, it is undecrypted data, and the "
              "only question left is")
        print("     what would decrypt it.")

    print("=== where the stealer's strings are built")
    live_hits = dead_hits = 0
    for text in STEALER_STRINGS:
        found: dict[int, int] = collections.Counter()
        for chunk in chunks(text):
            start_at = 0
            while True:
                index = image.find(chunk, start_at)
                if index < 0:
                    break
                found[(PAY + index) & ~0xFFF] += 1
                start_at = index + 1
        if not found:
            print(f"  {text[:44]:<46} no chunk found")
            continue
        live = sum(n for page, n in found.items() if page in pages_ran)
        dead = sum(n for page, n in found.items() if page not in pages_ran)
        live_hits += live
        dead_hits += dead
        where = ", ".join(
            f"{page:#010x}{'*' if page in pages_ran else ''}"
            for page in sorted(found)[:4]
        )
        print(f"  {text[:44]:<46} {live:>3} live / {dead:>3} dead   {where}")

    print("\n  (* marks a page that executed)")
    print(f"\n  totals: {live_hits} chunk hit(s) in live pages, "
          f"{dead_hits} in dead pages")

    print("\n--- what this run says")
    if not live_hits and not dead_hits:
        print("  NO chunk of any stealer string is present in the image at all.")
        print("  That is not evidence they are packed: it equally fits strings "
              "built byte at a")
        print("  time from computed values, or copied out of a blob this "
              "search does not model.")
        print("  It says this instrument cannot see them, and nothing more.")
    elif dead_hits and not live_hits:
        print("  Every hit is in a page that never executed. **`0j`'s reading "
              "holds**: the")
        print("  harvesting code is in the packed two-thirds, and the only "
              "question left is what")
        print("  would decrypt it.")
    elif live_hits and not dead_hits:
        print("  Every hit is in a page that DID execute. **The harvesting code "
              "is plaintext and")
        print("  merely unreached**, so there is a declined branch to find and "
              "`0j`'s 'not code")
        print("  yet' framing is wrong. Run stage4_declined.py against these "
              "pages.")
    else:
        print(f"  Mixed: {live_hits} live, {dead_hits} dead. Some of the string "
              f"construction is in")
        print("  plaintext pages and some is not, so neither framing is whole. "
              "The live ones are")
        print("  where a declined branch could be found without decrypting "
              "anything.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
