"""Anti-analysis token search over stage 3.

Gap 4's negative was recorded as weak because stage 2's payload was encrypted.
It is not any more. This searches the material that was unreadable then.

The scoping is the whole point. Stage 3 is ~6.8 KB of plaintext stub plus a
272 KB blob that is still packed, so a negative over the blob says nothing at
all -- it is the same shape as the registry-read pass reporting a zero on a run
that captured no reads. Each region is therefore reported separately, and the
emulated allocation is included because it is 284 KB of partly unpacked content
that no search has ever seen.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, r"C:\Users\aring\dev\ringforge-workbench\scripts")
sys.path.insert(0, r"C:\Users\aring\dev\ringforge-workbench")
from dotnet_meta import xor_unwrap
from dynamic_analysis.vm_artifact_reads import VM_ARTIFACT_MARKERS

STAGE3 = xor_unwrap(Path(
    r"G:\ringforge-artifacts\422e30ed_stage2\stage3_native_e84f7824.xor9").read_bytes())
ALLOC = Path(r"C:\Users\aring\AppData\Local\Temp\claude"
             r"\C--Users-aring-dev-ringforge-workbench"
             r"\5daa5351-45b9-4334-a185-0524bd51feae\scratchpad\alloc_2001000.bin")

#: Tokens a string search can actually hit, as opposed to the registry paths the
#: pipeline's marker list carries. Substrings, lowercased, matched in both
#: encodings.
TOKENS = {
    "hypervisor": ["vbox", "virtualbox", "vmware", "vmtoolsd", "vboxservice",
                   "vboxtray", "qemu", "bochs", "xen", "kvm", "parallels",
                   "hyper-v", "hyperv", "virtual machine", "vmxh", "prl_",
                   "innotek", "5.2.7"],
    "sandbox": ["sandbox", "sbiedll", "cuckoo", "joesandbox", "anubis",
                "threatexpert", "comodo", "sunbelt", "wine_get", "wine",
                "sample.exe", "malware.exe", "virus.exe"],
    "debugger": ["isdebuggerpresent", "checkremotedebugger", "ntqueryinformation",
                 "outputdebugstring", "dbghelp", "ollydbg", "x64dbg", "windbg",
                 "idaq", "immunity", "debugport", "beingdebugged"],
    "analysis tools": ["wireshark", "procmon", "procexp", "regmon", "filemon",
                       "tcpview", "autoruns", "processhacker", "fiddler", "pestudio"],
    "wmi / identity": ["win32_computersystem", "win32_bios", "win32_diskdrive",
                       "wbemscripting", "select * from", "root\\cimv2",
                       "systembiosversion", "videobiosversion",
                       "hardware\\description", "cpuid", "rdtsc"],
}


def hits(blob: bytes, needle: str):
    """(encoding, offset) for every occurrence, ascii and utf-16le."""
    out = []
    for enc, pat in (("ascii", needle.encode()),
                     ("utf16", needle.encode("utf-16-le"))):
        for m in re.finditer(re.escape(pat), blob, re.I):
            out.append((enc, m.start()))
    return out


def scan(name, blob, meaningful):
    print(f"\n=== {name} — {len(blob):,} bytes "
          f"({'a negative here is evidence' if meaningful else 'PACKED: a negative here proves nothing'})")
    total = 0
    for group, needles in TOKENS.items():
        found = []
        for n in needles:
            h = hits(blob, n)
            if h:
                found.append((n, h[:3], len(h)))
        if found:
            print(f"  {group}:")
            for n, where, count in found:
                spots = ", ".join(f"{e}@{o:#x}" for e, o in where)
                print(f"    {n!r} x{count}  {spots}")
            total += len(found)
    marker_hits = [m for m in VM_ARTIFACT_MARKERS if hits(blob, m[0])]
    if marker_hits:
        print(f"  pipeline VM_ARTIFACT_MARKERS: {[m[0] for m in marker_hits]}")
    if not total and not marker_hits:
        print("  no tokens from any group")
    return total + len(marker_hits)


print(f"marker list: {len(VM_ARTIFACT_MARKERS)} pipeline markers + "
      f"{sum(len(v) for v in TOKENS.values())} string tokens, ascii and utf-16")

n1 = scan("stage 3 stub (0x1000-0x2ad9)", STAGE3[0x1000:0x2ad9], True)
n2 = scan("stage 3 headers (0x0-0x1000)", STAGE3[:0x1000], True)
n3 = scan("stage 3 packed blob (0x2c00-EOF)", STAGE3[0x2c00:], False)
if ALLOC.exists():
    n4 = scan("emulated allocation (partly unpacked)", ALLOC.read_bytes(), True)
else:
    n4 = None
    print("\n(emulated allocation not on disk - rerun with --dump)")

print(f"\nsummary: stub={n1} headers={n2} packed={n3} allocation={n4}")
