"""Read the CLR metadata of a carved .NET payload, on the bench.

Written for the loader `422e30ed...` on 07 Aug 2026, when its stage 2 was
recovered by the parent-at-spawn dump and there was no decompiler on the host --
no ILSpy, no dnSpy, and no .NET SDK, so `dotnet tool install -g ilspycmd` could
not run either. Everything here works from `pefile`, which is already pinned.

It is not a decompiler and it is not trying to be. What it does is answer the
questions that come up first on a carved managed payload, none of which need one:

* what does the assembly say it is (forged version resources included)
* what is in the metadata heaps -- identifiers, and the user-string literals a
  protector leaves behind
* which methods exist, where their bodies are, and what a given body does
* what byte-array literals sit in FieldRVA data, which is where a .NET key
  lives when it is not a string
* the managed resources, their names, sizes and entropy

* who really calls what, once the protector's proxy delegates are resolved

The IL disassembler resolves `ldstr` against `#US` and `call`/`callvirt`/`newobj`
against `MemberRef`, which is enough to read a method's intent. It has no
control-flow reconstruction, so a flattened method still reads as a dispatcher --
but it decodes completely, which is a different thing from being readable and is
the property `--callgraph` depends on.

One thing this found that a decompiler would have shown less directly: a method
whose entire body is `ldstr <16-char literal>` / `String::get_Length` / `ret`.
Ten such literals sat beside an AES call and about 4,000 key derivations were
spent on them before the bodies were read. `--disasm` is cheaper than a brute
force.

`--callgraph` is the second instance of the same lesson. Under proxy-delegate call
hiding every interesting wrapper has *zero* direct callers, so the IL looks inert;
the edges come back by joining the decrypted field-to-target map against an inverse
index of which methods load which field. On `422e30ed...` stage 2 that produced the
payload decryptor -- and produced it as a negative first, since `--xref
CreateDecryptor` showed no cryptographic API on the payload path at all.

Usage:

    python scripts/dotnet_meta.py PAYLOAD --summary
    python scripts/dotnet_meta.py PAYLOAD --strings user
    python scripts/dotnet_meta.py PAYLOAD --methods GetManifestResourceStream
    python scripts/dotnet_meta.py PAYLOAD --disasm 1357
    python scripts/dotnet_meta.py PAYLOAD --field-rvas
    python scripts/dotnet_meta.py PAYLOAD --resources OUTDIR
    python scripts/dotnet_meta.py PAYLOAD --callgraph
    python scripts/dotnet_meta.py PAYLOAD --callgraph --xref GetObject
    python scripts/dotnet_meta.py PAYLOAD --callgraph --resolve 470

PAYLOAD may be a `.xor9` wrapper; it is unwrapped in memory and never written back
out in the clear.
"""

from __future__ import annotations

import argparse
import collections
import math
import struct
from pathlib import Path
from typing import Any, NamedTuple, Optional

import pefile

M32 = 0xFFFFFFFF

#: Carved stage-2 images are kept XOR-wrapped on the artifact drive, because
#: Bitdefender matches them on content and ate three plain copies on 07 Aug --
#: `.bin_` gave no protection. A file with this suffix is unwrapped in memory and
#: never written back out in the clear, so the analysis leaves no scannable copy.
XOR_SUFFIX = ".xor9"
XOR_KEY = b"RINGFORGE"


def xor_unwrap(data: bytes) -> bytes:
    return bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(data))


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 4)


class DotNetImage:
    """Metadata heaps and tables of a managed PE, read straight from the file."""

    def __init__(self, path: str | Path, data: Optional[bytes] = None):
        self.path = Path(path)
        if data is None:
            data = self.path.read_bytes()
            if self.path.suffix == XOR_SUFFIX:
                data = xor_unwrap(data)
        self.data = data
        self.pe = pefile.PE(data=self.data, fast_load=False)
        self._read_metadata_root()
        self._read_table_header()

    # -- heaps ------------------------------------------------------------

    def _read_metadata_root(self) -> None:
        d = self.data
        cor = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        if not cor.VirtualAddress:
            raise ValueError("not a managed image: no COM descriptor")
        off = self.pe.get_offset_from_rva(cor.VirtualAddress)
        self.cor_flags = struct.unpack_from("<I", d, off + 16)[0]
        md_rva, self.md_size = struct.unpack_from("<II", d, off + 8)
        self.resources_rva, self.resources_size = struct.unpack_from("<II", d, off + 24)

        md = self.pe.get_offset_from_rva(md_rva)
        if struct.unpack_from("<I", d, md)[0] != 0x424A5342:
            raise ValueError("metadata root signature 'BSJB' not found")
        ver_len = struct.unpack_from("<I", d, md + 12)[0]
        self.runtime_version = d[md + 16 : md + 16 + ver_len].rstrip(b"\x00").decode("latin1")

        p = md + 16 + ver_len
        count = struct.unpack_from("<HH", d, p)[1]
        p += 4
        self.heaps: dict[str, tuple[int, int]] = {}
        for _ in range(count):
            s_off, s_size = struct.unpack_from("<II", d, p)
            p += 8
            end = d.index(b"\x00", p)
            self.heaps[d[p:end].decode("latin1")] = (md + s_off, s_size)
            p = end + 1
            p += (-(p - md)) % 4
        self.md_off = md

    def string(self, index: int) -> str:
        base = self.heaps["#Strings"][0]
        end = self.data.index(b"\x00", base + index)
        return self.data[base + index : end].decode("utf-8", "replace")

    def user_string(self, index: int) -> str:
        base = self.heaps["#US"][0]
        p = base + index
        first = self.data[p]
        if first < 0x80:
            length, q = first, p + 1
        elif first & 0xC0 == 0x80:
            length, q = struct.unpack(">H", self.data[p : p + 2])[0] & 0x3FFF, p + 2
        else:
            return ""
        return self.data[q : q + length - 1].decode("utf-16-le", "replace")

    def identifiers(self) -> list[str]:
        off, size = self.heaps["#Strings"]
        blob = self.data[off : off + size]
        return [x.decode("latin1") for x in blob.split(b"\x00") if len(x) > 2]

    def user_strings(self) -> dict[int, str]:
        """Heap offset -> literal. The offset is the low 24 bits of an ldstr token."""
        off, size = self.heaps["#US"]
        blob = self.data[off : off + size]
        out: dict[int, str] = {}
        p = 1
        while p < len(blob):
            start = p
            first = blob[p]
            if first < 0x80:
                length, q = first, p + 1
            elif first & 0xC0 == 0x80:
                length, q = struct.unpack(">H", blob[p : p + 2])[0] & 0x3FFF, p + 2
            else:
                break
            if length == 0 or q + length > len(blob):
                break
            out[start] = blob[q : q + length - 1].decode("utf-16-le", "replace")
            p = q + length
        return out

    # -- tables -----------------------------------------------------------

    def _read_table_header(self) -> None:
        d = self.data
        t_off = self.heaps["#~"][0]
        heap_sizes = d[t_off + 6]
        valid = struct.unpack_from("<Q", d, t_off + 8)[0]
        p = t_off + 24
        self.rows: dict[int, int] = {}
        for i in range(64):
            if valid >> i & 1:
                self.rows[i] = struct.unpack_from("<I", d, p)[0]
                p += 4

        self.str_w = 4 if heap_sizes & 1 else 2
        self.guid_w = 4 if heap_sizes & 2 else 2
        self.blob_w = 4 if heap_sizes & 4 else 2
        S, G, B = self.str_w, self.guid_w, self.blob_w

        def simple(t: int) -> int:
            return 4 if self.rows.get(t, 0) >= 1 << 16 else 2

        def coded(tables: tuple[int, ...], bits: int) -> int:
            biggest = max((self.rows.get(t, 0) for t in tables), default=0)
            return 4 if biggest >= 1 << (16 - bits) else 2

        self.simple = simple
        TypeDefOrRef = coded((2, 1, 27), 2)
        self.MemberRefParent = coded((2, 1, 26, 6, 27), 3)
        self.ResolutionScope = coded((0, 26, 35, 1), 2)
        self.TypeDefOrRef = TypeDefOrRef

        # Row widths for tables 0..29. Enough to reach FieldRVA, which is the
        # one that matters: a .NET key is a byte[] literal, and byte[] literals
        # live in FieldRVA data rather than in any string heap.
        self.sizes = {
            0: 2 + S + 3 * G,
            1: self.ResolutionScope + 2 * S,
            2: 4 + 2 * S + TypeDefOrRef + simple(4) + simple(6),
            3: simple(4),
            4: 2 + S + B,
            5: simple(6),
            6: 8 + S + B + simple(8),
            7: simple(8),
            8: 4 + S,
            9: simple(2) + TypeDefOrRef,
            10: self.MemberRefParent + S + B,
            11: 2 + coded((4, 8, 23), 2) + B,
            12: coded(tuple(range(0, 45)), 5) + coded((6, 10), 3) + B,
            13: coded((4, 8), 1) + B,
            14: 2 + coded((2, 6, 35), 2) + B,
            15: 6 + simple(2),
            16: 4 + simple(4),
            17: B,
            18: simple(2) + simple(20),
            19: simple(20),
            20: 2 + S + TypeDefOrRef,
            21: simple(2) + simple(23),
            22: simple(23),
            23: 2 + S + B,
            24: 2 + simple(6) + coded((23, 20), 1),
            25: simple(2) + 2 * coded((6, 10), 1),
            26: S,
            27: B,
            28: 2 + coded((4, 6), 1) + S + simple(26),
            29: 4 + simple(4),
            # 30..40, present only to reach ManifestResource (40). Without that
            # table the resource region can be walked for sizes but not for
            # *names*, and inferring which blob is which from its size is how an
            # afternoon went into pointing a recovered key at the wrong one.
            30: 8,
            31: 4,
            32: 16 + B + 2 * S,
            33: 4,
            34: 12,
            35: 12 + 2 * B + 2 * S,
            36: 4 + simple(35),
            37: 12 + simple(35),
            38: 4 + S + B,
            39: 8 + 2 * S + coded((38, 35, 39), 2),
            40: 8 + S + coded((38, 35, 39), 2),
        }
        self.offsets: dict[int, int] = {}
        for i in sorted(self.rows):
            self.offsets[i] = p
            if i not in self.sizes:
                break
            p += self.sizes[i] * self.rows[i]

    def _idx(self, off: int, width: int) -> int:
        return struct.unpack_from("<I" if width == 4 else "<H", self.data, off)[0]

    def type_refs(self) -> dict[int, tuple[str, str]]:
        out = {}
        base, w = self.offsets[1], self.sizes[1]
        for i in range(self.rows.get(1, 0)):
            p = base + i * w + self.ResolutionScope
            out[i + 1] = (self.string(self._idx(p, self.str_w)),
                          self.string(self._idx(p + self.str_w, self.str_w)))
        return out

    def type_defs(self) -> list[dict[str, Any]]:
        out = []
        base, w = self.offsets[2], self.sizes[2]
        S, T = self.str_w, self.TypeDefOrRef
        for i in range(self.rows.get(2, 0)):
            p = base + i * w
            out.append({
                "index": i + 1,
                "name": self.string(self._idx(p + 4, S)),
                "namespace": self.string(self._idx(p + 4 + S, S)),
                "method_list": self._idx(p + 4 + 2 * S + T + self.simple(4), self.simple(6)),
            })
        return out

    def method_defs(self) -> list[dict[str, Any]]:
        out = []
        base, w = self.offsets[6], self.sizes[6]
        for i in range(self.rows.get(6, 0)):
            p = base + i * w
            out.append({
                "index": i + 1,
                "rva": struct.unpack_from("<I", self.data, p)[0],
                "name": self.string(self._idx(p + 8, self.str_w)),
            })
        return out

    def member_refs(self) -> dict[int, str]:
        out = {}
        base, w = self.offsets[10], self.sizes[10]
        trefs = self.type_refs()
        for i in range(self.rows.get(10, 0)):
            p = base + i * w
            parent = self._idx(p, self.MemberRefParent)
            owner = ""
            if parent & 7 == 1:
                ref = trefs.get(parent >> 3)
                if ref:
                    owner = f"{ref[1]}.{ref[0]}" if ref[1] else ref[0]
            name = self.string(self._idx(p + self.MemberRefParent, self.str_w))
            out[i + 1] = f"{owner}::{name}" if owner else name
        return out

    def field_rvas(self) -> dict[int, int]:
        """Field row -> RVA. Where byte[] literals, and therefore keys, live."""
        if 29 not in self.offsets:
            return {}
        base, w = self.offsets[29], self.sizes[29]
        fw = self.simple(4)
        out = {}
        for i in range(self.rows[29]):
            p = base + i * w
            out[self._idx(p + 4, fw)] = struct.unpack_from("<I", self.data, p)[0]
        return out

    def declaring_type(self, method_row: int) -> Optional[dict[str, Any]]:
        best = None
        for t in self.type_defs():
            if t["method_list"] <= method_row and (best is None or t["method_list"] > best["method_list"]):
                best = t
        return best

    # -- method bodies ----------------------------------------------------

    def method_body(self, row: int) -> Optional[tuple[int, int]]:
        method = self.method_defs()[row - 1]
        if not method["rva"]:
            return None
        try:
            off = self.pe.get_offset_from_rva(method["rva"])
        except Exception:
            return None
        first = self.data[off]
        if first & 3 == 2:
            return off + 1, off + 1 + (first >> 2)
        if first & 3 == 3:
            size = struct.unpack_from("<I", self.data, off + 4)[0]
            header = (struct.unpack_from("<H", self.data, off)[0] >> 12) * 4
            return off + header, off + header + size
        return None

    def manifest_resources(self) -> list[dict[str, Any]]:
        """Name and region offset of every embedded resource, from table 40.

        The resource region is a run of length-prefixed blobs; walking it gives
        sizes and no names. This is the table that says which blob is the
        encrypted payload and which is the protector's string table, and that
        distinction is worth having before pointing a recovered key at one.
        """
        if 40 not in self.offsets:
            return []
        base, w = self.offsets[40], self.sizes[40]
        out = []
        for i in range(self.rows.get(40, 0)):
            p = base + i * w
            offset, flags = struct.unpack_from("<II", self.data, p)
            out.append({
                "name": self.string(self._idx(p + 8, self.str_w)),
                "offset": offset,
                "flags": flags,
            })
        return sorted(out, key=lambda r: r["offset"])

    def managed_resources(self) -> list[dict[str, Any]]:
        """The resource region as length-prefixed blobs, with entropy."""
        if not self.resources_rva:
            return []
        start = self.pe.get_offset_from_rva(self.resources_rva)
        end = start + self.resources_size
        out, p = [], start
        while p + 4 <= end:
            (length,) = struct.unpack_from("<I", self.data, p)
            p += 4
            if length <= 0 or p + length > end:
                break
            blob = self.data[p : p + length]
            out.append({
                "offset": p,
                "size": length,
                "entropy": _entropy(blob),
                "resource_set": blob[:4] == b"\xce\xca\xef\xbe",
                "data": blob,
            })
            p += length
        return out


# ---------------------------------------------------------------------------
# IL
# ---------------------------------------------------------------------------

#: One-byte opcodes with no operand.
#:
#: This table has to be *complete*, not merely adequate, and the reason is the
#: same one the two-byte table below documents: an operand-carrying opcode that
#: is missing here falls through to `.byte`, its operand is then read as the next
#: opcode, and everything after it is fiction. `beq` (0x3B) and `endfinally`
#: (0xDC) were both absent, which desynchronised every method the protector
#: flattened -- and a flattened method is exactly the kind worth reading. The
#: comparison-branch families (0x2E-0x37 short, 0x3B-0x44 long) are the whole
#: point of a dispatcher, so their absence was not a cosmetic gap.
_SIMPLE = {
    0x00: "nop", 0x01: "break",
    0x02: "ldarg.0", 0x03: "ldarg.1", 0x04: "ldarg.2", 0x05: "ldarg.3",
    0x06: "ldloc.0", 0x07: "ldloc.1", 0x08: "ldloc.2", 0x09: "ldloc.3",
    0x0A: "stloc.0", 0x0B: "stloc.1", 0x0C: "stloc.2", 0x0D: "stloc.3",
    0x14: "ldnull", 0x15: "ldc.i4.m1",
    0x25: "dup", 0x26: "pop", 0x2A: "ret",
    0x58: "add", 0x59: "sub", 0x5A: "mul", 0x5B: "div", 0x5C: "div.un",
    0x5D: "rem", 0x5E: "rem.un", 0x5F: "and", 0x60: "or", 0x61: "xor",
    0x62: "shl", 0x63: "shr", 0x64: "shr.un", 0x65: "neg", 0x66: "not",
    0x67: "conv.i1", 0x68: "conv.i2", 0x69: "conv.i4", 0x6A: "conv.i8",
    0x6B: "conv.r4", 0x6C: "conv.r8", 0x6D: "conv.u4", 0x6E: "conv.u8",
    0x76: "conv.r.un",
    0x7A: "throw", 0x8E: "ldlen",
    0xC3: "ckfinite",
    0xD1: "conv.u2", 0xD2: "conv.u1", 0xD3: "conv.i",
    0xD4: "conv.ovf.i", 0xD5: "conv.ovf.u",
    0xD6: "add.ovf", 0xD7: "add.ovf.un", 0xD8: "mul.ovf", 0xD9: "mul.ovf.un",
    0xDA: "sub.ovf", 0xDB: "sub.ovf.un",
    # `endfinally`. Absent, it read as `.byte dc` and the decode survived by
    # luck; it is the terminator of every protected region in a flattened body.
    0xDC: "endfinally",
    0xDF: "stind.i", 0xE0: "conv.u",
    # The array-store family. `stelem.i1` is how a byte[] key is built one index
    # at a time, so decoding it as `.byte 9c` loses precisely the instruction
    # worth reading.
    0x9B: "stelem.i", 0x9C: "stelem.i1", 0x9D: "stelem.i2", 0x9E: "stelem.i4",
    0x9F: "stelem.i8", 0xA0: "stelem.r4", 0xA1: "stelem.r8", 0xA2: "stelem.ref",
    0x90: "ldelem.i1", 0x91: "ldelem.u1", 0x92: "ldelem.i2", 0x93: "ldelem.u2",
    0x94: "ldelem.i4", 0x95: "ldelem.u4", 0x96: "ldelem.i8", 0x97: "ldelem.i",
    0x98: "ldelem.r4", 0x99: "ldelem.r8", 0x9A: "ldelem.ref",
}
for _i in range(9):
    _SIMPLE[0x16 + _i] = f"ldc.i4.{_i}"
for _i, _n in enumerate(("i1", "u1", "i2", "u2", "i4", "u4", "i8", "i", "r4", "r8", "ref")):
    _SIMPLE[0x46 + _i] = f"ldind.{_n}"
for _i, _n in enumerate(("ref", "i1", "i2", "i4", "i8", "r4", "r8")):
    _SIMPLE[0x51 + _i] = f"stind.{_n}"
for _i, _n in enumerate(("i1", "i2", "i4", "i8", "u1", "u2", "u4", "u8", "i", "u")):
    _SIMPLE[0x82 + _i] = f"conv.ovf.{_n}.un"
for _i, _n in enumerate(("i1", "u1", "i2", "u2", "i4", "u4", "i8", "u8")):
    _SIMPLE[0xB3 + _i] = f"conv.ovf.{_n}"

_TOKEN = {
    0x27: "jmp", 0x28: "call", 0x29: "calli", 0x6F: "callvirt",
    0x70: "cpobj", 0x71: "ldobj", 0x73: "newobj", 0x74: "castclass",
    0x75: "isinst", 0x79: "unbox",
    0x7B: "ldfld", 0x7C: "ldflda", 0x7D: "stfld",
    # `ldsflda` was missing, and it is not interchangeable with `ldsfld`: the
    # proxy-field index keys on static field loads, so an undecoded 0x7F is a
    # call edge that never appears in the graph.
    0x7E: "ldsfld", 0x7F: "ldsflda", 0x80: "stsfld", 0x81: "stobj",
    0x8C: "box", 0x8D: "newarr", 0x8F: "ldelema",
    0xA3: "ldelem", 0xA4: "stelem", 0xA5: "unbox.any",
    0xC2: "refanyval", 0xC6: "mkrefany", 0xD0: "ldtoken",
}
_INT8 = {0x0E: "ldarg.s", 0x0F: "ldarga.s", 0x10: "starg.s", 0x11: "ldloc.s",
         0x12: "ldloca.s", 0x13: "stloc.s", 0x1F: "ldc.i4.s", 0xDE: "leave.s"}
#: The one-byte opcodes whose operand is an unsigned slot number rather than a
#: signed displacement or constant.
_INT8_SLOT = frozenset(("ldarg.s", "ldarga.s", "starg.s", "ldloc.s", "ldloca.s", "stloc.s"))
_INT32 = {0x20: "ldc.i4", 0xDD: "leave"}
_BRANCHES = ("br", "brfalse", "brtrue", "beq", "bge", "bgt", "ble", "blt",
             "bne.un", "bge.un", "bgt.un", "ble.un", "blt.un")
for _i, _n in enumerate(_BRANCHES):
    _INT8[0x2B + _i] = f"{_n}.s"
    _INT32[0x38 + _i] = _n
#: Wider immediates: `ldc.i8`, `ldc.r4`, `ldc.r8`. Read as bytes rather than
#: decoded to a value -- what matters here is consuming the right *width*.
_WIDE = {0x21: ("ldc.i8", 8), 0x22: ("ldc.r4", 4), 0x23: ("ldc.r8", 8)}

#: Two-byte opcodes, `FE xx`, with their operand widths.
#:
#: Not optional, and getting it wrong is silent. Without these the decoder
#: consumed the `FE xx` pair and then read the *operand* as the next opcode, so a
#: single `ldloc` desynchronised everything after it. On a control-flow-flattened
#: method that turned 3,865 instructions into 1,370 `.byte` lines and made the
#: method look like garbage rather than like code the tool could not read --
#: which is exactly the failure this project keeps naming: a decoder that is
#: wrong and a payload that is unreadable must not look alike.
_TWO_BYTE = {
    0x00: ("arglist", 0), 0x01: ("ceq", 0), 0x02: ("cgt", 0), 0x03: ("cgt.un", 0),
    0x04: ("clt", 0), 0x05: ("clt.un", 0),
    0x06: ("ldftn", "tok"), 0x07: ("ldvirtftn", "tok"),
    0x09: ("ldarg", 2), 0x0A: ("ldarga", 2), 0x0B: ("starg", 2),
    0x0C: ("ldloc", 2), 0x0D: ("ldloca", 2), 0x0E: ("stloc", 2),
    0x0F: ("localloc", 0), 0x11: ("endfilter", 0), 0x12: ("unaligned.", 1),
    0x13: ("volatile.", 0), 0x14: ("tail.", 0), 0x15: ("initobj", "tok"),
    0x16: ("constrained.", "tok"), 0x17: ("cpblk", 0), 0x18: ("initblk", 0),
    0x19: ("no.", 1),
    0x1A: ("rethrow", 0), 0x1C: ("sizeof", "tok"), 0x1D: ("refanytype", 0),
    0x1E: ("readonly.", 0),
}


class Instruction(NamedTuple):
    """One decoded IL instruction. `operand` is a metadata token for the token
    opcodes, an immediate for the rest, and None where there is no operand."""

    offset: int
    op: str
    operand: Optional[int]
    #: True when the decoder did not recognise the opcode. Any body with a
    #: decoded instruction after one of these is suspect: the operand of the
    #: unknown opcode was read as an instruction. Callers that build a graph
    #: from this should check `undecoded` rather than trusting the stream.
    unknown: bool = False


def instructions(image: DotNetImage, row: int) -> list[Instruction]:
    """Decode a method body to structured instructions.

    `disassemble` renders these for a human; the call-graph passes consume them
    directly, so the decode lives here once rather than in each caller.
    """
    span = image.method_body(row)
    if span is None:
        return []
    d = image.data
    start, end = span
    out: list[Instruction] = []
    p = start
    while p < end:
        op, at = d[p], p - start
        p += 1
        if op == 0xFE:
            op2 = d[p]
            p += 1
            name, width = _TWO_BYTE.get(op2, (f"fe{op2:02x}", 0))
            if width == "tok":
                out.append(Instruction(at, name, struct.unpack_from("<I", d, p)[0]))
                p += 4
            elif width:
                out.append(Instruction(at, name, int.from_bytes(d[p:p + width], "little")))
                p += width
            else:
                out.append(Instruction(at, name, None, op2 not in _TWO_BYTE))
        elif op in _SIMPLE:
            out.append(Instruction(at, _SIMPLE[op], None))
        elif op in _TOKEN or op == 0x72:
            name = "ldstr" if op == 0x72 else _TOKEN[op]
            out.append(Instruction(at, name, struct.unpack_from("<I", d, p)[0]))
            p += 4
        elif op in _INT8:
            name = _INT8[op]
            # Branch displacements and `ldc.i4.s` are signed; the argument and
            # local accessors carry an unsigned slot number.
            out.append(Instruction(at, name,
                                   int.from_bytes(d[p:p + 1], "little",
                                                  signed=name not in _INT8_SLOT)))
            p += 1
        elif op in _INT32:
            out.append(Instruction(at, _INT32[op], struct.unpack_from("<i", d, p)[0]))
            p += 4
        elif op in _WIDE:
            name, width = _WIDE[op]
            out.append(Instruction(at, name, int.from_bytes(d[p:p + width], "little")))
            p += width
        elif op == 0x45:
            # switch: a 4-byte count then that many 4-byte targets. The only
            # variable-length operand in IL, and skipping it is not survivable --
            # a flattened dispatcher's jump table is hundreds of entries, and
            # reading them as instructions produced 619 bytes of `ff` that looked
            # like an unreadable method rather than a decoder walking off the
            # rails.
            count = struct.unpack_from("<I", d, p)[0]
            p += 4 + count * 4
            out.append(Instruction(at, "switch", count))
        else:
            out.append(Instruction(at, f".byte {op:02x}", None, True))
    return out


#: Opcode names whose operand is a metadata token rather than an immediate.
TOKEN_OPS = frozenset(_TOKEN.values()) | {
    "ldstr", "ldftn", "ldvirtftn", "initobj", "constrained.", "sizeof",
}


def disassemble(image: DotNetImage, row: int) -> list[str]:
    """A method's IL, with ldstr and call targets resolved to names."""
    if image.method_body(row) is None:
        return ["(no body)"]

    member_refs = image.member_refs()
    methods = {m["index"]: m["name"] for m in image.method_defs()}
    field_rvas = image.field_rvas()

    def token(value: int) -> str:
        table, index = value >> 24, value & 0xFFFFFF
        if table == 0x0A:
            return member_refs.get(index, f"memberref#{index}")
        if table == 0x06:
            return f"this::{methods.get(index, f'method#{index}')}"
        if table == 0x04:
            rva = field_rvas.get(index)
            return f"field#{index}" + (f" @rva {rva:#x}" if rva else "")
        return f"{table:#04x}:{index}"

    lines = []
    for ins in instructions(image, row):
        if ins.operand is None:
            lines.append(f"{ins.offset:04x}  {ins.op}")
        elif ins.op == "ldstr":
            lines.append(f"{ins.offset:04x}  ldstr      "
                         f"{image.user_string(ins.operand & 0xFFFFFF)!r}")
        elif ins.op == "switch":
            lines.append(f"{ins.offset:04x}  switch     {ins.operand} targets")
        elif ins.op in TOKEN_OPS:
            lines.append(f"{ins.offset:04x}  {ins.op:10s} {token(ins.operand)}")
        else:
            lines.append(f"{ins.offset:04x}  {ins.op:10s} {ins.operand}")
    return lines


# ---------------------------------------------------------------------------
# Protector-specific: the proxy-delegate token map
# ---------------------------------------------------------------------------

def proxy_keystream_step(state: int) -> int:
    """One word of the keystream guarding the proxy-delegate token map.

    Specific to the protector on `422e30ed...` stage 2, and reproduced from its
    own `RuntimeTypeHandle` initialiser. There is **no key**: every constant is
    hardcoded and the state starts at zero, so the whole stream is computable.

    The two `%` moduli are 32-bit wrapping multiplies. That detail cost an hour:
    with a zero seed `state * state % modulus` is zero whatever the modulus is,
    so the *first* output word is correct even when the modulus is wrong, and
    only word two onwards diverges. **A reimplemented PRNG validated on its first
    output has not been validated at all** when the seed is zero.
    """
    original = value = state
    c11, c12, c13, c14 = 1065643639, 372079291, 616644994, 1182205445
    modulus = c13 * 432322986
    c14 = ((c14 * c14) & M32) % modulus & M32
    c13 = (36951 * (c13 & 0xFFFF) + (c13 >> 16)) & M32
    c14 = (40498 * (c14 & 0xFFFF) - (c14 >> 16)) & M32
    c12 = (19870 * c12 - c11) & M32
    c12 = (c12 + c14) & M32
    c13 = ((c13 << 15) | (c13 >> 17)) & M32
    modulus = ((c14 * 88665022) & M32) | 1
    value = ((value * value) & M32) % modulus & M32
    value ^= value >> 2
    value = (value + c12) & M32
    value ^= value >> 17
    value = (value + c13) & M32
    value ^= (value << 15) & M32
    value = (value + value) & M32
    value = ((((((c12 << 5) & M32) + c12) & M32) ^ c13) + value) & M32
    return (original + value) & M32


def decrypt_proxy_map(blob: bytes) -> list[tuple[int, int, bool]]:
    """Decrypt the token map to (field_token, target_token, use_callvirt).

    Validate the result by checking that every field token is in table 0x04 --
    1,181 of 1,181 on the reference sample. A wrong keystream fails that
    immediately, which is what makes it a usable self-check.
    """
    plain = bytearray(len(blob))
    state = 0
    remainder = len(blob) % 4
    blocks = len(blob) // 4 + (1 if remainder else 0)
    for i in range(blocks):
        base = i * 4
        if i == blocks - 1 and remainder:
            word_in = 0
            for j in range(remainder):
                if j:
                    word_in = (word_in << 8) & M32
                word_in |= blob[len(blob) - (1 + j)]
        else:
            word_in = struct.unpack_from("<I", blob, base)[0]
        state = proxy_keystream_step(state)
        word = state ^ word_in
        if i == blocks - 1 and remainder:
            mask, shift = 0xFF, 0
            for k in range(remainder):
                if k:
                    mask = (mask << 8) & M32
                    shift += 8
                plain[base + k] = (word & mask) >> shift
        else:
            struct.pack_into("<I", plain, base, word)

    out = []
    for i in range(len(plain) // 8):
        field, target = struct.unpack_from("<II", plain, i * 8)
        out.append((field, target & 0x3FFFFFFF, bool(target & 0x40000000)))
    return out


def decrypt_stage_payload(blob: bytes, key: bytes) -> bytes:
    """Reverse the payload cipher of `422e30ed...` stage 2 (`ConcatAllocator`, #470).

    Recovered from the IL once the call graph exposed the method, and it is
    **not AES** -- which is why 792 AES combinations and 24 candidate field keys
    got nowhere. The resource sits next to `AesCryptoServiceProvider` and its
    length happens to divide by 16, and both of those were read as evidence of a
    cipher that is not there. `--callgraph --xref CreateDecryptor` answers it
    directly: the image contains exactly two decryptors and both belong to the
    protector's own string layer.

    Per byte, over the array shortened by one (`Array.Resize(ref d, len - 1)`):

        d[i] = ((d[i] ^ key[i % len(key)]) - d[(i + 1) % len(d)] + 256) % 256

    `d[i + 1]` is still ciphertext when byte `i` is written, so the recurrence
    inverts in one forward pass -- and it inverts with *known plaintext* too,
    which is how the key was recovered rather than guessed:

        key[i % len(key)] = c[i] ^ ((plain[i] + c[i + 1]) % 256)

    against a stock MZ/DOS stub. The recovered stream repeated with period 10 in
    printable ASCII, which is the self-check: the key is built by
    `Encoding.ASCII.GetBytes`, so a wrong guess does not come back printable
    *and* periodic.

    Byte 0 is the one the algorithm loses. The loop guard is `i <= d.Length`, so
    a final iteration wraps `i % d.Length` back to 0 and overwrites the already
    decrypted first byte. The caller restores it; for a PE it is `M`.
    """
    d = bytearray(blob[:-1])
    n = len(d)
    return bytes(bytearray(
        ((d[i] ^ key[i % len(key)]) - d[(i + 1) % n] + 256) % 256 for i in range(n)))


def find_proxy_map(image: DotNetImage) -> Optional[tuple[str, bytes, list]]:
    """Locate the proxy-map resource by decrypting every candidate.

    The resource's *name* is generated per build, so keying on
    `StrategyEnumerator.SegmentedInitializer` would only ever work on this one
    sample. The self-check is the locator instead: the map is the blob whose
    plaintext is a whole number of 8-byte pairs with a Field token in every key
    slot, which no other resource satisfies by accident.

    Returns (name, blob, bindings) or None.
    """
    named = {}
    if image.resources_rva:
        base = image.pe.get_offset_from_rva(image.resources_rva)
        for entry in image.manifest_resources():
            named[base + entry["offset"] + 4] = entry["name"]
    for blob in image.managed_resources():
        data = blob["data"]
        if not data or len(data) % 8 or blob["resource_set"]:
            continue
        bindings = decrypt_proxy_map(data)
        if bindings and all(field >> 24 == 0x04 for field, _, _ in bindings):
            return named.get(blob["offset"], "?"), data, bindings
    return None


# ---------------------------------------------------------------------------
# The call graph the protector's proxy delegates hide
# ---------------------------------------------------------------------------

class CallGraph:
    """The real call graph, with proxy-delegate calls resolved back to targets.

    The protector replaces direct calls with a load of a static delegate field
    followed by an invoke, and the field-to-target bindings live encrypted in a
    resource. Read straight, the IL therefore shows almost no call edges at all:
    on the reference sample every interesting wrapper had **zero** direct callers
    while plainly being reached. The edges are recoverable because the map is,
    and rebuilding them is bookkeeping rather than inference.

    Two indexes, and the second is the one that was missing:

    * `binding` -- field token -> (target token, callvirt). Straight from the map.
    * `field_users` -- field token -> the methods that load it. This is the
      inverse index: the map says what a field *is*, and only a scan of every
      method body says who *uses* it.

    `edges` merges direct calls with proxy-mediated ones so a caller walk does
    not have to know which kind it is looking at.
    """

    def __init__(self, image: DotNetImage, bindings: list[tuple[int, int, bool]]):
        self.image = image
        self.binding = {field: (target, callvirt) for field, target, callvirt in bindings}
        self.names = {m["index"]: m["name"] for m in image.method_defs()}
        self.member_refs = image.member_refs()

        self.body: dict[int, list[Instruction]] = {}
        self.field_users: dict[int, set[int]] = collections.defaultdict(set)
        self.edges: dict[int, set[int]] = collections.defaultdict(set)
        self.callers: dict[int, set[int]] = collections.defaultdict(set)

        for method in image.method_defs():
            row = method["index"]
            ins = instructions(image, row)
            if not ins:
                continue
            self.body[row] = ins
            for i in ins:
                if i.operand is None:
                    continue
                if i.op in ("ldsfld", "ldsflda") and i.operand in self.binding:
                    self.field_users[i.operand].add(row)
                    self.edges[row].add(self.binding[i.operand][0])
                elif i.op in ("call", "callvirt", "newobj", "ldftn", "ldvirtftn", "jmp"):
                    if i.operand >> 24 in (0x06, 0x0A):
                        self.edges[row].add(i.operand)

        for row, targets in self.edges.items():
            for target in targets:
                if target >> 24 == 0x06:
                    self.callers[target & 0xFFFFFF].add(row)

    # -- naming -----------------------------------------------------------

    @staticmethod
    def readable(name: str) -> str:
        """Renamed-to-invisible identifiers rendered as a placeholder.

        The protector renames real code to runs of zero-width and
        bidirectional-control characters. Printed raw they are invisible, so two
        different methods look like the same empty string -- which is worse than
        useless in a call graph. Row numbers are the stable identity here.
        """
        return name if all(32 <= ord(c) < 127 for c in name) else f"<renamed:{len(name)}>"

    def method(self, row: int) -> str:
        return f"#{row} {self.readable(self.names.get(row, '?'))}"

    def owner(self, row: int) -> str:
        found = self.image.declaring_type(row)
        return self.readable(f"{found['namespace']}.{found['name']}") if found else "?"

    def target(self, token: int) -> str:
        table, index = token >> 24, token & 0xFFFFFF
        if table == 0x0A:
            return self.member_refs.get(index, f"memberref#{index}")
        if table == 0x06:
            return self.method(index)
        return f"{table:#04x}:{index}"

    # -- queries ----------------------------------------------------------

    def reaches(self, pattern: str) -> dict[int, set[str]]:
        """Methods with an edge to an external member matching `pattern`."""
        wanted = pattern.lower()
        out: dict[int, set[str]] = collections.defaultdict(set)
        for row, targets in self.edges.items():
            for token in targets:
                if token >> 24 != 0x0A:
                    continue
                name = self.member_refs.get(token & 0xFFFFFF, "")
                if wanted in name.lower():
                    out[row].add(name)
        return out

    def ancestors(self, row: int, depth: int = 12, budget: int = 64) -> list[list[int]]:
        """Caller chains reaching `row`, innermost first.

        Cycles are cut rather than followed, and the walk is bounded twice over:
        by `depth` and by a `budget` of chains. Both are needed. The protector's
        own runtime binder is called from all 1,181 proxy initialisers, so an
        unbounded enumeration here does not terminate in any useful time -- and
        it would say nothing anyway, because "reached from every stub" is the
        same statement as "reached from nowhere in particular".
        """
        chains: list[list[int]] = []
        queue = collections.deque([[row]])
        while queue and len(chains) < budget:
            path = queue.popleft()
            parents = sorted(self.callers.get(path[-1], set()) - set(path))
            if not parents or len(path) >= depth:
                chains.append(path)
                continue
            for parent in parents[:budget]:
                queue.append(path + [parent])
        chains.extend(queue)
        return chains[:budget]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("payload", help="a carved managed PE (any extension)")
    parser.add_argument("--summary", action="store_true", help="identity and heap sizes")
    parser.add_argument("--strings", choices=("ident", "user"), help="dump a heap")
    parser.add_argument("--methods", metavar="SUBSTRING",
                        help="methods whose body references a MemberRef matching this")
    parser.add_argument("--disasm", metavar="ROW", type=int, help="disassemble a MethodDef row")
    parser.add_argument("--field-rvas", action="store_true", help="byte[] literals, where keys live")
    parser.add_argument("--resources", metavar="OUTDIR", help="write managed resource blobs out")
    parser.add_argument("--proxy-map", metavar="BLOB",
                        help="decrypt a proxy-delegate token map (protector-specific)")
    parser.add_argument("--callgraph", action="store_true",
                        help="rebuild the call graph the proxy delegates hide")
    parser.add_argument("--xref", metavar="SUBSTRING",
                        help="with --callgraph: who really reaches this external member")
    parser.add_argument("--resolve", metavar="ROW", type=int,
                        help="with --callgraph: disassemble a row, proxy loads resolved")
    parser.add_argument("--decrypt-payload", nargs=2, metavar=("BLOB", "OUT"),
                        help="reverse the stage-2 payload cipher; key from --key")
    parser.add_argument("--key", default="HREWPjFNAr",
                        help="ASCII key for --decrypt-payload (default: the recovered one)")
    args = parser.parse_args(argv)

    image = DotNetImage(args.payload)

    if args.summary:
        print(f"runtime      {image.runtime_version}")
        print(f"cor flags    {image.cor_flags:#x} (ILONLY={bool(image.cor_flags & 1)}, "
              f"32BIT={bool(image.cor_flags & 2)})")
        print(f"heaps        " + ", ".join(f"{k}={v[1]}" for k, v in image.heaps.items()))
        print(f"typedefs     {image.rows.get(2, 0)}")
        print(f"methoddefs   {image.rows.get(6, 0)} "
              f"({sum(1 for m in image.method_defs() if m['rva'])} with bodies)")
        print(f"memberrefs   {image.rows.get(10, 0)}")
        print(f"fieldrvas    {len(image.field_rvas())}")
        print(f"resources    {image.resources_size} bytes at rva {image.resources_rva:#x}")

    if args.strings == "ident":
        for s in image.identifiers():
            print(s)
    elif args.strings == "user":
        for offset, text in sorted(image.user_strings().items()):
            print(f"ldstr token 0x70{offset:06x}  {text!r}")

    if args.methods:
        wanted = {row for row, name in image.member_refs().items()
                  if args.methods.lower() in name.lower()}
        patterns = {row: struct.pack("<I", 0x0A000000 | row) for row in wanted}
        names = image.member_refs()
        for method in image.method_defs():
            span = image.method_body(method["index"])
            if span is None:
                continue
            body = image.data[span[0]:span[1]]
            hits = sorted({names[row] for row, pat in patterns.items() if pat in body})
            if hits:
                owner = image.declaring_type(method["index"])
                where = f"{owner['namespace']}.{owner['name']}" if owner else "?"
                print(f"#{method['index']:<6} {method['name']:34s} {where}")
                for hit in hits:
                    print(f"          -> {hit}")

    if args.disasm:
        method = image.method_defs()[args.disasm - 1]
        owner = image.declaring_type(args.disasm)
        where = f"{owner['namespace']}.{owner['name']}" if owner else "?"
        print(f"#{args.disasm} {method['name']!r} in {where}")
        for line in disassemble(image, args.disasm):
            print("  " + line)

    if args.field_rvas:
        entries = sorted(image.field_rvas().items(), key=lambda kv: kv[1])
        for i, (field, rva) in enumerate(entries):
            nxt = entries[i + 1][1] if i + 1 < len(entries) else rva + 64
            size = min(nxt - rva, 512)
            off = image.pe.get_offset_from_rva(rva)
            blob = image.data[off:off + size]
            print(f"field#{field:<5} rva {rva:#x} size~{size:<4} {blob[:32].hex()}")

    if args.resources:
        out_dir = Path(args.resources)
        out_dir.mkdir(parents=True, exist_ok=True)
        for i, blob in enumerate(image.managed_resources(), 1):
            path = out_dir / f"resource_{i}.bin"
            path.write_bytes(blob["data"])
            kind = "resource set" if blob["resource_set"] else "raw blob"
            print(f"{path.name}  {blob['size']:>8} bytes  entropy {blob['entropy']:.3f}  {kind}")

    if args.proxy_map:
        bindings = decrypt_proxy_map(Path(args.proxy_map).read_bytes())
        valid = sum(1 for field, _, _ in bindings if field >> 24 == 0x04)
        print(f"{len(bindings)} bindings, {valid} with a Field-token key "
              f"({'PASS' if valid == len(bindings) else 'FAIL -- keystream is wrong'})")
        member_refs = image.member_refs()
        methods = {m["index"]: m["name"] for m in image.method_defs()}
        for field, target, callvirt in bindings:
            table, index = target >> 24, target & 0xFFFFFF
            if table == 0x0A:
                name = f"extern {member_refs.get(index, index)}"
            elif table == 0x06:
                name = f"intern {methods.get(index, index)}"
            else:
                name = f"other  {target:#x}"
            print(f"{field:#010x}  {'callvirt' if callvirt else 'call    '}  {name}")

    if args.decrypt_payload:
        blob_path, out_path = args.decrypt_payload
        plain = bytearray(decrypt_stage_payload(Path(blob_path).read_bytes(),
                                                args.key.encode("ascii")))
        # Byte 0 is destroyed by the cipher's own wrap-around, so it cannot be
        # recovered -- it is asserted from the format. Say so rather than
        # letting a repaired byte read as a decrypted one.
        recovered = plain[0]
        plain[0] = 0x4D
        print(f"{len(plain)} bytes, key {args.key!r}")
        print(f"byte 0 was {recovered:#04x} (lost to the i == Length wrap), set to 'M'")
        e_lfanew = int.from_bytes(plain[0x3C:0x40], "little")
        signature = bytes(plain[e_lfanew:e_lfanew + 4])
        print(f"e_lfanew {e_lfanew:#x}, signature {signature!r}")
        # The signature alone is not a check, and finding that out was the point.
        # `e_lfanew` sits at bytes 60-63 and `PE\0\0` at 184-187, so against a
        # 10-byte key they exercise key offsets 0-3 and 4-7 and never touch 8 or
        # 9 -- a key wrong in its last byte passes both. The same shape as
        # validating a PRNG on its first output. So the check that decides is the
        # header padding: the run from SizeOfHeaders to the first section is
        # zero-filled in every PE, it is kilobytes long, and it therefore covers
        # every key offset many times over.
        pad = plain[0x200:0x1000]
        zeros = pad.count(0) / len(pad)
        ok = signature == b"PE\0\0" and zeros > 0.99
        print(f"header padding 0x200-0x1000 is {zeros:.2%} zero "
              f"({'PASS' if ok else 'FAIL -- wrong key'})")
        if not ok:
            print("not writing output")
            return 1
        if Path(out_path).suffix == XOR_SUFFIX:
            plain = bytearray(xor_unwrap(bytes(plain)))
            print(f"written XOR-wrapped to {out_path}")
        Path(out_path).write_bytes(plain)
        return 0

    if args.callgraph or args.xref or args.resolve:
        found = find_proxy_map(image)
        if found is None:
            print("no proxy-delegate map in this image -- the IL's own call edges "
                  "are all there is")
            return 1
        name, blob, bindings = found
        graph = CallGraph(image, bindings)
        used = {f for f in graph.binding if graph.field_users.get(f)}
        print(f"proxy map    {name!r}, {len(blob)} bytes, {len(bindings)} bindings "
              f"(all keys Field tokens)")
        print(f"inverse index {len(used)} of {len(bindings)} proxy fields are loaded "
              f"by {len(set().union(*graph.field_users.values()) if used else set())} methods")
        print(f"edges        {sum(len(v) for v in graph.edges.values())} "
              f"({sum(1 for row in graph.edges for t in graph.edges[row] if t >> 24 == 0x0A)} "
              f"external), over {len(graph.body)} bodies")
        # An unloaded binding is a dangling entry, not a decode failure. Saying
        # so keeps a silent zero distinguishable from a real absence.
        orphans = [f for f in graph.binding if not graph.field_users.get(f)]
        if orphans:
            print(f"unused       {len(orphans)} bindings that no method loads: "
                  + ", ".join(f"{f:#x}" for f in sorted(orphans)))

    if args.xref:
        hits = graph.reaches(args.xref)
        print(f"\n{len(hits)} methods reach an external member matching {args.xref!r}")
        for row in sorted(hits):
            print(f"\n  {graph.method(row)}  in {graph.owner(row)}")
            for member in sorted(hits[row]):
                print(f"      -> {member}")
            for chain in graph.ancestors(row)[:8]:
                print("      via " + " <- ".join(graph.method(r) for r in chain))

    if args.resolve:
        row = args.resolve
        print(f"\n{graph.method(row)} in {graph.owner(row)}, "
              f"called by {sorted(graph.callers.get(row, ())) or 'nothing (entry point)'}")
        for i in graph.body.get(row, ()):
            if i.op in ("ldsfld", "ldsflda") and i.operand in graph.binding:
                token, callvirt = graph.binding[i.operand]
                print(f"  {i.offset:04x}  {i.op:9s} {i.operand:#x}  ==> "
                      f"{'callvirt' if callvirt else 'call'} {graph.target(token)}")
            elif i.op == "ldstr":
                print(f"  {i.offset:04x}  ldstr     "
                      f"{image.user_string(i.operand & 0xFFFFFF)!r}")
            elif i.op in TOKEN_OPS:
                print(f"  {i.offset:04x}  {i.op:9s} {graph.target(i.operand)}")
            else:
                print(f"  {i.offset:04x}  {i.op}"
                      + (f" {i.operand}" if i.operand is not None else ""))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
