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

The IL disassembler resolves `ldstr` against `#US` and `call`/`callvirt`/`newobj`
against `MemberRef`, which is enough to read a method's intent. It has no
control-flow reconstruction, so a control-flow-flattened method is where this
stops being the right tool -- reach for de4dot at that point.

One thing this found that a decompiler would have shown less directly: a method
whose entire body is `ldstr <16-char literal>` / `String::get_Length` / `ret`.
Ten such literals sat beside an AES call and about 4,000 key derivations were
spent on them before the bodies were read. `--disasm` is cheaper than a brute
force.

Usage:

    python scripts/dotnet_meta.py PAYLOAD --summary
    python scripts/dotnet_meta.py PAYLOAD --strings user
    python scripts/dotnet_meta.py PAYLOAD --methods GetManifestResourceStream
    python scripts/dotnet_meta.py PAYLOAD --disasm 1357
    python scripts/dotnet_meta.py PAYLOAD --field-rvas
    python scripts/dotnet_meta.py PAYLOAD --resources OUTDIR
"""

from __future__ import annotations

import argparse
import collections
import math
import struct
from pathlib import Path
from typing import Any, Optional

import pefile

M32 = 0xFFFFFFFF


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 4)


class DotNetImage:
    """Metadata heaps and tables of a managed PE, read straight from the file."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.pe = pefile.PE(str(self.path), fast_load=False)
        self.data = self.path.read_bytes()
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

_SIMPLE = {
    0x00: "nop", 0x02: "ldarg.0", 0x03: "ldarg.1", 0x04: "ldarg.2", 0x05: "ldarg.3",
    0x06: "ldloc.0", 0x07: "ldloc.1", 0x08: "ldloc.2", 0x09: "ldloc.3",
    0x0A: "stloc.0", 0x0B: "stloc.1", 0x0C: "stloc.2", 0x0D: "stloc.3",
    0x14: "ldnull", 0x25: "dup", 0x26: "pop", 0x2A: "ret", 0x58: "add", 0x59: "sub",
    0x5A: "mul", 0x5F: "and", 0x60: "or", 0x61: "xor", 0x62: "shl", 0x63: "shr",
    0x69: "conv.i4", 0x6A: "conv.i8", 0x7A: "throw", 0x8E: "ldlen",
    0x9A: "ldelem.ref", 0xA2: "stelem.ref",
    # The array-store family. `stelem.i1` is how a byte[] key is built one index
    # at a time, so decoding it as `.byte 9c` loses precisely the instruction
    # worth reading.
    0x9C: "stelem.i1", 0x9D: "stelem.i2", 0x9E: "stelem.i4", 0x9F: "stelem.i8",
    0xA0: "stelem.r4", 0xA1: "stelem.r8", 0x9B: "stelem.i",
    0x90: "ldelem.i1", 0x91: "ldelem.u1", 0x92: "ldelem.i2", 0x93: "ldelem.u2",
    0x94: "ldelem.i4", 0x95: "ldelem.u4", 0x96: "ldelem.i8", 0x97: "ldelem.i",
    0x5B: "div", 0x5C: "div.un", 0x5D: "rem", 0x5E: "rem.un",
    0x64: "shr.un", 0x65: "neg", 0x66: "not", 0x67: "conv.i1", 0x68: "conv.i2",
    0x6B: "conv.r4", 0x6C: "conv.r8", 0xD1: "conv.u2", 0xD2: "conv.u1",
    0x1E: "ldc.i4.8",
}
for _i in range(9):
    _SIMPLE[0x16 + _i] = f"ldc.i4.{_i}"

_TOKEN = {
    0x28: "call", 0x6F: "callvirt", 0x71: "ldobj", 0x73: "newobj", 0x74: "castclass",
    0x75: "isinst", 0x79: "unbox", 0x7B: "ldfld", 0x7D: "stfld", 0x7E: "ldsfld",
    0x80: "stsfld", 0x8C: "box", 0x8D: "newarr", 0x8F: "ldelema", 0xA4: "stelem",
    0xA5: "unbox.any", 0xD0: "ldtoken",
}
_INT8 = {0x0E: "ldarg.s", 0x11: "ldloc.s", 0x12: "ldloca.s", 0x13: "stloc.s",
         0x1F: "ldc.i4.s", 0x2B: "br.s", 0x2C: "brfalse.s", 0x2D: "brtrue.s",
         0xDE: "leave.s"}
_INT32 = {0x20: "ldc.i4", 0x38: "br", 0x39: "brfalse", 0x3A: "brtrue", 0xDD: "leave"}

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
    0x1A: ("rethrow", 0), 0x1C: ("sizeof", "tok"), 0x1D: ("refanytype", 0),
    0x1E: ("readonly.", 0),
}


def disassemble(image: DotNetImage, row: int) -> list[str]:
    """A method's IL, with ldstr and call targets resolved to names."""
    span = image.method_body(row)
    if span is None:
        return ["(no body)"]

    member_refs = image.member_refs()
    methods = {m["index"]: m["name"] for m in image.method_defs()}
    field_rvas = image.field_rvas()
    d = image.data
    start, end = span

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

    lines, p = [], start
    while p < end:
        op, at = d[p], p - start
        p += 1
        if op == 0xFE:
            op2 = d[p]
            p += 1
            name, width = _TWO_BYTE.get(op2, (f"fe{op2:02x}", 0))
            if width == "tok":
                value = struct.unpack_from("<I", d, p)[0]
                p += 4
                lines.append(f"{at:04x}  {name:10s} {token(value)}")
            elif width:
                value = int.from_bytes(d[p:p + width], "little")
                p += width
                lines.append(f"{at:04x}  {name:10s} {value}")
            else:
                lines.append(f"{at:04x}  {name}")
        elif op in _SIMPLE:
            lines.append(f"{at:04x}  {_SIMPLE[op]}")
        elif op in _TOKEN:
            value = struct.unpack_from("<I", d, p)[0]
            p += 4
            lines.append(f"{at:04x}  {_TOKEN[op]:10s} {token(value)}")
        elif op == 0x72:
            value = struct.unpack_from("<I", d, p)[0]
            p += 4
            lines.append(f"{at:04x}  ldstr      {image.user_string(value & 0xFFFFFF)!r}")
        elif op in _INT8:
            lines.append(f"{at:04x}  {_INT8[op]:10s} {d[p]}")
            p += 1
        elif op in _INT32:
            lines.append(f"{at:04x}  {_INT32[op]:10s} {struct.unpack_from('<i', d, p)[0]}")
            p += 4
        elif op == 0x45:
            # switch: a 4-byte count then that many 4-byte targets. The only
            # variable-length operand in IL, and skipping it is not survivable --
            # a flattened dispatcher's jump table is hundreds of entries, and
            # reading them as instructions produced 619 bytes of `ff` that looked
            # like an unreadable method rather than a decoder walking off the
            # rails.
            count = struct.unpack_from("<I", d, p)[0]
            p += 4
            targets = [struct.unpack_from("<i", d, p + i * 4)[0] for i in range(count)]
            p += count * 4
            lines.append(f"{at:04x}  switch     {count} targets")
            for i, target in enumerate(targets):
                lines.append(f"          [{i}] -> {target}")
        else:
            lines.append(f"{at:04x}  .byte {op:02x}")
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

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
