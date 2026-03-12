from __future__ import annotations
import math
import json
from pathlib import Path

import pefile

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 4)

def extract_pe_metadata(sample_path: Path) -> dict:
    pe = pefile.PE(str(sample_path), fast_load=False)

    imports = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors="replace") if entry.dll else ""
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(imp.name.decode(errors="replace"))
                elif imp.ordinal is not None:
                    funcs.append(f"ordinal_{imp.ordinal}")
            imports.append({"dll": dll, "imports": funcs[:500]})

    sections = []
    for s in pe.sections:
        name = s.Name.decode(errors="replace").rstrip("\x00")
        data = s.get_data() or b""
        sections.append({
            "name": name,
            "virtual_size": int(s.Misc_VirtualSize),
            "raw_size": int(s.SizeOfRawData),
            "entropy": _entropy(data),
            "characteristics": int(s.Characteristics),
        })

    ts = int(pe.FILE_HEADER.TimeDateStamp)

    meta = {
        "is_pe": True,
        "machine": int(pe.FILE_HEADER.Machine),
        "timestamp_epoch": ts,
        "characteristics": int(pe.FILE_HEADER.Characteristics),
        "subsystem": int(pe.OPTIONAL_HEADER.Subsystem),
        "entrypoint_rva": int(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": int(pe.OPTIONAL_HEADER.ImageBase),
        "sections": sections,
        "imports": imports,
    }

    meta["heuristics"] = {
        "high_entropy_sections": [s for s in sections if s["entropy"] >= 7.2],
        "suspicious_import_dlls_present": sorted({
            i["dll"].lower() for i in imports
            if i["dll"].lower() in {"wininet.dll", "urlmon.dll", "ws2_32.dll", "crypt32.dll", "advapi32.dll"}
        }),
    }
    return meta

def write_pe_metadata(out_path: Path, meta: dict) -> None:
    out_path.write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
