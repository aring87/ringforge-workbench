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

#: The four fields `stripped_metadata` asks about, plus the ones a reader wants
#: alongside them. Values come out of the resource directory as bytes.
_VERSION_KEYS = (
    "CompanyName", "ProductName", "FileDescription", "OriginalFilename",
    "InternalName", "FileVersion", "ProductVersion", "LegalCopyright",
)


def _decode(raw) -> str:
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace").strip()
    return str(raw or "").strip()


def _version_info(pe) -> tuple[dict, bool]:
    """Return (fields, found_block) from the VS_VERSIONINFO resource.

    `found_block` distinguishes *this binary carries no StringFileInfo* from
    *we never looked*, which is the difference between an observation and a
    gap. The caller records it; the categoriser refuses to call a file
    anonymous on the strength of a lookup that did not happen.
    """
    fields: dict[str, str] = {}
    file_info = getattr(pe, "FileInfo", None)
    if not file_info:
        return fields, False

    # pefile nests this one level deeper once a binary carries more than one
    # version resource, so flatten before walking.
    entries = []
    for item in file_info:
        entries.extend(item) if isinstance(item, list) else entries.append(item)

    found = False
    for fi in entries:
        if getattr(fi, "Key", None) not in (b"StringFileInfo", "StringFileInfo"):
            continue
        found = True
        for table in getattr(fi, "StringTable", None) or []:
            for key, value in (getattr(table, "entries", None) or {}).items():
                name = _decode(key)
                text = _decode(value)
                # First language wins. A second translation of the same field
                # says the same thing about who built it.
                if name and text:
                    fields.setdefault(name, text)
    return fields, found


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

    # **The version-info block was read by the categoriser long before anything
    # wrote one.** `stripped_metadata` asks `_pe_string_table` for four fields
    # that no collector produced, so every sample looked anonymous and the
    # category silently degraded into `not trusted_signed`. Only the tests ever
    # built the block, by hand, which is why they passed throughout.
    try:
        version_fields, version_block = _version_info(pe)
        version_collected = True
    except Exception as exc:  # noqa: BLE001 - a parse failure is not an absence
        version_fields, version_block, version_collected = {}, False, False
        version_error = str(exc)
    else:
        version_error = ""

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
        "version_info": {k: v for k, v in version_fields.items()
                         if k in _VERSION_KEYS},
        "version_info_all": version_fields,
        # False means the lookup failed, not that the file is anonymous.
        "version_info_collected": version_collected,
        # False means the binary genuinely carries no StringFileInfo block.
        "version_info_present": version_block,
    }
    if version_error:
        meta["version_info_error"] = version_error

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
