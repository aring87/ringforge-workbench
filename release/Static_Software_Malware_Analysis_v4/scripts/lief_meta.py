from __future__ import annotations
import json
from pathlib import Path

def extract_lief_metadata(sample_path: Path) -> dict:
    import lief  # optional dependency
    try:
        pe = lief.parse(str(sample_path))
        if pe is None:
            return {"parsed": False, "reason": "lief.parse returned None"}
    except Exception as e:
        return {"parsed": False, "reason": str(e)}

    # LIEF objects aren't JSON-serializable; keep it simple and stable.
    imports = []
    try:
        for lib in pe.imports:
            imports.append({
                "library": str(lib.name),
                "entries": [str(e.name) for e in lib.entries if e.name][:500]
            })
    except Exception:
        pass

    sections = []
    try:
        for s in pe.sections:
            sections.append({
                "name": str(s.name),
                "size": int(s.size),
                "virtual_size": int(getattr(s, "virtual_size", 0)),
                "entropy": float(getattr(s, "entropy", 0.0)),
                "characteristics": int(getattr(s, "characteristics", 0)),
            })
    except Exception:
        pass

    tls_callbacks = []
    try:
        if pe.tls and pe.tls.callbacks:
            tls_callbacks = [hex(int(x)) for x in pe.tls.callbacks]
    except Exception:
        pass

    overlay_size = 0
    try:
        overlay_size = int(pe.overlay.size()) if pe.has_overlay else 0
    except Exception:
        pass

    return {
        "parsed": True,
        "format": "PE",
        "has_signature": bool(getattr(pe, "has_signature", False)),
        "has_debug": bool(getattr(pe, "has_debug", False)),
        "has_resources": bool(getattr(pe, "has_resources", False)),
        "overlay_size": overlay_size,
        "imports": imports,
        "sections": sections,
        "tls_callbacks": tls_callbacks,
    }

def write_lief_metadata(out_path: Path, meta: dict) -> None:
    out_path.write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
