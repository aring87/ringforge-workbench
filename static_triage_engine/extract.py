# ~/analysis/static_triage_engine/extract.py
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

from .steps import run_cmd

PE_EXTS = {".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl"}
ARCHIVE_EXTS = {".zip", ".7z", ".rar", ".cab", ".msi"}


def find_7z() -> str | None:
    candidates = [
        shutil.which("7z"),
        shutil.which("7z.exe"),
        r"C:\Program Files\7-Zip\7z.exe",
        r"C:\Program Files (x86)\7-Zip\7z.exe",
        os.path.expandvars(r"%ProgramFiles%\7-Zip\7z.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\7-Zip\7z.exe"),
    ]
    seen: set[str] = set()
    for path in candidates:
        if not path:
            continue
        norm = os.path.normpath(path)
        if norm in seen:
            continue
        seen.add(norm)
        if os.path.isfile(norm):
            return norm
    return None


def _looks_like_inno(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            blob = f.read(5 * 1024 * 1024)
        return (b"Inno Setup" in blob) or (b"InnoSetup" in blob)
    except Exception:
        return False


def extract_payloads(sample_path: Path, out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)

    # Try innoextract first if detected
    if shutil.which("innoextract") is not None and _looks_like_inno(sample_path):
        cmd = ["innoextract", "-d", str(out_dir), str(sample_path)]
        res = run_cmd(cmd, cwd=out_dir, timeout=1800)

        extracted_files = [p for p in out_dir.rglob("*") if p.is_file()]
        extracted_pes = [p for p in extracted_files if p.suffix.lower() in PE_EXTS]
        success = (res.get("returncode", 1) == 0 and len(extracted_files) > 0)

        if success:
            notes = f"Extracted {len(extracted_files)} files; found {len(extracted_pes)} PE payload(s)."
            return {
                "attempted": True,
                "success": True,
                "extractor": "innoextract",
                "extracted_dir": str(out_dir),
                "notes": notes,
                "extracted_files": [str(p) for p in extracted_files[:5000]],
                "extracted_pes": [str(p) for p in extracted_pes[:2000]],
                **res,
            }

        # Fallback to 7z if innoextract failed/empty
        seven_zip = find_7z()
        if seven_zip is not None:
            cmd2 = [seven_zip, "x", "-y", f"-o{str(out_dir)}", str(sample_path)]
            res2 = run_cmd(cmd2, cwd=out_dir, timeout=1800)

            extracted_files2 = [p for p in out_dir.rglob("*") if p.is_file()]
            extracted_pes2 = [p for p in extracted_files2 if p.suffix.lower() in PE_EXTS]
            success2 = (res2.get("returncode", 1) == 0 and len(extracted_files2) > 0)

            if extracted_files2:
                notes2 = (
                    f"innoextract failed; 7z fallback extracted {len(extracted_files2)} files; "
                    f"found {len(extracted_pes2)} PE payload(s)."
                )
            else:
                notes2 = "innoextract failed; 7z fallback produced no files."

            return {
                "attempted": True,
                "success": bool(success2),
                "extractor": "7z_fallback_from_innoextract",
                "extracted_dir": str(out_dir),
                "notes": notes2,
                "extracted_files": [str(p) for p in extracted_files2[:5000]],
                "extracted_pes": [str(p) for p in extracted_pes2[:2000]],
                "innoextract": {
                    "cmd": cmd,
                    "returncode": res.get("returncode"),
                    "stderr": res.get("stderr", ""),
                    "stdout": res.get("stdout", ""),
                },
                **res2,
            }

        return {
            "attempted": True,
            "success": False,
            "extractor": "innoextract",
            "extracted_dir": str(out_dir),
            "notes": "innoextract failed and 7z not available for fallback.",
            "extracted_files": [],
            "extracted_pes": [],
            **res,
        }

    # Default: 7z
    seven_zip = find_7z()
    if seven_zip is None:
        return {
            "attempted": False,
            "success": False,
            "extractor": "7z",
            "extracted_dir": str(out_dir),
            "notes": "7z not found. Add 7-Zip to PATH or install it in the default Program Files path.",
            "extracted_files": [],
            "extracted_pes": [],
            "returncode": 127,
            "stdout": "",
            "stderr": "",
            "cmd": [],
            "duration_sec": 0.0,
        }

    cmd = [seven_zip, "x", "-y", f"-o{str(out_dir)}", str(sample_path)]
    res = run_cmd(cmd, cwd=out_dir, timeout=1800)

    extracted_files = [p for p in out_dir.rglob("*") if p.is_file()]
    extracted_pes = [p for p in extracted_files if p.suffix.lower() in PE_EXTS]
    success = (res.get("returncode", 1) == 0 and len(extracted_files) > 0)

    if not extracted_files:
        notes = "No files extracted. Installer may be a downloader, encrypted, or unsupported."
    elif extracted_pes:
        notes = f"Extracted {len(extracted_files)} files; found {len(extracted_pes)} PE payload(s)."
    else:
        notes = f"Extracted {len(extracted_files)} files; no PE payloads detected."

    return {
        "attempted": True,
        "success": bool(success),
        "extractor": "7z",
        "extracted_dir": str(out_dir),
        "notes": notes,
        "extracted_files": [str(p) for p in extracted_files[:5000]],
        "extracted_pes": [str(p) for p in extracted_pes[:2000]],
        **res,
    }


def recursive_extract(out_dir: Path, max_rounds: int = 3) -> dict[str, Any]:
    notes: list[str] = []
    extracted_more = 0

    seven_zip = find_7z()
    if seven_zip is None:
        notes.append("7z not found; cannot recursively extract")
        return {"rounds": 0, "extracted_more": 0, "notes": notes}

    cab_ok = shutil.which("cabextract") is not None

    rounds_completed = 0
    for round_idx in range(1, max_rounds + 1):
        rounds_completed = round_idx

        archives = [
            p for p in out_dir.rglob("*")
            if p.is_file() and (p.suffix.lower() in ARCHIVE_EXTS or p.name.lower().endswith(".cab"))
        ]
        if not archives:
            break

        round_extracted_files = 0

        for a in archives:
            dest = a.parent / (a.name + ".d")
            if dest.exists():
                continue
            dest.mkdir(parents=True, exist_ok=True)

            if a.suffix.lower() == ".cab" or a.name.lower().endswith(".cab"):
                res7 = run_cmd([seven_zip, "x", "-y", f"-o{str(dest)}", str(a)], cwd=dest, timeout=1800)
                files7 = [p for p in dest.rglob("*") if p.is_file()]
                if res7.get("returncode") == 0 and files7:
                    extracted_more += len(files7)
                    round_extracted_files += len(files7)
                    notes.append(f"Round {round_idx}: 7z extracted {len(files7)} from {a.name} -> {dest.name}")
                    continue

                if cab_ok:
                    res_cab = run_cmd(["cabextract", "-d", str(dest), str(a)], cwd=dest, timeout=1800)
                    files_cab = [p for p in dest.rglob("*") if p.is_file()]
                    if res_cab.get("returncode") == 0 and files_cab:
                        extracted_more += len(files_cab)
                        round_extracted_files += len(files_cab)
                        notes.append(f"Round {round_idx}: cabextract extracted {len(files_cab)} from {a.name} -> {dest.name}")
                    else:
                        notes.append(f"Round {round_idx}: CAB extract produced no files for {a.name} (7z+cabextract).")
                else:
                    notes.append(f"Round {round_idx}: cabextract not installed; CAB extraction incomplete for {a.name}.")
                continue

            res = run_cmd([seven_zip, "x", "-y", f"-o{str(dest)}", str(a)], cwd=dest, timeout=1800)
            files_now = [p for p in dest.rglob("*") if p.is_file()]
            if res.get("returncode") == 0 and files_now:
                extracted_more += len(files_now)
                round_extracted_files += len(files_now)
                notes.append(f"Round {round_idx}: 7z extracted {len(files_now)} from {a.name} -> {dest.name}")

        if round_extracted_files == 0:
            break

    return {"rounds": rounds_completed, "extracted_more": extracted_more, "notes": notes}


def rescan_extracted(out_dir: Path) -> dict[str, Any]:
    all_files = [p for p in out_dir.rglob("*") if p.is_file()]
    all_pes = [p for p in all_files if p.suffix.lower() in PE_EXTS]
    return {
        "file_count": len(all_files),
        "pe_count": len(all_pes),
        "files": [str(p) for p in all_files[:5000]],
        "pes": [str(p) for p in all_pes[:2000]],
    }


def write_extracted_manifest(case_dir: Path, payload_result: dict[str, Any]) -> Path:
    out = case_dir / "extracted_manifest.json"
    out.write_text(json.dumps(payload_result, indent=2), encoding="utf-8", errors="replace")
    return out


def select_subfile_targets(payload_result: dict[str, Any], limit: int = 25) -> list[Path]:
    pes = payload_result.get("extracted_pes") or payload_result.get("pes")
    if not isinstance(pes, list):
        return []

    out: list[Path] = []
    for s in pes:
        try:
            p = Path(str(s))
            if p.exists() and p.is_file():
                out.append(p)
        except Exception:
            continue
    return out[:limit]

