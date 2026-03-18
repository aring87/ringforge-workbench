#!/usr/bin/env python3
from __future__ import annotations

import csv
import shutil
from datetime import datetime
from pathlib import Path

from static_triage_engine.engine import run_case

BASE = Path.home() / "analysis"
INBOX = BASE / "samples" / "inbox"
PROCESSED = BASE / "samples" / "processed"
OUTCSV = BASE / "logs" / f"batch_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

def safe_case_name(p: Path) -> str:
    # keep it predictable and filesystem-safe
    stem = p.stem.replace(" ", "_")
    return stem[:80]

def main() -> None:
    PROCESSED.mkdir(parents=True, exist_ok=True)
    (BASE / "logs").mkdir(parents=True, exist_ok=True)

    samples = sorted([p for p in INBOX.iterdir() if p.is_file() and p.suffix.lower() in (".exe", ".dll")])
    if not samples:
        print(f"[!] No samples found in {INBOX}")
        return

    rows = []
    for p in samples:
        case = safe_case_name(p)
        print(f"[+] Running: {p.name} -> case={case}")
        r = run_case(str(p), case_name=case, show_progress=False)
        rows.append({
            "filename": p.name,
            "case": case,
            "case_dir": r.get("case_dir"),
            "sha256": _read_sha256(Path(r["case_dir"]) / "summary.json"),
            "verdict": r.get("verdict"),
            "risk_score": r.get("risk_score"),
            "runtime_sec_total": r.get("runtime_sec_total"),
            "report_pdf": r.get("report_pdf"),
        })

        # move to processed (avoid overwrite)
        dest = PROCESSED / p.name
        if dest.exists():
            dest = PROCESSED / f"{p.stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{p.suffix}"
        shutil.move(str(p), str(dest))
        print(f"    moved -> {dest.name}")

    with OUTCSV.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    print(f"[+] Wrote batch summary: {OUTCSV}")

def _read_sha256(summary_json: Path) -> str:
    import json
    try:
        data = json.loads(summary_json.read_text(encoding="utf-8", errors="replace"))
        return (data.get("sample", {}) or {}).get("sha256", "")
    except Exception:
        return ""

if __name__ == "__main__":
    main()
