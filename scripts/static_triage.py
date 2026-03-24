#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

"""
scripts/static_triage.py

Backwards-compatible shim:
- Keeps: `python3 scripts/static_triage.py <sample> --case NAME`
- Delegates work to: static_triage_engine.engine.run_case
"""

import argparse
from typing import Any

from static_triage_engine.engine import run_case as run_case  # noqa: F401
from static_triage_engine.logging import EventCallback as EventCallback  # noqa: F401

# Optional re-exports (kept)
from static_triage_engine.steps import (  # noqa: F401
    sha_hash,
    run_cmd,
    ensure_capa_paths,
    safe_write,
    step_file,
    step_strings,
    step_capa,
    step_pe_metadata,
    step_lief_metadata,
    step_iocs,
)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("sample", help="Path to sample (.exe/.dll)")
    ap.add_argument("--case", default=None, help="Case folder name (default: sample basename)")
    ap.add_argument("--no-progress", action="store_true", help="Disable tqdm progress bars (CLI only)")

    # Fast/feature knobs (NEW)
    ap.add_argument("--no-extract", action="store_true", help="Disable payload extraction/recursion")
    ap.add_argument("--no-subfiles", action="store_true", help="Disable triage of extracted PE payloads")
    ap.add_argument("--subfile-limit", type=int, default=25, help="Max extracted PE payloads to triage (default: 25)")
    ap.add_argument("--no-strings", action="store_true", help="Skip strings extraction (faster, less IOC visibility)")
    ap.add_argument("--strings-lite", action="store_true", help="Faster, truncated strings output (still enables IOCs)")
    ap.add_argument("--capa-timeout", type=int, default=1800, help="Timeout in seconds for capa analysis (default: 1800)")
    ap.add_argument("--capa-max-size-mb", type=int, default=100, help="Skip capa when file size exceeds this many MB (default: 100)")

    args = ap.parse_args()

    r: dict[str, Any] = run_case(
        args.sample,
        case_name=args.case,
        show_progress=(not args.no_progress),
        enable_payload_extraction=(not args.no_extract),
        triage_extracted_pes=(not args.no_subfiles),
        subfile_limit=int(args.subfile_limit),
        skip_strings=bool(args.no_strings),
        strings_lite=bool(args.strings_lite),
        capa_timeout=max(60, int(args.capa_timeout)),
        capa_max_size_mb=max(1, int(args.capa_max_size_mb)),
    )

    print(f"[+] Case: {r['case_dir']}")
    print(f"[+] report.md: {r.get('report_md')}")
    print(f"[+] report.html: {r.get('report_html')}")
    print(f"[+] report.pdf: {r.get('report_pdf')}")
    print(f"[+] total runtime: {r.get('runtime_sec_total')}s")
    print(f"[+] SOC verdict: {r.get('verdict')} (score={r.get('risk_score')}/100)")


if __name__ == "__main__":
    main()
