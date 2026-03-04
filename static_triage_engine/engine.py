from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

from .config import TriageConfig
from .logging import EventCallback, emit, log_line, ledger_append, utc_now_iso
from .report import generate_reports
from .scoring import score_risk, classify_verdict
from .steps import (
    sha_hash,
    step_file,
    step_strings,
    step_capa,
    step_pe_metadata,
    step_lief_metadata,
    step_iocs,
)
from .extract import (
    extract_payloads,
    recursive_extract,
    write_extracted_manifest,
    select_subfile_targets,
)


TRUST_OVERRIDE_TECH_PREFIXES = {
    "T1055",  # injection
    "T1003",  # credential dumping
    "T1105",  # ingress tool transfer
    "T1071",  # C2
    "T1041",  # exfil
    "T1218",  # signed binary proxy exec
    "T1574",  # hijack execution flow
}


def _sha256_file(path: Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}


def _write_json(path: Path, obj: Any) -> None:
    try:
        path.write_text(json.dumps(obj, indent=2), encoding="utf-8", errors="replace")
    except Exception:
        pass


# ----------------------------
# Authenticode verification + cache (NEW)
# ----------------------------
def verify_authenticode_cached(
    file_path: str | Path,
    cache: dict[str, Any],
    timeout_sec: int = 60,
) -> dict[str, Any]:
    """
    Best-effort Authenticode verification via `osslsigncode verify`, cached by sha256.
    Never raises.
    """
    p = Path(file_path)

    result: dict[str, Any] = {
        "attempted": True,
        "tool": "osslsigncode",
        "path": str(p),
        "sha256": "",
        "verify_ok": False,
        "timestamp_verified": False,
        "subject": "",
        "issuer": "",
        "signing_time_utc": "",
        "timestamp_time_utc": "",
        "raw": "",
        "error": "",
    }

    if not p.exists():
        result["attempted"] = False
        result["error"] = "file does not exist"
        return result

    try:
        sha256 = _sha256_file(p)
        result["sha256"] = sha256
    except Exception as e:
        result["attempted"] = False
        result["error"] = f"sha256 failed: {type(e).__name__}: {e}"
        return result

    if sha256 in cache:
        cached = cache[sha256]
        if isinstance(cached, dict):
            # return cached but keep path fresh
            out = dict(cached)
            out["path"] = str(p)
            return out

    exe = shutil.which("osslsigncode")
    if not exe:
        result["attempted"] = False
        result["error"] = "osslsigncode not found in PATH"
        cache[sha256] = result
        return result

    try:
        cp = subprocess.run(
            [exe, "verify", "-in", str(p)],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        out = (cp.stdout or "") + ("\n" + cp.stderr if cp.stderr else "")
        result["raw"] = out[:120000]  # keep cache small-ish

        cur = re.search(r"Current message digest\s*:\s*([A-F0-9]{64})", out, re.I)
        calc = re.search(r"Calculated message digest\s*:\s*([A-F0-9]{64})", out, re.I)
        if cur and calc and cur.group(1).upper() == calc.group(1).upper():
            result["verify_ok"] = True

        if re.search(r"Timestamp verified using", out, re.I):
            result["timestamp_verified"] = True

        m_sub = re.search(r"Subject:\s*(.+)", out)
        if m_sub:
            result["subject"] = m_sub.group(1).strip()

        m_iss = re.search(r"Issuer\s*:\s*(.+)", out)
        if m_iss:
            result["issuer"] = m_iss.group(1).strip()

        m_ts = re.search(r"Timestamp time:\s*(.+)", out)
        if m_ts:
            result["timestamp_time_utc"] = m_ts.group(1).strip()

        m_st = re.search(r"Signing time:\s*(.+)", out)
        if m_st:
            result["signing_time_utc"] = m_st.group(1).strip()

        cache[sha256] = result
        return result

    except subprocess.TimeoutExpired:
        result["error"] = f"timeout after {timeout_sec}s"
        cache[sha256] = result
        return result
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        cache[sha256] = result
        return result


def write_signing_json(case_dir: Path, sample_path: Path, cache: dict[str, Any]) -> dict[str, Any]:
    signing = verify_authenticode_cached(sample_path, cache)
    signing["generated_utc"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    _write_json(case_dir / "signing.json", signing)
    return signing


def _trust_override_from_case(case_dir: Path) -> bool:
    # scan capa.json for technique IDs
    capa_json = case_dir / "capa.json"
    if not capa_json.exists():
        return False
    blob = capa_json.read_text(encoding="utf-8", errors="replace")
    techs = set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", blob))
    for t in techs:
        for pref in TRUST_OVERRIDE_TECH_PREFIXES:
            if t == pref or t.startswith(pref + "."):
                return True
    return False


def _reasons_list(suspicious: list[str], benign: list[str], limit_each: int = 12) -> list[str]:
    out: list[str] = []
    for s in (suspicious or [])[:limit_each]:
        out.append(f"SUSPICIOUS: {s}")
    for b in (benign or [])[:limit_each]:
        out.append(f"BENIGN: {b}")
    return out


def run_case(
    sample_path: str,
    case_name: Optional[str] = None,
    show_progress: bool = True,
    on_event: Optional[EventCallback] = None,
    config: Optional[TriageConfig] = None,
    *,
    enable_payload_extraction: bool = True,
    triage_extracted_pes: bool = True,
    subfile_limit: int = 25,
    recursive_rounds: int = 3,
    skip_strings: bool = False,
    strings_lite: bool = False,
) -> dict[str, Any]:
    """
    Added knobs:
      - skip_strings: skip strings extraction
      - strings_lite: allow strings-lite mode (depends on steps.py supporting it)
    """
    cfg = config or TriageConfig()
    total_start = time.time()

    sample_in = Path(sample_path).expanduser().resolve()
    if not sample_in.exists():
        raise FileNotFoundError(sample_in)

    case_name = case_name or sample_in.stem
    case_dir = cfg.cases_dir / case_name
    case_dir.mkdir(parents=True, exist_ok=True)

    # Signing cache (NEW)
    signing_cache_path = cfg.logs_dir / "signing_cache.json"
    signing_cache = _load_json(signing_cache_path)

    log_line(case_dir, f"CASE_START case={case_name} sample={sample_in}")

    sample_case = case_dir / sample_in.name
    if sample_case.resolve() != sample_in.resolve():
        shutil.copy2(sample_in, sample_case)

    emit(on_event, "info", "case", {"case_dir": str(case_dir), "sample": str(sample_case)})

    # NEW: signing.json for top-level sample
    signing_top = write_signing_json(case_dir, sample_case, signing_cache)
    signing_summary = {
        "verify_ok": bool(signing_top.get("verify_ok")),
        "timestamp_verified": bool(signing_top.get("timestamp_verified")),
        "subject": signing_top.get("subject", "") or "",
        "issuer": signing_top.get("issuer", "") or "",
    }

    # Hashes
    md5 = sha_hash(sample_case, "md5", show_progress=show_progress)
    sha1 = sha_hash(sample_case, "sha1", show_progress=show_progress)
    sha256 = sha_hash(sample_case, "sha256", show_progress=show_progress)

    meta = {
        "timestamp_utc": utc_now_iso(),
        "path_original": str(sample_in),
        "path_case": str(sample_case),
        "filename": sample_case.name,
        "size_bytes": sample_case.stat().st_size,
        "analysis": "static",
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
    }

    runlog: dict[str, Any] = {}
    summary: dict[str, Any] = {"sample": meta, "tools": {}, "signing": signing_summary}

    def _run_step(step_name: str, fn: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        emit(on_event, "start", step_name, {})
        log_line(case_dir, f"STEP_START {step_name}")
        step_start = time.time()
        res = fn()
        dur = round(time.time() - step_start, 3)
        res.setdefault("duration_sec", dur)
        rc = int(res.get("returncode", 0) or 0)
        if rc == 0 or res.get("skipped") is True:
            emit(on_event, "done", step_name, {"returncode": rc, "skipped": bool(res.get("skipped", False))})
            log_line(case_dir, f"STEP_DONE {step_name} rc={rc} dur={dur}")
        else:
            emit(on_event, "error", step_name, {"returncode": rc, "stderr": res.get("stderr", "")})
            log_line(case_dir, f"STEP_FAIL {step_name} rc={rc} dur={dur} err={str(res.get('stderr',''))[:200]}")
        return res

    # ----------------------------
    # Payload extraction + recursion (+ Inno happens in extract.py)
    # ----------------------------
    payload_result: dict[str, Any] = {"attempted": False, "success": False}

    if enable_payload_extraction:

        def _do_extract() -> dict[str, Any]:
            extracted_dir = case_dir / "extracted"
            r = extract_payloads(sample_case, extracted_dir)  # may choose innoextract/7z
            rec = recursive_extract(extracted_dir, max_rounds=recursive_rounds)
            r["recursive"] = rec

            all_files = [p for p in extracted_dir.rglob("*") if p.is_file()]
            all_pes = [p for p in all_files if p.suffix.lower() in {".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl"}]
            r["extracted_files"] = [str(p) for p in all_files[:5000]]
            r["extracted_pes"] = [str(p) for p in all_pes[:2000]]
            r["notes"] = f"Extracted {len(all_files)} files; found {len(all_pes)} PE payload(s)."
            r["post_recursive_rescan"] = {"files": len(all_files), "pes": len(all_pes)}

            write_extracted_manifest(case_dir, r)
            return {"returncode": int(r.get("returncode", 0) or 0), "payload": r, "manifest": str(case_dir / "extracted_manifest.json")}

        runlog["extract"] = _run_step("extract", _do_extract)
        payload_result = (runlog["extract"].get("payload") or {}) if isinstance(runlog["extract"], dict) else {}

        summary["payload_extraction"] = {
            "attempted": bool(payload_result.get("attempted", False)),
            "success": bool(payload_result.get("success", False)),
            "extractor": payload_result.get("extractor"),
            "notes": payload_result.get("notes"),
            "manifest": str(case_dir / "extracted_manifest.json"),
            "extracted_file_count": len(payload_result.get("extracted_files") or []),
            "extracted_pe_count": len(payload_result.get("extracted_pes") or []),
            "recursive": payload_result.get("recursive", {}),
        }
    else:
        summary["payload_extraction"] = {"attempted": False, "success": False, "notes": "disabled"}

    # ----------------------------
    # Top-level steps
    # ----------------------------
    runlog["pe_meta"] = _run_step("pe_meta", lambda: step_pe_metadata(sample_case, case_dir))
    runlog["lief_meta"] = _run_step("lief_meta", lambda: step_lief_metadata(sample_case, case_dir))
    runlog["file"] = _run_step("file", lambda: step_file(sample_case, case_dir))

    if skip_strings:
        runlog["strings"] = {"returncode": 0, "skipped": True, "output_file": None, "stdout": "", "stderr": ""}
    else:
        # strings_lite requires steps.py support; if not supported, it will simply ignore.
        runlog["strings"] = _run_step("strings", lambda: step_strings(sample_case, case_dir, lite=strings_lite))

    runlog["capa"] = _run_step("capa", lambda: step_capa(sample_case, case_dir, cfg))
    runlog["iocs"] = _run_step("iocs", lambda: step_iocs(case_dir))

    # ----------------------------
    # Subfile triage + rollups (NEW: top_scoring + attention)
    # ----------------------------
    sub_rollup: dict[str, Any] = {
        "enabled": bool(triage_extracted_pes),
        "count": 0,
        "top_scoring_subfiles": [],
        "attention_subfiles": [],
        "criteria": {
            "score_ge": 60,
            "unsigned_or_unverified": True,
            "trust_override": True,
        },
    }

    if triage_extracted_pes and enable_payload_extraction and bool(payload_result.get("success", False)):
        targets = select_subfile_targets(payload_result, limit=subfile_limit)
        sub_rollup["count"] = len(targets)

        sub_results: list[dict[str, Any]] = []
        sub_base = case_dir / "subfiles"
        sub_base.mkdir(parents=True, exist_ok=True)

        for idx, t in enumerate(targets, start=1):
            sub_name = f"{idx:02d}_{t.name}"
            sub_dir = sub_base / sub_name
            sub_dir.mkdir(parents=True, exist_ok=True)

            sub_sample = sub_dir / t.name
            try:
                if sub_sample.resolve() != t.resolve():
                    shutil.copy2(t, sub_sample)
            except Exception:
                sub_sample = t  # fallback

            signing_sf = write_signing_json(sub_dir, sub_sample, signing_cache)
            signed_ok = bool(signing_sf.get("verify_ok")) and bool(signing_sf.get("timestamp_verified"))

            sub_runlog: dict[str, Any] = {}
            sub_summary: dict[str, Any] = {
                "sample": {
                    "timestamp_utc": utc_now_iso(),
                    "path_original": str(t),
                    "path_case": str(sub_sample),
                    "filename": sub_sample.name,
                    "size_bytes": sub_sample.stat().st_size if sub_sample.exists() else 0,
                    "analysis": "static_subfile",
                },
                "tools": {},
                "signing": {
                    "verify_ok": bool(signing_sf.get("verify_ok")),
                    "timestamp_verified": bool(signing_sf.get("timestamp_verified")),
                    "subject": signing_sf.get("subject", "") or "",
                    "issuer": signing_sf.get("issuer", "") or "",
                },
                "flags": {},
            }

            def _sub_step(fn: Callable[[], dict[str, Any]]) -> dict[str, Any]:
                st = time.time()
                r = fn()
                r.setdefault("duration_sec", round(time.time() - st, 3))
                return r

            sub_runlog["pe_meta"] = _sub_step(lambda: step_pe_metadata(sub_sample, sub_dir))
            sub_runlog["lief_meta"] = _sub_step(lambda: step_lief_metadata(sub_sample, sub_dir))
            sub_runlog["file"] = _sub_step(lambda: step_file(sub_sample, sub_dir))
            if skip_strings:
                sub_runlog["strings"] = {"returncode": 0, "skipped": True}
            else:
                sub_runlog["strings"] = _sub_step(lambda: step_strings(sub_sample, sub_dir, lite=strings_lite))
            sub_runlog["capa"] = _sub_step(lambda: step_capa(sub_sample, sub_dir, cfg))
            sub_runlog["iocs"] = _sub_step(lambda: step_iocs(sub_dir))

            _write_json(sub_dir / "runlog.json", sub_runlog)
            _write_json(sub_dir / "summary.json", sub_summary)

            # trust-override flag from capa techniques
            trust_override = _trust_override_from_case(sub_dir)
            sub_summary["flags"]["trust_override"] = trust_override

            iocs_sf = _load_json(sub_dir / "iocs.json")
            pe_sf = _load_json(sub_dir / "pe_metadata.json")
            lief_sf = _load_json(sub_dir / "lief_metadata.json")

            sf_score, sf_susp, sf_ben = score_risk(sub_summary, iocs_sf, pe_sf, lief_sf)
            sf_verdict, sf_conf = classify_verdict(sf_score)

            sub_summary["risk_score"] = sf_score
            sub_summary["verdict"] = sf_verdict
            sub_summary["confidence"] = sf_conf
            sub_summary["reasons"] = _reasons_list(sf_susp, sf_ben)
            sub_summary["reason_breakdown"] = {"suspicious": sf_susp, "benign": sf_ben}

            _write_json(sub_dir / "summary.json", sub_summary)

            sub_results.append(
                {
                    "name": sub_name,
                    "path": str(sub_dir),
                    "filename": sub_sample.name,
                    "score": sf_score,
                    "verdict": sf_verdict,
                    "confidence": sf_conf,
                    "signed_ok": signed_ok,
                    "signer": sub_summary["signing"].get("subject", ""),
                    "trust_override": trust_override,
                }
            )

        sub_results_sorted = sorted(sub_results, key=lambda x: int(x.get("score", 0)), reverse=True)
        sub_rollup["top_scoring_subfiles"] = sub_results_sorted[:5]

        # attention list (NEW)
        attention: list[dict[str, Any]] = []
        for r in sub_results_sorted:
            if int(r.get("score", 0)) >= 60 or (not bool(r.get("signed_ok", False))) or bool(r.get("trust_override", False)):
                attention.append(r)
        sub_rollup["attention_subfiles"] = attention[:10]

    summary["subfiles_rollup"] = sub_rollup

    total_sec = round(time.time() - total_start, 3)
    summary["runtime_sec_total"] = total_sec

    _write_json(case_dir / "runlog.json", runlog)
    _write_json(case_dir / "summary.json", summary)

    # ----------------------------
    # Score + verdict (top-level)
    # ----------------------------
    iocs = _load_json(case_dir / "iocs.json")
    pe_meta = _load_json(case_dir / "pe_metadata.json")
    lief_meta = _load_json(case_dir / "lief_metadata.json")

    score, suspicious, benign = score_risk(summary, iocs, pe_meta, lief_meta)
    verdict, confidence = classify_verdict(score)

    summary["risk_score"] = score
    summary["verdict"] = verdict
    summary["confidence"] = confidence
    summary["reasons"] = _reasons_list(suspicious, benign)
    summary["reason_breakdown"] = {"suspicious": suspicious, "benign": benign}
    summary.setdefault("flags", {})
    summary["flags"]["trust_override"] = _trust_override_from_case(case_dir)

    _write_json(case_dir / "summary.json", summary)

    # ----------------------------
    # Reports
    # ----------------------------
    emit(on_event, "start", "report", {})
    rep = generate_reports(case_dir)
    emit(on_event, "done", "report", rep)

    log_line(case_dir, f"CASE_DONE total_sec={total_sec} verdict={verdict} score={score}")

    # ----------------------------
    # Ledger
    # ----------------------------
    ledger_append(
        cfg.ledger_file,
        cfg.logs_dir,
        {
            "timestamp_utc": utc_now_iso(),
            "case": case_name,
            "filename": sample_case.name,
            "sha256": sha256,
            "sha1": sha1,
            "md5": md5,
            "size_bytes": sample_case.stat().st_size,
            "case_dir": str(case_dir),
            "verdict": verdict,
            "confidence": confidence,
            "risk_score": score,
            "runtime_sec_total": total_sec,
            "report_pdf": rep.get("report_pdf"),
            "report_html": rep.get("report_html"),
            "report_md": rep.get("report_md"),
            "payload_extraction_success": bool(summary.get("payload_extraction", {}).get("success", False)),
            "subfile_count": int(summary.get("subfiles_rollup", {}).get("count", 0) or 0),
            "attention_subfiles": len(summary.get("subfiles_rollup", {}).get("attention_subfiles", []) or []),
        },
    )

    # persist signing cache (NEW)
    _write_json(signing_cache_path, signing_cache)

    return {
        "case_dir": str(case_dir),
        "sample_case": str(sample_case),
        **rep,
        "runtime_sec_total": total_sec,
        "risk_score": score,
        "verdict": verdict,
        "confidence": confidence,
    }
