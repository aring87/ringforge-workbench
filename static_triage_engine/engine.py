from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

import requests

from .api_analysis import analyze_apis
from .config import TriageConfig
from .decoded_strings import extract_decoded_strings
from .extract import (
    extract_payloads,
    recursive_extract,
    select_subfile_targets,
    write_extracted_manifest,
)
from .floss_runner import floss_result_to_dict, run_floss
from .ioc_parser import extract_iocs_from_strings
from .logging import EventCallback, emit, ledger_append, log_line, utc_now_iso
from .report import generate_reports
from .scoring import classify_verdict, score_risk
from .steps import (
    sha_hash,
    step_capa,
    step_file,
    step_iocs,
    step_lief_metadata,
    step_pe_metadata,
    step_strings,
    step_yara,
)
from .verdict_rationale import build_static_verdict_rationale

TRUST_OVERRIDE_TECH_PREFIXES = {
    "T1055",
    "T1003",
    "T1105",
    "T1071",
    "T1041",
    "T1218",
    "T1574",
}

def _normalize_floss_summary(floss_summary: dict[str, Any] | None, case_dir: Path) -> dict[str, Any]:
    fs = floss_summary if isinstance(floss_summary, dict) else {}

    floss_json_path = case_dir / "floss_results.json"
    floss_json = _load_json(floss_json_path)

    metadata_block = floss_json.get("metadata", {}) if isinstance(floss_json.get("metadata"), dict) else {}
    analysis_block = floss_json.get("analysis", {}) if isinstance(floss_json.get("analysis"), dict) else {}
    strings_block = floss_json.get("strings", {}) if isinstance(floss_json.get("strings"), dict) else {}

    decoded_entries = strings_block.get("decoded_strings", [])
    if not isinstance(decoded_entries, list):
        decoded_entries = []

    cleaned_strings: list[str] = []
    for item in decoded_entries:
        if isinstance(item, dict):
            s = str(item.get("string", "") or "").strip()
            if s:
                cleaned_strings.append(s)
        elif item is not None:
            s = str(item).strip()
            if s:
                cleaned_strings.append(s)

    cleaned_strings = list(dict.fromkeys(cleaned_strings))

    high_risk_keywords = [
        "powershell",
        "cmd.exe",
        "rundll32",
        "regsvr32",
        "wscript",
        "cscript",
        "mshta",
        "http://",
        "https://",
        "\\run",
        "\\runonce",
        "appdata",
        "temp\\",
        "startup",
        ".ps1",
        ".vbs",
        ".js",
        ".hta",
        "base64",
        "frombase64string",
    ]

    high_risk_strings: list[str] = []
    for s in cleaned_strings:
        ls = s.lower()
        if any(k in ls for k in high_risk_keywords):
            high_risk_strings.append(s)

    function_block = analysis_block.get("functions", {}) if isinstance(analysis_block.get("functions"), dict) else {}
    runtime_block = metadata_block.get("runtime", {}) if isinstance(metadata_block.get("runtime"), dict) else {}

    notes: list[str] = []
    if fs.get("success") is True:
        notes.append("FLOSS decoded-string analysis completed.")
    if cleaned_strings:
        notes.append(f"Recovered {len(cleaned_strings)} decoded string(s) from FLOSS output.")
    else:
        notes.append("FLOSS ran successfully but did not recover decoded strings.")

    return {
        "enabled": bool(fs.get("enabled", False) or floss_json_path.exists()),
        "source": "floss",
        "stats": {
            "decoded_count": len(cleaned_strings),
            "high_risk_count": len(high_risk_strings),
            "analyzed_decoded_strings": int(function_block.get("analyzed_decoded_strings", 0) or 0),
            "runtime_decoded_strings": runtime_block.get("decoded_strings"),
        },
        "decoded_strings": cleaned_strings[:200],
        "high_risk_strings": high_risk_strings[:50],
        "notes": notes,
        "raw_metadata": {
            "file_path": metadata_block.get("file_path", ""),
            "version": metadata_block.get("version", ""),
        },
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


def _collect_strings_from_strings_json(strings_json: dict[str, Any]) -> list[str]:
    if not isinstance(strings_json, dict):
        return []

    candidates: list[str] = []

    for key in ("strings", "all_strings", "items", "lines"):
        value = strings_json.get(key)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    candidates.append(item)
                elif isinstance(item, dict):
                    for nested_key in ("string", "text", "value"):
                        nested_val = item.get(nested_key)
                        if isinstance(nested_val, str):
                            candidates.append(nested_val)
            if candidates:
                return candidates

    stdout_val = strings_json.get("stdout")
    if isinstance(stdout_val, str) and stdout_val.strip():
        return [line.strip() for line in stdout_val.splitlines() if line.strip()]

    output_file = strings_json.get("output_file")
    if output_file:
        try:
            p = Path(output_file)
            if p.exists():
                return [
                    line.strip()
                    for line in p.read_text(encoding="utf-8", errors="replace").splitlines()
                    if line.strip()
                ]
        except Exception:
            pass

    return []


def _count_capa_hits(case_dir: Path) -> int:
    capa_json = _load_json(case_dir / "capa.json")
    if not isinstance(capa_json, dict):
        return 0

    for key in ("rules", "matches", "capabilities"):
        value = capa_json.get(key)
        if isinstance(value, dict):
            return len(value)
        if isinstance(value, list):
            return len(value)

    meta = capa_json.get("meta", {})
    if isinstance(meta, dict):
        analysis = meta.get("analysis", {})
        if isinstance(analysis, dict):
            count = analysis.get("feature_counts")
            if isinstance(count, dict):
                total = count.get("total")
                if isinstance(total, int):
                    return total

    return 0


def vt_lookup_by_hash(sha256: str, api_key: str, timeout_sec: int = 30) -> dict[str, Any]:
    result: dict[str, Any] = {
        "enabled": True,
        "found": False,
        "sha256": sha256,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "meaningful_name": "",
        "type_description": "",
        "times_submitted": 0,
        "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
        "error": "",
        "last_analysis_stats": {},
        "last_analysis_results": {},
    }

    if not api_key:
        result["enabled"] = False
        result["error"] = "VT_API_KEY not set"
        return result

    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": api_key},
            timeout=timeout_sec,
        )

        if r.status_code == 200:
            data = r.json().get("data", {}) or {}
            attrs = data.get("attributes", {}) or {}
            stats = attrs.get("last_analysis_stats", {}) or {}
            results = attrs.get("last_analysis_results", {}) or {}

            result["found"] = True
            result["malicious"] = int(stats.get("malicious", 0) or 0)
            result["suspicious"] = int(stats.get("suspicious", 0) or 0)
            result["harmless"] = int(stats.get("harmless", 0) or 0)
            result["undetected"] = int(stats.get("undetected", 0) or 0)
            result["meaningful_name"] = attrs.get("meaningful_name", "") or ""
            result["type_description"] = attrs.get("type_description", "") or ""
            result["times_submitted"] = int(attrs.get("times_submitted", 0) or 0)
            result["last_analysis_stats"] = stats
            result["last_analysis_results"] = results
            return result

        if r.status_code == 404:
            result["error"] = "Hash not found in VirusTotal"
            return result

        try:
            result["error"] = f"VirusTotal API error {r.status_code}: {r.json()}"
        except Exception:
            result["error"] = f"VirusTotal API error {r.status_code}: {r.text[:500]}"
        return result

    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        return result


def write_virustotal_json(case_dir: Path, sha256: str, api_key: str = "") -> dict[str, Any]:
    api_key = (api_key or "").strip() or os.getenv("VT_API_KEY", "").strip()
    vt = vt_lookup_by_hash(sha256, api_key)
    _write_json(case_dir / "virustotal.json", vt)
    return vt


def _extract_first_match(pattern: str, text: str, flags: int = 0) -> str:
    m = re.search(pattern, text, flags)
    return m.group(1).strip() if m else ""


def _parse_osslsigncode_output(raw: str) -> dict[str, Any]:
    text = raw or ""

    subject = _extract_first_match(
        r"Signer #0:\s*\n\s*Subject:\s*(.+)",
        text,
        re.MULTILINE,
    )
    issuer = _extract_first_match(
        r"Signer #0:\s*\n\s*Subject:\s*.+\n\s*Issuer\s*:\s*(.+)",
        text,
        re.MULTILINE,
    )
    signing_time_utc = _extract_first_match(r"Signing time:\s*(.+)", text)
    timestamp_time_utc = _extract_first_match(r"Timestamp time:\s*(.+)", text)

    signature_verification_ok = bool(
        re.search(r"(?mi)^Signature verification:\s*ok\s*$", text)
    )
    timestamp_verified = bool(
        re.search(r"(?mi)^Timestamp(?: Server Signature)? verification:\s*ok\s*$", text)
    )
    timestamp_crl_ok = bool(
        re.search(r"(?mi)^Timestamp(?: Server Signature)? CRL verification:\s*ok\s*$", text)
    )
    signature_crl_ok = bool(
        re.search(r"(?mi)^Signature CRL verification:\s*ok\s*$", text)
    )
    succeeded_marker = bool(re.search(r"(?mi)^Succeeded\s*$", text))

    verified_sig_count = 0
    m_count = re.search(r"(?mi)^Number of verified signatures:\s*(\d+)\s*$", text)
    if m_count:
        try:
            verified_sig_count = int(m_count.group(1))
        except ValueError:
            verified_sig_count = 0

    digest_match_ok = False
    cur = re.search(r"Current message digest\s*:\s*([A-F0-9]{40,64})", text, re.I)
    calc = re.search(r"Calculated message digest\s*:\s*([A-F0-9]{40,64})", text, re.I)
    if cur and calc and cur.group(1).upper() == calc.group(1).upper():
        digest_match_ok = True

    verify_ok = (
        signature_verification_ok
        or verified_sig_count > 0
        or succeeded_marker
        or digest_match_ok
    )

    return {
        "verify_ok": verify_ok,
        "timestamp_verified": timestamp_verified,
        "subject": subject,
        "issuer": issuer,
        "signing_time_utc": signing_time_utc,
        "timestamp_time_utc": timestamp_time_utc,
        "parse_evidence": {
            "signature_verification_ok": signature_verification_ok,
            "verified_sig_count": verified_sig_count,
            "succeeded_marker": succeeded_marker,
            "digest_match_ok": digest_match_ok,
            "timestamp_verified": timestamp_verified,
            "timestamp_crl_ok": timestamp_crl_ok,
            "signature_crl_ok": signature_crl_ok,
        },
    }


def _signature_present_from_subject(subject: str) -> bool:
    return bool((subject or "").strip())


def _verify_authenticode_powershell(
    file_path: str | Path,
    timeout_sec: int = 60,
) -> dict[str, Any]:
    p = Path(file_path)

    result: dict[str, Any] = {
        "attempted": True,
        "tool": "powershell:Get-AuthenticodeSignature",
        "path": str(p),
        "sha256": "",
        "signature_present": False,
        "verify_ok": False,
        "timestamp_verified": False,
        "verification_status": "unknown",
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

    ps = shutil.which("powershell") or shutil.which("powershell.exe")
    if not ps:
        result["attempted"] = False
        result["error"] = "powershell not found in PATH"
        return result

    try:
        path_escaped = str(p).replace("'", "''")
        ps_script = (
            "$s = Get-AuthenticodeSignature -FilePath "
            f"'{path_escaped}' ; "
            "$o = [ordered]@{"
            "Status = [string]$s.Status; "
            "StatusMessage = [string]$s.StatusMessage; "
            "Path = [string]$s.Path; "
            "SignerSubject = if ($s.SignerCertificate) { [string]$s.SignerCertificate.Subject } else { '' }; "
            "SignerIssuer = if ($s.SignerCertificate) { [string]$s.SignerCertificate.Issuer } else { '' }; "
            "TimeStamperSubject = if ($s.TimeStamperCertificate) { [string]$s.TimeStamperCertificate.Subject } else { '' }; "
            "TimeStamperIssuer = if ($s.TimeStamperCertificate) { [string]$s.TimeStamperCertificate.Issuer } else { '' }"
            "}; $o | ConvertTo-Json -Compress"
        )
        cp = subprocess.run(
            [ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        raw = (cp.stdout or "") + ("\n" + cp.stderr if cp.stderr else "")
        result["raw"] = raw[:120000]

        payload = {}
        stdout = (cp.stdout or "").strip()
        if stdout:
            try:
                payload = json.loads(stdout)
            except Exception:
                payload = {}

        status = str(payload.get("Status") or "").strip()
        status_message = str(payload.get("StatusMessage") or "").strip()
        subject = str(payload.get("SignerSubject") or "").strip()
        issuer = str(payload.get("SignerIssuer") or "").strip()
        ts_subject = str(payload.get("TimeStamperSubject") or "").strip()

        signature_present = _signature_present_from_subject(subject) or status.lower() not in {"notsigned", ""}
        verify_ok = status.lower() == "valid"
        timestamp_verified = bool(ts_subject)

        verification_status = "unknown"
        if verify_ok:
            verification_status = "verified"
        elif signature_present:
            verification_status = "signed_unverified"
        elif status.lower() == "notsigned":
            verification_status = "unsigned"
        elif status:
            verification_status = "verification_error"

        result["signature_present"] = signature_present
        result["verify_ok"] = verify_ok
        result["timestamp_verified"] = timestamp_verified
        result["verification_status"] = verification_status
        result["subject"] = subject
        result["issuer"] = issuer
        if status_message and not verify_ok and verification_status != "unsigned":
            result["error"] = status_message

        if cp.returncode != 0 and not stdout and not result["error"]:
            result["error"] = f"powershell exited with code {cp.returncode}"

        return result

    except subprocess.TimeoutExpired:
        result["error"] = f"timeout after {timeout_sec}s"
        result["verification_status"] = "verification_error"
        return result
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        result["verification_status"] = "verification_error"
        return result


def verify_authenticode_cached(
    file_path: str | Path,
    cache: dict[str, Any],
    timeout_sec: int = 60,
) -> dict[str, Any]:
    p = Path(file_path)

    result: dict[str, Any] = {
        "attempted": True,
        "tool": "",
        "path": str(p),
        "sha256": "",
        "signature_present": False,
        "verify_ok": False,
        "timestamp_verified": False,
        "verification_status": "unknown",
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
            out = dict(cached)
            out["path"] = str(p)
            out["sha256"] = sha256
            out.setdefault(
                "signature_present",
                _signature_present_from_subject(str(out.get("subject", "") or "")) or bool(out.get("verify_ok")),
            )
            out.setdefault(
                "verification_status",
                "verified" if out.get("verify_ok") else ("signed_unverified" if out.get("signature_present") else "unsigned"),
            )
            return out

    verifiers: list[Callable[[], dict[str, Any]]] = []
    if os.name == "nt":
        verifiers.append(lambda: _verify_authenticode_powershell(p, timeout_sec=timeout_sec))
    verifiers.append(lambda: _verify_authenticode_osslsigncode(p, timeout_sec=timeout_sec))

    best: dict[str, Any] | None = None
    errors: list[str] = []

    for verifier in verifiers:
        current = verifier()
        current["path"] = str(p)
        current["sha256"] = sha256
        current.setdefault(
            "signature_present",
            _signature_present_from_subject(str(current.get("subject", "") or "")) or bool(current.get("verify_ok")),
        )
        current.setdefault(
            "verification_status",
            "verified"
            if current.get("verify_ok")
            else ("signed_unverified" if current.get("signature_present") else ("unsigned" if not current.get("error") else "verification_error")),
        )

        if current.get("verify_ok"):
            cache[sha256] = current
            return current

        if current.get("signature_present") and best is None:
            best = current

        err = str(current.get("error") or "").strip()
        if err:
            errors.append(f"{current.get('tool')}: {err}")

        if best is None:
            best = current

    final = dict(best or result)
    final["path"] = str(p)
    final["sha256"] = sha256
    if errors and not final.get("error"):
        final["error"] = " | ".join(errors[:3])
    cache[sha256] = final
    return final


def _verify_authenticode_osslsigncode(
    file_path: str | Path,
    timeout_sec: int = 60,
) -> dict[str, Any]:
    p = Path(file_path)

    result: dict[str, Any] = {
        "attempted": True,
        "tool": "osslsigncode",
        "path": str(p),
        "sha256": "",
        "signature_present": False,
        "verify_ok": False,
        "timestamp_verified": False,
        "verification_status": "unknown",
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

    exe = shutil.which("osslsigncode")
    if not exe:
        result["attempted"] = False
        result["error"] = "osslsigncode not found in PATH"
        result["verification_status"] = "verification_error"
        return result

    try:
        cp = subprocess.run(
            [exe, "verify", "-in", str(p)],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )

        raw = (cp.stdout or "") + ("\n" + cp.stderr if cp.stderr else "")
        result["raw"] = raw[:120000]

        parsed = _parse_osslsigncode_output(raw)
        result["verify_ok"] = bool(parsed.get("verify_ok"))
        result["timestamp_verified"] = bool(parsed.get("timestamp_verified"))
        result["subject"] = parsed.get("subject", "") or ""
        result["issuer"] = parsed.get("issuer", "") or ""
        result["signing_time_utc"] = parsed.get("signing_time_utc", "") or ""
        result["timestamp_time_utc"] = parsed.get("timestamp_time_utc", "") or ""
        result["parse_evidence"] = parsed.get("parse_evidence", {})
        result["signature_present"] = _signature_present_from_subject(result["subject"]) or bool(result["verify_ok"])

        if result["verify_ok"]:
            result["verification_status"] = "verified"
        elif result["signature_present"]:
            result["verification_status"] = "signed_unverified"
        else:
            result["verification_status"] = "unsigned"

        if cp.returncode != 0 and not result["verify_ok"]:
            result["error"] = f"osslsigncode verify returned {cp.returncode}"

        return result

    except subprocess.TimeoutExpired:
        result["error"] = f"timeout after {timeout_sec}s"
        result["verification_status"] = "verification_error"
        return result
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        result["verification_status"] = "verification_error"
        return result


def write_signing_json(case_dir: Path, sample_path: Path, cache: dict[str, Any]) -> dict[str, Any]:
    signing = verify_authenticode_cached(sample_path, cache)
    signing["generated_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    signing["parser_version"] = "signing-v2"
    _write_json(case_dir / "signing.json", signing)
    return signing


def _trust_override_from_case(case_dir: Path) -> bool:
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


def _vt_summary_from_result(vt_result: dict[str, Any]) -> dict[str, Any]:
    return {
        "enabled": bool(vt_result.get("enabled", False)),
        "found": bool(vt_result.get("found", False)),
        "malicious": int(vt_result.get("malicious", 0) or 0),
        "suspicious": int(vt_result.get("suspicious", 0) or 0),
        "harmless": int(vt_result.get("harmless", 0) or 0),
        "undetected": int(vt_result.get("undetected", 0) or 0),
        "meaningful_name": vt_result.get("meaningful_name", "") or "",
        "type_description": vt_result.get("type_description", "") or "",
        "times_submitted": int(vt_result.get("times_submitted", 0) or 0),
        "permalink": vt_result.get("permalink", "") or "",
        "error": vt_result.get("error", "") or "",
    }


def _classify_verdict_compat(score: int, summary: Optional[dict[str, Any]] = None) -> tuple[str, str]:
    try:
        if summary is not None:
            return classify_verdict(score, summary)
    except TypeError as e:
        msg = str(e)
        if "positional argument" not in msg or "were given" not in msg:
            raise
    return classify_verdict(score)


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
    capa_timeout: int = 1800,
    capa_max_size_mb: int = 100,
) -> dict[str, Any]:
    cfg = config or TriageConfig()
    total_start = time.time()

    sample_in = Path(sample_path).expanduser().resolve()
    if not sample_in.exists():
        raise FileNotFoundError(sample_in)

    case_name = case_name or sample_in.stem
    case_dir = cfg.cases_dir / case_name
    case_dir.mkdir(parents=True, exist_ok=True)

    signing_cache_path = cfg.logs_dir / "signing_cache.json"
    signing_cache = _load_json(signing_cache_path)

    log_line(case_dir, f"CASE_START case={case_name} sample={sample_in}")

    sample_case = case_dir / sample_in.name
    if sample_case.resolve() != sample_in.resolve():
        shutil.copy2(sample_in, sample_case)

    emit(on_event, "info", "case", {"case_dir": str(case_dir), "sample": str(sample_case)})

    floss_result = run_floss(
        sample_path=sample_case,
        case_dir=case_dir,
        tool_dir=cfg.tools_dir if getattr(cfg, "tools_dir", None) else None,
        timeout_seconds=getattr(cfg, "floss_timeout", 180),
        enabled=getattr(cfg, "enable_floss", True),
    )
    floss_summary = floss_result_to_dict(floss_result)
    
    normalized_floss = _normalize_floss_summary(floss_summary, case_dir)

    signing_top = write_signing_json(case_dir, sample_case, signing_cache)
    signing_summary = {
        "signature_present": bool(signing_top.get("signature_present")),
        "verify_ok": bool(signing_top.get("verify_ok")),
        "timestamp_verified": bool(signing_top.get("timestamp_verified")),
        "verification_status": signing_top.get("verification_status", "") or "",
        "subject": signing_top.get("subject", "") or "",
        "issuer": signing_top.get("issuer", "") or "",
        "tool": signing_top.get("tool", "") or "",
        "error": signing_top.get("error", "") or "",
    }

    def _run_hash_step(algo: str) -> str:
        emit(on_event, "start", algo, {})
        log_line(case_dir, f"STEP_START {algo}")
        step_start = time.time()
        try:
            value = sha_hash(sample_case, algo, show_progress=show_progress)
            dur = round(time.time() - step_start, 3)
            emit(on_event, "done", algo, {"returncode": 0, "value": value})
            log_line(case_dir, f"STEP_DONE {algo} rc=0 dur={dur}")
            return value
        except Exception as e:
            dur = round(time.time() - step_start, 3)
            emit(on_event, "error", algo, {"returncode": 1, "stderr": str(e)})
            log_line(case_dir, f"STEP_FAIL {algo} rc=1 dur={dur} err={str(e)[:200]}")
            raise

    md5 = _run_hash_step("md5")
    sha1 = _run_hash_step("sha1")
    sha256 = _run_hash_step("sha256")

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

    vt_result = write_virustotal_json(case_dir, sha256, os.getenv("VT_API_KEY", "").strip())
    vt_summary = _vt_summary_from_result(vt_result)

    runlog: dict[str, Any] = {
        "virustotal": vt_result,
        "floss": floss_summary,
    }
    summary: dict[str, Any] = {
        "sample": meta,
        "tools": {
            "floss": floss_summary,
        },
        "signing": signing_summary,
        "virustotal": vt_summary,
        "floss": floss_summary,
        "decoded_strings": normalized_floss,
    }

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
            log_line(case_dir, f"STEP_FAIL {step_name} rc={rc} dur={dur} err={str(res.get('stderr', ''))[:200]}")
        return res

    payload_result: dict[str, Any] = {"attempted": False, "success": False}

    if enable_payload_extraction:

        def _do_extract() -> dict[str, Any]:
            extracted_dir = case_dir / "extracted"
            r = extract_payloads(sample_case, extracted_dir)
            rec = recursive_extract(extracted_dir, max_rounds=recursive_rounds)
            r["recursive"] = rec

            all_files = [p for p in extracted_dir.rglob("*") if p.is_file()]
            all_pes = [p for p in all_files if p.suffix.lower() in {".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl"}]
            r["extracted_files"] = [str(p) for p in all_files[:5000]]
            r["extracted_pes"] = [str(p) for p in all_pes[:2000]]
            r["notes"] = f"Extracted {len(all_files)} files; found {len(all_pes)} PE payload(s)."
            r["post_recursive_rescan"] = {"files": len(all_files), "pes": len(all_pes)}

            write_extracted_manifest(case_dir, r)
            return {
                "returncode": int(r.get("returncode", 0) or 0),
                "payload": r,
                "manifest": str(case_dir / "extracted_manifest.json"),
            }

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

    runlog["pe_meta"] = _run_step("pe_meta", lambda: step_pe_metadata(sample_case, case_dir))
    runlog["lief_meta"] = _run_step("lief_meta", lambda: step_lief_metadata(sample_case, case_dir))
    runlog["file"] = _run_step("file", lambda: step_file(sample_case, case_dir))

    if skip_strings:
        runlog["strings"] = {"returncode": 0, "skipped": True, "output_file": None, "stdout": "", "stderr": ""}
    else:
        runlog["strings"] = _run_step("strings", lambda: step_strings(sample_case, case_dir, lite=strings_lite))

    runlog["api_analysis"] = _run_step("api_analysis", lambda: analyze_apis(sample_case, case_dir))
    runlog["yara"] = _run_step("yara", lambda: step_yara(sample_case, case_dir, cfg))
    runlog["capa"] = _run_step(
        "capa",
        lambda: step_capa(sample_case, case_dir, cfg, capa_timeout=capa_timeout, max_size_mb=capa_max_size_mb),
    )
    runlog["iocs"] = _run_step("iocs", lambda: step_iocs(case_dir))

    yara_result = _load_json(case_dir / "yara_results.json")
    summary["yara"] = {
        "matched": bool(yara_result.get("matched", False)),
        "match_count": int(yara_result.get("match_count", 0) or 0),
        "rule_file_count": int(yara_result.get("rule_file_count", 0) or 0),
        "top_rules": [m.get("rule", "") for m in (yara_result.get("matches", []) or [])[:10]],
        "error": yara_result.get("error", "") or "",
    }

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
                sub_sample = t

            signing_sf = write_signing_json(sub_dir, sub_sample, signing_cache)
            signed_ok = bool(signing_sf.get("verify_ok"))

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
                    "signature_present": bool(signing_sf.get("signature_present")),
                    "verify_ok": bool(signing_sf.get("verify_ok")),
                    "timestamp_verified": bool(signing_sf.get("timestamp_verified")),
                    "verification_status": signing_sf.get("verification_status", "") or "",
                    "subject": signing_sf.get("subject", "") or "",
                    "issuer": signing_sf.get("issuer", "") or "",
                    "tool": signing_sf.get("tool", "") or "",
                    "error": signing_sf.get("error", "") or "",
                },
                "flags": {},
                "virustotal": {
                    "enabled": False,
                    "found": False,
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 0,
                    "undetected": 0,
                    "meaningful_name": "",
                    "type_description": "",
                    "times_submitted": 0,
                    "permalink": "",
                    "error": "subfile VT lookup not performed",
                },
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
            sub_runlog["api_analysis"] = _sub_step(lambda: analyze_apis(sub_sample, sub_dir))
            sub_runlog["capa"] = _sub_step(lambda: step_capa(sub_sample, sub_dir, cfg))
            sub_runlog["iocs"] = _sub_step(lambda: step_iocs(sub_dir))

            _write_json(sub_dir / "runlog.json", sub_runlog)
            _write_json(sub_dir / "summary.json", sub_summary)

            trust_override = _trust_override_from_case(sub_dir)
            sub_summary["flags"]["trust_override"] = trust_override

            iocs_sf = _load_json(sub_dir / "iocs.json")
            pe_sf = _load_json(sub_dir / "pe_metadata.json")
            lief_sf = _load_json(sub_dir / "lief_metadata.json")

            sf_score, sf_susp, sf_ben = score_risk(sub_summary, iocs_sf, pe_sf, lief_sf)
            sf_verdict, sf_conf = _classify_verdict_compat(sf_score, sub_summary)

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

        attention: list[dict[str, Any]] = []
        for r in sub_results_sorted:
            if int(r.get("score", 0)) >= 60 or (not bool(r.get("signed_ok", False))) or bool(r.get("trust_override", False)):
                attention.append(r)
        sub_rollup["attention_subfiles"] = attention[:10]

    summary["subfiles_rollup"] = sub_rollup
    summary["runtime_sec_total"] = round(time.time() - total_start, 3)

    _write_json(case_dir / "runlog.json", runlog)
    _write_json(case_dir / "summary.json", summary)

    decoded_result = extract_decoded_strings(sample_case)
    strings_json = _load_json(case_dir / "strings.json")
    raw_strings = _collect_strings_from_strings_json(strings_json)

    legacy_decoded_strings = decoded_result.get("decoded_strings", []) or []
    floss_decoded_strings = normalized_floss.get("decoded_strings", []) or []

    all_string_material = list(raw_strings) + list(legacy_decoded_strings) + list(floss_decoded_strings)
    ioc_summary = extract_iocs_from_strings(all_string_material)

    merged_decoded_strings = dict(normalized_floss)

    legacy_notes = decoded_result.get("notes", []) if isinstance(decoded_result, dict) else []
    if isinstance(legacy_notes, list) and legacy_notes:
        merged_decoded_strings["notes"] = list(merged_decoded_strings.get("notes", [])) + [
            str(x) for x in legacy_notes if str(x).strip()
        ]

    summary["decoded_strings"] = merged_decoded_strings
    summary["ioc_summary"] = ioc_summary

    iocs = _load_json(case_dir / "iocs.json")
    pe_meta = _load_json(case_dir / "pe_metadata.json")
    lief_meta = _load_json(case_dir / "lief_metadata.json")

    score, suspicious, benign = score_risk(summary, iocs, pe_meta, lief_meta)
    verdict, confidence = _classify_verdict_compat(score, summary)

    summary["risk_score"] = score
    summary["verdict"] = verdict
    summary["confidence"] = confidence
    summary["reasons"] = _reasons_list(suspicious, benign)
    summary["reason_breakdown"] = {"suspicious": suspicious, "benign": benign}
    summary.setdefault("flags", {})
    summary["flags"]["trust_override"] = _trust_override_from_case(case_dir)

    capa_hits = _count_capa_hits(case_dir)
    summary["verdict_rationale"] = build_static_verdict_rationale(
        static_score=score,
        verdict=verdict,
        confidence=confidence,
        is_signed=bool(summary.get("signing", {}).get("verify_ok", False)),
        yara_hits=int(summary.get("yara", {}).get("match_count", 0) or 0),
        capa_hits=capa_hits,
        high_risk_strings=int(summary.get("decoded_strings", {}).get("stats", {}).get("high_risk_count", 0) or 0),
        ioc_counts=summary.get("ioc_summary", {}).get("counts", {}) or {},
        packer_score=summary.get("packer_obfuscation_rating"),
        vt_found=bool(summary.get("virustotal", {}).get("found", False)),
        vt_malicious=int(summary.get("virustotal", {}).get("malicious", 0) or 0),
        vt_suspicious=int(summary.get("virustotal", {}).get("suspicious", 0) or 0),
    )

    _write_json(case_dir / "summary.json", summary)

    log_line(case_dir, "STEP_START report")
    emit(on_event, "start", "report", {})
    rep = generate_reports(case_dir)
    log_line(case_dir, "STEP_DONE report rc=0")
    emit(on_event, "done", "report", rep)

    total_sec = round(time.time() - total_start, 3)
    log_line(case_dir, "STEP_START finalize")
    log_line(case_dir, "STEP_DONE finalize rc=0")
    log_line(case_dir, f"CASE_DONE total_sec={total_sec} verdict={verdict} score={score}")

    try:
        _write_json(signing_cache_path, signing_cache)
    except Exception:
        pass

    try:
        ledger_append(
            cfg.ledger_file,
            {
                "timestamp_utc": utc_now_iso(),
                "case_name": case_name,
                "sample": str(sample_case),
                "sha256": sha256,
                "score": score,
                "verdict": verdict,
                "confidence": confidence,
                "runtime_sec_total": total_sec,
                "vt_found": bool(summary.get("virustotal", {}).get("found", False)),
                "vt_malicious": int(summary.get("virustotal", {}).get("malicious", 0) or 0),
                "vt_suspicious": int(summary.get("virustotal", {}).get("suspicious", 0) or 0),
            },
        )
    except Exception:
        pass

    report_md = rep.get("report_md") if isinstance(rep, dict) else None
    report_html = rep.get("report_html") if isinstance(rep, dict) else None
    report_pdf = rep.get("report_pdf") if isinstance(rep, dict) else None

    return {
        "case_dir": str(case_dir),
        "sample": str(sample_case),
        "score": score,
        "risk_score": score,
        "verdict": verdict,
        "confidence": confidence,
        "summary": summary,
        "report": rep,
        "report_md": report_md,
        "report_html": report_html,
        "report_pdf": report_pdf,
        "virustotal": summary.get("virustotal", {}),
        "floss": summary.get("floss", {}),
        "decoded_strings": summary.get("decoded_strings", {}),
    }
