from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse


@dataclass
class ScoreEvidence:
    source: str
    rule: str
    points: int
    message: str


@dataclass
class CombinedScore:
    total_score: int
    severity: str
    verdict: str
    confidence: str
    subscores: Dict[str, int] = field(default_factory=dict)
    present: Dict[str, bool] = field(default_factory=dict)
    evidence: List[ScoreEvidence] = field(default_factory=list)
    raw_flags: Dict[str, Any] = field(default_factory=dict)


HIGH_SIGNAL_TECH_PREFIXES = {
    "T1055", "T1059", "T1105", "T1547", "T1543", "T1569", "T1021", "T1071",
    "T1041", "T1003", "T1110", "T1552", "T1218", "T1574", "T1036", "T1566",
}
LOW_SIGNAL_TECH_PREFIXES = {"T1027", "T1033", "T1082", "T1083", "T1087", "T1129", "T1497", "T1564.003"}
TRUST_OVERRIDE_TECH_PREFIXES = {"T1055", "T1003", "T1105", "T1071", "T1041", "T1218", "T1574"}

KNOWN_BENIGN_DOMAIN_SUFFIXES = {
    "digicert.com", "ocsp.digicert.com", "crl3.digicert.com", "crl4.digicert.com", "cacerts.digicert.com",
}
KNOWN_BENIGN_IPS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9"}


def _safe_load_json(path: Path) -> dict[str, Any]:
    try:
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}


def _safe_count(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, (list, tuple, set, dict)):
        return len(value)
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return 0
        try:
            return int(raw)
        except Exception:
            return 0
    return 0


def _is_weak_vt_noise(vt: dict[str, Any]) -> bool:
    if not isinstance(vt, dict):
        return False
    vt_found = bool(vt.get("found", False))
    vt_mal = _safe_count(vt.get("malicious", 0))
    vt_susp = _safe_count(vt.get("suspicious", 0))
    return vt_found and 1 <= vt_mal <= 2 and vt_susp == 0


def classify_verdict(score: int, summary: dict[str, Any] | None = None) -> tuple[str, str]:
    vt = summary.get("virustotal", {}) if isinstance(summary, dict) and isinstance(summary.get("virustotal"), dict) else {}
    vt_found = bool(vt.get("found", False))
    vt_mal = int(vt.get("malicious", 0) or 0)
    vt_susp = int(vt.get("suspicious", 0) or 0)
    vt_harmless = int(vt.get("harmless", 0) or 0)
    vt_undetected = int(vt.get("undetected", 0) or 0)

    verdict = "BENIGN"
    confidence = "Low confidence"

    if score >= 75:
        verdict = "MALICIOUS"
        confidence = "High confidence"
    elif score >= 50:
        verdict = "SUSPICIOUS"
        confidence = "Moderate confidence"
    elif score >= 20:
        verdict = "LOW_RISK"
        confidence = "Low confidence"

    if vt_found:
        strong_vt_malicious = vt_mal >= 15 or (vt_mal >= 8 and score >= 60)
        medium_vt_suspicious = vt_mal >= 5 or vt_susp >= 10 or (vt_mal + vt_susp) >= 8
        weak_vt_noise = _is_weak_vt_noise(vt)
        clean_vt_signal = vt_mal == 0 and vt_susp == 0 and (vt_harmless >= 1 or vt_undetected >= 10)

        if strong_vt_malicious:
            verdict = "MALICIOUS"
            confidence = "High confidence" if (vt_mal >= 15 or score >= 90) else "Moderate confidence"

        elif medium_vt_suspicious and verdict != "MALICIOUS":
            if score >= 75:
                verdict = "MALICIOUS"
                confidence = "High confidence"
            elif score >= 50:
                verdict = "SUSPICIOUS"
                confidence = "High confidence" if (vt_mal >= 5 or vt_susp >= 10) else "Moderate confidence"
            elif score >= 20:
                verdict = "LOW_RISK"
                confidence = "Moderate confidence"
            else:
                verdict = "SUSPICIOUS"
                confidence = "Moderate confidence"

        elif weak_vt_noise:
            if score < 50:
                verdict = "LOW_RISK" if score >= 20 else "BENIGN"
                confidence = "Low confidence"

        elif clean_vt_signal:
            if score < 50:
                verdict = "BENIGN"
                confidence = "Moderate confidence" if (vt_harmless >= 3 or vt_undetected >= 20) else "Low confidence"
            elif score < 75:
                verdict = "LOW_RISK"
                confidence = "Low confidence"

    return verdict, confidence


def score_static(
    summary: dict[str, Any] | None,
    iocs: dict[str, Any] | None,
    pe_meta: dict[str, Any] | None,
    lief_meta: dict[str, Any] | None,
    api_analysis: dict[str, Any] | None,
) -> tuple[int, list[ScoreEvidence], dict[str, Any]]:
    summary = summary or {}
    iocs = iocs or {}
    pe_meta = pe_meta or {}
    lief_meta = lief_meta or {}
    api_analysis = api_analysis or {}

    evidence: list[ScoreEvidence] = []
    flags: dict[str, Any] = {}
    score = 0

    case_dir = _get_case_dir(summary)
    yara_results = _safe_load_json(case_dir / "yara_results.json")
    file_info = _pe_string_table(pe_meta)
    company = (file_info.get("CompanyName") or "").strip()
    product = (file_info.get("ProductName") or "").strip()
    desc = (file_info.get("FileDescription") or "").strip()
    original_filename = (file_info.get("OriginalFilename") or "").strip()
    looks_like_installer = _looks_like_installer(company, product, desc, summary, case_dir)
    flags["looks_like_installer"] = looks_like_installer

    vt = summary.get("virustotal", {}) if isinstance(summary.get("virustotal"), dict) else {}
    weak_vt_noise = _is_weak_vt_noise(vt)

    yara_matched = bool(yara_results.get("matched", False)) if isinstance(yara_results, dict) else False
    likely_benign_installer_context = looks_like_installer and weak_vt_noise and not yara_matched
    flags["likely_benign_installer_context"] = likely_benign_installer_context
        
    signing = _load_signing(case_dir)
    verify_ok = bool(signing.get("verify_ok"))
    timestamp_verified = bool(signing.get("timestamp_verified"))
    signer_subject = (signing.get("subject") or "").strip()
    trusted_signed = verify_ok and timestamp_verified

    if trusted_signed:
        evidence.append(
            ScoreEvidence(
                "static",
                "trusted_signature",
                -6,
                f"Valid signature verified ({signer_subject or 'subject unavailable'})",
            )
        )
        score -= 6
    else:
        score += 8
        evidence.append(
            ScoreEvidence(
                "static",
                "unsigned_or_unverified",
                8,
                "File is unsigned or signing verification failed",
            )
        )

    if likely_benign_installer_context:
        evidence.append(
            ScoreEvidence(
                "static",
                "installer_context",
                -2,
                "Installer-like package with only weak VirusTotal noise and no YARA matches; ATT&CK/capa evidence dampened",
            )
        )
        score -= 2

    if not company:
        score += 2
        evidence.append(ScoreEvidence("static", "missing_company", 2, "Missing CompanyName in version information"))
    if not product:
        score += 2
        evidence.append(ScoreEvidence("static", "missing_product", 2, "Missing ProductName in version information"))
    if not desc:
        score += 1
        evidence.append(ScoreEvidence("static", "missing_description", 1, "Missing FileDescription in version information"))
    if not original_filename:
        score += 1
        evidence.append(ScoreEvidence("static", "missing_original_filename", 1, "Missing OriginalFilename in version information"))

    sample_info = summary.get("sample", {}) if isinstance(summary.get("sample"), dict) else {}
    sample_name = str(
        sample_info.get("filename")
        or sample_info.get("name")
        or sample_info.get("path")
        or sample_info.get("path_case")
        or ""
    ).strip().lower()

    if re.fullmatch(r"[0-9a-f]{24,}\.(exe|dll|scr|com|bat|ps1)?", sample_name):
        score += 6
        evidence.append(ScoreEvidence("static", "hash_like_name", 6, "Filename resembles a hash or random artifact"))

    if sample_name.endswith((".scr", ".com", ".js", ".jse", ".vbs", ".ps1", ".hta")):
        score += 10
        evidence.append(ScoreEvidence("static", "suspicious_extension", 10, f"Suspicious script or executable extension: {sample_name}"))

    techs = _extract_techniques(summary)
    high = [t for t in techs if _prefix_in(t, HIGH_SIGNAL_TECH_PREFIXES)]
    other = [t for t in techs if not _prefix_in(t, LOW_SIGNAL_TECH_PREFIXES)]

    if high:
        add = min(22, 12 + 3 * len(high))
        score += add
        evidence.append(
            ScoreEvidence(
                "static",
                "high_signal_attack",
                add,
                f"High-signal ATT&CK techniques present: {', '.join(high[:8])}",
            )
        )
    elif techs:
        add = 4 if looks_like_installer else 6
        score += add
        evidence.append(
            ScoreEvidence(
                "static",
                "techniques_present",
                add,
                f"ATT&CK techniques present: {len(techs)}",
            )
        )

    if other and not high:
        add = min(5, 1 + len(other) // 2)
        score += add
        evidence.append(
            ScoreEvidence(
                "static",
                "additional_techniques",
                add,
                f"Additional ATT&CK techniques detected: {len(other)}",
            )
        )

    capa_json_path = case_dir / "capa.json"
    capa_blob = capa_json_path.read_text(encoding="utf-8", errors="replace") if capa_json_path.exists() else ""
    match_count = capa_blob.count('"matches"')
    if match_count > 0:
        add = min(6, 1 + int(match_count / 40))
        score += add
        evidence.append(ScoreEvidence("static", "capa_density", add, f"capa match density observed: {match_count}"))

    api_add = _score_api_findings_evidence(
        api_json=api_analysis,
        looks_like_installer=looks_like_installer,
    )
    score += api_add[0]
    evidence.extend(api_add[1])

    yara_add = _score_yara_evidence(yara_results)
    score += yara_add[0]
    evidence.extend(yara_add[1])
    flags.update(yara_add[2])

    score = max(0, min(40, score))
    return score, evidence, flags


def _score_api_findings_evidence(
    api_json: dict[str, Any],
    looks_like_installer: bool,
) -> tuple[int, list[ScoreEvidence]]:
    if not isinstance(api_json, dict) or not api_json:
        return 0, []

    if int(api_json.get("returncode", 0) or 0) != 0:
        err = str(api_json.get("error", "") or "").strip()
        msg = "API analysis returned incomplete data"
        if err:
            msg += f": {err}"
        return 0, [ScoreEvidence("static", "api_analysis_incomplete", 0, msg)]

    chains = api_json.get("chain_findings", [])
    if not isinstance(chains, list):
        chains = []

    if not chains:
        return 0, []

    high = [x for x in chains if isinstance(x, dict) and str(x.get("severity", "")).lower() == "high"]
    medium = [x for x in chains if isinstance(x, dict) and str(x.get("severity", "")).lower() == "medium"]
    low = [x for x in chains if isinstance(x, dict) and str(x.get("severity", "")).lower() == "low"]

    add = 0
    if high:
        add += min(12, 6 * len(high))
    if medium:
        add += min(6, 2 * len(medium))
    if low:
        add += min(2, len(low))

    if looks_like_installer:
        add = max(0, add - 2)

    counts = f"high={len(high)}, medium={len(medium)}, low={len(low)}"

    if add > 0:
        return add, [
            ScoreEvidence(
                "static",
                "api_behavior_chains",
                add,
                f"API behavior chains detected ({counts})",
            )
        ]

    return 0, [
        ScoreEvidence(
            "static",
            "api_behavior_chains",
            0,
            f"API behavior chains detected ({counts}); no net score after dampening",
        )
    ]


def _score_yara_evidence(yara_results: dict[str, Any]) -> tuple[int, list[ScoreEvidence], dict[str, Any]]:
    if not isinstance(yara_results, dict) or not yara_results:
        return 0, [], {}

    evidence: list[ScoreEvidence] = []
    flags: dict[str, Any] = {}

    matched = bool(yara_results.get("matched", False))
    match_count = int(yara_results.get("match_count", 0) or 0)
    rule_file_count = int(yara_results.get("rule_file_count", 0) or 0)
    matches = yara_results.get("matches", []) if isinstance(yara_results.get("matches"), list) else []

    flags["yara_present"] = bool(yara_results)
    flags["yara_matched"] = matched
    flags["yara_match_count"] = match_count
    flags["yara_rule_file_count"] = rule_file_count

    if yara_results.get("error"):
        flags["yara_error"] = str(yara_results.get("error"))
        return 0, [ScoreEvidence("static", "yara_incomplete", 0, f"YARA scan incomplete: {yara_results.get('error')}")], flags

    if not matched or match_count == 0:
        return 0, [], flags

    rule_names: list[str] = []
    high_signal = 0
    medium_signal = 0
    low_signal = 0

    for match in matches:
        if not isinstance(match, dict):
            continue

        rule = str(match.get("rule", "") or "").strip()
        meta = match.get("meta", {}) if isinstance(match.get("meta"), dict) else {}
        tags = [str(x).lower() for x in (match.get("tags", []) or []) if isinstance(x, (str, int, float))]

        if rule:
            rule_names.append(rule)

        severity = str(meta.get("severity", "") or "").strip().lower()
        text = " ".join([rule.lower(), severity] + tags)

        if severity in {"critical", "high"} or any(x in text for x in ["malware", "loader", "trojan", "ransom", "backdoor", "stealer", "rat"]):
            high_signal += 1
        elif severity in {"medium", "suspicious"} or any(x in text for x in ["suspicious", "powershell", "script", "persistence", "inject", "shellcode"]):
            medium_signal += 1
        elif any(x in text for x in ["packer", "packed", "obfusc", "upx"]):
            low_signal += 1
        else:
            low_signal += 1

    add = 0
    if high_signal:
        add += min(10, 5 * high_signal)
    if medium_signal:
        add += min(5, 2 * medium_signal)
    if low_signal:
        add += min(2, low_signal)

    add = min(12, add)

    if add > 0:
        top_rules = ", ".join(rule_names[:5]) if rule_names else f"{match_count} rule(s)"
        evidence.append(
            ScoreEvidence(
                "static",
                "yara_matches",
                add,
                f"YARA matched {match_count} rule(s): {top_rules}",
            )
        )

    return add, evidence, flags


def score_dynamic(dynamic_result: dict[str, Any] | None) -> tuple[int, list[ScoreEvidence], dict[str, Any]]:
    dynamic_result = dynamic_result or {}
    evidence: list[ScoreEvidence] = []
    flags: dict[str, Any] = {}
    score = 0

    findings = dynamic_result.get("findings", {}) if isinstance(dynamic_result.get("findings"), dict) else {}
    counts = findings.get("counts", {}) if isinstance(findings.get("counts"), dict) else {}

    if not counts and isinstance(dynamic_result.get("counts"), dict):
        counts = dynamic_result.get("counts", {})

    task_summary = (
        dynamic_result.get("task_diff_summary", {})
        if isinstance(dynamic_result.get("task_diff_summary"), dict)
        else {}
    )
    service_summary = (
        dynamic_result.get("service_diff_summary", {})
        if isinstance(dynamic_result.get("service_diff_summary"), dict)
        else {}
    )

    spawned = _safe_count(
        findings.get("spawned_process_count")
        or findings.get("spawned_processes")
        or counts.get("process_creates")
        or dynamic_result.get("spawned_processes")
        or dynamic_result.get("child_processes")
        or dynamic_result.get("process_tree")
    )

    file_writes = _safe_count(
        findings.get("file_write_count")
        or findings.get("file_writes")
        or counts.get("file_write_events")
        or dynamic_result.get("file_writes")
    )

    net_events = _safe_count(
        findings.get("network_event_count")
        or findings.get("network_events")
        or counts.get("network_events")
        or dynamic_result.get("network_events")
    )

    suspicious_paths = _safe_count(
        findings.get("suspicious_path_hit_count")
        or findings.get("suspicious_path_hits")
        or counts.get("suspicious_path_hits")
        or dynamic_result.get("suspicious_path_hits")
    )

    persistence_hits = _safe_count(
        findings.get("persistence_hit_count")
        or findings.get("persistence_hits")
        or counts.get("persistence_hits")
        or dynamic_result.get("persistence_hits")
    )

    suspicious_tasks = _safe_count(task_summary.get("suspicious_new_or_modified"))
    suspicious_services = _safe_count(service_summary.get("suspicious_new_or_modified"))

    highlights = (
        findings.get("highlights")
        if isinstance(findings.get("highlights"), list)
        else dynamic_result.get("highlights", [])
        if isinstance(dynamic_result.get("highlights"), list)
        else []
    )

    high_signal_highlights = [
        str(h) for h in highlights
        if isinstance(h, str)
        and any(term in str(h).lower() for term in (
            "persistence", "scheduled task", "service", "autorun", "run key",
            "temp", "startup", "appdata", "powershell", "cmd.exe", "wscript",
            "mshta", "rundll32", "regsvr32", "encoded", "download", "inject",
            "credential", "lsass", "beacon", "c2", "unsigned"
        ))
    ]

    if persistence_hits > 0:
        add = min(12, 6 + 3 * persistence_hits)
        score += add
        evidence.append(ScoreEvidence("dynamic", "persistence_hits", add, f"Persistence-related hits observed: {persistence_hits}"))

    if suspicious_tasks > 0:
        add = min(12, 6 + 2 * suspicious_tasks)
        score += add
        evidence.append(ScoreEvidence("dynamic", "task_persistence", add, f"Suspicious scheduled tasks: {suspicious_tasks}"))

    if suspicious_services > 0:
        add = min(12, 6 + 2 * suspicious_services)
        score += add
        evidence.append(ScoreEvidence("dynamic", "service_persistence", add, f"Suspicious service changes: {suspicious_services}"))

    if suspicious_paths > 0:
        add = min(8, 3 + suspicious_paths)
        score += add
        evidence.append(ScoreEvidence("dynamic", "suspicious_paths", add, f"Suspicious path hits observed: {suspicious_paths}"))

    if spawned >= 6:
        add = min(4, 1 + max(0, (spawned - 6) // 4))
        score += add
        evidence.append(ScoreEvidence("dynamic", "spawned_processes", add, f"Spawned processes observed: {spawned}"))

    if file_writes >= 10:
        add = min(3, 1 + file_writes // 100)
        score += add
        evidence.append(ScoreEvidence("dynamic", "file_writes", add, f"File writes observed: {file_writes}"))

    if net_events >= 100:
        add = 1
        if net_events >= 250:
            add = 2
        if net_events >= 500:
            add = 3
        score += add
        evidence.append(ScoreEvidence("dynamic", "network_events", add, f"Network activity observed: {net_events}"))

    if high_signal_highlights:
        add = min(4, len(high_signal_highlights))
        score += add
        evidence.append(ScoreEvidence("dynamic", "runtime_highlights", add, f"High-signal runtime highlights recorded: {len(high_signal_highlights)}"))

    flags.update({
        "spawned_processes": spawned,
        "file_writes": file_writes,
        "network_events": net_events,
        "suspicious_paths": suspicious_paths,
        "persistence_hits": persistence_hits,
        "suspicious_tasks": suspicious_tasks,
        "suspicious_services": suspicious_services,
        "high_signal_highlights": len(high_signal_highlights),
        "highlight_count": len(highlights),
    })

    return max(0, min(30, score)), evidence, flags


def score_spec(spec_result: dict[str, Any] | None) -> tuple[int, list[ScoreEvidence], dict[str, Any]]:
    spec_result = spec_result or {}
    evidence: list[ScoreEvidence] = []
    flags: dict[str, Any] = {}
    score = 0

    summary = spec_result.get("summary", {}) if isinstance(spec_result.get("summary"), dict) else {}
    endpoints = spec_result.get("endpoints", []) if isinstance(spec_result.get("endpoints"), list) else []
    risk_notes = spec_result.get("risk_notes", []) if isinstance(spec_result.get("risk_notes"), list) else []
    servers = spec_result.get("servers", []) if isinstance(spec_result.get("servers"), list) else []
    auth_summary = spec_result.get("auth_summary", []) if isinstance(spec_result.get("auth_summary"), list) else []
    security_schemes = spec_result.get("security_schemes", []) if isinstance(spec_result.get("security_schemes"), list) else []

    endpoint_count = int(summary.get("endpoint_count", 0) or spec_result.get("endpoint_count", 0) or 0)
    auth_scheme_count = int(summary.get("auth_scheme_count", 0) or spec_result.get("auth_scheme_count", 0) or 0)
    admin_like_route_count = int(summary.get("admin_like_route_count", 0) or spec_result.get("admin_like_route_count", 0) or 0)
    sensitive_param_count = int(summary.get("sensitive_param_count", 0) or spec_result.get("sensitive_param_count", 0) or 0)

    no_auth = (
        bool(spec_result.get("no_auth_detected"))
        or auth_scheme_count == 0
        or (not auth_summary and not security_schemes)
    )

    destructive_admin = sum(
        1 for ep in endpoints
        if isinstance(ep, dict) and ep.get("admin_like_route") and ep.get("destructive_method")
    )

    file_uploads = sum(
        1 for ep in endpoints
        if isinstance(ep, dict)
        and any(
            isinstance(p, dict) and str(p.get("in", "")).lower() == "body:multipart/form-data"
            for p in (ep.get("parameters") or [])
        )
    )

    http_server = (
        bool(spec_result.get("http_server_detected"))
        or any(str(s).lower().startswith("http://") for s in servers)
    )

    sensitive_unauth = sum(
        1 for ep in endpoints
        if isinstance(ep, dict)
        and ep.get("admin_like_route")
        and auth_scheme_count == 0
    )

    if no_auth:
        score += 10
        evidence.append(ScoreEvidence("spec", "no_auth", 10, "No obvious authentication scheme detected in the API spec"))

    if sensitive_unauth > 0:
        add = min(8, 4 + 2 * sensitive_unauth)
        score += add
        evidence.append(ScoreEvidence("spec", "sensitive_unauth", add, f"Sensitive unauthenticated endpoints: {sensitive_unauth}"))

    if destructive_admin > 0:
        add = min(6, 3 + 2 * destructive_admin)
        score += add
        evidence.append(ScoreEvidence("spec", "destructive_admin", add, f"Admin-like destructive routes: {destructive_admin}"))

    if http_server:
        score += 6
        evidence.append(ScoreEvidence("spec", "http_server", 6, "Non-TLS server URL detected in spec"))

    if file_uploads > 0:
        add = min(4, 2 + file_uploads)
        score += add
        evidence.append(ScoreEvidence("spec", "file_uploads", add, f"File upload endpoints detected: {file_uploads}"))

    flags.update({
        "endpoint_count": endpoint_count,
        "auth_scheme_count": auth_scheme_count,
        "admin_like_route_count": admin_like_route_count,
        "sensitive_param_count": sensitive_param_count,
    })

    return max(0, min(30, score)), evidence, flags


def calculate_combined_score(
    static_result: dict[str, Any] | None = None,
    dynamic_result: dict[str, Any] | None = None,
    spec_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evidence: list[ScoreEvidence] = []
    raw_flags: dict[str, Any] = {}

    present = {
        "static": bool(static_result),
        "dynamic": bool(dynamic_result),
        "spec": bool(spec_result),
    }

    static_score = 0
    if static_result:
        static_score, static_ev, static_flags = score_static(
            static_result.get("summary"),
            static_result.get("iocs"),
            static_result.get("pe_meta"),
            static_result.get("lief_meta"),
            static_result.get("api_analysis"),
        )
        evidence.extend(static_ev)
        raw_flags["static"] = static_flags
    else:
        raw_flags["static"] = {}

    dynamic_score = 0
    if dynamic_result:
        dynamic_score, dynamic_ev, dynamic_flags = score_dynamic(dynamic_result)
        evidence.extend(dynamic_ev)
        raw_flags["dynamic"] = dynamic_flags
    else:
        raw_flags["dynamic"] = {}

    spec_score = 0
    if spec_result:
        spec_score, spec_ev, spec_flags = score_spec(spec_result)
        evidence.extend(spec_ev)
        raw_flags["spec"] = spec_flags
    else:
        raw_flags["spec"] = {}

    total = max(0, min(100, static_score + dynamic_score + spec_score))
    summary_for_verdict = static_result.get("summary", {}) if isinstance(static_result, dict) else {}
    verdict, confidence = classify_verdict(total, summary_for_verdict)
    severity = severity_from_score(total)

    combined = CombinedScore(
        total_score=total,
        severity=severity,
        verdict=verdict,
        confidence=confidence,
        subscores={"static": static_score, "dynamic": dynamic_score, "spec": spec_score},
        present=present,
        evidence=evidence,
        raw_flags=raw_flags,
    )
    return asdict(combined)


def combined_score_from_case_dir(
    case_dir: str | Path,
    dynamic_result: dict[str, Any] | None = None,
    spec_result: dict[str, Any] | None = None,
    write_output: bool = True,
) -> dict[str, Any]:
    case_dir = Path(case_dir)

    static_result = {
        "summary": _safe_load_json(case_dir / "summary.json"),
        "iocs": _safe_load_json(case_dir / "iocs.json"),
        "pe_meta": _safe_load_json(case_dir / "pe_metadata.json"),
        "lief_meta": _safe_load_json(case_dir / "lief_metadata.json"),
        "api_analysis": _safe_load_json(case_dir / "api_analysis.json"),
    }

    if not any(static_result.values()):
        static_result = None

    if dynamic_result is None:
        dynamic_result = (
            _safe_load_json(case_dir / "dynamic_findings.json")
            or _safe_load_json(case_dir / "reports" / "dynamic_findings.json")
        )

    if spec_result is None:
        spec_result = (
            _safe_load_json(case_dir / "spec" / "api_spec_analysis.json")
            or _safe_load_json(case_dir / "api_spec_analysis.json")
        )

    combined = calculate_combined_score(
        static_result=static_result,
        dynamic_result=dynamic_result,
        spec_result=spec_result,
    )

    if write_output:
        (case_dir / "combined_score.json").write_text(
            json.dumps(combined, indent=2),
            encoding="utf-8",
            errors="replace",
        )

    return combined


def score_risk(
    summary: dict[str, Any],
    iocs: dict[str, Any],
    pe_meta: dict[str, Any],
    lief_meta: dict[str, Any],
) -> Tuple[int, list[str], list[str]]:
    static_score, evidence, _ = score_static(summary, iocs, pe_meta, lief_meta, None)
    suspicious = [e.message for e in evidence if e.points > 0]
    benign = [e.message for e in evidence if e.points <= 0]
    if static_score < 40:
        benign.append("Low overall heuristic score")
    elif static_score < 75:
        benign.append("Moderate overall heuristic score")
    else:
        suspicious.append("High overall heuristic score")
    return static_score, suspicious, benign


def _extract_techniques(summary: dict[str, Any]) -> list[str]:
    case_dir = _get_case_dir(summary)
    capa_json_path = case_dir / "capa.json"
    capa_blob = capa_json_path.read_text(encoding="utf-8", errors="replace") if capa_json_path.exists() else ""
    return sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", capa_blob)))


def _load_api_analysis(case_dir: Path) -> dict[str, Any]:
    p = case_dir / "api_analysis.json"
    return _safe_load_json(p) or {}


def _prefix_in(t: str, prefixes: set[str]) -> bool:
    return any(t == p or t.startswith(p + ".") for p in prefixes)


def _looks_like_installer(company: str, product: str, desc: str, summary: dict[str, Any], case_dir: Path) -> bool:
    words = " ".join(
        [
            company or "",
            product or "",
            desc or "",
            str((summary.get("sample", {}) or {}).get("filename", "") or ""),
            str((summary.get("sample", {}) or {}).get("name", "") or ""),
        ]
    ).lower()

    installer_keywords = ("installer", "setup", "update", "updater", "launcher", "bootstrap")
    if any(x in words for x in installer_keywords):
        return True

    file_line = ""
    fp = case_dir / "file.txt"
    if fp.exists():
        try:
            lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
            file_line = lines[0].lower() if lines else ""
        except Exception:
            file_line = ""

    return any(x in file_line for x in ("installer", "setup", "installshield", "launcher", "bootstrap"))


def _get_case_dir(summary: dict[str, Any]) -> Path:
    sample = summary.get("sample", {}) if isinstance(summary.get("sample", {}), dict) else {}
    path_case = sample.get("path_case")
    if isinstance(path_case, str) and path_case:
        return Path(path_case).parent
    return Path(".")


def _is_subfile_case(case_dir: Path) -> bool:
    return "subfiles" in {p.lower() for p in case_dir.parts}


def _get_parent_case_dir_from_subfile(case_dir: Path) -> Path | None:
    parts = list(case_dir.parts)
    lowered = [p.lower() for p in parts]
    if "subfiles" not in lowered:
        return None
    idx = lowered.index("subfiles")
    if idx == 0:
        return None
    return Path(*parts[:idx])


def _load_signing(case_dir: Path) -> dict[str, Any]:
    p = case_dir / "signing.json"
    data = _safe_load_json(p) or {}

    if not data and (case_dir / "summary.json").exists():
        s = _safe_load_json(case_dir / "summary.json") or {}
        embedded = s.get("signing")
        if isinstance(embedded, dict):
            data = embedded

    out: dict[str, Any] = {}
    out["verify_ok"] = bool(data.get("verify_ok") or data.get("verified") or data.get("ok"))
    out["timestamp_verified"] = bool(data.get("timestamp_verified") or data.get("ts_verified"))
    out["subject"] = data.get("subject") or data.get("signer_subject") or ""
    return out


def _extract_observables(iocs: dict[str, Any]) -> dict[str, list[str]]:
    obs = iocs.get("observables", {}) if isinstance(iocs.get("observables", {}), dict) else {}
    domains = obs.get("domains") if isinstance(obs.get("domains"), list) else []
    urls = obs.get("urls") if isinstance(obs.get("urls"), list) else []
    ips = obs.get("ips") if isinstance(obs.get("ips"), list) else []
    return {
        "domains": [str(x) for x in domains if isinstance(x, (str, int, float))],
        "urls": [str(x) for x in urls if isinstance(x, (str, int, float))],
        "ips": [str(x) for x in ips if isinstance(x, (str, int, float))],
    }


def _has_only_known_benign_infra(observables: dict[str, list[str]]) -> bool:
    domains = [d.lower().strip(".") for d in observables.get("domains", [])]
    urls = [u for u in observables.get("urls", [])]
    if not domains and not urls:
        return False

    def is_benign_domain(d: str) -> bool:
        return any(d == sfx or d.endswith("." + sfx) for sfx in KNOWN_BENIGN_DOMAIN_SUFFIXES)

    dom_ok = all(is_benign_domain(d) for d in domains) if domains else True

    url_hosts = []
    for u in urls:
        host = _safe_url_host(u)
        if host:
            url_hosts.append(host.lower().strip("."))

    url_ok = all(is_benign_domain(h) for h in url_hosts) if url_hosts else True
    return dom_ok and url_ok


def _safe_url_host(u: str) -> str | None:
    try:
        parsed = urlparse(u.strip())
        if parsed.scheme not in {"http", "https"}:
            return None
        if not parsed.netloc:
            return None
        host = parsed.netloc.split("@")[-1].split(":")[0]
        return host if host else None
    except Exception:
        return None


def _filter_domains(domains: list[str]) -> list[str]:
    out: list[str] = []
    for d in domains:
        dd = d.strip().lower().strip(".")
        if not dd:
            continue
        if any(dd == sfx or dd.endswith("." + sfx) for sfx in KNOWN_BENIGN_DOMAIN_SUFFIXES):
            continue
        out.append(dd)
    return sorted(set(out))


def _filter_urls(urls: list[str]) -> list[str]:
    out: list[str] = []
    for u in urls:
        host = _safe_url_host(u)
        if not host:
            continue
        h = host.lower().strip(".")
        if any(h == sfx or h.endswith("." + sfx) for sfx in KNOWN_BENIGN_DOMAIN_SUFFIXES):
            continue
        out.append(u.strip())
    return sorted(set(out))


def _filter_ips(ips: list[str]) -> list[str]:
    out: list[str] = []
    for s in ips:
        ss = s.strip()
        if not ss:
            continue
        if ss in KNOWN_BENIGN_IPS:
            continue
        try:
            ip = ipaddress.ip_address(ss)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            continue
        out.append(str(ip))
    return sorted(set(out))


def _pe_string_table(pe_meta: dict[str, Any]) -> dict[str, str]:
    blob = json.dumps(pe_meta, ensure_ascii=False) if pe_meta else ""
    out: dict[str, str] = {}

    for key in [
        "CompanyName",
        "ProductName",
        "FileVersion",
        "ProductVersion",
        "OriginalFilename",
        "InternalName",
        "FileDescription",
    ]:
        m = re.search(rf'"{key}"\s*:\s*"([^"]+)"', blob)
        if m:
            out[key] = m.group(1)

    for k in ["version_strings", "version_info_strings", "strings"]:
        if isinstance(pe_meta, dict) and isinstance(pe_meta.get(k), dict):
            for kk, vv in pe_meta[k].items():
                if isinstance(vv, str):
                    out.setdefault(kk, vv)

    return out