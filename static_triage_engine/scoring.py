from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any, Tuple
from urllib.parse import urlparse


def classify_verdict(score: int, summary: dict[str, Any] | None = None) -> tuple[str, str]:
    vt = summary.get("virustotal", {}) if isinstance(summary, dict) and isinstance(summary.get("virustotal"), dict) else {}
    vt_found = bool(vt.get("found", False))
    vt_mal = int(vt.get("malicious", 0) or 0)
    vt_susp = int(vt.get("suspicious", 0) or 0)
    vt_harmless = int(vt.get("harmless", 0) or 0)
    vt_undetected = int(vt.get("undetected", 0) or 0)

    verdict = "BENIGN"
    confidence = "Low confidence"

    if score >= 90:
        verdict = "MALICIOUS"
        confidence = "High confidence"
    elif score >= 75:
        verdict = "SUSPICIOUS"
        confidence = "Moderate confidence"
    elif score >= 40:
        verdict = "LOW_RISK"
        confidence = "Low confidence"

    if vt_found:
        strong_vt_malicious = vt_mal >= 15 or (vt_mal >= 8 and score >= 55)
        medium_vt_suspicious = vt_mal >= 5 or vt_susp >= 10 or (vt_mal + vt_susp) >= 8
        clean_vt_signal = vt_mal == 0 and vt_susp == 0 and (vt_harmless >= 1 or vt_undetected >= 10)

        if strong_vt_malicious:
            verdict = "MALICIOUS"
            confidence = "High confidence" if (vt_mal >= 15 or score >= 90) else "Moderate confidence"
        elif medium_vt_suspicious and verdict != "MALICIOUS":
            if score >= 75:
                verdict = "SUSPICIOUS"
            elif score >= 40:
                verdict = "LOW_RISK"
            else:
                verdict = "SUSPICIOUS"
            confidence = "High confidence" if (vt_mal >= 5 or vt_susp >= 10 or score >= 75) else "Moderate confidence"
        elif clean_vt_signal:
            if score < 40:
                verdict = "BENIGN"
                confidence = "Moderate confidence" if (vt_harmless >= 3 or vt_undetected >= 20) else "Low confidence"
            elif score < 75:
                verdict = "LOW_RISK"
                confidence = "Low confidence"

    return verdict, confidence


HIGH_SIGNAL_TECH_PREFIXES = {
    "T1055",
    "T1059",
    "T1105",
    "T1547",
    "T1543",
    "T1569",
    "T1021",
    "T1071",
    "T1041",
    "T1003",
    "T1110",
    "T1552",
    "T1218",
    "T1574",
    "T1036",
    "T1566",
}

LOW_SIGNAL_TECH_PREFIXES = {
    "T1027",
    "T1033",
    "T1082",
    "T1083",
    "T1087",
    "T1129",
    "T1497",
    "T1564.003",
}

TRUST_OVERRIDE_TECH_PREFIXES = {
    "T1055",
    "T1003",
    "T1105",
    "T1071",
    "T1041",
    "T1218",
    "T1574",
}

KNOWN_BENIGN_DOMAIN_SUFFIXES = {
    "digicert.com",
    "ocsp.digicert.com",
    "crl3.digicert.com",
    "crl4.digicert.com",
    "cacerts.digicert.com",
}

KNOWN_BENIGN_IPS = {
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "9.9.9.9",
}


def score_risk(
    summary: dict[str, Any],
    iocs: dict[str, Any],
    pe_meta: dict[str, Any],
    lief_meta: dict[str, Any],
) -> Tuple[int, list[str], list[str]]:
    suspicious: list[str] = []
    benign: list[str] = []
    score = 0

    case_dir = _get_case_dir(summary)

    capa_json_path = case_dir / "capa.json"
    capa_blob = capa_json_path.read_text(encoding="utf-8", errors="replace") if capa_json_path.exists() else ""
    techs = sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", capa_blob)))
    match_count = capa_blob.count('"matches"')

    file_info = _pe_string_table(pe_meta)
    company = (file_info.get("CompanyName") or "").strip()
    product = (file_info.get("ProductName") or "").strip()
    desc = (file_info.get("FileDescription") or "").strip()
    original_filename = (file_info.get("OriginalFilename") or "").strip()

    looks_like_installer = _looks_like_installer(company, product, desc, summary, case_dir)

    is_subfile = _is_subfile_case(case_dir)
    parent_case_dir = _get_parent_case_dir_from_subfile(case_dir) if is_subfile else None
    parent_summary = _safe_load_json(parent_case_dir / "summary.json") if parent_case_dir else None
    parent_verdict = (parent_summary or {}).get("verdict") if isinstance(parent_summary, dict) else None
    parent_is_low = parent_verdict in {"BENIGN", "LOW_RISK"}

    signing = _load_signing(case_dir)
    verify_ok = bool(signing.get("verify_ok"))
    timestamp_verified = bool(signing.get("timestamp_verified"))
    signer_subject = (signing.get("subject") or "").strip()
    has_signer_subject = bool(signer_subject)

    is_trusted_signed = verify_ok and timestamp_verified
    is_partially_trusted_signed = (timestamp_verified and has_signer_subject) or verify_ok

    vt = summary.get("virustotal", {}) if isinstance(summary.get("virustotal"), dict) else {}
    vt_found = bool(vt.get("found", False))
    vt_enabled = bool(vt.get("enabled", False))
    vt_malicious = int(vt.get("malicious", 0) or 0)
    vt_suspicious = int(vt.get("suspicious", 0) or 0)
    vt_harmless = int(vt.get("harmless", 0) or 0)
    vt_undetected = int(vt.get("undetected", 0) or 0)
    clean_vt = vt_found and vt_malicious == 0 and vt_suspicious == 0 and (vt_harmless > 0 or vt_undetected > 0)

    api_json = _load_api_analysis(case_dir)

    sample_info = summary.get("sample", {}) if isinstance(summary.get("sample"), dict) else {}
    sample_name = str(
        sample_info.get("filename")
        or sample_info.get("name")
        or sample_info.get("path")
        or sample_info.get("path_case")
        or ""
    ).strip()
    lower_name = sample_name.lower()

    hashy_name = bool(re.fullmatch(r"[0-9a-f]{24,}\.(exe|dll|scr|com|bat|ps1)?", lower_name))
    suspicious_ext = lower_name.endswith((".scr", ".com", ".js", ".jse", ".vbs", ".ps1", ".hta"))

    high = [t for t in techs if _prefix_in(t, HIGH_SIGNAL_TECH_PREFIXES)]
    low = [t for t in techs if _prefix_in(t, LOW_SIGNAL_TECH_PREFIXES)]
    other = [t for t in techs if t not in set(high) and t not in set(low)]
    trust_override = any(_prefix_in(t, TRUST_OVERRIDE_TECH_PREFIXES) for t in techs)

    if is_trusted_signed:
        benign.append(
            f"Valid Authenticode signature with verified timestamp"
            f"{f' (Subject={signer_subject})' if signer_subject else ''}"
        )
    elif is_partially_trusted_signed:
        score += 4
        suspicious.append("File has partial signing trust (signer/timestamp present but full verification not confirmed) (+4)")
    else:
        score += 12
        suspicious.append("File is unsigned or signature/timestamp verification failed (+12)")

    meta_penalty_scale = 0.5 if looks_like_installer else 1.0

    if not company:
        add = max(1, int(5 * meta_penalty_scale))
        score += add
        suspicious.append(f"Missing CompanyName in version info (+{add})")
    else:
        benign.append(f"CompanyName present: {company}")

    if not product:
        add = max(1, int(4 * meta_penalty_scale))
        score += add
        suspicious.append(f"Missing ProductName in version info (+{add})")
    else:
        benign.append(f"ProductName present: {product}")

    if not desc:
        add = max(1, int(3 * meta_penalty_scale))
        score += add
        suspicious.append(f"Missing FileDescription in version info (+{add})")

    if not original_filename:
        add = max(1, int(3 * meta_penalty_scale))
        score += add
        suspicious.append(f"Missing OriginalFilename in version info (+{add})")

    if hashy_name:
        score += 8
        suspicious.append("Filename resembles a hash/random artifact name (+8)")

    if suspicious_ext:
        score += 12
        suspicious.append(f"Suspicious executable/script extension observed: {sample_name} (+12)")

    if techs:
        if high:
            add = min(50, 22 + 8 * len(high))
            score += add
            suspicious.append(
                f"High-signal ATT&CK techniques present (count={len(high)}): {', '.join(high[:10])} (+{add})"
            )
        else:
            add = 8 if not looks_like_installer else 3
            score += add
            suspicious.append(f"Only low/medium-signal ATT&CK techniques detected (count={len(techs)}) (+{add})")

        if looks_like_installer and low and not high:
            benign.append(f"Installer/launcher context detected; down-weighting common techniques: {', '.join(low[:8])}")

        if other:
            if looks_like_installer and not high and not trust_override:
                add = min(8, 2 + len(other))
            else:
                add = min(20, 4 + 2 * len(other))
            score += add
            suspicious.append(f"Additional ATT&CK techniques detected (count={len(other)}) (+{add})")
    else:
        benign.append("No ATT&CK technique IDs detected in capa output")

    if match_count > 0:
        if looks_like_installer and not high:
            density = min(5, 1 + int(match_count / 35))
        elif is_trusted_signed and not trust_override and not high:
            density = min(8, 2 + int(match_count / 25))
        else:
            density = min(24, 6 + int(match_count / 8))
        score += density
        suspicious.append(f"capa match density (match_count≈{match_count}) (+{density})")
    else:
        benign.append("No capa matches detected")

    score += _score_api_findings(
        api_json=api_json,
        looks_like_installer=looks_like_installer,
        is_trusted_signed=is_trusted_signed,
        is_partially_trusted_signed=is_partially_trusted_signed,
        clean_vt=clean_vt,
        trust_override=trust_override,
        suspicious=suspicious,
        benign=benign,
    )

    observables = _extract_observables(iocs)
    filtered_ips = _filter_ips(observables.get("ips", []))
    filtered_domains = _filter_domains(observables.get("domains", []))
    filtered_urls = _filter_urls(observables.get("urls", []))

    only_benign_infra = (
        (len(filtered_domains) == 0 and len(filtered_urls) == 0 and len(filtered_ips) == 0)
        and _has_only_known_benign_infra(observables)
    )

    if only_benign_infra:
        benign.append("Only known-benign certificate/OCSP/CRL infrastructure observed; no IOC risk added")
    else:
        ip_count = len(filtered_ips)
        dom_count = len(filtered_domains)
        url_count = len(filtered_urls)

        if ip_count > 0:
            if clean_vt and ip_count <= 1 and not trust_override:
                add = min(6, 2 + ip_count)
            else:
                add = min(22, 10 + 3 * ip_count)
            score += add
            suspicious.append(f"Network IP IOCs present (filtered_ips={ip_count}) (+{add})")
        else:
            benign.append("No high-confidence network IP IOCs extracted after filtering")

        if dom_count + url_count > 0:
            if clean_vt and (dom_count + url_count) <= 6 and not trust_override:
                add = min(4, 1 + dom_count)
            else:
                add = min(16, 3 + (2 * dom_count) + min(5, url_count))
            score += add
            suspicious.append(f"Domains/URLs present (filtered_domains={dom_count}, filtered_urls={url_count}) (+{add})")
        elif ip_count == 0:
            benign.append("No high-confidence network domains/URLs extracted after filtering")

    if vt_enabled:
        if vt_found:
            if vt_malicious >= 10:
                add = min(28, 14 + vt_malicious)
                score += add
                suspicious.append(f"VirusTotal malicious detections present (malicious={vt_malicious}) (+{add})")
            elif vt_malicious >= 3:
                add = min(18, 8 + vt_malicious)
                score += add
                suspicious.append(f"VirusTotal elevated detections present (malicious={vt_malicious}) (+{add})")
            elif vt_suspicious >= 5:
                add = min(12, 4 + vt_suspicious)
                score += add
                suspicious.append(f"VirusTotal suspicious detections present (suspicious={vt_suspicious}) (+{add})")
            elif clean_vt:
                benign.append(
                    f"VirusTotal shows no malicious/suspicious detections "
                    f"(harmless={vt_harmless}, undetected={vt_undetected})"
                )
        else:
            benign.append("VirusTotal lookup did not return a matching record")

    lief_blob = json.dumps(lief_meta, ensure_ascii=False) if lief_meta else ""
    if re.search(r"\bUPX\b", lief_blob, re.I) or re.search(r"\bpacked\b", lief_blob, re.I):
        score += 10
        suspicious.append("Packer/compression indicators present (+10)")

    if clean_vt and not high and not trust_override:
        before = score
        discount_factor = 0.75
        if looks_like_installer:
            discount_factor = 0.65
        if is_trusted_signed:
            discount_factor = min(discount_factor, 0.55)
        elif is_partially_trusted_signed:
            discount_factor = min(discount_factor, 0.70)

        score = max(0, int(score * discount_factor))
        benign.append(f"VirusTotal found sample with no malicious/suspicious detections; applying clean-VT discount: {before} -> {score}")

    if is_trusted_signed and not trust_override:
        before = score
        score = int(score * 0.75) if high else int(score * 0.55)
        benign.append(
            f"Valid Authenticode signature (timestamp verified) detected"
            f"{f' (Subject={signer_subject})' if signer_subject else ''}; applying trust discount: {before} -> {score}"
        )

    if looks_like_installer and not trust_override and not high:
        cap = 59 if clean_vt else 69
        if score > cap:
            benign.append(f"Installer/launcher context and no trust-override behavior; capping score at {cap}")
            score = cap

    if is_subfile and parent_is_low and not trust_override:
        cap = 60
        if score > cap:
            benign.append(f"Parent verdict {parent_verdict} and no high-signal override; capping subfile score at {cap}")
            score = cap

    score = max(0, min(100, score))
    if score < 40:
        benign.append("Low overall heuristic score")
    elif score < 75:
        benign.append("Moderate overall heuristic score")
    else:
        suspicious.append("High overall heuristic score")

    return score, suspicious, benign


def _load_api_analysis(case_dir: Path) -> dict[str, Any]:
    p = case_dir / "api_analysis.json"
    return _safe_load_json(p) or {}


def _score_api_findings(
    api_json: dict[str, Any],
    looks_like_installer: bool,
    is_trusted_signed: bool,
    is_partially_trusted_signed: bool,
    clean_vt: bool,
    trust_override: bool,
    suspicious: list[str],
    benign: list[str],
) -> int:
    if not isinstance(api_json, dict) or not api_json:
        benign.append("No API analysis artifact present")
        return 0

    if int(api_json.get("returncode", 0) or 0) != 0:
        err = str(api_json.get("error", "") or "")
        suspicious.append(f"API analysis failed or returned incomplete data ({err or 'unknown error'}) (+0)")
        return 0

    chains = api_json.get("chain_findings", [])
    if not isinstance(chains, list):
        chains = []

    high = [x for x in chains if isinstance(x, dict) and x.get("severity") == "high"]
    medium = [x for x in chains if isinstance(x, dict) and x.get("severity") == "medium"]
    low = [x for x in chains if isinstance(x, dict) and x.get("severity") == "low"]

    if not chains:
        benign.append("No API behavior chains detected")
        return 0

    raw_add = 0
    if high:
        raw_add += min(12, 6 * len(high))
    if medium:
        raw_add += min(6, 2 * len(medium))
    if low:
        raw_add += min(2, len(low))

    net_add = raw_add
    dampening_reasons: list[str] = []

    if net_add > 0 and looks_like_installer and clean_vt and not trust_override:
        net_add = max(0, net_add - 2)
        dampening_reasons.append("installer/clean-VT context")

    if net_add > 0 and is_trusted_signed and clean_vt and not trust_override:
        net_add = max(0, net_add - 2)
        dampening_reasons.append("trusted signature + clean VT")
    elif net_add > 0 and is_partially_trusted_signed and clean_vt and not trust_override:
        net_add = max(0, net_add - 1)
        dampening_reasons.append("partial signing trust + clean VT")

    counts = f"high={len(high)}, medium={len(medium)}, low={len(low)}"

    if net_add > 0:
        suspicious.append(f"API behavior chains detected ({counts}); net contribution (+{net_add})")
    else:
        benign.append(f"API behavior chains detected ({counts}); net contribution (+0) after benign-context dampening")

    if dampening_reasons:
        benign.append(f"API-chain dampening applied: {', '.join(dampening_reasons)}")

    return net_add


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


def _safe_load_json(p: Path) -> dict[str, Any] | None:
    try:
        if p.exists():
            x = json.loads(p.read_text(encoding="utf-8", errors="replace"))
            return x if isinstance(x, dict) else None
    except Exception:
        return None
    return None


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
