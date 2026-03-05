from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any, Tuple
from urllib.parse import urlparse


def classify_verdict(score: int) -> tuple[str, str]:
    if score >= 75:
        return ("MALICIOUS", "High confidence")
    if score >= 30:
        return ("SUSPICIOUS", "Moderate confidence")
    return ("BENIGN", "Low confidence")


# High-signal techniques
HIGH_SIGNAL_TECH_PREFIXES = {
    "T1055",  # Process Injection
    "T1059",  # Command and Scripting Interpreter
    "T1105",  # Ingress Tool Transfer
    "T1547",  # Boot/Logon Autostart Execution
    "T1543",  # Create/Modify System Process
    "T1569",  # System Services
    "T1021",  # Remote Services
    "T1071",  # Application Layer Protocol
    "T1041",  # Exfiltration Over C2 Channel
    "T1003",  # Credential Dumping
    "T1110",  # Brute Force
    "T1552",  # Unsecured Credentials
    "T1218",  # Signed Binary Proxy Execution
    "T1574",  # Hijack Execution Flow
    "T1036",  # Masquerading
    "T1566",  # Phishing
}

# Lower-signal techniques that often appear in installers
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

    # ---- Load capa ----
    capa_json_path = case_dir / "capa.json"
    capa_blob = capa_json_path.read_text(encoding="utf-8", errors="replace") if capa_json_path.exists() else ""
    techs = sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", capa_blob)))
    match_count = capa_blob.count('"matches"')

    # ---- Version info / installer look ----
    file_info = _pe_string_table(pe_meta)
    company = (file_info.get("CompanyName") or "").strip()
    product = (file_info.get("ProductName") or "").strip()
    desc = (file_info.get("FileDescription") or "").strip()
    original_filename = (file_info.get("OriginalFilename") or "").strip()

    looks_like_installer = _looks_like_installer(company, product, desc, summary, case_dir)

    # ---- Parent/subfile context ----
    is_subfile = _is_subfile_case(case_dir)
    parent_case_dir = _get_parent_case_dir_from_subfile(case_dir) if is_subfile else None
    parent_summary = _safe_load_json(parent_case_dir / "summary.json") if parent_case_dir else None
    parent_verdict = (parent_summary or {}).get("verdict") if isinstance(parent_summary, dict) else None
    parent_is_benign = parent_verdict == "BENIGN"

    # ---- Signing context ----
    signing = _load_signing(case_dir)
    is_trusted_signed = bool(signing.get("verify_ok")) and bool(signing.get("timestamp_verified"))
    signer_subject = (signing.get("subject") or "").strip()

    # ---- File name / path context ----
    sample_info = summary.get("sample", {}) if isinstance(summary.get("sample"), dict) else {}
    sample_name = str(sample_info.get("name") or sample_info.get("path") or "").strip()
    lower_name = sample_name.lower()

    hashy_name = bool(re.fullmatch(r"[0-9a-f]{24,}\.(exe|dll|scr|com|bat|ps1)?", lower_name))
    suspicious_ext = lower_name.endswith((".scr", ".com", ".js", ".jse", ".vbs", ".ps1", ".hta"))

    # ---- Technique grouping ----
    high = [t for t in techs if _prefix_in(t, HIGH_SIGNAL_TECH_PREFIXES)]
    low = [t for t in techs if _prefix_in(t, LOW_SIGNAL_TECH_PREFIXES)]
    other = [t for t in techs if t not in set(high) and t not in set(low)]
    trust_override = any(_prefix_in(t, TRUST_OVERRIDE_TECH_PREFIXES) for t in techs)

    # ---- Baseline trust / metadata ----
    if is_trusted_signed:
        benign.append(
            f"Valid Authenticode signature with verified timestamp"
            f"{f' (Subject={signer_subject})' if signer_subject else ''}"
        )
    else:
        score += 12
        suspicious.append("File is unsigned or signature/timestamp verification failed (+12)")

    if not company:
        score += 5
        suspicious.append("Missing CompanyName in version info (+5)")
    else:
        benign.append(f"CompanyName present: {company}")

    if not product:
        score += 4
        suspicious.append("Missing ProductName in version info (+4)")
    else:
        benign.append(f"ProductName present: {product}")

    if not desc:
        score += 3
        suspicious.append("Missing FileDescription in version info (+3)")

    if not original_filename:
        score += 3
        suspicious.append("Missing OriginalFilename in version info (+3)")

    if hashy_name:
        score += 8
        suspicious.append("Filename resembles a hash/random artifact name (+8)")

    if suspicious_ext:
        score += 12
        suspicious.append(f"Suspicious executable/script extension observed: {sample_name} (+12)")

    # ---- Technique scoring ----
    if techs:
        if high:
            add = min(50, 22 + 8 * len(high))
            score += add
            suspicious.append(
                f"High-signal ATT&CK techniques present (count={len(high)}): {', '.join(high[:10])} (+{add})"
            )
        else:
            add = 10 if not looks_like_installer else 4
            score += add
            suspicious.append(f"Only low/medium-signal ATT&CK techniques detected (count={len(techs)}) (+{add})")

        if other:
            add = min(20, 4 + 2 * len(other))
            score += add
            suspicious.append(f"Additional ATT&CK techniques detected (count={len(other)}) (+{add})")

        if looks_like_installer and low and is_trusted_signed and not high:
            benign.append(f"Installer context detected; down-weighting common techniques: {', '.join(low[:8])}")
    else:
        # neutral, not benign
        suspicious.append("No ATT&CK techniques detected in capa output (neutral: may be packed/unsupported) (+0)")

    # ---- Behavior density ----
    if match_count > 0:
        if looks_like_installer and is_trusted_signed and not high:
            density = min(10, 3 + int(match_count / 20))
        else:
            density = min(24, 6 + int(match_count / 8))
        score += density
        suspicious.append(f"capa match density (match_count≈{match_count}) (+{density})")
    else:
        suspicious.append("No capa matches detected (neutral: may be packed/unsupported) (+0)")

    # ---- IOC scoring ----
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
            add = min(22, 10 + 3 * ip_count)
            score += add
            suspicious.append(f"Network IP IOCs present (filtered_ips={ip_count}) (+{add})")

        if dom_count + url_count > 0:
            add = min(16, 3 + (2 * dom_count) + min(5, url_count))
            score += add
            suspicious.append(f"Domains/URLs present (filtered_domains={dom_count}, filtered_urls={url_count}) (+{add})")

        if ip_count == 0 and dom_count == 0 and url_count == 0:
            benign.append("No high-confidence network IOCs extracted after filtering")

    # ---- Packer hints ----
    lief_blob = json.dumps(lief_meta, ensure_ascii=False) if lief_meta else ""
    if re.search(r"\bUPX\b", lief_blob, re.I) or re.search(r"\bpacked\b", lief_blob, re.I):
        score += 15
        suspicious.append("Packer/compression indicators present (+15)")

    # ---- Installer discounts (more conservative than before) ----
    if looks_like_installer and is_trusted_signed and not trust_override and not high:
        before = score
        score = max(0, int(score * 0.75))
        benign.append(f"Trusted installer context detected; applying mild score reduction: {before} -> {score}")

    # ---- Signature-aware trust discount (only when genuinely low-risk context) ----
    if is_trusted_signed and not trust_override and not high and not filtered_ips and not filtered_domains and not filtered_urls:
        before = score
        score = max(0, int(score * 0.85))
        benign.append(
            f"Trusted signature in otherwise low-signal context; applying mild trust discount: {before} -> {score}"
        )

    # ---- Subfile damping (only for BENIGN parents) ----
    if is_subfile and parent_is_benign and not trust_override and not high:
        cap = 60
        if score > cap:
            benign.append(f"Parent verdict BENIGN and no high-signal override; capping subfile score at {cap}")
            score = cap

    # ---- Safety floor ----
    if (
        not is_trusted_signed
        and (
            hashy_name
            or suspicious_ext
            or match_count > 0
            or len(high) > 0
            or len(filtered_ips) > 0
            or len(filtered_domains) > 0
            or len(filtered_urls) > 0
            or re.search(r"\bUPX\b|\bpacked\b", lief_blob, re.I)
        )
    ):
        if score < 35:
            suspicious.append("Applying unsigned suspicious-file floor (+adjust)")
            score = 35

    score = max(0, min(100, score))

    if score < 30:
        benign.append("Low overall heuristic score")

    return score, suspicious, benign


def _prefix_in(t: str, prefixes: set[str]) -> bool:
    return any(t == p or t.startswith(p + ".") for p in prefixes)


def _looks_like_installer(company: str, product: str, desc: str, summary: dict[str, Any], case_dir: Path) -> bool:
    s = (company + " " + product + " " + desc).lower()
    if "installer" in s or "setup" in s or "update" in s:
        return True
    file_line = ""
    fp = case_dir / "file.txt"
    if fp.exists():
        try:
            file_line = fp.read_text(encoding="utf-8", errors="replace").splitlines()[0].lower()
        except Exception:
            file_line = ""
    return ("installer" in file_line) or ("setup" in file_line) or ("installshield" in file_line)


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
