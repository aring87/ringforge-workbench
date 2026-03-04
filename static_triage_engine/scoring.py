from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any, Tuple
from urllib.parse import urlparse


def classify_verdict(score: int) -> tuple[str, str]:
    if score >= 85:
        return ("MALICIOUS", "High confidence")
    if score >= 60:
        return ("SUSPICIOUS", "Moderate confidence")
    if score >= 35:
        return ("LOW_RISK", "Low confidence")
    return ("BENIGN", "Low confidence")


# "High signal" for general scoring (existing behavior; installers can still hit some of these)
HIGH_SIGNAL_TECH_PREFIXES = {
    "T1055",  # Process Injection
    "T1059",  # Command and Scripting Interpreter
    "T1105",  # Ingress Tool Transfer
    "T1547",  # Boot/Logon Autostart Execution
    "T1543",  # Create/Modify System Process (services)
    "T1569",  # System Services
    "T1021",  # Remote Services
    "T1071",  # Application Layer Protocol (C2)
    "T1041",  # Exfiltration Over C2 Channel
    "T1003",  # OS Credential Dumping
    "T1110",  # Brute Force
    "T1552",  # Unsecured Credentials
    "T1218",  # Signed Binary Proxy Execution
    "T1574",  # Hijack Execution Flow
    "T1036",  # Masquerading
    "T1566",  # Phishing
}

# Common/low-signal techniques that can show up in legitimate installers/updaters
LOW_SIGNAL_TECH_PREFIXES = {
    "T1027",      # Obfuscated/Compressed Files and Information (installers compress)
    "T1033",      # System Owner/User Discovery
    "T1082",      # System Information Discovery
    "T1083",      # File and Directory Discovery
    "T1087",      # Account Discovery (sometimes for environment checks)
    "T1129",      # Shared Modules
    "T1497",      # Virtualization/Sandbox Evasion (many products do env checks)
    "T1564.003",  # Hidden Window (UI behavior can trigger)
}

# "Override" high-signal set for trust/discount logic (stricter than HIGH_SIGNAL_TECH_PREFIXES).
# Rationale: installers often legitimately create services / run keys / enumerate processes,
# but true malware-leaning signals like injection / cred dumping / explicit C2/exfil should not be discounted.
TRUST_OVERRIDE_TECH_PREFIXES = {
    "T1055",  # injection
    "T1003",  # credential dumping
    "T1105",  # ingress tool transfer
    "T1071",  # C2 protocol
    "T1041",  # exfil over C2
    "T1218",  # signed binary proxy execution (can be abused)
    "T1574",  # execution flow hijack
}

# Known-benign CA / OCSP / CRL infrastructure that frequently appears in signed binaries.
KNOWN_BENIGN_DOMAIN_SUFFIXES = {
    "digicert.com",
    "ocsp.digicert.com",
    "crl3.digicert.com",
    "crl4.digicert.com",
    "cacerts.digicert.com",
}

# Known-benign public resolver IPs that shouldn't add risk by themselves.
KNOWN_BENIGN_IPS = {
    "8.8.8.8",  # Google Public DNS
    "8.8.4.4",
    "1.1.1.1",  # Cloudflare
    "9.9.9.9",  # Quad9
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

    # ---- Version info / "installer look" ----
    file_info = _pe_string_table(pe_meta)
    company = (file_info.get("CompanyName") or "").strip()
    product = (file_info.get("ProductName") or "").strip()
    desc = (file_info.get("FileDescription") or "").strip()
    looks_like_installer = _looks_like_installer(company, product, desc, summary, case_dir)

    # ---- Parent/subfile context ----
    is_subfile = _is_subfile_case(case_dir)
    parent_case_dir = _get_parent_case_dir_from_subfile(case_dir) if is_subfile else None
    parent_summary = _safe_load_json(parent_case_dir / "summary.json") if parent_case_dir else None
    parent_verdict = (parent_summary or {}).get("verdict") if isinstance(parent_summary, dict) else None
    parent_is_low = parent_verdict in {"BENIGN", "LOW_RISK"}

    # ---- Signing context (optional) ----
    signing = _load_signing(case_dir)
    is_trusted_signed = bool(signing.get("verify_ok")) and bool(signing.get("timestamp_verified"))
    signer_subject = (signing.get("subject") or "").strip()

    # ---- Technique grouping ----
    high = [t for t in techs if _prefix_in(t, HIGH_SIGNAL_TECH_PREFIXES)]
    low = [t for t in techs if _prefix_in(t, LOW_SIGNAL_TECH_PREFIXES)]
    other = [t for t in techs if t not in set(high) and t not in set(low)]

    # ---- Trust override detection (do NOT discount signed binaries if these appear) ----
    trust_override = any(_prefix_in(t, TRUST_OVERRIDE_TECH_PREFIXES) for t in techs)

    # ---- Technique scoring (existing logic, kept) ----
    if techs:
        if high:
            add = min(40, 18 + 6 * len(high))
            score += add
            suspicious.append(
                f"High-signal ATT&CK techniques present (count={len(high)}): {', '.join(high[:10])} (+{add})"
            )
        else:
            add = 8 if not looks_like_installer else 3
            score += add
            suspicious.append(f"Only low/medium-signal ATT&CK techniques detected (count={len(techs)}) (+{add})")

        if looks_like_installer and low:
            benign.append(f"Installer context detected; down-weighting common techniques: {', '.join(low[:8])}")

        if other:
            add = min(18, 3 + 2 * len(other))
            score += add
            suspicious.append(f"Additional ATT&CK techniques detected (count={len(other)}) (+{add})")
    else:
        benign.append("No ATT&CK technique IDs detected in capa output")

    # ---- Behavior density (existing logic, kept) ----
    if match_count > 0:
        if looks_like_installer and not high:
            density = min(10, 3 + int(match_count / 20))
        else:
            density = min(20, 5 + int(match_count / 10))
        score += density
        suspicious.append(f"capa match density (match_count≈{match_count}) (+{density})")
    else:
        benign.append("No capa matches detected")

    # ---- IOC scoring (improved: validate/filter) ----
    observables = _extract_observables(iocs)
    filtered_ips = _filter_ips(observables.get("ips", []))
    filtered_domains = _filter_domains(observables.get("domains", []))
    filtered_urls = _filter_urls(observables.get("urls", []))

    # If all network-ish indicators are only known-benign CA/OCSP/CRL, do not treat as suspicious.
    only_benign_infra = (
        (len(filtered_domains) == 0 and len(filtered_urls) == 0 and len(filtered_ips) == 0)
        and _has_only_known_benign_infra(observables)
    )
    if only_benign_infra:
        benign.append("Only known-benign certificate/OCSP/CRL infrastructure observed; no IOC risk added")
    else:
        # IP scoring: keep conservative; ignore common resolvers/loopback/private
        ip_count = len(filtered_ips)
        if ip_count > 0:
            add = min(18, 10 + 2 * ip_count)
            score += add
            suspicious.append(f"Network IP IOCs present (filtered_ips={ip_count}) (+{add})")
        else:
            benign.append("No high-confidence IP IOCs extracted (after filtering)")

        # Domains/URLs: very light weight, and only when not purely CA/OCSP/CRL
        dom_count = len(filtered_domains)
        url_count = len(filtered_urls)
        if dom_count + url_count > 0:
            add = min(10, 2 + dom_count + min(3, url_count))
            score += add
            suspicious.append(f"Domains/URLs present (filtered_domains={dom_count}, filtered_urls={url_count}) (+{add})")

    # ---- Metadata quality (existing logic, kept) ----
    if not company:
        score += 3
        suspicious.append("Missing CompanyName in version info (+3)")
    else:
        benign.append(f"CompanyName present: {company}")
    if not product:
        score += 2
        suspicious.append("Missing ProductName in version info (+2)")

    # ---- Packer hints (existing logic, kept) ----
    lief_blob = json.dumps(lief_meta, ensure_ascii=False) if lief_meta else ""
    if re.search(r"\bUPX\b", lief_blob, re.I) or re.search(r"\bpacked\b", lief_blob, re.I):
        score += 10
        suspicious.append("Packer/compression indicators present (+10)")

    # ---- Apply signature-aware trust discount (NEW) ----
    # If Authenticode is valid and timestamp verified, discount score unless strong override techniques exist.
    if is_trusted_signed and not trust_override:
        before = score
        score = int(score * 0.55)
        benign.append(
            f"Valid Authenticode signature (timestamp verified) detected"
            f"{f' (Subject={signer_subject})' if signer_subject else ''}; applying trust discount: {before} -> {score}"
        )

    # ---- Apply subfile damping if parent was low-risk (NEW) ----
    # Prevent extracted payload subfiles from spiking to SUSPICIOUS based on noisy installer behaviors.
    if is_subfile and parent_is_low and not trust_override:
        cap = 60
        if score > cap:
            benign.append(f"Parent verdict {parent_verdict} and no high-signal override; capping subfile score at {cap}")
            score = cap

    # ---- Clamp and return ----
    score = max(0, min(100, score))
    if score < 35:
        benign.append("Low overall heuristic score")

    return score, suspicious, benign


def _prefix_in(t: str, prefixes: set[str]) -> bool:
    return any(t == p or t.startswith(p + ".") for p in prefixes)


def _looks_like_installer(company: str, product: str, desc: str, summary: dict[str, Any], case_dir: Path) -> bool:
    s = (company + " " + product + " " + desc).lower()
    if "installer" in s or "setup" in s:
        return True
    file_line = ""
    fp = case_dir / "file.txt"
    if fp.exists():
        try:
            file_line = fp.read_text(encoding="utf-8", errors="replace").splitlines()[0].lower()
        except Exception:
            file_line = ""
    return ("installer" in file_line) or ("setup" in file_line)


def _get_case_dir(summary: dict[str, Any]) -> Path:
    sample = summary.get("sample", {}) if isinstance(summary.get("sample", {}), dict) else {}
    path_case = sample.get("path_case")
    if isinstance(path_case, str) and path_case:
        return Path(path_case).parent
    return Path(".")


def _is_subfile_case(case_dir: Path) -> bool:
    # typical: .../cases/<parent>/subfiles/<nn_name>/
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
    """
    Looks for signing.json in the case directory.
    Expected keys (best effort):
      - verify_ok: bool
      - timestamp_verified: bool
      - subject: str
    If missing, returns {}.
    """
    p = case_dir / "signing.json"
    data = _safe_load_json(p) or {}

    # Also allow signature info to be nested under "signing" if you embed it elsewhere later.
    if not data and (case_dir / "summary.json").exists():
        s = _safe_load_json(case_dir / "summary.json") or {}
        embedded = s.get("signing")
        if isinstance(embedded, dict):
            data = embedded

    # Normalize some common variants
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
    # If there are *some* domains/urls but they all point to known-benign infra, treat as benign.
    domains = [d.lower().strip(".") for d in observables.get("domains", [])]
    urls = [u for u in observables.get("urls", [])]
    if not domains and not urls:
        return False

    def is_benign_domain(d: str) -> bool:
        return any(d == sfx or d.endswith("." + sfx) for sfx in KNOWN_BENIGN_DOMAIN_SUFFIXES)

    dom_ok = all(is_benign_domain(d) for d in domains) if domains else True

    # For URLs, require parseable host and benign domain
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
        # drop userinfo/port
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
        # ignore known-benign CA infra
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
        # ignore known-benign CA infra
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
            # drop non-IPs (e.g., OIDs accidentally captured as "1.3.6.1")
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
