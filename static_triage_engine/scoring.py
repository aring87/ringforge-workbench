"""Shared helpers for reading a case: observables, PE strings, VirusTotal noise.

**This file used to be the scorer.** It held an additive model -- a 0-40 static
score, a 0-30 dynamic score, a spec score, summed and clamped to 100 and banded
with thresholds derived for the 0-40 scale -- which `docs/SCORING.md` retired in
favour of `corroboration-v1`. `static_triage_engine/categories.py` authors the
evidence categories now, `verdict/` bands them, and
`static_triage_engine/combine_case.py` reads a case off disk.

What is left is the part that never had anything to do with scoring:
normalising IOC observables, pulling the PE version-info table, recognising the
noise floor of multi-engine scanning, and loading JSON without raising. The new
code imports these rather than reimplementing them, because they were checked
against real samples and a second copy would only introduce disagreements.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse


HIGH_SIGNAL_TECH_PREFIXES = {
    "T1055", "T1059", "T1105", "T1547", "T1543", "T1569", "T1021", "T1071",
    "T1041", "T1003", "T1110", "T1552", "T1218", "T1574", "T1036", "T1566",
}
LOW_SIGNAL_TECH_PREFIXES = {"T1027", "T1033", "T1082", "T1083", "T1087", "T1129", "T1497", "T1564.003"}
TRUST_OVERRIDE_TECH_PREFIXES = {"T1055", "T1003", "T1105", "T1071", "T1041", "T1218", "T1574"}

#: Hosts that appear in ordinary binaries *by construction* rather than by
#: intent, so finding one says nothing about the file.
#:
#: **This held only digicert, and the cost was 84.6%.** Once `strings` was fixed
#: and `embedded_network_indicators` could run for the first time, it fired on
#: 247 of 292 signed System32 binaries. The three biggest contributors were
#: `schemas.microsoft.com` (102), `crl.microsoft.com` (71) and
#: `www.microsoft.com` (69) -- an XML namespace, a certificate revocation
#: endpoint, and the PKI root URL that Authenticode embeds in every signed file
#: on the machine.
#:
#: Two classes, and neither is a network destination in any meaningful sense:
#:
#: - **PKI.** CRL, OCSP and CA-certificate URLs are part of a signature. Every
#:   signed binary carries them, malicious ones included, so they cannot
#:   discriminate.
#: - **XML namespaces.** `schemas.microsoft.com/SMI/2005/WindowsSettings` is an
#:   identifier in a manifest. Nothing ever resolves it.
#:
#: A suffix match does mean C2 hosted on one of these domains would be
#: suppressed. That is a real cost, accepted deliberately: the alternative is a
#: category that fires on five out of six benign files and is therefore ignored.
KNOWN_BENIGN_DOMAIN_SUFFIXES = {
    # Certificate infrastructure -- embedded by signing, not by the program.
    "digicert.com", "ocsp.digicert.com", "crl3.digicert.com",
    "crl4.digicert.com", "cacerts.digicert.com",
    "verisign.com", "symcb.com", "symcd.com", "thawte.com",
    "globalsign.com", "globalsign.net", "sectigo.com", "usertrust.com",
    "comodoca.com", "entrust.net", "identrust.com", "letsencrypt.org",
    "certum.pl", "quovadisglobal.com", "amazontrust.com", "sca1b.amazontrust.com",
    # Microsoft PKI and update infrastructure.
    "microsoft.com", "crl.microsoft.com", "www.microsoft.com",
    "go.microsoft.com", "windowsupdate.com", "msftconnecttest.com",
    "digicert.cn", "microsoft.net", "windows.com", "msn.com",
    # XML namespaces and standards URIs. Identifiers, never fetched.
    "schemas.microsoft.com", "schemas.openxmlformats.org",
    "schemas.xmlsoap.org", "w3.org", "www.w3.org", "purl.org",
    "oasis-open.org", "iana.org", "ietf.org", "rfc-editor.org",
    "openoffice.org", "docs.oasis-open.org",
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
        p = Path(path_case).parent
        return p
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