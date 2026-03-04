from __future__ import annotations
import re
import json
import csv
from pathlib import Path
from urllib.parse import urlparse

# --- Regexes ---
RE_URL = re.compile(r'(?i)\b((?:https?|hxxps?)://[^\s"\'<>]{4,})')
RE_DOMAIN = re.compile(r'(?i)\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}))\b')
RE_IPV4 = re.compile(r'\b((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})\b')
RE_EMAIL = re.compile(r'(?i)\b([a-z0-9._%+\-]{1,64}@[a-z0-9.\-]{2,255}\.[a-z]{2,63})\b')
RE_WIN_PATH = re.compile(r'(?i)\b([a-z]:\\(?:[^\\/:*?"<>|\r\n]{1,240}\\)*[^\\/:*?"<>|\r\n]{1,240})\b')
RE_UNC_PATH = re.compile(r'(?i)\b(\\\\[a-z0-9._\-]{1,80}\\[^\s"\'<>]{1,240})\b')
RE_REG_KEY = re.compile(r'(?i)\b((?:HKLM|HKEY_LOCAL_MACHINE|HKCU|HKEY_CURRENT_USER|HKCR|HKEY_CLASSES_ROOT|HKU|HKEY_USERS)\\[^\r\n]{3,240})\b')
RE_HASH_MD5 = re.compile(r'\b([a-fA-F0-9]{32})\b')
RE_HASH_SHA1 = re.compile(r'\b([a-fA-F0-9]{40})\b')
RE_HASH_SHA256 = re.compile(r'\b([a-fA-F0-9]{64})\b')

# --- Filters to reduce "strings noise" ---
ASSET_EXT_DENY = {
    "js","css","svg","png","jpg","jpeg","gif","webp","ico","map","woff","woff2","ttf","eot","otf"
}

# A pragmatic TLD allowlist (expand any time)
TLD_ALLOW = {
    "com","net","org","edu","gov","mil","int",
    "io","ai","co","app","dev","cloud","site","info","biz","me",
    "us","uk","ca","au","nz","ie","de","fr","es","it","nl","se","no","dk","fi","ch","at","be","pt","gr","pl","cz","sk","hu","ro","bg",
    "jp","kr","cn","tw","hk","sg","in","id","my","th","vn","ph",
    "br","mx","ar","cl","co","pe","uy",
    "ru","ua","il","tr","za","ae","sa"
}

DOMAIN_DENYLIST = {
    "microsoft.com", "windows.com", "google.com", "github.com", "wikipedia.org",
    "akamai.net", "digicert.com", "verisign.com"
}

def _clean(s: str) -> str:
    s = s.replace("\\x00", "").replace("\x00", "")
    s = "".join(ch for ch in s if ch.isprintable())
    return s.strip()

def _normalize_url(u: str) -> str:
    u = _clean(u)
    u = re.sub(r'(?i)^hxxps://', 'https://', u)
    u = re.sub(r'(?i)^hxxp://', 'http://', u)
    return u.rstrip(').,;\'"<>]')

def _is_asset_like_domain_or_label(s: str) -> bool:
    # e.g., "chunk-vendors.83fd6fc0.js" or "index.html"
    parts = s.lower().split(".")
    if len(parts) >= 2 and parts[-1] in ASSET_EXT_DENY:
        return True
    return False

def _is_valid_domain(dom: str) -> bool:
    dom = dom.lower().strip().rstrip(".")
    if dom in DOMAIN_DENYLIST:
        return False

    # quick asset suppression
    if _is_asset_like_domain_or_label(dom):
        return False

    if len(dom) < 7 or len(dom) > 253:
        return False
    if ".." in dom:
        return False

    labels = dom.split(".")
    if len(labels) < 2:
        return False

    tld = labels[-1]
    # Strong filter: TLD must be known + alpha
    if not tld.isalpha() or tld not in TLD_ALLOW:
        return False

    # Validate labels
    for lab in labels:
        if not (1 <= len(lab) <= 63):
            return False
        if lab.startswith("-") or lab.endswith("-"):
            return False
        if not re.fullmatch(r"[a-z0-9-]+", lab):
            return False

    return True

def _clean_host(host: str) -> str:
    host = host.strip().lower()
    # Remove creds/port if present
    host = host.split("@")[-1].split(":")[0].strip()

    # Keep only hostname chars
    host = re.sub(r"[^a-z0-9\.\-]", "", host)

    # Fix cases like "ocsp.digicert.com0I" -> "ocsp.digicert.com"
    # Strategy: if invalid, strip trailing non-letter/digit noise and try again.
    if _is_valid_domain(host):
        return host

    # If host ends with digits (common string-garbage), strip digits and retry.
    h2 = re.sub(r"\d+$", "", host)
    if h2 != host and _is_valid_domain(h2):
        return h2

    # If host ends with a single trailing letter after digits, strip both and retry (e.g., com0i)
    h3 = re.sub(r"\d+[a-z]$", "", host)
    if h3 != host and _is_valid_domain(h3):
        return h3

    return host

def _domain_from_url(u: str) -> str | None:
    try:
        p = urlparse(u)
        if not p.netloc:
            return None
        host = _clean_host(p.netloc)
        return host if _is_valid_domain(host) else None
    except Exception:
        return None

def extract_from_strings(strings_text: str) -> dict:
    urls, domains, ips, emails, paths, unc_paths, reg_keys = set(), set(), set(), set(), set(), set(), set()
    md5s, sha1s, sha256s = set(), set(), set()

    for raw in strings_text.splitlines():
        line = _clean(raw)
        if not line or len(line) < 4:
            continue

        # URLs (high value)
        for m in RE_URL.findall(line):
            url = _normalize_url(m)
            if len(url) >= 8:
                urls.add(url)
                d = _domain_from_url(url)
                if d:
                    domains.add(d)

        # Emails (filtered)
        for m in RE_EMAIL.findall(line):
            m = m.lower()
            local, _, dom = m.partition("@")
            if len(local) > 1 and _is_valid_domain(dom):
                emails.add(m)

        # IPs (filtered: drop placeholders like x.0.0.0)
        for m in RE_IPV4.findall(line):
            if m.endswith(".0.0.0"):
                continue
            ips.add(m)

        # Paths/registry (keep; can still be noisy but useful)
        for m in RE_WIN_PATH.findall(line):
            paths.add(_clean(m))
        for m in RE_UNC_PATH.findall(line):
            unc_paths.add(_clean(m))
        for m in RE_REG_KEY.findall(line):
            reg_keys.add(_clean(m))

        # Hash-like pivots
        for m in RE_HASH_SHA256.findall(line):
            sha256s.add(m.lower())
        for m in RE_HASH_SHA1.findall(line):
            sha1s.add(m.lower())
        for m in RE_HASH_MD5.findall(line):
            md5s.add(m.lower())

        # Domains outside URLs (strictly validated)
        for m in RE_DOMAIN.findall(line):
            dom = m.lower().rstrip(".")
            if _is_valid_domain(dom):
                domains.add(dom)

    return {
        "urls": sorted(urls),
        "domains": sorted(domains),
        "ips": sorted(ips),
        "emails": sorted(emails),
        "paths": sorted(paths),
        "unc_paths": sorted(unc_paths),
        "registry_keys": sorted(reg_keys),
        "hashes": {
            "md5": sorted(md5s),
            "sha1": sorted(sha1s),
            "sha256": sorted(sha256s),
        }
    }

def extract_from_capa_json(capa_obj: dict) -> dict:
    techniques, mbc, capabilities = set(), set(), set()

    for key in ("rules", "matches"):
        if key in capa_obj and isinstance(capa_obj[key], dict):
            for rule_name, rule_body in capa_obj[key].items():
                capabilities.add(str(rule_name))
                if not isinstance(rule_body, dict):
                    continue
                meta = rule_body.get("meta") or rule_body.get("metadata") or {}
                if not isinstance(meta, dict):
                    continue
                for mv in meta.values():
                    if not mv:
                        continue
                    vals = [mv] if isinstance(mv, str) else [str(x) for x in mv] if isinstance(mv, list) else [str(mv)]
                    for v in vals:
                        for t in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", v):
                            techniques.add(t)
                        for c in re.findall(r"\bC\d{4}(?:\.\d{3})?\b", v):
                            mbc.add(c)

    top_meta = capa_obj.get("meta", {})
    if isinstance(top_meta, dict):
        for v in top_meta.values():
            if isinstance(v, str):
                for t in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", v):
                    techniques.add(t)
                for c in re.findall(r"\bC\d{4}(?:\.\d{3})?\b", v):
                    mbc.add(c)

    return {"techniques": sorted(techniques), "mbc": sorted(mbc), "capabilities": sorted(capabilities)}

def build_iocs(strings_txt_path: Path, capa_json_path: Path | None = None) -> dict:
    strings_text = strings_txt_path.read_text(encoding="utf-8", errors="replace")
    obs = extract_from_strings(strings_text)

    capa_part = {"techniques": [], "mbc": [], "capabilities": []}
    if capa_json_path and capa_json_path.exists():
        try:
            capa_obj = json.loads(capa_json_path.read_text(encoding="utf-8", errors="replace"))
            capa_part = extract_from_capa_json(capa_obj)
        except Exception:
            pass

    stats = {
        "counts": {
            "urls": len(obs["urls"]),
            "domains": len(obs["domains"]),
            "ips": len(obs["ips"]),
            "emails": len(obs["emails"]),
            "paths": len(obs["paths"]) + len(obs["unc_paths"]),
            "registry_keys": len(obs["registry_keys"]),
            "attack_techniques": len(capa_part["techniques"]),
            "mbc": len(capa_part["mbc"]),
            "capa_capabilities": len(capa_part["capabilities"]),
        }
    }

    return {"observables": obs, "capa": capa_part, "stats": stats}

def write_iocs_json(out_path: Path, iocs: dict) -> None:
    out_path.write_text(json.dumps(iocs, indent=2, sort_keys=True), encoding="utf-8")

def write_iocs_csv(out_path: Path, iocs: dict) -> None:
    rows = []
    obs = iocs.get("observables", {})
    for k in ("urls", "domains", "ips", "emails", "paths", "unc_paths", "registry_keys"):
        for v in obs.get(k, []):
            rows.append({"type": k, "value": v})
    for htype, hvals in (obs.get("hashes", {}) or {}).items():
        for v in hvals:
            rows.append({"type": f"hash_{htype}", "value": v})

    for t in iocs.get("capa", {}).get("techniques", []):
        rows.append({"type": "attack_technique", "value": t})
    for m in iocs.get("capa", {}).get("mbc", []):
        rows.append({"type": "mbc_behavior", "value": m})

    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["type", "value"])
        w.writeheader()
        w.writerows(rows)
