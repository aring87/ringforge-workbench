from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional

from dynamic_analysis.report_theme import badge, score_badge, report_page
from .scoring import combined_score_from_case_dir


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_text(p: Path, limit: int = 250_000) -> str:
    if not p.exists():
        return ""
    s = p.read_text(encoding="utf-8", errors="replace")
    return s if len(s) <= limit else s[:limit] + "\n\n[...truncated...]\n"


def _read_json(p: Path) -> Dict[str, Any]:
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _first_line(p: Path) -> str:
    if not p.exists():
        return ""
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip():
            return line.strip()
    return ""


def _safe(s: Any) -> str:
    return html.escape("" if s is None else str(s))


def _extract_attack_techniques_from_capa(capa_json_path: Path) -> Tuple[List[str], int]:
    if not capa_json_path.exists():
        return ([], 0)
    blob = capa_json_path.read_text(encoding="utf-8", errors="replace")
    techs = sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", blob)))
    return (techs, blob.count('"matches"'))


def _ioc_counts(iocs: dict[str, Any]) -> dict[str, int]:
    stats = None
    if isinstance(iocs.get("stats"), dict):
        stats = iocs["stats"].get("counts")
        if not isinstance(stats, dict):
            stats = iocs["stats"]

    if isinstance(iocs.get("counts"), dict) and not isinstance(stats, dict):
        stats = iocs["counts"]

    keys = ["domains", "urls", "ips", "emails", "paths", "registry_keys"]
    if isinstance(stats, dict):
        out: dict[str, int] = {}
        for k in keys:
            try:
                out[k] = int(stats.get(k, 0) or 0)
            except Exception:
                out[k] = 0
        out.setdefault("registry", out.get("registry_keys", 0))
        return out

    obs = iocs.get("observables", {}) if isinstance(iocs.get("observables"), dict) else {}
    return {
        "domains": len(obs.get("domains", []) or []) if isinstance(obs.get("domains"), list) else 0,
        "urls": len(obs.get("urls", []) or []) if isinstance(obs.get("urls"), list) else 0,
        "ips": len(obs.get("ips", []) or []) if isinstance(obs.get("ips"), list) else 0,
        "emails": len(obs.get("emails", []) or []) if isinstance(obs.get("emails"), list) else 0,
        "paths": len(obs.get("paths", []) or []) if isinstance(obs.get("paths"), list) else 0,
        "registry": len(obs.get("registry_keys", []) or []) if isinstance(obs.get("registry_keys"), list) else 0,
    }




def _capa_evidence_block(case_dir: Path) -> dict[str, Any]:
    capa_json_path = case_dir / "capa.json"
    capa_txt_path = case_dir / "capa.txt"
    if not capa_json_path.exists() and not capa_txt_path.exists():
        return {"present": False, "techniques": [], "match_count": 0, "families": {}, "top_families": [], "top_rules": [], "analyst_notes": [], "family_confidence": {}}

    techniques, match_count = _extract_attack_techniques_from_capa(capa_json_path)
    candidate_rules: set[str] = set()

    if capa_json_path.exists():
        try:
            capa_json = json.loads(capa_json_path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            capa_json = {}

        for key in ("rules", "rule_matches", "capabilities"):
            block = capa_json.get(key)
            if isinstance(block, dict):
                for name in block.keys():
                    s = str(name).strip()
                    if 3 < len(s) < 140:
                        candidate_rules.add(s)

        def walk(obj: Any) -> None:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if str(k).lower() in {"name", "rule_name"} and isinstance(v, str):
                        s = v.strip()
                        if 3 < len(s) < 140:
                            candidate_rules.add(s)
                    walk(v)
            elif isinstance(obj, list):
                for item in obj:
                    walk(item)
        walk(capa_json)

    noisy = {"meta", "analysis", "strings", "sample", "rules", "matches", "name", "function-name", "basic block", "instruction", "feature", "characteristic"}
    top_rules = []
    for item in sorted(candidate_rules):
        low = item.lower()
        if low in noisy or low.startswith("namespace/"):
            continue
        top_rules.append(item)
    top_rules = top_rules[:12]

    family_patterns = {
        "Persistence": [r"\bcreate service\b", r"\binstall service\b", r"\bservice persistence\b", r"\bscheduled task\b", r"\bautorun\b", r"\brun key\b", r"\bstartup folder\b", r"\bregistry run\b"],
        "Network": [r"\bhttp\b", r"\bhttps\b", r"\burl\b", r"\bdns\b", r"\bsocket\b", r"\bconnect\b", r"\bdownload\b", r"\bupload\b", r"\bwininet\b", r"\bwinhttp\b"],
        "Injection/Hollowing": [r"\binject\b", r"\bprocess hollow", r"\bhollowing\b", r"\breflective\b", r"\bshellcode\b", r"\bremote thread\b", r"\bwriteprocessmemory\b", r"\bcreateremotethread\b", r"\bprocess replacement\b", r"\bhook\b"],
        "Defense Evasion": [r"\banti-analysis\b", r"\banti debug\b", r"\banti-debug\b", r"\bsandbox\b", r"\bvm detection\b", r"\bpacker\b", r"\bunhook\b", r"\bhide\b", r"\bevasion\b"],
        "Execution": [r"\bcommand shell\b", r"\bpowershell\b", r"\bexecute\b", r"\bcreate process\b", r"\bspawn process\b", r"\bprocess creation\b", r"\bcmd\.exe\b", r"\brundll32\b"],
        "Discovery": [r"\bcheck os version\b", r"\benumerate\b", r"\bwhoami\b", r"\bhostname\b", r"\bsystem information\b", r"\bquery registry\b", r"\bget computer name\b"],
        "Credential Access": [r"\bcredential\b", r"\blsass\b", r"\bpassword\b", r"\blogon\b", r"\btoken\b"],
        "Collection": [r"\bkeylog", r"\bscreen capture\b", r"\bclipboard\b", r"\baudio capture\b"],
        "Crypto/Encoding": [r"\bxor\b", r"\bencrypt\b", r"\bdecrypt\b", r"\bbase64\b", r"\bencode\b", r"\bdecode\b", r"\bcrypt\b"],
        "File / Archive Operations": [r"\bcreate directory\b", r"\bcreate file\b", r"\bopen file\b", r"\bwrite file\b", r"\bread file\b", r"\barchive\b", r"\bzip\b", r"\b7z\b", r"\bextract\b", r"\bcompress\b", r"\bdecompress\b"],
        "Registry Interaction": [r"\bregistry\b", r"\bopen registry key\b", r"\bcreate or open registry key\b", r"\bquery registry\b", r"\bset registry\b"],
    }

    families = {}
    family_confidence = {}
    for family, patterns in family_patterns.items():
        hits = 0
        for rule in top_rules:
            rule_l = rule.lower()
            if any(re.search(pat, rule_l, flags=re.IGNORECASE) for pat in patterns):
                hits += 1
        if hits:
            families[family] = hits
            family_confidence[family] = "high" if hits >= 2 else "medium"

    family_order = ["File / Archive Operations", "Registry Interaction", "Discovery", "Execution", "Crypto/Encoding", "Defense Evasion", "Persistence", "Network", "Credential Access", "Collection", "Injection/Hollowing"]
    top_families = [name for name in family_order if name in families][:5]

    analyst_notes = []
    if top_families:
        annotated = [f"{name} ({family_confidence.get(name, 'medium')})" for name in top_families[:4]]
        analyst_notes.append("Likely behavior families from explicit capa rule names: " + ", ".join(annotated))
    if "Persistence" in families:
        analyst_notes.append("Persistence was only labeled because capa rule names explicitly referenced service, task, autorun, or run-key style behavior.")
    if "Network" in families:
        analyst_notes.append("Network was only labeled because capa rule names explicitly referenced connect, DNS, HTTP, URL, or socket behavior.")
    if "Injection/Hollowing" in families:
        analyst_notes.append("Injection/Hollowing was only labeled because capa rule names explicitly referenced injection or hollowing-related behavior.")
    if techniques:
        analyst_notes.append("ATT&CK techniques remain supporting evidence and should be reviewed together with strings, signing, imports, and runtime data.")
    if not analyst_notes and match_count:
        analyst_notes.append("capa produced behavioral matches, but none mapped cleanly to the stricter analyst family buckets.")

    return {"present": True, "techniques": techniques[:25], "match_count": int(match_count or 0), "families": families, "top_families": top_families, "top_rules": top_rules[:10], "analyst_notes": analyst_notes[:6], "family_confidence": family_confidence}
def _ioc_counts_from_summary(summary: dict[str, Any], iocs: dict[str, Any]) -> dict[str, int]:
    ioc_summary = summary.get("ioc_summary") if isinstance(summary.get("ioc_summary"), dict) else {}
    counts = ioc_summary.get("counts") if isinstance(ioc_summary.get("counts"), dict) else {}

    if counts:
        return {
            "domains": int(counts.get("domains", 0) or 0),
            "urls": int(counts.get("urls", 0) or 0),
            "ips": int(counts.get("ips", 0) or 0),
            "emails": int(counts.get("emails", 0) or 0),
            "paths": int(counts.get("file_paths", 0) or 0),
            "registry": int(counts.get("registry_paths", 0) or 0),
            "commands": int(counts.get("commands", 0) or 0),
        }

    base = _ioc_counts(iocs)
    base["commands"] = 0
    return base


def _top_reasons(summary: dict[str, Any], max_items: int = 6) -> Tuple[List[str], List[str]]:
    rb = summary.get("reason_breakdown")
    if isinstance(rb, dict):
        susp = rb.get("suspicious", []) if isinstance(rb.get("suspicious"), list) else []
        ben = rb.get("benign", []) if isinstance(rb.get("benign"), list) else []
        return ([str(x) for x in susp][:max_items], [str(x) for x in ben][:max_items])

    reasons = summary.get("reasons")
    if isinstance(reasons, list):
        suspicious_out: List[str] = []
        benign_out: List[str] = []
        for x in reasons:
            sx = str(x)
            if sx.upper().startswith("SUSPICIOUS:"):
                suspicious_out.append(sx.replace("SUSPICIOUS:", "", 1).strip())
            elif sx.upper().startswith("BENIGN:"):
                benign_out.append(sx.replace("BENIGN:", "", 1).strip())
        return (suspicious_out[:max_items], benign_out[:max_items])

    if isinstance(reasons, dict):
        suspicious = reasons.get("suspicious", []) if isinstance(reasons.get("suspicious"), list) else []
        benign = reasons.get("benign", []) if isinstance(reasons.get("benign"), list) else []
        return ([str(x) for x in suspicious][:max_items], [str(x) for x in benign][:max_items])

    return ([], [])


def _artifact_links(case_dir: Path) -> List[Tuple[str, Path]]:
    want = [
        ("report.md", case_dir / "report.md"),
        ("report.html", case_dir / "report.html"),
        ("report.pdf", case_dir / "report.pdf"),
        ("summary.json", case_dir / "summary.json"),
        ("combined_score.json", case_dir / "combined_score.json"),
        ("api_spec_analysis.json", case_dir / "spec" / "api_spec_analysis.json"),
        ("runlog.json", case_dir / "runlog.json"),
        ("analysis.log", case_dir / "analysis.log"),
        ("signing.json", case_dir / "signing.json"),
        ("file.txt", case_dir / "file.txt"),
        ("strings.txt", case_dir / "strings.txt"),
        ("api_analysis.json", case_dir / "api_analysis.json"),
        ("capa.json", case_dir / "capa.json"),
        ("capa.txt", case_dir / "capa.txt"),
        ("iocs.json", case_dir / "iocs.json"),
        ("iocs.csv", case_dir / "iocs.csv"),
        ("pe_metadata.json", case_dir / "pe_metadata.json"),
        ("lief_metadata.json", case_dir / "lief_metadata.json"),
        ("extracted_manifest.json", case_dir / "extracted_manifest.json"),
    ]
    return [(label, p) for (label, p) in want if p.exists()]


def _subfiles_block(summary: dict[str, Any]) -> dict[str, Any]:
    sr = summary.get("subfiles_rollup") if isinstance(summary.get("subfiles_rollup"), dict) else {}
    top = sr.get("top_scoring_subfiles", []) if isinstance(sr.get("top_scoring_subfiles"), list) else []
    attn = sr.get("attention_subfiles", []) if isinstance(sr.get("attention_subfiles"), list) else []
    crit = sr.get("criteria", {}) if isinstance(sr.get("criteria"), dict) else {}
    return {
        "top": top[:5],
        "attn": attn[:10],
        "crit": crit,
    }


def _api_block(case_dir: Path) -> dict[str, Any]:
    api = _read_json(case_dir / "api_analysis.json")
    summary = api.get("summary") if isinstance(api.get("summary"), dict) else {}
    category_hits = api.get("category_hits") if isinstance(api.get("category_hits"), dict) else {}
    chain_findings = api.get("chain_findings") if isinstance(api.get("chain_findings"), list) else []
    imports_by_dll = api.get("imports_by_dll") if isinstance(api.get("imports_by_dll"), dict) else {}

    high = [x for x in chain_findings if isinstance(x, dict) and x.get("severity") == "high"]
    med = [x for x in chain_findings if isinstance(x, dict) and x.get("severity") == "medium"]

    top_categories: List[Tuple[str, int, List[str]]] = []
    for cat, funcs in category_hits.items():
        if isinstance(funcs, list):
            top_categories.append((str(cat), len(funcs), [str(x) for x in funcs[:12]]))
    top_categories.sort(key=lambda x: x[1], reverse=True)

    dll_preview: List[Tuple[str, int, List[str]]] = []
    for dll, funcs in imports_by_dll.items():
        if isinstance(funcs, list):
            dll_preview.append((str(dll), len(funcs), [str(x) for x in funcs[:10]]))
    dll_preview.sort(key=lambda x: x[1], reverse=True)

    return {
        "present": bool(api),
        "returncode": int(api.get("returncode", 0) or 0) if api else 0,
        "error": str(api.get("error", "") or "") if api else "",
        "dll_count": int(summary.get("dll_count", 0) or 0) if summary else 0,
        "import_count": int(summary.get("import_count", 0) or 0) if summary else 0,
        "category_count": int(summary.get("category_count", 0) or 0) if summary else 0,
        "high_chain_count": int(summary.get("high_severity_chain_count", 0) or 0) if summary else 0,
        "high_chains": high[:8],
        "medium_chains": med[:8],
        "top_categories": top_categories[:8],
        "top_dlls": dll_preview[:8],
    }


def _yara_block(case_dir: Path) -> dict[str, Any]:
    yara_j = _read_json(case_dir / "yara_results.json")
    matches = yara_j.get("matches", []) if isinstance(yara_j.get("matches"), list) else []

    top_rules: List[str] = []
    for m in matches[:10]:
        if isinstance(m, dict):
            rule_name = str(m.get("rule", "") or "").strip()
            if rule_name:
                top_rules.append(rule_name)

    return {
        "present": bool(yara_j),
        "matched": bool(yara_j.get("matched", False)),
        "match_count": int(yara_j.get("match_count", 0) or 0),
        "rule_file_count": int(yara_j.get("rule_file_count", 0) or 0),
        "rules_dir": str(yara_j.get("rules_dir", "") or ""),
        "error": str(yara_j.get("error", "") or ""),
        "top_rules": top_rules,
    }


def _spec_block(case_dir: Path) -> dict[str, Any]:
    spec = _read_json(case_dir / "spec" / "api_spec_analysis.json")
    if not spec:
        spec = _read_json(case_dir / "api_spec_analysis.json")

    scoring = spec.get("scoring", {}) if isinstance(spec.get("scoring"), dict) else {}
    summary = spec.get("summary", {}) if isinstance(spec.get("summary"), dict) else {}

    return {
        "present": bool(spec),
        "title": str(spec.get("title", "") or ""),
        "version": str(spec.get("version", "") or ""),
        "servers": spec.get("servers", []) if isinstance(spec.get("servers"), list) else [],
        "auth_summary": spec.get("auth_summary", []) if isinstance(spec.get("auth_summary"), list) else [],
        "risk_notes": spec.get("risk_notes", []) if isinstance(spec.get("risk_notes"), list) else [],
        "summary": summary,
        "scoring": scoring,
    }


def _combined_block(case_dir: Path) -> dict[str, Any]:
    combined = _read_json(case_dir / "combined_score.json")
    if not combined:
        try:
            combined = combined_score_from_case_dir(case_dir, write_output=True)
        except Exception:
            combined = {}
    return combined


def _decoded_strings_block(summary: dict[str, Any]) -> dict[str, Any]:
    ds = summary.get("decoded_strings") if isinstance(summary.get("decoded_strings"), dict) else {}
    stats = ds.get("stats") if isinstance(ds.get("stats"), dict) else {}

    decoded_strings = ds.get("decoded_strings", []) if isinstance(ds.get("decoded_strings"), list) else []
    high_risk_strings = ds.get("high_risk_strings", []) if isinstance(ds.get("high_risk_strings"), list) else []
    notes = ds.get("notes", []) if isinstance(ds.get("notes"), list) else []

    source = str(ds.get("source", "") or "").strip()
    if source.lower() == "placeholder":
        source = ""

    return {
        "enabled": bool(ds.get("enabled", False)),
        "source": source,
        "decoded_count": int(stats.get("decoded_count", len(decoded_strings)) or 0),
        "high_risk_count": int(stats.get("high_risk_count", len(high_risk_strings)) or 0),
        "high_risk_strings": [str(x) for x in high_risk_strings[:20]],
        "notes": [str(x) for x in notes[:5]],
    }


def _verdict_rationale_block(summary: dict[str, Any]) -> dict[str, Any]:
    vr = summary.get("verdict_rationale") if isinstance(summary.get("verdict_rationale"), dict) else {}
    return {
        "score": vr.get("score", summary.get("risk_score", 0)),
        "confidence": str(vr.get("confidence", summary.get("confidence", "")) or ""),
        "increased": [
            str(x)
            for x in (
                vr.get("increased_score_reasons", [])
                if isinstance(vr.get("increased_score_reasons"), list)
                else []
            )[:8]
        ],
        "decreased": [
            str(x)
            for x in (
                vr.get("decreased_score_reasons", [])
                if isinstance(vr.get("decreased_score_reasons"), list)
                else []
            )[:5]
        ],
        "notes": [
            str(x)
            for x in (
                vr.get("notes", [])
                if isinstance(vr.get("notes"), list)
                else []
            )[:5]
        ],
        "recommended_next_step": str(vr.get("recommended_next_step", "") or ""),
    }


def _actions_html(score: int) -> str:
    if score >= 85:
        items = [
            "<li><b>Contain:</b> Isolate endpoint(s) and block SHA256 where applicable.</li>",
            "<li><b>Hunt:</b> Search for hash + any IOCs across EDR/SIEM.</li>",
            "<li><b>Scope:</b> Identify origin and any execution traces.</li>",
            "<li><b>Confirm:</b> Detonate in an isolated sandbox if permitted.</li>",
        ]
    elif score >= 60:
        items = [
            "<li><b>Triage:</b> Validate signature/publisher and compare against known-good.</li>",
            "<li><b>Review:</b> Inspect capa techniques, API chains, spec findings, and suspicious reasons.</li>",
            "<li><b>Hunt:</b> Search IOCs and hash across telemetry.</li>",
        ]
    else:
        items = [
            "<li><b>Review:</b> Likely low risk; verify provenance and signature if required.</li>",
            "<li><b>Document:</b> Record hash + source, close if no anomalies.</li>",
        ]
    return "\n".join(items)


def _kv_table(title: str, data: dict[str, Any], badge_html: str = "") -> str:
    rows = [
        f"<tr><th>{_safe(str(k).replace('_', ' ').title())}</th><td>{_safe(v)}</td></tr>"
        for k, v in data.items()
    ]
    table_rows = "".join(rows) if rows else "<tr><td class='muted'>None</td></tr>"
    return f"""
    <section class="card">
      <div class="section-head">
        <h2>{_safe(title)}</h2>
        {badge_html}
      </div>
      <table class="kv">
        {table_rows}
      </table>
    </section>
    """


def _list_section(title: str, items: list[str], emphasize: bool = False) -> str:
    section_class = "card card-alert" if emphasize and items else "card"
    body = "<p class='muted'>None</p>" if not items else "<ul>" + "".join(f"<li>{_safe(x)}</li>" for x in items) + "</ul>"
    return f"""
    <section class="{section_class}">
      <div class="section-head">
        <h2>{_safe(title)}</h2>
        {badge("Count", len(items))}
      </div>
      {body}
    </section>
    """


def _summary_tiles(data: dict[str, Any]) -> str:
    combined = data.get("combined", {}) or {}
    tiles = [
        ("Static Verdict", data.get("verdict", "")),
        ("Static Score", data.get("score", 0)),
        ("Combined Score", combined.get("total_score", 0)),
        ("Combined Severity", combined.get("severity", "Informational")),
        ("Spec Score", combined.get("subscores", {}).get("spec", 0)),
        ("Dynamic Score", combined.get("subscores", {}).get("dynamic", 0)),
        ("Techniques", len(data.get("techniques", []) or [])),
        ("IOC URLs", data.get("ioc_counts", {}).get("urls", 0)),
    ]
    return '<section class="tile-grid">' + "".join(
        f'<div class="tile"><div class="tile-label">{_safe(label)}</div><div class="tile-value">{_safe(value)}</div></div>'
        for label, value in tiles
    ) + "</section>"


def _write_md(case_dir: Path, data: dict[str, Any]) -> Path:
    report_md = case_dir / "report.md"
    lines: list[str] = []

    lines.append("# Static Triage Ticket")
    lines.append(f"**Generated (UTC):** {_utc()}")
    lines.append("")

    lines.append("## Verdict")
    lines.append(f"- **Static Verdict:** **{data['verdict']}**")
    lines.append(f"- **Static Risk Score:** `{data['score']}/100`")
    lines.append(f"- **Confidence:** `{data['confidence']}`")

    combined = data.get("combined", {}) or {}
    if combined:
        lines.append(f"- **Combined Score:** `{combined.get('total_score', 0)}/100`")
        lines.append(f"- **Combined Severity:** `{combined.get('severity', 'Informational')}`")
        lines.append(
            f"- **Subscores:** static=`{combined.get('subscores', {}).get('static', 0)}` | "
            f"dynamic=`{combined.get('subscores', {}).get('dynamic', 0)}` | "
            f"spec=`{combined.get('subscores', {}).get('spec', 0)}`"
        )
    lines.append("")

    lines.append("## File")
    lines.append(f"- **Name:** `{data['filename']}`")
    lines.append(f"- **Size:** `{data['size_bytes']}` bytes")
    lines.append(f"- **SHA256:** `{data['sha256']}`")
    lines.append(f"- **SHA1:** `{data['sha1']}`")
    lines.append(f"- **MD5:** `{data['md5']}`")

    if data["file_sig"]:
        lines.append(f"- **Type (file):** `{data['file_sig']}`")

    if data.get("signing_summary"):
        ss = data["signing_summary"]
        lines.append(f"- **Signature present:** `{ss.get('signature_present')}`")
        lines.append(f"- **Verified:** `{ss.get('verified')}`")
        if ss.get("verification_status"):
            lines.append(f"- **Verification status:** `{ss.get('verification_status')}`")
        if ss.get("subject"):
            lines.append(f"- **Signer:** `{ss.get('subject')}`")
        if ss.get("tool"):
            lines.append(f"- **Signing tool:** `{ss.get('tool')}`")
        if ss.get("error"):
            lines.append(f"- **Signing note:** `{ss.get('error')}`")
    lines.append("")

    lines.append("## Key Findings")
    if data["suspicious_reasons"]:
        for r in data["suspicious_reasons"]:
            lines.append(f"- {r}")
    else:
        lines.append("- No high-signal suspicious reasons recorded.")
    lines.append("")

    rationale = data.get("verdict_rationale", {}) or {}
    lines.append("## Verdict Rationale")
    lines.append(f"- **Confidence Model:** `{rationale.get('confidence', data.get('confidence', 'N/A'))}`")

    if rationale.get("increased"):
        lines.append("- **Score Increased Because:**")
        for item in rationale["increased"]:
            lines.append(f"  - {item}")

    if rationale.get("decreased"):
        lines.append("- **Score Decreased Because:**")
        for item in rationale["decreased"]:
            lines.append(f"  - {item}")

    if rationale.get("notes"):
        lines.append("- **Notes:**")
        for item in rationale["notes"]:
            lines.append(f"  - {item}")

    if rationale.get("recommended_next_step"):
        lines.append(f"- **Recommended Next Step:** {rationale['recommended_next_step']}")
    lines.append("")

    decoded = data.get("decoded_strings", {}) or {}
    lines.append("## Decoded Strings")
    lines.append(f"- **Decoder Enabled:** `{decoded.get('enabled', False)}`")
    lines.append(f"- **Source:** `{decoded.get('source', 'N/A')}`")
    lines.append(f"- **Decoded Strings Found:** `{decoded.get('decoded_count', 0)}`")
    lines.append(f"- **High-Risk Strings:** `{decoded.get('high_risk_count', 0)}`")

    if decoded.get("high_risk_strings"):
        lines.append("- **Top High-Risk Strings:**")
        for item in decoded["high_risk_strings"]:
            lines.append(f"  - `{item}`")

    if decoded.get("notes"):
        lines.append("- **Decoder Notes:**")
        for item in decoded["notes"]:
            lines.append(f"  - {item}")
    lines.append("")

    if combined.get("evidence"):
        lines.append("## Combined Scoring Evidence")
        for item in combined.get("evidence", [])[:12]:
            if isinstance(item, dict):
                lines.append(
                    f"- **{item.get('source', 'unknown')}** "
                    f"`{item.get('rule', '')}` "
                    f"`{item.get('points', 0):+}` — {item.get('message', '')}"
                )
        lines.append("")

    lines.append("## API Import Analysis")
    api = data["api"]
    if api["present"] and api["returncode"] == 0:
        lines.append(f"- **Imported DLLs:** `{api['dll_count']}`")
        lines.append(f"- **Imported APIs:** `{api['import_count']}`")
        lines.append(f"- **Behavior Categories Hit:** `{api['category_count']}`")
        lines.append(f"- **High Severity API Chains:** `{api['high_chain_count']}`")
    else:
        lines.append("- API analysis artifact not present or returned an error.")
    lines.append("")

    lines.append("## YARA Results")
    yara = data["yara"]
    if yara["present"]:
        lines.append(f"- **Matched:** `{'Yes' if yara['matched'] else 'No'}`")
        lines.append(f"- **Match Count:** `{yara['match_count']}`")
        lines.append(f"- **Rules Scanned:** `{yara['rule_file_count']}`")
        if yara["top_rules"]:
            lines.append("- **Top Matched Rules:**")
            for rule in yara["top_rules"]:
                lines.append(f"  - `{rule}`")
        if yara["error"]:
            lines.append(f"- **Error:** `{yara['error']}`")
    else:
        lines.append("- YARA results artifact not present.")
    lines.append("")

    spec = data["spec"]
    lines.append("## API Spec Risk Analysis")
    if spec["present"]:
        lines.append(f"- **Spec:** `{spec['title']}` `{spec['version']}`")
        lines.append(f"- **Servers:** {', '.join(f'`{x}`' for x in spec['servers']) if spec['servers'] else '`none`'}")
        lines.append(f"- **Auth:** {', '.join(f'`{x}`' for x in spec['auth_summary']) if spec['auth_summary'] else '`none`'}")
        lines.append(f"- **Sensitive unauthenticated endpoints:** `{spec['scoring'].get('sensitive_unauthenticated_endpoints', 0)}`")
        lines.append(f"- **File upload endpoints:** `{spec['scoring'].get('file_upload_endpoints', 0)}`")
        if spec["risk_notes"]:
            for note in spec["risk_notes"]:
                lines.append(f"- {note}")
    else:
        lines.append("- Spec analysis artifact not present.")
    lines.append("")

    capa = data.get("capa", {}) or {}
    lines.append("## ATT&CK / Behavior Density (capa)")
    lines.append(f"- **Technique IDs:** `{len(capa.get('techniques', data.get('techniques', [])) or [])}`")
    lines.append(f"- **Match Count (heuristic):** `{capa.get('match_count', data.get('capa_match_count', 0))}`")
    if capa.get("top_families"):
        fam_conf = capa.get("family_confidence", {}) if isinstance(capa.get("family_confidence"), dict) else {}
        lines.append("- **Likely Behavior Families:** " + ", ".join(f"`{x}` ({fam_conf.get(x, 'medium')})" for x in capa.get("top_families", [])[:5]))
    if capa.get("top_rules"):
        lines.append("- **Top Rules:** " + ", ".join(f"`{x}`" for x in capa.get("top_rules", [])[:8]))
    if capa.get("techniques"):
        lines.append(f"- **Techniques:** {', '.join(f'`{t}`' for t in capa.get('techniques', [])[:20])}")
    else:
        lines.append("- No technique IDs detected in capa output.")
    for note in capa.get("analyst_notes", [])[:4]:
        lines.append(f"- {note}")
    lines.append("")

    lines.append("## IOC Summary")
    c = data["ioc_counts"]
    lines.append(
        f"- Domains: `{c.get('domains', 0)}` | URLs: `{c.get('urls', 0)}` | "
        f"IPs: `{c.get('ips', 0)}` | Emails: `{c.get('emails', 0)}`"
    )
    lines.append(
        f"- Paths: `{c.get('paths', 0)}` | Registry: `{c.get('registry', 0)}` | "
        f"Commands: `{c.get('commands', 0)}`"
    )
    lines.append("")

    report_md.write_text("\n".join(lines), encoding="utf-8", errors="replace")
    return report_md


def _write_html(case_dir: Path, data: dict[str, Any]) -> Path:
    report_html = case_dir / "report.html"

    combined = data.get("combined", {}) or {}
    verdict_rationale = data.get("verdict_rationale", {}) or {}
    decoded = data.get("decoded_strings", {}) or {}
    yara = data.get("yara", {}) or {}
    spec = data.get("spec", {}) or {}
    capa = data.get("capa", {}) or {}

    sample_meta = {
        "Name": data.get("filename", ""),
        "Size Bytes": data.get("size_bytes", 0),
        "SHA256": data.get("sha256", ""),
        "SHA1": data.get("sha1", ""),
        "MD5": data.get("md5", ""),
        "Type (file)": data.get("file_sig", "") or "N/A",
        "Signature Present": (data.get("signing_summary") or {}).get("signature_present", ""),
        "Verified": (data.get("signing_summary") or {}).get("verified", ""),
        "Verification Status": (data.get("signing_summary") or {}).get("verification_status", ""),
        "Signer": (data.get("signing_summary") or {}).get("subject", ""),
    }

    combined_meta = {
        "Total Score": combined.get("total_score", 0),
        "Severity": combined.get("severity", "Informational"),
        "Verdict": combined.get("verdict", ""),
        "Confidence": combined.get("confidence", ""),
        "Static": combined.get("subscores", {}).get("static", 0),
        "Dynamic": combined.get("subscores", {}).get("dynamic", 0),
        "Spec": combined.get("subscores", {}).get("spec", 0),
    }

    decoded_meta = {
        "Decoder Enabled": decoded.get("enabled", False),
        "Source": decoded.get("source", "") or "N/A",
        "Decoded Strings Found": decoded.get("decoded_count", 0),
        "High-Risk Strings": decoded.get("high_risk_count", 0),
    }

    rationale_meta = {
        "Score": verdict_rationale.get("score", data.get("score", 0)),
        "Confidence": verdict_rationale.get("confidence", data.get("confidence", "")),
        "Recommended Next Step": verdict_rationale.get("recommended_next_step", "") or "N/A",
    }

    yara_meta = {
        "Present": yara.get("present", False),
        "Matched": yara.get("matched", False),
        "Match Count": yara.get("match_count", 0),
        "Rules Scanned": yara.get("rule_file_count", 0),
        "Rules Dir": yara.get("rules_dir", "") or "N/A",
        "Error": yara.get("error", "") or "",
    }

    yara_rules = [str(x) for x in (yara.get("top_rules", []) or [])]

    spec_meta = {
        "Present": spec.get("present", False),
        "Title": spec.get("title", ""),
        "Version": spec.get("version", ""),
        "Servers": ", ".join(spec.get("servers", []) or []) or "none",
        "Auth": ", ".join(spec.get("auth_summary", []) or []) or "none",
        "Sensitive unauth": spec.get("scoring", {}).get("sensitive_unauthenticated_endpoints", 0),
        "File uploads": spec.get("scoring", {}).get("file_upload_endpoints", 0),
    }


    capa_meta = {
        "Present": capa.get("present", False),
        "Technique IDs": len(capa.get("techniques", []) or []),
        "Match Count": capa.get("match_count", data.get("capa_match_count", 0)),
        "Top Families": ", ".join(
            f"{name} ({(capa.get('family_confidence', {}) if isinstance(capa.get('family_confidence'), dict) else {}).get(name, 'medium')})"
            for name in capa.get("top_families", [])[:4]
        ) or "none",
    }

    evidence = [
        f"{item.get('source', 'unknown')} | {item.get('rule', '')} | {item.get('points', 0):+} | {item.get('message', '')}"
        for item in combined.get("evidence", [])
        if isinstance(item, dict)
    ]

    action_items = [
        re.sub(r"<[^>]+>", "", x).strip()
        for x in re.findall(r"<li>(.*?)</li>", data.get("actions_html", ""))
    ]

    sample_meta_html = _kv_table("Sample Metadata", sample_meta)
    combined_html = _kv_table(
        "Combined Scoring",
        combined_meta,
        score_badge("Total", combined.get("total_score", 0)),
    )
    rationale_html = _kv_table(
        "Verdict Rationale",
        rationale_meta,
        badge("Confidence", verdict_rationale.get("confidence", data.get("confidence", "N/A"))),
    )
    capa_html = _kv_table(
        "Capa Evidence Summary",
        capa_meta,
        badge("Families", len(capa.get("top_families", []) or [])),
    ) if capa.get("present") else ""
    # Only show Decoded Strings card if there is real decoded-string data
    show_decoded_card = (
        decoded.get("enabled", False)
        or int(decoded.get("decoded_count", 0) or 0) > 0
        or int(decoded.get("high_risk_count", 0) or 0) > 0
    )

    decoded_html = _kv_table(
        "Decoded Strings",
        decoded_meta,
        badge("High Risk", decoded.get("high_risk_count", 0)),
    ) if show_decoded_card else ""

    # Only show Spec card if spec analysis is actually present
    show_spec_card = bool(spec.get("present", False))

    spec_html = _kv_table(
        "Spec Risk Analysis",
        spec_meta,
        badge("Spec Score", combined.get("subscores", {}).get("spec", 0)),
    ) if show_spec_card else ""

    show_yara_card = (
        yara.get("present", False)
        and (
            yara.get("matched", False)
            or int(yara.get("match_count", 0) or 0) > 0
            or int(yara.get("rule_file_count", 0) or 0) > 0
        )
    )

    yara_html = _kv_table(
        "YARA Results",
        yara_meta,
        badge("Matches", yara.get("match_count", 0)),
    ) if show_yara_card else ""

    # Only show sections when they contain data
    increased_section = _list_section(
        "Why Score Increased",
        verdict_rationale.get("increased", []),
        emphasize=True,
    ) if verdict_rationale.get("increased") else ""

    decreased_section = _list_section(
        "Why Score Decreased",
        verdict_rationale.get("decreased", []),
    ) if verdict_rationale.get("decreased") else ""

    notes_section = _list_section(
        "Verdict Notes",
        verdict_rationale.get("notes", []),
    ) if verdict_rationale.get("notes") else ""

    decoded_strings_section = _list_section(
        "High-Risk Decoded Strings",
        decoded.get("high_risk_strings", []),
        emphasize=True,
    ) if decoded.get("high_risk_strings") else ""

    decoder_notes_section = _list_section(
        "Decoder Notes",
        decoded.get("notes", []),
    ) if (
        decoded.get("enabled", False)
        or int(decoded.get("decoded_count", 0) or 0) > 0
        or int(decoded.get("high_risk_count", 0) or 0) > 0
    ) and decoded.get("notes") else ""

    spec_notes_section = _list_section(
        "Spec Risk Notes",
        spec.get("risk_notes", []),
        emphasize=True,
    ) if spec.get("risk_notes") else ""

    suspicious_section = _list_section(
        "Key Findings (Suspicious)",
        data.get("suspicious_reasons", []),
        emphasize=True,
    ) if data.get("suspicious_reasons") else ""

    benign_section = _list_section(
        "Context (Benign / Low signal)",
        data.get("benign_reasons", []),
    ) if data.get("benign_reasons") else ""

    actions_section = _list_section(
        "Recommended Actions",
        action_items,
        emphasize=True,
    ) if action_items else ""

    yara_rules_section = _list_section(
        "YARA Matched Rules",
        yara_rules,
        emphasize=True,
    ) if yara_rules else ""

    capa_rules_section = _list_section(
        "Top capa Rules",
        capa.get("top_rules", []),
        emphasize=True,
    ) if capa.get("top_rules") else ""

    capa_notes_section = _list_section(
        "capa Analyst Notes",
        capa.get("analyst_notes", []),
    ) if capa.get("analyst_notes") else ""

    evidence_section = _list_section(
        "Combined Evidence",
        evidence,
        emphasize=True,
    ) if evidence else ""

    subtitle = f"Generated (UTC): {_safe(data.get('generated_utc', ''))}"

    body_html = f"""
{_summary_tiles(data)}
<div class="grid">
  {sample_meta_html}
  {combined_html}
  {rationale_html}
  {decoded_html}
  {spec_html}
  {yara_html}
</div>
{increased_section}
{decreased_section}
{notes_section}
{decoded_strings_section}
{decoder_notes_section}
{yara_rules_section}
{capa_rules_section}
{capa_notes_section}
{evidence_section}
{spec_notes_section}
{suspicious_section}
{benign_section}
{actions_section}
"""

    verdict = str(data.get("verdict", "UNKNOWN"))
    verdict_class = "sev-none"
    if verdict.upper() == "MALICIOUS":
        verdict_class = "sev-high"
    elif verdict.upper() == "SUSPICIOUS":
        verdict_class = "sev-med"
    elif verdict.upper() == "LOW_RISK":
        verdict_class = "sev-low"

    html_doc = report_page(
        "Static Triage Ticket",
        subtitle,
        verdict,
        verdict_class,
        body_html,
    )

    report_html.write_text(html_doc, encoding="utf-8", errors="replace")
    return report_html


def generate_reports(case_dir: Path) -> dict[str, Any]:
    summary = _read_json(case_dir / "summary.json")
    iocs_j = _read_json(case_dir / "iocs.json")

    sample = summary.get("sample", {}) if isinstance(summary.get("sample"), dict) else {}
    filename = str(sample.get("filename", ""))
    size_bytes = int(sample.get("size_bytes", 0) or 0)
    sha256 = str(sample.get("sha256", ""))
    sha1 = str(sample.get("sha1", ""))
    md5 = str(sample.get("md5", ""))

    verdict = str(summary.get("verdict", "UNKNOWN"))
    score = int(summary.get("risk_score", 0) or 0)
    confidence = str(summary.get("confidence", "") or "N/A")

    file_sig = _first_line(case_dir / "file.txt")
    techs, match_count = _extract_attack_techniques_from_capa(case_dir / "capa.json")
    capa = _capa_evidence_block(case_dir)
    susp, ben = _top_reasons(summary, max_items=6)
    counts = _ioc_counts_from_summary(summary, iocs_j)
    artifacts = _artifact_links(case_dir)
    api = _api_block(case_dir)
    spec = _spec_block(case_dir)
    combined = _combined_block(case_dir)
    yara = _yara_block(case_dir)
    decoded_strings = _decoded_strings_block(summary)
    verdict_rationale = _verdict_rationale_block(summary)

    signing = summary.get("signing") if isinstance(summary.get("signing"), dict) else {}
    signing_summary = (
        {
            "signature_present": bool(signing.get("signature_present"))
            or bool(signing.get("subject"))
            or bool(signing.get("verify_ok")),
            "verified": bool(signing.get("verify_ok")),
            "verification_status": signing.get("verification_status", "") or (
                "verified"
                if signing.get("verify_ok")
                else (
                    "signed_unverified"
                    if (signing.get("signature_present") or signing.get("subject"))
                    else "unsigned"
                )
            ),
            "subject": signing.get("subject", "") or "",
            "tool": signing.get("tool", "") or "",
            "error": signing.get("error", "") or "",
        }
        if signing
        else {}
    )

    data = {
        "generated_utc": _utc(),
        "verdict": verdict,
        "score": score,
        "confidence": confidence,
        "filename": filename,
        "size_bytes": size_bytes,
        "sha256": sha256,
        "sha1": sha1,
        "md5": md5,
        "file_sig": file_sig,
        "techniques": techs,
        "capa_match_count": match_count,
        "capa": capa,
        "suspicious_reasons": susp,
        "benign_reasons": ben,
        "ioc_counts": counts,
        "artifacts": artifacts,
        "actions_html": _actions_html(combined.get("total_score", score)),
        "subfiles": _subfiles_block(summary),
        "signing_summary": signing_summary,
        "api": api,
        "yara": yara,
        "spec": spec,
        "combined": combined,
        "decoded_strings": decoded_strings,
        "verdict_rationale": verdict_rationale,
    }

    report_md = _write_md(case_dir, data)
    report_html = _write_html(case_dir, data)

    report_pdf: Optional[Path] = None
    try:
        from weasyprint import HTML  # type: ignore

        report_pdf = case_dir / "report.pdf"
        HTML(filename=str(report_html)).write_pdf(str(report_pdf))
    except Exception:
        report_pdf = None

    return {
        "report_md": str(report_md),
        "report_html": str(report_html),
        "report_pdf": str(report_pdf) if report_pdf else None,
    }