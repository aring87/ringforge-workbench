
from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional
from dynamic_analysis.report_theme import badge, report_page
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


def _top_reasons(summary: dict[str, Any], max_items: int = 6) -> Tuple[List[str], List[str]]:
    rb = summary.get("reason_breakdown")
    if isinstance(rb, dict):
        susp = rb.get("suspicious", []) if isinstance(rb.get("suspicious"), list) else []
        ben = rb.get("benign", []) if isinstance(rb.get("benign"), list) else []
        return ([str(x) for x in susp][:max_items], [str(x) for x in ben][:max_items])

    reasons = summary.get("reasons")
    if isinstance(reasons, list):
        s_out, b_out = [], []
        for x in reasons:
            sx = str(x)
            if sx.upper().startswith("SUSPICIOUS:"):
                s_out.append(sx.replace("SUSPICIOUS:", "", 1).strip())
            elif sx.upper().startswith("BENIGN:"):
                b_out.append(sx.replace("BENIGN:", "", 1).strip())
        return (s_out[:max_items], b_out[:max_items])

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
    return {"top": top[:5], "attn": attn[:10], "crit": crit}


def _api_block(case_dir: Path) -> dict[str, Any]:
    api = _read_json(case_dir / "api_analysis.json")
    summary = api.get("summary") if isinstance(api.get("summary"), dict) else {}
    category_hits = api.get("category_hits") if isinstance(api.get("category_hits"), dict) else {}
    chain_findings = api.get("chain_findings") if isinstance(api.get("chain_findings"), list) else []
    imports_by_dll = api.get("imports_by_dll") if isinstance(api.get("imports_by_dll"), dict) else {}

    high = [x for x in chain_findings if isinstance(x, dict) and x.get("severity") == "high"]
    med = [x for x in chain_findings if isinstance(x, dict) and x.get("severity") == "medium"]

    top_categories = []
    for cat, funcs in category_hits.items():
        if isinstance(funcs, list):
            top_categories.append((str(cat), len(funcs), [str(x) for x in funcs[:12]]))
    top_categories.sort(key=lambda x: x[1], reverse=True)

    dll_preview = []
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
        lines.append(f"- **Subscores:** static=`{combined.get('subscores', {}).get('static', 0)}` | dynamic=`{combined.get('subscores', {}).get('dynamic', 0)}` | spec=`{combined.get('subscores', {}).get('spec', 0)}`")
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
        lines.append(f"- **Signed (verified):** `{ss.get('signed_ok')}`")
        if ss.get("subject"):
            lines.append(f"- **Signer:** `{ss.get('subject')}`")
    lines.append("")

    lines.append("## Key Findings")
    if data["suspicious_reasons"]:
        for r in data["suspicious_reasons"]:
            lines.append(f"- {r}")
    else:
        lines.append("- No high-signal suspicious reasons recorded.")
    lines.append("")

    if combined.get("evidence"):
        lines.append("## Combined Scoring Evidence")
        for item in combined.get("evidence", [])[:12]:
            if isinstance(item, dict):
                lines.append(f"- **{item.get('source','unknown')}** `{item.get('rule','')}` `{item.get('points',0):+}` — {item.get('message','')}")
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

    lines.append("## ATT&CK / Behavior Density (capa)")
    lines.append(f"- **Technique IDs:** `{len(data['techniques'])}`")
    lines.append(f"- **Match Count (heuristic):** `{data['capa_match_count']}`")
    if data["techniques"]:
        lines.append(f"- **Techniques:** {', '.join(f'`{t}`' for t in data['techniques'][:20])}")
    else:
        lines.append("- No technique IDs detected in capa output.")
    lines.append("")

    lines.append("## IOC Summary")
    c = data["ioc_counts"]
    lines.append(f"- Domains: `{c.get('domains',0)}` | URLs: `{c.get('urls',0)}` | IPs: `{c.get('ips',0)}` | Emails: `{c.get('emails',0)}`")
    lines.append(f"- Paths: `{c.get('paths',0)}` | Registry: `{c.get('registry',0)}`")
    lines.append("")
    report_md.write_text("\n".join(lines), encoding="utf-8", errors="replace")
    return report_md


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
    rows = [f"<tr><th>{_safe(str(k).replace('_', ' ').title())}</th><td>{_safe(v)}</td></tr>" for k, v in data.items()]
    return f"""
    <section class="card">
      <div class="section-head">
        <h2>{_safe(title)}</h2>
        {badge_html}
      </div>
      <table class="kv">
        {''.join(rows) if rows else "<tr><td class='muted'>None</td></tr>"}
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
        f"""<div class="tile"><div class="tile-label">{_safe(label)}</div><div class="tile-value">{_safe(value)}</div></div>"""
        for label, value in tiles
    ) + "</section>"


def _write_html(case_dir: Path, data: dict[str, Any]) -> Path:
    report_html = case_dir / "report.html"
    combined = data.get("combined", {}) or {}
    sample_meta = {
        "Name": data.get("filename", ""),
        "Size Bytes": data.get("size_bytes", 0),
        "SHA256": data.get("sha256", ""),
        "SHA1": data.get("sha1", ""),
        "MD5": data.get("md5", ""),
        "Type (file)": data.get("file_sig", "") or "N/A",
        "Signed (verified)": (data.get("signing_summary") or {}).get("signed_ok", ""),
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
    spec = data.get("spec", {}) or {}
    spec_meta = {
        "Present": spec.get("present", False),
        "Title": spec.get("title", ""),
        "Version": spec.get("version", ""),
        "Servers": ", ".join(spec.get("servers", []) or []) or "none",
        "Auth": ", ".join(spec.get("auth_summary", []) or []) or "none",
        "Sensitive unauth": spec.get("scoring", {}).get("sensitive_unauthenticated_endpoints", 0),
        "File uploads": spec.get("scoring", {}).get("file_upload_endpoints", 0),
    }
    evidence = [
        f"{item.get('source','unknown')} | {item.get('rule','')} | {item.get('points',0):+} | {item.get('message','')}"
        for item in combined.get("evidence", []) if isinstance(item, dict)
    ]
    subtitle = f"Generated (UTC): {_safe(data.get('generated_utc', ''))}"
    body_html = f"""
{_summary_tiles(data)}
<div class="grid">
  {_kv_table("Sample Metadata", sample_meta)}
  {_kv_table("Combined Scoring", combined_meta, badge("Total", combined.get("total_score", 0)))}
  {_kv_table("Spec Risk Analysis", spec_meta, badge("Spec Score", combined.get("subscores", {}).get("spec", 0)))}
</div>
{_list_section("Combined Evidence", evidence, emphasize=True)}
{_list_section("Spec Risk Notes", spec.get("risk_notes", []), emphasize=True)}
{_list_section("Key Findings (Suspicious)", data.get("suspicious_reasons", []), emphasize=True)}
{_list_section("Context (Benign / Low signal)", data.get("benign_reasons", []))}
{_list_section("Recommended Actions", [re.sub(r'<[^>]+>', '', x) for x in re.findall(r'<li>(.*?)</li>', data.get("actions_html", ""))], emphasize=True)}
"""
    verdict = str(data.get("verdict", "UNKNOWN"))
    verdict_class = "sev-none"
    if verdict.upper() == "MALICIOUS":
        verdict_class = "sev-high"
    elif verdict.upper() == "SUSPICIOUS":
        verdict_class = "sev-med"
    elif verdict.upper() == "LOW_RISK":
        verdict_class = "sev-low"

    html_doc = report_page("Static Triage Ticket", subtitle, verdict, verdict_class, body_html)
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
    confidence = str(summary.get("confidence", "")) or "N/A"

    file_sig = _first_line(case_dir / "file.txt")
    techs, match_count = _extract_attack_techniques_from_capa(case_dir / "capa.json")
    susp, ben = _top_reasons(summary, max_items=6)
    counts = _ioc_counts(iocs_j)
    artifacts = _artifact_links(case_dir)
    api = _api_block(case_dir)
    spec = _spec_block(case_dir)
    combined = _combined_block(case_dir)

    signing = summary.get("signing") if isinstance(summary.get("signing"), dict) else {}
    signing_summary = {"signed_ok": bool(signing.get("verify_ok")) and bool(signing.get("timestamp_verified")), "subject": signing.get("subject", "") or ""} if signing else {}

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
        "suspicious_reasons": susp,
        "benign_reasons": ben,
        "ioc_counts": counts,
        "artifacts": artifacts,
        "actions_html": _actions_html(combined.get("total_score", score)),
        "subfiles": _subfiles_block(summary),
        "signing_summary": signing_summary,
        "api": api,
        "spec": spec,
        "combined": combined,
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

    return {"report_md": str(report_md), "report_html": str(report_html), "report_pdf": str(report_pdf) if report_pdf else None}
