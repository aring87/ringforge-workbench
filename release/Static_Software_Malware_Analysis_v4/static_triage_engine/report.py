from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_text(p: Path, limit: int = 250_000) -> str:
    if not p.exists():
        return ""
    s = p.read_text(encoding="utf-8", errors="replace")
    if len(s) <= limit:
        return s
    return s[:limit] + "\n\n[...truncated...]\n"


def _read_json(p: Path) -> Dict[str, Any]:
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
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
    match_count = blob.count('"matches"')
    return (techs, match_count)


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
    out = {}
    out["domains"] = len(obs.get("domains", []) or []) if isinstance(obs.get("domains"), list) else 0
    out["urls"] = len(obs.get("urls", []) or []) if isinstance(obs.get("urls"), list) else 0
    out["ips"] = len(obs.get("ips", []) or []) if isinstance(obs.get("ips"), list) else 0
    out["emails"] = len(obs.get("emails", []) or []) if isinstance(obs.get("emails"), list) else 0
    out["paths"] = len(obs.get("paths", []) or []) if isinstance(obs.get("paths"), list) else 0
    out["registry"] = len(obs.get("registry_keys", []) or []) if isinstance(obs.get("registry_keys"), list) else 0
    return out


def _top_reasons(summary: dict[str, Any], max_items: int = 6) -> Tuple[List[str], List[str]]:
    rb = summary.get("reason_breakdown")
    if isinstance(rb, dict):
        susp = rb.get("suspicious", [])
        ben = rb.get("benign", [])
        if not isinstance(susp, list):
            susp = []
        if not isinstance(ben, list):
            ben = []
        return ([str(x) for x in susp][:max_items], [str(x) for x in ben][:max_items])

    reasons = summary.get("reasons")
    if isinstance(reasons, list):
        s_out: List[str] = []
        b_out: List[str] = []
        for x in reasons:
            sx = str(x)
            if sx.upper().startswith("SUSPICIOUS:"):
                s_out.append(sx.replace("SUSPICIOUS:", "", 1).strip())
            elif sx.upper().startswith("BENIGN:"):
                b_out.append(sx.replace("BENIGN:", "", 1).strip())
        return (s_out[:max_items], b_out[:max_items])

    if isinstance(reasons, dict):
        suspicious = reasons.get("suspicious", [])
        benign = reasons.get("benign", [])
        if not isinstance(suspicious, list):
            suspicious = []
        if not isinstance(benign, list):
            benign = []
        return ([str(x) for x in suspicious][:max_items], [str(x) for x in benign][:max_items])

    return ([], [])


def _artifact_links(case_dir: Path) -> List[Tuple[str, Path]]:
    want = [
        ("report.md", case_dir / "report.md"),
        ("report.html", case_dir / "report.html"),
        ("report.pdf", case_dir / "report.pdf"),
        ("summary.json", case_dir / "summary.json"),
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
    top = sr.get("top_scoring_subfiles", [])
    attn = sr.get("attention_subfiles", [])
    crit = sr.get("criteria", {})
    if not isinstance(top, list):
        top = []
    if not isinstance(attn, list):
        attn = []
    if not isinstance(crit, dict):
        crit = {}
    return {"top": top[:5], "attn": attn[:10], "crit": crit}


def _api_block(case_dir: Path) -> dict[str, Any]:
    api = _read_json(case_dir / "api_analysis.json")
    if not isinstance(api, dict):
        api = {}

    summary = api.get("summary") if isinstance(api.get("summary"), dict) else {}
    category_hits = api.get("category_hits") if isinstance(api.get("category_hits"), dict) else {}
    chain_findings = api.get("chain_findings") if isinstance(api.get("chain_findings"), list) else []
    all_imports = api.get("all_imports") if isinstance(api.get("all_imports"), list) else []
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
        "all_imports_preview": [str(x) for x in all_imports[:40]],
    }


def _write_md(case_dir: Path, data: dict[str, Any]) -> Path:
    report_md = case_dir / "report.md"
    lines: list[str] = []
    lines.append("# Static Triage Ticket")
    lines.append(f"**Generated (UTC):** {_utc()}")
    lines.append("")

    lines.append("## Verdict")
    lines.append(f"- **Verdict:** **{data['verdict']}**")
    lines.append(f"- **Risk Score:** `{data['score']}/100`")
    lines.append(f"- **Confidence:** `{data['confidence']}`")
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

    lines.append("## API Analysis")
    api = data["api"]
    if api["present"] and api["returncode"] == 0:
        lines.append(f"- **Imported DLLs:** `{api['dll_count']}`")
        lines.append(f"- **Imported APIs:** `{api['import_count']}`")
        lines.append(f"- **Behavior Categories Hit:** `{api['category_count']}`")
        lines.append(f"- **High Severity API Chains:** `{api['high_chain_count']}`")
        if api["top_categories"]:
            lines.append("")
            lines.append("### API Categories")
            for cat, count, funcs in api["top_categories"]:
                lines.append(f"- **{cat}** (`{count}`): {', '.join(f'`{x}`' for x in funcs)}")
        if api["high_chains"] or api["medium_chains"]:
            lines.append("")
            lines.append("### API Behavior Chains")
            for item in api["high_chains"] + api["medium_chains"]:
                name = item.get("name", "")
                sev = item.get("severity", "")
                hits = item.get("matched_apis", []) if isinstance(item.get("matched_apis"), list) else []
                lines.append(f"- **{name}** (`{sev}`): {', '.join(f'`{x}`' for x in hits[:12])}")
        if api["top_dlls"]:
            lines.append("")
            lines.append("### Top Imported DLLs")
            for dll, count, funcs in api["top_dlls"]:
                lines.append(f"- **{dll}** (`{count}` imports): {', '.join(f'`{x}`' for x in funcs)}")
    elif api["present"]:
        lines.append(f"- API analysis returned an error: `{api['error']}`")
    else:
        lines.append("- API analysis artifact not present.")
    lines.append("")

    lines.append("## ATT&CK / Behavior Density (capa)")
    lines.append(f"- **Technique IDs:** `{len(data['techniques'])}`")
    lines.append(f"- **Match Count (heuristic):** `{data['capa_match_count']}`")
    if data["techniques"]:
        lines.append(f"- **Techniques:** {', '.join(f'`{t}`' for t in data['techniques'][:20])}")
        if len(data["techniques"]) > 20:
            lines.append("- (…truncated; see capa.json/capa.txt for full)")
    else:
        lines.append("- No technique IDs detected in capa output.")
    lines.append("")

    lines.append("## IOC Summary")
    c = data["ioc_counts"]
    lines.append(
        f"- Domains: `{c.get('domains',0)}` | URLs: `{c.get('urls',0)}` | IPs: `{c.get('ips',0)}` | Emails: `{c.get('emails',0)}`"
    )
    lines.append(f"- Paths: `{c.get('paths',0)}` | Registry: `{c.get('registry',0)}`")
    lines.append("- Full IOC list: `iocs.csv` / `iocs.json`")
    lines.append("")

    sub = data["subfiles"]
    lines.append("## Embedded Payloads")
    if sub["top"]:
        lines.append("### Top Scoring Embedded Payloads (Top 5)")
        for r in sub["top"]:
            name = r.get("name") or r.get("filename") or "subfile"
            score = r.get("score")
            verdict = r.get("verdict", "")
            signed_ok = r.get("signed_ok")
            signer = r.get("signer", "")
            lines.append(f"- `{name}` — score `{score}` — `{verdict}` — Signed: `{signed_ok}`" + (f" — Signer: `{signer}`" if signer else ""))
    else:
        lines.append("- No subfile triage results recorded.")
    lines.append("")
    lines.append("### Attention (if any)")
    crit = sub["crit"] or {}
    lines.append(f"- Criteria: score >= `{crit.get('score_ge',60)}` OR unsigned/unverified OR high-signal override")
    if sub["attn"]:
        for r in sub["attn"]:
            name = r.get("name") or r.get("filename") or "subfile"
            score = r.get("score")
            verdict = r.get("verdict", "")
            signed_ok = r.get("signed_ok")
            lines.append(f"- `{name}` — score `{score}` — `{verdict}` — Signed: `{signed_ok}`")
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Recommended Actions")
    if data["score"] >= 85:
        lines.append("- **Containment:** Isolate affected endpoint(s) and block SHA256 where applicable.")
        lines.append("- **Hunt:** Search for these hashes and any extracted IOCs across EDR/SIEM.")
        lines.append("- **Detonation (controlled):** If permitted, run in an isolated sandbox to confirm runtime behavior.")
    elif data["score"] >= 60:
        lines.append("- **Triage:** Validate signature/Publisher, compare against known-good installer, and review capa/API findings.")
        lines.append("- **Hunt:** Search for IOCs and hash occurrences in logs.")
    else:
        lines.append("- **Review:** Likely low risk; verify provenance (source) and signature if required.")
    lines.append("")

    lines.append("## Evidence / Artifacts")
    for label, p in data["artifacts"]:
        lines.append(f"- `{label}` -> `{p.name}`")
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
            "<li><b>Review:</b> Inspect capa techniques, API chains, and suspicious reasons.</li>",
            "<li><b>Hunt:</b> Search IOCs and hash across telemetry.</li>",
        ]
    else:
        items = [
            "<li><b>Review:</b> Likely low risk; verify provenance and signature if required.</li>",
            "<li><b>Document:</b> Record hash + source, close if no anomalies.</li>",
        ]
    return "\n".join(items)


def _subfiles_html(sub: dict[str, Any]) -> str:
    top = sub.get("top", [])
    attn = sub.get("attn", [])
    crit = sub.get("crit", {}) or {}
    score_ge = crit.get("score_ge", 60)

    def row(r: dict[str, Any]) -> str:
        name = _safe(r.get("name") or r.get("filename") or "subfile")
        score = _safe(r.get("score"))
        verdict = _safe(r.get("verdict", ""))
        signed_ok = _safe(r.get("signed_ok"))
        signer = _safe(r.get("signer", ""))
        extra = f"<div class='small muted'>Signer: <code>{signer}</code></div>" if signer else ""
        return f"<li><b><code>{name}</code></b> — score <code>{score}</code> — <code>{verdict}</code> — Signed: <code>{signed_ok}</code>{extra}</li>"

    top_html = "".join(row(r) for r in top) or "<li>None</li>"
    attn_html = "".join(row(r) for r in attn) or "<li>None</li>"

    return f"""
      <div class="card">
        <div style="font-weight:700; margin-bottom:8px;">Embedded Payloads</div>
        <div class="small muted">Attention criteria: score &ge; <code>{_safe(score_ge)}</code> OR unsigned/unverified OR high-signal override</div>
        <div style="margin-top:10px; font-weight:700;">Top Scoring (Top 5)</div>
        <ul>{top_html}</ul>
        <div style="margin-top:10px; font-weight:700;">Attention</div>
        <ul>{attn_html}</ul>
      </div>
    """


def _api_html(api: dict[str, Any]) -> str:
    if not api.get("present"):
        return """
        <div class="card">
          <div style="font-weight:700; margin-bottom:8px;">API Analysis</div>
          <div class="small muted">API analysis artifact not present.</div>
        </div>
        """

    if api.get("returncode", 0) != 0:
        return f"""
        <div class="card">
          <div style="font-weight:700; margin-bottom:8px;">API Analysis</div>
          <div class="small muted">API analysis returned an error.</div>
          <div><code>{_safe(api.get("error",""))}</code></div>
        </div>
        """

    cat_html = ""
    for cat, count, funcs in api.get("top_categories", []):
        cat_html += f"<li><b>{_safe(cat)}</b> — <code>{_safe(count)}</code> hits — {', '.join(f'<code>{_safe(x)}</code>' for x in funcs)}</li>"
    if not cat_html:
        cat_html = "<li>None</li>"

    chain_items = []
    for item in api.get("high_chains", []) + api.get("medium_chains", []):
        name = _safe(item.get("name", ""))
        sev = _safe(item.get("severity", ""))
        hits = item.get("matched_apis", []) if isinstance(item.get("matched_apis"), list) else []
        hit_html = ", ".join(f"<code>{_safe(x)}</code>" for x in hits[:12])
        chain_items.append(f"<li><b>{name}</b> — <code>{sev}</code> — {hit_html}</li>")
    chain_html = "".join(chain_items) or "<li>None</li>"

    dll_items = []
    for dll, count, funcs in api.get("top_dlls", []):
        func_html = ", ".join(f"<code>{_safe(x)}</code>" for x in funcs)
        dll_items.append(f"<li><b>{_safe(dll)}</b> — <code>{_safe(count)}</code> imports — {func_html}</li>")
    dll_html = "".join(dll_items) or "<li>None</li>"

    return f"""
      <div class="card">
        <div style="font-weight:700; margin-bottom:8px;">API Analysis</div>
        <div class="kv">
          <div>Imported DLLs</div><div><code>{_safe(api.get("dll_count",0))}</code></div>
          <div>Imported APIs</div><div><code>{_safe(api.get("import_count",0))}</code></div>
          <div>Behavior Categories</div><div><code>{_safe(api.get("category_count",0))}</code></div>
          <div>High Severity Chains</div><div><code>{_safe(api.get("high_chain_count",0))}</code></div>
        </div>
        <div style="margin-top:10px; font-weight:700;">Top Categories</div>
        <ul>{cat_html}</ul>
        <div style="margin-top:10px; font-weight:700;">Behavior Chains</div>
        <ul>{chain_html}</ul>
        <div style="margin-top:10px; font-weight:700;">Top Imported DLLs</div>
        <ul>{dll_html}</ul>
      </div>
    """


def _write_html(case_dir: Path, data: dict[str, Any]) -> Path:
    report_html = case_dir / "report.html"

    verdict_class = "benign"
    if data["verdict"].upper() in ("MALICIOUS",):
        verdict_class = "malicious"
    elif data["verdict"].upper() in ("SUSPICIOUS",):
        verdict_class = "suspicious"
    elif data["verdict"].upper() in ("LOW_RISK",):
        verdict_class = "lowrisk"

    ev_items = []
    for label, p in data["artifacts"]:
        ev_items.append(f'<li><a href="{_safe(p.name)}">{_safe(label)}</a></li>')
    ev_html = "\n".join(ev_items) if ev_items else "<li>No artifacts found.</li>"

    susp_html = "".join(f"<li>{_safe(x)}</li>" for x in data["suspicious_reasons"]) or "<li>None</li>"
    ben_html = "".join(f"<li>{_safe(x)}</li>" for x in data["benign_reasons"]) or "<li>None</li>"

    techs = data["techniques"][:24]
    tech_html = " ".join(f"<span class='pill'>{_safe(t)}</span>" for t in techs) or "<span class='muted'>None detected</span>"

    c = data["ioc_counts"]
    file_sig = _safe(data["file_sig"])
    if file_sig and len(file_sig) > 160:
        file_sig = file_sig[:160] + "…"

    signing_line = ""
    ss = data.get("signing_summary") or {}
    if ss:
        signing_line = f"""
          <div>Signed (verified): <code>{_safe(ss.get("signed_ok"))}</code></div>
          <div>Signer: <code>{_safe(ss.get("subject",""))}</code></div>
        """

    html_doc = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Static Triage Ticket</title>
  <style>
    body {{ margin: 0; padding: 24px; font-family: Arial, sans-serif; background:#ffffff; color:#111; }}
    .container {{ max-width: 980px; margin: 0 auto; }}
    .row {{ display: flex; gap: 12px; flex-wrap: wrap; }}
    .card {{ border: 1px solid #e5e7eb; border-radius: 10px; padding: 14px 16px; background: #fff; flex: 1; min-width: 280px; }}
    .header {{ display:flex; align-items:center; justify-content:space-between; margin-bottom: 12px; }}
    .title {{ font-size: 20px; font-weight: 700; }}
    .small {{ color:#555; font-size: 12px; }}
    .banner {{ border-radius: 12px; padding: 14px 16px; color: #fff; margin-bottom: 14px; }}
    .banner.benign {{ background: #1f8f5f; }}
    .banner.lowrisk {{ background: #5aa0d6; }}
    .banner.suspicious {{ background: #c99b2b; }}
    .banner.malicious {{ background: #d14b4b; }}
    .kv {{ display:grid; grid-template-columns: 160px 1fr; gap: 6px 12px; font-size: 13px; }}
    .kv div:nth-child(odd) {{ color:#444; }}
    code {{ background:#f3f4f6; padding:2px 4px; border-radius: 4px; }}
    ul {{ margin: 8px 0 0 18px; }}
    .pill {{ display:inline-block; border:1px solid #e5e7eb; border-radius: 999px; padding: 4px 8px; margin: 3px 4px 0 0; font-size: 12px; background: #f9fafb; }}
    .muted {{ color:#666; }}
    .actions li {{ margin: 6px 0; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="title">Static Triage Ticket</div>
      <div class="small">Generated (UTC): {_safe(data["generated_utc"])}</div>
    </div>

    <div class="banner {verdict_class}">
      <div style="font-size:16px; font-weight:700;">Verdict: {_safe(data["verdict"])} &nbsp;|&nbsp; Score: {_safe(data["score"])}/100 &nbsp;|&nbsp; Confidence: {_safe(data["confidence"])}</div>
      <div style="font-size:12px; opacity:0.95; margin-top:6px;">
        SHA256: <code>{_safe(data["sha256"])}</code>
      </div>
    </div>

    <div class="row">
      <div class="card">
        <div style="font-weight:700; margin-bottom:8px;">File</div>
        <div class="kv">
          <div>Name</div><div><code>{_safe(data["filename"])}</code></div>
          <div>Size</div><div><code>{_safe(data["size_bytes"])}</code> bytes</div>
          <div>Type (file)</div><div><code>{file_sig or "N/A"}</code></div>
          <div>SHA256</div><div><code>{_safe(data["sha256"])}</code></div>
          <div>SHA1</div><div><code>{_safe(data["sha1"])}</code></div>
          <div>MD5</div><div><code>{_safe(data["md5"])}</code></div>
        </div>
        <div style="margin-top:10px;">{signing_line}</div>
      </div>

      <div class="card">
        <div style="font-weight:700; margin-bottom:8px;">ATT&CK / Behavior (capa)</div>
        <div class="kv">
          <div>Technique IDs</div><div><code>{len(data["techniques"])}</code></div>
          <div>Match Count</div><div><code>{_safe(data["capa_match_count"])}</code></div>
        </div>
        <div style="margin-top:8px;">{tech_html}</div>
        <div class="small" style="margin-top:8px;">See <code>capa.json</code> / <code>capa.txt</code> for full details.</div>
      </div>
    </div>

    <div class="row" style="margin-top:12px;">
      {_api_html(data["api"])}
    </div>

    <div class="row" style="margin-top:12px;">
      <div class="card">
        <div style="font-weight:700; margin-bottom:8px;">Key Findings (Suspicious)</div>
        <ul>{susp_html}</ul>
      </div>

      <div class="card">
        <div style="font-weight:700; margin-bottom:8px;">Context (Benign / Low signal)</div>
        <ul>{ben_html}</ul>
      </div>
    </div>

    <div class="row" style="margin-top:12px;">
      <div class="card">
        <div style="font-weight:700; margin-bottom:8px;">IOC Summary</div>
        <div class="kv">
          <div>Domains</div><div><code>{_safe(c.get("domains",0))}</code></div>
          <div>URLs</div><div><code>{_safe(c.get("urls",0))}</code></div>
          <div>IPs</div><div><code>{_safe(c.get("ips",0))}</code></div>
          <div>Emails</div><div><code>{_safe(c.get("emails",0))}</code></div>
          <div>Paths</div><div><code>{_safe(c.get("paths",0))}</code></div>
          <div>Registry</div><div><code>{_safe(c.get("registry",0))}</code></div>
        </div>
        <div class="small" style="margin-top:8px;">Full IOC list: <code>iocs.csv</code> / <code>iocs.json</code></div>
      </div>

      <div class="card">
        <div style="font-weight:700; margin-bottom:8px;">Recommended Actions</div>
        <ul class="actions">
          {data["actions_html"]}
        </ul>
      </div>
    </div>

    <div class="row" style="margin-top:12px;">
      {_subfiles_html(data["subfiles"])}
    </div>

    <div class="row" style="margin-top:12px;">
      <div class="card">
        <div style="font-weight:700; margin-bottom:8px;">Evidence / Artifacts</div>
        <ul>
          {ev_html}
        </ul>
        <div class="small">All paths are relative to the case folder.</div>
      </div>
    </div>
  </div>
</body>
</html>
"""
    report_html.write_text(html_doc, encoding="utf-8", errors="replace")
    return report_html


def generate_reports(case_dir: Path) -> dict[str, Any]:
    summary = _read_json(case_dir / "summary.json")
    iocs_j = _read_json(case_dir / "iocs.json")

    sample = summary.get("sample", {}) if isinstance(summary.get("sample", {}), dict) else {}
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

    signing = summary.get("signing") if isinstance(summary.get("signing"), dict) else {}
    signing_summary = {}
    if signing:
        signing_summary = {
            "signed_ok": bool(signing.get("verify_ok")) and bool(signing.get("timestamp_verified")),
            "subject": signing.get("subject", "") or "",
        }

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
        "actions_html": _actions_html(score),
        "subfiles": _subfiles_block(summary),
        "signing_summary": signing_summary,
        "api": api,
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
