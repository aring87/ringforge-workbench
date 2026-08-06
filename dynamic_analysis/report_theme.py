from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def severity_class_for_count(value: Any) -> str:
    n = _safe_int(value, 0)
    if n <= 0:
        return "sev-none"
    if n <= 2:
        return "sev-low"
    if n <= 10:
        return "sev-med"
    return "sev-high"


def severity_class_for_score(value: Any) -> str:
    n = _safe_int(value, 0)
    if n >= 65:
        return "sev-high"
    if n >= 45:
        return "sev-med"
    if n >= 20:
        return "sev-low"
    return "sev-none"


def severity_class_for_label(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"critical", "high", "malicious"}:
        return "sev-high"
    if text in {"medium", "suspicious"}:
        return "sev-med"
    if text in {"low", "low_risk"}:
        return "sev-low"
    return "sev-none"


def badge(label: str, value: Any) -> str:
    cls = severity_class_for_count(value)
    return f'<span class="badge {cls}">{label}: {value}</span>'


def score_badge(label: str, value: Any) -> str:
    cls = severity_class_for_score(value)
    return f'<span class="badge {cls}">{label}: {value}</span>'


def label_badge(label: str, value: Any) -> str:
    cls = severity_class_for_label(value)
    return f'<span class="badge {cls}">{label}: {value}</span>'


def report_css() -> str:
    return r"""
:root {
  --bg: #0A0A0A;
  --panel: #101726;
  --panel-2: #0B1220;
  --border: #22314F;
  --text: #F3F6FB;
  --muted: #A9B7D0;
  --blue: #6EA8FF;
  --blue-strong: #1E4ED8;
  --good: #19C37D;
  --warn: #F5B942;
  --bad: #E45757;
  --shadow: 0 10px 30px rgba(0,0,0,0.35);
}
* { box-sizing: border-box; }
body {
  font-family: Segoe UI, Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
  margin: 0;
  padding: 24px;
}
.container {
  max-width: 1280px;
  margin: 0 auto;
}
h1 {
  margin: 0 0 8px 0;
  font-size: 32px;
  color: var(--blue);
}
h2 {
  margin: 0;
  font-size: 18px;
  color: #bfdbfe;
}
.subtitle {
  color: var(--muted);
  margin-top: 6px;
  font-size: 14px;
}
.banner {
  background: linear-gradient(135deg, #0A0A0A, #0F1C3F 45%, #1E4ED8 100%);
  border: 1px solid #22314F;
  border-radius: 18px;
  padding: 22px;
  margin-bottom: 20px;
  box-shadow: var(--shadow);
}
.verdict {
  display: inline-block;
  margin-top: 14px;
  padding: 8px 12px;
  border-radius: 999px;
  font-weight: 600;
  border: 1px solid transparent;
}
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 18px;
}
.tile-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
  margin-bottom: 18px;
}
.tile {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 14px;
  box-shadow: var(--shadow);
}
.tile-label {
  color: var(--muted);
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  margin-bottom: 6px;
}
.tile-value {
  font-size: 24px;
  font-weight: 700;
  color: var(--text);
}
.card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 18px;
  margin-bottom: 18px;
  box-shadow: var(--shadow);
}
.card-alert {
  border-color: rgba(245, 158, 11, 0.55);
  box-shadow: 0 10px 30px rgba(245, 158, 11, 0.08);
}
.section-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  margin-bottom: 14px;
  flex-wrap: wrap;
}
table {
  width: 100%;
  border-collapse: collapse;
}
th, td {
  text-align: left;
  padding: 9px 10px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
  word-break: break-word;
  font-size: 14px;
}
th {
  color: #cbd5e1;
  width: 35%;
  background: rgba(255,255,255,0.01);
}
.kv th {
  width: 42%;
}

/* Generic multi-column tables.
   The global "th { width: 35% }" above is sized for the two-column key/value
   tables. Applied to a four-column table it claims 140% of the width and
   crushes the final column to one character per line, so these opt out and
   size to their content instead. */
.data-table {
  table-layout: auto;
  width: 100%;
}
.data-table th {
  width: auto;
  white-space: nowrap;
}
.data-table td {
  word-break: normal;
  overflow-wrap: anywhere;
}
/* Addresses, ports and identifiers should not be broken mid-token. */
.data-table td.nowrap {
  white-space: nowrap;
}

.muted {
  color: var(--muted);
}
ul {
  margin: 0;
  padding-left: 20px;
}
li {
  margin-bottom: 6px;
}
.table-wrap {
  overflow-x: auto;
}

.subfile-table {
  table-layout: auto;
  min-width: 980px;
}

.subfile-table th {
  width: auto;
  white-space: nowrap;
  word-break: normal;
}

.subfile-table td {
  word-break: normal;
  overflow-wrap: anywhere;
}

.subfile-table th:nth-child(1),
.subfile-table td:nth-child(1) {
  min-width: 220px;
}

.subfile-table th:nth-child(2),
.subfile-table td:nth-child(2) {
  width: 80px;
  text-align: center;
}

.subfile-table th:nth-child(3),
.subfile-table td:nth-child(3) {
  width: 130px;
}

.subfile-table th:nth-child(4),
.subfile-table td:nth-child(4) {
  width: 130px;
}

.subfile-table th:nth-child(5),
.subfile-table td:nth-child(5),
.subfile-table th:nth-child(6),
.subfile-table td:nth-child(6) {
  width: 100px;
  text-align: center;
}

.subfile-table th:nth-child(7),
.subfile-table td:nth-child(7) {
  min-width: 320px;
}

.autoruns-table {
  table-layout: fixed;
  min-width: 1360px;
}

.autoruns-table th,
.autoruns-table td {
  word-break: normal;
  overflow-wrap: anywhere;
  vertical-align: top;
}

.autoruns-table th:nth-child(1),
.autoruns-table td:nth-child(1) {
  width: 150px;
  white-space: nowrap;
}

.autoruns-table th:nth-child(2),
.autoruns-table td:nth-child(2) {
  width: 110px;
  white-space: nowrap;
}

/* Location. Wide because a registry hive path is what distinguishes two
   entries of the same name, and truncating it undoes the reason it is here. */
.autoruns-table th:nth-child(3),
.autoruns-table td:nth-child(3) {
  width: 260px;
}

.autoruns-table th:nth-child(4),
.autoruns-table td:nth-child(4) {
  width: 140px;
}

.autoruns-table th:nth-child(5),
.autoruns-table td:nth-child(5) {
  width: 160px;
}

.autoruns-table th:nth-child(6),
.autoruns-table td:nth-child(6),
.autoruns-table th:nth-child(7),
.autoruns-table td:nth-child(7) {
  width: 270px;
}

.process-table {
  table-layout: fixed;
  min-width: 1250px;
}

.process-table th,
.process-table td {
  word-break: normal;
  overflow-wrap: anywhere;
  vertical-align: top;
}

.process-table th:nth-child(1),
.process-table td:nth-child(1) {
  width: 170px;
  white-space: nowrap;
}

.process-table th:nth-child(2),
.process-table td:nth-child(2) {
  width: 170px;
}

.process-table th:nth-child(3),
.process-table td:nth-child(3) {
  width: 170px;
}

.process-table th:nth-child(4),
.process-table td:nth-child(4) {
  width: 80px;
  white-space: nowrap;
}

.process-table th:nth-child(5),
.process-table td:nth-child(5) {
  width: 300px;
}

.process-table th:nth-child(6),
.process-table td:nth-child(6) {
  width: 320px;
}

.process-table th:nth-child(7),
.process-table td:nth-child(7) {
  width: 90px;
  text-align: center;
  white-space: nowrap;
}

.event-hits-table {
  table-layout: fixed;
  min-width: 1150px;
}

.event-hits-table th,
.event-hits-table td {
  word-break: normal;
  overflow-wrap: anywhere;
  vertical-align: top;
}

.event-hits-table th:nth-child(1),
.event-hits-table td:nth-child(1) {
  width: 170px;
  white-space: nowrap;
}

.event-hits-table th:nth-child(2),
.event-hits-table td:nth-child(2) {
  width: 180px;
}

.event-hits-table th:nth-child(3),
.event-hits-table td:nth-child(3) {
  width: 140px;
  white-space: nowrap;
}

.event-hits-table th:nth-child(4),
.event-hits-table td:nth-child(4) {
  width: 360px;
}

.event-hits-table th:nth-child(5),
.event-hits-table td:nth-child(5) {
  width: 300px;
}

.badge {
  display: inline-block;
  padding: 6px 10px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 700;
  border: 1px solid transparent;
  white-space: nowrap;
}
.sev-none {
  background: rgba(16,185,129,0.12);
  color: #a7f3d0;
  border-color: rgba(16,185,129,0.35);
}
.sev-low {
  background: rgba(59,130,246,0.12);
  color: #bfdbfe;
  border-color: rgba(59,130,246,0.35);
}
.sev-med {
  background: rgba(245,158,11,0.12);
  color: #fde68a;
  border-color: rgba(245,158,11,0.35);
}
.sev-high {
  background: rgba(239,68,68,0.12);
  color: #fecaca;
  border-color: rgba(239,68,68,0.35);
}
.footer {
  margin-top: 20px;
  color: var(--muted);
  font-size: 12px;
  text-align: right;
}
@media print {
  body {
    background: white;
    color: black;
    padding: 0;
  }
  .banner, .card, .tile {
    box-shadow: none;
  }
}
"""


def report_page(title: str, subtitle: str, verdict: str, verdict_class: str, body_html: str) -> str:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>{report_css()}</style>
</head>
<body>
<div class="container">
  <div class="banner">
    <h1>{title}</h1>
    <div class="subtitle">{subtitle}</div>
    <div class="verdict {verdict_class}">{verdict}</div>
  </div>
  {body_html}
  <div class="footer">Generated: {generated_at}</div>
</div>
</body>
</html>"""