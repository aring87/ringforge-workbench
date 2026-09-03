from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from design_tokens import (
    ACCENT,
    ACCENT_DEEP,
    ACCENT_TEXT,
    BG,
    BG_ALT,
    BORDER,
    BORDER_STRONG,
    CRITICAL,
    DANGER,
    HEADER_TOP,
    INFO,
    SUCCESS,
    SURFACE,
    TEXT,
    TEXT_SECONDARY,
    WARNING,
    alpha_over,
    lighten,
)


def _severity_vars() -> str:
    """CSS custom properties for the badge ramp, from the shared palette.

    **Flattened rather than `rgba()`.** Tk has no alpha channel, so the desktop
    application already pre-computes its translucency; computing the HTML the
    same way is what stops a badge being one colour in the window and a slightly
    different one in the exported report. That difference is exactly the kind
    nobody can name and everybody notices.
    """
    ramp = {
        "none": SUCCESS,
        "low": INFO,
        "med": WARNING,
        "high": DANGER,
        "critical": CRITICAL,
    }
    lines = []
    for name, colour in ramp.items():
        lines.append(f"  --sev-{name}-fg: {lighten(colour, 0.55)};")
        lines.append(f"  --sev-{name}-bg: {alpha_over(colour, SURFACE, 0.14)};")
        lines.append(f"  --sev-{name}-border: {alpha_over(colour, SURFACE, 0.38)};")
    return "\n".join(lines)


#: The palette half of the stylesheet, built from `design_tokens`. Split from
#: the rules below so the rules can stay a raw string -- CSS is mostly braces,
#: and an f-string over the whole sheet would mean doubling every one of them.
_ROOT = f""":root {{
  --bg: {BG};
  --panel: {SURFACE};
  --panel-2: {BG_ALT};
  --border: {BORDER};
  --border-strong: {BORDER_STRONG};
  --text: {TEXT};
  --muted: {TEXT_SECONDARY};
  --blue: {ACCENT_TEXT};
  --blue-strong: {ACCENT};
  --blue-deep: {ACCENT_DEEP};
  --header-top: {HEADER_TOP};
  --good: {SUCCESS};
  --warn: {WARNING};
  --bad: {DANGER};
  --critical: {CRITICAL};
  --shadow: 0 10px 30px rgba(0,0,0,0.35);
{_severity_vars()}
}}
"""


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
    """Map a severity or a verdict onto the badge ramp.

    Knows both vocabularies. The `corroboration-v1` bands are the ones written
    today; MALICIOUS / SUSPICIOUS / LOW_RISK are the retired additive verdicts,
    kept here so a case folder written before the change still renders rather
    than turning grey.
    """
    text = str(value or "").strip().lower()
    if text in {"critical", "high", "malicious",
                # malware wording, then posture wording, then the neutral band
                "likely malicious", "elevated attention",
                "serious exposure", "multiple weaknesses",
                "strongly corroborated", "corroborated"}:
        return "sev-high"
    if text in {"medium", "suspicious", "needs review",
                "unknown", "insufficient coverage",
                "single observation", "nothing collected"}:
        return "sev-med"
    if text in {"low", "low_risk", "low suspicion",
                "no findings, coverage incomplete"}:
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
    """The one report stylesheet.

    There were five in this repository -- this one, two near-identical copies in
    `gui/extension_window.py` and `gui/unified_report_window.py`, and two
    ad-hoc sheets in `gui/dynamic_window.py` and `gui/api_window.py` with
    entirely different palettes. Every window that exports HTML now renders
    through this, so the application and its own reports stop reading as
    different products.
    """
    return _ROOT + r"""
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
  color: var(--blue);
}
.subtitle {
  color: var(--muted);
  margin-top: 6px;
  font-size: 14px;
}
.banner {
  background: linear-gradient(135deg, var(--bg), var(--header-top) 45%, var(--blue-strong) 100%);
  border: 1px solid var(--border);
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
  color: var(--muted);
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
ul,
ol {
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
  background: var(--sev-none-bg);
  color: var(--sev-none-fg);
  border-color: var(--sev-none-border);
}
.sev-low {
  background: var(--sev-low-bg);
  color: var(--sev-low-fg);
  border-color: var(--sev-low-border);
}
.sev-med {
  background: var(--sev-med-bg);
  color: var(--sev-med-fg);
  border-color: var(--sev-med-border);
}
.sev-high {
  background: var(--sev-high-bg);
  color: var(--sev-high-fg);
  border-color: var(--sev-high-border);
}
/* Carried over from the window-local sheets this one replaced, each of which
   had a rule or two the others lacked. They live here now so those copies
   could be deleted. */
.label {
  color: var(--muted);
  font-weight: 700;
}
.sev-critical {
  background: var(--sev-critical-bg);
  color: var(--sev-critical-fg);
  border-color: var(--sev-critical-border);
}
pre {
  background: var(--panel-2);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 12px;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-word;
  font-family: Consolas, monospace;
  font-size: 12.5px;
  color: var(--text);
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


def report_page(title: str, subtitle: str, verdict: str = "",
                verdict_class: str = "", body_html: str = "",
                footer_note: str = "") -> str:
    """The one page shell every report in this workbench renders into.

    **The verdict is optional, and that is the point of it being optional.**
    Three reports used to hand-roll their own `<!DOCTYPE html>` around
    `report_css()` rather than call this, so the application and its own outputs
    read as different products -- the same argument `design_tokens` was created
    to settle for colour, one level up at the structure. Two of those three have
    no verdict to show, and the fix for that is to let a report say nothing
    rather than to invent a band for it.

    ``footer_note`` names the producing module beside the timestamp, because a
    reader holding one exported page should be able to tell which screen made
    it.
    """
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    verdict_html = (f'\n    <div class="verdict {verdict_class}">{verdict}</div>'
                    if verdict else "")
    footer = f"{footer_note} &bull; Generated: {generated_at}" if footer_note \
        else f"Generated: {generated_at}"
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
    <div class="subtitle">{subtitle}</div>{verdict_html}
  </div>
  {body_html}
  <div class="footer">{footer}</div>
</div>
</body>
</html>"""