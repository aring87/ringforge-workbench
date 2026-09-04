"""What a case folder amounts to, for the screen that shows it.

**Why this is a module and not a method on the controller.** The main window's
Results panel -- Score, Verdict, Confidence and the VirusTotal line -- was built
by 142 lines in `gui/controllers/result_controller.py`, of which about ninety
were pure data work: hunting a score across a dozen possible keys, reading
VirusTotal statistics in two different shapes, and choosing the sentence the VT
status line shows. None of it touched a widget and none of it could be imported
without a display, so none of it was tested. Fourth module through this pass,
and the defect it was hiding is the one on the application's front page.

**Every current verdict rendered grey in the Verdict tile.** The tile colours
itself with `gui.theme.status_colors`, which knew severities (`High`, `Medium`,
`Low`, `Unknown`) and the retired additive verdicts (`MALICIOUS`, `SUSPICIOUS`,
`BENIGN`) -- and was handed the verdict *sentence*. Measured 03 Sep: all twelve
sentences `corroboration-v1` can write fell through to the neutral default. A
case folder written before the scoring rewrite coloured; every one written after
it did not. `summary.json` carries `severity` beside `verdict` and nothing read
it, which is the same fix as the extension module's and for the same reason:
**the band is the model's output, not a word in a sentence.**

**`found` was derived from a URL.** The VT view called a report found when the
permalink was non-empty -- and `engine.py` builds that permalink out of the
sha256 in the *default* record, before any lookup happens, so it is there
whether or not VirusTotal was ever asked. A skipped lookup carried a link and
therefore read as found. It is read from the `found` flag and the analysis
counts now.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

#: Where a case's headline numbers may live, canonical first. Only
#: `summary.json` is written today; the other two are legacy names still read
#: so an old case folder opens. **Earlier entries win** -- the previous merge
#: was `dict.update` in this order, so the legacy names would have quietly
#: overwritten the file the engine actually writes.
RESULT_FILES = ("summary.json", "report.json", "metadata/run_summary.json")

#: Where a score hides, in the order tried. The first four are top-level keys
#: from four generations of this tool; the nested blocks repeat them.
_SCORE_KEYS = ("score", "risk_score", "static_score", "total_score")
_NESTED_BLOCKS = ("scoring", "summary", "verdict_rationale")

_MISSING = (None, "")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        if not path.exists():
            return {}
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            data = json.load(handle)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def load_case_result(case_dir: str | Path) -> dict[str, Any]:
    """Merge a case folder's result files, canonical first.

    A key present in `summary.json` is never replaced by one of the legacy
    names. The version this replaces merged in the opposite order, so a
    `metadata/run_summary.json` -- a name nothing has written for several
    releases -- would have taken precedence over the engine's own output.
    """
    case_dir = Path(case_dir)
    merged: dict[str, Any] = {}
    for name in RESULT_FILES:
        data = _read_json(case_dir.joinpath(*name.split("/")))
        for key, value in data.items():
            merged.setdefault(key, value)
    return merged


def load_virustotal(case_dir: str | Path) -> dict[str, Any]:
    """The case's `virustotal.json`, or an empty record if there is none."""
    return _read_json(Path(case_dir) / "virustotal.json")


def _in(source: Any, keys: tuple[str, ...]) -> Any:
    if not isinstance(source, Mapping):
        return None
    for key in keys:
        value = source.get(key)
        if value not in _MISSING:
            return value
    return None


def _first(data: Mapping[str, Any], *keys: str) -> Any:
    """Block by block, every alias within a block before moving on.

    The order matters and is the order the controller used: the whole record
    first, then each nested block. Scanning alias-first across blocks would
    prefer a canonical name in a legacy block over a legacy name in the
    canonical one, which is a different answer for the same folder.
    """
    value = _in(data, keys)
    if value not in _MISSING:
        return value
    for block in _NESTED_BLOCKS:
        value = _in(data.get(block), keys)
        if value not in _MISSING:
            return value
    return None


def result_headline(data: Mapping[str, Any]) -> dict[str, Any]:
    """The three tiles, plus the band that decides their colour.

    `severity` is the point of this function. It is written into
    `summary.json` beside `verdict` by every run since the scoring rewrite, it
    is the model's own output, and the screen was ignoring it in favour of
    pattern-matching the sentence -- which no longer matched anything.

    An old folder has no `severity`; the sentence is the fallback there, and
    the retired words are ones the colour map still knows.
    """
    data = data if isinstance(data, Mapping) else {}
    score = _first(data, *_SCORE_KEYS)
    verdict = _first(data, "verdict")
    severity = _first(data, "severity")
    confidence = _first(data, "confidence")
    return {
        "score": "-" if score in _MISSING else str(score),
        "verdict": "-" if verdict in _MISSING else str(verdict),
        # Empty rather than "-": the caller falls back to the wording, and a
        # literal dash would be a band nothing knows.
        "severity": "" if severity in _MISSING else str(severity),
        "confidence": "-" if confidence in _MISSING else str(confidence),
    }


def band_for(headline: Mapping[str, Any]) -> str:
    """The word to colour by: the model's band, else the sentence.

    Never both, and never the score. Returning the sentence when there is no
    severity is what keeps a pre-rewrite case folder rendering.
    """
    severity = str(headline.get("severity", "") or "").strip()
    return severity or str(headline.get("verdict", "") or "").strip()


def _counts(vt: Mapping[str, Any]) -> dict[str, int]:
    """VirusTotal's numbers, in either shape it has been stored in.

    A live lookup nests them under `last_analysis_stats`; the record
    `engine.py` writes flattens them to the top level.
    """
    stats = vt.get("last_analysis_stats")
    source = stats if isinstance(stats, Mapping) and stats else vt

    def count(name: str) -> int:
        try:
            return int(source.get(name, 0) or 0)
        except (TypeError, ValueError):
            return 0

    return {name: count(name)
            for name in ("malicious", "suspicious", "harmless", "undetected")}


def _name(vt: Mapping[str, Any]) -> str:
    for key in ("meaningful_name", "file_name", "name"):
        value = str(vt.get(key, "") or "").strip()
        if value:
            return value
    return "-"


def virustotal_view(
    *,
    embedded: Any = None,
    raw: Any = None,
    api_key_present: bool = False,
) -> dict[str, Any]:
    """Everything the VirusTotal panel shows, decided once.

    `raw` is `virustotal.json`; `embedded` is the copy inside the case summary.
    The raw file wins where both exist.

    **`found` is not read off the permalink any more.** `engine.py` builds that
    URL from the sha256 in the record it writes when the lookup is *skipped*,
    so it is present whether or not VirusTotal was asked -- and a skipped
    lookup therefore reported a report found. A report is found when the record
    says so or when the analysis actually returned counts.

    The status ladder is one ladder. There were two, and the second was
    unreachable: it was guarded by `if vt_raw:` inside a branch entered only
    when `vt_raw or embedded` was falsy, which `vt_raw` truthy makes impossible.
    """
    raw = raw if isinstance(raw, Mapping) else {}
    embedded = embedded if isinstance(embedded, Mapping) else {}
    vt = raw or embedded

    counts = _counts(vt)
    link = str(vt.get("permalink", "") or "")
    status_word = str(vt.get("status", "") or "").strip().lower()
    lookup_status = str(vt.get("lookup_status", "") or "").strip()
    error = str(vt.get("error", "") or "").strip()
    found = bool(vt.get("found", False)) or any(counts.values())

    if not vt:
        status = ("VirusTotal: no result available" if api_key_present
                  else "VirusTotal: disabled")
        return {"status": status, "name": "-", "counts": _counts({}),
                "link": "", "found": False}

    if status_word == "skipped" or error == "VT_API_KEY not set":
        status = "VirusTotal: skipped"
    elif status_word == "warning":
        status = f"VirusTotal: warning ({lookup_status or 'unavailable'})"
    elif lookup_status == "not_found":
        status = "VirusTotal: hash not found"
    elif found:
        status = "VirusTotal: report found"
    else:
        status = "VirusTotal: no report available"

    return {"status": status, "name": _name(vt), "counts": counts,
            "link": link, "found": found}


def counts_line(counts: Mapping[str, int]) -> str:
    """The one-line count summary, so the screen and any export agree."""
    return ("Counts: mal={malicious} | susp={suspicious} | "
            "harmless={harmless} | undetected={undetected}").format(
        **{k: int(counts.get(k, 0) or 0)
           for k in ("malicious", "suspicious", "harmless", "undetected")})
