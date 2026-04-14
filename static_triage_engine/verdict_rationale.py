from __future__ import annotations

from typing import Any


def build_static_verdict_rationale(
    *,
    static_score: int | float | None,
    verdict: str | None = None,
    confidence: str | None = None,
    is_signed: bool | None,
    yara_hits: int = 0,
    capa_hits: int = 0,
    high_risk_strings: int = 0,
    ioc_counts: dict[str, int] | None = None,
    packer_score: str | None = None,
    vt_found: bool = False,
    vt_malicious: int = 0,
    vt_suspicious: int = 0,
) -> dict[str, Any]:
    ioc_counts = ioc_counts or {}

    increased: list[str] = []
    decreased: list[str] = []
    notes: list[str] = []

    total_iocs = sum(v for v in ioc_counts.values() if isinstance(v, int))

    if yara_hits > 0:
        increased.append(f"YARA produced {yara_hits} match(es).")

    if high_risk_strings > 0:
        increased.append(
            f"Found {high_risk_strings} high-risk string(s) such as suspicious commands, URLs, or persistence indicators."
        )

    if total_iocs > 0:
        increased.append(f"Extracted {total_iocs} potential IOC artifact(s) from strings and decoded content.")

    if packer_score and str(packer_score).lower() in {"moderate", "high"}:
        increased.append(f"Packer/obfuscation rating was {packer_score}.")

    if capa_hits > 0:
        notes.append(f"capa identified {capa_hits} capability finding(s); capability counts should be interpreted with context.")

    if is_signed is True:
        decreased.append("File appears to be signed and signature verification succeeded.")
    elif is_signed is False:
        increased.append("File is unsigned or signature validation failed.")

    if vt_found:
        if vt_malicious > 0 or vt_suspicious > 0:
            increased.append(
                f"VirusTotal reported {vt_malicious} malicious and {vt_suspicious} suspicious engine verdict(s)."
            )
        else:
            decreased.append("VirusTotal did not report malicious or suspicious engine verdicts for this file.")

    final_confidence = confidence or "N/A"
    final_verdict = (verdict or "").upper()

    if final_verdict == "BENIGN":
        recommended_next_step = "Likely benign based on current evidence. Review provenance if needed; dynamic analysis is optional."
    elif final_verdict == "LOW_RISK":
        recommended_next_step = "Review provenance and supporting telemetry. Dynamic analysis is optional unless other context raises concern."
    elif final_verdict == "SUSPICIOUS":
        recommended_next_step = "Proceed with dynamic analysis to validate suspicious indicators and confirm behavior."
    elif final_verdict == "MALICIOUS":
        recommended_next_step = "Run dynamic analysis immediately, contain if necessary, and pivot on hash and any related observables."
    else:
        recommended_next_step = "Review the full static report and determine whether dynamic analysis is needed."

    if not increased:
        notes.append("No strong high-confidence static indicators were identified from the currently collected evidence.")

    return {
        "score": static_score,
        "confidence": final_confidence,
        "verdict": verdict or "",
        "increased_score_reasons": increased[:5],
        "decreased_score_reasons": decreased[:5],
        "notes": notes[:5],
        "recommended_next_step": recommended_next_step,
    }