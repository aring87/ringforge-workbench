# static_triage_engine/decoded_strings.py

from __future__ import annotations

from pathlib import Path
from typing import Any


SUSPICIOUS_KEYWORDS = [
    "powershell",
    "cmd.exe",
    "rundll32",
    "reg add",
    "schtasks",
    "startup",
    "runonce",
    "wscript",
    "cscript",
    "mshta",
    "http://",
    "https://",
    "pastebin",
    "appdata",
    "temp",
    "programdata",
    "base64",
    "encodedcommand",
]


def extract_decoded_strings(sample_path: str | Path) -> dict[str, Any]:
    """
    Placeholder framework for decoded/deobfuscated strings.

    Later this can call FLOSS or another decoder.
    For now it returns a stable structure so the rest of the UI/reporting
    can be built immediately.
    """
    sample_path = str(sample_path)

    results = {
        "enabled": False,
        "source": "placeholder",
        "decoded_strings": [],
        "high_risk_strings": [],
        "stats": {
            "decoded_count": 0,
            "high_risk_count": 0,
        },
        "notes": [
            "Decoded string extraction framework is present but no external decoder is configured yet."
        ],
    }

    return results


def summarize_suspicious_strings(strings: list[str]) -> dict[str, Any]:
    high_risk = []
    for s in strings:
        s_lower = s.lower()
        if any(k in s_lower for k in SUSPICIOUS_KEYWORDS):
            high_risk.append(s)

    return {
        "high_risk_strings": high_risk[:100],
        "stats": {
            "decoded_count": len(strings),
            "high_risk_count": len(high_risk),
        },
    }