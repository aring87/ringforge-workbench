# static_triage_engine/ioc_parser.py

from __future__ import annotations

import re
from typing import Any


URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
REG_PATH_RE = re.compile(r"\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\n\r\"']+", re.IGNORECASE)
WIN_PATH_RE = re.compile(r"\b[a-zA-Z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*")
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
TASK_CMD_RE = re.compile(r"\b(?:schtasks|powershell|cmd\.exe|wscript|cscript|rundll32|mshta)\b", re.IGNORECASE)


def extract_iocs_from_strings(strings: list[str]) -> dict[str, Any]:
    urls = set()
    ips = set()
    domains = set()
    reg_paths = set()
    file_paths = set()
    emails = set()
    commands = set()

    for s in strings:
        urls.update(URL_RE.findall(s))
        ips.update(IP_RE.findall(s))
        reg_paths.update(REG_PATH_RE.findall(s))
        file_paths.update(WIN_PATH_RE.findall(s))
        emails.update(EMAIL_RE.findall(s))

        for match in DOMAIN_RE.findall(s):
            if not match.lower().startswith(("hklm", "hkcu")):
                domains.add(match)

        if TASK_CMD_RE.search(s):
            commands.add(s.strip())

    return {
        "urls": sorted(urls),
        "ips": sorted(ips),
        "domains": sorted(domains),
        "registry_paths": sorted(reg_paths),
        "file_paths": sorted(file_paths),
        "emails": sorted(emails),
        "commands": sorted(commands)[:100],
        "counts": {
            "urls": len(urls),
            "ips": len(ips),
            "domains": len(domains),
            "registry_paths": len(reg_paths),
            "file_paths": len(file_paths),
            "emails": len(emails),
            "commands": len(commands),
        },
    }


def flatten_iocs(iocs: dict[str, Any]) -> list[str]:
    output: list[str] = []
    for key in ("urls", "ips", "domains", "registry_paths", "file_paths", "emails", "commands"):
        output.extend(iocs.get(key, []))
    return output