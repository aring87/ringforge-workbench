"""Re-run only the VirusTotal lookup over an existing corpus.

**Five samples in the malware corpora carry signatures that verify**, from real
companies -- `NetSupport Ltd`, `AVG Technologies USA`, `Sahlmen Software AB`,
`A-LINE PIPE TOOLS INC.` and one in Wuhan. None matches a YARA rule and one
produces zero capa rules. Three of them sit in the No Evidence band, so the
question "why can the module not see these" may have the answer "because there
is nothing to see". Both corpora come from MalwareBazaar's daily archive, which
is a *submission* feed: what people uploaded believing it malicious.

`virustotal.json` has read `status: skipped, VT_API_KEY not set` since the
corpora were built, so the cheapest way to settle it has never been run.

    setx VT_API_KEY <your key>        # then open a new shell
    .venv\\Scripts\\python.exe scripts\\refresh_virustotal.py --cases G:\\...\\cases --signed-only

**This sends hashes to a third party.** Only SHA-256 digests already recorded in
each case leave the machine -- never a file, never a path, never a name -- and
`--signed-only` limits it to the handful in question rather than the whole
corpus. `--dry-run` prints exactly what would be sent and contacts nobody.

The key is read from the environment and never logged. Rate limiting is the
public-tier default of 4 requests a minute unless `--rate` says otherwise.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_ENDPOINT = "https://www.virustotal.com/api/v3/files/"


def cases_to_check(root: Path, signed_only: bool) -> list[tuple[Path, str, str]]:
    out = []
    for case in sorted(p for p in root.iterdir() if p.is_dir()):
        summary = case / "summary.json"
        if not summary.is_file():
            continue
        try:
            data = json.loads(summary.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        digest = str((data.get("sample") or {}).get("sha256") or "").strip()
        if not digest:
            continue
        subject = ""
        signing_path = case / "signing.json"
        if signing_path.is_file():
            try:
                signing = json.loads(signing_path.read_text(encoding="utf-8",
                                                            errors="replace"))
            except Exception:
                signing = {}
            trusted = (bool(signing.get("verify_ok"))
                       and bool(signing.get("timestamp_verified")))
            subject = str(signing.get("subject") or "")
            if signed_only and not trusted:
                continue
        elif signed_only:
            continue
        out.append((case, digest, subject))
    return out


def lookup(digest: str, key: str, timeout: int) -> dict[str, Any]:
    request = urllib.request.Request(
        _ENDPOINT + digest,
        headers={"x-apikey": key, "Accept": "application/json",
                 "User-Agent": "ringforge-corpus/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return {"found": False, "status": "not_present_in_vt"}
        return {"found": False, "status": f"http_{error.code}"}
    except Exception as error:
        return {"found": False, "status": f"{type(error).__name__}"}

    attributes = (body.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    return {
        "found": True,
        "status": "ok",
        "malicious": int(stats.get("malicious", 0) or 0),
        "suspicious": int(stats.get("suspicious", 0) or 0),
        "harmless": int(stats.get("harmless", 0) or 0),
        "undetected": int(stats.get("undetected", 0) or 0),
        "meaningful_name": str(attributes.get("meaningful_name") or ""),
        "type_description": str(attributes.get("type_description") or ""),
        "times_submitted": int(attributes.get("times_submitted", 0) or 0),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cases", required=True)
    parser.add_argument("--signed-only", action="store_true",
                        help="only cases whose signature verifies")
    parser.add_argument("--dry-run", action="store_true",
                        help="print what would be sent; contact nobody")
    parser.add_argument("--apply", action="store_true",
                        help="write the answer back into virustotal.json")
    parser.add_argument("--rate", type=float, default=15.0,
                        help="seconds between requests; public tier allows 4/min")
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args(argv)

    root = Path(args.cases)
    if not root.is_dir():
        print(f"failed: --cases {root} is not a directory")
        return 1

    targets = cases_to_check(root, args.signed_only)
    print(f"{len(targets)} case(s) to look up in {root.parent.name}"
          f"{' (signature verifies)' if args.signed_only else ''}")
    if args.dry_run:
        print("\ndry run -- these SHA-256 digests would be sent to VirusTotal, "
              "and nothing else:")
        for case, digest, subject in targets:
            print(f"    {digest}  {case.name[:28]}  {subject[:40]}")
        return 0

    key = os.environ.get("VT_API_KEY", "").strip()
    if not key:
        print("failed: VT_API_KEY is not set in this environment.\n"
              "        setx VT_API_KEY <your key>, then open a new shell.\n"
              "        Refusing to run rather than recording another skipped "
              "lookup as an answer.")
        return 1

    for index, (case, digest, subject) in enumerate(targets, 1):
        if index > 1:
            time.sleep(args.rate)
        result = lookup(digest, key, args.timeout)
        verdict = (f"{result.get('malicious', 0)} malicious / "
                   f"{result.get('harmless', 0)} harmless"
                   if result.get("found") else result.get("status"))
        print(f"  {index}/{len(targets)}  {case.name[:26]:26} {verdict}")
        if result.get("found") and result.get("meaningful_name"):
            print(f"        name on VT: {result['meaningful_name'][:60]}")
        if args.apply:
            path = case / "virustotal.json"
            existing = {}
            if path.is_file():
                try:
                    existing = json.loads(path.read_text(encoding="utf-8",
                                                         errors="replace"))
                except Exception:
                    existing = {}
            existing.update(result)
            existing["sha256"] = digest
            existing["enabled"] = True
            existing["lookup_status"] = result.get("status")
            existing.pop("error", None)
            path.write_text(json.dumps(existing, indent=2, sort_keys=True),
                            encoding="utf-8")
    if not args.apply:
        print("\nnothing written -- pass --apply to update virustotal.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
