from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yara
except ImportError:  # pragma: no cover
    yara = None


def _safe_bytes_to_text(data: Any, limit: int = 200) -> str:
    """
    Convert bytes or other objects to a safe preview string.
    """
    if data is None:
        return ""

    if isinstance(data, bytes):
        try:
            return data[:limit].decode("utf-8", errors="replace")
        except Exception:
            return repr(data[:limit])

    text = str(data)
    return text[:limit]


def _collect_rule_files(rules_dir: Path) -> Dict[str, str]:
    """
    Recursively collect .yar/.yara files for yara.compile(filepaths=...).
    """
    filepaths: Dict[str, str] = {}
    index = 0

    for rule_file in rules_dir.rglob("*"):
        if rule_file.is_file() and rule_file.suffix.lower() in {".yar", ".yara"}:
            namespace = f"rule_{index}"
            filepaths[namespace] = str(rule_file)
            index += 1

    return filepaths


def _externals_for(sample: Path) -> Dict[str, Any]:
    """
    YARA external variables that public rulesets expect to be declared.

    Neo23x0's signature-base and others reference `filepath`, `filename`,
    `extension`, `filetype` and `owner`. yara-python requires these at compile
    time; without them every rule that mentions one fails to compile. Since the
    whole corpus compiles in a single call, one such rule takes down all of it.

    Real values are supplied where they can be derived from the sample, so rules
    depending on them can actually evaluate rather than merely compile.
    """
    return {
        "filepath": str(sample),
        "filename": sample.name,
        "extension": sample.suffix.lstrip("."),
        "filetype": "",
        "owner": "",
    }


def _parse_match(match: Any) -> Dict[str, Any]:
    """
    Convert a yara.Match into a JSON-safe dictionary.
    Supports common yara-python match formats.
    """
    parsed: Dict[str, Any] = {
        "rule": getattr(match, "rule", ""),
        "namespace": getattr(match, "namespace", ""),
        "tags": list(getattr(match, "tags", []) or []),
        "meta": dict(getattr(match, "meta", {}) or {}),
        "strings": [],
    }

    raw_strings = getattr(match, "strings", []) or []

    for item in raw_strings:
        # Newer yara-python may expose StringMatch objects with .identifier and .instances
        if hasattr(item, "identifier") and hasattr(item, "instances"):
            identifier = getattr(item, "identifier", "")
            for instance in getattr(item, "instances", []) or []:
                parsed["strings"].append(
                    {
                        "identifier": identifier,
                        "offset": getattr(instance, "offset", None),
                        "data": _safe_bytes_to_text(
                            getattr(instance, "matched_data", b"")
                        ),
                    }
                )
            continue

        # Older yara-python often returns tuples:
        # (offset, identifier, data)
        if isinstance(item, tuple) and len(item) >= 3:
            offset, identifier, data = item[0], item[1], item[2]
            parsed["strings"].append(
                {
                    "identifier": str(identifier),
                    "offset": offset,
                    "data": _safe_bytes_to_text(data),
                }
            )
            continue

        # Fallback
        parsed["strings"].append(
            {
                "identifier": "",
                "offset": None,
                "data": _safe_bytes_to_text(item),
            }
        )

    return parsed


def run_yara_scan(
    sample_path: str | Path,
    rules_dir: str | Path,
    timeout: int = 60,
) -> Dict[str, Any]:
    """
    Run YARA scan against a sample using all .yar/.yara files under rules_dir.
    Returns a JSON-safe dictionary with results.
    """
    sample = Path(sample_path)
    rules_root = Path(rules_dir)

    result: Dict[str, Any] = {
        "sample_path": str(sample),
        "rules_dir": str(rules_root),
        "engine": "yara-python",
        "matched": False,
        "match_count": 0,
        "rule_file_count": 0,
        "rules_compiled": 0,
        "rules_skipped": [],
        "matches": [],
        "error": None,
    }

    if yara is None:
        result["error"] = "yara-python is not installed"
        return result

    if not sample.exists() or not sample.is_file():
        result["error"] = f"Sample not found: {sample}"
        return result

    if not rules_root.exists() or not rules_root.is_dir():
        result["error"] = f"Rules directory not found: {rules_root}"
        return result

    filepaths = _collect_rule_files(rules_root)
    result["rule_file_count"] = len(filepaths)

    if not filepaths:
        result["error"] = f"No YARA rule files found in: {rules_root}"
        return result

    externals = _externals_for(sample)
    skipped: List[Dict[str, str]] = []

    try:
        compiled_rules = yara.compile(filepaths=filepaths, externals=externals)
    except Exception as bulk_exc:
        # A single unbuildable rule file must not zero out the whole corpus.
        # Fall back to identifying the bad ones and compiling the rest.
        usable: Dict[str, str] = {}
        for namespace, rule_path in filepaths.items():
            try:
                yara.compile(filepath=rule_path, externals=externals)
            except Exception as file_exc:
                skipped.append({"file": rule_path, "error": str(file_exc)})
                continue
            usable[namespace] = rule_path

        result["rules_skipped"] = skipped

        if not usable:
            result["error"] = (
                f"YARA compile failed for all {len(filepaths)} rule files; "
                f"first error: {bulk_exc}"
            )
            return result

        try:
            compiled_rules = yara.compile(filepaths=usable, externals=externals)
        except Exception as retry_exc:
            result["error"] = f"YARA compile failed after skipping bad files: {retry_exc}"
            return result

    result["rules_compiled"] = len(filepaths) - len(skipped)
    result["rules_skipped"] = skipped

    try:
        matches = compiled_rules.match(str(sample), timeout=timeout)
    except Exception as exc:
        result["error"] = f"YARA scan failed: {exc}"
        return result

    parsed_matches: List[Dict[str, Any]] = [_parse_match(m) for m in matches]

    result["matched"] = len(parsed_matches) > 0
    result["match_count"] = len(parsed_matches)
    result["matches"] = parsed_matches
    return result


def save_yara_results(output_path: str | Path, yara_result: Dict[str, Any]) -> None:
    """
    Save YARA result dictionary to JSON.
    """
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(yara_result, indent=2), encoding="utf-8")


def summarize_yara_results(yara_result: Dict[str, Any], max_rules: int = 10) -> str:
    """
    Build a short analyst-friendly text summary.
    """
    if yara_result.get("error"):
        return f"YARA Results\n- Error: {yara_result['error']}"

    found = yara_result.get("rule_file_count", 0)
    compiled = yara_result.get("rules_compiled", found)
    skipped = yara_result.get("rules_skipped", []) or []

    # Report compiled-of-found rather than found alone, so a corpus that failed
    # to build cannot read as a clean no-match scan.
    scanned = f"- Rules scanned: {compiled} of {found}"
    if skipped:
        scanned += f" ({len(skipped)} skipped, would not compile)"

    if not yara_result.get("matched"):
        return "YARA Results\n- Matched: No\n" + scanned

    matches = yara_result.get("matches", [])
    rule_names = [m.get("rule", "unknown_rule") for m in matches[:max_rules]]

    lines = [
        "YARA Results",
        "- Matched: Yes",
        f"- Match count: {yara_result.get('match_count', 0)}",
        scanned,
        "- Top matched rules:",
    ]
    lines.extend([f"  - {name}" for name in rule_names])

    if len(matches) > max_rules:
        lines.append(f"  - ... and {len(matches) - max_rules} more")

    return "\n".join(lines)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run YARA scan on a sample")
    parser.add_argument("sample", help="Path to sample file")
    parser.add_argument(
        "--rules-dir",
        default="tools/yara/rules",
        help="Directory containing .yar/.yara files",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Optional output JSON path (example: cases/test/yara_results.json)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="YARA match timeout in seconds",
    )

    args = parser.parse_args()

    result = run_yara_scan(
        sample_path=args.sample,
        rules_dir=args.rules_dir,
        timeout=args.timeout,
    )

    print(summarize_yara_results(result))

    if args.output:
        save_yara_results(args.output, result)
        print(f"\nSaved JSON results to: {args.output}")