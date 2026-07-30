"""Build and validate the UPX positive control before spending a detonation.

The memory canary proves the delta logic fires. It says nothing about whether
the installed ruleset covers a payload that is compressed at rest, because the
canary's rule is hand-written and lives in tools\\yara\\local. This script
covers the other half: take a binary the *downloaded* ruleset already detects,
pack it, and establish -- on disk, before anything is run -- that the detection
has genuinely been destroyed by packing.

That pre-flight matters because an empty memory-only result after a detonation
has at least four causes, and only one of them is interesting:

    1. The candidate was never detected on disk to begin with.
    2. Packing did not actually break the match.
    3. The rule that broke is gated on the ``pe`` module, so it could never
       match a raw minidump regardless of what the process unpacked.
    4. The dump or the delta logic is broken -- the real finding.

Everything except (4) is decidable without running the sample, so this script
decides it. It exits non-zero when the control is not worth detonating, which
is the whole point: a failed detonation costs a snapshot revert.

The ruleset is resolved through ``memory_yara.resolve_rules_dir`` rather than a
path of its own, so the comparison is made against exactly the rules the
dynamic run will use. Diffing against a differently-sourced ruleset would
answer a different question.

Usage (in the analysis VM, with the ruleset bootstrapped):

    python test_specs\\upx_control\\prepare_control.py --sample samples\\mimikatz.exe
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from dynamic_analysis.memory_yara import _COMMON_EXTERNALS, resolve_rules_dir  # noqa: E402
from static_triage_engine.yara_scan import _collect_rule_files  # noqa: E402

try:
    import yara
except ImportError:  # pragma: no cover
    yara = None

#: Matches the start of a rule definition at the beginning of a line, including
#: the private/global qualifiers signature-base uses.
_RULE_START = re.compile(r"^(?:private\s+|global\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)

#: A reference to the pe module from inside a rule body. Checked per rule rather
#: than per file: signature-base files commonly `import "pe"` at the top while
#: most rules in them never touch it, so a file-level check would discard
#: perfectly good candidates.
_USES_PE = re.compile(r"\bpe\s*\.")

#: A magic-number test anchored at offset 0, of which `uint16(0) == 0x5a4d` --
#: "is this a PE" -- is overwhelmingly the common case in signature-base. A
#: minidump begins with `MDMP`, so any rule anchored to the sample's own header
#: fails against a dump no matter what its strings do.
_ANCHORED_MAGIC = re.compile(r"\buint(?:8|16|32)(?:be)?\s*\(\s*0\s*\)")

#: An upper bound on file size. Rules routinely carry one as a cheap performance
#: guard, with no intent to exclude memory -- but a dump is two to three orders
#: of magnitude larger than the binary the bound was written for.
_FILESIZE_BOUND = re.compile(r"\bfilesize\s*<=?\s*(\d+)\s*(TB|GB|MB|KB)?", re.IGNORECASE)

_UNIT_BYTES = {"": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3, "TB": 1024 ** 4}

#: Assumed dump size when judging a filesize bound, in megabytes. A full dump of
#: even a small console process runs to tens of megabytes, so a bound below this
#: cannot be satisfied. Override with --assume-dump-mb.
DEFAULT_ASSUMED_DUMP_MB = 50


# ---------------------------------------------------------------------------
# Rule source inspection
# ---------------------------------------------------------------------------

def index_rule_sources(rule_files: dict[str, str]) -> dict[str, dict[str, Any]]:
    """Map every rule name to its source file and body text.

    Bodies are delimited by the next top-level ``rule`` keyword rather than by
    counting braces. Brace counting looks more precise but is wrong here --
    signature-base is full of hex strings and regexes containing braces, and a
    single miscount silently swallows the following rule.
    """
    index: dict[str, dict[str, Any]] = {}

    for path_str in sorted(set(rule_files.values())):
        path = Path(path_str)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        starts = [(m.start(), m.group(1)) for m in _RULE_START.finditer(text)]
        for position, (offset, name) in enumerate(starts):
            end = starts[position + 1][0] if position + 1 < len(starts) else len(text)
            body = text[offset:end]
            # First definition wins. A duplicate name across files cannot both
            # be live in one compile anyway.
            index.setdefault(name, {"file": path, "body": body})

    return index


def _filesize_blockers(body: str, assumed_dump_bytes: int) -> list[str]:
    """Filesize upper bounds that a dump of the assumed size cannot satisfy."""
    blockers: list[str] = []
    for value, unit in _FILESIZE_BOUND.findall(body):
        try:
            limit = int(value) * _UNIT_BYTES[unit.upper() if unit else ""]
        except (ValueError, KeyError):
            continue
        if limit < assumed_dump_bytes:
            blockers.append(
                f"bounded to filesize < {value}{unit or 'B'}, below a {assumed_dump_bytes // (1024 * 1024)} MB dump"
            )
    return blockers


def classify_rule(
    name: str,
    index: dict[str, dict[str, Any]],
    assumed_dump_mb: int = DEFAULT_ASSUMED_DUMP_MB,
) -> dict[str, Any]:
    """Decide whether a rule could ever match a raw process dump.

    Three things independently disqualify a rule, and a rule can carry more than
    one. Reporting all of them rather than the first matters when deciding
    whether a candidate is salvageable: a lone filesize bound might be worth
    scanning a smaller dump for, whereas an anchored magic test never will be.
    """
    entry = index.get(name)
    if entry is None:
        # Not finding the source is not a reason to discard the rule; it only
        # means the expectation cannot be justified in advance.
        return {
            "rule": name,
            "file": "",
            "memory_viable": None,
            "reason": "rule source not located; viability unknown",
        }

    body = entry["body"]
    reasons: list[str] = []

    if _USES_PE.search(body):
        reasons.append("gated on the pe module")
    if _ANCHORED_MAGIC.search(body):
        reasons.append("anchored to a magic number at offset 0, where a dump has MDMP")
    reasons.extend(_filesize_blockers(body, assumed_dump_mb * 1024 * 1024))

    return {
        "rule": name,
        "file": str(entry["file"].relative_to(REPO_ROOT)) if _under_repo(entry["file"]) else str(entry["file"]),
        "memory_viable": not reasons,
        "reason": "; ".join(reasons) if reasons else "string-based, so it can match a minidump",
    }


def _under_repo(path: Path) -> bool:
    try:
        path.relative_to(REPO_ROOT)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Packing
# ---------------------------------------------------------------------------

def find_upx(configured: str | Path | None = None) -> Optional[Path]:
    """Locate upx.exe, preferring the copy bootstrap_tools.ps1 installs."""
    if configured:
        candidate = Path(configured).expanduser()
        if candidate.is_file():
            return candidate

    local = REPO_ROOT / "tools" / "upx.exe"
    if local.is_file():
        return local

    found = shutil.which("upx")
    return Path(found) if found else None


def pack(upx: Path, source: Path, destination: Path) -> dict[str, Any]:
    """UPX-pack ``source`` into ``destination``, leaving the original intact."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        destination.unlink()

    result = subprocess.run(
        [str(upx), "--best", "--force", "-o", str(destination), str(source)],
        capture_output=True,
        text=True,
        timeout=300,
    )

    # Unlike ProcDump, UPX does report failure through its return code -- but the
    # written file is still the thing that matters downstream, so both are
    # checked.
    packed = destination.exists() and destination.stat().st_size > 0
    return {
        "packed": packed,
        "returncode": result.returncode,
        "output": (result.stdout or "") + (result.stderr or ""),
        "path": str(destination),
        "size": destination.stat().st_size if packed else 0,
    }


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def scan(compiled: Any, path: Path, timeout: int) -> list[str]:
    matches = compiled.match(str(path), timeout=timeout)
    return sorted({getattr(m, "rule", "") for m in matches if getattr(m, "rule", "")})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build and validate a UPX-packed YARA positive control.",
    )
    parser.add_argument("--sample", required=True, help="The binary to pack. Must already be detected on disk.")
    parser.add_argument("--out", default="", help="Packed output path. Default: <sample>.upx.exe beside the sample.")
    parser.add_argument("--rules", default="", help="Override the rules directory. Default: whatever the dynamic run uses.")
    parser.add_argument("--upx", default="", help="Path to upx.exe. Default: tools\\upx.exe, then PATH.")
    parser.add_argument("--timeout", type=int, default=120, help="Per-file YARA timeout in seconds.")
    parser.add_argument(
        "--assume-dump-mb",
        type=int,
        default=DEFAULT_ASSUMED_DUMP_MB,
        help="Dump size assumed when judging filesize bounds in rules.",
    )
    parser.add_argument("--json", default="", help="Also write the full result as JSON to this path.")
    args = parser.parse_args()

    if yara is None:
        print("ERROR: yara-python is not installed. Run this in the analysis VM's venv.")
        return 1

    sample = Path(args.sample).expanduser()
    if not sample.is_file():
        print(f"ERROR: sample not found: {sample}")
        return 1

    upx = find_upx(args.upx)
    if upx is None:
        print("ERROR: upx.exe not found. Run scripts\\bootstrap_tools.ps1, or pass --upx.")
        return 1

    rules_dir = resolve_rules_dir(args.rules or None)
    if rules_dir is None:
        print("ERROR: no YARA rules directory found. Run scripts\\bootstrap_yara_rules.ps1 first.")
        return 1

    rule_files = _collect_rule_files(rules_dir)
    if not rule_files:
        print(f"ERROR: no .yar or .yara files under {rules_dir}")
        return 1

    print(f"Rules:  {rules_dir} ({len(rule_files)} file(s))")
    print(f"UPX:    {upx}")
    print(f"Sample: {sample}")
    print()

    print("Compiling the ruleset...")
    try:
        compiled = yara.compile(filepaths=rule_files, externals=dict(_COMMON_EXTERNALS))
    except Exception as error:
        print(f"ERROR: rule compilation failed: {error}")
        return 1

    # --- Step 1: the candidate must be detected before packing -------------
    print("Scanning the unpacked candidate on disk...")
    try:
        before = scan(compiled, sample, args.timeout)
    except Exception as error:
        print(f"ERROR: scanning the sample failed: {error}")
        return 1

    if not before:
        print()
        print("NOT A VIABLE CONTROL: the ruleset does not detect this binary on disk.")
        print("Packing something already invisible proves nothing. Pick another candidate.")
        return 2

    index = index_rule_sources(rule_files)
    classified = [classify_rule(name, index, args.assume_dump_mb) for name in before]
    viable = [c for c in classified if c["memory_viable"] is not False]

    print(f"  {len(before)} rule(s) matched:")
    for entry in classified:
        marker = "  " if entry["memory_viable"] is not False else "! "
        print(f"    {marker}{entry['rule']}  [{entry['reason']}]")
    print()

    if not viable:
        print("NOT A VIABLE CONTROL: every rule that detects this binary is gated on the")
        print("pe module. None of them can match a raw minidump, so a memory-only result")
        print("is impossible regardless of whether the dump is correct.")
        return 2

    # --- Step 2: packing must actually destroy the detection ---------------
    destination = Path(args.out).expanduser() if args.out else sample.with_suffix(".upx" + sample.suffix)
    print(f"Packing to {destination.name}...")
    packing = pack(upx, sample, destination)
    if not packing["packed"]:
        print(f"ERROR: UPX did not produce an output file (rc={packing['returncode']}).")
        print(packing["output"].strip())
        return 1
    print(f"  {sample.stat().st_size:,} bytes -> {packing['size']:,} bytes")

    print("Scanning the packed binary on disk...")
    try:
        after = scan(compiled, destination, args.timeout)
    except Exception as error:
        print(f"ERROR: scanning the packed file failed: {error}")
        return 1

    broken = sorted(set(before) - set(after))
    survived = sorted(set(before) & set(after))
    gained = sorted(set(after) - set(before))

    if survived:
        print(f"  {len(survived)} rule(s) still match after packing: {', '.join(survived)}")
    if gained:
        # Almost always a packer-detection rule firing on the UPX stub. Harmless:
        # it adds to the disk set, which only makes the memory-only test stricter.
        print(f"  {len(gained)} new rule(s) match the packed file: {', '.join(gained)}")

    # The expectation is the intersection: broken by packing *and* able to match
    # a dump. A rule that is only one of the two proves nothing when it reappears
    # or fails to.
    viable_names = {c["rule"] for c in viable}
    expected = sorted(set(broken) & viable_names)

    print()
    if not broken:
        print("NOT A VIABLE CONTROL: packing did not break a single detection.")
        print("The rules matching this binary survive compression, so there is no")
        print("memory-versus-disk delta to observe. Try a different candidate.")
        return 2

    if not expected:
        print("NOT A VIABLE CONTROL: packing broke detections, but only pe-gated ones.")
        print("Those cannot return in a minidump, so the detonation cannot succeed.")
        return 2

    result = {
        "sample": str(sample),
        "packed": str(destination),
        "rules_dir": str(rules_dir),
        "rule_file_count": len(rule_files),
        "disk_rules_before": before,
        "disk_rules_after": after,
        "classified": classified,
        "broken_by_packing": broken,
        "survived_packing": survived,
        "gained_by_packing": gained,
        "expected_memory_only_rules": expected,
    }

    if args.json:
        json_path = Path(args.json).expanduser()
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"Wrote {json_path}")
        print()

    print("CONTROL READY.")
    print(f"  Detonate: {destination}")
    print(f"  Expect these under 'matched in memory but not on disk' ({len(expected)}):")
    for name in expected:
        print(f"    {name}")
    print()
    print("  Anything less means the dump or the delta logic is at fault -- every")
    print("  other explanation has been eliminated above.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
