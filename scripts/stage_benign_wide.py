"""Stage a wider benign corpus from this host: many vendors, few from each.

**The benign half of the headline is the weak half, and this is why.** The
102-sample `benign-embedded` corpus came from `stage_managed_apps.py`, which
collects managed applications only -- so it is Visual Studio test hosts,
ASUS / Armoury Crate and Overwolf, and its 9.0% Corroborated-or-stronger rate
describes those vendors more than benign software. This collects native and
managed programs from every vendor installed here, capped per signer so no
single vendor dominates again.

    .venv\\Scripts\\python.exe scripts\\stage_benign_wide.py --out G:\\ringforge-corpus\\benign-wide [--dry-run]

What is kept, and why each filter exists:

* **Programs only**: `.exe`, no `IMAGE_FILE_DLL` flag, machine x86 or x64. The
  guest is x64 and the detonator launches with CreateProcess -- the 9 ARM64
  builds in `benign-102` never ran.
* **Embedded Authenticode, status Valid.** Catalog-signed files read as
  unsigned in the guest and fire the signer-mismatch detector -- measured
  15 Sep on `notepad.exe`. So nothing from `System32`, and `Get-AuthenticodeSignature`
  must report `SignatureType Authenticode`, not `Catalog`.
* **Not the analyzer's own tools** (Wireshark / dumpcap, Procmon, Sysmon,
  Python, FakeNet, procdump): `findings.py` suppresses them by name, so they
  would measure the suppression list, not the scorer.
* **Not security, anti-cheat, VPN or network-scanning products.** Their label
  is arguable or they load drivers, and a disputed label is worse than a
  missing sample.
* **Not already in a benign corpus** (by SHA-256).
* **At most `--per-signer` from each signer** (default 3), chosen by name so
  a re-run picks the same files.

Named `<stem>_<sha8>.exe` with anything outside `[A-Za-z0-9._-]` made a
hyphen: case names are derived from the file name, and basenames collide.

**These are ordinary programs from this machine, copied inbound to an analysis
VM.** Nothing here is a sample and nothing leaves the guest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

_IMAGE_FILE_DLL = 0x2000
_SECURITY_DIRECTORY = 4
_MACHINES = {0x14C: "x86", 0x8664: "x64"}
_DEFAULT_ROOTS = (r"C:\Program Files", r"C:\Program Files (x86)")
_MAX_BYTES = 200 * 1024 * 1024

#: Directory fragments (lower case) that are never harvested. See the module
#: docstring for the reason behind each group.
EXCLUDED_DIRS = (
    # the analyzer's own tools
    "\\wireshark", "\\npcap", "\\python", "sysinternals", "\\fakenet",
    # security, anti-cheat, VPN, network scanning
    "\\bitdefender", "\\windows defender", "\\easyanticheat", "\\battleye", "\\ipvanish",
    "\\nmap", "\\cloudflared",
    # the platform itself rather than an application
    "\\windowsapps", "\\windows nt", "\\windowspowershell", "\\common files\\microsoft shared\\ink",
)

#: Image names never harvested wherever they sit: the analyzer's tools, which
#: `findings.ANALYZER_TOOL_PROCESS_NAMES` suppresses by name.
EXCLUDED_NAMES = {
    "procmon.exe", "procmon64.exe", "autorunsc.exe", "autorunsc64.exe",
    "python.exe", "pythonw.exe", "fakenet.exe", "dumpcap.exe", "tshark.exe",
    "sysmon.exe", "sysmon64.exe", "procdump.exe", "procdump64.exe",
}


def candidates(roots: list[Path]):
    """Programs with an embedded signature directory, x86 or x64."""
    import pefile

    for root in roots:
        if not root.is_dir():
            continue
        for dirpath, _dirs, files in os.walk(root):
            lowered = dirpath.lower()
            if any(fragment in lowered for fragment in EXCLUDED_DIRS):
                continue
            for name in files:
                if not name.lower().endswith(".exe") or name.lower() in EXCLUDED_NAMES:
                    continue
                path = Path(dirpath) / name
                try:
                    size = path.stat().st_size
                    if size == 0 or size > _MAX_BYTES:
                        continue
                    pe = pefile.PE(str(path), fast_load=True)
                    library = bool(pe.FILE_HEADER.Characteristics & _IMAGE_FILE_DLL)
                    machine = _MACHINES.get(pe.FILE_HEADER.Machine)
                    directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
                    embedded = (len(directories) > _SECURITY_DIRECTORY
                                and directories[_SECURITY_DIRECTORY].VirtualAddress != 0)
                    pe.close()
                except Exception:                       # noqa: BLE001
                    continue
                if machine and embedded and not library:
                    yield path, machine, size


def signatures(paths: list[Path]) -> dict[str, dict[str, str]]:
    """`Get-AuthenticodeSignature` for each path, in one PowerShell call.

    A security directory proves a signature is *present*, not that it is valid
    or that Windows reads it as embedded, so this is the check that decides.
    """
    listing = Path(os.environ.get("TEMP", ".")) / "ringforge_benign_wide_paths.txt"
    listing.write_text("\n".join(str(p) for p in paths), encoding="utf-8")
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        f"Get-Content -LiteralPath '{listing}' -Encoding UTF8 | ForEach-Object {{"
        # [string]: a Get-Content line carries PSPath and friends, and
        # PowerShell 5.1's ConvertTo-Json serialises it as an object.
        " $p = [string]$_; $s = Get-AuthenticodeSignature -LiteralPath $p;"
        " [pscustomobject]@{path=$p; status=[string]$s.Status;"
        " type=[string]$s.SignatureType;"
        " signer=$(if ($s.SignerCertificate) { $s.SignerCertificate.GetNameInfo('SimpleName', $false) } else { '' })}"
        "} | ConvertTo-Json -Compress"
    )
    out = subprocess.run(["powershell.exe", "-NoProfile", "-Command", script],
                         capture_output=True, text=True, encoding="utf-8", check=False).stdout
    listing.unlink(missing_ok=True)
    rows = json.loads(out) if out.strip() else []
    if isinstance(rows, dict):
        rows = [rows]
    return {row["path"]: row for row in rows}


def known_hashes(corpus_dirs: list[Path]) -> set[str]:
    seen: set[str] = set()
    for directory in corpus_dirs:
        if directory.is_dir():
            for path in directory.iterdir():
                if path.is_file() and path.suffix.lower() == ".exe":
                    seen.add(hashlib.sha256(path.read_bytes()).hexdigest())
    return seen


def vendor_key(signer: str) -> str:
    """One key per vendor, however its certificates spell it.

    `ASUSTeK COMPUTER INC.`, `ASUSTeK Computer Inc.` and `ASUSTEK COMPUTER
    INCORPORATION` are one vendor, and capping each spelling separately let
    ASUS take seven places. The first significant word is the vendor.
    """
    words = [w for w in re.findall(r"[a-z0-9]+", signer.lower()) if w != "the"]
    return words[0] if words else "?"


def crowded_vendors(records: list[Path], at_least: int) -> set[str]:
    """Vendors an earlier corpus already holds `at_least` samples of."""
    counts: dict[str, int] = defaultdict(int)
    for record in records:
        if record.is_file():
            data = json.loads(record.read_text(encoding="utf-8-sig"))
            for signer, count in (data.get("signers") or {}).items():
                counts[vendor_key(signer)] += int(count)
    return {vendor for vendor, count in counts.items() if count >= at_least}


def safe_name(stem: str, digest: str) -> str:
    return f"{re.sub(r'[^A-Za-z0-9._-]', '-', stem)}_{digest[:8]}.exe"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, help="corpus directory to create")
    parser.add_argument("--root", action="append", default=[])
    parser.add_argument("--per-signer", type=int, default=3)
    parser.add_argument("--exclude-corpus", action="append",
                        default=[r"G:\ringforge-corpus\benign-embedded",
                                 r"G:\ringforge-corpus\benign-dotnet2"])
    parser.add_argument("--crowded-at", type=int, default=5,
                        help="skip vendors an excluded corpus already holds this many of")
    parser.add_argument("--dry-run", action="store_true",
                        help="list what would be staged; copy nothing")
    args = parser.parse_args(argv)

    roots = [Path(r) for r in (args.root or list(_DEFAULT_ROOTS))]
    found = list(candidates(roots))
    sigs = signatures([p for p, _m, _s in found])
    already = known_hashes([Path(p) for p in args.exclude_corpus])
    # Widening is the point: a vendor the old corpus is already heavy with adds
    # nothing, and those vendors are exactly what made it narrow.
    crowded = crowded_vendors(
        [Path(p).parent / f"{Path(p).name}._corpus.json" for p in args.exclude_corpus],
        args.crowded_at)

    excluded: list[dict[str, str]] = []
    skipped_crowded: dict[str, int] = defaultdict(int)
    by_signer: dict[str, list[dict]] = defaultdict(list)
    hashes_seen: set[str] = set()
    for path, machine, size in found:
        sig = sigs.get(str(path), {})
        if sig.get("status") != "Valid" or sig.get("type") != "Authenticode":
            excluded.append({"source": str(path),
                             "reason": f"signature {sig.get('status') or '?'} / {sig.get('type') or '?'}"})
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest in already or digest in hashes_seen:
            continue
        hashes_seen.add(digest)
        vendor = vendor_key(sig.get("signer") or "?")
        if vendor in crowded:
            skipped_crowded[vendor] += 1
            continue
        by_signer[vendor].append(
            {"source": str(path), "sha256": digest, "size": size,
             "machine": machine, "signer": sig.get("signer") or "?"})

    chosen: list[dict] = []
    for signer in sorted(by_signer, key=str.lower):
        picks = sorted(by_signer[signer], key=lambda r: r["source"].lower())[: args.per_signer]
        chosen.extend(picks)

    for row in chosen:
        row["name"] = safe_name(Path(row["source"]).stem, row["sha256"])
    signer_counts = {
        f"{v[0]['signer']} [{s}]": min(len(v), args.per_signer)
        for s, v in sorted(by_signer.items())
    }
    print(f"{len(found)} signed x86/x64 programs, {len(chosen)} chosen "
          f"from {len(by_signer)} vendors (at most {args.per_signer} each)")
    print(f"skipped as already crowded in the old corpus: {dict(skipped_crowded)}")
    for signer, count in signer_counts.items():
        print(f"  {count}  {signer}")
    if args.dry_run:
        for row in chosen:
            print(f"    {row['name']:<60} {row['machine']}  {row['source']}")
        return 0

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=False)
    for row in chosen:
        shutil.copy2(row["source"], out / row["name"])
        if hashlib.sha256((out / row["name"]).read_bytes()).hexdigest() != row["sha256"]:
            raise SystemExit(f"copy of {row['source']} does not hash-match")
    record = {
        "corpus": out.name,
        "built": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": [str(r) for r in roots],
        "label": "benign",
        "why": ("Wider benign corpus: native and managed programs from every vendor "
                "on this host, capped per signer. Embedded Authenticode (Valid) only, "
                "x86/x64 only, no analyzer tools, no security / anti-cheat / VPN / "
                "scanning products, nothing already in a benign corpus."),
        "per_signer": args.per_signer,
        "crowded_vendors_skipped": dict(skipped_crowded),
        "counts": {"signed_programs": len(found), "chosen": len(chosen),
                   "vendors": len(by_signer), "signature_excluded": len(excluded)},
        "signers": signer_counts,
        "excluded_samples": excluded,
        "samples": chosen,
    }
    (out.parent / f"{out.name}._corpus.json").write_text(
        json.dumps(record, indent=1), encoding="utf-8")
    print(f"staged {len(chosen)} into {out}; record {out.parent / (out.name + '._corpus.json')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
