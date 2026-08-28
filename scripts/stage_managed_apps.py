"""Stage benign managed *applications* for a capa run on the guest.

**The sixteen namespaces at infinite lift were a confound, and this is what
tests it.** Restricting the capa comparison to managed code produced
`collection/keylog` at 12.6% of malware and 0.0% of benign -- but the 51 benign
managed samples carrying capa are almost all libraries and satellite resource
assemblies, and all 103 malware samples are applications. A library does not
take screenshots whatever its intent, so that measured
library-against-application.

This collects the other half: every managed assembly on the host with an entry
point and no `IMAGE_FILE_DLL` flag. capa lives on the guest and the benign
software lives here, so the files are staged for copying rather than analysed
in place.

    .venv\\Scripts\\python.exe scripts\\stage_managed_apps.py --out G:\\managed-apps-staging

Then, on the guest, over the copied folder:

    .venv\\Scripts\\python.exe scripts\\static_corpus.py --root <copied> --recursive \\
        --count 126 --out C:\\benign-managed-cases
    .venv\\Scripts\\python.exe scripts\\benign_rates.py --module static \\
        --cases C:\\benign-managed-cases\\cases

`static_corpus.py` is the designed path -- it runs `engine.run_case`, so capa,
YARA and the IOC pass all happen exactly as they do for any other corpus, and
the result is comparable to the malware corpora rather than to a reimplementation.

**These are ordinary programs from this machine, copied inbound to an analysis
VM.** Nothing here is a sample and nothing leaves the guest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_IMAGE_FILE_DLL = 0x2000
_COM_DESCRIPTOR = 14
_DEFAULT_ROOTS = (
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\Windows\SysWOW64",
    r"C:\Windows\System32",
)


def managed_applications(roots: list[Path]):
    """Managed, has an entry point, is not a library."""
    import os

    import pefile

    scanned = 0
    for root in roots:
        if not root.is_dir():
            continue
        for dirpath, _dirs, files in os.walk(root):
            for name in files:
                if not name.lower().endswith(".exe"):
                    continue
                path = Path(dirpath) / name
                scanned += 1
                try:
                    pe = pefile.PE(str(path), fast_load=True)
                    is_library = bool(pe.FILE_HEADER.Characteristics & _IMAGE_FILE_DLL)
                    directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
                    managed = (len(directories) > _COM_DESCRIPTOR
                               and directories[_COM_DESCRIPTOR].VirtualAddress != 0)
                    pe.close()
                except Exception:
                    continue
                if managed and not is_library:
                    yield path, scanned


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, help="staging directory")
    parser.add_argument("--root", action="append", default=[])
    args = parser.parse_args(argv)

    roots = [Path(r) for r in (args.root or list(_DEFAULT_ROOTS))]
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    manifest = []
    scanned = 0
    for path, scanned in managed_applications(roots):
        # **Named by content, because basenames collide.** Four different
        # `Uninstaller.exe` would overwrite each other in a flat directory and
        # the corpus would silently be three samples short.
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            continue
        target = out / f"{path.stem}_{digest[:8]}{path.suffix}"
        if target.exists():
            continue
        try:
            shutil.copy2(path, target)
        except OSError as error:
            print(f"  skipped {path.name}: {error}")
            continue
        manifest.append({"staged": target.name, "source": str(path),
                         "sha256": digest, "size": target.stat().st_size})

    (out / "_staged.json").write_text(
        json.dumps({"roots": [str(r) for r in roots],
                    "scanned_exe": scanned,
                    "staged": len(manifest),
                    "note": "benign managed applications from the host; "
                            "capa runs on the guest",
                    "files": manifest}, indent=1),
        encoding="utf-8")

    total_mb = sum(m["size"] for m in manifest) / (1024 * 1024)
    print(f"scanned {scanned} .exe, staged {len(manifest)} managed applications "
          f"({total_mb:.0f} MB) into {out}")
    print(f"manifest: {out / '_staged.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
