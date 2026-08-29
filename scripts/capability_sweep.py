"""Re-test `HIGH_SIGNAL_CAPABILITIES` and `CAPABILITY_PRESENT_AT` on every corpus.

**Two things went stale under the same measurement.** The set and its threshold
were fitted on 532 benign samples that are overwhelmingly native and, where
managed, overwhelmingly libraries. Adding 124 benign .NET *applications* on
28 Aug showed `dangerous_capability` firing at **17.7%** there against the 1.1%
and 4.0% published -- so the benign side the threshold was chosen against did
not contain the population it is worst on.

The same corpus proposed candidate additions: `data-manipulation/encryption/aes`
at 19.3x, `prng` at 11.0x, `host-interaction/gui/window/get-text` at 10.8x,
`collection/keylog` at 5.2x. **Those lifts were measured on managed applications
alone, which is not a reason to add them.** A member chosen on one population and
never checked against the rest is how a set stops meaning what its name says.

So this runs the original test again, over everything:

    .venv\\Scripts\\python.exe scripts\\capability_sweep.py

* per-namespace benign and malware rates across all five corpora
* the threshold sweep for the shipped set
* the same sweep with candidates added, so a change is accepted only if
  detection rises while the benign rate does not

**Nothing here edits the set.** It prints the evidence for doing so, or against.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_BENIGN = {
    "Sys32": r"G:\static-corpus-full\cases",
    "ProgFiles": r"G:\pf-corpus\cases",
    "managed apps": r"G:\benign-managed-cases\cases",
}
_MALWARE = {
    "family": r"C:\Users\aring\Downloads\ringforge\cases\bazaar2\cases",
    "6-year": r"C:\Users\aring\Downloads\ringforge\cases\datalake2\cases",
}

#: Proposed by the managed-application comparison on 28 Aug and **not** shipped.
#: Listed here so the test is reproducible and so the reason each one survives
#: or fails is written down rather than remembered.
_CANDIDATES = (
    "data-manipulation/encryption/aes",
    "data-manipulation/prng",
    "host-interaction/gui/window/get-text",
    "collection/keylog",
    "communication/tcp",
    "communication/socket",
    "data-manipulation/hashing/sha256",
    "data-manipulation/hashing/md5",
    "host-interaction/hardware/storage",
    "host-interaction/hardware/cpu",
)


def namespaces_per_case(root: Path) -> list[set[str]]:
    from static_triage_engine.combine_case import capa_namespaces

    out = []
    for case in sorted(p for p in root.iterdir() if p.is_dir()):
        capa_path = next((p for p in (case / "capa.json",
                                      case / "static_analysis" / "capa.json")
                          if p.is_file()), None)
        if capa_path is None:
            continue
        try:
            data = json.loads(capa_path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        out.append(set(capa_namespaces(data) or []))
    return out


def rate(samples: list[set[str]], members: frozenset[str], at: int) -> float:
    if not samples:
        return 0.0
    return 100.0 * sum(1 for s in samples if len(s & members) >= at) / len(samples)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.parse_args(argv)

    from static_triage_engine.scoring import (
        CAPABILITY_PRESENT_AT, CAPABILITY_STRONG_AT, HIGH_SIGNAL_CAPABILITIES)

    benign = {k: namespaces_per_case(Path(v)) for k, v in _BENIGN.items()
              if Path(v).is_dir()}
    malware = {k: namespaces_per_case(Path(v)) for k, v in _MALWARE.items()
               if Path(v).is_dir()}
    all_benign = [s for v in benign.values() for s in v]
    all_malware = [s for v in malware.values() for s in v]
    print(f"benign  {len(all_benign):4}  "
          + ", ".join(f"{k} {len(v)}" for k, v in benign.items()))
    print(f"malware {len(all_malware):4}  "
          + ", ".join(f"{k} {len(v)}" for k, v in malware.items()))

    print(f"\n=== candidates, on all {len(all_benign)} benign and "
          f"{len(all_malware)} malware")
    print(f"{'lift':>7} {'malware':>8} {'benign':>8}  namespace")
    scored = []
    for ns in _CANDIDATES:
        b = 100.0 * sum(1 for s in all_benign if ns in s) / len(all_benign)
        m = 100.0 * sum(1 for s in all_malware if ns in s) / len(all_malware)
        scored.append(((m / b) if b else float("inf"), m, b, ns))
    for lift, m, b, ns in sorted(scored, reverse=True):
        text = "inf" if lift == float("inf") else f"{lift:.1f}x"
        print(f"{text:>7} {m:7.1f}% {b:7.1f}%  {ns}")

    for label, members in (("shipped set", HIGH_SIGNAL_CAPABILITIES),
                           ("set + candidates",
                            HIGH_SIGNAL_CAPABILITIES | frozenset(_CANDIDATES))):
        print(f"\n=== {label}: {len(members)} namespaces")
        print("  at " + "".join(f"{k:>14}" for k in benign)
              + f"{'benign':>12}{'malware':>12}{'lift':>8}")
        for at in range(2, 7):
            cells = "".join(f"{rate(v, members, at):13.1f}%" for v in benign.values())
            b, m = rate(all_benign, members, at), rate(all_malware, members, at)
            mark = "  <- present" if at == CAPABILITY_PRESENT_AT else ""
            mark += "  <- strong" if at == CAPABILITY_STRONG_AT else ""
            lift = f"{m / b:.1f}x" if b else "inf"
            print(f"  {at:2}{cells}{b:11.1f}%{m:11.1f}%{lift:>8}{mark}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
