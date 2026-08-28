"""Cheap CLR facts for every sample, so managed code stops being invisible.

**59% of what the static module cannot see is managed code.** Of the 22 malware
samples that survived every category on 28 Aug, 13 are .NET assemblies. The
reason is structural: a managed binary imports `mscoree.dll` and nothing else
and keeps its call graph in CLR metadata, while every category the module has
reads the import table, the section table or the version block. Adding a seventh
thing that reads those three cannot see a population defined by having nothing
in them.

This is the collector, not the category. It answers three questions per sample
and none of them need a decompiler:

* is this managed at all, and is it IL-only or mixed-mode C++/CLI
* how much of the `#Strings` heap is unreadable -- obfuscators rename every
  type, method and field, and benign assemblies do not
* does it name a protector outright

`scripts/dotnet_meta.py` is the analyst tool for one carved payload;
this runs over a corpus. It reuses that module's `DotNetImage` so there is one
metadata parser rather than two that can disagree.

**No category ships from this until the malware side is measured.** The benign
floor below was established on 592 binaries; the detection rate needs the guest,
where the malware samples are.
"""

from __future__ import annotations

import json
import string
from pathlib import Path
from typing import Any

#: `COMIMAGE_FLAGS_ILONLY`. A mixed-mode C++/CLI assembly carries mangled native
#: symbols in `#Strings` -- `mfcm140u.dll` reads as 20.1% unreadable and is
#: entirely legitimate -- so the two populations are separated rather than
#: thresholded apart.
_COR_ILONLY = 0x00000001

#: Characters a compiler-generated or human-written .NET identifier is built
#: from. Anything else is a renamer's output: obfuscators emit non-ASCII,
#: zero-width and homoglyph characters precisely because they are legal here.
_IDENTIFIER_CHARS = frozenset(string.ascii_letters + string.digits + "_.<>`@$-+ ")

#: Below this the fraction is noise, not a measurement. A satellite resource
#: assembly with five identifiers reads 0.200 unreadable on a single generic
#: type name, which is the benign maximum until the count is floored.
_MIN_IDENTIFIERS = 50

#: Protectors that sign their work. Matching is exact and case-folded against
#: whole identifiers, never a substring of one, because `Confused` appears
#: inside ordinary words.
_PROTECTOR_MARKERS = {
    "confusedbyattribute": "ConfuserEx",
    "dotnetreactor": ".NET Reactor",
    "smartassembly": "SmartAssembly",
    "eazfuscator": "Eazfuscator.NET",
    "babelattribute": "Babel",
    "obfuscar": "Obfuscar",
    "dotfuscatorattribute": "Dotfuscator",
    "netguard": "NETGuard",
    "agiledotnet": "Agile.NET",
    "securteam": "SecureTeam",
}


def _looks_renamed(name: str) -> bool:
    """A name no compiler and no developer would produce.

    Two independent tells: a character outside the identifier set at all, or
    four or more letters without a vowel among them.
    """
    if any(c not in _IDENTIFIER_CHARS for c in name):
        return True
    letters = "".join(c for c in name if c.isalpha())
    return len(letters) >= 4 and not any(v in letters.lower() for v in "aeiou")


def extract_dotnet_metadata(sample_path: Path) -> dict[str, Any]:
    """CLR facts for one sample. Never raises for a native binary."""
    from scripts.dotnet_meta import DotNetImage

    out: dict[str, Any] = {"is_managed": False, "collected": True}
    try:
        image = DotNetImage(sample_path)
    except Exception as error:
        # **Not managed and could not be parsed are different answers.** The
        # first is a fact about the sample; the second must not read as one.
        text = str(error)
        if "not a managed image" in text:
            return out
        out["collected"] = False
        out["error"] = f"{type(error).__name__}: {text}"[:200]
        return out

    out["is_managed"] = True
    out["runtime_version"] = image.runtime_version
    out["cor_flags"] = int(image.cor_flags)
    out["il_only"] = bool(image.cor_flags & _COR_ILONLY)

    try:
        base, size = image.heaps["#Strings"]
        blob = image.data[base:base + size]
        names = [p.decode("utf-8", "replace") for p in blob.split(b"\x00") if p]
    except Exception as error:
        out["collected"] = False
        out["error"] = f"#Strings unreadable: {type(error).__name__}: {error}"[:200]
        return out

    out["identifier_count"] = len(names)
    if names:
        renamed = sum(1 for n in names if _looks_renamed(n))
        short = sum(1 for n in names if len(n) <= 2)
        out["unreadable_fraction"] = round(renamed / len(names), 4)
        out["short_name_fraction"] = round(short / len(names), 4)
    else:
        out["unreadable_fraction"] = 0.0
        out["short_name_fraction"] = 0.0
    # Below the floor the fraction is arithmetic on too few names to mean
    # anything; the reader is told rather than left to infer it.
    out["identifiers_sufficient"] = len(names) >= _MIN_IDENTIFIERS

    folded = {n.strip().lower().lstrip(".") for n in names}
    out["protectors"] = sorted(
        {label for marker, label in _PROTECTOR_MARKERS.items() if marker in folded})
    return out


def write_dotnet_metadata(out_path: Path, meta: dict[str, Any]) -> None:
    out_path.write_text(json.dumps(meta, indent=2, sort_keys=True),
                        encoding="utf-8")
