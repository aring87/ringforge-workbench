"""What static analysis can claim about a sample, as evidence categories.

Phase 2 of `docs/SCORING.md`. This is the static half of `corroboration-v1`:
the same contract `dynamic_analysis` emits, so the combiner can count agreement
across the two instead of adding their scores together.

**Written alongside `scoring.py` rather than replacing it.** Nothing consumes
this yet -- the swap happens in Phase 4, with the report -- so the additive
scorer stays live and its callers keep working. Two scorers briefly coexisting
is the cost of not breaking the GUI mid-migration; the additive one is deleted
when the last consumer moves.

**Everything is injected, nothing is read from disk.** `scoring.score_static`
reaches into the case directory for `yara_results.json`, `capa.json` and
`signing.json`, which is why it has one real test: exercising it means building
a case folder. Here every input is a parameter, so the discrimination test can
state a contract in six lines. That matters practically as well: the sample
binaries are not on this host, so a fixture-replay test could not be written
today even if it were the better design.

**`None` means the collector did not run. `{}` means it ran and found nothing.**
The distinction is the whole point of `collected`, and collapsing the two is the
mistake this model exists to prevent -- `capa` with no ruleset and a clean
sample are not the same observation, and a scorer that cannot tell them apart
reports the second when it saw the first.
"""

from __future__ import annotations

import re
from typing import Any, Sequence

from verdict import MAX_CONTEXT_SCORE, Category

from static_triage_engine.scoring import (
    HIGH_SIGNAL_TECH_PREFIXES,
    _extract_observables,
    _has_only_known_benign_infra,
    _pe_string_table,
    _prefix_in,
)

#: Rule text that names a malware family or role, rather than a technique. Three
#: unrelated rules agreeing is emphatic; so is one that says "stealer".
_FAMILY_WORDS = ("malware", "loader", "trojan", "ransom", "backdoor",
                 "stealer", "rat")

#: Extensions that are executable but read as documents or are unusual enough
#: to be worth a claim on their own.
_SUSPICIOUS_EXTENSIONS = (".scr", ".com", ".js", ".jse", ".vbs", ".ps1", ".hta")

#: A name that is only a hash is a name chosen to say nothing.
_HASH_NAME = re.compile(r"^[0-9a-f]{24,}(\.(exe|dll|scr|com|bat|ps1))?$")

#: `document.pdf.exe`. The first extension is the lie.
_DOUBLE_EXTENSION = re.compile(
    r"\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|jpg|jpeg|png|gif|zip|rar)"
    r"\.(exe|scr|com|bat|cmd|pif|js|vbs|hta)$")

#: U+202E, which reverses the display of everything after it: `exe.txt` becomes
#: `txt.exe` to the eye. Nothing legitimate puts one in a filename.
_RLO = "‮"


def _sample_name(summary: dict[str, Any]) -> str:
    info = summary.get("sample", {}) if isinstance(summary.get("sample"), dict) else {}
    return str(
        info.get("filename")
        or info.get("name")
        or info.get("path")
        or info.get("path_case")
        or ""
    ).strip().lower()


def _yara_signal(matches: Sequence[Any]) -> tuple[int, list[str]]:
    """Count rules naming a family or role, and collect the rule names.

    Reproduces the classification `scoring._score_yara_evidence` already used,
    because it was checked against real rule sets and rewriting it here would
    make the two disagree for no reason.
    """
    family = 0
    names: list[str] = []
    for match in matches or []:
        if not isinstance(match, dict):
            continue
        rule = str(match.get("rule", "") or "").strip()
        if rule:
            names.append(rule)
        meta = match.get("meta", {}) if isinstance(match.get("meta"), dict) else {}
        tags = [str(x).lower() for x in (match.get("tags", []) or [])
                if isinstance(x, (str, int, float))]
        severity = str(meta.get("severity", "") or "").strip().lower()
        text = " ".join([rule.lower(), severity] + tags)
        if severity in {"critical", "high"} or any(w in text for w in _FAMILY_WORDS):
            family += 1
    return family, names


def static_categories(
    *,
    summary: dict[str, Any] | None = None,
    iocs: dict[str, Any] | None = None,
    pe_meta: dict[str, Any] | None = None,
    api_analysis: dict[str, Any] | None = None,
    yara_results: dict[str, Any] | None = None,
    signing: dict[str, Any] | None = None,
    techniques: Sequence[str] | None = None,
    capa_match_count: int | None = None,
) -> tuple[list[Category], int]:
    """Every category static analysis can author, present or not.

    Returns `(categories, context_score)`. The list is complete -- a module that
    runs emits its whole category set, absent ones included, because that is
    what makes an absence mean anything.

    `context_score` is descriptive volume. It never decides a band.
    """
    cats: list[Category] = []

    # --- Signature ----------------------------------------------------------
    #
    # **Being unsigned is not a category.** Most malware is unsigned and so is
    # most small legitimate tooling; the absence of exculpatory evidence is not
    # incriminating evidence, and making it a category would start every
    # unsigned binary at one -- which is Needs Review, for every unsigned
    # binary ever triaged. The additive model charged 8 points for it, which is
    # the same mistake priced differently.
    #
    # A signature that is *present and does not verify* is a different claim,
    # and that is the category.
    signing_ran = signing is not None
    signing = signing or {}
    verify_ok = bool(signing.get("verify_ok"))
    timestamp_verified = bool(signing.get("timestamp_verified"))
    trusted_signed = verify_ok and timestamp_verified
    has_signature = bool(signing.get("subject") or signing.get("signature_present"))
    subject = (signing.get("subject") or "").strip()

    cats.append(Category(
        name="invalid_signature",
        module="static",
        collected=signing_ran,
        present=signing_ran and has_signature and not verify_ok,
        # Never strong on its own. Expired certificates, stripped timestamps and
        # ordinary build mistakes all land here, so it corroborates rather than
        # concludes.
        strong=False,
        detail=f"signature present, verification failed ({subject or 'no subject'})"
        if (signing_ran and has_signature and not verify_ok) else "",
        reason=(
            f"The file carries a signature that does not verify "
            f"({subject or 'subject unavailable'}). Something was changed after "
            f"signing, or the signature was never valid."
        ) if (signing_ran and has_signature and not verify_ok) else "",
    ))

    # --- Version information ------------------------------------------------
    #
    # Four separate points for four missing fields is one claim charged four
    # times, and it is exactly how a volume-driven model creeps back. One
    # category, strong only when the whole block is empty.
    #
    # **Dampened by a verifying signature, and by nothing else.** If the
    # signature checks out, the version-info block means what it says. VirusTotal
    # is deliberately not consulted here even though the additive model used it:
    # letting a third-party opinion suppress a local observation is the same
    # error as letting it raise one, and "VirusTotal is not a category" has to
    # be true in both directions to be true at all.
    pe_ran = pe_meta is not None
    info = _pe_string_table(pe_meta or {})
    fields = {
        "CompanyName": (info.get("CompanyName") or "").strip(),
        "ProductName": (info.get("ProductName") or "").strip(),
        "FileDescription": (info.get("FileDescription") or "").strip(),
        "OriginalFilename": (info.get("OriginalFilename") or "").strip(),
    }
    missing = sorted(k for k, v in fields.items() if not v)
    stripped = pe_ran and bool(missing) and not trusted_signed

    cats.append(Category(
        name="stripped_metadata",
        module="static",
        collected=pe_ran,
        present=stripped,
        # **Never strong, even when the whole block is empty.** Go and Rust
        # binaries ship with no version info as a matter of course, as does
        # anything built without a resource script. Letting an empty block stand
        # alone would put a large population of ordinary open-source tooling
        # into Elevated Attention on its own -- which is the false positive this
        # engine is worst placed to catch, because nothing downstream disagrees
        # with it. It corroborates; it does not conclude.
        strong=False,
        detail=f"{len(missing)} of {len(fields)} version-info fields empty: "
               f"{', '.join(missing)}" if stripped else "",
        reason=(
            f"The version-info block is missing {', '.join(missing)}. A build "
            f"that identifies nobody is either deliberately anonymous or was "
            f"never meant to be inspected."
        ) if stripped else "",
    ))

    # --- What the file is pretending to be ----------------------------------
    #
    # **A hash-like filename claims nothing, and the additive model charging 6
    # points for it was a live false positive.** The on-disk name is whatever
    # the *analyst* called the file, not what the author called it: this
    # pipeline acquires samples by hash and stores them under it, so every
    # sample it has ever downloaded arrived six points up. The author's own
    # claim about the name is `OriginalFilename`, which the version-info
    # category already covers.
    #
    # What survives that objection is deception that had to be authored: a
    # document extension in front of an executable one, or a right-to-left
    # override. Those are in the name because someone put them there.
    summary_ran = summary is not None
    name = _sample_name(summary or {})
    odd_extension = name.endswith(_SUSPICIOUS_EXTENSIONS)
    double_extension = bool(_DOUBLE_EXTENSION.search(name))
    rlo = _RLO in name
    deceptive = summary_ran and bool(name) and (
        odd_extension or double_extension or rlo)

    why = []
    if double_extension:
        why.append("a document extension followed by an executable one")
    if rlo:
        why.append("a right-to-left override that reverses how the name reads")
    if odd_extension:
        why.append(f"the extension {name.rsplit('.', 1)[-1]}")

    cats.append(Category(
        name="deceptive_file_identity",
        module="static",
        collected=summary_ran and bool(name),
        present=deceptive,
        # A double extension or an RLO is a deliberate attempt to be misread.
        # A hash-like name is merely uninformative -- automated sample handling
        # produces those too, including ours.
        strong=deceptive and (double_extension or rlo),
        detail=name if deceptive else "",
        reason=(f"The filename carries {', and '.join(why)}.") if deceptive else "",
    ))

    # --- Signatures of known malware ----------------------------------------
    #
    # A scan that errored is not a scan that found nothing.
    yara_ran = yara_results is not None and not (yara_results or {}).get("error")
    yara_results = yara_results or {}
    matched = bool(yara_results.get("matched", False))
    match_count = int(yara_results.get("match_count", 0) or 0)
    matches = yara_results.get("matches") if isinstance(yara_results.get("matches"), list) else []
    family_hits, rule_names = _yara_signal(matches)
    yara_present = yara_ran and matched and match_count > 0

    cats.append(Category(
        name="known_malware_signature",
        module="static",
        collected=yara_ran,
        present=yara_present,
        # One rule naming a family, or three unrelated rules agreeing. The
        # dynamic side draws the same line at three for memory-only rules, and
        # for the same reason: one is a marker, three is a consensus.
        strong=yara_present and (family_hits >= 1 or len(set(rule_names)) >= 3),
        detail=f"{match_count} rule(s): {', '.join(rule_names[:5])}"
        if yara_present else "",
        reason=(
            f"YARA matched {match_count} rule(s) on disk "
            f"({', '.join(rule_names[:3])}), which is a signature written "
            f"against something previously seen."
        ) if yara_present else "",
    ))

    # --- What the code is built to do ---------------------------------------
    #
    # capa's ATT&CK mapping and the import-table chains are folded into **one**
    # category on purpose. They are two views of the same fact -- capa saying
    # "injects code" and the import table carrying `WriteProcessMemory` is one
    # observation seen twice, and counting it twice would manufacture
    # corroboration out of a single claim.
    api_ok = api_analysis is not None and int((api_analysis or {}).get("returncode", 0) or 0) == 0
    capability_ran = api_ok or techniques is not None

    api_analysis = api_analysis or {}
    chains = api_analysis.get("chain_findings") if isinstance(api_analysis.get("chain_findings"), list) else []
    high_chains = [c for c in chains
                   if isinstance(c, dict) and str(c.get("severity", "")).lower() == "high"]

    techniques = list(techniques or [])
    high_techniques = [t for t in techniques if _prefix_in(t, HIGH_SIGNAL_TECH_PREFIXES)]

    groups = (1 if high_techniques else 0) + (1 if high_chains else 0)
    capable = capability_ran and groups > 0

    cats.append(Category(
        name="dangerous_capability",
        module="static",
        collected=capability_ran,
        present=capable,
        # Both routes agreeing, or one of them emphatic. A single high-signal
        # technique in an installer is ordinary; two independent readings of the
        # binary saying the same thing is not.
        strong=capable and (groups >= 2 or len(high_techniques) >= 3),
        detail=f"{len(high_techniques)} high-signal technique(s), "
               f"{len(high_chains)} high-severity API chain(s)" if capable else "",
        reason=(
            f"The binary contains code for "
            f"{', '.join(high_techniques[:4]) if high_techniques else 'high-severity API chains'}"
            f", which is capability rather than behaviour -- it says what the "
            f"file can do, not that it did."
        ) if capable else "",
    ))

    # --- Network indicators built into the file -----------------------------
    iocs_ran = iocs is not None
    observables = _extract_observables(iocs or {})
    any_observable = any(observables.get(k) for k in ("domains", "urls", "ips"))
    notable = iocs_ran and any_observable and not _has_only_known_benign_infra(observables)

    hosts = (observables.get("domains") or []) + (observables.get("ips") or [])
    cats.append(Category(
        name="embedded_network_indicators",
        module="static",
        collected=iocs_ran,
        present=notable,
        # Never strong. A hostname in a binary is a string until something
        # contacts it, and the module that can watch it do that is the dynamic
        # one. This category exists to corroborate, which is the whole point of
        # having more than one module.
        strong=False,
        detail=", ".join(hosts[:5]) if notable else "",
        reason=(
            f"The file carries network indicators that are not known-benign "
            f"infrastructure ({', '.join(hosts[:3]) or 'URLs only'}). Static "
            f"analysis cannot say they are contacted, only that they are there."
        ) if notable else "",
    ))

    # --- Context: volume, capped, never a verdict input ---------------------
    #
    # capa density belongs here and not in a category. "How many rules matched"
    # is the definition of volume, and the additive model let it buy up to six
    # points -- enough to move a band on a large, busy, entirely legitimate
    # binary.
    context = 0
    if capa_match_count:
        context += min(6, 1 + int(capa_match_count / 40))
    if techniques:
        context += min(4, len(techniques) // 3)
    if match_count:
        context += min(5, match_count)
    context = max(0, min(MAX_CONTEXT_SCORE, context))

    return cats, context
