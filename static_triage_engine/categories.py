"""What static analysis can claim about a sample, as evidence categories.

Phase 2 of `docs/SCORING.md`. This is the static half of `corroboration-v1`:
the same contract `dynamic_analysis` emits, so the combiner can count agreement
across the two instead of adding their scores together.

**This is the only static scorer now.** It was written alongside the additive
one in Phase 2 and consumed nothing until Phase 4, so that the GUI kept working
through the migration; Phase 4b moved the last consumer and deleted the old
path. What survives in `scoring.py` is the helpers below, which never had
anything to do with scoring.

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
from urllib.parse import urlparse

from verdict import MAX_CONTEXT_SCORE, Category

from static_triage_engine.scoring import (
    CAPABILITY_PRESENT_AT,
    CAPABILITY_STRONG_AT,
    HIGH_SIGNAL_CAPABILITIES,
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

#: A section that is executable *and* near-random is packed code. Benign high
#: entropy is almost entirely `.rsrc` -- compressed icons and images -- so the
#: executable bit is part of the test rather than entropy alone. Measured
#: 28 Aug over 819 samples: **0.3% / 0.0%** on the two benign corpora against
#: **35.4% / 28.0%** on the two malware ones. Undifferentiated `any section
#: >= 7.2` is 2.7% / 3.0% against 48.8% / 59.0% -- more of the malware, but at
#: ten times the false-positive rate, which is the wrong trade for a bench
#: whose expensive error is firing on ordinary software.
_PACKED_ENTROPY = 7.5

#: The fraction of a managed assembly's `#Strings` heap that no compiler and no
#: developer would emit. Measured 28 Aug: benign tops out at **0.099** over 39
#: measurable assemblies in 592 binaries, and the five No Evidence samples this
#: recovers sit at 0.298, 0.267, 0.255, 0.239 and 0.228. Nothing in either band
#: falls between 0.099 and 0.228, so **the threshold is not load-bearing** --
#: any cut from 0.10 to 0.22 gives identical coverage. 0.20 is twice the benign
#: ceiling and clears the lowest true positive by 0.028.
#:
#: It costs four corpus-wide detections against a cut at 0.10, all of them on
#: samples YARA or capa already catch, and none of the unique coverage.
_RENAMED_IDENTIFIERS = 0.20
_IMAGE_SCN_MEM_EXECUTE = 0x20000000

#: Vendors the **benign** corpora show (a) shipping at least four samples,
#: (b) signing at least 95% of them, and (c) signing them *themselves*.
#: **Derived, not chosen** -- `scripts/derive_signers.py` regenerates it, and a
#: list written by looking at the malware would be tuned to the test set.
#:
#: **(c) was added on 28 Aug and is the condition that matters.** A 900-binary
#: survey qualified `ffmpeg` on the first two rules at 7 of 7 signed -- and 0 of
#: those 7 were signed by FFmpeg. OBS Project, Chengdu Yiwo Tech and Microsoft
#: 3rd Party had signed them, because FFmpeg is redistributed far more than it
#: is shipped. Listing it would have accused every unsigned FFmpeg build, which
#: is the ordinary case, of impersonation. `patriot` (signed by Creative
#: Technology), `insecure` (by Nmap Software LLC) and `epic` (half by
#: EasyAntiCheat) failed the same way. The narrow corpus could not show this
#: because it contained none of them.
#:
#: Microsoft is the threshold case on (b), at 848 of 859 over 1,219 samples.
#: Measured false-positive cost of the whole rule: 0 of 292 System32 and 4 of
#: 300 Program Files, those four being unsigned COM interop stubs that
#: `stripped_metadata` already fires on.
#:
#: **`nvidia` is a deliberate, conservative loss.** It qualified on the survey
#: alone at 22 of 22 self-signed, and dropped out once the case corpora added
#: two NVIDIA binaries signed by Microsoft Windows Hardware Compatibility.
#: Unsigned NVIDIA binaries are almost certainly not ordinary, so this probably
#: gives up a real detection -- but rule (c) cannot tell WHQL co-signing apart
#: from redistribution, and a false accusation of impersonation is the more
#: expensive error.
#:
#: **It still only covers vendors the benign corpora contain.** Impersonations
#: of Adobe, Avira and Opera were seen in the malware and none is caught, and
#: widening from 592 to 1,492 binaries did not add any of the three. Widening
#: further widens this list; reading the malware for it does not.
_ALWAYS_SIGNS = frozenset({
    "asus", "asustek", "bitdefender", "corsair", "google", "ipvanish",
    "logitech", "microsoft", "oracle", "overwolf", "simon", "valve",
    "wireshark",
})

#: Dropped before taking a vendor's first distinctive word, so that
#: `Oracle Corporation` and `Oracle and/or its affiliates` key the same.
_VENDOR_NOISE = frozenset({"the", "and", "or", "its", "a"})

_VENDOR_SUFFIX = re.compile(
    r"\b(inc|corp|corporation|ltd|limited|llc|gmbh|co|company|sa|ab|as|oy|"
    r"plc|pty|bv|srl|sarl)\b", re.I)


def _vendor_key(company: str) -> str:
    """The first distinctive word of a company name, or "".

    A three-letter token is too generic to accuse anyone over, so it is
    discarded rather than matched.
    """
    text = re.sub(r"<[^>]*>", " ", (company or "").lower().strip())
    text = re.sub(r"[^\w\s]", " ", text)
    text = _VENDOR_SUFFIX.sub(" ", text)
    for token in text.split():
        if token in _VENDOR_NOISE:
            continue
        return token if len(token) >= 4 else ""
    return ""


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
    capa_ok: bool | None = None,
    capa_namespaces: Sequence[str] | None = None,
    dotnet_meta: dict[str, Any] | None = None,
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
    # **`collected` here means the version-info block was looked for, not that
    # the PE parsed.** For most of this engine's life no collector wrote one,
    # so `_pe_string_table` returned `{}` on every real sample and the category
    # decayed into `not trusted_signed` -- reproducing the published column to
    # the decimal across all four corpora while appearing to measure metadata.
    # `version_info_collected` is what the collector sets once it has actually
    # walked the resource directory. Its absence means the file was written by
    # a build that never looked, which is `unknown`, not `clean`.
    pe_ran = pe_meta is not None
    vi_ran = pe_ran and bool((pe_meta or {}).get("version_info_collected"))
    info = _pe_string_table(pe_meta or {})
    fields = {
        "CompanyName": (info.get("CompanyName") or "").strip(),
        "ProductName": (info.get("ProductName") or "").strip(),
        "FileDescription": (info.get("FileDescription") or "").strip(),
        "OriginalFilename": (info.get("OriginalFilename") or "").strip(),
    }
    missing = sorted(k for k, v in fields.items() if not v)
    stripped = vi_ran and bool(missing) and not trusted_signed

    cats.append(Category(
        name="stripped_metadata",
        module="static",
        collected=vi_ran,
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

    # --- What the code was built out of -------------------------------------
    #
    # **Managed code is the module's largest blind spot, and this is one narrow
    # window into it.** 47.6% of the malware corpora is .NET against 11.3% of
    # benign, and 13 of the 22 samples that survived every other category are
    # managed. A .NET assembly imports `mscoree.dll` and nothing else and keeps
    # its call graph in CLR metadata, so the import table, the section table and
    # the version block -- everything the other categories read -- are empty or
    # uninformative on it.
    #
    # This does not fix that. It reads one property, identifier renaming, and
    # recovers 5 of the 22. The rest of the blind spot is still open.
    dotnet_ran = dotnet_meta is not None and bool((dotnet_meta or {}).get("collected"))
    dotnet_meta = dotnet_meta or {}
    # **IL-only and a floor on the count are preconditions, not thresholds.**
    # Mixed-mode C++/CLI carries mangled native symbols in `#Strings` --
    # `mfcm140u.dll` reads 0.201 unreadable and is entirely legitimate -- and a
    # satellite resource assembly with five identifiers reads 0.200 on a single
    # generic name. Both are excluded by what they are, not by where they sit.
    renamed_fraction = float(dotnet_meta.get("unreadable_fraction") or 0.0)
    measurable = bool(dotnet_meta.get("is_managed")) and \
        bool(dotnet_meta.get("il_only")) and \
        bool(dotnet_meta.get("identifiers_sufficient"))
    obfuscated = dotnet_ran and measurable and \
        renamed_fraction >= _RENAMED_IDENTIFIERS
    protectors = [str(p) for p in (dotnet_meta.get("protectors") or [])]

    cats.append(Category(
        name="obfuscated_managed_code",
        module="static",
        # A native binary is not an absence: the collector looked and the answer
        # is that there is no CLR metadata to read.
        collected=dotnet_ran,
        present=obfuscated,
        # **Not strong, and this one is not close.** Commercial .NET is
        # legitimately obfuscated -- Dotfuscator and SmartAssembly are products
        # people buy -- and the benign corpora hold 39 measurable managed
        # assemblies, which is far too few to characterise that population. 0
        # of 39 is not a false-positive rate for protected commercial software;
        # it is the absence of protected commercial software from the corpus.
        strong=False,
        detail=(f"{renamed_fraction:.0%} of identifiers renamed"
                + (f", names {', '.join(protectors)}" if protectors else ""))
        if obfuscated else "",
        reason=(
            f"{renamed_fraction:.0%} of this assembly's type, method and field "
            f"names are ones no compiler emits"
            + (f", and it names {', '.join(protectors)} outright" if protectors
               else "")
            + ". The names were replaced to stop the code being read."
        ) if obfuscated else "",
    ))

    # --- How the code is stored ---------------------------------------------
    #
    # **Measured before it shipped, which is the first time that has been true
    # here.** Packing is the one cheap static signal `static` was not already
    # reading: `pe_meta` has computed section entropy on every sample since the
    # beginning and nothing consumed it.
    #
    # The executable bit is what makes it work. Benign binaries carry high
    # entropy in `.rsrc` -- a PNG is incompressible and says nothing about
    # intent -- while malware carries it in `.text`, which is packed code.
    sections = [s for s in (pe_meta or {}).get("sections") or []
                if isinstance(s, dict) and (s.get("raw_size") or 0) > 0]
    packed = [s for s in sections
              if int(s.get("characteristics") or 0) & _IMAGE_SCN_MEM_EXECUTE
              and float(s.get("entropy") or 0.0) >= _PACKED_ENTROPY]
    # **The key being present is what "looked" means**, not the list being
    # non-empty. `extract_pe_metadata` always writes `sections`; a dict without
    # it came from something that did not parse the section table, and an empty
    # list from something that did and found nothing worth measuring.
    entropy_ran = pe_ran and isinstance((pe_meta or {}).get("sections"), list)

    cats.append(Category(
        name="high_entropy_sections",
        module="static",
        collected=entropy_ran,
        present=entropy_ran and bool(packed),
        # **Not strong, and this was measured rather than assumed.** 0.3% and
        # 0.0% on the two case corpora would ordinarily earn it, but both are
        # *installed* software and neither contains the installers where
        # legitimate packing lives. That gap was the stated reason to withhold
        # `strong`, and on 28 Aug it was closed: a 210-binary installer corpus
        # -- package caches, `Windows\Installer`, and installer-named files
        # under Program Files -- fires at **0.95%** here against 0.00% for 900
        # installed binaries.
        #
        # Two signed, entirely legitimate installers cross the line:
        # `uninstall.exe` from Indigo Rose at 7.93 and `Docker Desktop
        # Installer.exe` at 7.74. A strong category would carry both to
        # Corroborated on their own. Non-strong they reach Single Observation,
        # which is the right price. **The condition is answered and the answer
        # is no** -- do not revisit it without a corpus that disagrees.
        #
        # It also re-confirms the 7.5 cut. At 7.2 the installer rate doubles to
        # 1.90% as two Armoury Crate binaries (7.49, 7.46) join.
        strong=False,
        detail=", ".join(
            f"{s.get('name') or '?'} {float(s.get('entropy') or 0):.2f}"
            for s in packed[:4]) if packed else "",
        reason=(
            f"{len(packed)} executable section(s) carry near-random bytes "
            f"(entropy >= {_PACKED_ENTROPY}). Code that is unreadable until it "
            f"runs was packed to be unreadable."
        ) if (entropy_ran and packed) else "",
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
    #
    # **The version block answers what the filename cannot.** All three name
    # predicates were correct and none had fired on 819 samples, because this
    # pipeline acquires by hash: every malware sample arrives as
    # `<sha256>.exe`, and the name the author chose was destroyed before
    # analysis began. The claim that survives acquisition is `CompanyName`, and
    # it is claimed loudly -- of the 56 samples nothing else fired on, thirteen
    # named Microsoft, three Oracle, one Windows Defender, one Adobe, none of
    # them signed. Impersonating a vendor who signs everything is the same act
    # as an RLO override: deception someone had to author.
    summary_ran = summary is not None
    name = _sample_name(summary or {})
    odd_extension = name.endswith(_SUSPICIOUS_EXTENSIONS)
    double_extension = bool(_DOUBLE_EXTENSION.search(name))
    rlo = _RLO in name

    company = (info.get("CompanyName") or "").strip()
    vendor = _vendor_key(company)
    # `vi_ran` and not `pe_ran`: a version block nobody collected cannot be
    # read as a file claiming nothing.
    #
    # **The claim has to be complete, and that is what keeps the two categories
    # from counting one fact twice.** Four Program Files binaries honestly say
    # `Microsoft Corporation` while filling in two of the four fields and
    # shipping unsigned inside someone else's installer. Firing here as well as
    # in `stripped_metadata` carried all four to Corroborated on a single
    # observation -- being unsigned -- which is the exact arithmetic this module
    # exists to refuse.
    #
    # Requiring the whole block splits the two cleanly: a partial identity is
    # `stripped_metadata`, a complete and false one is this. It costs nothing in
    # detection, because every one of the 56 samples nothing else fired on
    # carried four or more fields.
    vendor_claim = bool(vi_ran and not missing and vendor in _ALWAYS_SIGNS
                        and not trusted_signed)

    name_ran = summary_ran and bool(name)
    deceptive = (name_ran and (odd_extension or double_extension or rlo)) \
        or vendor_claim

    why = []
    if double_extension:
        why.append("a document extension followed by an executable one")
    if rlo:
        why.append("a right-to-left override that reverses how the name reads")
    if odd_extension:
        why.append(f"the extension {name.rsplit('.', 1)[-1]}")
    if vendor_claim:
        why.append(f"a claim to be {company}, which is unsigned here and "
                   f"signed on everything that vendor ships")

    cats.append(Category(
        name="deceptive_file_identity",
        module="static",
        # Either source of an identity claim counts as having looked.
        collected=name_ran or vi_ran,
        present=deceptive,
        # A double extension or an RLO is a deliberate attempt to be misread.
        # A hash-like name is merely uninformative -- automated sample handling
        # produces those too, including ours.
        #
        # **The vendor claim is deliberately not strong**, though it is just as
        # authored. Its measured cost is four Program Files binaries that
        # honestly say `Microsoft Corporation` while shipping unsigned inside
        # someone else's installer, and a strong category would carry those
        # four to Corroborated on their own. An RLO has no such population.
        strong=deceptive and (double_extension or rlo),
        detail=(name if (odd_extension or double_extension or rlo)
                else company) if deceptive else "",
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
    # **A collector that failed did not find nothing.** `techniques` is `[]`
    # both when capa ran and matched nothing and when capa was never found --
    # and capa is missing far more often than anyone assumed. On 229 malware
    # samples it failed on 194 of them, 182 with `WinError 2` because
    # `capa.exe` lives in a venv that a fresh shell had not activated. The
    # category reported `collected=True, present=False` for every one: a clean
    # answer from a tool that never ran, which is the exact failure this
    # contract exists to prevent. `capa_ok=False` makes it say `unknown`.
    capa_failed = capa_ok is False
    capability_ran = (api_ok or techniques is not None) and not capa_failed

    api_analysis = api_analysis or {}

    # **Behaviour namespaces, not the ATT&CK mapping.** The previous version
    # counted `HIGH_SIGNAL_TECH_PREFIXES` against capa's technique list and
    # measured 35.1% on System32, 22.0% on Program Files, 39.3% and 29.7% on
    # two malware corpora -- a lift of 1.1x, which is a coin. 86 of its 99
    # benign firings were `T1059`, Command and Scripting Interpreter, which
    # capa maps onto anything able to launch a process.
    #
    # `HIGH_SIGNAL_CAPABILITIES` was chosen by measuring 532 benign against 203
    # malicious samples, and its members are behaviours a reader can act on:
    # screenshots, keylogging, clipboard access, C2 file transfer, shellcode
    # loading, self-deletion.
    matched = sorted(set(capa_namespaces or []) & HIGH_SIGNAL_CAPABILITIES)
    capable = capability_ran and len(matched) >= CAPABILITY_PRESENT_AT

    cats.append(Category(
        name="dangerous_capability",
        module="static",
        collected=capability_ran,
        present=capable,
        # Five distinct behaviours fires on 0.56% of 532 benign samples and
        # 18.7% of malware. That is the rate at which one category may stand
        # alone; three is the rate at which it corroborates.
        strong=capable and len(matched) >= CAPABILITY_STRONG_AT,
        detail=(f"{len(matched)} high-signal capabilities: "
                f"{', '.join(m.split('/')[-1] for m in matched[:5])}"
                if capable else ""),
        reason=(
            f"capa identified {len(matched)} distinct high-signal behaviours in "
            f"the code -- {', '.join(m.split('/')[-1] for m in matched[:4])}. "
            f"This is capability rather than behaviour: it says what the file "
            f"is built to do, not that it did it."
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


# ---------------------------------------------------------------------------
# API specifications
# ---------------------------------------------------------------------------

#: Hosts where a plaintext scheme says nothing. A spec that lists
#: `http://localhost:8080` is describing a development server, not shipping an
#: unencrypted service.
_LOCAL_HOST_NAMES = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"}
_LOCAL_SUFFIXES = (".local", ".test", ".localhost", ".internal", ".invalid")


def _is_local_host(url: str) -> bool:
    try:
        host = (urlparse(str(url).strip()).hostname or "").lower()
    except ValueError:
        return False
    if not host:
        return False
    if host in _LOCAL_HOST_NAMES or host.endswith(_LOCAL_SUFFIXES):
        return True
    if host.startswith("10.") or host.startswith("192.168."):
        return True
    if host.startswith("172."):
        parts = host.split(".")
        if len(parts) > 1 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
            return True
    return False


def spec_categories(
    spec_result: dict[str, Any] | None = None,
) -> tuple[list[Category], int]:
    """What an API specification review can claim, as categories.

    Phase 3a of `docs/SCORING.md`. `score_spec` had no tests at all, and reading
    it with the question Phase 2 was built on -- *what claim is this, and does it
    stand alone* -- turned up the same shape of defect three more times.

    **An unparseable spec scored 10 of 30 for having no authentication.** The
    old `no_auth` test was `auth_scheme_count == 0`, which is true of an empty
    dict, a spec that failed to parse, and a file that was never a spec. Missing
    data was read as a finding, which is the error this whole model exists to
    stop.

    **`no_auth` and `sensitive_unauth` were one claim charged twice.**
    `sensitive_unauth` requires `auth_scheme_count == 0`, which is one of the
    conditions that makes `no_auth` true -- so an unauthenticated admin route
    scored on both, up to 18 of a 30-point ceiling. They are collapsed here: the
    admin case is the *strong form* of the same category, exactly as the design
    note called for.

    **A destructive admin route is not a finding on its own.** `DELETE
    /admin/users/{id}` is how a correct admin API is built; every CRUD service
    has one. It is interesting when nothing authenticates it, and that is
    already the category above. It stays as a category because exposed
    destructive power corroborates, but it can never be emphatic by itself.

    `None`, or a result whose `returncode` is non-zero, means the analysis did
    not run: every category comes back `collected=False` rather than absent.
    """
    ran = spec_result is not None and int((spec_result or {}).get("returncode", 0) or 0) == 0
    spec_result = spec_result or {}

    summary = spec_result.get("summary") if isinstance(spec_result.get("summary"), dict) else {}
    endpoints = spec_result.get("endpoints") if isinstance(spec_result.get("endpoints"), list) else []
    servers = spec_result.get("servers") if isinstance(spec_result.get("servers"), list) else []
    auth_summary = spec_result.get("auth_summary") if isinstance(spec_result.get("auth_summary"), list) else []
    security_schemes = spec_result.get("security_schemes") if isinstance(spec_result.get("security_schemes"), list) else []

    endpoint_count = int(summary.get("endpoint_count", 0)
                         or spec_result.get("endpoint_count", 0) or 0) or len(endpoints)
    auth_scheme_count = int(summary.get("auth_scheme_count", 0)
                            or spec_result.get("auth_scheme_count", 0) or 0)

    # **A spec with no endpoints cannot be unauthenticated.** There is nothing
    # to authenticate. Gating on this is what stops an empty document scoring.
    described = ran and endpoint_count > 0

    # **`no_auth_detected` is gone from this condition, and it was never in
    # it.** The analyser writes that flag under `result["scoring"]`; this read
    # it from the top level, where it has always been `None`. So the OR-branch
    # has never once run, and the corpus is what made that visible.
    #
    # It is removed rather than repaired, because repairing it would make the
    # category *worse*. The flag is `not auth_summary` -- true of a spec whose
    # scheme the summariser did not recognise, which is missing data rather
    # than a finding. Three of 300 specifications declare Swagger 2.0's
    # `type: basic`, and reviving the flag would have called all three
    # unauthenticated. The condition beside it asks the stricter and correct
    # question: the document names no scheme *anywhere*.
    no_auth = described and (
        auth_scheme_count == 0 and not auth_summary and not security_schemes
    )

    admin_routes = [ep for ep in endpoints
                    if isinstance(ep, dict) and ep.get("admin_like_route")]
    sensitive_unauth = bool(admin_routes) and no_auth

    # **The exemption, not the existence.** `DELETE /admin/users/{id}` is how a
    # correct admin API is built; every CRUD service has one, and a category
    # that fires on its existence would put all of them at Needs Review.
    #
    # What is a finding is a spec that *declares* authentication and then
    # exempts a destructive administrative route from it. Scoping the category
    # that way also keeps it independent of the one above, which covers the
    # no-auth-anywhere case -- if both could fire on the same spec, an API with
    # no auth would corroborate itself.
    exempt_destructive_admin = [] if no_auth else [
        ep for ep in admin_routes
        if ep.get("destructive_method") and not ep.get("auth_required", True)
    ]

    uploads = [
        ep for ep in endpoints
        if isinstance(ep, dict) and any(
            isinstance(param, dict)
            and str(param.get("in", "")).lower() == "body:multipart/form-data"
            for param in (ep.get("parameters") or [])
        )
    ]

    plaintext = [s for s in servers
                 if str(s).lower().startswith("http://") and not _is_local_host(s)]
    # The fallback that used to sit here -- trust `http_server_detected` when
    # no server URL was listed -- was dead twice over. It read the flag from
    # the top level, where the analyser does not write it, and the flag is
    # computed from `server_entries`, which is the same list `servers` is
    # derived from: it cannot be true while `servers` is empty. A branch that
    # cannot run is worse than no branch, because it reads as coverage.

    cats: list[Category] = [
        Category(
            name="unauthenticated_sensitive_endpoint",
            module="spec",
            collected=ran,
            present=no_auth,
            # **The strong form is the admin case, not a separate claim.** An
            # API with no auth may be a legitimate public read-only service. An
            # API whose *administrative* routes have no auth is not.
            strong=sensitive_unauth,
            detail=(f"{endpoint_count} endpoint(s), no authentication scheme"
                    + (f", {len(admin_routes)} admin-like"
                       if admin_routes else "")) if no_auth else "",
            # **The claim is about the document, and the wording now says so.**
            # This used to end "...administrative route(s) that anyone reaching
            # the service can call", which is a statement about the running
            # service that a specification cannot support. The corpus proved it
            # false: of the twelve specs reaching the strong form across 300,
            # the members include JIRA, Magento B2B, Yodlee Core APIs and Datto
            # Autotask -- all certainly authenticated products whose published
            # specification simply omits the scheme. An undocumented control is
            # a gap in the document first, and the reader is the one who gets to
            # decide whether it is also a gap in the API.
            reason=(
                f"The specification describes {endpoint_count} endpoint(s) and "
                f"declares no authentication scheme"
                + (f", including {len(admin_routes)} administrative route(s)."
                   if admin_routes else ".")
                + " This is what the document omits, not what the service was "
                  "observed to allow: an API may authenticate by a mechanism it "
                  "never wrote down. The gap is in the specification, and "
                  "whether it is also a gap in the API is the thing to check."
            ) if no_auth else "",
        ),
        Category(
            name="destructive_admin_surface",
            module="spec",
            collected=ran,
            present=bool(exempt_destructive_admin),
            # Never strong. A route can be exempt from the declared scheme for
            # legitimate reasons -- a health check, an internal callback -- and
            # the spec does not record which. It corroborates.
            strong=False,
            detail=f"{len(exempt_destructive_admin)} destructive admin route(s) "
                   f"exempt from the declared auth scheme"
            if exempt_destructive_admin else "",
            reason=(
                f"The specification declares authentication, and then exempts "
                f"{len(exempt_destructive_admin)} destructive administrative "
                f"route(s) from it "
                f"({', '.join(str(e.get('path', '?')) for e in exempt_destructive_admin[:3])}). "
                f"A scheme with holes in it is not the scheme the document "
                f"appears to describe."
            ) if exempt_destructive_admin else "",
        ),
        Category(
            name="unrestricted_upload",
            module="spec",
            collected=ran,
            present=bool(uploads),
            # Also never strong on its own -- accepting files is a feature.
            strong=False,
            detail=f"{len(uploads)} multipart upload endpoint(s)" if uploads else "",
            reason=(
                f"{len(uploads)} endpoint(s) accept multipart file uploads, so "
                f"content can be pushed into the service from outside."
            ) if uploads else "",
        ),
        Category(
            name="plaintext_transport",
            module="spec",
            collected=ran,
            present=bool(plaintext),
            strong=False,
            detail=", ".join(str(s) for s in plaintext[:3]) if plaintext else "",
            reason=(
                f"The specification declares a non-TLS server URL "
                f"({', '.join(str(s) for s in plaintext[:2])}), so traffic to it "
                f"is readable in transit."
            ) if plaintext else "",
        ),
    ]

    # Volume: how large the described surface is. Descriptive only -- a big API
    # is a big API, not a suspicious one.
    context = 0
    if endpoint_count:
        context += min(6, endpoint_count // 20)
    if admin_routes:
        context += min(4, len(admin_routes))
    context = max(0, min(MAX_CONTEXT_SCORE, context))

    return cats, context

