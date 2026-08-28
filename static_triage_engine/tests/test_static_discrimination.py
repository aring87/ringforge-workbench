"""Static analysis has to be able to tell these samples apart.

Phase 2 of `docs/SCORING.md`, and the first real test this engine has had. Two
tests covered 6,518 lines before it, one of which asserted only that
`score_static` returns an int, a list and a dict.

**Method taken from `dynamic_analysis/tests/test_score_discrimination.py`**,
which calls the scorer directly with synthetic inputs and encodes the contract
rather than replaying recorded runs. That is the better design regardless, and
here it is also the only available one: the sample binaries are not on this
host, and the two case folders that survive locally are neither of them ground
truth. A fixture-replay suite could not have been written today.

The contract, in one place:

    signed vendor installer, clean metadata     no category      Low
    unsigned, hash-named, stripped version-info one category     Needs Review
    family YARA hit + dangerous capability      two categories   Elevated
    all three plus embedded C2 indicators       four categories  Likely Malicious
    capa with no ruleset                        unknown, not absent
"""

import unittest

from static_triage_engine.categories import static_categories
from verdict import band


def _named(cats, name):
    return next(c for c in cats if c.name == name)


def _verdict(**kwargs):
    """Band with category holds lifted -- these test what the categoriser says.

    `dangerous_capability` is held in `verdict.CONTEXT_ONLY_CATEGORIES` on
    measurement (it fires 3x more on benign System32 than on malware). That is a
    deployment decision about what counts, and these tests are about what the
    categories *claim*, which is a different question. Lifting it here is the
    same move `test_extension_discrimination` makes for the module-level hold --
    and it means flipping the registry cannot silently rewrite what these
    assert.
    """
    cats, context = static_categories(**kwargs)
    return band(cats, context_score=context, context_only_categories={}), cats


# --- the reference samples -------------------------------------------------

def _signed_installer():
    """A real vendor installer: signature verifies, version-info complete."""
    return dict(
        summary={"sample": {"filename": "vendor_setup.exe"}},
        pe_meta={"version_info_collected": True, "sections": [], "version_info": {
            "CompanyName": "Trusted Vendor Ltd",
            "ProductName": "Trusted Product",
            "FileDescription": "Trusted Product Installer",
            "OriginalFilename": "vendor_setup.exe",
        }},
        signing={"verify_ok": True, "timestamp_verified": True,
                 "subject": "CN=Trusted Vendor Ltd", "signature_present": True},
        yara_results={"matched": False, "match_count": 0},
        iocs={"observables": {"domains": ["ocsp.digicert.com"], "urls": [], "ips": []}},
        api_analysis={"returncode": 0, "chain_findings": []},
        techniques=[],
        capa_match_count=120,
        # A native binary: the CLR collector ran and found no managed metadata.
        dotnet_meta={"collected": True, "is_managed": False},
    )


def _anonymous_binary():
    """Unsigned, named after its own hash, no version information."""
    sample = _signed_installer()
    sample.update(
        summary={"sample": {"filename": "a3f8c1e29b74d05f6a2b8c31.exe"}},
        pe_meta={"version_info_collected": True, "sections": [], "version_info": {}},
        signing={"verify_ok": False, "timestamp_verified": False},
    )
    return sample


class ASignedInstallerIsNotSuspicious(unittest.TestCase):
    """The false-positive end, which is where a static scorer actually fails."""

    def test_it_reaches_no_category(self) -> None:
        result, _ = _verdict(**_signed_installer())

        self.assertEqual(result.categories_present, 0)
        self.assertEqual(result.severity, "Low")

    def test_a_busy_legitimate_binary_cannot_be_scored_into_a_band(self) -> None:
        # capa density bought up to six points in the additive model, which was
        # enough to move a band on a large, busy, entirely legitimate file.
        # Volume is context now, and context does not decide bands.
        loud = _signed_installer()
        loud["capa_match_count"] = 100000
        result, _ = _verdict(**loud)

        self.assertEqual(result.severity, "Low")
        self.assertLessEqual(result.context_score, 15)

    def test_benign_signing_infrastructure_is_not_an_indicator(self) -> None:
        # Every signed binary references its CA's OCSP responder.
        _, cats = _verdict(**_signed_installer())

        self.assertFalse(_named(cats, "embedded_network_indicators").present)

    def test_a_verifying_signature_excuses_missing_version_info(self) -> None:
        # If the signature checks out, the version-info block means what it
        # says -- including when it says little.
        sample = _signed_installer()
        sample["pe_meta"] = {"version_info_collected": True, "sections": [],
                             "version_info": {"CompanyName": "Trusted Vendor Ltd"}}
        _, cats = _verdict(**sample)

        self.assertFalse(_named(cats, "stripped_metadata").present)


class BeingUnsignedIsNotEvidence(unittest.TestCase):
    """The additive model charged 8 points for it. That was the wrong shape.

    Most malware is unsigned and so is most small legitimate tooling. Making it
    a category would put every unsigned binary ever triaged at one category,
    which is Needs Review -- a floor so common it would mean nothing.
    """

    def test_an_unsigned_file_with_good_metadata_reaches_no_category(self) -> None:
        sample = _signed_installer()
        sample["signing"] = {"verify_ok": False, "timestamp_verified": False}
        result, cats = _verdict(**sample)

        self.assertFalse(_named(cats, "invalid_signature").present)
        self.assertEqual(result.categories_present, 0)

    def test_a_signature_that_does_not_verify_is_a_category(self) -> None:
        # Different claim entirely: something was changed after signing, or the
        # signature was never valid.
        sample = _signed_installer()
        sample["signing"] = {"verify_ok": False, "timestamp_verified": False,
                             "subject": "CN=Impersonated Vendor",
                             "signature_present": True}
        _, cats = _verdict(**sample)

        self.assertTrue(_named(cats, "invalid_signature").present)

    def test_a_broken_signature_never_stands_alone(self) -> None:
        # Expired certificates, stripped timestamps and ordinary build mistakes
        # all land here, so it corroborates rather than concludes.
        sample = _signed_installer()
        sample["signing"] = {"verify_ok": False, "signature_present": True,
                             "subject": "CN=Expired Vendor"}
        result, cats = _verdict(**sample)

        self.assertFalse(_named(cats, "invalid_signature").strong)
        self.assertEqual(result.verdict, "Needs Review")


class OneClaimIsOneCategory(unittest.TestCase):
    def test_four_missing_version_fields_are_one_category_not_four(self) -> None:
        # Four points for four empty fields is one claim charged four times,
        # and it is how a volume-driven model creeps back in.
        result, cats = _verdict(**_anonymous_binary())

        self.assertEqual(result.categories_present, 1)
        self.assertTrue(_named(cats, "stripped_metadata").present)

    def test_an_entirely_empty_version_block_still_does_not_stand_alone(self) -> None:
        # Go and Rust binaries ship this way, as does anything built without a
        # resource script. Letting an empty block reach Elevated Attention on
        # its own would sweep up a large population of ordinary open-source
        # tooling -- and it is the false positive this engine is worst placed to
        # catch, because nothing downstream disagrees with it.
        _, cats = _verdict(**_anonymous_binary())

        self.assertFalse(_named(cats, "stripped_metadata").strong)

    def test_a_partially_filled_block_is_present_but_not_strong(self) -> None:
        sample = _anonymous_binary()
        sample["pe_meta"] = {"version_info_collected": True, "sections": [],
                             "version_info": {"CompanyName": "Something"}}
        _, cats = _verdict(**sample)

        category = _named(cats, "stripped_metadata")
        self.assertTrue(category.present)
        self.assertFalse(category.strong)


class WhatTheFileIsPretendingToBe(unittest.TestCase):
    def test_a_hash_like_name_claims_nothing_because_it_is_probably_ours(self) -> None:
        # The on-disk name is whatever the analyst called the file. This
        # pipeline acquires samples by hash and stores them under it, so the
        # additive model's 6 points for a hash-like name were charged to every
        # sample it has ever downloaded. The author's own claim about the name
        # is OriginalFilename, which the version-info category covers.
        _, cats = _verdict(**_anonymous_binary())

        self.assertFalse(_named(cats, "deceptive_file_identity").present)

    def test_a_double_extension_is_emphatic(self) -> None:
        sample = _anonymous_binary()
        sample["summary"] = {"sample": {"filename": "invoice.pdf.exe"}}
        _, cats = _verdict(**sample)

        category = _named(cats, "deceptive_file_identity")
        self.assertTrue(category.present)
        self.assertTrue(category.strong)

    def test_a_right_to_left_override_is_emphatic(self) -> None:
        # U+202E reverses how everything after it displays. Nothing legitimate
        # puts one in a filename.
        sample = _anonymous_binary()
        sample["summary"] = {"sample": {"filename": "report‮xcod.exe"}}
        _, cats = _verdict(**sample)

        self.assertTrue(_named(cats, "deceptive_file_identity").strong)

    def test_an_ordinary_name_claims_nothing(self) -> None:
        _, cats = _verdict(**_signed_installer())

        self.assertFalse(_named(cats, "deceptive_file_identity").present)


_EXEC = 0x20000000


def _claiming(company):
    """A complete version block naming `company`.

    Complete, because a partial one is `stripped_metadata`'s claim rather than
    this one -- see the categoriser.
    """
    return {"CompanyName": company, "ProductName": "Product",
            "FileDescription": "Description", "OriginalFilename": "thing.exe"}


def _section(name, entropy, executable=True, raw_size=4096):
    return {"name": name, "entropy": entropy, "raw_size": raw_size,
            "virtual_size": raw_size,
            "characteristics": _EXEC if executable else 0x40000000}


class ClaimingAVendorThatSignsEverything(unittest.TestCase):
    """The version block answers what the filename cannot.

    All three name predicates were correct and none had ever fired: this
    pipeline acquires by hash, so the authored filename is destroyed before
    analysis. `CompanyName` survives, and of the 56 samples nothing else fired
    on, thirteen claimed Microsoft while unsigned.
    """

    def test_an_unsigned_binary_claiming_microsoft_is_deceptive(self) -> None:
        sample = _anonymous_binary()
        sample["pe_meta"] = {"version_info_collected": True, "sections": [],
                             "version_info": _claiming("Microsoft Corporation")}
        _, cats = _verdict(**sample)

        self.assertTrue(_named(cats, "deceptive_file_identity").present)

    def test_the_same_claim_signed_is_not(self) -> None:
        # Microsoft binaries claiming Microsoft are the overwhelming majority
        # of System32, and all 284 of them verify.
        sample = _signed_installer()
        sample["pe_meta"] = {"version_info_collected": True, "sections": [],
                             "version_info": _claiming("Microsoft Corporation")}
        _, cats = _verdict(**sample)

        self.assertFalse(_named(cats, "deceptive_file_identity").present)

    def test_a_vendor_that_ships_unsigned_is_not_accused(self) -> None:
        # Igor Pavlov signs nothing -- 0 of 6 in Program Files -- so an unsigned
        # 7-Zip binary claiming him is telling the truth. The list is derived
        # from that fact rather than from a guess about who matters.
        sample = _anonymous_binary()
        sample["pe_meta"] = {"version_info_collected": True, "sections": [],
                             "version_info": _claiming("Igor Pavlov")}
        _, cats = _verdict(**sample)

        self.assertFalse(_named(cats, "deceptive_file_identity").present)

    def test_the_claim_is_not_emphatic_on_its_own(self) -> None:
        # Four Program Files binaries honestly say `Microsoft Corporation` while
        # shipping unsigned inside someone else's installer. A strong category
        # would carry those four to Corroborated alone.
        sample = _anonymous_binary()
        sample["pe_meta"] = {"version_info_collected": True, "sections": [],
                             "version_info": _claiming("Microsoft Corporation")}
        _, cats = _verdict(**sample)

        category = _named(cats, "deceptive_file_identity")
        self.assertTrue(category.present)
        self.assertFalse(category.strong)

    def test_a_vendor_claim_needs_a_collected_version_block(self) -> None:
        # A block nobody collected is not a file claiming nothing.
        sample = _anonymous_binary()
        sample["pe_meta"] = {"sections": []}
        _, cats = _verdict(**sample)

        self.assertFalse(_named(cats, "deceptive_file_identity").present)

    def test_a_three_letter_vendor_token_is_too_generic_to_accuse(self) -> None:
        sample = _anonymous_binary()
        sample["pe_meta"] = {"version_info_collected": True, "sections": [],
                             "version_info": _claiming("ENE Technology inc.")}
        _, cats = _verdict(**sample)

        self.assertFalse(_named(cats, "deceptive_file_identity").present)


def _assembly(fraction, il_only=True, enough=True, protectors=()):
    """A managed sample whose identifiers are `fraction` unreadable."""
    return {"collected": True, "is_managed": True, "il_only": il_only,
            "identifiers_sufficient": enough, "identifier_count": 800,
            "unreadable_fraction": fraction, "protectors": list(protectors)}


class WhatTheCodeWasBuiltOutOf(unittest.TestCase):
    """Managed code is the module's largest blind spot; this is one window.

    47.6% of the malware corpora is .NET against 11.3% of benign, and 13 of the
    22 samples that survived every other category are managed. The threshold is
    not load-bearing: benign tops out at 0.099 and the five samples this
    recovers sit at 0.228 and above, with nothing in between.
    """

    def test_a_renamed_assembly_is_obfuscated(self) -> None:
        sample = _anonymous_binary()
        sample["dotnet_meta"] = _assembly(0.267)
        _, cats = _verdict(**sample)

        self.assertTrue(_named(cats, "obfuscated_managed_code").present)

    def test_ordinary_managed_code_is_not(self) -> None:
        # `protobuf-net.Core.dll` is the highest benign assembly measured, at
        # 0.099 over 1,818 identifiers.
        sample = _anonymous_binary()
        sample["dotnet_meta"] = _assembly(0.099)
        _, cats = _verdict(**sample)

        self.assertFalse(_named(cats, "obfuscated_managed_code").present)

    def test_mixed_mode_is_excluded_by_what_it_is(self) -> None:
        # `mfcm140u.dll` reads 0.201 unreadable on mangled C++ symbols and is
        # entirely legitimate. Mixed mode is a precondition, not a threshold.
        sample = _anonymous_binary()
        sample["dotnet_meta"] = _assembly(0.201, il_only=False)
        _, cats = _verdict(**sample)

        self.assertFalse(_named(cats, "obfuscated_managed_code").present)

    def test_too_few_identifiers_is_arithmetic_not_a_measurement(self) -> None:
        # A satellite resource assembly with five identifiers reads 0.200 on a
        # single generic type name.
        sample = _anonymous_binary()
        sample["dotnet_meta"] = _assembly(0.200, enough=False)
        _, cats = _verdict(**sample)

        self.assertFalse(_named(cats, "obfuscated_managed_code").present)

    def test_a_native_binary_is_answered_not_skipped(self) -> None:
        sample = _anonymous_binary()
        sample["dotnet_meta"] = {"collected": True, "is_managed": False}
        _, cats = _verdict(**sample)

        category = _named(cats, "obfuscated_managed_code")
        self.assertTrue(category.collected)
        self.assertFalse(category.present)

    def test_a_collector_that_did_not_run_is_unknown(self) -> None:
        sample = _anonymous_binary()
        sample["dotnet_meta"] = {"collected": False, "error": "boom"}
        _, cats = _verdict(**sample)

        self.assertFalse(_named(cats, "obfuscated_managed_code").collected)

    def test_a_named_protector_does_not_fire_it_alone(self) -> None:
        # Dotfuscator and SmartAssembly are products people buy. 0 of 39 benign
        # managed assemblies is not a false-positive rate for protected
        # commercial software; it is the absence of that software from the
        # corpus. The marker explains a finding, it does not make one.
        sample = _anonymous_binary()
        sample["dotnet_meta"] = _assembly(0.02, protectors=("Dotfuscator",))
        _, cats = _verdict(**sample)

        self.assertFalse(_named(cats, "obfuscated_managed_code").present)

    def test_it_never_concludes_alone(self) -> None:
        sample = _anonymous_binary()
        sample["dotnet_meta"] = _assembly(0.776, protectors=("ConfuserEx",))
        _, cats = _verdict(**sample)

        category = _named(cats, "obfuscated_managed_code")
        self.assertTrue(category.present)
        self.assertFalse(category.strong)
        self.assertIn("ConfuserEx", category.detail)


class HowTheCodeIsStored(unittest.TestCase):
    """Packing, measured before it shipped.

    0.3% and 0.0% on the two benign corpora against 35.4% and 28.0% on the two
    malware ones -- and the executable bit is what makes that true.
    """

    def test_a_near_random_executable_section_is_packed(self) -> None:
        sample = _anonymous_binary()
        sample["pe_meta"] = {"version_info_collected": True, "version_info": {},
                             "sections": [_section(".text", 7.81)]}
        _, cats = _verdict(**sample)

        self.assertTrue(_named(cats, "high_entropy_sections").present)

    def test_a_compressed_resource_section_is_not(self) -> None:
        # A PNG is incompressible and says nothing about intent. Benign high
        # entropy is almost entirely `.rsrc`; malware's is `.text`.
        sample = _anonymous_binary()
        sample["pe_meta"] = {"version_info_collected": True, "version_info": {},
                             "sections": [_section(".rsrc", 7.99, executable=False)]}
        _, cats = _verdict(**sample)

        self.assertFalse(_named(cats, "high_entropy_sections").present)

    def test_ordinary_compiled_code_is_not(self) -> None:
        sample = _anonymous_binary()
        sample["pe_meta"] = {"version_info_collected": True, "version_info": {},
                             "sections": [_section(".text", 5.84)]}
        _, cats = _verdict(**sample)

        self.assertFalse(_named(cats, "high_entropy_sections").present)

    def test_an_empty_section_carries_no_entropy(self) -> None:
        # A section with no bytes on disk has nothing to measure; `raw_size` 0
        # with a stored entropy would otherwise be read as a finding.
        sample = _anonymous_binary()
        sample["pe_meta"] = {"version_info_collected": True, "version_info": {},
                             "sections": [_section(".text", 7.99, raw_size=0)]}
        _, cats = _verdict(**sample)

        self.assertFalse(_named(cats, "high_entropy_sections").present)

    def test_no_section_table_is_unknown_not_clean(self) -> None:
        sample = _anonymous_binary()
        sample["pe_meta"] = {"version_info_collected": True, "version_info": {}}
        _, cats = _verdict(**sample)

        self.assertFalse(_named(cats, "high_entropy_sections").collected)

    def test_it_never_concludes_alone(self) -> None:
        # 0.3% would ordinarily earn `strong`, but both benign corpora are
        # *installed* software and contain none of the installers where
        # legitimate packing lives. The measurement cannot see the population
        # that would produce the false positives.
        sample = _anonymous_binary()
        sample["pe_meta"] = {"version_info_collected": True, "version_info": {},
                             "sections": [_section(".text", 7.99)]}
        _, cats = _verdict(**sample)

        self.assertFalse(_named(cats, "high_entropy_sections").strong)


class SignaturesOfKnownMalware(unittest.TestCase):
    def test_a_family_named_rule_is_emphatic(self) -> None:
        sample = _anonymous_binary()
        sample["yara_results"] = {
            "matched": True, "match_count": 1,
            "matches": [{"rule": "Formbook_Stealer_Loader", "meta": {}, "tags": []}],
        }
        _, cats = _verdict(**sample)

        category = _named(cats, "known_malware_signature")
        self.assertTrue(category.present)
        self.assertTrue(category.strong)

    def test_three_unrelated_rules_agreeing_is_emphatic(self) -> None:
        # Same line the dynamic side draws at three memory-only rules, for the
        # same reason: one is a marker, three is a consensus.
        sample = _anonymous_binary()
        sample["yara_results"] = {
            "matched": True, "match_count": 3,
            "matches": [{"rule": f"Generic_Indicator_{n}", "meta": {}, "tags": []}
                        for n in range(3)],
        }
        _, cats = _verdict(**sample)

        self.assertTrue(_named(cats, "known_malware_signature").strong)

    def test_one_generic_rule_is_present_but_not_emphatic(self) -> None:
        sample = _anonymous_binary()
        sample["yara_results"] = {
            "matched": True, "match_count": 1,
            "matches": [{"rule": "Contains_Base64_Blob", "meta": {}, "tags": []}],
        }
        _, cats = _verdict(**sample)

        category = _named(cats, "known_malware_signature")
        self.assertTrue(category.present)
        self.assertFalse(category.strong)


class CapabilityIsCountedInBehaviours(unittest.TestCase):
    """Rebuilt 27 Aug on capa namespaces, measured over 735 samples.

    **The two tests that were here are gone, and their subject with them.** They
    asserted that a high-signal ATT&CK technique and a high-severity API chain
    were one claim seen twice rather than two. That was sound reasoning about a
    signal that turned out not to be one: measured, the technique route fired on
    35.1% of System32 and 39.3% of malware -- 1.1x, a coin. `T1059` was 86 of
    its 99 benign firings, and capa maps it onto anything able to launch a
    process.

    The category now counts distinct high-signal *behaviour namespaces*.
    Measured: three or more fires on 2.4% of benign and 25.1% of malware, five
    or more on 0.56% and 18.7%.
    """

    THREE = ["collection/screenshot", "load-code/shellcode",
             "host-interaction/hardware/keyboard"]
    FIVE = THREE + ["communication/c2/file-transfer",
                    "anti-analysis/anti-forensic/self-deletion"]

    def test_three_behaviours_is_a_claim(self) -> None:
        sample = _signed_installer()
        sample["capa_namespaces"] = self.THREE
        _, cats = _verdict(**sample)

        category = _named(cats, "dangerous_capability")
        self.assertTrue(category.present)
        self.assertFalse(category.strong)

    def test_five_is_emphatic(self) -> None:
        # 0.56% of 532 benign samples reach five. That is the rate at which a
        # category is allowed to stand on its own.
        sample = _signed_installer()
        sample["capa_namespaces"] = self.FIVE
        _, cats = _verdict(**sample)

        self.assertTrue(_named(cats, "dangerous_capability").strong)

    def test_two_is_not(self) -> None:
        # Two fires on 6.0% of benign software. The step from two to three
        # more than halves that and costs four points of sensitivity.
        sample = _signed_installer()
        sample["capa_namespaces"] = self.THREE[:2]
        _, cats = _verdict(**sample)

        self.assertFalse(_named(cats, "dangerous_capability").present)

    def test_anti_debugging_is_not_evidence(self) -> None:
        # Measured at 41.2% benign against 12.8% malware -- inverted. Legitimate
        # software checks for debuggers constantly, and this is the single
        # namespace most responsible for the old category's noise.
        sample = _signed_installer()
        sample["capa_namespaces"] = ["anti-analysis/anti-debugging"] * 1 + [
            "anti-analysis", "host-interaction/process/inject",
            "persistence", "compiler", "load-code/dotnet"]
        _, cats = _verdict(**sample)

        self.assertFalse(_named(cats, "dangerous_capability").present)

    def test_a_failed_capa_is_unknown_not_clean(self) -> None:
        # capa failed on 194 of 229 malware samples once, and the category
        # reported collected=True with nothing found. The rate that came out
        # was wrong by a factor of four.
        sample = _signed_installer()
        sample["capa_namespaces"] = []
        sample["capa_ok"] = False
        _, cats = _verdict(**sample)

        category = _named(cats, "dangerous_capability")
        self.assertFalse(category.collected)
        self.assertFalse(category.present)

    def test_low_signal_techniques_alone_claim_nothing(self) -> None:
        # T1082 is system information discovery. Every installer on earth does
        # it, and an additive model still charged for it.
        sample = _signed_installer()
        sample["techniques"] = ["T1082", "T1083", "T1033"]
        result, cats = _verdict(**sample)

        self.assertFalse(_named(cats, "dangerous_capability").present)
        self.assertEqual(result.categories_present, 0)


class EmbeddedIndicatorsCorroborateAndNoMore(unittest.TestCase):
    def test_a_non_benign_host_is_a_category(self) -> None:
        sample = _anonymous_binary()
        sample["iocs"] = {"observables": {
            "domains": ["klopasnarhia.cc"], "urls": [], "ips": []}}
        _, cats = _verdict(**sample)

        self.assertTrue(_named(cats, "embedded_network_indicators").present)

    def test_it_is_never_emphatic(self) -> None:
        # A hostname in a binary is a string until something contacts it, and
        # the module that can watch it do that is the dynamic one.
        sample = _anonymous_binary()
        sample["iocs"] = {"observables": {
            "domains": ["klopasnarhia.cc"], "urls": [], "ips": []}}
        _, cats = _verdict(**sample)

        self.assertFalse(_named(cats, "embedded_network_indicators").strong)


class TheBandsSeparateTheReferenceSamples(unittest.TestCase):
    """The whole point, stated as four rows."""

    def test_signed_installer_is_low(self) -> None:
        result, _ = _verdict(**_signed_installer())

        self.assertEqual(result.severity, "Low")

    def test_anonymous_binary_is_needs_review(self) -> None:
        # One unexplained observation with nothing corroborating it.
        result, _ = _verdict(**_anonymous_binary())

        self.assertEqual(result.severity, "Medium")
        self.assertEqual(result.verdict, "Needs Review")

    def test_a_family_hit_with_dangerous_capability_is_elevated(self) -> None:
        sample = _signed_installer()
        sample["yara_results"] = {
            "matched": True, "match_count": 1,
            "matches": [{"rule": "Formbook_Stealer", "meta": {}, "tags": []}]}
        sample["techniques"] = ["T1055"]
        result, _ = _verdict(**sample)

        self.assertEqual(result.severity, "High")
        self.assertEqual(result.verdict, "Elevated Attention")

    def test_the_full_picture_is_likely_malicious(self) -> None:
        sample = _anonymous_binary()
        sample["yara_results"] = {
            "matched": True, "match_count": 1,
            "matches": [{"rule": "Formbook_Stealer", "meta": {}, "tags": []}]}
        sample["techniques"] = ["T1055", "T1071"]
        sample["iocs"] = {"observables": {
            "domains": ["klopasnarhia.cc"], "urls": [], "ips": []}}
        result, _ = _verdict(**sample)

        self.assertGreaterEqual(result.categories_present, 3)
        self.assertEqual(result.verdict, "Likely Malicious")


class ACollectorThatDidNotRunIsUnknown(unittest.TestCase):
    def test_no_yara_ruleset_is_unknown_not_absent(self) -> None:
        sample = _signed_installer()
        sample["yara_results"] = None
        result, cats = _verdict(**sample)

        self.assertFalse(_named(cats, "known_malware_signature").collected)
        self.assertIn("known_malware_signature", result.unknown_names)

    def test_a_yara_scan_that_errored_is_also_unknown(self) -> None:
        # "capa with no ruleset" and "YARA that could not load rules" are the
        # same failure, and both used to degrade into a quiet zero.
        sample = _signed_installer()
        sample["yara_results"] = {"error": "could not open rules directory"}
        _, cats = _verdict(**sample)

        self.assertFalse(_named(cats, "known_malware_signature").collected)

    def test_a_failed_api_run_does_not_claim_capability_coverage(self) -> None:
        sample = _signed_installer()
        sample["api_analysis"] = {"returncode": 2, "error": "capa not found"}
        sample["techniques"] = None
        _, cats = _verdict(**sample)

        self.assertFalse(_named(cats, "dangerous_capability").collected)

    def test_a_dark_collector_costs_the_clean_headline(self) -> None:
        sample = _signed_installer()
        sample["yara_results"] = None
        result, _ = _verdict(**sample)

        self.assertEqual(result.severity, "Low")
        self.assertEqual(result.verdict, "No Findings, Coverage Incomplete")

    def test_nothing_collected_at_all_says_so(self) -> None:
        result, _ = _verdict()

        self.assertEqual(result.severity, "Unknown")
        self.assertEqual(result.verdict, "Insufficient Coverage")

    def test_static_alone_never_claims_a_clean_baseline(self) -> None:
        # "Clean Baseline" is a claim about having watched the sample run.
        result, _ = _verdict(**_signed_installer())

        self.assertEqual(result.verdict, "No Indicators Found")
        self.assertIn("dynamic", result.modules_absent)


class VirusTotalIsNotConsultedHere(unittest.TestCase):
    """In either direction, which is what makes the rule true rather than half true.

    The additive model used a clean VirusTotal signal to suppress local
    observations. Letting a third-party opinion lower a verdict is the same
    error as letting it raise one.
    """

    def test_a_clean_virustotal_result_does_not_suppress_a_category(self) -> None:
        sample = _anonymous_binary()
        sample["summary"] = dict(sample["summary"])
        sample["summary"]["virustotal"] = {
            "found": True, "malicious": 0, "suspicious": 0,
            "harmless": 60, "undetected": 10}
        result, _ = _verdict(**sample)

        self.assertEqual(result.verdict, "Needs Review")

    def test_a_damning_virustotal_result_does_not_create_one(self) -> None:
        sample = _signed_installer()
        sample["summary"] = dict(sample["summary"])
        sample["summary"]["virustotal"] = {
            "found": True, "malicious": 64, "suspicious": 3}
        result, _ = _verdict(**sample)

        # The dissent floor is the combiner's job, and it is capped at Needs
        # Review. Static on its own reports what static saw.
        self.assertEqual(result.categories_present, 0)


if __name__ == "__main__":
    unittest.main()
