r"""`Add-Type` scratch files must not carry a scored category on their own.

Found on run `33fe6c3b`. A PowerShell RunPE script took `payload_dropped` to
**strong** on exactly two files:

    C:\Users\adam\AppData\Local\Temp\zrudxjpg\zrudxjpg.dll
    C:\Users\adam\AppData\Local\Temp\hryya5bb\hryya5bb.dll

Both are `csc.exe` output -- the temporary assembly `Add-Type` compiles inline
C# into. Lineage was correct and the files were really written by the sample's
tree, so the collection is right and only the *claim* is wrong: every PowerShell
script calling `Add-Type` drops these, and that population is mostly legitimate
administration.

The bar these tests hold is narrowness. An exclusion that swallowed anything in
`%TEMP%` would hide real drops, so the shape has to stay specific enough that a
payload sitting next to a compiler artifact still scores.
"""
import unittest

from dynamic_analysis.dropped_file_triage import (
    enrich_dropped_files,
    path_is_compiler_artifact,
    summarize_dropped_files,
)

TEMP = r"C:\Users\adam\AppData\Local\Temp"


def _record(path):
    return {"path": path, "classification": "library", "suspicious_path": True,
            "exists_on_disk": True}


class TheShapeItRecognises(unittest.TestCase):
    def test_the_two_files_from_run_33fe6c3b(self):
        for name in ("zrudxjpg", "hryya5bb"):
            self.assertTrue(
                path_is_compiler_artifact(rf"{TEMP}\{name}\{name}.dll"), name)

    def test_the_pdb_beside_it(self):
        self.assertTrue(path_is_compiler_artifact(rf"{TEMP}\abcdefgh\abcdefgh.pdb"))

    def test_csc_and_res_scratch_files(self):
        self.assertTrue(path_is_compiler_artifact(
            rf"{TEMP}\CSC93069137B66D45F68F8848077F0A5DC.TMP"))
        self.assertTrue(path_is_compiler_artifact(rf"{TEMP}\RESCF83.tmp"))


class TheShapeItRefuses(unittest.TestCase):
    """Narrowness is the whole safety argument for this exclusion."""

    def test_a_real_drop_in_appdata_still_counts(self):
        # The other file run 33fe6c3b dropped, and the one that matters.
        self.assertFalse(path_is_compiler_artifact(
            r"C:\Users\adam\AppData\Roaming\whcjHybcIRKrlH.exe"))

    def test_a_payload_in_temp_under_a_different_name_still_counts(self):
        self.assertFalse(path_is_compiler_artifact(rf"{TEMP}\evil\payload.dll"))

    def test_the_stem_must_equal_its_directory(self):
        self.assertFalse(path_is_compiler_artifact(rf"{TEMP}\zrudxjpg\other.dll"))

    def test_an_exe_is_never_a_compiler_artifact(self):
        # csc writes a .dll here; a .exe with the same shape is not its output
        # and is exactly what a dropper would produce.
        self.assertFalse(path_is_compiler_artifact(rf"{TEMP}\zrudxjpg\zrudxjpg.exe"))

    def test_outside_a_suspicious_location_it_does_not_apply(self):
        self.assertFalse(path_is_compiler_artifact(r"C:\Windows\System32\a\a.dll"))


class WhatEnrichmentDoes(unittest.TestCase):
    def test_a_compiler_artifact_is_flagged_and_not_suspicious(self):
        record = enrich_dropped_files([_record(rf"{TEMP}\zrudxjpg\zrudxjpg.dll")])[0]
        self.assertTrue(record["compiler_artifact"])
        self.assertFalse(record["suspicious"])

    def test_its_reasons_are_kept_so_the_decision_is_auditable(self):
        """Set aside, not erased -- the `resource_only` precedent.

        The reasons that *would* have made it suspicious stay on the record, so
        a reader can see what was excluded and why rather than finding a file
        silently absent from the count.
        """
        record = enrich_dropped_files([_record(rf"{TEMP}\zrudxjpg\zrudxjpg.dll")])[0]
        self.assertTrue(record["reasons"])

    def test_a_real_drop_alongside_one_is_untouched(self):
        records = enrich_dropped_files([
            _record(rf"{TEMP}\zrudxjpg\zrudxjpg.dll"),
            {"path": r"C:\Users\adam\AppData\Roaming\whcjHybcIRKrlH.exe",
             "classification": "executable", "suspicious_path": True,
             "exists_on_disk": True},
        ])
        self.assertFalse(records[0]["suspicious"])
        self.assertTrue(records[1]["suspicious"])

    def test_run_33fe6c3b_no_longer_reaches_strong(self):
        """The regression this exists for.

        `payload_dropped` is strong at `suspicious_dropped >= 2`. That run had
        exactly two drops and both were compiler scratch, so the count has to
        fall to zero -- not to one.
        """
        summary = summarize_dropped_files(enrich_dropped_files([
            _record(rf"{TEMP}\zrudxjpg\zrudxjpg.dll"),
            _record(rf"{TEMP}\hryya5bb\hryya5bb.dll"),
        ]))
        self.assertEqual(summary["suspicious"], 0)
        self.assertEqual(summary["compiler_artifacts"], 2)
        self.assertEqual(summary["total_candidates"], 2)


if __name__ == "__main__":
    unittest.main()
