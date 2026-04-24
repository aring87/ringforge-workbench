import json
import tempfile
import unittest
from pathlib import Path

from static_triage_engine.scoring import score_static


class ScoreStaticInstallerContextTests(unittest.TestCase):
    def test_sets_likely_benign_installer_context_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp)
            (case_dir / "yara_results.json").write_text(
                json.dumps({"matched": False, "match_count": 0}),
                encoding="utf-8",
            )

            summary = {
                "sample": {"path_case": str(case_dir / "sample_setup.exe"), "filename": "sample_setup.exe"},
                "virustotal": {"found": True, "malicious": 1, "suspicious": 0},
            }
            pe_meta = {
                "version_info": {
                    "CompanyName": "Trusted Vendor",
                    "ProductName": "Sample Setup",
                    "FileDescription": "Installer",
                    "OriginalFilename": "sample_setup.exe",
                }
            }

            _, evidence, flags = score_static(summary, {}, pe_meta, {}, None)

            self.assertTrue(flags.get("likely_benign_installer_context"))
            self.assertTrue(any(e.rule == "installer_context" for e in evidence))

    def test_handles_missing_installer_context_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp)
            summary = {"sample": {"path_case": str(case_dir / "sample.exe")}}

            score, evidence, flags = score_static(summary, {}, {}, {}, None)

            self.assertIsInstance(score, int)
            self.assertIsInstance(evidence, list)
            self.assertIsInstance(flags, dict)


if __name__ == "__main__":
    unittest.main()