"""An autorun entry that names nothing is not evidence of anything.

The Remcos run reported `autoruns_suspicious: 3` for what were two genuine Run
keys. The third row carried a category and a hive location and nothing else --
no entry name, no image path, no launch string. It qualified as suspicious
purely by having category "Logon" and no signer, which is true of every blank
row Autoruns emits.

Two real entries inflated to three does not change a verdict on its own, but the
count is what `persistence_installed` reports as its detail, and a category that
counts noise cannot be read against a threshold.
"""

import unittest

from dynamic_analysis.orchestrator import _is_suspicious_autorun


def _row(**overrides) -> dict:
    row = {
        "Time": "8/6/2026 2:18:58 AM",
        "Entry Location": r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "Entry": "",
        "Enabled": "enabled",
        "Category": "Logon",
        "Signer": "",
        "Company": "",
        "Image Path": "",
        "Launch String": "",
    }
    row.update(overrides)
    return row


class SuspiciousAutorunTests(unittest.TestCase):
    def test_the_remcos_run_key_is_suspicious(self) -> None:
        self.assertTrue(
            _is_suspicious_autorun(
                _row(
                    Entry="TRY150-6P1GV6",
                    **{
                        "Image Path": r"C:\Users\adam\AppData\Roaming\Config\smng.exe",
                        "Launch String": r'"C:\Users\adam\AppData\Roaming\Config\smng.exe"',
                    },
                )
            )
        )

    def test_an_entry_naming_nothing_is_not(self) -> None:
        # Category "Logon", a location, and no other content whatsoever.
        self.assertFalse(_is_suspicious_autorun(_row()))

    def test_an_entry_with_only_a_name_still_counts(self) -> None:
        # A named entry whose image path Autoruns could not resolve is still
        # something that will run at logon. Only the wholly empty row is
        # discarded.
        self.assertTrue(_is_suspicious_autorun(_row(Entry="TRY150-6P1GV6")))

    def test_an_entry_with_only_a_path_still_counts(self) -> None:
        self.assertTrue(
            _is_suspicious_autorun(
                _row(**{"Image Path": r"C:\Users\adam\AppData\Roaming\Config\smng.exe"})
            )
        )

    def test_a_disabled_entry_is_not_suspicious(self) -> None:
        self.assertFalse(
            _is_suspicious_autorun(_row(Entry="TRY150-6P1GV6", Enabled="disabled"))
        )


if __name__ == "__main__":
    unittest.main()
