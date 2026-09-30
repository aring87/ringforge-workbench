"""The socket family counts once in `dangerous_capability`, and a moved case
scores the same on another host.

Two fixes shipped together on 29 Sep, both measured against the detonated
corpora before and after (`scripts/capability_verdicts.py`):

* `communication/socket/{receive,send,tcp}` said one thing -- TCP I/O -- three
  times, and took both benign ASUS Aura services toward `strong`.
* The technique term of the static context score opened the capa.json at the
  path the *summary* recorded, which is the guest's work directory and does
  not exist on the host; 20 of 208 re-combined cases lost context points.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from static_triage_engine.categories import static_categories
from static_triage_engine.combine_case import static_categories_for_case
from static_triage_engine.scoring import (
    CAPABILITY_PRESENT_AT, CAPABILITY_STRONG_AT, HIGH_SIGNAL_CAPABILITIES,
    SOCKET_FAMILY, SOCKET_FAMILY_AS, high_signal_matches)

SOCKET = sorted(SOCKET_FAMILY)
#: The Aura-Wallpaper-Service shape: seven members, three of them the family.
AURA = SOCKET + ["host-interaction/process/list", "host-interaction/thread/suspend",
                 "host-interaction/wmi", "communication/tcp/client"]


def _named(cats, name):
    return next(c for c in cats if c.name == name)


def _capability(namespaces):
    cats, _ = static_categories(
        summary={}, iocs={}, pe_meta={}, api_analysis={"ok": True}, yara_results={},
        signing={}, techniques=[], capa_namespaces=namespaces, capa_ok=True,
        capa_match_count=0, dotnet_meta=None)
    return _named(cats, "dangerous_capability")


class HighSignalMatchesTests(unittest.TestCase):

    def test_the_family_counts_once(self) -> None:
        self.assertEqual(high_signal_matches(SOCKET), [SOCKET_FAMILY_AS])

    def test_one_member_still_counts(self) -> None:
        self.assertEqual(high_signal_matches(["communication/socket/tcp"]), [SOCKET_FAMILY_AS])

    def test_other_members_are_untouched(self) -> None:
        others = ["collection/screenshot", "communication/c2", "communication/c2/file-transfer"]
        self.assertEqual(high_signal_matches(others + SOCKET), sorted(others + [SOCKET_FAMILY_AS]))

    def test_the_c2_parent_is_not_collapsed(self) -> None:
        """Measured at the same time and rejected: it cost three malware bands."""
        got = high_signal_matches(["communication/c2", "communication/c2/file-transfer"])
        self.assertEqual(len(got), 2)

    def test_non_members_and_none(self) -> None:
        self.assertEqual(high_signal_matches(["data-manipulation/xml"]), [])
        self.assertEqual(high_signal_matches(None), [])

    def test_the_family_is_inside_the_set(self) -> None:
        self.assertTrue(SOCKET_FAMILY <= HIGH_SIGNAL_CAPABILITIES)


class CapabilityCategoryTests(unittest.TestCase):

    def test_the_aura_shape_is_present_not_strong(self) -> None:
        """Seven raw members, five distinct behaviours: present, not strong."""
        self.assertEqual(len(AURA), 7)
        category = _capability(AURA)
        self.assertTrue(category.present)
        self.assertFalse(category.strong)
        self.assertIn("5 high-signal capabilities", category.detail)
        self.assertIn("socket", category.detail)

    def test_the_family_alone_is_not_present(self) -> None:
        """Three socket members plus one other was four -- present -- before."""
        category = _capability(SOCKET + ["host-interaction/wmi"])
        self.assertFalse(category.present)

    def test_six_distinct_behaviours_are_still_strong(self) -> None:
        six = ["collection/screenshot", "load-code/shellcode", "host-interaction/clipboard",
               "host-interaction/hardware/keyboard", "anti-analysis/anti-vm"] + SOCKET
        self.assertEqual(len(high_signal_matches(six)), CAPABILITY_STRONG_AT)
        self.assertTrue(_capability(six).strong)
        self.assertGreater(CAPABILITY_STRONG_AT, CAPABILITY_PRESENT_AT)


class TechniquePortabilityTests(unittest.TestCase):

    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(prefix="rf-case-"))
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        capa = {"meta": {}, "rules": {f"r{i}": {"meta": {"attack": [{"id": f"T10{i:02}"}]},
                                              "matches": {}} for i in range(12)}}
        # capa's own text carries the ids; the regex reads the file, not the dict.
        (self.home / "capa.json").write_text(
            json.dumps(capa) + " " + " ".join(f"T10{i:02}" for i in range(12)), encoding="utf-8")

    def test_techniques_come_from_the_case_not_the_recorded_path(self) -> None:
        """The summary names a directory on another machine. The context
        score must be the same as if it had not."""
        foreign = {"case_dir": r"C:\ProgramData\RingForge\work\nowhere",
                   "sample": {"filename": "x.exe"}}
        _cats, context = static_categories_for_case(
            self.home, summary=foreign, iocs={}, pe_meta={}, api_analysis={"ok": True},
            yara_results={}, signing={})
        # 12 techniques -> min(4, 12 // 3) = 4 points, plus capa density.
        _cats_none, context_without = static_categories_for_case(
            self.home, summary=None, iocs={}, pe_meta={}, api_analysis={"ok": True},
            yara_results={}, signing={})
        self.assertGreaterEqual(context - context_without, 4)


if __name__ == "__main__":
    unittest.main()
