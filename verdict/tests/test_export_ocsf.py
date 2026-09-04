"""The verdict as an OCSF Detection Finding.

Most tools send a SIEM a severity and a score. The point of this mapping is
that it also sends **coverage** -- which modules ran, which were absent, which
categories could not be checked -- so a detection engineer can write "alert on
Corroborated, and separately alert on Unknown where coverage was incomplete".

That distinction dies if `Unknown` is flattened into `Informational`, which is
the obvious mapping and the wrong one. Most of what is pinned here is that it
survives the trip.
"""

import json
import tempfile
import unittest
from pathlib import Path

from verdict.export_ocsf import (
    CLASS_UID,
    OCSF_VERSION,
    TYPE_UID,
    is_actionable,
    severity_id,
    to_ocsf,
    write_ndjson,
)

CORROBORATED = {
    "schema_version": "1.0",
    "generated_utc": "2026-09-04T14:47:43Z",
    "case_id": "7ea500ad175878014fa1ec391416ae477066b2622c96c8b882126febdeddf004",
    "case_name": "c14cb5b6_payload",
    "sample": {"sha256": "7ea500ad", "md5": "dfc0bdba", "sha1": "e696f56f",
               "filename": "payload.bin", "size_bytes": 258048},
    "provenance": {"analyzer": {"name": "ringforge-workbench",
                                "version": "1.12.0", "commit": "abc1234"}},
    "severity": "High", "verdict": "Elevated Attention", "band": "Corroborated",
    "score": 43, "score_model": "corroboration-v1", "domain": "malware",
    "modules_run": ["static"],
    "modules_absent": ["dynamic", "spec", "api", "extension"],
    "uncollected_categories": [], "coverage_complete": True,
    "evidence": [{"name": "known_malware_signature", "module": "static",
                  "strong": False, "reason": "YARA matched 2 rules on disk.",
                  "detail": "RingForge_EtherHiding_eth_call"}],
}

NOTHING_COLLECTED = {
    "generated_utc": "2026-09-04T15:00:00Z",
    "case_id": "empty_case", "case_name": "empty_case",
    "severity": "Unknown", "verdict": "Insufficient Coverage",
    "band": "Nothing Collected", "score": 0,
    "modules_run": [],
    "modules_absent": ["static", "dynamic", "spec", "api", "extension"],
    "uncollected_categories": ["known_malware_signature"],
    "coverage_complete": False, "evidence": [],
}


class CoverageSurvivesTheMapping(unittest.TestCase):
    """The reason this exporter is worth having."""

    def test_unknown_maps_to_unknown_not_informational(self) -> None:
        """OCSF has a severity for "could not be determined" and this uses it.
        Mapping `Unknown` to Informational would deliver a case nobody looked
        at as a quiet clean one, which is the failure the whole scoring model
        was rewritten to prevent."""
        self.assertEqual(severity_id("Unknown"), 0)
        self.assertNotEqual(severity_id("Unknown"), severity_id("Info"))

    def test_the_bands_keep_their_order(self) -> None:
        self.assertGreater(severity_id("High"), severity_id("Medium"))
        self.assertGreater(severity_id("Medium"), severity_id("Low"))
        self.assertGreater(severity_id("Low"), severity_id("Info"))

    def test_coverage_rides_as_an_enrichment(self) -> None:
        enrichment = to_ocsf(NOTHING_COLLECTED)["enrichments"][0]

        self.assertEqual(enrichment["name"], "ringforge_coverage")
        self.assertFalse(enrichment["data"]["complete"])
        self.assertEqual(enrichment["data"]["modules_run"], [])
        self.assertIn("known_malware_signature",
                      enrichment["data"]["uncollected_categories"])

    def test_incomplete_coverage_is_said_in_the_description(self) -> None:
        """The analyst reading the SIEM sees it without opening the payload."""
        desc = to_ocsf(NOTHING_COLLECTED)["finding_info"]["desc"]

        self.assertIn("COVERAGE INCOMPLETE", desc)
        self.assertIn("modules run: none", desc)

    def test_a_case_nobody_looked_at_is_still_exported(self) -> None:
        """Filtering it out would hide exactly the gap a coverage rule needs.
        `is_actionable` lets a caller route instead of drop."""
        event = to_ocsf(NOTHING_COLLECTED)

        self.assertEqual(event["class_uid"], CLASS_UID)
        self.assertFalse(is_actionable(NOTHING_COLLECTED))
        self.assertTrue(is_actionable(CORROBORATED))


class TheEventShape(unittest.TestCase):
    def test_it_is_a_detection_finding(self) -> None:
        event = to_ocsf(CORROBORATED)

        self.assertEqual(event["class_uid"], 2004)
        self.assertEqual(event["category_uid"], 2)
        self.assertEqual(event["type_uid"], TYPE_UID)
        self.assertEqual(event["type_uid"], 200401)
        self.assertEqual(event["metadata"]["version"], OCSF_VERSION)

    def test_the_uid_is_the_sample_so_a_re_run_updates(self) -> None:
        first, second = to_ocsf(CORROBORATED), to_ocsf(CORROBORATED)

        self.assertEqual(first["finding_info"]["uid"], CORROBORATED["case_id"])
        self.assertEqual(first["finding_info"]["uid"],
                         second["finding_info"]["uid"])

    def test_the_time_is_the_analysis_not_the_shipping(self) -> None:
        """A finding re-exported next week must not claim to be new.

        Asserted as a property rather than against a hardcoded epoch: `time`
        is derived from `generated_utc` on the document, so it is stable across
        exports, while `logged_time` moves with the clock.
        """
        first = to_ocsf(CORROBORATED)
        second = to_ocsf(CORROBORATED)

        self.assertEqual(first["time"], second["time"])
        self.assertLess(first["time"], first["metadata"]["logged_time"])

    def test_a_verdict_with_no_timestamp_falls_back_to_now(self) -> None:
        """Rather than emitting epoch zero, which a SIEM would file in 1970."""
        import time as _time

        event = to_ocsf({"severity": "Low"})

        self.assertGreater(event["time"], (_time.time() - 60) * 1000)

    def test_evidence_keeps_the_module_that_saw_it(self) -> None:
        evidences = to_ocsf(CORROBORATED)["evidences"]

        self.assertEqual(len(evidences), 1)
        self.assertEqual(evidences[0]["name"], "known_malware_signature")
        self.assertEqual(evidences[0]["data"]["module"], "static")

    def test_the_sample_becomes_a_resource_with_its_hashes(self) -> None:
        resource = to_ocsf(CORROBORATED)["resources"][0]

        self.assertEqual(resource["type"], "file")
        self.assertEqual(set(resource["data"]["hashes"]), {"md5", "sha1", "sha256"})

    def test_a_case_with_no_sample_has_no_resource(self) -> None:
        self.assertNotIn("resources", to_ocsf(NOTHING_COLLECTED))

    def test_nothing_the_model_produced_is_lost(self) -> None:
        """The mapping is not lossy: what OCSF has no field for is kept
        verbatim so a consumer can always recover it."""
        unmapped = to_ocsf(CORROBORATED)["unmapped"]

        self.assertEqual(unmapped["score"], 43)
        self.assertEqual(unmapped["schema_version"], "1.0")
        self.assertEqual(unmapped["provenance"]["analyzer"]["version"], "1.12.0")

    def test_an_empty_verdict_does_not_raise(self) -> None:
        event = to_ocsf({})

        self.assertEqual(event["class_uid"], 2004)
        self.assertEqual(event["severity_id"], 0)

    def test_it_is_json_serialisable(self) -> None:
        json.dumps(to_ocsf(CORROBORATED))


class TheSpool(unittest.TestCase):
    def test_one_object_per_line(self) -> None:
        spool = Path(tempfile.mkdtemp(prefix="ringforge_spool_"))

        write_ndjson([CORROBORATED, NOTHING_COLLECTED], spool)
        lines = (spool / "findings.ndjson").read_text(
            encoding="utf-8").strip().split("\n")

        self.assertEqual(len(lines), 2)
        self.assertEqual([json.loads(l)["class_uid"] for l in lines], [2004, 2004])

    def test_it_appends_rather_than_truncating(self) -> None:
        """The forwarder owns the read cursor. Truncating under it loses
        events that were never shipped."""
        spool = Path(tempfile.mkdtemp(prefix="ringforge_spool_"))

        write_ndjson(CORROBORATED, spool)
        write_ndjson(CORROBORATED, spool)
        lines = (spool / "findings.ndjson").read_text(
            encoding="utf-8").strip().split("\n")

        self.assertEqual(len(lines), 2)

    def test_a_single_verdict_need_not_be_wrapped_in_a_list(self) -> None:
        spool = Path(tempfile.mkdtemp(prefix="ringforge_spool_"))

        path = write_ndjson(CORROBORATED, spool)

        self.assertTrue(json.loads(path.read_text(encoding="utf-8").strip()))

    def test_it_creates_the_spool_directory(self) -> None:
        spool = Path(tempfile.mkdtemp(prefix="ringforge_spool_")) / "deeper"

        write_ndjson(CORROBORATED, spool)

        self.assertTrue((spool / "findings.ndjson").exists())


class AgainstTheRealCombiner(unittest.TestCase):
    """A fixture can agree with the exporter and disagree with the model."""

    def test_a_real_verdict_maps_without_losing_its_band(self) -> None:
        from static_triage_engine.combine_case import combine_case

        case = Path(tempfile.mkdtemp(prefix="ringforge_ocsf_"))
        (case / "summary.json").write_text(
            json.dumps({"sample": {"sha256": "abc", "filename": "x.bin"}}),
            encoding="utf-8")

        verdict = combine_case(case, write_output=False)
        event = to_ocsf(verdict)

        self.assertEqual(event["finding_info"]["types"], [verdict["band"]])
        self.assertEqual(event["severity"], verdict["severity"])
        self.assertEqual(event["enrichments"][0]["data"]["complete"],
                         verdict["coverage_complete"])


if __name__ == "__main__":
    unittest.main()
