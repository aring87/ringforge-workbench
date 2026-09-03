"""The API Spec report, which could not be tested until it moved.

`_render_html` lived in `gui/spec_window.py`, so exercising it needed a
display. Third module through this pass, third one hiding something there --
and this was the loudest of the three.

**It put parser confidence in the verdict slot.** `analyze_api_spec` sets
`confidence` to say how much of the *document* it managed to read: it starts at
`"high"`, drops to `"medium"` at three parser warnings and `"low"` at five. The
report uppercased it into the banner where every other report writes a risk
band, coloured it backwards -- a confident parse took the chip that elsewhere
means nothing was found -- and, because the default is set before parsing
begins, a file that was not JSON at all rendered a banner reading **HIGH**.

Meanwhile `combine_case` was already running `spec_categories` over this exact
result to feed the Combined Score, and the module's own page ignored it.
"""

import json
import tempfile
import unittest
from pathlib import Path

from static_triage_engine.api_spec_analysis import analyze_api_spec
from static_triage_engine.spec_report import (
    auth_line,
    auth_names,
    build_spec_report,
    endpoint_auth,
    endpoint_auth_source,
    endpoint_flags,
    normalize_auth_name,
    spec_verdict,
)

#: Every sentence the posture domain can write. A spec bands here because
#: `POSTURE_MODULES` contains `spec`.
POSTURE_VERDICTS = (
    "Insufficient Coverage", "No Weaknesses Found", "Needs Review",
    "Multiple Weaknesses", "Serious Exposure",
)


def _analyze(text: str, name: str = "spec.json") -> dict:
    """Through the real analyser, so the report is tested against its input."""
    out = Path(tempfile.mkdtemp(prefix="ringforge_spec_report_"))
    path = out / name
    path.write_text(text, encoding="utf-8")
    return analyze_api_spec(path, out)


def _spec(**over) -> str:
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Thing API", "version": "1.0"},
        "servers": [{"url": "https://api.example.test"}],
        "components": {"securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer"}}},
        "security": [{"bearerAuth": []}],
        "paths": {"/v1/things": {"get": {"summary": "List things",
                                         "responses": {"200": {}}}}},
    }
    spec.update(over)
    return json.dumps(spec)


class TheVerdictWasNotAVerdict(unittest.TestCase):
    """The defect the extraction was for."""

    def test_a_file_that_is_not_a_spec_does_not_band_high(self) -> None:
        """The sharpest form of it.

        `confidence` defaults to `"high"` *before* the parse is attempted, so
        a document the parser could not open printed HIGH in the banner.
        """
        result = _analyze("this is not json at all")

        self.assertEqual(result["returncode"], 1)
        self.assertEqual(result["confidence"], "high")  # the misleading input

        verdict, _ = spec_verdict(result)

        self.assertEqual(verdict, "Insufficient Coverage")
        self.assertIn('<div class="verdict sev-med">Insufficient Coverage</div>',
                      build_spec_report(result))

    def test_the_banner_never_carries_the_parser_confidence(self) -> None:
        for confidence in ("high", "medium", "low"):
            with self.subTest(confidence=confidence):
                result = _analyze(_spec())
                result["confidence"] = confidence
                verdict, _ = spec_verdict(result)

                self.assertIn(verdict, POSTURE_VERDICTS)
                self.assertNotEqual(verdict.upper(), confidence.upper())

    def test_the_spec_type_never_reaches_the_banner_either(self) -> None:
        """Where confidence was blank it fell back to `spec_type.upper()`, so
        the verdict slot read OPENAPI."""
        result = _analyze(_spec())
        result["confidence"] = ""

        verdict, _ = spec_verdict(result)

        self.assertNotEqual(verdict.upper(), str(result["spec_type"]).upper())
        self.assertIn(verdict, POSTURE_VERDICTS)

    def test_the_class_comes_from_the_band_not_the_sentence(self) -> None:
        """"No Weaknesses Found" is not a string `severity_class_for_label`
        knows; the `Low` severity behind it is. Reading the sentence would put
        a parsed, scored spec back in the neutral chip."""
        result = _analyze(_spec())

        verdict, verdict_class = spec_verdict(result)

        self.assertEqual(verdict, "No Weaknesses Found")
        self.assertEqual(verdict_class, "sev-low")

    def test_a_weak_spec_bands_above_a_clean_one(self) -> None:
        clean = _analyze(_spec())
        exposed = _analyze(_spec(
            servers=[{"url": "http://api.example.test"}],
            components={},
            security=[],
            paths={"/v1/admin/users": {
                "delete": {"summary": "Delete a user", "security": [],
                           "responses": {"200": {}}}}}))

        _, clean_class = spec_verdict(clean)
        exposed_verdict, exposed_class = spec_verdict(exposed)

        self.assertNotEqual(clean_class, exposed_class)
        self.assertIn(exposed_verdict, POSTURE_VERDICTS)
        self.assertNotEqual(exposed_verdict, "No Weaknesses Found")

    def test_no_page_renders_its_verdict_in_the_neutral_chip(self) -> None:
        for text in ("not json", _spec(), _spec(paths={})):
            with self.subTest(text=text[:24]):
                html = build_spec_report(_analyze(text))
                self.assertNotIn('<div class="verdict sev-none">', html)


class TheSharedVocabulary(unittest.TestCase):
    """The window canonicalised auth names and the report did not.

    So the screen said `bearer` where the exported page said `bearerAuth`, and
    two specs naming the same scheme differently could not be compared.
    """

    def test_the_aliases_collapse(self) -> None:
        for raw, expected in (("bearerAuth", "bearer"), ("JWT", "bearer"),
                              ("api_key", "api-key"), ("X-API-Key", "api-key"),
                              ("BasicAuth", "basic"), ("OAuth", "oauth2"),
                              ("", "none")):
            with self.subTest(raw=raw):
                self.assertEqual(normalize_auth_name(raw), expected)

    def test_an_unknown_scheme_is_kept_not_dropped(self) -> None:
        """A name this does not recognise is still what the spec said."""
        self.assertEqual(normalize_auth_name("mTLS"), "mtls")

    def test_duplicates_collapse_and_order_holds(self) -> None:
        self.assertEqual(auth_names(["bearerAuth", "JWT", "api_key"]),
                         ["bearer", "api-key"])

    def test_none_is_stated_rather_than_left_blank(self) -> None:
        self.assertEqual(auth_line([]), "none")
        self.assertEqual(auth_line(["none"]), "none")

    def test_a_bare_string_is_accepted(self) -> None:
        self.assertEqual(auth_line("bearerAuth"), "bearer")

    def test_required_and_a_named_scheme_are_different_facts(self) -> None:
        self.assertEqual(endpoint_auth({"auth_required": True}), "required")
        self.assertEqual(
            endpoint_auth({"auth_required": True,
                           "auth_schemes_applied": ["bearerAuth"]}), "bearer")
        self.assertEqual(endpoint_auth({}), "none")

    def test_explicit_none_reads_as_public(self) -> None:
        self.assertEqual(endpoint_auth_source({"auth_source": "explicit_none"}),
                         "public")

    def test_the_upload_flag_exists(self) -> None:
        """The window built its own three-flag list and this was the fourth,
        so an upload endpoint was flagged on the page and not on screen."""
        self.assertEqual(endpoint_flags({"file_upload": True}), ["upload"])

    def test_the_flags_keep_a_fixed_order(self) -> None:
        flags = endpoint_flags({"file_upload": True, "admin_like_route": True,
                                "destructive_method": True,
                                "sensitive_parameters": True})

        self.assertEqual(flags, ["admin-like", "destructive",
                                 "sensitive-params", "upload"])


class ThePage(unittest.TestCase):
    def test_it_uses_the_one_page_builder_and_names_itself(self) -> None:
        html = build_spec_report(_analyze(_spec()))

        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn('<div class="banner">', html)
        self.assertIn("API Spec Analysis Report", html)
        # The footer note was the one part of `report_page` this call skipped,
        # so the exported page did not say which screen made it.
        self.assertIn("RingForge Workbench &bull; API Spec Analysis", html)

    def test_the_verdict_class_is_not_written_twice(self) -> None:
        """It passed `"verdict sev-none"` into a slot already wrapped in
        `class="verdict {…}"`, producing `class="verdict verdict sev-none"`."""
        html = build_spec_report(_analyze(_spec()))

        self.assertNotIn('class="verdict verdict', html)

    def test_a_failed_parse_says_so_before_its_zeros(self) -> None:
        html = build_spec_report(_analyze("not json"))

        self.assertIn("card-alert", html)
        self.assertIn("The spec was not parsed", html)
        self.assertIn("JSONDecodeError", html)

    def test_a_parsed_spec_grows_no_alert(self) -> None:
        self.assertNotIn('<div class="card card-alert">',
                         build_spec_report(_analyze(_spec())))

    def test_confidence_is_shown_as_coverage_and_says_what_it_means(self) -> None:
        html = build_spec_report(_analyze(_spec()))

        self.assertIn("Parser Coverage", html)
        self.assertIn("how much of the document was read", html)

    def test_the_display_score_is_labelled_as_not_the_banner(self) -> None:
        """The two models disagree on the reference spec. Showing both, named,
        beats one number on each of two pages."""
        html = build_spec_report(_analyze(_spec()))

        self.assertIn("Unified Report Display Score", html)
        self.assertIn("Not the band in the banner", html)

    def test_endpoint_auth_reaches_the_table_canonicalised(self) -> None:
        result = _analyze(_spec())
        result["endpoints"] = [{"method": "GET", "path": "/v1/things",
                                "auth_schemes_applied": ["bearerAuth"],
                                "risk_level": "low", "parameters": []}]

        html = build_spec_report(result)

        self.assertIn("<td>bearer</td>", html)
        self.assertNotIn("<td>bearerAuth</td>", html)

    def test_a_hostile_path_cannot_break_the_table(self) -> None:
        result = _analyze(_spec())
        result["endpoints"] = [{"method": "GET", "parameters": [],
                                "path": "</td><td><script>alert(1)</script>"}]

        html = build_spec_report(result)

        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_it_renders_an_empty_result_without_raising(self) -> None:
        html = build_spec_report({})

        self.assertIn("API Spec Analysis Report", html)

    def test_the_real_reference_spec_renders_whole(self) -> None:
        out = Path(tempfile.mkdtemp(prefix="ringforge_spec_report_"))
        result = analyze_api_spec("test_specs/petstore3_openapi.json", out)

        html = build_spec_report(result)

        self.assertEqual(result["returncode"], 0)
        self.assertIn("Endpoint Inventory", html)
        self.assertIn("Notable Endpoints", html)
        self.assertGreater(html.count("<tr>"),
                           result["summary"]["endpoint_count"])


if __name__ == "__main__":
    unittest.main()
