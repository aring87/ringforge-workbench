"""The Manual API Tester's report, which could not be tested until it moved.

It lived inline in `gui/api_window.py`, so exercising it needed a display and
nobody did. That is how it drifted: it hand-rolled its own page shell instead of
calling `report_page`, and it flattened `analyze_response`'s structured findings
into a `<pre>` of plain text — the one module whose purpose is scoring a
response was the only one that could not show a severity.

These pin the parts that carry a claim: that an unredacted export announces
itself, that redaction reports what it actually removed, that findings keep
their severities and their order, and that "no findings" is never allowed to
read as a clearance.
"""

import unittest

from dynamic_analysis.report_theme import report_page
from static_triage_engine.api_report import build_api_report, verdict_for


def _report(**over):
    base = dict(
        method="GET", url="https://api.example.test/v1/thing",
        status="200 OK", elapsed="12 ms", content_type="application/json",
        size="410 B", request_headers="Accept: application/json",
        request_body="", response_headers="Server: nginx",
        response_body='{"ok":true}', response_raw="HTTP/1.1 200 OK",
        analysis={"findings": [], "counts": {}}, redacted=True, redactions=0,
    )
    base.update(over)
    return build_api_report(**base)


class Redaction(unittest.TestCase):
    """The most important fact about a page that may hold credentials."""

    def test_an_unredacted_export_announces_itself(self) -> None:
        html = _report(redacted=False, redactions=None)

        self.assertIn("card-alert", html)
        self.assertIn("Unredacted", html)
        self.assertIn("may contain bearer", html)

    def test_a_redacted_export_says_how_many_values_went(self) -> None:
        """"Redaction was on" and "redaction removed nothing" are different
        facts, and the reader deciding how to handle the file needs the second.

        Asserted on the *element*, not on the string `card-alert`: that string
        is in the embedded stylesheet of every page, so the obvious negative
        assertion could never have failed.
        """
        html = _report(redacted=True, redactions=4)

        self.assertIn("4 value(s) were replaced", html)
        self.assertNotIn('<section class="card card-alert">', html)

    def test_only_the_unredacted_page_grows_the_alert_element(self) -> None:
        self.assertIn('<section class="card card-alert">',
                      _report(redacted=False, redactions=None))

    def test_redaction_is_not_claimed_to_be_a_guarantee(self) -> None:
        html = _report(redacted=True, redactions=1)

        self.assertIn("pattern-based", html)

    def test_an_unknown_count_still_renders(self) -> None:
        html = _report(redacted=True, redactions=None)

        self.assertIn("Redaction", html)
        self.assertNotIn("value(s) were replaced", html)


class Findings(unittest.TestCase):
    ANALYSIS = {
        "findings": [
            {"severity": "Low", "message": "framework disclosed"},
            {"severity": "High", "message": "stack trace in body"},
            {"severity": "Medium", "message": "no HSTS"},
        ],
        "counts": {"High": 1, "Medium": 1, "Low": 1, "Info": 0},
    }

    def test_findings_are_ordered_worst_first(self) -> None:
        html = _report(analysis=self.ANALYSIS)
        positions = [html.index(m) for m in
                     ("stack trace in body", "no HSTS", "framework disclosed")]

        self.assertEqual(positions, sorted(positions))

    def test_each_finding_carries_its_severity_class(self) -> None:
        """The severities existed all along and the old report threw them away."""
        html = _report(analysis=self.ANALYSIS)

        self.assertIn("sev-high", html)
        self.assertIn("sev-med", html)
        self.assertIn("sev-low", html)

    def test_the_heuristic_caveat_survives_the_restyling(self) -> None:
        html = _report(analysis=self.ANALYSIS)

        self.assertIn("heuristic indicators", html)

    def test_no_findings_is_not_a_clearance(self) -> None:
        html = _report(analysis={"findings": [], "counts": {}})

        self.assertIn("not a clearance", html)

    def test_a_missing_analysis_still_produces_a_page(self) -> None:
        """The window falls back to an empty result when analysis raises. A
        report that renders is worth more than no report."""
        html = _report(analysis=None)

        self.assertIn("Manual API Test Report", html)
        self.assertIn("not a clearance", html)


class Verdict(unittest.TestCase):
    def test_the_worst_band_present_wins(self) -> None:
        text, css = verdict_for({"High": 1, "Low": 5})

        self.assertIn("High", text)
        self.assertIn("6 finding(s)", text)
        self.assertEqual(css, "sev-high")

    def test_info_only_is_still_reported_as_findings(self) -> None:
        text, _ = verdict_for({"Info": 2})

        self.assertIn("Info", text)

    def test_nothing_found_says_so(self) -> None:
        text, css = verdict_for({})

        self.assertEqual(text, "No findings")
        self.assertEqual(css, "sev-none")


class Rendering(unittest.TestCase):
    def test_a_malformed_header_is_kept_not_dropped(self) -> None:
        """Discarding it to keep the table tidy would hide a finding."""
        html = _report(response_headers="Server: nginx\nthis-has-no-colon")

        self.assertIn("malformed", html)
        self.assertIn("this-has-no-colon", html)

    def test_a_hostile_response_body_cannot_inject_markup(self) -> None:
        html = _report(response_body="<script>alert(1)</script>")

        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_the_status_family_is_visible_at_a_glance(self) -> None:
        """A 500 and a 200 are not the same event."""
        self.assertIn("sev-high", _report(status="500 Server Error"))
        self.assertIn("sev-med", _report(status="404 Not Found"))

    def test_empty_sections_say_what_is_empty(self) -> None:
        html = _report(request_body="", response_body="", response_raw="")

        self.assertIn("No request body was sent", html)
        self.assertIn("The response had no body", html)

    def test_it_names_the_module_that_produced_it(self) -> None:
        self.assertIn("Manual API Tester", _report())


class ARequestThatNeverCompleted(unittest.TestCase):
    """A connection that was refused is not a clean test.

    The window sets the status to `Error` when the request produced no HTTP
    response and puts the client's exception where the body goes. The checks
    then ran over that exception text, found nothing in it, and the page came
    out `Info &middot; 1 finding(s)` in `sev-none` -- the banner and the chip a
    clean `200` gets. Every count on it was zero because nothing was received,
    not because nothing was found.
    """

    def _failed(self):
        return _report(
            status="Error", elapsed="—", content_type="—", size="—",
            response_headers="", response_body="ConnectionError: refused",
            response_raw="ConnectionError: refused",
            analysis={"findings": [{"severity": "Info",
                                    "message": "No response findings generated."}],
                      "counts": {"Info": 1}})

    def test_the_banner_does_not_report_a_finding_count(self) -> None:
        self.assertIn('<div class="verdict sev-med">No response received</div>',
                      self._failed())

    def test_the_status_chip_is_not_the_clean_one(self) -> None:
        self.assertIn('<span class="badge sev-med">Status: Error</span>',
                      self._failed())

    def test_the_page_says_so_above_its_zeros(self) -> None:
        html = self._failed()

        self.assertIn('<section class="card card-alert">', html)
        self.assertIn("No response was received", html)
        self.assertIn("Nothing below describes the endpoint", html)

    def test_the_findings_section_says_none_were_run(self) -> None:
        """Not "no findings" -- there was nothing to check."""
        html = self._failed()

        self.assertIn("None were run. There was no response to check.", html)

    def test_verdict_for_ignores_the_counts_when_there_was_no_response(self) -> None:
        self.assertEqual(verdict_for({"High": 3}, "Error"),
                         ("No response received", "sev-med"))

    def test_a_real_response_is_unaffected(self) -> None:
        html = _report()

        self.assertNotIn("No response was received", html)
        self.assertIn('<div class="verdict sev-none">No findings</div>', html)

    def test_every_status_family_still_reads(self) -> None:
        for status, expected in (("200 OK", "sev-none"), ("301", "sev-low"),
                                 ("404 Not Found", "sev-med"),
                                 ("500 Internal Server Error", "sev-high")):
            with self.subTest(status=status):
                self.assertIn(f'<span class="badge {expected}">Status: {status}',
                              _report(status=status))

    def test_an_empty_status_counts_as_no_response(self) -> None:
        """A saved page with the status field blank cannot claim a clean test
        either."""
        self.assertEqual(verdict_for({}, "")[0], "No response received")


class TheSharedPageShell(unittest.TestCase):
    """`report_page` gained an optional verdict so reports need not invent one."""

    def test_a_verdict_renders_when_given(self) -> None:
        html = report_page("T", "S", "Likely Malicious", "sev-high", "<p>b</p>")

        self.assertIn('class="verdict sev-high"', html)
        self.assertIn("Likely Malicious", html)

    def test_no_verdict_omits_the_element_rather_than_showing_an_empty_one(self) -> None:
        html = report_page("T", "S", body_html="<p>b</p>")

        self.assertNotIn('class="verdict', html)
        self.assertIn("<p>b</p>", html)

    def test_the_footer_can_name_its_producing_module(self) -> None:
        html = report_page("T", "S", body_html="", footer_note="Module X")

        self.assertIn("Module X", html)
        self.assertIn("Generated:", html)


if __name__ == "__main__":
    unittest.main()
