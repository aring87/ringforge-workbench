"""The redaction that runs before an API exchange is written to a file.

39 lines of regular expressions inside `gui/api_window.py` -- the security
control in the one screen that routinely holds live bearer tokens, cookies and
API keys, and no test could reach it without a display. Sixth module through
this pass.

**The defect it was part of was the ordering, not the patterns.**
`save_html_report` redacted the response headers and body *in place* and then
handed those same variables to `analyze_response`, so the findings were
computed from text with the values already gone. Ticking the redact box changed
the security result in both directions, and the window's own analysis pane --
which reads the unredacted text -- disagreed with the file it had just written.

The patterns themselves moved unchanged and are pinned below, including the
parts that are arguably wrong: `Authorization: Bearer x` loses the scheme along
with the token. Changing that would be a change, not a fix.
"""

import unittest

from static_triage_engine.api_redaction import (
    MARKER,
    count_markers,
    redact,
    redact_fields,
    redact_findings,
)
from static_triage_engine.api_response_analysis import analyze_response

HEADERS = ("Content-Type: application/json\n"
           "Set-Cookie: sid=abc123; Path=/; HttpOnly; Secure; SameSite=Strict\n"
           "Authorization: Bearer eyJhbGciOi.payload.sig")
BODY = '{"ok": true, "access_token": "eyJhbGciOi.payload.sig"}'


class RedactionMustNotChangeTheFindings(unittest.TestCase):
    """The defect the extraction was for.

    Redaction is a presentation step. It ran before the analysis, so the
    analysis saw `[REDACTED]` where the evidence had been.
    """

    def _analyse(self, headers, body):
        return analyze_response(method="GET", url="https://api.example.test/t",
                                status="200 OK", response_headers=headers,
                                body=body)

    def test_a_well_configured_cookie_is_not_reported_as_misconfigured(self) -> None:
        """`Set-Cookie: sid=x; HttpOnly; Secure; SameSite=Strict` became
        `Set-Cookie: [REDACTED]`, so the flags went with the value and the
        engine reported all three missing. A finding about nothing."""
        real = self._analyse(HEADERS, BODY)
        after_redaction = self._analyse(redact(HEADERS), redact(BODY))

        real_cookie = next(f for f in real["findings"]
                           if "Set-Cookie" in f["message"])
        redacted_cookie = next(f for f in after_redaction["findings"]
                               if "Set-Cookie" in f["message"])

        self.assertEqual(real_cookie["severity"], "Info")
        self.assertIn("with HttpOnly, Secure and SameSite set",
                      real_cookie["message"])
        # The wrong answer, kept as the reason this ordering matters.
        self.assertEqual(redacted_cookie["severity"], "Medium")

    def test_a_leaked_credential_is_not_hidden_by_redacting_it(self) -> None:
        """The High finding disappeared -- suppressed by the act of preparing
        the report that was supposed to warn about it."""
        real = self._analyse(HEADERS, BODY)
        after_redaction = self._analyse(redact(HEADERS), redact(BODY))

        self.assertEqual(real["counts"]["High"], 1)
        self.assertEqual(after_redaction["counts"]["High"], 0)

    def test_the_banner_band_flips(self) -> None:
        """Not a detail in a table -- the headline verdict of the page."""
        from static_triage_engine.api_report import verdict_for

        real, _ = verdict_for(self._analyse(HEADERS, BODY)["counts"], "200 OK")
        wrong, _ = verdict_for(
            self._analyse(redact(HEADERS), redact(BODY))["counts"], "200 OK")

        self.assertTrue(real.startswith("High"))
        self.assertTrue(wrong.startswith("Medium"))


class ThePatterns(unittest.TestCase):
    """Moved unchanged. These pin what they do, warts included."""

    def test_a_bearer_header_loses_the_scheme_with_the_token(self) -> None:
        """Arguably wrong -- knowing an endpoint uses Bearer is not a
        disclosure -- and deliberately unchanged. Pinned so a future change is
        a decision rather than a side effect."""
        self.assertEqual(redact("Authorization: Bearer abc.def"),
                         f"Authorization: {MARKER}")

    def test_basic_and_unknown_schemes_go_too(self) -> None:
        self.assertEqual(redact("Authorization: Basic dXNlcjpwYXNz"),
                         f"Authorization: {MARKER}")
        self.assertEqual(redact("authorization: Token xyz"),
                         f"authorization: {MARKER}")

    def test_cookies_in_both_directions(self) -> None:
        self.assertEqual(redact("Cookie: sid=1"), f"Cookie: {MARKER}")
        self.assertEqual(redact("Set-Cookie: sid=1; HttpOnly"),
                         f"Set-Cookie: {MARKER}")

    def test_json_secrets_double_and_single_quoted(self) -> None:
        self.assertIn(MARKER, redact('{"password": "hunter2"}'))
        self.assertIn(MARKER, redact("{'client_secret': 'shhh'}"))
        self.assertNotIn("hunter2", redact('{"password": "hunter2"}'))

    def test_the_field_name_survives_so_the_finding_still_makes_sense(self) -> None:
        self.assertIn("access_token",
                      redact('{"access_token": "eyJ.abc"}'))

    def test_form_and_query_secrets(self) -> None:
        out = redact("grant_type=password&password=hunter2&x=1")

        self.assertNotIn("hunter2", out)
        self.assertIn("x=1", out)

    def test_a_loose_bearer_token_in_a_body(self) -> None:
        self.assertEqual(redact("sent Bearer AAA.BBB-CCC along"),
                         f"sent Bearer {MARKER} along")

    def test_reflected_caller_identity(self) -> None:
        """Not a credential, but it is the analyst's own address in a file
        they may share."""
        self.assertNotIn("1.2.3.4", redact('{"origin": "1.2.3.4"}'))
        self.assertNotIn("8.8.8.8", redact("X-Forwarded-For: 8.8.8.8"))
        self.assertNotIn("9.9.9.9", redact("X-Real-IP: 9.9.9.9"))

    def test_header_rules_are_anchored_to_a_line(self) -> None:
        """A body mentioning the word `cookie` must not trip a header rule."""
        text = "the response explains that Cookie: handling is up to you"

        self.assertEqual(redact(text), text)

    def test_ordinary_text_is_untouched(self) -> None:
        self.assertEqual(redact("nothing sensitive here"),
                         "nothing sensitive here")

    def test_none_and_empty_answer_with_a_string(self) -> None:
        self.assertEqual(redact(None), "")
        self.assertEqual(redact(""), "")

    def test_it_is_idempotent(self) -> None:
        """Running twice must not multiply the markers, or the count is wrong."""
        once = redact(HEADERS + "\n" + BODY)

        self.assertEqual(redact(once), once)


class TheCount(unittest.TestCase):
    """"Redaction was on" and "redaction removed nothing" are different facts."""

    def test_it_counts_values_replaced(self) -> None:
        _, count = redact_fields({"headers": HEADERS, "body": BODY})

        self.assertEqual(count, 3)  # Set-Cookie, Authorization, access_token

    def test_a_clean_exchange_counts_zero(self) -> None:
        fields, count = redact_fields({"headers": "Content-Type: text/plain",
                                       "body": "hello"})

        self.assertEqual(count, 0)
        self.assertEqual(fields["body"], "hello")

    def test_a_response_that_already_says_redacted_is_not_counted(self) -> None:
        """Otherwise a server echoing the word inflates the number the page
        prints, which is the one number the reader is trusting."""
        _, count = redact_fields({"body": f"the value was {MARKER} already"})

        self.assertEqual(count, 0)

    def test_the_marker_counter_spans_every_field(self) -> None:
        self.assertEqual(count_markers(MARKER, "x", f"{MARKER}{MARKER}"), 3)

    def test_every_field_comes_back(self) -> None:
        fields, _ = redact_fields({"a": "x", "b": None, "c": 7})

        self.assertEqual(set(fields), {"a", "b", "c"})
        self.assertEqual(fields["b"], "")
        self.assertEqual(fields["c"], "7")


class TheFindingText(unittest.TestCase):
    def test_findings_pass_through_the_same_rules(self) -> None:
        """No finding written today quotes a secret. This holds the control in
        place for the one somebody adds later."""
        cleaned = redact_findings([
            {"severity": "High", "message": "leaked Bearer abc.def here"}])

        self.assertEqual(cleaned[0]["message"], f"leaked Bearer {MARKER} here")
        self.assertEqual(cleaned[0]["severity"], "High")

    def test_the_messages_written_today_are_unchanged_by_it(self) -> None:
        real = analyze_response(method="GET", url="https://x/t",
                                status="200 OK", response_headers=HEADERS,
                                body=BODY)

        self.assertEqual([f["message"] for f in redact_findings(real["findings"])],
                         [f["message"] for f in real["findings"]])

    def test_an_empty_list_is_answered_not_raised(self) -> None:
        self.assertEqual(redact_findings([]), [])
        self.assertEqual(redact_findings(None), [])


if __name__ == "__main__":
    unittest.main()
