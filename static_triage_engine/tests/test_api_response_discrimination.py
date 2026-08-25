"""A response analyser has to tell a login endpoint from a leaked token.

Phase 3b of `docs/SCORING.md`, api half, and the first test this analysis has
had -- it lived inside `gui/api_window.py` and returned a block of text, so
nothing could reach it and nothing else could read it.

**Its only High finding fired on every endpoint that sets a cookie.** The
sensitive-value list held `set-cookie`, `authorization` and `bearer ` and
matched them as substrings against headers and body alike. Every login endpoint
returns `Set-Cookie`; so does every session refresh. The finding that should
matter most was the one that fired regardless of what happened.
"""

import unittest

from static_triage_engine.api_response_analysis import (
    analyze_response,
    api_categories,
)
from verdict import band as _band


def band(cats, **kw):
    """`api` is held context-only by decision, and these test the categoriser.

    See `verdict.CONTEXT_ONLY`. The hold is about whether the module has been
    measured against a population, which is a different question from whether
    its categories say the right thing.
    """
    kw.setdefault("context_only", {})
    return _band(cats, **kw)


def _codes(result):
    return {f["code"]: f["severity"] for f in result["findings"]}


class ACookieIsNotADisclosure(unittest.TestCase):
    """The false positive that made the High severity meaningless."""

    def test_a_login_endpoint_setting_a_well_formed_cookie_is_not_high(self) -> None:
        result = analyze_response(
            url="https://api.example.com/login", status=200,
            response_headers={"Set-Cookie": "sid=abc; HttpOnly; Secure; SameSite=Lax"},
            body='{"ok": true}')

        self.assertEqual(_codes(result)["set_cookie"], "Info")
        self.assertEqual(result["counts"]["High"], 0)

    def test_a_cookie_without_its_flags_is_worth_saying(self) -> None:
        # The finding that was buried: not that a cookie exists, but that it
        # is reachable from script and will travel over cleartext.
        result = analyze_response(
            url="https://api.example.com/login", status=200,
            response_headers={"Set-Cookie": "sid=abc"}, body='{"ok": true}')

        self.assertEqual(_codes(result)["set_cookie"], "Medium")

    def test_a_body_mentioning_authorization_is_not_a_leak(self) -> None:
        # An endpoint returning its own API documentation used to trip the
        # credential check on the word alone.
        result = analyze_response(
            url="https://api.example.com/docs", status=200,
            response_headers={}, body='{"auth": "send an authorization header, bearer style"}')

        self.assertNotIn("credential_in_body", _codes(result))


class ProseIsNotAStackTrace(unittest.TestCase):
    def test_a_debug_field_is_not_leaked_internals(self) -> None:
        # `debug` was on the verbose-error list and matched any JSON with a
        # `debug` field; `line ` matched most English.
        result = analyze_response(
            url="https://api.example.com/status", status=200,
            response_headers={},
            body='{"debug": false, "message": "queued on line 3 of the batch"}')

        self.assertNotIn("verbose_error", _codes(result))

    def test_a_real_traceback_is(self) -> None:
        result = analyze_response(
            url="https://api.example.com/thing", status=500,
            response_headers={},
            body="Traceback (most recent call last):\\n  File ...")

        self.assertEqual(_codes(result)["verbose_error"], "Medium")


class ACredentialIsAValueNotAWord(unittest.TestCase):
    def test_a_token_in_the_body_is_high(self) -> None:
        result = analyze_response(
            url="https://api.example.com/token", status=200,
            response_headers={},
            body='{"access_token": "eyJhbGciOiJIUzI1NiJ9.abcdefghij"}')

        self.assertEqual(_codes(result)["credential_in_body"], "High")

    def test_a_field_name_with_no_value_is_not(self) -> None:
        result = analyze_response(
            url="https://api.example.com/schema", status=200,
            response_headers={}, body='{"fields": ["access_token", "api_key"]}')

        self.assertNotIn("credential_in_body", _codes(result))

    def test_a_documentation_url_is_not_a_password(self) -> None:
        result = analyze_response(
            url="https://api.example.com/help", status=200, response_headers={},
            body='{"password_policy_url": "https://example.com/policy"}')

        self.assertNotIn("credential_in_body", _codes(result))


class SharingRules(unittest.TestCase):
    def test_a_wildcard_origin_alone_is_low(self) -> None:
        result = analyze_response(
            url="https://api.example.com/public", status=200,
            response_headers={"Access-Control-Allow-Origin": "*"}, body="{}")

        self.assertEqual(_codes(result)["wildcard_cors"], "Low")

    def test_a_wildcard_origin_with_credentials_is_medium(self) -> None:
        # A combination browsers refuse outright, which means whoever set it
        # was not testing what they thought they were.
        result = analyze_response(
            url="https://api.example.com/public", status=200,
            response_headers={"Access-Control-Allow-Origin": "*",
                              "Access-Control-Allow-Credentials": "true"},
            body="{}")

        self.assertEqual(_codes(result)["wildcard_cors"], "Medium")


class HeadersParseEitherWay(unittest.TestCase):
    def test_a_raw_header_block_works_like_a_mapping(self) -> None:
        # The window hands over the response headers as text.
        as_text = analyze_response(
            url="https://api.example.com/x", status=200,
            response_headers="Server: nginx/1.18.0\\nContent-Type: application/json",
            body="{}")
        as_map = analyze_response(
            url="https://api.example.com/x", status=200,
            response_headers={"Server": "nginx/1.18.0",
                              "Content-Type": "application/json"},
            body="{}")

        self.assertEqual(_codes(as_text), _codes(as_map))


class TheCategories(unittest.TestCase):
    def test_no_request_sent_is_not_a_clean_result(self) -> None:
        cats, context = api_categories(None)
        result = band(cats, context_score=context)

        self.assertEqual(result.verdict, "Insufficient Coverage")

    def test_a_clean_response_reaches_no_category(self) -> None:
        analysis = analyze_response(
            url="https://api.example.com/health", status=200,
            response_headers={}, body='{"ok": true}')
        cats, context = api_categories(analysis)

        self.assertEqual(band(cats, context_score=context).categories_present, 0)

    def test_a_leaked_token_stands_alone(self) -> None:
        analysis = analyze_response(
            url="https://api.example.com/token", status=200, response_headers={},
            body='{"access_token": "eyJhbGciOiJIUzI1NiJ9.abcdefghij"}')
        cats, context = api_categories(analysis)
        result = band(cats, context_score=context)

        self.assertEqual(result.categories_strong, 1)
        self.assertEqual(result.severity, "High")

    def test_a_server_banner_never_stands_alone(self) -> None:
        # A `Server:` header is a default, not a decision.
        analysis = analyze_response(
            url="https://api.example.com/x", status=200,
            response_headers={"Server": "nginx/1.18.0"}, body="{}")
        cats, context = api_categories(analysis)
        result = band(cats, context_score=context)

        self.assertEqual(result.verdict, "Needs Review")
        self.assertEqual(result.categories_strong, 0)


if __name__ == "__main__":
    unittest.main()
