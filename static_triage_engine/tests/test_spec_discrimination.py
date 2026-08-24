"""An API specification review has to separate these, and `score_spec` could not.

Phase 3a of `docs/SCORING.md`. `score_spec` was 84 lines with **zero** tests,
and reading it with the question Phase 2 was built on -- *what claim is this,
and does it stand alone* -- turned up three defects of the same shape as the
static ones.

The contract:

    an authenticated, TLS-only spec           no category      Low
    a public API with no auth                 one category     Needs Review
    admin routes reachable with no auth       one, strong      Elevated Attention
    an empty or unparseable spec              unknown, not a finding
"""

import unittest

from static_triage_engine.categories import spec_categories
from verdict import band


def _named(cats, name):
    return next(c for c in cats if c.name == name)


def _verdict(spec):
    cats, context = spec_categories(spec)
    return band(cats, context_score=context), cats


def _endpoint(path="/v1/things", admin=False, destructive=False, upload=False):
    return {
        "path": path,
        "method": "DELETE" if destructive else "GET",
        "admin_like_route": admin,
        "destructive_method": destructive,
        "parameters": ([{"in": "body:multipart/form-data", "name": "file"}]
                       if upload else []),
    }


def _authenticated_spec():
    """An ordinary, well-built API: auth declared, TLS only."""
    return {
        "returncode": 0,
        "error": "",
        "servers": ["https://api.example.com/v1"],
        "endpoints": [_endpoint(), _endpoint("/v1/admin/users", admin=True,
                                             destructive=True)],
        "auth_summary": ["bearer"],
        "security_schemes": [{"type": "http", "scheme": "bearer"}],
        "summary": {"endpoint_count": 2, "auth_scheme_count": 1},
    }


class AnUnparseableSpecIsNotAFinding(unittest.TestCase):
    """The largest defect in the old scorer, and the quietest.

    `no_auth` was `auth_scheme_count == 0`, which is true of an empty dict, a
    spec that failed to parse, and a file that was never a spec at all. Each of
    those scored 10 of a 30-point ceiling for "no authentication scheme
    detected" -- missing data read as a finding.
    """

    def test_no_spec_at_all_is_unknown(self) -> None:
        result, _ = _verdict(None)

        self.assertEqual(result.severity, "Unknown")
        self.assertEqual(result.verdict, "Insufficient Coverage")

    def test_a_spec_that_failed_to_parse_is_unknown(self) -> None:
        result, cats = _verdict({"returncode": 1,
                                 "error": "Spec root must be an object"})

        self.assertEqual(result.verdict, "Insufficient Coverage")
        self.assertFalse(_named(cats, "unauthenticated_sensitive_endpoint").collected)

    def test_an_empty_spec_reaches_no_category(self) -> None:
        # It ran, and it described nothing. That is coverage, not evidence.
        result, cats = _verdict({})

        self.assertEqual(result.categories_present, 0)
        self.assertFalse(_named(cats, "unauthenticated_sensitive_endpoint").present)

    def test_a_spec_with_no_endpoints_cannot_be_unauthenticated(self) -> None:
        # There is nothing to authenticate.
        result, _ = _verdict({"returncode": 0, "endpoints": [],
                              "summary": {"endpoint_count": 0}})

        self.assertEqual(result.categories_present, 0)


class AWellBuiltApiIsNotSuspicious(unittest.TestCase):
    def test_it_reaches_no_category(self) -> None:
        result, _ = _verdict(_authenticated_spec())

        self.assertEqual(result.categories_present, 0)
        self.assertEqual(result.severity, "Low")

    def test_a_destructive_admin_route_is_not_a_finding_when_authenticated(self) -> None:
        # DELETE /admin/users/{id} is how a correct admin API is built.
        _, cats = _verdict(_authenticated_spec())

        self.assertFalse(_named(cats, "destructive_admin_surface").present)

    def test_a_large_api_cannot_be_scored_into_a_band(self) -> None:
        spec = _authenticated_spec()
        spec["endpoints"] = [_endpoint(f"/v1/thing{n}") for n in range(400)]
        spec["summary"] = {"endpoint_count": 400, "auth_scheme_count": 1}
        result, _ = _verdict(spec)

        self.assertEqual(result.severity, "Low")
        self.assertLessEqual(result.context_score, 15)


class OneClaimNotTwo(unittest.TestCase):
    """`no_auth` and `sensitive_unauth` were the same claim charged twice.

    `sensitive_unauth` required `auth_scheme_count == 0`, which is one of the
    conditions that made `no_auth` true -- so an unauthenticated admin route
    scored on both, up to 18 of a 30-point ceiling.
    """

    def test_an_unauthenticated_api_is_one_category(self) -> None:
        spec = _authenticated_spec()
        spec.update(auth_summary=[], security_schemes=[],
                    endpoints=[_endpoint()],
                    summary={"endpoint_count": 1, "auth_scheme_count": 0})
        result, cats = _verdict(spec)

        self.assertEqual(result.categories_present, 1)
        self.assertTrue(_named(cats, "unauthenticated_sensitive_endpoint").present)

    def test_a_public_read_only_api_does_not_stand_alone(self) -> None:
        # Plenty of legitimate services publish an unauthenticated read API.
        spec = _authenticated_spec()
        spec.update(auth_summary=[], security_schemes=[],
                    endpoints=[_endpoint()],
                    summary={"endpoint_count": 1, "auth_scheme_count": 0})
        result, cats = _verdict(spec)

        self.assertFalse(_named(cats, "unauthenticated_sensitive_endpoint").strong)
        self.assertEqual(result.verdict, "Needs Review")

    def test_unauthenticated_admin_routes_are_the_strong_form(self) -> None:
        # The finding that matters, and it is the same category emphatic --
        # not a second one agreeing with itself.
        spec = _authenticated_spec()
        spec.update(auth_summary=[], security_schemes=[],
                    endpoints=[_endpoint("/v1/admin/users", admin=True,
                                         destructive=True)],
                    summary={"endpoint_count": 1, "auth_scheme_count": 0})
        result, cats = _verdict(spec)

        category = _named(cats, "unauthenticated_sensitive_endpoint")
        self.assertTrue(category.strong)
        self.assertEqual(result.verdict, "Elevated Attention")


class DestructiveSurfaceIsAboutTheExemption(unittest.TestCase):
    """The finding is a scheme with holes in it, not the existence of a DELETE.

    Scoping it this way also keeps it independent of the category above. If
    both could fire on one spec, an API with no authentication would corroborate
    itself -- two categories agreeing about a single fact.
    """

    def test_a_route_exempt_from_the_declared_scheme_is_a_category(self) -> None:
        spec = _authenticated_spec()
        exempt = _endpoint("/v1/admin/purge", admin=True, destructive=True)
        exempt["auth_required"] = False
        spec["endpoints"] = [_endpoint(), exempt]
        _, cats = _verdict(spec)

        self.assertTrue(_named(cats, "destructive_admin_surface").present)

    def test_a_fully_unauthenticated_api_does_not_also_fire_it(self) -> None:
        # Already covered by unauthenticated_sensitive_endpoint. Firing here as
        # well would manufacture corroboration out of one fact.
        spec = _authenticated_spec()
        spec.update(auth_summary=[], security_schemes=[],
                    summary={"endpoint_count": 2, "auth_scheme_count": 0})
        result, cats = _verdict(spec)

        self.assertFalse(_named(cats, "destructive_admin_surface").present)
        self.assertEqual(result.categories_present, 1)

    def test_it_is_never_emphatic(self) -> None:
        # A route can be exempt for legitimate reasons -- a health check, an
        # internal callback -- and the spec does not record which.
        spec = _authenticated_spec()
        exempt = _endpoint("/v1/admin/purge", admin=True, destructive=True)
        exempt["auth_required"] = False
        spec["endpoints"] = [exempt]
        _, cats = _verdict(spec)

        self.assertFalse(_named(cats, "destructive_admin_surface").strong)


class PlaintextTransport(unittest.TestCase):
    def test_a_public_http_server_is_a_category(self) -> None:
        spec = _authenticated_spec()
        spec["servers"] = ["http://api.example.com/v1"]
        _, cats = _verdict(spec)

        self.assertTrue(_named(cats, "plaintext_transport").present)

    def test_a_localhost_server_is_not(self) -> None:
        # A spec listing http://localhost:8080 describes a development server,
        # not an unencrypted service. The old scorer charged 6 points for it.
        spec = _authenticated_spec()
        spec["servers"] = ["http://localhost:8080"]
        _, cats = _verdict(spec)

        self.assertFalse(_named(cats, "plaintext_transport").present)

    def test_private_network_addresses_are_not_either(self) -> None:
        for host in ("http://10.0.0.5/api", "http://192.168.1.10",
                     "http://172.20.3.4:8080", "http://gateway.internal"):
            with self.subTest(host=host):
                spec = _authenticated_spec()
                spec["servers"] = [host]
                _, cats = _verdict(spec)

                self.assertFalse(_named(cats, "plaintext_transport").present)

    def test_it_never_stands_alone(self) -> None:
        spec = _authenticated_spec()
        spec["servers"] = ["http://api.example.com/v1"]
        result, _ = _verdict(spec)

        self.assertEqual(result.verdict, "Needs Review")


class UnrestrictedUpload(unittest.TestCase):
    def test_a_multipart_endpoint_is_a_category(self) -> None:
        spec = _authenticated_spec()
        spec["endpoints"] = [_endpoint("/v1/files", upload=True)]
        _, cats = _verdict(spec)

        self.assertTrue(_named(cats, "unrestricted_upload").present)

    def test_accepting_files_is_a_feature_not_a_verdict(self) -> None:
        spec = _authenticated_spec()
        spec["endpoints"] = [_endpoint("/v1/files", upload=True)]
        _, cats = _verdict(spec)

        self.assertFalse(_named(cats, "unrestricted_upload").strong)


class TheBandsSeparateTheReferenceSpecs(unittest.TestCase):
    def test_authenticated_and_tls_only_is_low(self) -> None:
        result, _ = _verdict(_authenticated_spec())

        self.assertEqual(result.severity, "Low")

    def test_the_worst_case_is_likely_malicious(self) -> None:
        # No auth on admin routes, destructive methods, uploads, plaintext.
        spec = {
            "returncode": 0,
            "servers": ["http://api.example.com"],
            "endpoints": [
                _endpoint("/v1/admin/users", admin=True, destructive=True),
                _endpoint("/v1/upload", upload=True),
            ],
            "auth_summary": [],
            "security_schemes": [],
            "summary": {"endpoint_count": 2, "auth_scheme_count": 0},
        }
        result, _ = _verdict(spec)

        # Three, not four: destructive_admin_surface deliberately stays silent
        # when nothing is authenticated, because the first category already
        # says so.
        self.assertEqual(result.categories_present, 3)
        self.assertEqual(result.verdict, "Likely Malicious")


if __name__ == "__main__":
    unittest.main()
