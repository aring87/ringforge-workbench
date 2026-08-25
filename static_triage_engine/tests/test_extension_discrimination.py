"""An extension analyser has to tell a jQuery bundle from a session stealer.

Phase 3b of `docs/SCORING.md`, and the first test this analysis has ever had --
it lived inside a 1,743-line Tkinter `Toplevel`, so there was nothing importable
to reach.

**The scorer it replaces was saturated.** It summed weighted permissions,
manifest features and source-pattern hits toward 100 and called 80 `Critical`,
and the source scan added its points once per *file*. `fetch(` was worth 5 in
every file containing it, `https://` one, `XMLHttpRequest` five -- so an
extension shipping any minified vendor library reached the ceiling on ordinary
code. That is not a scorer with false positives; it is a scorer that returns the
same answer for everything, which is the same as having no verdict.

The contract:

    an ordinary extension with a vendor bundle    no category      Low
    broad host access alone                       one category     Needs Review
    content scripts on every site                 one, strong      Elevated
    cookies + every site + native messaging       several          Likely Malicious
    no manifest, no source tree                   unknown, not clean
"""

import json
import tempfile
import unittest
from pathlib import Path

from static_triage_engine.extension_analysis import (
    analyze_extension,
    extension_categories,
    scan_sources,
)
from verdict import band


def _named(cats, name):
    return next(c for c in cats if c.name == name)


def _verdict(manifest=None, sources=None):
    """Band the categories with the context-only hold lifted.

    `extension` is held context-only by decision -- see `verdict.CONTEXT_ONLY`
    -- so in production its categories are reported and never counted. That is a
    deployment decision about calibration, not a property of the categoriser,
    and these tests are about the categoriser. Passing `context_only={}` tests
    what the categories *say*; flipping the hold must not silently rewrite what
    this file asserts.
    """
    cats, context = extension_categories(manifest, sources)
    return band(cats, context_score=context, context_only={}), cats


def _tree(**files) -> Path:
    root = Path(tempfile.mkdtemp())
    for rel, body in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return root


def _ordinary_manifest():
    """What most of the store looks like."""
    return {
        "manifest_version": 3,
        "name": "Tab Tidier",
        "permissions": ["storage", "activeTab", "notifications"],
        "host_permissions": ["https://api.example.com/*"],
        "content_scripts": [{"matches": ["https://example.com/*"]}],
        "background": {"service_worker": "background.js"},
    }


class AVendorBundleIsNotAFinding(unittest.TestCase):
    """The bug that made the old analyser useless, pinned so it cannot return."""

    def test_a_pattern_fires_once_however_many_files_contain_it(self) -> None:
        root = _tree(**{
            f"vendor/lib{n}.js": "fetch( https:// XMLHttpRequest"
            for n in range(40)
        })
        found = scan_sources(root)

        # 40 files, one claim. The count is kept because it is worth reading --
        # it is just not worth scoring.
        self.assertEqual(found.get("cleartext"), None)
        self.assertNotIn("dynamic_code", found)

    def test_an_ordinary_extension_reaches_no_category(self) -> None:
        root = _tree(**{
            "vendor/jquery.min.js": "https://cdn.example.com fetch( XMLHttpRequest",
            "vendor/sentry.min.js": "https://sentry.example.com fetch(",
            "background.js": "chrome.tabs; fetch('https://api.example.com')",
            "content.js": "chrome.runtime.sendMessage({})",
            "popup/popup.js": "fetch('https://api.example.com')",
        })
        result = analyze_extension(root, _ordinary_manifest())

        self.assertEqual(result["counts"]["categories_present"], 0)
        self.assertEqual(result["severity"], "Low")

    def test_a_large_package_cannot_be_scored_into_a_band(self) -> None:
        root = _tree(**{f"vendor/lib{n}.js": "fetch( https://" for n in range(200)})
        manifest = _ordinary_manifest()
        manifest["permissions"] = ["storage"] * 1 + ["activeTab", "notifications"]
        result = analyze_extension(root, manifest)

        self.assertEqual(result["severity"], "Low")
        self.assertLessEqual(result["context_score"], 15)


class AccessToEverySite(unittest.TestCase):
    def test_broad_host_permission_is_a_category(self) -> None:
        manifest = _ordinary_manifest()
        manifest["host_permissions"] = ["<all_urls>"]
        result, cats = _verdict(manifest, {})

        self.assertTrue(_named(cats, "broad_host_access").present)
        self.assertEqual(result["verdict"] if isinstance(result, dict) else result.verdict,
                         "Needs Review")

    def test_it_is_not_emphatic_without_code_running_there(self) -> None:
        # A host permission is the right to make requests. That is not the same
        # as executing inside every page.
        manifest = _ordinary_manifest()
        manifest["host_permissions"] = ["<all_urls>"]
        _, cats = _verdict(manifest, {})

        self.assertFalse(_named(cats, "broad_host_access").strong)

    def test_content_scripts_on_every_site_are_still_not_emphatic(self) -> None:
        # **Measured, 25 Aug.** This asserted `strong` until a corpus of 14 real
        # installed extensions put the category at 57% present and 43%
        # emphatic. Access to every site is the price of admission for whole
        # legitimate categories -- blockers, password managers, translators --
        # and a claim that is emphatic on nearly half an ordinary population
        # cannot carry a band alone.
        manifest = _ordinary_manifest()
        manifest["content_scripts"] = [{"matches": ["<all_urls>"]}]
        result, cats = _verdict(manifest, {})

        category = _named(cats, "broad_host_access")
        self.assertTrue(category.present)
        self.assertFalse(category.strong)
        self.assertEqual(result.verdict, "Needs Review")

    def test_manifest_v2_host_patterns_in_permissions_are_found(self) -> None:
        # v2 puts host patterns in `permissions`; v3 separates them. Missing
        # that would make every v2 extension look narrowly scoped.
        manifest = {"manifest_version": 2, "permissions": ["<all_urls>", "storage"]}
        _, cats = _verdict(manifest, {})

        self.assertTrue(_named(cats, "broad_host_access").present)


class CapabilityTheBrowserReserves(unittest.TestCase):
    def test_two_reserved_permissions_together_are_emphatic(self) -> None:
        # Two of this set together stayed rare under measurement: one extension
        # in fourteen, holding `debugger` *and* `nativeMessaging`.
        manifest = _ordinary_manifest()
        manifest["permissions"] = ["debugger", "nativeMessaging"]
        _, cats = _verdict(manifest, {})

        self.assertTrue(_named(cats, "high_risk_permission").strong)

    def test_native_messaging_alone_is_not(self) -> None:
        # **Measured, 25 Aug.** It appeared alone in 3 of 14 ordinary
        # extensions -- password managers and PDF tools use it to reach a helper
        # binary -- so standing alone made it emphatic on a fifth of the
        # population.
        manifest = _ordinary_manifest()
        manifest["permissions"] = ["nativeMessaging"]
        _, cats = _verdict(manifest, {})

        category = _named(cats, "high_risk_permission")
        self.assertTrue(category.present)
        self.assertFalse(category.strong)

    def test_the_standard_content_blocking_apis_claim_nothing(self) -> None:
        # `declarativeNetRequest` is MV3's sanctioned replacement for
        # `webRequest`. Both were in the reserved set and put two ordinary ad
        # blockers at the top band.
        manifest = _ordinary_manifest()
        manifest["permissions"] = ["declarativeNetRequestWithHostAccess",
                                   "webRequestBlocking"]
        _, cats = _verdict(manifest, {})

        self.assertFalse(_named(cats, "high_risk_permission").present)

    def test_one_ordinary_elevated_permission_is_not_emphatic(self) -> None:
        manifest = _ordinary_manifest()
        manifest["permissions"] = ["storage", "management"]
        _, cats = _verdict(manifest, {})

        category = _named(cats, "high_risk_permission")
        self.assertTrue(category.present)
        self.assertFalse(category.strong)

    def test_storage_and_notifications_claim_nothing(self) -> None:
        # The old scorer charged 1, 2 and 3 points for storage, notifications
        # and activeTab -- a rounding error that still moved a saturating total,
        # on permissions every extension in the store requests.
        _, cats = _verdict(_ordinary_manifest(), {})

        self.assertFalse(_named(cats, "high_risk_permission").present)


class ReachIntoUserData(unittest.TestCase):
    def test_cookies_across_every_site_is_not_emphatic_by_itself(self) -> None:
        # **Measured, 25 Aug.** The `cookies` permission appears in 5 of 14
        # ordinary extensions and broad host access in 8. Cookie access across
        # every site is what a password manager does; combining two common
        # facts inside one category pre-empts the corroboration the model exists
        # to measure, and lets one category do the work of two.
        manifest = _ordinary_manifest()
        manifest["permissions"] = ["cookies"]
        manifest["host_permissions"] = ["<all_urls>"]
        _, cats = _verdict(manifest, {})

        category = _named(cats, "credential_surface")
        self.assertTrue(category.present)
        self.assertFalse(category.strong)

    def test_cookies_on_one_site_is_not(self) -> None:
        manifest = _ordinary_manifest()
        manifest["permissions"] = ["cookies"]
        _, cats = _verdict(manifest, {})

        category = _named(cats, "credential_surface")
        self.assertTrue(category.present)
        self.assertFalse(category.strong)

    def test_source_access_counts_even_without_the_permission(self) -> None:
        _, cats = _verdict(_ordinary_manifest(),
                           {"credential": {"patterns": ["document.cookie"],
                                           "files": ["content.js"], "file_count": 1}})

        self.assertTrue(_named(cats, "credential_surface").present)


class CodeBuiltWhileRunning(unittest.TestCase):
    def test_the_policy_decides_and_the_source_does_not(self) -> None:
        # **Measured, 25 Aug.** Scanning for `eval(` fired on 7 of 14 ordinary
        # extensions, because it appears in almost any minified vendor bundle.
        # Under Manifest V3 the default policy forbids `unsafe-eval` outright,
        # so that code *cannot execute* -- reporting it is reporting dead
        # branches in somebody else's library.
        manifest = _ordinary_manifest()
        _, cats = _verdict(manifest,
                           {"dynamic_code": {"patterns": ["eval("],
                                             "files": ["vendor/jquery.min.js"],
                                             "file_count": 1}})

        self.assertFalse(_named(cats, "dynamic_code_execution").present)

    def test_a_permissive_policy_is_the_claim(self) -> None:
        # A policy permitting runtime code is a decision the author made.
        manifest = _ordinary_manifest()
        manifest["content_security_policy"] = "script-src 'self' 'unsafe-eval'"
        _, cats = _verdict(manifest, {})

        category = _named(cats, "dynamic_code_execution")
        self.assertTrue(category.present)
        # Not emphatic: 3 of 14 ordinary extensions carried a permissive policy
        # with matching source calls.
        self.assertFalse(category.strong)


class ControlFromOutside(unittest.TestCase):
    def test_broad_externally_connectable_is_emphatic(self) -> None:
        manifest = _ordinary_manifest()
        manifest["externally_connectable"] = {"matches": ["*://*/*"]}
        _, cats = _verdict(manifest, {})

        self.assertTrue(_named(cats, "external_control_surface").strong)

    def test_a_scoped_externally_connectable_is_not(self) -> None:
        manifest = _ordinary_manifest()
        manifest["externally_connectable"] = {"matches": ["https://example.com/*"]}
        _, cats = _verdict(manifest, {})

        category = _named(cats, "external_control_surface")
        self.assertTrue(category.present)
        self.assertFalse(category.strong)


class WhatWasNotRead(unittest.TestCase):
    def test_no_manifest_and_no_sources_is_not_a_clean_result(self) -> None:
        result, _ = _verdict(None, None)

        self.assertEqual(result.severity, "Unknown")
        self.assertEqual(result.verdict, "Insufficient Coverage")

    def test_a_manifest_with_no_source_scan_reports_partial_coverage(self) -> None:
        result, _ = _verdict(_ordinary_manifest(), None)

        self.assertEqual(result.verdict, "No Findings, Coverage Incomplete")

    def test_an_unreadable_manifest_is_not_a_manifest_requesting_nothing(self) -> None:
        no_manifest, _ = _verdict(None, {})
        empty_manifest, _ = _verdict({}, {})

        self.assertGreater(no_manifest.categories_unknown,
                           empty_manifest.categories_unknown)


class TheBandsSeparateTheReferencePackages(unittest.TestCase):
    def test_a_session_stealer_is_likely_malicious(self) -> None:
        manifest = {
            "manifest_version": 3,
            "permissions": ["cookies", "debugger", "nativeMessaging", "tabs"],
            "host_permissions": ["<all_urls>"],
            "content_scripts": [{"matches": ["<all_urls>"]}],
            "externally_connectable": {"matches": ["*://*/*"]},
            "content_security_policy": "script-src 'self' 'unsafe-eval'",
        }
        sources = {
            "dynamic_code": {"patterns": ["eval("], "files": ["evil.js"], "file_count": 1},
            "credential": {"patterns": ["document.cookie"], "files": ["evil.js"], "file_count": 1},
            "native": {"patterns": ["chrome.runtime.connectNative"],
                       "files": ["evil.js"], "file_count": 1},
        }
        result, _ = _verdict(manifest, sources)

        # Still the top band, now on **count** rather than on four categories
        # each declaring itself emphatic. That is the intended shape: five
        # independent claims agreeing, not one claim asserting hard enough.
        self.assertEqual(result.verdict, "Likely Malicious")
        self.assertEqual(result.categories_present, 5)

    def test_the_ordinary_one_and_the_stealer_do_not_land_together(self) -> None:
        # The single thing the old model could not do: it called both Critical.
        ordinary, _ = _verdict(_ordinary_manifest(), {})
        stealer, _ = _verdict(
            {"permissions": ["cookies", "nativeMessaging"],
             "host_permissions": ["<all_urls>"],
             "content_scripts": [{"matches": ["<all_urls>"]}]}, {})

        self.assertNotEqual(ordinary.severity, stealer.severity)


class TheScannerReadsRealFiles(unittest.TestCase):
    def test_it_groups_patterns_by_the_claim_they_support(self) -> None:
        root = _tree(**{"a.js": "eval(x)", "b.js": "new Function(y)"})
        found = scan_sources(root)

        self.assertEqual(found["dynamic_code"]["file_count"], 2)
        self.assertEqual(sorted(found["dynamic_code"]["patterns"]),
                         ["eval(", "new Function("])

    def test_it_ignores_files_that_are_not_source(self) -> None:
        root = _tree(**{"README.md": "eval(", "icon.svg": "eval("})

        self.assertEqual(scan_sources(root), {})

    def test_it_records_only_a_few_example_files(self) -> None:
        root = _tree(**{f"f{n}.js": "eval(" for n in range(20)})
        found = scan_sources(root)

        self.assertEqual(found["dynamic_code"]["file_count"], 20)
        self.assertLessEqual(len(found["dynamic_code"]["files"]), 5)


if __name__ == "__main__":
    unittest.main()
