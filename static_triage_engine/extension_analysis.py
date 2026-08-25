"""What a browser extension package can be claimed to do, as evidence categories.

Phase 3b of `docs/SCORING.md`. The analysis lived inside
`gui/extension_window.py` -- a 1,743-line Tkinter `Toplevel` that imported
nothing but the theme -- which is why it had no tests: there was nothing
importable to test.

**The scorer it replaces was saturated, not merely wrong.** It summed weighted
permissions, manifest features and source-code pattern hits toward 100 and
banded at 80 for `Critical`. The source scan added its points **once per file**:
`fetch(` was worth 5 points in each file that contained it, `https://` one point
per file, `XMLHttpRequest` five. An extension with a vendor bundle -- jQuery,
Sentry, anything minified -- reaches the ceiling on ordinary code. Nine files
with no malicious behaviour at all scored 67 from the source scan, and the
manifest terms for broad hosts, content scripts and a background worker add 43
more. Every non-trivial extension was `Critical`, which is the same as having no
verdict at all.

The fix is not a reweighting. Counting occurrences is what a corroboration model
does not do: **a pattern fires once however many files contain it**, and the
file count goes in `detail` where a reader can weigh it.

**Calibrated against 394 random store extensions, 25 Aug**, sampled from the
store's own sitemap. An earlier pass used the fourteen extensions installed on
this bench and drew a wrong conclusion from them: those are the ones somebody
chose to install, which skews hard toward the capable, and the categories fired
at two to four times their real rate. The `strong` conditions were cut to almost
nothing on that basis, and three are restored here.

    category                  present   emphatic
    broad_host_access           20.1%       --      too common to be emphatic
    credential_surface           7.4%      2.8%
    external_control_surface     3.0%      0.0%
    high_risk_permission         2.5%      1.5%
    dynamic_code_execution       2.0%      1.0%

    bands   No Evidence 72.8%  |  Single Observation 20.8%
            Corroborated 5.3%  |  Strongly Corroborated 1.0%
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse

from verdict import MAX_CONTEXT_SCORE, Category

#: Host patterns that mean "every site the user visits".
BROAD_HOSTS = frozenset({"<all_urls>", "*://*/*", "http://*/*", "https://*/*"})

#: Permissions that hand an extension a capability the browser otherwise
#: reserves. Not a weighted list -- membership is the claim.
#:
#: `storage`, `notifications` and `activeTab` are deliberately absent. The old
#: scorer charged 1, 2 and 3 points for them, which is a rounding error that
#: still moved a saturating total, and every extension in the store has them.
HIGH_RISK_PERMISSIONS = frozenset({
    "debugger", "nativeMessaging", "proxy", "management", "desktopCapture",
})

#: **Removed after measurement, 25 Aug.** `declarativeNetRequestWithHostAccess`
#: and `webRequestBlocking` were in the set above and are the *standard* content
#: blocking APIs -- `declarativeNetRequest` is MV3's sanctioned replacement for
#: `webRequest`, and every ad blocker on both stores requests one of them. They
#: put two ordinary blockers at `Strongly Corroborated` in a corpus of fourteen
#: real installed extensions.
_RETIRED_HIGH_RISK = frozenset({
    "webRequestBlocking", "declarativeNetRequestWithHostAccess",
})

#: The official store update endpoints. **Every extension installed from a store
#: carries `update_url`** -- it is how updates are delivered -- so its presence
#: is a store requirement and not a signal. Measured at 14 of 14. What *is* a
#: signal is an update URL pointing somewhere else: off-store distribution.
STORE_UPDATE_HOSTS = (
    "clients2.google.com",
    "edge.microsoft.com",
    "clients2.googleusercontent.com",
)

#: Permissions that reach the user's data rather than the browser's machinery.
CREDENTIAL_PERMISSIONS = frozenset({
    "cookies", "clipboardRead", "history",
})

#: Source patterns, grouped by the claim they support. The old list carried a
#: point value per pattern; a claim does not need one.
SOURCE_PATTERNS: dict[str, tuple[str, ...]] = {
    "dynamic_code": ("eval(", "new Function("),
    "credential": ("document.cookie", "chrome.cookies"),
    "traffic": ("chrome.webRequest", "chrome.declarativeNetRequest"),
    "injection": ("chrome.scripting", "executeScript"),
    "native": ("chrome.runtime.connectNative", "chrome.runtime.sendNativeMessage"),
    "cleartext": ("http://",),
}

_SOURCE_SUFFIXES = frozenset({".js", ".mjs", ".html", ".htm", ".json"})


def scan_sources(root: str | Path) -> dict[str, dict[str, Any]]:
    """Which source patterns appear anywhere in the package.

    Returns `{group: {"patterns": [...], "files": [...], "file_count": n}}`.

    **A pattern fires once, however many files contain it.** The old scanner
    added its score per file, which is how a jQuery bundle reached the top band
    on `https://` alone. The file count is kept because it is worth *reading* --
    it is just not worth *scoring*.
    """
    root = Path(root)
    found: dict[str, dict[str, Any]] = {}

    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in _SOURCE_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        rel = path.relative_to(root).as_posix()
        for group, needles in SOURCE_PATTERNS.items():
            hits = [n for n in needles if n in text]
            if not hits:
                continue
            entry = found.setdefault(
                group, {"patterns": set(), "files": [], "file_count": 0})
            entry["patterns"].update(hits)
            entry["file_count"] += 1
            if len(entry["files"]) < 5:
                entry["files"].append(rel)

    for entry in found.values():
        entry["patterns"] = sorted(entry["patterns"])
    return found


def _is_offstore_update(update_url: Any) -> bool:
    """Does `update_url` point somewhere other than an official store?

    Presence alone is meaningless -- every store install has one. A URL pointing
    elsewhere means the author distributes and updates outside the store, which
    is where sideloaded extensions get their persistence.
    """
    if not update_url:
        return False
    try:
        host = (urlparse(str(update_url)).hostname or "").lower()
    except ValueError:
        return True
    if not host:
        return True
    return not any(host == known or host.endswith("." + known)
                   for known in STORE_UPDATE_HOSTS)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]


def manifest_facts(manifest: Mapping[str, Any] | None) -> dict[str, Any]:
    """The manifest fields the categories are built from, normalised.

    Manifest v2 puts host patterns in `permissions`; v3 separates them. Both
    shapes end up in `host_permissions` here so nothing downstream has to know
    which version it is looking at.
    """
    manifest = manifest or {}
    permissions = [p for p in _as_list(manifest.get("permissions")) if isinstance(p, str)]
    hosts = [h for h in _as_list(manifest.get("host_permissions")) if isinstance(h, str)]
    hosts += [p for p in permissions if "://" in p or p == "<all_urls>"]

    content_scripts = [s for s in _as_list(manifest.get("content_scripts"))
                       if isinstance(s, dict)]
    script_matches: list[str] = []
    for script in content_scripts:
        script_matches += [m for m in _as_list(script.get("matches"))
                           if isinstance(m, str)]

    csp = manifest.get("content_security_policy")
    csp_text = csp if isinstance(csp, str) else json.dumps(csp) if csp else ""

    external = manifest.get("externally_connectable")
    external_matches: list[str] = []
    if isinstance(external, dict):
        external_matches = [m for m in _as_list(external.get("matches"))
                            if isinstance(m, str)]

    return {
        "permissions": permissions,
        "host_permissions": hosts,
        "broad_hosts": sorted({h for h in hosts if h in BROAD_HOSTS}),
        "content_scripts": content_scripts,
        "script_matches": script_matches,
        "broad_script_matches": sorted({m for m in script_matches if m in BROAD_HOSTS}),
        "csp_unsafe_eval": "unsafe-eval" in csp_text,
        "externally_connectable": external,
        "external_matches": external_matches,
        "broad_external": sorted({m for m in external_matches if m in BROAD_HOSTS}),
        "update_url": manifest.get("update_url") or "",
        "offstore_update_url": _is_offstore_update(manifest.get("update_url")),
        "background": bool(manifest.get("background")),
        "web_accessible_resources": _as_list(manifest.get("web_accessible_resources")),
    }


def extension_categories(
    manifest: Mapping[str, Any] | None = None,
    sources: Mapping[str, Any] | None = None,
) -> tuple[list[Category], int]:
    """Every category an extension package can author, present or not.

    `None` for either input means that half of the analysis did not run: an
    unreadable manifest and a manifest requesting nothing are not the same
    observation, and neither are a source tree that was scanned and a source
    tree that was not.
    """
    manifest_ran = manifest is not None
    sources_ran = sources is not None
    facts = manifest_facts(manifest)
    sources = dict(sources or {})

    def group(name: str) -> dict[str, Any]:
        entry = sources.get(name)
        return entry if isinstance(entry, dict) else {}

    def where(name: str) -> str:
        entry = group(name)
        if not entry:
            return ""
        files = ", ".join(entry.get("files", [])[:3])
        return f"{entry.get('file_count', 0)} file(s): {files}"

    cats: list[Category] = []

    # --- Access to every site -----------------------------------------------
    broad_hosts = facts["broad_hosts"]
    broad_scripts = facts["broad_script_matches"]
    broad = manifest_ran and bool(broad_hosts or broad_scripts)
    cats.append(Category(
        name="broad_host_access",
        module="extension",
        collected=manifest_ran,
        present=broad,
        # **Never strong, and the corpus agreed.** Content scripts on every
        # site appear in 12.7% of 394 random store extensions -- the one retired
        # condition the larger sample confirmed. Access to every site is the
        # price of admission for whole legitimate categories: blockers,
        # password managers, translators, readers. It corroborates.
        strong=False,
        detail=", ".join(sorted(set(broad_hosts + broad_scripts))) if broad else "",
        reason=(
            "The extension requests access to every site the user visits"
            + (" and runs content scripts there, so its code executes inside "
               "every page they open." if broad_scripts else
               ", so it can read and modify traffic to any of them.")
        ) if broad else "",
    ))

    # --- Capabilities the browser otherwise reserves -------------------------
    high = sorted(set(facts["permissions"]) & HIGH_RISK_PERMISSIONS)
    cats.append(Category(
        name="high_risk_permission",
        module="extension",
        collected=manifest_ran,
        present=manifest_ran and bool(high),
        # **Restored after the corpus, 25 Aug.** Cut to "two or more" against
        # the fourteen installed extensions, where `nativeMessaging` alone
        # appeared in three. Across 394 random store extensions it appears in
        # 1.5%, and "two or more" fires in **none** of them -- a condition that
        # never fires is not calibrated, it is absent.
        #
        # `debugger` attaches to the browser's own debugging protocol and
        # `nativeMessaging` runs a program outside the sandbox. Either is
        # emphatic, and at 1.5% of the population saying so costs almost
        # nothing.
        strong=bool(high) and (len(high) >= 2
                               or "debugger" in high
                               or "nativeMessaging" in high),
        detail=", ".join(high),
        reason=(
            f"The manifest requests {', '.join(high)} -- capability the browser "
            f"reserves, and which an extension has to justify rather than merely "
            f"declare."
        ) if high else "",
    ))

    # --- Reach into the user's data -----------------------------------------
    credential_perms = sorted(set(facts["permissions"]) & CREDENTIAL_PERMISSIONS)
    credential_code = group("credential")
    # **Both halves, not either.** The dynamic module counts a category as
    # collected when *any* of its telemetry routes ran, because those routes are
    # three views of the same behaviour. Here they are not: the manifest says
    # what the extension *requests* and the source says what it *uses*, and an
    # extension that asks for nothing while its code reads cookies is exactly
    # the case worth catching. Reading one half is partial coverage and says so.
    credential_ran = manifest_ran and sources_ran
    credential = credential_ran and bool(credential_perms or credential_code)
    cats.append(Category(
        name="credential_surface",
        module="extension",
        collected=credential_ran,
        present=credential,
        # Cookies plus access to every site is the shape of a session stealer.
        # Either alone is ordinary.
        # **Restored after the corpus, 25 Aug.** Cut against the fourteen
        # installed extensions, where cookies appeared in 5 and broad host
        # access in 8, which made the pair look ordinary. Across 394 random
        # store extensions the pair appears in **2.8%**. Cookie access across
        # every site is the shape of a session stealer, and it is rare enough
        # to say so.
        strong=credential and broad and bool(
            {"cookies"} & set(credential_perms) or credential_code),
        detail=", ".join(credential_perms + ([where("credential")]
                                             if credential_code else [])),
        reason=(
            "The extension can reach session data"
            + (f" ({', '.join(credential_perms)})" if credential_perms else "")
            + (" and its code reads cookies directly" if credential_code else "")
            + (", across every site the user visits." if broad else ".")
        ) if credential else "",
    ))

    # --- Code assembled at runtime ------------------------------------------
    # **The CSP decides, and the source corroborates.** `eval(` and
    # `new Function(` appear in almost any minified vendor bundle, so scanning
    # for them alone fired on 7 of 14 ordinary extensions. Under Manifest V3 the
    # default policy forbids `unsafe-eval` outright -- so that code *cannot
    # execute*, and reporting it is reporting dead branches in somebody else's
    # library.
    #
    # A policy that permits runtime code is a decision the author made. That is
    # the claim; the source is what shows they meant it.
    dynamic_code = group("dynamic_code")
    dynamic_ran = manifest_ran and sources_ran
    dynamic = dynamic_ran and bool(facts["csp_unsafe_eval"])
    cats.append(Category(
        name="dynamic_code_execution",
        module="extension",
        collected=dynamic_ran,
        present=dynamic,
        # **Restored after the corpus, 25 Aug.** 3 of 14 installed extensions
        # carried a permissive policy with matching source calls; across 394
        # random store extensions it is **1.0%**. A policy permitting runtime
        # code *and* source that uses it is a decision the author made twice.
        strong=bool(facts["csp_unsafe_eval"] and dynamic_code),
        detail=("unsafe-eval in CSP" if facts["csp_unsafe_eval"] else "")
        + ((" | " if facts["csp_unsafe_eval"] and dynamic_code else "")
           + where("dynamic_code") if dynamic_code else ""),
        reason=(
            "The extension can execute code assembled at runtime"
            + (", which its content security policy explicitly permits"
               if facts["csp_unsafe_eval"] else "")
            + (", and its source calls eval or the Function constructor"
               if dynamic_code else "")
            + ". Code that is built while running is code no review saw."
        ) if dynamic else "",
    ))

    # --- Control from outside the browser ------------------------------------
    # **Native messaging is deliberately not here.** It is a permission, and
    # `high_risk_permission` already claims it -- counting the same fact in two
    # categories manufactures the corroboration the model is built to measure.
    # It was doing so through a source-string match, which fired on 4 of 14
    # ordinary extensions.
    external = manifest_ran and bool(
        facts["externally_connectable"] or facts["offstore_update_url"])
    parts = []
    if facts["externally_connectable"]:
        parts.append("externally_connectable"
                     + (f" ({', '.join(facts['broad_external'])})"
                        if facts["broad_external"] else ""))
    if facts["offstore_update_url"]:
        parts.append(f"off-store update_url {facts['update_url']}")
    cats.append(Category(
        name="external_control_surface",
        module="extension",
        collected=manifest_ran and sources_ran,
        present=external,
        # Broad `externally_connectable` lets any page on any origin drive the
        # extension. That is the one shape here that needs no corroboration.
        strong=bool(facts["broad_external"]),
        detail=" | ".join(parts),
        reason=(
            "Something outside the extension can direct it: "
            + "; ".join(parts) + "."
        ) if external else "",
    ))

    # --- Context: size of the ask, not its nature ----------------------------
    context = 0
    if facts["permissions"]:
        context += min(6, len(facts["permissions"]) // 2)
    if facts["host_permissions"]:
        context += min(4, len(facts["host_permissions"]))
    if facts["web_accessible_resources"]:
        context += 2
    if facts["background"]:
        context += 1
    return cats, max(0, min(MAX_CONTEXT_SCORE, context))


def analyze_extension(
    working_dir: str | Path | None,
    manifest: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Everything the window needs, with nothing Tk-shaped about it."""
    sources = scan_sources(working_dir) if working_dir is not None else None
    cats, context = extension_categories(manifest, sources)

    from verdict.combine import combine

    result = combine({"extension": (cats, context)})
    result["facts"] = manifest_facts(manifest)
    result["sources"] = sources or {}
    result["notes"] = [c.reason for c in cats if c.present] or [
        "No evidence category fired. That is the absence of a claim, not a "
        "claim of absence -- this pass reads the manifest and greps the "
        "source, and neither can show what the extension does at runtime."
    ]
    return result
