"""What an HTTP response discloses, as findings and evidence categories.

Phase 3b of `docs/SCORING.md`, api half. The analysis lived inside
`gui/api_window.py` -- a 1,394-line Tkinter `Toplevel` -- and returned a block
of text, so nothing could test it and nothing else could read it.

**Its only High-severity finding fired on every endpoint that sets a cookie.**
The sensitive-value list held `set-cookie`, `authorization` and `bearer ` and
matched them as substrings against the response headers and body alike. Any
login endpoint -- the exact thing an analyst reaches for this tool to test --
returns `Set-Cookie`, so every one of them reported "Token, credential, cookie,
or secret-like content may be present". So did any endpoint whose body merely
*mentions* authorization, such as one returning its own API documentation. The
finding that should matter most was the one that fired regardless.

**Two of the verbose-error markers matched ordinary prose.** `debug` matches any
JSON carrying a `debug` field; `line ` matches most English sentences. Both were
tested against the response body *and* the raw text, so a well-behaved API
returning `{"debug": false}` was reported as leaking debug content.

The rewrite matches a credential-shaped *value* -- a named field with a
plausible secret after it -- rather than the appearance of a word, and treats
`Set-Cookie` as what it is: a cookie, worth checking for its flags, not a
disclosure.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping, Sequence

from verdict import MAX_CONTEXT_SCORE, Category

#: Markers that only appear in an actual stack trace or framework error page.
#:
#: `debug` and `line ` were on this list and are gone: the first matches any
#: JSON carrying a `debug` field, the second matches most English.
STACK_TRACE_MARKERS = (
    "traceback (most recent call last)",
    "stack trace:",
    "nullreferenceexception",
    "sqlexception",
    "system.exception",
    "at java.",
    "org.springframework",
    ".php on line ",
    "warning: mysql",
    "syntaxerror:",
)

#: Names that identify a credential when they appear as a *field* in a response
#: body. Matched with a delimiter on each side so `password_policy_url` in a
#: documentation payload does not read as a leaked password.
CREDENTIAL_FIELDS = (
    "access_token", "refresh_token", "id_token", "client_secret",
    "api_key", "apikey", "private_key", "secret_key", "session_token",
)

#: Words that are a *type* or a *description*, never a secret. An API serving
#: its own OpenAPI document declares `refresh_token:` and then describes it, and
#: the description is made of these.
NON_SECRET_VALUES = frozenset({
    "description", "string", "integer", "boolean", "number", "object", "array",
    "example", "examples", "required", "optional", "nullable", "properties",
    "format", "default", "readonly", "writeonly", "deprecated", "reference",
    "password", "credentials", "undefined", "unknown", "redacted", "changeme",
})

#: `[ \t]` rather than `\s`. **The gap must not cross a line.** A JSON or YAML
#: document writes `"api_key": "abc123..."` on one line; a *schema* writes
#:
#:     refresh_token:
#:       description: "Refresh token value for refresh token grants"
#:
#: and `\s*` spanning that newline made `description` the credential. One of
#: 103 replayed responses is an API serving its own specification, and this is
#: how it reported a leaked refresh token. It is the same defect the module was
#: rewritten to remove -- a word where a value should be -- in a new place.
_FIELD_RE = re.compile(
    r"[\"']?(" + "|".join(CREDENTIAL_FIELDS)
    + r")[\"']?[ \t]*[:=][ \t]*[\"']?(?P<value>[A-Za-z0-9._\-/+]{8,})",
    re.IGNORECASE)

#: A bearer token in a response body, rather than in the request the analyst
#: composed.
_BEARER_RE = re.compile(r"\bbearer\s+[A-Za-z0-9._\-]{16,}", re.IGNORECASE)

#: A dotted version number -- `nginx/1.18.0`, `Microsoft-IIS/10.0`, `PHP/7.3.25`.
#: `AmazonS3` and `Layer7-API-Gateway` carry a digit and no version, so a bare
#: `\d` is not the test.
_VERSION_RE = re.compile(r"\d+\.\d+")


def _lower(value: Any) -> str:
    return str(value or "").lower()


#: What a response's headers may arrive as. The pair sequence is the only one
#: that survives a repeated header, and `Set-Cookie` is the header that repeats.
Headers = Mapping[str, str] | Sequence[tuple[str, str]] | str | None


def _header_values(response_headers: Headers, name: str) -> list[str]:
    """**Every** value sent under this name, in order.

    A response that sets three cookies sends three `Set-Cookie` headers, and a
    `dict` keeps one of them. Across 108 replayed responses, 8 repeat the
    header and 6 of those have a *non-final* cookie missing a flag -- including
    one with no `HttpOnly`, `Secure` or `SameSite` at all, sent first and
    overwritten by a well-formed one. Reading a single value scored those
    responses on their best cookie.
    """
    if isinstance(response_headers, Mapping):
        return [str(v) for k, v in response_headers.items() if k.lower() == name]
    if isinstance(response_headers, str):
        marker = f"{name}:"
        return [line.split(":", 1)[1].strip()
                for line in response_headers.splitlines()
                if line.lower().startswith(marker)]
    if response_headers is None:
        return []
    out = []
    for pair in response_headers:
        if (isinstance(pair, (list, tuple)) and len(pair) == 2
                and str(pair[0]).lower() == name):
            out.append(str(pair[1]))
    return out


def _header_present(response_headers: Headers, name: str) -> bool:
    return bool(_header_values(response_headers, name))


def _header_value(response_headers: Headers, name: str) -> str:
    values = _header_values(response_headers, name)
    return values[0] if values else ""


def analyze_response(
    *,
    method: str = "",
    url: str = "",
    status: Any = 0,
    response_headers: Headers = None,
    body: str = "",
) -> dict[str, Any]:
    """Findings about the response, keyed by severity.

    **The body is read for values; the headers for decisions the server made.**
    The old code searched one lowercased blob per source for a list of words,
    so `Set-Cookie` -- a header every login endpoint sends -- matched a list
    named `sensitive_terms` and produced the only High finding it had.
    """
    findings: list[dict[str, str]] = []

    def add(severity: str, code: str, message: str) -> None:
        findings.append({"severity": severity, "code": code, "message": message})

    url_l = _lower(url)
    body_l = _lower(body)

    try:
        status_i = int(str(status).strip().split()[0])
    except (ValueError, IndexError):
        status_i = 0

    # --- Status -------------------------------------------------------------
    if 200 <= status_i < 300:
        add("Info", "status_ok", "Successful HTTP response received.")
    elif 300 <= status_i < 400:
        add("Low", "status_redirect",
            "Redirect response. Review the Location header and its destination host.")
    elif status_i in {401, 403}:
        add("Info", "status_denied",
            "The endpoint returned an authentication or authorization denial.")
    elif 400 <= status_i < 500:
        add("Low", "status_client_error",
            "Client error response. Review request structure and authentication.")
    elif status_i >= 500:
        add("Medium", "status_server_error",
            "Server error response. Check whether it exposed internals.")

    # --- Transport ----------------------------------------------------------
    if url_l.startswith("http://"):
        add("Medium", "cleartext_transport",
            "Cleartext HTTP transport. Anything sent or returned is readable "
            "in transit.")

    # --- Headers the server chose to send ------------------------------------
    # **A version, not a name.** This used to fire on any `Server:` header at
    # all, which is 68.9% of 103 replayed responses -- and the values are
    # `cloudflare` 27 times, `nginx` 11, `Apache`, `Fastly`, `Heroku`. A bare
    # product name is what the whole internet sends and it discloses nothing a
    # caller could not guess. `nginx/1.10.3 (Ubuntu)` and `Microsoft-IIS/10.0`
    # are a different claim: they name the version to look up. The comment on
    # the category below already said a `Server:` header is "a default, not a
    # decision" -- that reasoning stopped the category being emphatic, and it
    # should have stopped it firing.
    server = _header_value(response_headers, "server")
    if server and _VERSION_RE.search(server):
        add("Low", "server_header",
            f"Server header disclosed backend version: {server}.")
    if _header_present(response_headers, "x-powered-by"):
        add("Low", "powered_by_header",
            f"X-Powered-By disclosed framework or runtime: "
            f"{_header_value(response_headers, 'x-powered-by')}.")

    cors = _header_value(response_headers, "access-control-allow-origin").strip()
    credentialed_cors = _lower(
        _header_value(response_headers, "access-control-allow-credentials")) == "true"
    if cors == "*":
        add("Medium" if credentialed_cors else "Low", "wildcard_cors",
            "Wildcard CORS origin"
            + (" together with Access-Control-Allow-Credentials, which browsers "
               "reject and which signals a misconfigured policy."
               if credentialed_cors else ". Review whether that is intended."))

    # **Every cookie, graded on the worst.** One well-formed cookie does not
    # excuse the one sent beside it, and reading a single value meant the last
    # cookie spoke for all of them.
    cookies = _header_values(response_headers, "set-cookie")
    if cookies:
        worst: list[str] = []
        for cookie in cookies:
            missing = [flag for flag in ("httponly", "secure", "samesite")
                       if flag not in _lower(cookie)]
            if len(missing) > len(worst):
                worst = missing
        count = f"{len(cookies)} cookies" if len(cookies) > 1 else "Set-Cookie"
        add("Medium" if worst else "Info", "set_cookie",
            f"{count} observed"
            + (f", one missing {', '.join(worst)}." if worst
               else " with HttpOnly, Secure and SameSite set."))

    # --- What the body gave away ---------------------------------------------
    #
    # Body only. A credential the analyst *sent* is not a disclosure, and
    # treating it as one is what made this finding meaningless.
    leaked_fields = sorted({
        m.group(1).lower() for m in _FIELD_RE.finditer(body or "")
        if m.group("value").lower() not in NON_SECRET_VALUES})
    leaked_bearer = bool(_BEARER_RE.search(body or ""))
    if leaked_fields or leaked_bearer:
        add("High", "credential_in_body",
            "The response body contains credential-shaped values"
            + (f" ({', '.join(leaked_fields)})" if leaked_fields else "")
            + ". Redact before sharing this report.")

    traces = [m for m in STACK_TRACE_MARKERS if m in body_l]
    if traces:
        add("Medium", "verbose_error",
            f"The response body contains error internals ({traces[0]!r}), which "
            f"disclose implementation detail to a caller.")

    if not findings:
        add("Info", "no_findings", "No response findings generated.")

    counts = {level: sum(1 for f in findings if f["severity"] == level)
              for level in ("High", "Medium", "Low", "Info")}
    return {"findings": findings, "counts": counts,
            "status_code": status_i, "method": method, "url": url}


def api_categories(
    analysis: Mapping[str, Any] | None = None,
) -> tuple[list[Category], int]:
    """Evidence categories from one response.

    `None` means no request was sent -- which is not the same as a request that
    returned nothing interesting.
    """
    ran = analysis is not None
    findings = list((analysis or {}).get("findings", []))
    codes = {f.get("code"): f for f in findings}

    def has(code: str) -> bool:
        return ran and code in codes

    cats = [
        Category(
            name="credential_disclosure",
            module="api",
            collected=ran,
            present=has("credential_in_body"),
            # A credential in a response body is a disclosure whatever else is
            # true of the endpoint. Nothing else here needs to agree with it.
            strong=has("credential_in_body"),
            detail=codes.get("credential_in_body", {}).get("message", ""),
            reason=(
                "The response body carried credential-shaped values. Whatever "
                "the endpoint is for, it returned material that should not "
                "leave the server in that form."
            ) if has("credential_in_body") else "",
        ),
        Category(
            name="cleartext_transport",
            module="api",
            collected=ran,
            present=has("cleartext_transport"),
            strong=has("cleartext_transport") and has("credential_in_body"),
            detail=codes.get("cleartext_transport", {}).get("message", ""),
            reason=(
                "The endpoint was reached over cleartext HTTP, so both the "
                "request and the response are readable in transit"
                + (" -- and the response carried credentials."
                   if has("credential_in_body") else ".")
            ) if has("cleartext_transport") else "",
        ),
        Category(
            name="implementation_disclosure",
            module="api",
            collected=ran,
            present=has("verbose_error") or has("server_header") or has("powered_by_header"),
            # Never strong. A `Server:` header is a default, not a decision, and
            # a version string is a starting point rather than a finding.
            strong=False,
            detail="; ".join(
                codes[c]["message"] for c in
                ("verbose_error", "server_header", "powered_by_header") if c in codes),
            reason=(
                "The endpoint disclosed implementation detail a caller does not "
                "need, which shortens the work of anyone mapping it."
            ) if (has("verbose_error") or has("server_header")
                  or has("powered_by_header")) else "",
        ),
        Category(
            name="permissive_sharing",
            module="api",
            collected=ran,
            # **A wildcard origin on a public API is the configuration, not a
            # fault.** `Access-Control-Allow-Origin: *` is how an API meant for
            # any caller is built, and it fired on 25.2% of 103 replayed
            # responses -- 23 of the 26 without credentials. What is a finding
            # is the wildcard *together with* `Allow-Credentials: true`, which
            # browsers refuse outright and which therefore means somebody
            # configured a policy that cannot work. `analyze_response` already
            # grades that pair Medium; this now follows the grading instead of
            # firing on the header.
            present=(
                (has("wildcard_cors")
                 and codes.get("wildcard_cors", {}).get("severity") == "Medium")
                or (has("set_cookie")
                    and codes.get("set_cookie", {}).get("severity") == "Medium")),
            strong=has("wildcard_cors")
            and codes.get("wildcard_cors", {}).get("severity") == "Medium",
            detail="; ".join(codes[c]["message"] for c in
                             ("wildcard_cors", "set_cookie") if c in codes),
            reason=(
                "The endpoint's sharing rules are looser than its content "
                "warrants -- a wildcard origin, or a cookie without the flags "
                "that keep it out of script and off cleartext."
            ) if (has("wildcard_cors") or has("set_cookie")) else "",
        ),
    ]

    context = min(MAX_CONTEXT_SCORE, len(findings))
    return cats, context
