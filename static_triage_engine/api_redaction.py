"""Removing credentials from an API exchange before it is written to a file.

**Why this is a module and not a method on the window.** This is the security
control in the one screen that routinely holds bearer tokens, cookies and API
keys, and it lived in `gui/api_window.py` as `_redact_secrets` -- 39 lines of
regular expressions that no test could reach without a display. Sixth module
through this pass.

**The defect it was part of.** `save_html_report` redacted the response headers
and body *in place*, then handed those same variables to `analyze_response`. So
the findings were computed from text with the values already removed, and
ticking the redact box changed the security result in both directions:

* `Set-Cookie: sid=x; HttpOnly; Secure; SameSite=Strict` became
  `Set-Cookie: [REDACTED]`, the flags went with the value, and a correctly
  configured cookie was reported **Medium, "one missing httponly, secure,
  samesite"** -- a finding about nothing.
* `{"access_token": "..."}` became `{"access_token": "[REDACTED]"}`, so the
  **High** "credential-shaped values in the body" finding vanished -- the real
  finding, suppressed by the act of preparing the report.

The window's own analysis pane read the unredacted text, so the screen and the
exported file disagreed about the same response.

**Redaction is a presentation step and must run last.** Analyse the exchange,
then redact what goes on the page -- including the finding text, so a future
finding that quotes a value cannot leak through a control that ran before it
existed.

**The count is measured, not asserted.** "Redaction was on" and "redaction
removed nothing" are different facts, and the reader deciding how to handle the
file needs the second one.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

#: The marker left behind. Counted, so it is a constant rather than a literal
#: repeated in the patterns and the counter.
MARKER = "[REDACTED]"

#: `(pattern, replacement)`, applied in order. Header rules are anchored to the
#: start of a line so a word inside a body cannot trigger them; the JSON and
#: query-string rules are not, because a body has no line discipline.
#:
#: **These are patterns, and patterns miss.** A secret under an unusual field
#: name, or one in an unstructured body, survives all of them -- which is why
#: the report calls redaction a reduction in exposure rather than a guarantee.
REDACTIONS: tuple[tuple[str, str], ...] = (
    # HTTP headers. The scheme-specific rules run first and the general one
    # then overwrites what they left, so `Authorization: Bearer x` ends as
    # `Authorization: [REDACTED]` -- the scheme goes with the token. That is
    # the behaviour this has always had and it is pinned by a test; keeping
    # `Bearer` visible would be a change, not a fix, and this pass is not the
    # place to make it.
    (r"(?im)^(Authorization\s*:\s*Bearer\s+)[^\r\n]+", r"\1" + MARKER),
    (r"(?im)^(Authorization\s*:\s*Basic\s+)[^\r\n]+", r"\1" + MARKER),
    (r"(?im)^(Authorization\s*:\s*)[^\r\n]+", r"\1" + MARKER),
    (r"(?im)^(X-Api-Key\s*:\s*)[^\r\n]+", r"\1" + MARKER),
    (r"(?im)^(Api-Key\s*:\s*)[^\r\n]+", r"\1" + MARKER),
    (r"(?im)^(Cookie\s*:\s*)[^\r\n]+", r"\1" + MARKER),
    (r"(?im)^(Set-Cookie\s*:\s*)[^\r\n]+", r"\1" + MARKER),

    # JSON-style secrets, double- and single-quoted.
    (r'(?i)("?(?:api[_-]?key|x-api-key|access[_-]?token|refresh[_-]?token'
     r'|id[_-]?token|client[_-]?secret|secret|password|passwd|pwd)"?\s*:\s*")'
     r'[^"]+(")', r"\1" + MARKER + r"\2"),
    (r"(?i)('?(?:api[_-]?key|x-api-key|access[_-]?token|refresh[_-]?token"
     r"|id[_-]?token|client[_-]?secret|secret|password|passwd|pwd)'?\s*:\s*')"
     r"[^']+(')", r"\1" + MARKER + r"\2"),

    # Query-string or form-encoded.
    (r"(?i)\b(api[_-]?key|x-api-key|access[_-]?token|refresh[_-]?token"
     r"|id[_-]?token|client[_-]?secret|secret|password|passwd|pwd)=([^&\s]+)",
     r"\1=" + MARKER),

    # Bearer tokens loose in a body or a raw capture. Cannot re-match its own
    # output: `[` is not in the token character class.
    (r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+", "Bearer " + MARKER),

    # Reflected caller identity from test APIs like HTTPBin. Not a credential,
    # but it is the analyst's own public address in a file they may share.
    (r'(?i)("origin"\s*:\s*")[^"]+(")', r"\1" + MARKER + r"\2"),
    (r"(?im)^(X-Forwarded-For\s*:\s*)[^\r\n]+", r"\1" + MARKER),
    (r"(?im)^(X-Real-IP\s*:\s*)[^\r\n]+", r"\1" + MARKER),
)

_COMPILED = tuple((re.compile(pattern), replacement)
                  for pattern, replacement in REDACTIONS)


def redact(value: Any) -> str:
    """Every rule, in order, over one piece of text."""
    text = "" if value is None else str(value)
    for pattern, replacement in _COMPILED:
        text = pattern.sub(replacement, text)
    return text


def count_markers(*texts: Any) -> int:
    return sum(str(text or "").count(MARKER) for text in texts)


def redact_fields(fields: Mapping[str, Any]) -> tuple[dict[str, str], int]:
    """Redact each field, and report how many values were actually replaced.

    Counted by the change in `[REDACTED]` markers rather than by the number of
    rules that fired, so a value already redacted upstream is not counted
    twice and a response that legitimately contains the word is not counted at
    all.
    """
    before = count_markers(*fields.values())
    redacted = {name: redact(value) for name, value in fields.items()}
    after = count_markers(*redacted.values())
    return redacted, max(after - before, 0)


def redact_findings(findings: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """The same rules over finding text.

    No finding written today quotes a secret -- they name the *field* that
    leaked, not its value. This runs anyway, because the control has to hold
    for the finding somebody adds next year without reading this file.
    """
    cleaned = []
    for finding in findings or []:
        item = dict(finding)
        if "message" in item:
            item["message"] = redact(item["message"])
        cleaned.append(item)
    return cleaned
