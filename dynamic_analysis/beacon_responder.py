"""Phase 3 of `0bw`: answering the beacon, to reach `method=send&address=`.

Phase 2 established the C2 by serving `bare_host` and watching the implant take
the hostname from the chain and beacon to it. What it got back was FakeNet's
stock HTML page, and ten seconds later the process was gone. This module exists
to give it something better and find out what changes.

**What was observed, and it is all that is known.** Run `4bb6b0d5`::

    t125  SecurityHealthHost.exe spawned (hollowed by powershell.exe)
    t150  eth_call -> answered with the sink hostname
    t151  POST https://<sink>/  method=refresh&guid=4814CF26...
          Authorization: 4b817807-2731-459c-bc5d-4bd914c9eb55
    t161  process exit

One beacon. No retry. `method=send&guid=` and `&address=` are both resident in
the payload's memory, so the second half of the protocol exists and was never
reached.

**What a valid response looks like is unknown, and nothing on disk says.** The
config block carries the two request templates and no response parser worth
reading. So this enumerates rather than guesses, exactly as `jsonrpc_answer`
did -- that is the design that turned four failed detonations into one
successful one.

**Rotation is a bet, and the bet is legible.** Phase 2 could rotate because the
implant retried its `eth_call` seven times in two seconds when refused; rotation
advanced on rejection and one run tested every hypothesis. Whether the beacon
retries is *not known*: it fired once and the process exited, which is
consistent with "gave up after one bad answer" and equally consistent with "did
what it came for". If it retries on a bad response, this sweeps the list in a
single run. If it does not, the run tests exactly one shape and the log says so
-- `attempts` is recorded for precisely that reason.

**Three readouts, and none needs the right answer known in advance.**

1. `method=send&guid=&address=` arriving at all. That is the objective, and the
   `address=` value answers whether substitution targets the operator's sink.
2. **How many times the beacon is sent.** One means no retry and rotation is
   the wrong instrument. More than one means it is the right one.
3. **How long the process lives.** 36 seconds was its lifetime against a stock
   HTML answer, 10 of them after the beacon. A shape that extends that was
   better understood than the others, whether or not `send` follows.

**The address served is a tracer, and never a real wallet.** Same rule as
`jsonrpc_answer`, for the same reason: finding `0xC0FFEE…` in a beacon body is
proof of substitution, and finding a real address there proves nothing except
that the bench was pointed somewhere it should not have been.
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Optional
from urllib.parse import parse_qs

#: Reused rather than redefined: one definition of "the tracer" across phases.
from dynamic_analysis.jsonrpc_answer import TRACER_ADDRESS

#: The campaign GUID, sent by the implant as its `Authorization` header.
#:
#: Hardcoded in the config block and matched by `$guid` in the YARA rule. Its
#: purpose was unknown until run `4bb6b0d5` put it on the wire: it is the C2
#: credential. Recorded here so a beacon carrying a *different* one is visible
#: as a different campaign rather than blending in.
CAMPAIGN_GUID = "4b817807-2731-459c-bc5d-4bd914c9eb55"

#: The methods the payload's string table carries. There are no others.
METHOD_REFRESH = "refresh"
METHOD_SEND = "send"

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


class BeaconError(ValueError):
    """Raised for a request this module refuses to interpret."""


# -- reading the beacon ---------------------------------------------------


def parse_beacon(body: bytes) -> dict[str, Any]:
    """Read a form-encoded beacon body into its fields.

    Tolerant on purpose. A body that does not parse is still a beacon that
    arrived, and recording it as "unparsed" keeps it distinguishable from one
    that never came -- the same distinction phase 1 was built around.
    """
    result: dict[str, Any] = {
        "parsed": False, "method": "", "guid": "", "address": "",
        "fields": {}, "parse_error": "",
    }
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception as error:  # pragma: no cover -- decode is replace-safe
        result["parse_error"] = str(error)
        return result

    # **`parse_qs` is not a validity test, and using it as one loses the
    # distinction this phase depends on.** With `keep_blank_values` it turns
    # arbitrary bytes into a single key with an empty value, so binary noise
    # would be recorded as a *parsed* beacon and classified `other` rather than
    # `unparsed`. "It sent something unreadable" and "it sent a beacon we do not
    # recognise" call for different next moves, so they are separated here
    # before `parse_qs` gets the chance to blur them.
    if "=" not in text:
        result["parse_error"] = "no '=' anywhere: not form-encoded"
        return result
    if any(ord(c) < 0x20 and c not in "\r\n\t" for c in text):
        result["parse_error"] = "control bytes in body: not form-encoded"
        return result

    try:
        fields = {k: v[0] if v else "" for k, v in parse_qs(text, keep_blank_values=True).items()}
    except Exception as error:
        result["parse_error"] = f"not form-encoded: {error}"
        return result

    if not fields:
        result["parse_error"] = "no form fields"
        return result

    result["parsed"] = True
    result["fields"] = fields
    result["method"] = fields.get("method", "")
    result["guid"] = fields.get("guid", "")
    result["address"] = fields.get("address", "")
    return result


def classify(parsed: dict[str, Any]) -> str:
    """`refresh`, `send`, `other` or `unparsed`.

    `send` is the one this phase exists to provoke, so it is named rather than
    lumped in with whatever else may arrive.
    """
    if not parsed.get("parsed"):
        return "unparsed"
    method = str(parsed.get("method", "")).strip().lower()
    if method == METHOD_REFRESH:
        return METHOD_REFRESH
    if method == METHOD_SEND:
        return METHOD_SEND
    return "other"


def substituted_address(parsed: dict[str, Any], tracer: str = TRACER_ADDRESS) -> dict[str, Any]:
    """Read `address=` and say whether it is ours or the attacker's.

    **The whole point of the tracer.** An `address=` equal to the tracer means
    the implant relayed what it was given. Anything else -- and the wallet table
    is seventeen entries long -- means it substituted, and the value names which
    entry.
    """
    address = str(parsed.get("address", "") or "").strip()
    return {
        "address": address,
        "present": bool(address),
        "is_tracer": bool(address) and address.lower() == tracer.lower(),
        "well_formed": bool(_ADDRESS_RE.match(address)),
    }


# -- answering it ---------------------------------------------------------
#
# Every shape returns a complete HTTP response body. What varies is the body
# and the content type, because those are the only things the implant can be
# parsing.


class BeaconPlan:
    """One hypothesis about what the C2 says back to `refresh`."""

    def __init__(self, name: str, why: str, content_type: str,
                 build: Callable[[str], str]):
        self.name = name
        self.why = why
        self.content_type = content_type
        self._build = build

    def body(self, address: str) -> str:
        return self._build(address)

    def describe(self) -> dict[str, str]:
        return {"name": self.name, "why": self.why,
                "content_type": self.content_type}


def _empty(address: str) -> str:
    return ""


def _ok(address: str) -> str:
    return "ok"


def _form_address(address: str) -> str:
    # The request is form-encoded. A hand-rolled client that speaks one
    # encoding outbound very often expects it inbound, and this is the cheapest
    # shape to be wrong about.
    return f"address={address}"


def _bare_address(address: str) -> str:
    return address


def _json_address(address: str) -> str:
    return json.dumps({"address": address})


def _json_wallets(address: str) -> str:
    # `refresh` reads like "update what you substitute with". The implant already
    # carries seventeen hardcoded wallets, so a refresh that replaces them is the
    # reading that makes the method name mean something.
    return json.dumps({
        "eth": address, "btc": address, "address": address, "status": "ok",
    })


#: Ordered cheapest-to-most-elaborate, as `jsonrpc_answer.PLANS` is.
#:
#: `empty` leads deliberately. A 200 with no body is what a C2 with nothing to
#: say returns, it is the likeliest thing the implant tolerates, and if the
#: process lives longer than 36 seconds against it then the stock HTML page was
#: itself the problem -- which would be worth knowing before reading anything
#: into the more elaborate shapes.
PLANS: list[BeaconPlan] = [
    BeaconPlan("empty", "a 200 with no body -- what a C2 with nothing to say "
                        "returns, and the likeliest thing to be tolerated",
               "text/html", _empty),
    BeaconPlan("ok", "a minimal token body, for a client testing for content "
                     "rather than parsing it", "text/plain", _ok),
    BeaconPlan("form_address", "form-encoded, mirroring the request's own "
                               "encoding", "application/x-www-form-urlencoded",
               _form_address),
    BeaconPlan("bare_address", "the address alone, no framing -- the same shape "
                               "that turned out to be right for getData()",
               "text/plain", _bare_address),
    BeaconPlan("json_address", "a JSON object carrying one address",
               "application/json", _json_address),
    BeaconPlan("json_wallets", "a JSON document replacing the substitution "
                               "table, which is what 'refresh' would mean",
               "application/json", _json_wallets),
]

PLANS_BY_NAME = {plan.name: plan for plan in PLANS}


class BeaconPlanner:
    """Chooses what to answer `refresh` with, and remembers what it said.

    Mirrors `jsonrpc_answer.AnswerPlanner` deliberately: same rotation rule,
    same pinning, same report shape, so a reader who has understood phase 2
    already understands this.
    """

    def __init__(self, address: str = TRACER_ADDRESS, plan: str = ""):
        if not _ADDRESS_RE.match(address):
            raise BeaconError(f"not a 20-byte hex address: {address!r}")
        self.address = address

        if plan:
            if plan not in PLANS_BY_NAME:
                raise BeaconError(
                    f"unknown plan {plan!r}; have {sorted(PLANS_BY_NAME)}")
            self.pinned: Optional[BeaconPlan] = PLANS_BY_NAME[plan]
        else:
            self.pinned = None

        self.served: list[str] = []

    def next_plan(self) -> BeaconPlan:
        if self.pinned is not None:
            return self.pinned
        index = min(len(self.served), len(PLANS) - 1)
        return PLANS[index]

    def answer(self) -> dict[str, Any]:
        plan = self.next_plan()
        body = plan.body(self.address)
        self.served.append(plan.name)
        return {
            "body": body,
            "content_type": plan.content_type,
            "plan": plan.name,
            "plan_why": plan.why,
            "attempt": len(self.served),
        }

    def report(self) -> dict[str, Any]:
        return {
            "mode": "answer",
            "address": self.address,
            "address_is_tracer": self.address == TRACER_ADDRESS,
            "pinned_plan": self.pinned.name if self.pinned else "",
            "plans_available": [p.describe() for p in PLANS],
            "plans_served": list(self.served),
            # **The reading that decides whether rotation was the right tool.**
            # One attempt means the implant did not retry, so this run tested a
            # single shape however many were on the list -- and the next run
            # must pin a different one rather than expecting a sweep.
            "attempts": len(self.served),
            "rotation_advanced": len(set(self.served)) > 1,
            "all_plans_exhausted": (self.pinned is None
                                    and len(self.served) >= len(PLANS)),
        }
