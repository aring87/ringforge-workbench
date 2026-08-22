"""Phase 2 of `0bw`: answering `getData()` without knowing what it returns.

Phase 1 records the request. This encodes the reply -- and it is written before
phase 1 has run, which the design has to account for rather than pretend away.
What is unknown is not the *request* (phase 1 reads that) but the **return
shape**: `getData()`'s ABI signature is nowhere in the binary, only the
implant's parser, and nothing has read its expectations.

**So this does not encode one guess. It enumerates them.** The plausible shapes
are few and nameable -- an `address`, a `string` holding one, a JSON blob, raw
`bytes`, or a bare hex result with no ABI framing at all -- and the space is
small enough to sweep in a single run rather than argue about.

**Rotation advances only on retry, which is the whole trick.** The first call
gets the first plan. If the implant accepts it and proceeds, the run is over and
the answer is that plan; if it rejects it and asks again, the next call gets the
next plan. Acceptance and rejection are therefore both visible in the same log,
and one guest run tests every hypothesis instead of one. `--plan` pins a single
shape for a focused re-run once the answer is known.

**The served address is a tracer, and that is deliberate.** It defaults to an
obviously synthetic value rather than anything live, so that finding it in a
clipboard, a dump or a beacon is unambiguous proof of substitution rather than
something that has to be argued from context. **Never point this at a real
address**: the entire safety argument for a responder is that the operator
chooses the C2 and points it at a sink.

The beacon is not handled here. `method=refresh&guid=` and
`method=send&guid=&address=` are ordinary form-encoded POSTs, and FakeNet's HTTP
listener already writes those out under `DumpHTTPPosts`, which is on in the
stock config. Building a second path for them would be duplicating a collector
that already works.
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Optional

#: The default substitution address served to the implant.
#:
#: Synthetic on purpose and shaped to be unmistakable in a hex dump, a clipboard
#: or a beacon body. It is not a real wallet and must never be replaced with
#: one; `--address` exists for pointing at an operator-controlled sink, not for
#: making the run more realistic.
TRACER_ADDRESS = "0xC0FFEE0000000000000000000000000000C0FFEE"

#: The host served by the URL-bearing shapes.
#:
#: **Reserved TLD on purpose.** `.test` is RFC 2606 and can never be
#: registered, so a shape that escapes the guest cannot reach anyone; and
#: FakeNet answers every name locally anyway, so plausibility buys nothing.
#: `c0ffee` keeps it greppable in a beacon body, exactly like the address
#: tracer.
SINK_HOST = "c0ffee-sink.ringforge.test"

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


class AnswerError(ValueError):
    """Raised for a request this module refuses to encode."""


# -- ABI encoding ---------------------------------------------------------
#
# Written out rather than pulled from a dependency. The encoding is forty lines,
# the guest has no web3 installed, and a bench that needs a package manager to
# answer one call is a bench that stops working after a revert.


def _pad32(raw: bytes) -> bytes:
    """Right-pad to a 32-byte boundary, as the ABI requires for tail data."""
    remainder = len(raw) % 32
    return raw if remainder == 0 else raw + b"\x00" * (32 - remainder)


def _word(value: int) -> bytes:
    return value.to_bytes(32, "big")


def encode_address(address: str) -> bytes:
    """A 32-byte word, left-padded, low 20 bytes the address."""
    if not _ADDRESS_RE.match(address):
        raise AnswerError(f"not a 20-byte hex address: {address!r}")
    return b"\x00" * 12 + bytes.fromhex(address[2:])


def encode_bytes(raw: bytes) -> bytes:
    """A dynamic `bytes`, as the sole return value: offset, length, data."""
    return _word(0x20) + _word(len(raw)) + _pad32(raw)


def encode_string(text: str) -> bytes:
    """A dynamic `string`. Identical framing to `bytes`, utf-8 payload."""
    return encode_bytes(text.encode("utf-8"))


def to_hex(raw: bytes) -> str:
    return "0x" + raw.hex()


# -- the candidate shapes -------------------------------------------------


class AnswerPlan:
    """One hypothesis about what `getData()` returns.

    `why` is carried because the log is what a later session reads, and "plan 3
    was accepted" means nothing without the reason plan 3 existed.
    """

    def __init__(self, name: str, why: str, encode: Callable[[str, str], str]):
        self.name = name
        self.why = why
        self._encode = encode

    def result(self, address: str, host: str = SINK_HOST) -> str:
        # Both are passed to every shape. What `getData()` returns is still
        # unknown -- run `20260822_141514` showed it is not an address in any of
        # three encodings -- so a shape must be free to use either.
        return self._encode(address, host)

    def describe(self) -> dict[str, str]:
        return {"name": self.name, "why": self.why}


def _plan_address(address: str, host: str) -> str:
    return to_hex(encode_address(address))


def _plan_string_address(address: str, host: str) -> str:
    return to_hex(encode_string(address))


def _plan_string_json(address: str, host: str) -> str:
    # EtherHiding payloads are commonly a blob the implant parses rather than a
    # single typed value. The key names are a guess and are meant to be; what is
    # being tested is whether the parser wants a JSON document at all.
    return to_hex(encode_string(json.dumps({"eth": address, "address": address})))


def _plan_bytes_ascii(address: str, host: str) -> str:
    return to_hex(encode_bytes(address.encode("ascii")))


def _plan_raw_hex(address: str, host: str) -> str:
    # No ABI framing whatsoever: the result is the address, as a node would
    # never return it for a typed getter. Included because a hand-rolled client
    # that does its own slicing may not implement the ABI at all, and this is
    # the cheapest hypothesis to be wrong about.
    return address


def _plan_url_https(address: str, host: str) -> str:
    return to_hex(encode_string(f"https://{host}/"))


def _plan_bare_host(address: str, host: str) -> str:
    return to_hex(encode_string(host))


def _plan_json_c2(address: str, host: str) -> str:
    # Field names are a guess and meant to be. What is under test is whether the
    # parser wants a *document describing a C2* at all, not these key names.
    return to_hex(encode_string(json.dumps({
        "url": f"https://{host}/", "host": host, "address": address,
    })))


#: Ordered. The first is served first, and the order is roughly cheapest-to-
#: most-elaborate rather than most-to-least likely -- a wrong early guess costs
#: one retry, and the implant retrying is itself the signal that advances.
PLANS: list[AnswerPlan] = [
    AnswerPlan("address", "getData() returns a bare address; the config block "
                          "carries no EVM destination, so an address is the "
                          "minimum it must fetch", _plan_address),
    AnswerPlan("string_address", "returns the address as an ASCII string, the "
                                 "usual EtherHiding payload shape",
               _plan_string_address),
    AnswerPlan("string_json", "returns a JSON config blob the implant parses "
                              "for its fields", _plan_string_json),
    AnswerPlan("bytes_ascii", "returns dynamic bytes holding the address text",
               _plan_bytes_ascii),
    AnswerPlan("raw_hex", "no ABI framing at all -- a client doing its own "
                          "slicing", _plan_raw_hex),
    # **Added 22 Aug, and they are now the likelier half.** Run
    # `20260822_141514` served three address shapes and the implant rejected all
    # three, then stopped asking. Meanwhile the EVM wallet turned out to be
    # hardcoded alongside sixteen others, and substitution was observed working
    # *without* any successful fetch -- so `getData()` is not delivering a
    # substitution address. The beacon has no host anywhere in the config block,
    # which makes a C2 endpoint the thing still missing.
    AnswerPlan("url_https", "returns an https:// URL -- the beacon has no host "
                            "in the config block, so this is what it lacks",
               _plan_url_https),
    AnswerPlan("bare_host", "returns just the hostname, the implant supplying "
                            "scheme and path itself", _plan_bare_host),
    AnswerPlan("json_c2", "returns a document describing a C2 rather than a "
                          "single value", _plan_json_c2),
]

PLANS_BY_NAME = {plan.name: plan for plan in PLANS}


class AnswerPlanner:
    """Chooses which shape to serve, and remembers what it served.

    One instance per run. Held by `RequestRecorder`, which takes the lock, so
    this does no locking of its own.
    """

    def __init__(self, address: str = TRACER_ADDRESS, plan: str = "",
                 sink_host: str = SINK_HOST):
        if not _ADDRESS_RE.match(address):
            raise AnswerError(f"not a 20-byte hex address: {address!r}")
        self.address = address
        self.sink_host = sink_host or SINK_HOST

        if plan:
            if plan not in PLANS_BY_NAME:
                raise AnswerError(
                    f"unknown plan {plan!r}; have {sorted(PLANS_BY_NAME)}")
            self.pinned: Optional[AnswerPlan] = PLANS_BY_NAME[plan]
        else:
            self.pinned = None

        self.served: list[str] = []

    def next_plan(self) -> AnswerPlan:
        """The plan for the next target call.

        Pinned mode serves one shape forever. Rotation walks the list and then
        holds on the last rather than cycling: a client still asking after every
        hypothesis has been tried is telling you the list is wrong, and cycling
        would bury that under repetition.
        """
        if self.pinned is not None:
            return self.pinned
        index = min(len(self.served), len(PLANS) - 1)
        return PLANS[index]

    def answer(self, address: Optional[str] = None) -> dict[str, Any]:
        """Encode the next answer and record which hypothesis it was."""
        plan = self.next_plan()
        result = plan.result(address or self.address, self.sink_host)
        self.served.append(plan.name)
        return {
            "result": result,
            "plan": plan.name,
            "plan_why": plan.why,
            "attempt": len(self.served),
            "exhausted": self.pinned is None and len(self.served) >= len(PLANS),
        }

    def report(self) -> dict[str, Any]:
        return {
            "mode": "answer",
            "address": self.address,
            "address_is_tracer": self.address == TRACER_ADDRESS,
            "sink_host": self.sink_host,
            "sink_host_is_default": self.sink_host == SINK_HOST,
            "pinned_plan": self.pinned.name if self.pinned else "",
            "plans_available": [plan.describe() for plan in PLANS],
            "plans_served": list(self.served),
            # The reading that matters. One plan served and then silence means
            # that plan was accepted; every plan served means none were, and the
            # list is the thing that is wrong.
            "all_plans_exhausted": (self.pinned is None
                                    and len(self.served) >= len(PLANS)),
        }
