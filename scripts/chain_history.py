"""Who deployed the EtherHiding contract, and when -- `0bw`, the last open read.

The 24 Aug chain read got everything except this. `getData()` still returns
`klopasnarhia.cc`, the contract is live at 2,008 bytes with a zero balance, and
the string sits in storage slot 0 in Solidity short-string form -- so rotation is
one `SSTORE` against selector `0x47064d6a`, with no redeploy and nothing the
malware would notice. What could not be obtained was the deployment: the public
node prunes historical state and refuses `eth_getLogs` over wide ranges.

**Two routes, and which one answered is part of the answer.** An explorer's
`getcontractcreation` is a claim by Etherscan; a binary search on `eth_getCode`
is a measurement against whatever node you pointed at. They are different
provenance and the case notes should say which, for the same reason the dynamic
side distinguishes a Sysmon-recorded injection from one inferred from a crash.

**No key is not "no history found".** A collector that cannot run says so and
exits non-zero. Returning an empty result here would read exactly like a
contract with no deployment record, which is the failure this whole model exists
to prevent.

    .venv\\Scripts\\python.exe scripts\\chain_history.py
    .venv\\Scripts\\python.exe scripts\\chain_history.py --rpc https://... --no-explorer

Runs on the HOST. It needs the real internet, and the guest is contained.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any

#: The `0bw` contract, from the `eth_call` captured on the wire.
DEFAULT_CONTRACT = "0x4E31128a13AcBD1cF1909D67F072460c853F87f7"

#: BNB Smart Chain Testnet. Confirmed present and `status 1` in Etherscan's V2
#: chain list on 24 Aug, so one Etherscan key covers it -- the per-explorer
#: BscScan keys were consolidated into the multichain API.
DEFAULT_CHAIN_ID = 97

EXPLORER_URL = "https://api.etherscan.io/v2/api"

#: The node the implant itself used. Fine for `eth_getCode` at the head, and the
#: reason the binary search usually fails: it prunes.
DEFAULT_RPC = "https://data-seed-prebsc-1-s1.binance.org:8545"

KEY_ENV = "RINGFORGE_ETHERSCAN_KEY"


class ChainError(RuntimeError):
    pass


def _get(url: str, timeout: int = 30) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"User-Agent": "ringforge/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8", "replace"))


def _rpc(url: str, method: str, params: list[Any], timeout: int = 30,
         attempts: int = 4) -> Any:
    """One JSON-RPC call, retried on transport failure but not on a JSON error.

    **The distinction is the point.** A 500 from a shared public endpoint is
    noise and retrying costs a second; a `missing trie node` in the JSON body is
    the node telling you it does not have the state, and retrying that would
    turn a clear refusal into a slow one. Only the first is retried.
    """
    payload = json.dumps({"jsonrpc": "2.0", "id": 1,
                          "method": method, "params": params}).encode()
    request = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json",
                 "User-Agent": "ringforge/1.0"})

    last: Exception | None = None
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = json.loads(response.read().decode("utf-8", "replace"))
        except (urllib.error.HTTPError, urllib.error.URLError, OSError) as error:
            last = error
            time.sleep(0.5 * (2 ** attempt))
            continue
        if "error" in body:
            raise ChainError(f"{method}: {body['error']}")
        return body.get("result")

    raise ChainError(f"{method}: {attempts} attempts failed, last was {last}")


def explorer_creation(contract: str, chain_id: int, key: str) -> dict[str, Any]:
    """Ask the explorer who deployed it.

    One request, and it returns what a binary search cannot: the transaction
    hash, which is the thing that leads anywhere else.
    """
    url = (f"{EXPLORER_URL}?chainid={chain_id}&module=contract"
           f"&action=getcontractcreation&contractaddresses={contract}"
           f"&apikey={key}")
    body = _get(url)

    status = str(body.get("status", ""))
    message = str(body.get("message", ""))
    result = body.get("result")

    # **Etherscan reports "no data" and "we refused you" identically**: status 0
    # with a human-readable message. Telling them apart is the whole job here.
    # One is an answer about the contract; the other is a collector that did not
    # run, and reporting the second as the first is how a paid-plan wall ends up
    # filed as "this contract has no deployment record".
    #
    # Chain 97 is in the V2 chain list at `status 1` -- which means the endpoint
    # is up, not that it is on the free tier. It is not. That refusal arrives
    # here, and an earlier version of this check let it through as an answer.
    REFUSALS = (
        "invalid api key",
        "rate limit",
        "not supported for this chain",
        "upgrade your api plan",
        "missing or unsupported chainid",
        "max calls per sec",
    )
    if status != "1" or not isinstance(result, list) or not result:
        detail = result if isinstance(result, str) else message
        lowered = str(detail).lower()
        if any(marker in lowered for marker in REFUSALS):
            raise ChainError(f"explorer refused the request: {detail}")
        return {"found": False, "note": str(detail) or "no creation record"}

    entry = result[0]
    return {
        "found": True,
        "deployer": entry.get("contractCreator", ""),
        "creation_tx": entry.get("txHash", ""),
        "block": entry.get("blockNumber", ""),
        "timestamp": entry.get("timestamp", ""),
    }


def binary_search_creation(contract: str, rpc: str,
                           status=lambda _msg: None) -> dict[str, Any]:
    """Find the first block where the contract had code.

    **Needs an archive node.** A pruning node answers `eth_getCode` for recent
    blocks and returns `0x` for old ones whether or not the contract existed
    then, which makes the search converge confidently on the pruning horizon
    rather than on the deployment. The control below is what catches that: if
    the contract reads as absent at a block where it demonstrably existed, the
    node cannot answer this question and the result is refused rather than
    reported.
    """
    head = int(_rpc(rpc, "eth_blockNumber", []), 16)
    code_at_head = _rpc(rpc, "eth_getCode", [contract, hex(head)])
    if code_at_head in (None, "0x"):
        raise ChainError(
            f"no code at head block {head}: the contract is not deployed on "
            f"this chain, or this RPC is not the chain it was deployed on")

    # --- The control, and it samples the whole range on purpose ------------
    #
    # **A partial archive passes a one-block check and fails the search.** The
    # first version of this probed block 1 only. `bsc-testnet.drpc.org` answers
    # block 1 happily -- genesis-adjacent state is cheap to keep -- and then
    # threw `historical state ... is not available` nine probes into the bisect,
    # around block 81,000,000. The control has to exercise the state the search
    # will actually walk, or it is a control in name only.
    #
    # This is the same mistake this bench keeps finding elsewhere, in a new
    # place: a negative result is not evidence until the collector that produced
    # it has been shown capable of a positive *over the range that matters*.
    samples = sorted({1, 2}
                     | {head * n // 8 for n in range(1, 8)}
                     | {head - 1})
    for block in samples:
        try:
            probe = _rpc(rpc, "eth_getCode", [contract, hex(block)])
        except ChainError as error:
            raise ChainError(
                f"the node has no state at block {block} ({error}). It answers "
                f"some historical queries and not others -- a partial archive, "
                f"which cannot answer this. A full archive node is required."
            ) from None
        if block <= 2 and probe not in (None, "0x"):
            raise ChainError(
                f"the node reports code at block {block}, which is impossible; "
                f"its historical answers are not trustworthy")

    low, high = 1, head
    probes = 0
    while low < high:
        mid = (low + high) // 2
        probes += 1
        status(f"probe {probes}: block {mid} (range {low}-{high})")
        code = _rpc(rpc, "eth_getCode", [contract, hex(mid)])
        if code in (None, "0x"):
            low = mid + 1
        else:
            high = mid
        time.sleep(0.1)

    return {"found": True, "block": low, "probes": probes,
            "deployer": "", "creation_tx": "",
            "note": "block only -- eth_getCode cannot name the deployer or the "
                    "transaction; that needs the explorer or eth_getLogs"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--contract", default=DEFAULT_CONTRACT)
    parser.add_argument("--chain-id", type=int, default=DEFAULT_CHAIN_ID)
    parser.add_argument("--rpc", default=DEFAULT_RPC,
                        help="node for the fallback search; must be an archive "
                             "node for it to mean anything")
    parser.add_argument("--no-explorer", action="store_true",
                        help="skip the explorer and measure against --rpc")
    parser.add_argument("--out", default="",
                        help="write the result as JSON here")
    args = parser.parse_args(argv)

    record: dict[str, Any] = {
        "contract": args.contract,
        "chain_id": args.chain_id,
        "route": "",
        "provenance": "",
    }

    if not args.no_explorer:
        key = os.environ.get(KEY_ENV, "").strip()
        if not key:
            print(f"failed: {KEY_ENV} is not set.")
            print()
            print("This is a missing collector, not an empty result. Set the")
            print("key and run again, or pass --no-explorer to measure against")
            print("an archive node instead:")
            print(f'    $env:{KEY_ENV} = "<key>"')
            return 2
        if len(key) < 20:
            # The placeholder-paste case. A 3-character key would otherwise
            # produce "invalid api key", which reads like an account problem.
            print(f"failed: {KEY_ENV} is {len(key)} characters, which is not an "
                  f"Etherscan key (they are 34).")
            return 2

        try:
            found = explorer_creation(args.contract, args.chain_id, key)
        except (ChainError, urllib.error.URLError, OSError) as error:
            print(f"explorer route failed: {error}")
            print("Falling back to eth_getCode against --rpc.")
        else:
            record.update(found)
            record["route"] = "etherscan-v2"
            record["provenance"] = (
                "Etherscan's record of the deployment, not a measurement made "
                "here. Trustworthy for the transaction hash; confirm the "
                "deployer against the transaction if it matters.")
            _report(record, args.out)
            return 0

    try:
        found = binary_search_creation(args.contract, args.rpc,
                                       status=lambda m: print(f"  {m}"))
    except (ChainError, urllib.error.URLError, OSError) as error:
        print(f"failed: {error}")
        return 1

    record.update(found)
    record["route"] = "eth_getCode-bisect"
    record["rpc"] = args.rpc
    record["provenance"] = (
        "Measured here against the named node, with a block-1 control proving "
        "the node answers historical queries. The block is solid; the deployer "
        "and the transaction are not available by this route.")
    _report(record, args.out)
    return 0


def _report(record: dict[str, Any], out: str) -> None:
    print()
    for field in ("contract", "chain_id", "route", "found", "deployer",
                  "creation_tx", "block", "timestamp", "probes", "note"):
        if field in record and record[field] not in ("", None):
            print(f"{field:12}: {record[field]}")
    print()
    print(f"provenance  : {record['provenance']}")
    if out:
        with open(out, "w", encoding="utf-8") as handle:
            json.dump(record, handle, indent=2)
        print(f"written     : {out}")


if __name__ == "__main__":
    raise SystemExit(main())
