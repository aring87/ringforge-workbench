"""Ask MalwareBazaar about one signature and print what it actually says.

`malware_corpus.py` prints only `query_status`, so a failure reads as the bare
word `error` with no way to tell a wrong name from a refused query from a
server-side problem. This makes one request and shows the response.

**It downloads no malware.** `get_siginfo` returns metadata -- hashes, file
types, first-seen dates -- and this prints a summary of that, never a sample.
It is the diagnostic half of the fetch, which is why it is safe to run when
the fetch itself is not.

    .venv\\Scripts\\python.exe scripts\\probe_signature.py AgentTesla
    .venv\\Scripts\\python.exe scripts\\probe_signature.py AgentTesla --limit 1
    .venv\\Scripts\\python.exe scripts\\probe_signature.py Formbook Smokeloader QakBot

One request per signature, one second apart, because the same rate limit
applies here as anywhere.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.malware_corpus import _key, _post  # noqa: E402


#: `get_siginfo` times out server-side on the largest families -- measured
#: 23 Sep: AgentTesla and Formbook both answer "Query execution time exceeded
#: threshold. Try a different query." even at limit 3, so it is not the size
#: being asked for. Tags are a different index, and MalwareBazaar tags those
#: same samples with the family name, so `get_taginfo` is the different query
#: its own error message asks for.
QUERIES = {
    "get_siginfo": "signature",
    "get_taginfo": "tag",
}


def probe(key: str, signature: str, limit: int, query: str) -> None:
    field = QUERIES[query]
    print(f"=== {signature}  ({query}, {field}, limit {limit})")
    try:
        raw = _post(key, {"query": query, field: signature,
                          "limit": str(limit)})
    except Exception as error:                        # noqa: BLE001
        print(f"  request failed: {type(error).__name__}: {error}")
        return

    text = raw.decode("utf-8", "replace")
    try:
        payload = json.loads(text)
    except ValueError:
        print(f"  not JSON, {len(raw)} bytes: {text[:300]}")
        return

    status = payload.get("query_status")
    print(f"  query_status : {status!r}")

    # Everything the response carries other than the sample list, which is
    # where an explanation lives when there is one.
    extra = {k: v for k, v in payload.items() if k != "data"}
    if len(extra) > 1:
        print(f"  other fields : {json.dumps(extra)[:400]}")

    rows = payload.get("data")
    if isinstance(rows, list):
        print(f"  rows         : {len(rows)}")
        for row in rows[:3]:
            if isinstance(row, dict):
                print(f"    {row.get('sha256_hash','?')[:16]}  "
                      f"{str(row.get('file_type')):5}  "
                      f"{row.get('signature')}  {row.get('first_seen')}")
    elif rows is not None:
        print(f"  data         : {type(rows).__name__}  {str(rows)[:200]}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("signatures", nargs="+")
    parser.add_argument("--limit", type=int, default=5,
                        help="how many rows to ask for (default 5, small on "
                             "purpose -- this is a probe, not a fetch)")
    parser.add_argument("--delay", type=float, default=1.0)
    parser.add_argument("--key", default="")
    parser.add_argument("--key-file", default="")
    parser.add_argument("--query", default="get_siginfo",
                        choices=sorted(QUERIES),
                        help="which index to ask; get_siginfo times out on "
                             "the largest families")
    args = parser.parse_args(argv)

    key = _key(args)
    if not key:
        print("failed: no API key. Set ABUSE_CH_API_KEY.")
        return 1

    for position, signature in enumerate(args.signatures):
        if position:
            time.sleep(args.delay)
        probe(key, signature, args.limit, args.query)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
