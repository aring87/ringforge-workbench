"""Build a corpus of real OpenAPI specifications, so `spec` can be measured.

`scripts/benign_rates.py --module spec` measured the specification categoriser
against nine local fixtures, five of them clean.
`unauthenticated_sensitive_endpoint` fired on four of the nine -- and the
fixtures were *written to be* a mix, so that fraction is a fact about the
fixture author, not about specifications. It is the same shape of sample the
extension scorer was nearly ruined by: fourteen installed extensions produced a
wrong conclusion and a wrong correction, and 394 random store extensions
overruled both.

APIs.guru is the analogue of the store sitemap. It publishes a public,
versioned directory of a few thousand real specifications -- `v2/list.json`,
one request, no key, no scraping -- with a JSON URL for every entry.

**The directory is not flat, and sampling it flat would repeat the mistake in a
new shape.** Of 2,529 entries, 653 are `azure.com` and the top ten providers
are 62% of the total. Those are machine-generated from one toolchain and all
look alike; a uniform sample of 300 entries would be a quarter Azure Resource
Manager, and the resulting rate would describe Microsoft's generator rather
than the population of specifications. So the sample is drawn over *providers*
-- `--per-provider` entries from each, one by default -- which turns 2,529
entries dominated by four vendors into 677 organisations that each count once.

**Sample randomly with a recorded seed.** `--seed` is what makes two
measurements comparable; `_sample.json` records it along with the provider
count and the cap, so the corpus can be rebuilt exactly or deliberately varied.

**Be polite.** APIs.guru is a small free service with no key and no quota to
hide behind. One request a second is minutes for a few hundred specs, and the
measurement is not more true for arriving sooner.

    .venv\\Scripts\\python.exe scripts\\spec_corpus.py --count 300 --out G:\\spec-corpus
    .venv\\Scripts\\python.exe scripts\\benign_rates.py --module spec --specs G:\\spec-corpus

Runs on the HOST. These are public API documents, not malware, and none of
this belongs on the analysis guest.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

LIST_URL = "https://api.apis.guru/v2/list.json"

USER_AGENT = "Mozilla/5.0 (compatible; ringforge-corpus/1.0)"

#: Directory keys look like `azure.com:advisor` -- provider, then API name.
#: Everything outside this set becomes `_` so the key can name a file.
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _encode(url: str) -> str:
    """Percent-encode the path, which the directory does not do for us.

    `ljaero.com` publishes its version as `V 1.0.0`, and APIs.guru builds the
    URL straight from it -- `/v2/specs/ljaero.com/dflight/V 1.0.0/openapi.json`.
    `http.client` refuses a request line containing a space, which took the
    whole run down on entry 47 rather than costing one specification.
    """
    parts = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((
        parts.scheme, parts.netloc,
        urllib.parse.quote(parts.path, safe="/%"),
        urllib.parse.quote(parts.query, safe="=&%"), parts.fragment))


def _fetch(url: str, timeout: int = 60) -> bytes:
    request = urllib.request.Request(_encode(url),
                                     headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def slug(api_key: str) -> str:
    """A filesystem-safe name that still reads as the API it came from."""
    return _UNSAFE.sub("_", api_key).strip("._-")[:120] or "unnamed"


def preferred_entry(record: dict[str, Any]) -> dict[str, Any] | None:
    """The version APIs.guru itself points at, falling back to any version."""
    versions = record.get("versions")
    if not isinstance(versions, dict) or not versions:
        return None
    chosen = versions.get(record.get("preferred"))
    if not isinstance(chosen, dict):
        chosen = next((v for v in versions.values() if isinstance(v, dict)), None)
    return chosen


def by_provider(directory: dict[str, Any]) -> dict[str, list[tuple[str, dict[str, Any]]]]:
    """Group the directory by publishing organisation.

    The provider is the part of the key before the colon -- `azure.com` for all
    653 of its entries. Grouping is what lets the sample be drawn over
    organisations rather than over one vendor's generator output.
    """
    groups: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for api_key, record in sorted(directory.items()):
        if not isinstance(record, dict):
            continue
        entry = preferred_entry(record)
        if not entry or not entry.get("swaggerUrl"):
            continue
        groups.setdefault(api_key.split(":", 1)[0], []).append((api_key, entry))
    return groups


def choose(groups: dict[str, list[tuple[str, dict[str, Any]]]], count: int,
           per_provider: int, rng: random.Random) -> list[tuple[str, dict[str, Any]]]:
    """`per_provider` entries from each of as many providers as it takes.

    The providers are shuffled rather than sampled to a fixed size, because a
    provider may carry fewer than `per_provider` entries; walking a shuffled
    list until the quota is met reaches the requested count without letting a
    large provider backfill for a small one.
    """
    providers = list(groups)
    rng.shuffle(providers)
    picked: list[tuple[str, dict[str, Any]]] = []
    for provider in providers:
        entries = groups[provider]
        for item in rng.sample(entries, min(per_provider, len(entries))):
            if len(picked) >= count:
                return picked
            picked.append(item)
    return picked


def download(api_key: str, entry: dict[str, Any], out_dir: Path,
             overwrite: bool = False) -> str:
    """Fetch one specification as JSON. Returns a one-word outcome."""
    target = out_dir / (slug(api_key) + ".json")
    if target.exists() and not overwrite:
        return "skipped"
    try:
        data = _fetch(str(entry["swaggerUrl"]))
    except urllib.error.HTTPError as error:
        # An ordinary outcome rather than a failure: the directory is a
        # snapshot and entries are withdrawn.
        return "http" + str(error.code)
    except (urllib.error.URLError, OSError, ValueError) as error:
        # `ValueError` covers `http.client.InvalidURL` and its siblings. One
        # malformed entry in a public directory is a fact about the directory;
        # it should cost that specification and not the other 299.
        return "unreachable" if not isinstance(error, ValueError) else "bad-url"

    # Parse before writing. `--specs` globs `*.json` and hands every match to
    # the analyser; a truncated download saved under a `.json` name would come
    # back with a non-zero returncode, be silently dropped by the measurement
    # loop, and quietly shrink the corpus without shrinking the count reported
    # for it.
    try:
        parsed = json.loads(data.decode("utf-8", "replace"))
    except ValueError:
        return "unparseable"
    if not isinstance(parsed, dict) or not isinstance(parsed.get("paths"), dict):
        return "no-paths"

    target.write_bytes(data)
    return "ok"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, help="corpus directory")
    parser.add_argument("--count", type=int, default=300,
                        help="how many specifications to fetch")
    parser.add_argument("--per-provider", type=int, default=1,
                        help="entries taken from each provider; 1 keeps "
                             "azure.com from being a quarter of the sample")
    parser.add_argument("--seed", type=int, default=20260826,
                        help="fixed so the sample is reproducible; two "
                             "measurements are only comparable if they can be")
    parser.add_argument("--delay", type=float, default=1.0,
                        help="seconds between requests to APIs.guru")
    parser.add_argument("--overwrite", action="store_true",
                        help="re-download specifications already present")
    parser.add_argument("--list-only", action="store_true",
                        help="choose the sample, download nothing")
    args = parser.parse_args(argv)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("Reading the APIs.guru directory (" + LIST_URL + ")...")
    try:
        directory = json.loads(_fetch(LIST_URL).decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, ValueError) as error:
        print("failed: could not read the directory (" + str(error) + ")")
        return 1
    if not isinstance(directory, dict) or not directory:
        print("failed: the directory was empty -- its format may have changed")
        return 1

    groups = by_provider(directory)
    print(f"  {len(directory)} entries from {len(groups)} providers")
    biggest = sorted(groups.items(), key=lambda kv: -len(kv[1]))[:5]
    print("  largest: " + ", ".join(f"{p} {len(e)}" for p, e in biggest))

    rng = random.Random(args.seed)
    sample = choose(groups, args.count, args.per_provider, rng)
    if not sample:
        print("failed: no entry carried a spec URL -- the format may have changed")
        return 1

    providers = sorted({k.split(":", 1)[0] for k, _ in sample})
    (out_dir / "_sample.json").write_text(json.dumps({
        "source": LIST_URL,
        "seed": args.seed,
        "per_provider": args.per_provider,
        "directory_entries": len(directory),
        "directory_providers": len(groups),
        "sampled": len(sample),
        "providers": len(providers),
        "apis": [{"key": k, "version": e.get("openapiVer", ""),
                  "url": e.get("swaggerUrl", "")} for k, e in sample],
    }, indent=2), encoding="utf-8")
    print(f"  sampled {len(sample)} specs from {len(providers)} providers, "
          f"seed {args.seed} -> {out_dir / '_sample.json'}")

    if args.list_only:
        return 0

    print(f"Downloading at {args.delay}s intervals. Ctrl-C is safe; re-running "
          f"resumes.")
    outcomes: dict[str, int] = {}
    for index, (api_key, entry) in enumerate(sample, 1):
        outcome = download(api_key, entry, out_dir, overwrite=args.overwrite)
        outcomes[outcome] = outcomes.get(outcome, 0) + 1
        if index % 25 == 0 or index == len(sample):
            print(f"  {index}/{len(sample)}  " +
                  ", ".join(f"{k} {v}" for k, v in sorted(outcomes.items())))
        if outcome != "skipped":
            time.sleep(args.delay)

    # `_sample.json` lives here too and is not a specification.
    have = [p for p in out_dir.glob("*.json") if p.name != "_sample.json"]
    print()
    print(f"corpus: {len(have)} specifications in {out_dir}")
    print("Measure it with:")
    print("    .venv\\Scripts\\python.exe scripts\\benign_rates.py "
          "--module spec --specs " + str(out_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
