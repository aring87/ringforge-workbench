"""Build a corpus of real browser extensions, so the scorer can be measured.

`scripts/benign_rates.py` measured the extension categoriser against the
fourteen extensions installed on this machine. Four of them reached the top
band, and the finding was that the five categories are facets of one property
rather than independent kinds of evidence. **That is a suspicion, not a
measurement**, because fourteen is small enough to fit any conclusion --
and it is why tuning stopped there rather than continuing until the number
looked acceptable.

This makes the measurement possible. The store publishes its own catalogue:
`robots.txt` declares a sitemap, the sitemap indexes forty shards, and shard 0
alone carries 8,920 extension IDs -- roughly 357,000 in total. Downloading one
is a single request to the update endpoint.

**Sample randomly, never the first N.** The sitemap is ordered, so the head of
it is correlated with whatever the ordering is -- the IDs in shard 0 all begin
`dolp`. A rate computed over the first three hundred would be a rate about the
alphabet. `--seed` makes the sample reproducible, which is what lets two
measurements be compared.

**Be polite.** This is Google's endpoint and there is no reason to hurry: a few
hundred extensions at one request a second is minutes, and the measurement is
not more true for arriving sooner.

    .venv\\Scripts\\python.exe scripts\\extension_corpus.py --count 300 --out G:\\ext-corpus
    .venv\\Scripts\\python.exe scripts\\benign_rates.py --module extension --corpus G:\\ext-corpus

Runs on the HOST. Extensions are ordinary store software, not malware, and none
of this belongs on the analysis guest.
"""

from __future__ import annotations

import argparse
import io
import json
import random
import re
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Iterable

SITEMAP = "https://chromewebstore.google.com/sitemap"

#: The update endpoint a browser itself uses. `prodversion` only has to be
#: plausible; the store checks it is recent enough, not that it is real.
CRX_URL = ("https://clients2.google.com/service/update2/crx"
           "?response=redirect&acceptformat=crx2,crx3"
           "&prodversion={version}&x=id%3D{extension_id}%26uc")

DEFAULT_PRODVERSION = "120.0"

USER_AGENT = "Mozilla/5.0 (compatible; ringforge-corpus/1.0)"

#: Extension IDs are 32 characters from `a`-`p`.
_ID = re.compile(r"/detail/[^/]+/([a-p]{32})")


def _fetch(url: str, timeout: int = 45) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def shard_urls() -> list[str]:
    index = _fetch(SITEMAP).decode("utf-8", "replace")
    return re.findall(r"<loc>([^<]+)</loc>", index)


def ids_from_shards(shards: Iterable[str], delay: float,
                    log=print) -> list[str]:
    """Every extension ID in the named shards, de-duplicated, order preserved."""
    seen: dict[str, None] = {}
    for url in shards:
        try:
            body = _fetch(url).decode("utf-8", "replace")
        except (urllib.error.URLError, OSError) as error:
            log(f"  shard failed, skipping: {url} ({error})")
            continue
        found = _ID.findall(body)
        for extension_id in found:
            seen.setdefault(extension_id, None)
        log(f"  {url.rsplit('=', 1)[-1]:>3}: {len(found):>6} ids "
            f"({len(seen)} unique so far)")
        time.sleep(delay)
    return list(seen)


def unpack_crx(data: bytes, into: Path) -> bool:
    """A CRX is a zip behind a header. Returns False for anything unreadable.

    Lifted from `gui/extension_window._extract_crx`, which is where this logic
    has lived -- inside a Tkinter window, unreachable by anything else. It
    belongs in the engine and this is the second caller that needed it.
    """
    if len(data) < 16 or data[:4] != b"Cr24":
        return False
    version = int.from_bytes(data[4:8], "little")
    if version == 2:
        pub_len = int.from_bytes(data[8:12], "little")
        sig_len = int.from_bytes(data[12:16], "little")
        start = 16 + pub_len + sig_len
    elif version == 3:
        start = 12 + int.from_bytes(data[8:12], "little")
    else:
        return False

    try:
        with zipfile.ZipFile(io.BytesIO(data[start:])) as archive:
            into.mkdir(parents=True, exist_ok=True)
            # **Guard the paths.** A zip entry may name `../` and this is
            # untrusted software from the open internet, unpacked in bulk with
            # nobody watching. `extractall` alone would be a directory
            # traversal waiting for one malicious member.
            root = into.resolve()
            for member in archive.infolist():
                if member.is_dir():
                    continue
                target = (root / member.filename).resolve()
                if not str(target).startswith(str(root)):
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as source, open(target, "wb") as sink:
                    sink.write(source.read())
    except (zipfile.BadZipFile, OSError, ValueError):
        return False
    return True


def download(extension_id: str, out_dir: Path, version: str,
             keep_crx: bool = False) -> str:
    """Fetch and unpack one extension. Returns a one-word outcome."""
    target = out_dir / extension_id
    if (target / "manifest.json").exists():
        return "skipped"
    try:
        data = _fetch(CRX_URL.format(version=version, extension_id=extension_id))
    except urllib.error.HTTPError as error:
        # 404 is an ordinary outcome, not a failure: extensions are delisted,
        # and the sitemap is a snapshot.
        return f"http{error.code}"
    except (urllib.error.URLError, OSError):
        return "unreachable"

    if keep_crx:
        (out_dir / f"{extension_id}.crx").write_bytes(data)
    if not unpack_crx(data, target):
        return "unreadable"
    return "ok" if (target / "manifest.json").exists() else "no-manifest"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, help="corpus directory")
    parser.add_argument("--count", type=int, default=300)
    parser.add_argument("--shards", type=int, default=6,
                        help="how many sitemap shards to sample IDs from")
    parser.add_argument("--seed", type=int, default=20260825,
                        help="fixed so the sample is reproducible; two "
                             "measurements are only comparable if they can be")
    parser.add_argument("--delay", type=float, default=1.0,
                        help="seconds between requests to the store")
    parser.add_argument("--prodversion", default=DEFAULT_PRODVERSION)
    parser.add_argument("--keep-crx", action="store_true")
    parser.add_argument("--ids-only", action="store_true",
                        help="collect and sample IDs, download nothing")
    args = parser.parse_args(argv)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("Reading the store's own sitemap index...")
    try:
        shards = shard_urls()
    except (urllib.error.URLError, OSError) as error:
        print(f"failed: could not read {SITEMAP} ({error})")
        return 1
    print(f"  {len(shards)} shards published")

    rng = random.Random(args.seed)
    chosen = rng.sample(shards, min(args.shards, len(shards)))
    print(f"Sampling IDs from {len(chosen)} shards, seed {args.seed}:")
    ids = ids_from_shards(chosen, args.delay)
    if not ids:
        print("failed: no extension IDs found -- the sitemap format may have changed")
        return 1

    # **Random, not the head.** The IDs in a shard share a prefix; the first
    # three hundred of them would measure the alphabet.
    sample = rng.sample(ids, min(args.count, len(ids)))
    (out_dir / "_sample.json").write_text(json.dumps({
        "seed": args.seed, "shards": chosen, "pool": len(ids),
        "sampled": len(sample), "ids": sample}, indent=2), encoding="utf-8")
    print(f"  pool {len(ids)}, sampled {len(sample)} "
          f"-> {out_dir / '_sample.json'}")

    if args.ids_only:
        return 0

    print(f"Downloading at {args.delay}s intervals. Ctrl-C is safe; re-running "
          f"resumes.")
    outcomes: dict[str, int] = {}
    for index, extension_id in enumerate(sample, 1):
        outcome = download(extension_id, out_dir, args.prodversion,
                           keep_crx=args.keep_crx)
        outcomes[outcome] = outcomes.get(outcome, 0) + 1
        if index % 25 == 0 or index == len(sample):
            print(f"  {index}/{len(sample)}  " +
                  ", ".join(f"{k} {v}" for k, v in sorted(outcomes.items())))
        if outcome != "skipped":
            time.sleep(args.delay)

    unpacked = sum(1 for p in out_dir.glob("*/manifest.json"))
    print()
    print(f"corpus: {unpacked} extensions with a manifest in {out_dir}")
    print("Measure it with:")
    print(f"    .venv\\Scripts\\python.exe scripts\\benign_rates.py "
          f"--module extension --corpus {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
