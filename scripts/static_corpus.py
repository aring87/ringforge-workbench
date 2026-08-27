"""Run the *whole* static engine over a real corpus, not just the cheap fields.

`scripts/benign_rates.py --module static` measured three of six categories. The
other three -- `known_malware_signature`, `dangerous_capability` and
`embedded_network_indicators` -- need YARA, capa and IOC extraction, so they
were passed `None` and came back `unknown`. That was the honest partial report
and it was still a gap: **half the static scorer had never been pointed at
anything.**

This closes it by running `engine.run_case`, the real entry point, and reading
the result through `combine_case.static_verdict_for_case`, the real scorer. No
second implementation, because a corpus measured against a reimplementation
measures the reimplementation.

**The sample is random now, and the old one was not.** `benign_rates.measure_static`
walks `sorted(root.glob("*.exe"))` and stops at `--limit`, which on a machine
with 654 System32 executables meant the first 300 *alphabetically* -- `a`
through `MSchedExe`. That is the same defect the extension and spec corpora were
built to avoid, sitting unnoticed in the corpus that was supposed to be the easy
one. `--seed` makes the replacement reproducible.

**It is slow, and that is the whole reason the gap existed.** capa dominates:
30-85 seconds per binary on this bench, so a few hundred is hours rather than
minutes. `--workers` runs several at once, each with its own case and log
directory so nothing shares an append-mode ledger.

    .venv\\Scripts\\python.exe scripts\\static_corpus.py --count 300 --out G:\\static-corpus
    .venv\\Scripts\\python.exe scripts\\benign_rates.py --module static --cases G:\\static-corpus

Runs on the HOST, over signed Microsoft binaries. Nothing here is a sample.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import random
import sys
import time
import traceback
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

#: Signed system binaries. Not a flattering corpus -- Microsoft fills in version
#: info and signs everything -- which is exactly why a category firing here
#: would matter.
DEFAULT_ROOT = r"%SystemRoot%\System32"


def _config(corpus: Path, name: str):
    """A `TriageConfig` whose cases and logs live inside this corpus.

    Per sample, not per run. `ledger_append` opens the ledger in append mode,
    and several workers appending single lines to one file on Windows is a
    corrupted ledger waiting for a race. `tools_dir` is left alone -- that is
    where the capa and YARA rules are.
    """
    from static_triage_engine.config import TriageConfig

    cfg = TriageConfig()
    cases = corpus / "cases"
    logs = corpus / "logs" / name
    cases.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    object.__setattr__(cfg, "cases_dir", cases)
    object.__setattr__(cfg, "logs_dir", logs)
    object.__setattr__(cfg, "ledger_file", logs / "triage_ledger.jsonl")
    return cfg


def analyse(args: tuple[str, str, int]) -> dict[str, Any]:
    """One binary, all the way through the real engine. Never raises.

    A crash on one sample must cost that sample and not the run -- this is
    hours of work and it resumes, but only if it gets to the end.
    """
    path_str, corpus_str, capa_timeout, with_lief = args
    path, corpus = Path(path_str), Path(corpus_str)
    started = time.time()
    try:
        from static_triage_engine.engine import run_case

        cfg = _config(corpus, path.stem)
        summary = run_case(
            str(path), case_name=path.stem, show_progress=False, config=cfg,
            # **The parent binary is the sample.** Payload extraction triages
            # files carved *out* of it, which are a different population and
            # would quietly enlarge the corpus with things nobody sampled.
            enable_payload_extraction=False, triage_extracted_pes=False,
            capa_timeout=capa_timeout, skip_lief=not with_lief,
        )
        return {"file": path.name, "case": summary.get("case_dir", ""),
                "seconds": round(time.time() - started, 1), "ok": True}
    except Exception as error:
        return {"file": path.name, "ok": False,
                "seconds": round(time.time() - started, 1),
                "error": f"{type(error).__name__}: {error}",
                "traceback": traceback.format_exc()[-1500:]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, help="corpus directory")
    parser.add_argument("--root", default=DEFAULT_ROOT,
                        help="directory of executables to sample")
    parser.add_argument("--count", type=int, default=300)
    parser.add_argument("--seed", type=int, default=20260826,
                        help="fixed so the sample is reproducible; the old "
                             "static corpus was the first N alphabetically")
    parser.add_argument("--workers", type=int, default=4,
                        help="capa is the cost and it is CPU-bound")
    parser.add_argument("--capa-timeout", type=int, default=300)
    parser.add_argument("--max-mb", type=int, default=64,
                        help="skip the handful of very large binaries; capa on "
                             "a 218 MB image is its own afternoon")
    parser.add_argument("--with-lief", action="store_true",
                        help="run the LIEF metadata step. Off by default: it "
                             "feeds no category and averaged 1,253s per sample "
                             "on real malware against capa's 111s")
    parser.add_argument("--list-only", action="store_true")
    args = parser.parse_args(argv)

    corpus = Path(args.out)
    corpus.mkdir(parents=True, exist_ok=True)

    root = Path(os.path.expandvars(args.root))
    if not root.is_dir():
        print(f"failed: {root} is not a directory")
        return 1

    every = sorted(p for p in root.glob("*.exe") if p.is_file())
    sized = [p for p in every if p.stat().st_size <= args.max_mb * 1024 * 1024]
    print(f"{root}: {len(every)} executables, "
          f"{len(sized)} at or under {args.max_mb} MB")

    # **Random, not the head.** The old corpus was `sorted(...)[:300]`, which is
    # a fact about the alphabet.
    rng = random.Random(args.seed)
    sample = sorted(rng.sample(sized, min(args.count, len(sized))),
                    key=lambda p: p.name.lower())
    print(f"sampled {len(sample)}, seed {args.seed}")

    (corpus / "_sample.json").write_text(json.dumps({
        "root": str(root), "seed": args.seed, "pool": len(sized),
        "pool_before_size_filter": len(every), "max_mb": args.max_mb,
        "sampled": len(sample), "files": [p.name for p in sample],
    }, indent=2), encoding="utf-8")

    if args.list_only:
        print(f"plan written to {corpus / '_sample.json'}; nothing run")
        return 0

    # **One run at a time.** Two of these against the same corpus is not slow,
    # it is wrong: both pools open the same binaries and Windows answers with
    # `WinError 1224` -- "cannot be performed on a file with a user-mapped
    # section open" -- so samples fail for a reason that has nothing to do with
    # the sample. That happened, and the failures looked like data.
    lock = corpus / "_running.lock"
    if lock.exists():
        age = time.time() - lock.stat().st_mtime
        print(f"failed: {lock} exists ({age/60:.0f} min old). Another run is "
              f"using this corpus. Delete the file if you are sure it is not.")
        return 1
    lock.write_text(str(os.getpid()), encoding="utf-8")

    done_path = corpus / "_runs.jsonl"
    already = set()
    if done_path.exists():
        for line in done_path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                entry = json.loads(line)
            except Exception:
                continue
            # **Only successes count as done.** Recording a failure and then
            # treating it as complete means a sample that failed once can never
            # be retried, and the corpus quietly shrinks by exactly the samples
            # something went wrong on -- which are the ones worth rerunning.
            if entry.get("ok"):
                already.add(entry.get("file"))
    todo = [p for p in sample if p.name not in already]
    print(f"{len(already)} already run, {len(todo)} to go, "
          f"{args.workers} worker(s)")

    tasks = [(str(p), str(corpus), args.capa_timeout, args.with_lief)
             for p in todo]
    started = time.time()
    failures = 0
    # **`as_completed`, not `map`.** `pool.map` yields results *in order*, so one
    # slow binary -- capa on something large is minutes -- holds back every
    # result behind it. Observed: 12 cases finished on disk while the ledger
    # still said 3. Two costs, and the second is the real one: the progress line
    # lies, and an interrupted run loses every finished analysis that was
    # queued behind the straggler, because resume reads the ledger.
    try:
        with done_path.open("a", encoding="utf-8") as ledger:
            with concurrent.futures.ProcessPoolExecutor(
                    max_workers=max(1, args.workers)) as pool:
                futures = {pool.submit(analyse, task): task[0] for task in tasks}
                for index, future in enumerate(
                        concurrent.futures.as_completed(futures), 1):
                    try:
                        result = future.result()
                    except Exception as error:
                        result = {"file": Path(futures[future]).name, "ok": False,
                                  "error": f"{type(error).__name__}: {error}"}
                    ledger.write(json.dumps(result) + "\n")
                    ledger.flush()
                    if not result.get("ok"):
                        failures += 1
                        print(f"  ! {result['file']}: {result.get('error', '')}")
                    if index % 10 == 0 or index == len(tasks):
                        rate = (time.time() - started) / index
                        left = (len(tasks) - index) * rate / 60
                        print(f"  {index}/{len(tasks)}  {rate:4.1f}s each, "
                              f"~{left:.0f} min left, {failures} failed")
    finally:
        lock.unlink(missing_ok=True)

    print()
    print(f"corpus: {len(list((corpus / 'cases').glob('*')))} cases in {corpus}")
    print("Measure it with:")
    print("    .venv\\Scripts\\python.exe scripts\\benign_rates.py "
          "--module static --cases " + str(corpus / "cases"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
