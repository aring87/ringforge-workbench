"""Watch a folder, statically triage what lands in it, index the verdict.

Static triage never executes the sample, so none of the machinery a detonation
needs applies here: no snapshot revert, no containment check, no arm/disarm, no
serialisation against a single VM. That is the whole reason this is worth
building before the dynamic equivalent -- it is a queue and a shipper, not an
orchestration problem.

Three behaviours are deliberate.

Deduplication is by SHA-256 of the bytes, computed before analysis rather than
after. The same file arriving twice under different names is one sample, and
re-triaging it wastes minutes of capa and FLOSS time to produce an event that is
identical apart from its timestamp.

A sample that fails analysis is moved aside rather than left in place. Left in
place it is retried on every pass forever, and one malformed file stalls the
queue behind it.

Shipping failures do not fail the run. The case is complete and on disk either
way; an unreachable SIEM means the event is missing from the index, not that the
analysis has to happen again. Unshipped events are recorded so they can be
replayed with --replay-failed.

Usage:

    python scripts\\auto_static_triage.py --once
    python scripts\\auto_static_triage.py --watch --interval 60
    python scripts\\auto_static_triage.py --once --dry-run
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from integrations.splunk_hec import HecConfig, hec_status, send_events  # noqa: E402
from integrations.static_event import build_static_event  # noqa: E402
from static_triage_engine.config import TriageConfig  # noqa: E402
from static_triage_engine.engine import run_case  # noqa: E402

#: Extensions worth triaging. Anything else that lands in the inbox is left
#: alone rather than guessed at -- a queue that silently ignores files is better
#: than one that silently analyses the wrong ones.
_ANALYSABLE = {".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl", ".msi", ".ps1", ".vbs", ".js", ".hta", ".bin", ".dat"}

#: How long a file must be unmodified before it is considered fully written. A
#: file still being copied into the inbox will otherwise be hashed and analysed
#: half-complete.
_SETTLE_SECONDS = 5


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_state(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"seen": {}, "unshipped": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        data.setdefault("seen", {})
        data.setdefault("unshipped", [])
        return data
    except Exception:
        # A corrupt state file must not stop the queue. Losing dedupe history
        # costs duplicate analysis; refusing to start costs everything.
        return {"seen": {}, "unshipped": []}


def save_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    tmp.replace(path)


def is_settled(path: Path) -> bool:
    try:
        age = time.time() - path.stat().st_mtime
    except OSError:
        return False
    return age >= _SETTLE_SECONDS


def collect_candidates(inbox: Path) -> list[Path]:
    if not inbox.is_dir():
        return []
    return sorted(
        p for p in inbox.iterdir()
        if p.is_file() and p.suffix.lower() in _ANALYSABLE and is_settled(p)
    )


def ship(record: dict[str, Any], host: str, dry_run: bool) -> dict[str, Any]:
    return send_events([record], config=HecConfig(), host=host, dry_run=dry_run)


def process_one(
    sample: Path,
    state: dict[str, Any],
    processed_dir: Path,
    failed_dir: Path,
    host: str,
    dry_run: bool,
    force: bool,
) -> str:
    """Triage a single sample and ship its verdict. Returns a status word."""
    try:
        sha256 = sha256_of(sample)
    except Exception as error:
        print(f"  ! could not hash {sample.name}: {error}")
        return "error"

    if not force and sha256 in state["seen"]:
        previous = state["seen"][sha256]
        print(f"  - {sample.name}: already analysed ({previous.get('verdict', '?')}), skipping")
        processed_dir.mkdir(parents=True, exist_ok=True)
        shutil.move(str(sample), str(processed_dir / sample.name))
        return "duplicate"

    print(f"  * {sample.name} ({sha256[:12]}...) analysing")
    try:
        summary = run_case(str(sample), show_progress=False)
    except Exception as error:
        print(f"  ! analysis failed: {type(error).__name__}: {error}")
        failed_dir.mkdir(parents=True, exist_ok=True)
        shutil.move(str(sample), str(failed_dir / sample.name))
        return "failed"

    case_dir = str(summary.get("case_dir", "") or "")
    record = build_static_event(summary, case_dir=case_dir, analyzer_host=host)
    event = record["event"]
    print(f"    verdict={event['verdict']} score={event['risk_score']} severity={event['severity']}")

    outcome = ship(record, host, dry_run)
    if outcome.get("shipped"):
        print("    shipped" + (" (dry run)" if dry_run else f" to index={outcome['index']}"))
    else:
        print(f"    ! not shipped: {outcome.get('error', 'unknown error')}")
        state["unshipped"].append(record)

    state["seen"][sha256] = {
        "file_name": event["file_name"],
        "verdict": event["verdict"],
        "risk_score": event["risk_score"],
        "case_dir": case_dir,
        "analysed_utc": datetime.now(timezone.utc).isoformat(),
    }

    processed_dir.mkdir(parents=True, exist_ok=True)
    destination = processed_dir / sample.name
    if destination.exists():
        destination = processed_dir / f"{sha256[:12]}_{sample.name}"
    # The sample stays where run_case copied it into the case directory, so
    # moving the inbox copy loses nothing.
    try:
        shutil.move(str(sample), str(destination))
    except Exception as error:
        print(f"    ! could not move to processed: {error}")

    return "analysed"


def replay_failed(state: dict[str, Any], host: str, dry_run: bool) -> None:
    pending = state.get("unshipped", [])
    if not pending:
        print("No unshipped events to replay.")
        return

    print(f"Replaying {len(pending)} unshipped event(s)...")
    outcome = send_events(pending, config=HecConfig(), host=host, dry_run=dry_run)
    if outcome.get("shipped"):
        print(f"  shipped {outcome['event_count']} event(s) in {outcome['batches']} batch(es)")
        state["unshipped"] = []
    else:
        print(f"  ! still failing: {outcome.get('error', 'unknown error')}")


def run_pass(args: argparse.Namespace, state: dict[str, Any], host: str) -> dict[str, int]:
    inbox = Path(args.inbox).expanduser()
    processed_dir = Path(args.processed).expanduser()
    failed_dir = Path(args.failed).expanduser()

    candidates = collect_candidates(inbox)
    counts = {"analysed": 0, "duplicate": 0, "failed": 0, "error": 0}

    if not candidates:
        return counts

    print(f"{len(candidates)} file(s) to consider in {inbox}")
    for sample in candidates:
        status = process_one(sample, state, processed_dir, failed_dir, host, args.dry_run, args.force)
        counts[status] = counts.get(status, 0) + 1

    return counts


def main() -> int:
    cfg = TriageConfig()
    default_inbox = cfg.base_dir / "samples" / "inbox"

    parser = argparse.ArgumentParser(description="Statically triage an inbox and index the verdicts.")
    parser.add_argument("--inbox", default=str(default_inbox), help="Directory to watch.")
    parser.add_argument("--processed", default=str(default_inbox.parent / "processed"), help="Where analysed samples go.")
    parser.add_argument("--failed", default=str(default_inbox.parent / "failed"), help="Where samples that could not be analysed go.")
    parser.add_argument("--state", default="", help="Dedupe/replay state file. Default: <logs>/auto_static_triage_state.json")
    parser.add_argument("--once", action="store_true", help="Run a single pass and exit.")
    parser.add_argument("--watch", action="store_true", help="Poll the inbox until interrupted.")
    parser.add_argument("--interval", type=int, default=60, help="Seconds between passes in --watch mode.")
    parser.add_argument("--dry-run", action="store_true", help="Analyse and build events, but do not ship.")
    parser.add_argument("--force", action="store_true", help="Re-analyse even if the hash was seen before.")
    parser.add_argument("--replay-failed", action="store_true", help="Retry previously unshipped events and exit.")
    args = parser.parse_args()

    if not args.once and not args.watch and not args.replay_failed:
        parser.error("choose one of --once, --watch, or --replay-failed")

    state_path = Path(args.state).expanduser() if args.state else cfg.logs_dir / "auto_static_triage_state.json"
    state = load_state(state_path)
    host = socket.gethostname()

    status = hec_status()
    print(f"Splunk HEC: {status['note']}")
    if not status["available"] and not args.dry_run:
        print("  Events will be recorded as unshipped and can be replayed with --replay-failed.")
    print()

    try:
        if args.replay_failed:
            replay_failed(state, host, args.dry_run)
            return 0

        if args.once:
            counts = run_pass(args, state, host)
            print()
            print(f"Done: {counts['analysed']} analysed, {counts['duplicate']} duplicate, "
                  f"{counts['failed']} failed, {counts['error']} error")
            return 0

        print(f"Watching {args.inbox} every {args.interval}s. Ctrl-C to stop.")
        while True:
            run_pass(args, state, host)
            save_state(state_path, state)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped.")
        return 0
    finally:
        save_state(state_path, state)


if __name__ == "__main__":
    raise SystemExit(main())
