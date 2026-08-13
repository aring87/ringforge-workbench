"""Read a finished run and say which ledger rows it just settled.

Nine rows of the proven/unproven ledger ride on one detonation of the loader,
and the way that value gets lost is mundane: nobody remembers to open nine
files, or the interesting field is absent rather than empty and absence does not
draw the eye. This turns "go and look" into one command.

It also checks the *pre-registered predictions*, which is the half that makes a
run able to disagree with you. Writing expectations down before a run is what
made gap 1 findable; checking them afterwards is what stops a surprising result
being quietly reinterpreted as the expected one.

**The first thing it checks is whether the guest was up to date**, because that
failure looks exactly like a detector finding nothing. A run at `9df8ec0` was
diagnosed that way: `vm_artifact_reads` was *absent* from the summary while
`abnormal_termination` was present, and the absence was the whole answer. A
missing key and an empty result are different claims and this refuses to
conflate them.

    ..\\.venv\\Scripts\\python.exe verify_run.py <run-directory>

where <run-directory> is the one holding `metadata\\dynamic_run_summary.json`.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Pre-registered, written before the run. Stage 3's TimeDateStamp as Windows
# recorded it for RegSvcs.exe, and the real RegSvcs.exe on the guest.
PREDICTED_RUNNING_IMAGE = 0x5FF2B99B
PREDICTED_FILE_ON_DISK = 0x68531EE1
PREDICTED_MISMATCH_MODULE = "regsvcs.exe"
PREDICTED_MISMATCH_BASE = 0x400000

OK, MISS, WARN, GONE = "PASS", "FAIL", "....", "ABSENT"


class Report:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str]] = []

    def add(self, status: str, title: str, detail: str = "") -> None:
        self.rows.append((status, title, detail))

    def show(self) -> int:
        width = max(len(t) for _s, t, _d in self.rows) + 2
        for status, title, detail in self.rows:
            print(f"  [{status:^6}] {title:<{width}} {detail}")
        failed = sum(1 for s, _t, _d in self.rows if s in (MISS, GONE))
        print()
        print(f"{len(self.rows)} checks, {failed} needing attention")
        return 1 if failed else 0


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _hexi(value) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text, 16)
    except ValueError:
        return None


def check_guest_freshness(summary: dict, r: Report) -> None:
    """A key that is absent means the guest ran older code than you think."""
    expected = {
        "ntdll_unhooking": "the ntdll-unhooking pass (13 Aug)",
        "module_integrity_summary": "module integrity (10 Aug)",
        "vm_artifact_reads": "registry-read collection (06 Aug)",
        "abnormal_termination": "the chain-crashed warning (06 Aug)",
    }
    missing = [f"{k} -- {why}" for k, why in expected.items() if k not in summary]
    crash = summary.get("crash_summary", {}) or {}
    if "image_timestamps" not in crash:
        missing.append("crash_summary.image_timestamps -- the WER check (13 Aug)")

    if missing:
        r.add(GONE, "guest pipeline version",
              f"{len(missing)} field(s) absent: the guest did not pull. "
              f"First: {missing[0]}")
    else:
        r.add(OK, "guest pipeline version", "every expected field is present")


def check_config(run_config: dict | None, r: Report) -> None:
    """The settings that have silently not-taken before."""
    if run_config is None:
        r.add(WARN, "run_config.json", "not supplied; cannot confirm settings took")
        return

    offsets = run_config.get("memory_dump_offsets")
    r.add(OK if offsets else WARN, "memory_dump_offsets", str(offsets))

    redump = run_config.get("memory_dump_spawn_redump_seconds")
    detail = f"{redump}s"
    if isinstance(redump, int) and redump > 2:
        detail += "  (RegSvcs lived 2.14s; 3s fired nothing)"
        r.add(WARN, "spawn re-dump delay", detail)
    else:
        r.add(OK, "spawn re-dump delay", detail)

    procmon = str(run_config.get("procmon_config_path") or "")
    if "registry_reads" in procmon.lower():
        r.add(OK, "procmon config", Path(procmon).name)
    else:
        r.add(WARN, "procmon config",
              f"{Path(procmon).name or 'default'} -- registry reads not collected")


def check_image_timestamps(summary: dict, r: Report) -> None:
    stamps = (summary.get("crash_summary", {}) or {}).get("image_timestamps")
    if stamps is None:
        r.add(GONE, "WER image-timestamp check", "field absent")
        return
    counts = stamps.get("counts", {}) or {}
    if not stamps.get("available"):
        r.add(WARN, "WER image-timestamp check",
              f"nothing comparable ({counts.get('no_reference', 0)} no_reference) "
              f"-- could not tell, not clean")
        return

    hits = stamps.get("mismatches", []) or []
    r.add(OK if hits else WARN, "WER image-timestamp check",
          f"{counts.get('mismatch', 0)} mismatch, "
          f"{counts.get('mismatch_in_hollowing_target', 0)} in a hollowing target")

    matched = [
        m for m in hits
        if _hexi(m.get("recorded")) == PREDICTED_RUNNING_IMAGE
        and _hexi(m.get("on_disk")) == PREDICTED_FILE_ON_DISK
    ]
    if matched:
        r.add(OK, "  prediction: 5ff2b99b vs 68531ee1", matched[0].get("process", ""))
    elif hits:
        got = hits[0]
        r.add(MISS, "  prediction: 5ff2b99b vs 68531ee1",
              f"got {got.get('recorded')} vs {got.get('on_disk')} "
              f"on {got.get('process')} -- interesting, not wrong")
    else:
        r.add(MISS, "  prediction: 5ff2b99b vs 68531ee1", "no mismatch at all")


def check_module_integrity(summary: dict, r: Report) -> None:
    mi = summary.get("module_integrity_summary")
    if mi is None:
        r.add(GONE, "module integrity", "field absent")
        return
    counts = mi.get("counts", {}) or {}
    if not mi.get("available"):
        r.add(WARN, "module integrity",
              f"nothing comparable ({counts.get('no_reference', 0)} no_reference)")
        return

    r.add(OK, "module integrity",
          f"{mi.get('modules_compared', 0)} compared, "
          f"{counts.get('identical', 0)} identical, "
          f"{counts.get('patched', 0)} patched, "
          f"{counts.get('replaced', 0)} replaced, "
          f"{counts.get('header_mismatch', 0)} header_mismatch")

    if counts.get("replaced"):
        r.add(OK, "  'replaced' seen in the wild",
              "first time -- this had never fired on real malware")

    wanted = [
        m for m in (mi.get("header_mismatch", []) or [])
        if PREDICTED_MISMATCH_MODULE in str(m.get("name", "")).lower()
    ]
    if wanted:
        r.add(OK, f"  prediction: header_mismatch on {PREDICTED_MISMATCH_MODULE}",
              f"base {wanted[0].get('base')}")
    else:
        r.add(MISS, f"  prediction: header_mismatch on {PREDICTED_MISMATCH_MODULE}",
              "not reported")


def check_ntdll(summary: dict, r: Report) -> None:
    unhook = summary.get("ntdll_unhooking")
    if unhook is None:
        r.add(GONE, "ntdll-unhooking pass", "field absent")
        return
    counts = unhook.get("counts", {}) or {}
    if not unhook.get("collection_available"):
        r.add(WARN, "ntdll-unhooking pass",
              "no file opens captured -- a statement about the capture")
        return

    own = counts.get("ntdll_opens_by_sample", 0)
    r.add(OK if own else WARN, "ntdll-unhooking pass",
          f"{own} ntdll open(s) by the sample, "
          f"{counts.get('ntdll_opens_in_hollowing_target', 0)} in a hollowing target")
    # The number that decides whether this may ever score.
    r.add(OK, "  background rate (the FP baseline)",
          f"{counts.get('system_dll_opens_by_others', 0)} open(s) by other processes")
    if not own:
        r.add(WARN, "  prediction: the sample opens ntdll",
              "not seen -- ask whether the read beats Procmon attaching")


def check_vm_reads(summary: dict, r: Report) -> None:
    reads = summary.get("vm_artifact_reads")
    if reads is None:
        r.add(GONE, "registry-read collection", "field absent")
        return
    if not reads.get("collection_available"):
        r.add(MISS, "registry-read collection",
              "no reads captured -- wrong Procmon config")
        return
    counts = reads.get("counts", {}) or {}
    r.add(OK, "registry-read collection",
          f"{reads.get('sample_reads', 0)} by the sample, "
          f"{counts.get('artifacts_read', 0)} naming a VM artifact "
          f"({counts.get('vm_specific', 0)} VM-specific)")


def check_carver(summary: dict, r: Report) -> None:
    carve = summary.get("pe_carve_summary")
    if carve is None:
        r.add(GONE, "PE carver", "field absent")
        return
    counts = carve.get("counts", {}) or {}
    r.add(OK, "PE carver",
          f"{counts.get('unmapped_images', 0)} unmapped, "
          f"{counts.get('unmapped_in_hollowing_target', 0)} in a hollowing target, "
          f"{counts.get('known_module_images', 0)} known-module, "
          f"{counts.get('resource_only_images', 0)} resource-only")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("run_dir", help="the run directory, or the summary json itself")
    args = ap.parse_args()

    target = Path(args.run_dir)
    if target.is_file():
        summary_path = target
        config_path = target.parent / "run_config.json"
    else:
        summary_path = target / "metadata" / "dynamic_run_summary.json"
        config_path = target / "metadata" / "run_config.json"
        if not summary_path.is_file():
            found = list(target.rglob("dynamic_run_summary.json"))
            if not found:
                print(f"no dynamic_run_summary.json under {target}")
                return 2
            summary_path = found[0]
            config_path = summary_path.parent / "run_config.json"

    summary = _load(summary_path)
    config = _load(config_path) if config_path.is_file() else None

    print(f"run summary : {summary_path}")
    print(f"run config  : {config_path if config else 'not found'}")
    print()

    r = Report()
    check_guest_freshness(summary, r)
    check_config(config, r)
    check_image_timestamps(summary, r)
    check_module_integrity(summary, r)
    check_ntdll(summary, r)
    check_vm_reads(summary, r)
    check_carver(summary, r)
    return r.show()


if __name__ == "__main__":
    raise SystemExit(main())
