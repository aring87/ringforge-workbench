"""Measure what the dump-based detectors say about software that is not malware.

Queue C in `docs/ROADMAP.md`, and the number every "not scored" note in this
project is ultimately waiting on. Both controls pass and three real samples have
been through the pipeline, but nothing here has ever been run against a body of
ordinary software, so "false positive rate" has been an argument rather than a
measurement.

**It does not need the VM.** The carver, the module-integrity pass and the
identity check all consume minidumps, and this host has a couple of hundred
perfectly ordinary processes. Dumping those and running the same passes over
them measures exactly what the detectors say about benign software -- on real
images, with real ASLR, with whatever this machine's security software has
injected, which is the condition the synthetic fixtures cannot reproduce.

Two things make the result meaningful rather than decorative:

* **`explorer.exe` is in `HOLLOWING_TARGETS`.** So is `svchost.exe`. A benign
  corpus on a normal desktop therefore exercises the *emphatic* branch -- the
  one that says "a foreign image in a binary loaders hollow" -- and not just
  the ordinary path. If those fire here, they fire on every machine.
* **The analysis VM is excluded.** `VirtualBoxVM.exe` hosts the guest, and its
  address space is not benign desktop software in any useful sense.

Written to be re-run: a rate measured on this host today is a fact about this
host today, and the point of a script is that the next person gets their own.

    ..\\.venv\\Scripts\\python.exe benign_baseline.py --count 12
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import getpass
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dynamic_analysis import module_integrity as mi
from dynamic_analysis import pe_carve
from dynamic_analysis.crash_evidence import is_hollowing_target

#: MiniDumpWithFullMemory | MiniDumpWithFullMemoryInfo. The module bytes are the
#: whole point -- a normal minidump does not carry the images, so there would be
#: nothing to compare against the files.
_FULL = 0x00000002 | 0x00000800

_PROCESS_QUERY_INFORMATION = 0x0400
_PROCESS_VM_READ = 0x0010

#: Selection is by **virtual size, not working set**, and that distinction was
#: learned by getting it wrong: sorting on RSS picked `msedgewebview2` and
#: `SystemSettings`, whose resident sets are small and whose *reserved* address
#: spaces are not. A full-memory dump covers what is committed, so the first two
#: dumps came out at 445 MB and 796 MB. `vms` predicts dump size; `rss` does not.
DEFAULT_MAX_VIRTUAL = 700 * 1024 * 1024

#: Belt and braces: if a dump lands larger than this anyway, drop it rather than
#: spend minutes relocating every module in it. Recorded, not silently skipped.
MAX_DUMP_BYTES = 320 * 1024 * 1024

#: The analysis VM, and this interpreter's own tree.
ALWAYS_SKIP = {"virtualboxvm.exe", "vboxsvc.exe", "vboxheadless.exe"}


def _dump_process(pid: int, path: Path) -> tuple[bool, str]:
    """Full-memory dump of another process. False plus a reason on failure."""
    # use_last_error on **both**. Without it on dbghelp, a MiniDumpWriteDump
    # failure reports "(0)" -- ctypes never captured dbghelp's error, so the
    # one number that says why the dump failed was always zero. The OpenProcess
    # failures below looked fine only because kernel32 already had the flag.
    dbghelp = ctypes.WinDLL("dbghelp.dll", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)

    kernel32.OpenProcess.restype = wt.HANDLE
    kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    handle = kernel32.OpenProcess(
        _PROCESS_QUERY_INFORMATION | _PROCESS_VM_READ, False, pid)
    if not handle:
        return False, f"OpenProcess failed ({ctypes.get_last_error()})"

    kernel32.CreateFileW.restype = wt.HANDLE
    kernel32.CreateFileW.argtypes = [
        wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
        wt.DWORD, wt.DWORD, wt.HANDLE]
    out = kernel32.CreateFileW(str(path), 0x40000000, 0, None, 2, 0x80, None)
    if out == wt.HANDLE(-1).value:
        kernel32.CloseHandle(handle)
        return False, f"CreateFileW failed ({ctypes.get_last_error()})"

    dbghelp.MiniDumpWriteDump.restype = wt.BOOL
    dbghelp.MiniDumpWriteDump.argtypes = [
        wt.HANDLE, wt.DWORD, wt.HANDLE, wt.DWORD,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    ok = dbghelp.MiniDumpWriteDump(handle, pid, out, _FULL, None, None, None)
    err = ctypes.get_last_error()
    kernel32.CloseHandle(out)
    kernel32.CloseHandle(handle)
    if not ok:
        return False, f"MiniDumpWriteDump failed ({err})"
    return True, ""


def _candidates(limit: int, max_virtual: int) -> list[tuple[int, str]]:
    import psutil

    me = getpass.getuser().lower()
    rows = []
    for proc in psutil.process_iter(["pid", "name", "username", "memory_info"]):
        try:
            info = proc.info
            user = (info["username"] or "").split("\\")[-1].lower()
            name = (info["name"] or "").lower()
            if user != me or info["pid"] == os.getpid():
                continue
            if name in ALWAYS_SKIP:
                continue
            vms = getattr(info["memory_info"], "vms", 0) or 0
            if not vms or vms > max_virtual:
                continue
            rows.append((vms, info["pid"], info["name"]))
        except Exception:
            continue
    # Smallest first: more processes per gigabyte of scratch, and a hollowing
    # target is as informative small as large.
    rows.sort()

    # **One process per distinct executable before any second copy.** The first
    # run of this took the ten smallest and got six `conhost.exe`: "0 false
    # positives across 8 processes" was really 0 across three programs, which
    # is a far weaker claim than the number looks. Diversity of *binaries* is
    # what a false-positive rate is about; six copies of one image share a
    # module list and cannot disagree with each other.
    seen: set[str] = set()
    picked: list[tuple[int, str]] = []
    for _vms, pid, name in rows:
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        picked.append((pid, name))
        if len(picked) >= limit:
            break
    # Only then backfill with repeats, if the machine simply lacks that many
    # distinct small processes.
    if len(picked) < limit:
        for _vms, pid, name in rows:
            if (pid, name) in picked:
                continue
            picked.append((pid, name))
            if len(picked) >= limit:
                break
    # Make sure at least one hollowing target is in the sample if the machine
    # has one running -- that is the branch worth measuring.
    if not any(is_hollowing_target(n) for _p, n in picked):
        for _vms, pid, name in rows:
            if is_hollowing_target(name):
                picked = picked[:-1] + [(pid, name)]
                break
    return picked


#: Enough classes that the compile lasts long enough to *dump*, which is a much
#: longer window than merely being seen. At 400 the poll caught csc.exe three
#: times and every full-memory dump still failed; widening the window is the
#: cheap half of ruling timing in or out.
_PROBE_CLASSES = 2500

#: The managed processes an ordinary `Add-Type` produces. All three are in
#: HOLLOWING_TARGETS, which is the whole point -- see `_spawn_managed`.
_MANAGED_WANTED = {"csc.exe", "cvtres.exe", "msbuild.exe", "vbc.exe"}

#: How often to re-dump a live managed child. Each full-memory dump costs real
#: time, so this is a floor on the interval rather than a target.
_MANAGED_REDUMP_SECONDS = 0.4


#: Types that force `csc.exe` to load assemblies beyond `mscorlib`. The first
#: probe compiled trivial classes referencing nothing, came back with 0 unmapped
#: images, and that was read -- wrongly -- as the gate not firing on benign
#: compiles. The five images it *did* fire on in run `c14cb5b6` turned out to be
#: `mscorlib` and `System.Management.Automation`, so a control that never loads
#: them is not a control at all. `-ReferencedAssemblies` is the variable.
_PROBE_USES_REFS = """using System;
using System.Linq;
using System.Text.RegularExpressions;
using System.Management.Automation;

public class ProbeReferenced {
    public string R() { return new Regex("a+").Match("aaa").Value; }
    public int    L() { return Enumerable.Range(0, 10).Sum(); }
    public object P() { return new PSObject("probe"); }
    public Uri    U() { return new Uri("http://localhost/"); }
}
"""


def _probe_source(path: Path, classes: int = _PROBE_CLASSES,
                  with_refs: bool = True) -> None:
    """Write C# that is entirely ordinary and takes a moment to compile."""
    body = "\n".join(
        f"public class Probe{i} {{ public int F(int x) {{ return x + {i}; }} }}"
        for i in range(classes)
    )
    head = _PROBE_USES_REFS if with_refs else ""
    path.write_text(head + body, encoding="utf-8")


def _spawn_managed(scratch: Path, poll_seconds: float = 30.0,
                   with_refs: bool = True) -> list[tuple[str, int, Path]]:
    """Dump a legitimate `csc.exe` while it is alive.

    `_candidates` cannot reach this case: it iterates running processes, and the
    compiler is transient. Yet it is exactly the case that matters. On run
    `c14cb5b6` the gate graded **strong** on five .NET images inside `csc.exe`
    that the sample's own `Add-Type` had spawned -- and `Add-Type` is something
    ordinary scripts do constantly. The 13 Aug baseline never contained a
    managed process, so whether those images appear in a *benign* compile has
    been assumed rather than measured.

    So: run a real compile, dump the compiler while it works, and put the result
    through the identical passes.
    """
    import psutil

    src = scratch / "probe.cs"
    _probe_source(src, with_refs=with_refs)

    if with_refs:
        # [psobject].Assembly.Location rather than the bare name: the PowerShell
        # engine assembly does not resolve by simple name from csc's search path.
        command = (
            "$refs = @('System.dll','System.Core.dll',[psobject].Assembly.Location); "
            f"Add-Type -TypeDefinition (Get-Content -Raw '{src}') "
            "-ReferencedAssemblies $refs"
        )
    else:
        command = f"Add-Type -TypeDefinition (Get-Content -Raw '{src}')"

    print(f"  probe: {'with' if with_refs else 'without'} -ReferencedAssemblies")

    # **Capture the compile, do not discard it.** With output on DEVNULL a probe
    # that fails to compile is indistinguishable from one that compiled and
    # produced no unmapped images -- and the second is the result being claimed.
    # Redirected to a file rather than a pipe so a full buffer cannot deadlock
    # the poll loop below.
    log_path = scratch / "probe_compile.log"
    log_handle = open(log_path, "wb")

    # -NoProfile so a user profile cannot add anything to the picture.
    proc = subprocess.Popen(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        stdout=log_handle, stderr=subprocess.STDOUT,
    )

    found: dict[int, tuple[str, Path]] = {}
    last_dump: dict[int, float] = {}
    started = time.time()
    deadline = started + poll_seconds
    try:
        parent = psutil.Process(proc.pid)
    except Exception as exc:
        print(f"  spawn failed: {exc}")
        return []

    # **Keep re-dumping until it exits, and keep the last.** Dumping at the
    # first success measures a process that has barely started: the first guest
    # run caught csc.exe about 80 ms in with 23 modules loaded, against 36 in
    # the malware run's dump of the same binary. `unmapped 0` on that is a
    # statement about an initialising process, not about compilation. The last
    # dump before exit is the one that has actually done the work.
    while time.time() < deadline:
        try:
            children = parent.children(recursive=True)
        except Exception:
            children = []
        wanted = []
        for child in children:
            try:
                name = (child.name() or "").lower()
            except Exception:
                continue
            if name not in _MANAGED_WANTED:
                continue
            wanted.append((child, name))

        for child, name in wanted:
            now = time.time()
            if now - last_dump.get(child.pid, 0.0) < _MANAGED_REDUMP_SECONDS:
                continue
            path = scratch / f"benign_{Path(name).stem}_{child.pid}.dmp"
            ok, why = _dump_process(child.pid, path)
            last_dump[child.pid] = now
            if ok:
                found[child.pid] = (name, path)
                print(f"  dumped {name} ({child.pid}) at +{now - started:.2f}s")
            else:
                print(f"  miss   {name} ({child.pid}) at +{now - started:.2f}s: {why}")
                if child.pid not in found:
                    path.unlink(missing_ok=True)

        if proc.poll() is not None and not wanted:
            break
        time.sleep(0.02)

    try:
        proc.wait(timeout=30)
    except Exception:
        proc.kill()

    try:
        log_handle.close()
    except Exception:
        pass

    rc = proc.returncode
    output = ""
    try:
        output = log_path.read_text(encoding="utf-8", errors="replace").strip()
    except Exception:
        pass

    if rc not in (0, None) or output:
        # A failed compile exits in a fraction of the time a real one takes, and
        # the dump taken during it measures a compiler that never did any work.
        print(f"  PROBE COMPILE FAILED (rc={rc}) -- the dumps below are of a "
              f"compiler that errored out, not one that compiled:")
        for line in output.splitlines()[:12]:
            print(f"    | {line}")
        print(f"    (full output: {log_path})")
    else:
        print(f"  probe compiled cleanly (rc={rc})")

    src.unlink(missing_ok=True)

    if not found:
        print("  no managed child was caught -- the compile may have been too "
              "fast, or PowerShell reused a cached assembly")
    return [(name, pid, path) for pid, (name, path) in found.items()]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--count", type=int, default=12)
    ap.add_argument("--max-virtual", type=int, default=DEFAULT_MAX_VIRTUAL)
    ap.add_argument("--keep", action="store_true", help="do not delete the dumps")
    ap.add_argument("--out", default="", help="where to write baseline.json")
    ap.add_argument("--managed", action="store_true",
                    help="also spawn a legitimate Add-Type compile and dump "
                         "csc.exe while it runs")
    ap.add_argument("--only-managed", action="store_true",
                    help="skip the running-process corpus; measure only the "
                         "managed case")
    ap.add_argument("--no-refs", action="store_true",
                    help="compile the probe with no -ReferencedAssemblies. The "
                         "A of an A/B: run both and compare unmapped counts")
    ap.add_argument("--pid", type=int, action="append", default=[],
                    help="dump this pid specifically; repeatable. For reaching "
                         "a process the size-ranked corpus would not pick, such "
                         "as a long-lived .NET one")
    args = ap.parse_args()

    scratch = Path(os.environ.get("TEMP", ".")) / "ringforge-benign-baseline"
    scratch.mkdir(parents=True, exist_ok=True)

    picked = [] if args.only_managed else _candidates(args.count, args.max_virtual)
    print(f"{len(picked)} benign processes selected "
          f"({sum(1 for _p, n in picked if is_hollowing_target(n))} of them "
          f"binaries loaders hollow)\n")

    # (name, pid, already-dumped path or None)
    jobs: list[tuple[str, int, "Path | None"]] = [(n, p, None) for p, n in picked]

    if args.pid:
        import psutil
        for pid in args.pid:
            try:
                jobs.append((psutil.Process(pid).name(), pid, None))
            except Exception as exc:
                print(f"  skip  pid {pid}: {exc}")

    if args.managed or args.only_managed:
        print("spawning a legitimate Add-Type compile to reach csc.exe ...")
        jobs.extend(_spawn_managed(scratch, with_refs=not args.no_refs))
        print()

    totals = {
        "processes": 0, "dump_failures": 0, "oversize_skipped": 0,
        "carve_unmapped": 0, "carve_unmapped_in_hollowing_target": 0,
        "carve_resource_only": 0, "carve_known_module": 0,
        "mi_identical": 0, "mi_patched": 0, "mi_replaced": 0,
        "mi_header_mismatch": 0, "mi_no_reference": 0,
    }
    rows: list[dict] = []

    for name, pid, predumped in jobs:
        if predumped is None:
            path = scratch / f"{Path(name).stem}_{pid}.dmp"
            ok, why = _dump_process(pid, path)
            if not ok:
                print(f"  skip  {name} ({pid}): {why}")
                totals["dump_failures"] += 1
                path.unlink(missing_ok=True)
                continue
        else:
            # Dumped already, while it was alive -- see `_spawn_managed`.
            path = predumped

        size = path.stat().st_size
        if size > MAX_DUMP_BYTES:
            print(f"  skip  {name} ({pid}): dump {size/1e6:.0f} MB over the "
                  f"{MAX_DUMP_BYTES/1e6:.0f} MB analysis cap")
            totals["oversize_skipped"] += 1
            path.unlink(missing_ok=True)
            continue

        started = time.time()
        try:
            carve = pe_carve.analyze_dump(path)
            integrity = mi.analyze_dump(path)
        except Exception as exc:                       # pragma: no cover
            print(f"  fail  {name} ({pid}): {exc}")
            path.unlink(missing_ok=True)
            continue

        counts = carve.get("counts", {}) or {}
        images = carve.get("images", []) or []
        unmapped = [i for i in images if i.get("classification") == "unmapped"]
        verdicts = {"identical": 0, "patched": 0, "replaced": 0,
                    "header_mismatch": 0, "no_reference": 0}
        for module in integrity.get("modules", []):
            verdicts[module.get("verdict", "no_reference")] = \
                verdicts.get(module.get("verdict", "no_reference"), 0) + 1

        target = is_hollowing_target(name)
        row = {
            "process": name, "pid": pid, "hollowing_target": target,
            "size_mb": round(path.stat().st_size / 1e6, 1),
            "seconds": round(time.time() - started, 1),
            "unmapped": len(unmapped),
            "resource_only": int(counts.get("resource_only", 0) or 0),
            "known_module": int(counts.get("known_module", 0) or 0),
            **{f"mi_{k}": v for k, v in verdicts.items()},
        }
        rows.append(row)

        totals["processes"] += 1
        totals["carve_unmapped"] += len(unmapped)
        totals["carve_unmapped_in_hollowing_target"] += len(unmapped) if target else 0
        totals["carve_resource_only"] += row["resource_only"]
        totals["carve_known_module"] += row["known_module"]
        for k, v in verdicts.items():
            totals[f"mi_{k}"] += v

        flag = ""
        if len(unmapped) or verdicts["replaced"] or verdicts["header_mismatch"]:
            flag = "   <-- would be reported"
        print(f"  {name:<34} pid {pid:<7} {row['size_mb']:>6.1f} MB  "
              f"unmapped {len(unmapped)}  replaced {verdicts['replaced']}  "
              f"mismatch {verdicts['header_mismatch']}"
              f"{'  [hollowing target]' if target else ''}{flag}")

        if not args.keep:
            path.unlink(missing_ok=True)

    print("\n" + "=" * 72)
    print("benign baseline")
    print("=" * 72)
    for key, value in totals.items():
        print(f"  {key:<40} {value}")

    if totals["processes"]:
        print("\nthe numbers that decide whether these may score:")
        print(f"  unmapped PE images per benign process        "
              f"{totals['carve_unmapped'] / totals['processes']:.2f}")
        print(f"  unmapped in a hollowing target               "
              f"{totals['carve_unmapped_in_hollowing_target']}   <-- the emphatic branch")
        print(f"  modules reading 'replaced'                   "
              f"{totals['mi_replaced']}")
        print(f"  modules reading 'header_mismatch'            "
              f"{totals['mi_header_mismatch']}")

    out = Path(args.out) if args.out else scratch / "baseline.json"
    out.write_text(json.dumps({"totals": totals, "processes": rows}, indent=2),
                   encoding="utf-8")
    print(f"\nwritten to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
