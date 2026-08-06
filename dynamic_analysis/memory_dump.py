"""Process memory dumping for dynamic analysis runs.

Everything in tier 1 observes a sample from the outside: Procmon records the
syscalls, Sysmon records the injection, the pcap records the traffic. None of
them can see what the sample decrypted into its own address space. A packed
loader that unpacks, runs, and exits leaves a disk sample that matches nothing
and a memory image that matches immediately -- which is the whole reason to
dump.

Unlike every other collector here, this one cannot be a start-before /
stop-after pair. A memory dump is only meaningful while the process is alive,
so the session runs a watcher thread alongside the detonation, learns the
sample's PID from the orchestrator once it launches, and dumps at fixed offsets
into the observation window.

Dumping is done with Sysinternals ProcDump rather than MiniDumpWriteDump
through ctypes. The deciding reason is WOW64: a 64-bit Python dumping a 32-bit
target through the raw API produces a truncated dump that looks valid and scans
badly, and a silently bad dump is worse than no dump. ProcDump handles the
bitness mismatch itself.

Nothing here raises into the run. Every entry point degrades to a status dict
so a missing ProcDump, a denied OpenProcess, or a process that exited early
costs the dump and nothing else.
"""

from __future__ import annotations

import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

from dynamic_analysis.sysmon_collector import is_elevated
from dynamic_analysis.utils import sha256_file

try:
    import psutil
except ImportError:  # pragma: no cover - psutil is a declared dependency
    psutil = None

StatusCallback = Optional[Callable[[str], None]]

#: How often the watcher re-reads the sample's process tree. Descendants have to
#: be recorded while they are alive: a dropper that spawns a child and exits
#: leaves nothing to enumerate from, so the tree is tracked continuously rather
#: than looked up when a dump is due.
_POLL_INTERVAL_SECONDS = 0.5

#: Default guard rails. A full (-ma) dump is the size of the working set, so an
#: unbounded run against something chatty fills the case directory with
#: gigabytes of browser heap.
#:
#: The process cap was 5, which is smaller than an ordinary loader chain. A
#: Formbook sample produced six -- itself, powershell.exe, conhost.exe,
#: RegSvcs.exe, a second RegSvcs.exe spawned by the first, and WerFault.exe --
#: and the cap fell exactly on the second RegSvcs, the process most likely to
#: hold the unpacked payload. It was recorded as "process cap reached" rather
#: than lost silently, which is how this was found, but the image is still gone.
#:
#: The total-size cap is the one that really protects the case directory, and it
#: is unchanged. Raising the process count only allows more *small* dumps.
#:
#: Raised again, from 12, when the delayed re-dump below was added: it takes a
#: second image of every child, so the same chain now consumes close to twice as
#: many. The cap counts dumps rather than distinct processes, and re-dumps are
#: the last to be taken -- so a cap that binds drops precisely the image the
#: re-dump exists to collect.
DEFAULT_MAX_PROCESSES = 20
DEFAULT_MAX_WORKING_SET_MB = 1024
DEFAULT_MAX_TOTAL_MB = 4096

#: Seconds after a descendant first appears to dump it a second time.
#:
#: The spawn dump fires the instant a child is seen, which is by construction
#: before anything has been written into it. A loader that hollows its child
#: creates it suspended, unmaps, writes the payload and only then resumes, so
#: the image captured at first sighting is an empty shell. Across three runs of
#: one .NET loader every RegSvcs.exe dump was ~15 MB of untouched host image,
#: and the payload was only ever recovered from a WER crash dump -- which exists
#: only because that particular payload crashed.
#:
#: A fixed offset from launch cannot substitute. The same binary spawned its
#: target at +20s, +24s and +42s across three runs, so an offset tuned to one
#: run misses the next; measured from the spawn instead, the delay is a property
#: of the technique rather than of the sample's dormancy.
#:
#: 10s is an estimate, not a measurement. Hollowing completes in well under a
#: second, so anything past ~1s captures the mapped payload; the pressure the
#: other way is that a payload which faults takes the process with it. It is
#: recorded in the run summary and overridable per run so the first runs that
#: use it can tune it.
DEFAULT_SPAWN_REDUMP_SECONDS = 10

#: Per-process ProcDump timeout. Full dumps of a large working set are slow on
#: a VM's virtual disk, but a hang here would hold up the whole run teardown.
_DUMP_TIMEOUT_SECONDS = 300


def _decode_tool_output(raw: bytes) -> str:
    """Decode ProcDump's console output, which is UTF-16 on Windows.

    subprocess's text mode decodes with the locale codec, which turns UTF-16LE
    into every character followed by a null -- the failure report rendered
    "D u m p   1   e r r o r :   T a r g e t   p r o c e s s ..." instead of the
    message, making the one field that explains a failed dump unreadable.

    The BOM is not always present, so interleaved nulls are the reliable tell.
    """
    if not raw:
        return ""
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")

    sample = raw[:512]
    odd = sample[1::2]
    if odd and odd.count(0) > (len(odd) * 0.7):
        return raw.decode("utf-16-le", errors="replace")
    return raw.decode("utf-8", errors="replace")


class MemoryDumpError(Exception):
    pass


# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------

def _tools_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "tools"


def find_procdump(configured: str | Path | None = None) -> Optional[Path]:
    """Locate a ProcDump binary. Returns ``None`` when not found.

    The 64-bit build is preferred: it can dump both 32- and 64-bit targets,
    while procdump.exe cannot dump a 64-bit process.
    """
    if configured:
        candidate = Path(configured)
        if candidate.exists():
            return candidate

    tools = _tools_dir()
    for name in ("procdump64.exe", "procdump.exe"):
        candidate = tools / name
        if candidate.exists():
            return candidate

    for name in ("procdump64.exe", "procdump.exe"):
        found = shutil.which(name)
        if found:
            return Path(found)

    return None


def memory_dump_status(configured: str | Path | None = None) -> dict[str, Any]:
    """Preflight summary describing whether process memory can be dumped."""
    procdump = find_procdump(configured)
    elevated = is_elevated()
    have_psutil = psutil is not None

    available = procdump is not None and elevated

    if procdump is None:
        note = (
            "ProcDump not found. Place procdump64.exe under tools/ in the "
            "analysis VM (bootstrap_tools.ps1 installs it) to enable process "
            "memory dumps."
        )
    elif not elevated:
        note = (
            "ProcDump found, but the workbench is not running as Administrator. "
            "Opening another process for a full memory dump requires debug "
            "privilege. Relaunch the workbench elevated."
        )
    else:
        note = "ProcDump is available; process memory will be dumped during the run."

    return {
        "available": bool(available),
        "procdump_path": str(procdump) if procdump else "",
        "elevated": bool(elevated),
        "psutil_available": have_psutil,
        "note": note,
        "tree_note": (
            ""
            if have_psutil
            else "psutil is not installed; only the launched process will be dumped, "
                 "not the children it spawns."
        ),
    }


# ---------------------------------------------------------------------------
# Dump lifecycle
# ---------------------------------------------------------------------------

class MemoryDumpSession:
    """Dumps the sample's process tree at fixed offsets into the run.

    Held as an object because the watcher thread has to outlive the call that
    starts it and span the whole detonation, the same way ``PacketCapture``
    holds its capture process.

    Usage from the orchestrator::

        session = MemoryDumpSession(output_dir=..., dump_offsets=[25])
        session.start()                     # before the sample launches
        ...                                 # run_sample(on_launch=session.set_root_pid)
        result = session.stop()             # after observation ends
    """

    def __init__(
        self,
        output_dir: str | Path,
        procdump_path: str | Path | None = None,
        dump_offsets: list[int] | None = None,
        max_processes: int = DEFAULT_MAX_PROCESSES,
        max_working_set_mb: int = DEFAULT_MAX_WORKING_SET_MB,
        max_total_mb: int = DEFAULT_MAX_TOTAL_MB,
        spawn_redump_seconds: int = DEFAULT_SPAWN_REDUMP_SECONDS,
        status_cb: StatusCallback = None,
    ):
        self.output_dir = Path(output_dir)
        self.procdump_path = procdump_path
        self.dump_offsets = sorted(set(int(o) for o in (dump_offsets or [25]) if int(o) >= 0))
        #: 0 disables the second dump entirely; the spawn dump is unaffected.
        self.spawn_redump_seconds = max(0, int(spawn_redump_seconds))
        self.max_processes = int(max_processes)
        self.max_working_set_mb = int(max_working_set_mb)
        self.max_total_mb = int(max_total_mb)
        self.status_cb = status_cb

        self.procdump: Optional[Path] = None
        self.started = False
        self.error = ""

        self._root_pid: Optional[int] = None
        self._root_pid_event = threading.Event()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        self._root_exit_handled = False
        #: PIDs already considered for a spawn dump, successful or not, so a
        #: process is never dumped twice or retried every tick.
        self._spawn_dumped: set[int] = set()
        #: PID -> elapsed seconds when it was first seen, which is what the
        #: second dump is measured from. Populated for every PID the spawn dump
        #: considers, including ones it could not capture: a child that was
        #: already gone cannot be re-dumped either, and recording it here keeps
        #: the two decisions reading from the same set.
        self._spawn_seen: dict[int, float] = {}
        #: PIDs already considered for the delayed second dump.
        self._redumped: set[int] = set()

        # PID -> descriptor, accumulated while processes are alive so a tree
        # that has already collapsed can still be reported.
        self._known: dict[int, dict[str, Any]] = {}

        # PID -> live psutil handle, captured while the process was running.
        # Liveness is checked through these rather than by re-opening the PID:
        # Windows recycles PIDs, and a recycled one would otherwise read as the
        # sample still running and get dumped in its place.
        self._procs: dict[int, Any] = {}
        self._dumps: list[dict[str, Any]] = []
        self._total_bytes = 0
        self._skipped: list[dict[str, Any]] = []

        # Parents already imaged at the moment they spawned something. Once per
        # parent rather than once per child: a loader that starts three copies of
        # RegSvcs inside 15 ms would otherwise produce three near-identical
        # images of itself.
        self._parent_dumped: set[int] = set()

        # Processes whose exit has already been recorded against the offsets that
        # were still pending, so the record is written once rather than on every
        # subsequent poll.
        self._exit_offsets_recorded: set[int] = set()

    # -- lifecycle --------------------------------------------------------

    def start(self) -> dict[str, Any]:
        """Start the watcher thread. Call before the sample is launched."""
        self.procdump = find_procdump(self.procdump_path)
        if self.procdump is None:
            self.error = "procdump not found"
            return {"started": False, "error": self.error, "procdump_path": ""}

        if not is_elevated():
            self.error = "not running as Administrator"
            return {
                "started": False,
                "error": self.error,
                "procdump_path": str(self.procdump),
            }

        self.output_dir.mkdir(parents=True, exist_ok=True)

        self._thread = threading.Thread(
            target=self._watch,
            name="ringforge-memory-dump",
            daemon=True,
        )
        self._thread.start()
        self.started = True

        return {
            "started": True,
            "error": "",
            "procdump_path": str(self.procdump),
            "dump_offsets": list(self.dump_offsets),
            "spawn_redump_seconds": self.spawn_redump_seconds,
        }

    def set_root_pid(self, pid: int) -> None:
        """Hand the watcher the sample's PID. Safe to call from any thread.

        The handle is opened here, on the caller's thread, because this runs
        microseconds after Popen returns. Deferring it to the watcher's first
        poll is late enough that a fast sample can already be gone, and a
        handle opened after the fact carries no proof it is the same process.
        """
        with self._lock:
            if self._root_pid is not None:
                return
            self._root_pid = int(pid)
            if psutil is not None:
                try:
                    self._procs[int(pid)] = psutil.Process(int(pid))
                except Exception:
                    pass
        self._root_pid_event.set()

    def activity_observed(self) -> bool:
        """True once the sample has been seen to spawn something.

        The observation window asks this to tell a sample that is still dormant
        from one that has already acted. Sticky by construction: ``_known``
        accumulates and is never pruned, so a child that has since exited still
        counts. A probe that only looked at live children would report a
        loader which spawned and collapsed as having done nothing, and the
        window would then extend for the full cap waiting for behaviour that
        had already happened.
        """
        with self._lock:
            root = self._root_pid
            return any(pid != root for pid in self._known)

    def stop(self, timeout: float = _DUMP_TIMEOUT_SECONDS + 30) -> dict[str, Any]:
        """Stop watching and return everything collected."""
        self._stop_event.set()
        # A watcher blocked waiting for a PID that never arrives -- a launch that
        # threw -- must not hold up teardown.
        self._root_pid_event.set()

        if self._thread is not None:
            self._thread.join(timeout=timeout)

        with self._lock:
            dumps = list(self._dumps)
            skipped = list(self._skipped)
            observed = list(self._known.values())
            total_bytes = self._total_bytes

        successful = [d for d in dumps if d.get("success")]

        return {
            "stopped": True,
            "started": self.started,
            "error": self.error,
            "procdump_path": str(self.procdump) if self.procdump else "",
            "root_pid": self._root_pid,
            "dump_offsets": list(self.dump_offsets),
            "spawn_redump_seconds": self.spawn_redump_seconds,
            "dumps": dumps,
            "skipped": skipped,
            "observed_processes": observed,
            "counts": {
                "processes_observed": len(observed),
                "dumps_attempted": len(dumps),
                "dumps_succeeded": len(successful),
                "dumps_skipped": len(skipped),
                "total_bytes": total_bytes,
            },
        }

    # -- watcher ----------------------------------------------------------

    def _emit(self, message: str) -> None:
        if self.status_cb:
            self.status_cb(message)

    def _watch(self) -> None:
        """Track the sample's process tree and dump it at each offset."""
        # The offsets are relative to the sample launching, not to this thread
        # starting, so the clock does not begin until the PID arrives.
        self._root_pid_event.wait()
        if self._stop_event.is_set() or self._root_pid is None:
            return

        launched_at = time.monotonic()
        pending = list(self.dump_offsets)

        try:
            self._watch_loop(launched_at, pending)
        finally:
            # Every exit from the loop is a point where a scheduled re-dump can
            # still be outstanding -- the tree collapsed, or the run ended
            # first. Recorded rather than dropped, so "the payload window closed
            # before we could look again" cannot read as "we looked and found
            # nothing".
            self._flush_pending_redumps(time.monotonic() - launched_at)

    def _watch_loop(self, launched_at: float, pending: list[int]) -> None:
        """The poll loop itself. Split out so every exit runs the flush above."""
        # Not `while pending`: a tree that has finished its scheduled offsets can
        # still spawn the process that matters. The loop now runs until the
        # session is stopped or nothing of the sample is left alive.
        while not self._stop_event.is_set():
            self._refresh_tree()

            elapsed = time.monotonic() - launched_at
            root_alive = self._pid_alive(self._root_pid)
            due = [o for o in pending if elapsed >= o]

            # A newly appeared descendant is dumped the moment it is seen.
            #
            # Fixed offsets cannot catch a crypter that sleeps: one real sample
            # sat dormant for 77 seconds, then launched a second copy of itself
            # which crashed within a couple of seconds. The +5s and +25s dumps
            # both captured the dormant launcher, the payload process was never
            # dumped at all, and the run reported a clean result. No choice of
            # offsets fixes that in general -- the delay differs per crypter, and
            # a missed window is indistinguishable from a quiet sample.
            #
            # The 0.5s poll is what makes this viable: the tree is already
            # walked on every tick, so a child only has to outlive one interval.
            #
            # A scheduled offset falling on the same tick still runs. The two
            # answer different questions -- what is new, versus what the whole
            # tree looks like at a chosen moment -- and the spawn dump excludes
            # the root, so they do not duplicate each other.
            self._dump_spawned_children(elapsed)

            # A process that dies with scheduled offsets still ahead of it takes
            # those images with it, and until this record existed nothing said
            # so. Recorded here rather than where the offsets fire, because
            # `_dump_tree` only ever sees live processes: a dead one is simply
            # absent from its target list, which is the silence this closes.
            self._record_offsets_pending_at_exit(elapsed, pending)

            # And again once the child has had time to be written into. The
            # spawn dump above necessarily catches it before that: a hollowing
            # loader creates its target suspended and only then unmaps and
            # writes, so first sighting is always an empty shell.
            self._dump_spawn_redumps(elapsed)

            # The root exiting is the last moment anything can be salvaged from
            # a tree that may be about to disappear entirely, so it triggers an
            # extra dump of whatever is still alive.
            #
            # Deliberately an addition rather than a substitution. Consuming the
            # next scheduled offset instead would dump a surviving child at the
            # moment its parent died -- typically seconds in, before it has
            # unpacked anything -- and then never again at the offset that was
            # chosen precisely because it is late enough to be interesting.
            #
            # Skipped when a scheduled dump is already due on this same tick,
            # which would otherwise write two near-identical images.
            #
            # That skip is recorded. A Formbook run exited at ~t24 with the
            # +25s offset due on the same tick, so the exit dump was suppressed
            # and the scheduled dump covered only the surviving children -- the
            # sample's own process was captured once, at +5s, before it had
            # spawned anything. Nothing in the report said the exit dump had
            # been skipped, which left "we chose not to" looking exactly like
            # "there was nothing to take".
            if not root_alive and not self._root_exit_handled:
                self._root_exit_handled = True
                self._record_root_never_dumped(elapsed)
                if not due:
                    self._dump_tree(
                        offset=int(elapsed),
                        elapsed=elapsed,
                        trigger="process-exit",
                    )
                else:
                    with self._lock:
                        root = dict(self._known.get(self._root_pid or -1) or {})
                    self._record_skip(
                        {
                            "pid": self._root_pid,
                            "name": root.get("name", ""),
                        },
                        int(elapsed),
                        "exit dump not taken: a scheduled dump was due on the "
                        f"same tick (+{', +'.join(str(o) for o in due)}s)",
                    )

            for offset in due:
                pending.remove(offset)
                if self._stop_event.is_set():
                    return
                self._dump_tree(offset=offset, elapsed=elapsed, trigger="scheduled")

            # Nothing from the sample tree is running any more, so neither a
            # future offset nor a future spawn can produce anything.
            if not self._dump_targets():
                return

            self._stop_event.wait(_POLL_INTERVAL_SECONDS)

    def _dump_spawned_children(self, elapsed: float) -> bool:
        """Dump descendants seen for the first time. Returns True if any were.

        The root is excluded: it is covered by the scheduled offsets, and
        dumping it here would add a near-duplicate image at +0s.
        """
        root_pid = self._root_pid

        with self._lock:
            candidates = [
                dict(info)
                for pid, info in self._known.items()
                if pid != root_pid and pid not in self._spawn_dumped
            ]

        dumped_any = False
        for target in candidates:
            if self._stop_event.is_set():
                return dumped_any

            pid = int(target["pid"])
            # Marked before the attempt, not after. A process that dies during
            # the dump must not be retried on every subsequent tick.
            with self._lock:
                self._spawn_dumped.add(pid)

            # The parent first, and before the liveness check on the child --
            # because the parent is the image worth having and it is the one with
            # a deadline. See `_dump_parent_at_spawn`.
            self._dump_parent_at_spawn(target, elapsed)

            if not self._pid_alive(pid):
                # Seen and gone inside one poll interval. Recorded rather than
                # ignored, because "we saw a child we could not capture" is a
                # finding -- it is exactly the case that produced a clean report
                # from a sample that had in fact staged a payload.
                self._record_skip(target, int(elapsed), "child exited before it could be dumped")
                continue

            with self._lock:
                total_mb = self._total_bytes / (1024 * 1024)
                already = len([d for d in self._dumps if d.get("success")])

            if already >= self.max_processes:
                self._record_skip(target, int(elapsed), "process cap reached")
                continue
            if total_mb >= self.max_total_mb:
                self._record_skip(target, int(elapsed), "total dump size cap reached")
                continue

            working_set = self._working_set_mb(pid)
            if working_set > self.max_working_set_mb:
                self._record_skip(
                    target,
                    int(elapsed),
                    f"working set {working_set} MB exceeds the {self.max_working_set_mb} MB limit",
                )
                continue

            # Queued for the delayed second dump only once the spawn dump is
            # actually going ahead. A child that was already gone, or that a cap
            # turned away, has been recorded as skipped once already, and the
            # re-dump could only record the same thing a second time.
            with self._lock:
                self._spawn_seen[pid] = elapsed

            self._emit(
                f"Memory dump at +{int(elapsed)}s (process-spawn): "
                f"new process pid {pid} ({target.get('name') or '?'})"
            )

            record = self._dump_one(target, int(elapsed), "process-spawn")
            with self._lock:
                self._dumps.append(record)
                self._total_bytes += int(record.get("size", 0) or 0)

            if record.get("success"):
                dumped_any = True
                self._emit(
                    f"  dumped pid {record['pid']} ({record['name'] or '?'}) "
                    f"-> {Path(record['path']).name} "
                    f"({int(record.get('size', 0)) // (1024 * 1024)} MB)"
                )
            else:
                self._emit(
                    f"  dump failed for pid {record['pid']} "
                    f"({record['name'] or '?'}): {record.get('error', 'unknown error')}"
                )

        return dumped_any

    def _dump_parent_at_spawn(self, child: dict[str, Any], elapsed: float) -> None:
        """Image a process at the moment it starts a child.

        The one instant a loader is guaranteed to be holding its payload. It has
        decrypted the next stage and is about to write it into the process it just
        created -- so unlike every scheduled offset, this trigger is a property of
        the technique rather than a guess about timing.

        Seven runs of the same loader are the argument. Its dormancy has been
        +20, +23, +24, +42, +48 and +60s, so the window in which the parent is
        both unpacked and still alive is `[unpack, spawn + ~1s]` and moves by
        forty seconds between runs. A fixed offset lands inside it by luck: +25s
        found the payload on the run where dormancy was 48s and found nothing on
        the run where it was 23s, because the parent had already exited. No choice
        of offsets fixes that, which is the same argument that produced the spawn
        dump for children -- applied to the side of the pair that turned out to
        hold the evidence.

        **Ordered before the child's own dump, deliberately.** A dump takes
        seconds and the parent often has about one second left: on 06 Aug 21:15
        the root spawned `RegSvcs` at +23s and was gone by +24s. The child is the
        cheaper thing to lose -- across seven runs its spawn dump has been an
        empty shell every time, 11 to 15 MB with no unmapped image in it -- and
        losing it is recorded as a skip, so the cost is visible. `_dump_one`
        suspends its target, so the parent cannot exit part-way through its own
        dump once the dump has started.

        Once per parent. Caps are honoured and a refusal is recorded, the same as
        anywhere else.
        """
        parent_pid = child.get("parent_pid")
        try:
            parent_pid = int(parent_pid)
        except (TypeError, ValueError):
            return

        with self._lock:
            if parent_pid in self._parent_dumped:
                return
            # Only processes the watcher already tracks. The root's own parent is
            # the analyzer's python.exe, and dumping that would be both useless
            # and a 200 MB image of ourselves.
            parent = self._known.get(parent_pid)
            if parent is None:
                return
            parent = dict(parent)
            self._parent_dumped.add(parent_pid)

            total_mb = self._total_bytes / (1024 * 1024)
            already = len([d for d in self._dumps if d.get("success")])

        if not self._pid_alive(parent_pid):
            # It spawned the child and was gone within the poll interval. Worth a
            # record: it says the payload was in a process nobody could reach.
            self._record_skip(
                parent,
                int(elapsed),
                f"parent exited before it could be imaged at the spawn of pid {child.get('pid')}",
            )
            return

        if already >= self.max_processes:
            self._record_skip(parent, int(elapsed), "process cap reached")
            return
        if total_mb >= self.max_total_mb:
            self._record_skip(parent, int(elapsed), "total dump size cap reached")
            return

        working_set = self._working_set_mb(parent_pid)
        if working_set > self.max_working_set_mb:
            self._record_skip(
                parent,
                int(elapsed),
                f"working set {working_set} MB exceeds the {self.max_working_set_mb} MB limit",
            )
            return

        self._emit(
            f"Memory dump at +{int(elapsed)}s (parent-at-spawn): "
            f"pid {parent_pid} ({parent.get('name') or '?'}) as it started "
            f"pid {child.get('pid')} ({child.get('name') or '?'})"
        )

        record = self._dump_one(parent, int(elapsed), "parent-at-spawn")
        record["spawned_pid"] = child.get("pid")
        record["spawned_name"] = child.get("name", "")
        with self._lock:
            self._dumps.append(record)
            self._total_bytes += int(record.get("size", 0) or 0)

        if record.get("success"):
            self._emit(
                f"  dumped pid {record['pid']} ({record['name'] or '?'}) "
                f"-> {Path(record['path']).name} "
                f"({int(record.get('size', 0)) // (1024 * 1024)} MB)"
            )
        else:
            self._emit(
                f"  dump failed for pid {record['pid']} "
                f"({record['name'] or '?'}): {record.get('error', 'unknown error')}"
            )

    def _dump_spawn_redumps(self, elapsed: float) -> bool:
        """Dump spawned children again once they have had time to be written.

        The pairing is the point. The spawn dump says what the process looked
        like before the loader touched it and this one says what it looks like
        after, so a payload that appears between them is visible as a
        difference between two images of the same PID rather than having to be
        recognised in isolation.
        """
        if not self.spawn_redump_seconds:
            return False

        with self._lock:
            due_pids = [
                pid
                for pid, seen_at in self._spawn_seen.items()
                if pid not in self._redumped
                and elapsed >= seen_at + self.spawn_redump_seconds
            ]
            candidates = [
                dict(self._known[pid]) for pid in due_pids if pid in self._known
            ]

        dumped_any = False
        for target in candidates:
            if self._stop_event.is_set():
                return dumped_any

            pid = int(target["pid"])
            # Marked before the attempt, for the same reason as the spawn dump:
            # a failure must not become a retry on every subsequent tick.
            with self._lock:
                self._redumped.add(pid)

            if not self._pid_alive(pid):
                # The interesting case, and the reason this is recorded rather
                # than passed over. A hollowed process that faults takes the
                # payload with it, so "died before the re-dump" says the window
                # closed early -- and points at the WER crash dump as the only
                # remaining source for that image.
                self._record_skip(
                    target,
                    int(elapsed),
                    f"process exited before its +{self.spawn_redump_seconds}s re-dump",
                )
                continue

            with self._lock:
                total_mb = self._total_bytes / (1024 * 1024)
                already = len([d for d in self._dumps if d.get("success")])

            if already >= self.max_processes:
                self._record_skip(target, int(elapsed), "process cap reached")
                continue
            if total_mb >= self.max_total_mb:
                self._record_skip(target, int(elapsed), "total dump size cap reached")
                continue

            working_set = self._working_set_mb(pid)
            if working_set > self.max_working_set_mb:
                self._record_skip(
                    target,
                    int(elapsed),
                    f"working set {working_set} MB exceeds the {self.max_working_set_mb} MB limit",
                )
                continue

            self._emit(
                f"Memory dump at +{int(elapsed)}s (spawn-redump): "
                f"pid {pid} ({target.get('name') or '?'}), "
                f"{self.spawn_redump_seconds}s after it appeared"
            )

            record = self._dump_one(target, int(elapsed), "spawn-redump")
            with self._lock:
                self._dumps.append(record)
                self._total_bytes += int(record.get("size", 0) or 0)

            if record.get("success"):
                dumped_any = True
                self._emit(
                    f"  dumped pid {record['pid']} ({record['name'] or '?'}) "
                    f"-> {Path(record['path']).name} "
                    f"({int(record.get('size', 0)) // (1024 * 1024)} MB)"
                )
            else:
                self._emit(
                    f"  dump failed for pid {record['pid']} "
                    f"({record['name'] or '?'}): {record.get('error', 'unknown error')}"
                )

        return dumped_any

    def _record_offsets_pending_at_exit(self, elapsed: float, pending: list[int]) -> None:
        """Say which scheduled images a process took with it when it exited.

        The hole this closes cost the payload on a live run. On 06 Aug 21:15 the
        loader's own process was dumped at +1s, spawned `RegSvcs` at +23s and
        exited a second later, with the +25s offset never coming due for it. The
        run recorded 9 successful dumps, 1 skip and 2 failures, and **nothing at
        all** about the missing +25s image of the packer -- which is where the
        same offset had found the payload on the previous run. Read side by side,
        the two runs said `unmapped_images: 1` and `unmapped_images: 0`, and
        nothing distinguished "the packer held no payload" from "the dump that
        would have held it was never taken".

        `_record_root_never_dumped` covers only the harder case, a root that was
        never imaged at all, and returns silently when the root got even one
        dump. That early return is what made this invisible.
        """
        if not pending:
            return

        with self._lock:
            known = list(self._known.values())
            dumped_pids = {
                d.get("pid") for d in self._dumps if d.get("success")
            }

        root_pid = self._root_pid
        for info in known:
            pid = int(info.get("pid") or -1)
            if pid < 0 or pid in self._exit_offsets_recorded:
                continue
            if self._pid_alive(pid):
                continue

            self._exit_offsets_recorded.add(pid)

            # A root that was never dumped has its own, more specific record.
            # Two entries saying nearly the same thing about one process is the
            # kind of noise that makes a skip list stop being read.
            if pid == root_pid and pid not in dumped_pids:
                continue

            missed = ", ".join(f"+{o}s" for o in sorted(pending))
            self._record_skip(
                {"pid": pid, "name": info.get("name", "")},
                int(elapsed),
                f"process exited with scheduled offset(s) {missed} still pending, "
                "so those images were never taken",
            )

    def _record_root_never_dumped(self, elapsed: float) -> None:
        """Say so when the sample's own process was never captured.

        The root has exactly one route to being dumped: a scheduled offset that
        comes due while it is still alive. The spawn dump excludes it by design
        and the exit dump runs after it is already gone and unreadable. So a
        sample that spawns a child and exits inside the first offset is never
        imaged at all.

        That is the process that matters most on a dropper -- it is the one that
        did the unpacking. A Remcos run wrote five dumps, all of them of the
        dropped child, while the parent exited at ~t1 with the first offset at
        +5. `dumps_skipped` read 0, so the report could not distinguish "the
        packer was captured and held nothing" from "the packer was never
        looked at".
        """
        root_pid = self._root_pid
        if root_pid is None:
            return

        with self._lock:
            dumped = any(
                d.get("pid") == root_pid and d.get("success") for d in self._dumps
            )
            root = dict(self._known.get(root_pid) or {})

        if dumped:
            return

        pending = ", ".join(f"+{o}s" for o in self.dump_offsets)
        self._record_skip(
            {"pid": root_pid, "name": root.get("name", "")},
            int(elapsed),
            "the sample's own process exited before any scheduled offset came "
            f"due (offsets: {pending or 'none'}) and was never dumped; only the "
            "processes it spawned were captured",
        )

    def _flush_pending_redumps(self, elapsed: float) -> None:
        """Record re-dumps that were still owed when the watcher stopped."""
        if not self.spawn_redump_seconds:
            return

        with self._lock:
            outstanding = [
                dict(self._known[pid])
                for pid in self._spawn_seen
                if pid not in self._redumped and pid in self._known
            ]
            self._redumped.update(int(t["pid"]) for t in outstanding)

        for target in outstanding:
            # Which of the two ran out first is the whole content of this
            # record. "It died" says the payload window was shorter than the
            # delay and the delay wants lowering; "the run ended" says the
            # observation window was too short and the process may well still
            # have been holding the payload when the run was torn down.
            reason = (
                f"observation ended before its +{self.spawn_redump_seconds}s re-dump"
                if self._pid_alive(int(target["pid"]))
                else f"process exited before its +{self.spawn_redump_seconds}s re-dump"
            )
            self._record_skip(target, int(elapsed), reason)

    def _pid_alive(self, pid: int | None) -> bool:
        if pid is None:
            return False
        if psutil is None:
            # Without psutil there is no safe liveness check, so assume alive
            # and let ProcDump report the failure if the process has gone.
            return True

        with self._lock:
            process = self._procs.get(int(pid))
        if process is None:
            return False

        try:
            return process.is_running() and process.status() != psutil.STATUS_ZOMBIE
        except Exception:
            return False

    def _refresh_tree(self) -> None:
        """Record the root process and its descendants as they appear."""
        root_pid = self._root_pid
        if root_pid is None:
            return

        if psutil is None:
            with self._lock:
                self._known.setdefault(
                    root_pid,
                    {"pid": root_pid, "name": "", "image": "", "parent_pid": None},
                )
            return

        # Walk out from every process still tracked, not just the root. A
        # dropper that launches a child and exits is the common shape, and
        # anchoring the walk on the root alone loses the grandchildren it
        # spawns after the parent is already gone.
        with self._lock:
            handles = list(self._procs.values())

        candidates: list[Any] = []
        seen: set[int] = set()
        for handle in handles:
            for process in [handle] + self._children_of(handle):
                if process.pid not in seen:
                    seen.add(process.pid)
                    candidates.append(process)

        for process in candidates:
            try:
                info = {
                    "pid": process.pid,
                    "name": process.name(),
                    "image": process.exe(),
                    "parent_pid": process.ppid(),
                }
            except Exception:
                # A process that vanished between enumeration and inspection, or
                # one whose image path is unreadable, is still worth recording.
                try:
                    info = {"pid": process.pid, "name": "", "image": "", "parent_pid": None}
                except Exception:
                    continue

            with self._lock:
                self._procs.setdefault(info["pid"], process)
                existing = self._known.get(info["pid"])
                if existing is None:
                    self._known[info["pid"]] = info
                else:
                    # Fill in details that were unreadable on an earlier pass.
                    for key, value in info.items():
                        if value and not existing.get(key):
                            existing[key] = value

    @staticmethod
    def _children_of(handle: Any) -> list[Any]:
        try:
            return list(handle.children(recursive=True))
        except Exception:
            return []

    def _dump_targets(self) -> list[dict[str, Any]]:
        """Pick which live processes to dump, root first."""
        with self._lock:
            known = list(self._known.values())

        root_pid = self._root_pid
        live = [p for p in known if self._pid_alive(p["pid"])]

        # Root first, then the rest in the order they were discovered, so a cap
        # keeps the sample itself and its earliest children rather than an
        # arbitrary slice.
        live.sort(key=lambda p: (p["pid"] != root_pid, p["pid"]))
        return live

    def _suspend(self, pid: int) -> bool:
        """Freeze a process for the duration of its dump. True if suspended.

        Two reasons, and the second is why this exists.

        A dump of a running process is a smear: ProcDump reads hundreds of
        megabytes while the target keeps writing, so the image is not a snapshot
        of any single instant.

        More importantly it removes a race that has already cost a payload. A
        spawned child is dumped the moment it appears, but one real sample's
        second-generation process exited mid-read -- ProcDump reported
        ERROR_PARTIAL_COPY and wrote nothing usable. A suspended process cannot
        run the code that would exit it, so the window shrinks from "however
        long the dump takes" to "however long between noticing and suspending".

        A missing handle is the only "cannot suspend" case, and it covers a
        missing psutil too: the handle map is populated only where psutil is
        present, so it is empty when psutil is not.
        """
        with self._lock:
            process = self._procs.get(int(pid))
        if process is None:
            return False

        try:
            process.suspend()
            return True
        except Exception:
            # Already gone, or access denied on a protected process. Neither is
            # worth failing the dump over -- it just proceeds unsuspended.
            return False

    def _resume(self, pid: int) -> None:
        """Unfreeze a process. Failures here are deliberately silent.

        Called only from a finally block. A process that died during its own
        dump cannot be resumed and does not need to be; the thing that must not
        happen is an exception on this path leaving the sample frozen for the
        rest of the run.

        Only ever called when the matching ``_suspend`` returned True, so a
        missing handle here means the process is gone, not that it is frozen.
        """
        with self._lock:
            process = self._procs.get(int(pid))
        if process is None:
            return

        try:
            process.resume()
        except Exception:
            pass

    def _working_set_mb(self, pid: int) -> int:
        if psutil is None:
            return 0
        with self._lock:
            process = self._procs.get(int(pid))
        if process is None:
            return 0
        try:
            return int(process.memory_info().rss / (1024 * 1024))
        except Exception:
            return 0

    def _dump_tree(self, offset: int, elapsed: float, trigger: str) -> None:
        targets = self._dump_targets()

        if not targets:
            self._emit(
                f"Memory dump at +{int(elapsed)}s ({trigger}): "
                "no live process remained from the sample."
            )
            return

        self._emit(
            f"Memory dump at +{int(elapsed)}s ({trigger}): "
            f"{len(targets)} live process(es) from the sample tree."
        )

        dumped = 0
        for target in targets:
            if self._stop_event.is_set():
                return

            if dumped >= self.max_processes:
                self._record_skip(target, offset, "process cap reached")
                continue

            with self._lock:
                total_mb = self._total_bytes / (1024 * 1024)
            if total_mb >= self.max_total_mb:
                self._record_skip(target, offset, "total dump size cap reached")
                continue

            working_set = self._working_set_mb(target["pid"])
            if working_set > self.max_working_set_mb:
                self._record_skip(
                    target,
                    offset,
                    f"working set {working_set} MB exceeds the {self.max_working_set_mb} MB limit",
                )
                continue

            record = self._dump_one(target, offset, trigger)
            with self._lock:
                self._dumps.append(record)
                self._total_bytes += int(record.get("size", 0) or 0)

            if record.get("success"):
                dumped += 1
                self._emit(
                    f"  dumped pid {record['pid']} ({record['name'] or '?'}) "
                    f"-> {Path(record['path']).name} "
                    f"({int(record.get('size', 0)) // (1024 * 1024)} MB)"
                )
            else:
                self._emit(
                    f"  dump failed for pid {record['pid']} "
                    f"({record['name'] or '?'}): {record.get('error', 'unknown error')}"
                )

    def _record_skip(self, target: dict[str, Any], offset: int, reason: str) -> None:
        with self._lock:
            self._skipped.append(
                {
                    "pid": target["pid"],
                    "name": target.get("name", ""),
                    "offset_seconds": offset,
                    "reason": reason,
                }
            )
        self._emit(f"  skipped pid {target['pid']} ({target.get('name') or '?'}): {reason}")

    def _dump_one(
        self, target: dict[str, Any], offset: int, trigger: str = "scheduled"
    ) -> dict[str, Any]:
        pid = int(target["pid"])
        name = target.get("name", "") or f"pid{pid}"
        safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)
        # The trigger is part of the filename because an exit-triggered dump can
        # land on the same whole second as a scheduled one, and the two are
        # different evidence. The re-dump needs it for a sharper reason: a
        # scheduled offset landing on the same second would otherwise overwrite
        # the one image taken after the payload was written.
        suffix = {
            "process-exit": "_exit",
            "spawn-redump": "_redump",
            "parent-at-spawn": "_atspawn",
        }.get(trigger, "")
        out_path = self.output_dir / f"{safe_name}_{pid}_t{offset}{suffix}.dmp"

        record: dict[str, Any] = {
            "pid": pid,
            "name": target.get("name", ""),
            "image": target.get("image", ""),
            "parent_pid": target.get("parent_pid"),
            "offset_seconds": offset,
            "trigger": trigger,
            "path": str(out_path),
            "size": 0,
            "sha256": "",
            "success": False,
            "returncode": None,
            "duration_seconds": 0,
            "error": "",
        }

        started = time.monotonic()

        # Suspended for the dump, and resumed in the finally below whatever
        # happens. A leaked suspension would freeze the sample for the rest of
        # the run, which is worse than any dump failure it could prevent.
        suspended = self._suspend(pid)
        record["suspended"] = suspended

        try:
            # Bytes, not text: ProcDump emits UTF-16 and the locale codec
            # mangles it. Decoded explicitly below.
            result = subprocess.run(
                [str(self.procdump), "-accepteula", "-ma", str(pid), str(out_path)],
                capture_output=True,
                timeout=_DUMP_TIMEOUT_SECONDS,
            )
            record["returncode"] = int(result.returncode)
            stdout_text = _decode_tool_output(result.stdout or b"")
            stderr_text = _decode_tool_output(result.stderr or b"")
            record["stderr"] = stderr_text.strip()[:2000]
        except subprocess.TimeoutExpired:
            record["error"] = f"procdump timed out after {_DUMP_TIMEOUT_SECONDS} seconds"
            record["duration_seconds"] = int(time.monotonic() - started)
            return record
        except Exception as error:
            record["error"] = str(error)
            record["duration_seconds"] = int(time.monotonic() - started)
            return record
        finally:
            if suspended:
                self._resume(pid)

        record["duration_seconds"] = int(time.monotonic() - started)

        # ProcDump's exit code is not a reliable success signal -- it reports the
        # number of dumps written on some versions -- so the artifact decides.
        if out_path.exists() and out_path.stat().st_size > 0:
            record["size"] = out_path.stat().st_size
            record["success"] = True
            try:
                record["sha256"] = sha256_file(out_path)
            except Exception as error:
                record["sha256_error"] = str(error)
        else:
            # Collapsed to one line: ProcDump pads its output with blank lines
            # and timestamps, which made a one-sentence error span ten rows of
            # the report table.
            detail = " ".join((record.get("stderr") or stdout_text).split())
            record["error"] = (
                detail[-500:]
                or f"procdump wrote no dump file (rc={result.returncode})"
            )

        return record


# ---------------------------------------------------------------------------
# Summarising
# ---------------------------------------------------------------------------

def summarize_memory_dumps(dump_result: dict[str, Any]) -> dict[str, Any]:
    """Aggregate a session result into the shape the run summary carries."""
    if not isinstance(dump_result, dict):
        return {"collected": False, "counts": {}, "dumps": []}

    dumps = dump_result.get("dumps", []) or []
    successful = [d for d in dumps if d.get("success")]
    counts = dump_result.get("counts", {}) or {}

    return {
        "collected": bool(successful),
        "counts": {
            "processes_observed": int(counts.get("processes_observed", 0) or 0),
            "dumps_attempted": len(dumps),
            "dumps_succeeded": len(successful),
            "dumps_skipped": int(counts.get("dumps_skipped", 0) or 0),
            "total_mb": int(int(counts.get("total_bytes", 0) or 0) / (1024 * 1024)),
        },
        "dumps": [
            {
                "pid": d.get("pid"),
                "name": d.get("name", ""),
                "image": d.get("image", ""),
                "offset_seconds": d.get("offset_seconds"),
                "trigger": d.get("trigger", ""),
                "path": d.get("path", ""),
                "size_mb": int(int(d.get("size", 0) or 0) / (1024 * 1024)),
                "sha256": d.get("sha256", ""),
                # A dump taken unsuspended is a smear rather than a snapshot,
                # so whether the freeze succeeded is part of reading the result.
                "suspended": bool(d.get("suspended", False)),
            }
            for d in successful
        ],
        "failures": [
            {
                "pid": d.get("pid"),
                "name": d.get("name", ""),
                "offset_seconds": d.get("offset_seconds"),
                # Without this, two attempts on the same PID from different
                # triggers -- a spawn dump and the root-exit sweep, say --
                # render as identical rows.
                "trigger": d.get("trigger", ""),
                "error": d.get("error", ""),
            }
            for d in dumps
            if not d.get("success")
        ],
        "skipped": dump_result.get("skipped", []),
        "observed_processes": dump_result.get("observed_processes", []),
    }


def _sysmon_process_creates(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """ProcessCreate records, normalised to what the reconciliation needs."""
    creates: list[dict[str, Any]] = []
    for event in events or []:
        if event.get("event_id") != 1:
            continue
        data = event.get("data", {}) or {}
        pid = _safe_pid(data.get("ProcessId"))
        if pid is None:
            continue
        creates.append(
            {
                "pid": pid,
                "parent_pid": _safe_pid(data.get("ParentProcessId")),
                "image": str(data.get("Image", "") or ""),
                "parent_image": str(data.get("ParentImage", "") or ""),
                "command_line": str(data.get("CommandLine", "") or ""),
                "timestamp": str(event.get("timestamp", "") or ""),
            }
        )
    return creates


def _safe_pid(value: object) -> Optional[int]:
    try:
        pid = int(str(value).strip())
    except Exception:
        return None
    return pid if pid > 0 else None


def _image_name(value: object) -> str:
    return str(value or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()


def sample_descendant_pids(
    sysmon_events: list[dict[str, Any]],
    sample_pid: int | None = None,
    sample_name: str = "",
) -> set[int]:
    """Every PID in the sample's tree, from Sysmon's ProcessCreate records.

    Sysmon's ProcessCreate is a kernel callback and misses nothing, which makes
    it the authority on lineage -- better than the dump watcher's poll, which
    only sees a child that outlives one interval.

    Seeded the same way the findings lineage is: the launched PID, plus any
    process running the sample's own image, because a dropper relaunching
    itself is the shape this exists for. Then walked transitively.

    Returns an empty set when there is nothing to seed from, which callers must
    read as "lineage could not be resolved" rather than "the sample had no
    descendants" -- the two want opposite handling.
    """
    creates = _sysmon_process_creates(sysmon_events)
    if not creates:
        return set()

    sample_image = _image_name(sample_name)

    descendants: set[int] = set()
    if sample_pid:
        descendants.add(int(sample_pid))
    if sample_image:
        for create in creates:
            if _image_name(create["image"]) == sample_image:
                descendants.add(create["pid"])

    if not descendants:
        return set()

    changed = True
    while changed:
        changed = False
        for create in creates:
            parent = create["parent_pid"]
            if parent in descendants and create["pid"] not in descendants:
                descendants.add(create["pid"])
                changed = True

    return descendants


def reconcile_with_sysmon(
    dump_result: dict[str, Any],
    sysmon_events: list[dict[str, Any]],
    sample_pid: int | None = None,
    sample_name: str = "",
) -> list[dict[str, Any]]:
    """Descendants Sysmon recorded that the watcher never saw.

    The watcher walks the process tree twice a second, so a child has to
    outlive one interval to be noticed at all. One AgentTesla sample created
    two copies of itself seven milliseconds apart: the second was dumped with
    three rules matching, the first was never observed, and nothing in the run
    said it had existed.

    Sysmon's ProcessCreate is a kernel callback and misses nothing, so the
    difference between its tree and the watcher's is precisely what the poll
    dropped.

    Reported, never dumped. A process that lived milliseconds is gone long
    before ProcDump could attach, and no poll interval fixes that -- shortening
    it only moves the threshold. What this fixes is a payload staged in a
    process nobody knew had run, which is the same failure the spawn trigger
    was built for one level down.
    """
    creates = _sysmon_process_creates(sysmon_events)
    if not creates:
        return []

    descendants = sample_descendant_pids(sysmon_events, sample_pid, sample_name)
    if not descendants:
        return []

    observed = {
        _safe_pid(p.get("pid"))
        for p in (dump_result.get("observed_processes", []) or [])
    }
    observed.discard(None)

    missed: list[dict[str, Any]] = []
    seen: set[int] = set()
    for create in creates:
        pid = create["pid"]
        if pid in observed or pid in seen or pid not in descendants:
            continue
        seen.add(pid)
        missed.append(create)

    return missed


def dump_paths(dump_result: dict[str, Any]) -> list[Path]:
    """Paths of the dumps that were actually written."""
    dumps = dump_result.get("dumps", []) if isinstance(dump_result, dict) else []
    return [Path(d["path"]) for d in dumps if d.get("success") and d.get("path")]


def successful_dumps(dump_result: dict[str, Any]) -> list[dict[str, Any]]:
    """Dump records that produced a file on disk.

    The handoff point for the YARA pass: it scans exactly these, and keeps each
    record's pid, offset and trigger so a match can say which process it came
    from and when.
    """
    dumps = dump_result.get("dumps", []) if isinstance(dump_result, dict) else []
    return [d for d in dumps if d.get("success") and d.get("path")]
