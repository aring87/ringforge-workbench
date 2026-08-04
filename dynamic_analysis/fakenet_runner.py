"""FakeNet-NG integration for dynamic analysis runs.

Malware that cannot reach its C2 usually does nothing observable, so a
detonation on an isolated VM tends to under-report. FakeNet-NG answers DNS,
HTTP, HTTPS and raw TCP/UDP locally, which makes the sample proceed through its
real logic while every request is captured.

It also keeps the detonation contained: the sample talks to the local
responder instead of live attacker infrastructure, so the run neither reaches
out to a third party nor signals the operator that the sample was executed.

FakeNet writes its own pcap into the working directory, so the process is
started with ``cwd`` set to the run's network folder.

Its listeners, however, serve and receive files from their own roots inside the
FakeNet installation, which is outside the case directory -- see
``_collect_received_files``.

Requires Administrator rights (it installs a traffic diverter).
"""

from __future__ import annotations

import configparser
import os
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Any, Optional

from dynamic_analysis.utils import sha256_file

#: DNS request lines, e.g. "Received A request for domain 'evil.com'".
_DNS_RE = re.compile(
    r"request for domain\s+['\"]?([A-Za-z0-9_.\-]+)['\"]?", re.IGNORECASE
)
#: HTTP request lines, e.g. "GET /gate.php HTTP/1.1".
_HTTP_REQUEST_RE = re.compile(
    r"\b(GET|POST|HEAD|PUT|PATCH|DELETE|OPTIONS)\s+(\S+)\s+HTTP/\d", re.IGNORECASE
)
_HOST_HEADER_RE = re.compile(r"^\s*Host:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
#: Module tags that logged something, e.g. "[DNS Server]", "[FTP]".
#:
#: This is *not* the set of listeners that are running, and reading it as such
#: understated a healthy run badly: FakeNet 3.5 tags its modules by short name,
#: so a real run reported only "DNS Server" -- the one tag that happens to
#: contain the word "Server" -- while FTP was plainly starting up three lines
#: below and HTTP never logged at startup at all. A listener that boots quietly
#: is invisible here no matter how the pattern is written, which is why the
#: config file below is the authority and this is only the fallback.
_MODULE_TAG_RE = re.compile(r"^\S+\s+\S+\s+\S+\s+\[\s*([A-Za-z0-9 _\-]+?)\s*\]", re.MULTILINE)

#: Tags that are FakeNet's own plumbing rather than a protocol listener.
_NON_LISTENER_TAGS = {"fakenet", "diverter"}

#: FakeNet names the config it loaded on its first line. Taken from the log
#: rather than recomputed, so a run using a custom config through
#: fakenet_config_path is described by the config it actually used.
_CONFIG_PATH_RE = re.compile(r"Loaded configuration file:\s*(.+?)\s*$", re.MULTILINE)

#: Process-attributed connection attempts from the diverter, e.g.
#: "evil.exe (4880) requested UDP 127.0.0.1:52173".
#: This is FakeNet's most valuable output: the packet capture shows that a
#: connection happened, this shows which process wanted it.
_PROCESS_REQUEST_RE = re.compile(
    r"([\w.\-]+\.exe)\s+\((\d+)\)\s+requested\s+(TCP|UDP)\s+"
    r"([\d.]+|\[[0-9a-fA-F:]+\]):(\d+)",
    re.IGNORECASE,
)

#: The adapter FakeNet took over, e.g.
#: "Set DNS server 0.0.0.0 on the adapter: Ethernet 2".
_DNS_ADAPTER_RE = re.compile(
    r"Set DNS server\s+(\S+)\s+on the adapter:\s*(.+?)\s*$", re.MULTILINE
)
#: Diverted connections, e.g. "tcp 10.0.0.5:1234 -> 93.184.216.34:443".
_DIVERT_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\s*(?:->|to)\s*(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})"
)


#: Config keys naming a directory a listener serves from. A listener that
#: serves a directory also *writes* to it: an FTP STOR and an HTTP PUT both
#: land in the root, which is how a sample's uploaded file ends up inside the
#: FakeNet installation instead of the case directory.
_LISTENER_ROOT_KEYS = ("webroot", "ftproot", "tftproot")

#: FakeNet ships every listener pointed at this directory by default, so it is
#: worth watching even when no config could be read.
_DEFAULT_ROOT_NAME = "defaultFiles"

#: Received files are exfiltrated documents and stolen-credential reports --
#: kilobytes, not megabytes. Anything larger is recorded and left in place
#: rather than copied, so a misconfigured root cannot fill the case directory.
MAX_RECEIVED_FILE_BYTES = 25 * 1024 * 1024


#: Windows raises this from CreateProcess when antivirus blocks the image.
ERROR_VIRUS_INFECTED = 225

#: 0xC000013A. What a process returns after honouring CTRL_BREAK_EVENT, which
#: is how stop() asks FakeNet to shut down. Windows reports it as a signed
#: -1073741510 in some tools and as this unsigned value through Popen.
STATUS_CONTROL_C_EXIT = 3221225786

#: Exit codes that mean FakeNet stopped the way it was asked to. Anything else
#: means it died on its own, which leaves the sample unserved for the rest of
#: the run.
EXPECTED_EXIT_CODES = (0, None, STATUS_CONTROL_C_EXIT, -1073741510)

AV_GUIDANCE = (
    "Antivirus blocked or quarantined fakenet.exe. This is an expected false "
    "positive: FakeNet-NG diverts traffic, so AV classifies it as a HackTool. "
    "Exclude the tools directory in the analysis VM (or disable real-time "
    "protection inside the VM only), then re-run scripts/bootstrap_tools.ps1 "
    "to restore the file."
)


class FakeNetError(Exception):
    pass


def _describe_launch_error(error: OSError, binary: Path) -> str:
    """Turn a launch failure into something the analyst can act on."""
    winerror = getattr(error, "winerror", None)
    if winerror == ERROR_VIRUS_INFECTED:
        return f"{AV_GUIDANCE} (blocked path: {binary})"
    if isinstance(error, PermissionError):
        return (
            "Permission denied starting FakeNet-NG. It installs a traffic "
            "diverter and must run elevated."
        )
    return f"failed to start FakeNet-NG: {error}"


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def _tools_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "tools"


def find_fakenet(configured: str | Path | None = None) -> Optional[Path]:
    """Locate the FakeNet-NG executable."""
    if configured:
        candidate = Path(configured)
        if candidate.exists():
            return candidate

    tools = _tools_dir()
    for relative in (
        "fakenet.exe",
        "fakenet/fakenet.exe",
        "fakenet-ng/fakenet.exe",
        "flare-fakenet-ng/fakenet.exe",
    ):
        candidate = tools / relative
        if candidate.exists():
            return candidate

    found = shutil.which("fakenet.exe") or shutil.which("fakenet")
    return Path(found) if found else None


def _load_config(config_path: str | Path | None) -> Optional[configparser.ConfigParser]:
    """Parse a FakeNet config, or None for anything unreadable.

    Returns None rather than raising: a config that cannot be parsed must cost
    only the information derived from it.
    """
    if not config_path:
        return None

    path = Path(config_path)
    if not path.exists():
        return None

    parser = configparser.ConfigParser(strict=False)
    # FakeNet section names are case-sensitive to a reader ("DNS Server"),
    # and configparser lowercases option names but not sections, which is
    # what we want.
    try:
        parser.read(path, encoding="utf-8")
    except Exception:
        return None
    return parser


def _resolve_root(value: str, bases: list[Path]) -> Optional[Path]:
    """Turn a config root value into a directory that exists.

    FakeNet's roots are conventionally relative ("defaultFiles/"), and what
    they are relative to depends on how it was invoked. Rather than guess,
    every plausible base is tried and the first that exists wins.
    """
    raw = value.strip().strip('"').strip("'")
    if not raw:
        return None

    candidate = Path(raw)
    if candidate.is_absolute():
        return candidate.resolve() if candidate.is_dir() else None

    for base in bases:
        resolved = base / raw
        if resolved.is_dir():
            return resolved.resolve()
    return None


def listener_roots(
    config_path: str | Path | None = None,
    binary: str | Path | None = None,
    extra_bases: list[Path] | None = None,
) -> list[Path]:
    """Directories FakeNet's listeners serve from, and therefore receive into.

    The FTP listener is a real FTP server rooted at a real directory. When
    AgentTesla uploaded its stolen-credential report, the file was written
    there -- over the top of FakeNet's own default page -- and nothing in the
    case directory recorded that it had happened.
    """
    bases: list[Path] = []
    if binary:
        binary_dir = Path(binary).resolve().parent
        bases.extend([binary_dir, binary_dir.parent])
    if config_path:
        bases.append(Path(config_path).resolve().parent)
    if extra_bases:
        bases.extend(Path(base) for base in extra_bases)

    roots: list[Path] = []

    def _remember(path: Optional[Path]) -> None:
        if path is not None and path not in roots:
            roots.append(path)

    parser = _load_config(config_path)
    if parser is not None:
        for section in parser.sections():
            for key in _LISTENER_ROOT_KEYS:
                if parser.has_option(section, key):
                    _remember(_resolve_root(parser.get(section, key, fallback=""), bases))

    # The default every listener ships pointed at. Included unconditionally,
    # because a run with no readable config is exactly the run where an upload
    # would otherwise go uncollected.
    for base in bases:
        _remember(_resolve_root(_DEFAULT_ROOT_NAME, [base]))

    return roots


def _snapshot_root(root: Path) -> dict[str, tuple[int, int]]:
    """Size and mtime of every file under a root, keyed by relative path."""
    entries: dict[str, tuple[int, int]] = {}
    try:
        for path in root.rglob("*"):
            try:
                if not path.is_file():
                    continue
                stat = path.stat()
            except OSError:
                continue
            entries[str(path.relative_to(root))] = (stat.st_size, stat.st_mtime_ns)
    except Exception:
        pass
    return entries


def fakenet_status(configured: str | Path | None = None) -> dict[str, Any]:
    """Preflight summary describing whether simulated internet is available."""
    binary = find_fakenet(configured)
    available = binary is not None

    if available:
        note = "FakeNet-NG found; the sample will be served a simulated internet."
    else:
        note = (
            "FakeNet-NG not found. Place fakenet.exe under tools/fakenet/ to "
            "let samples resolve and connect without reaching real infrastructure."
        )
        # A tools/fakenet directory with no executable in it almost always
        # means antivirus quarantined the binary after extraction, so say so
        # rather than sending the analyst off to re-download it blindly.
        install_dir = _tools_dir() / "fakenet"
        if install_dir.is_dir() and not (install_dir / "fakenet.exe").exists():
            note = f"{install_dir} exists but fakenet.exe is missing. {AV_GUIDANCE}"

    return {
        "available": available,
        "binary_path": str(binary) if binary else "",
        "note": note,
        "requires_admin": True,
    }


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

class FakeNetSession:
    """Runs FakeNet-NG for the duration of a detonation."""

    def __init__(
        self,
        output_dir: str | Path,
        fakenet_path: str | Path | None = None,
        config_path: str | Path | None = None,
        startup_grace_seconds: int = 5,
    ):
        self.output_dir = Path(output_dir)
        self.fakenet_path = fakenet_path
        self.config_path = config_path
        self.startup_grace_seconds = startup_grace_seconds

        self.log_path = self.output_dir / "fakenet.log"
        self.stderr_path = self.output_dir / "fakenet.stderr.log"
        self.stop_flag_path = self.output_dir / "fakenet.stop"
        self.received_dir = self.output_dir / "received"
        self.process: Optional[subprocess.Popen] = None
        self.started = False
        self.error = ""
        self._existing_pcaps: set[str] = set()
        self._stderr_handle: Optional[Any] = None
        self._listener_roots: list[Path] = []
        self._root_snapshots: dict[str, dict[str, tuple[int, int]]] = {}

    # -- stderr -----------------------------------------------------------

    def _close_stderr(self) -> None:
        """Release the stderr file. Safe to call more than once."""
        handle, self._stderr_handle = self._stderr_handle, None
        if handle is None:
            return
        try:
            handle.close()
        except Exception:
            pass

    def _read_stderr(self, limit: int = 4000) -> str:
        """Whatever FakeNet wrote to stderr, for reporting a failure.

        Closes the handle first so the tail is actually on disk. Returns an
        empty string for anything unreadable -- a diagnostic that cannot be
        read must not become an error of its own.
        """
        self._close_stderr()
        try:
            return self.stderr_path.read_text(encoding="utf-8", errors="replace")[-limit:]
        except Exception:
            return ""

    # -- start ------------------------------------------------------------

    def start(self) -> dict[str, Any]:
        binary = find_fakenet(self.fakenet_path)
        if binary is None:
            self.error = "FakeNet-NG not found"
            return {"started": False, "error": self.error}

        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Remember pre-existing pcaps so we only claim the one this run creates.
        self._existing_pcaps = {p.name for p in self.output_dir.glob("*.pcap")}

        # ...and the contents of every listener root, so a file the sample
        # uploads can be told apart from the ones FakeNet ships with. Taken
        # before launch: the sample is what changes these directories, and
        # after the fact there is no way to know which files were already there.
        self._listener_roots = listener_roots(
            config_path=self.config_path,
            binary=binary,
            extra_bases=[self.output_dir],
        )
        self._root_snapshots = {
            str(root): _snapshot_root(root) for root in self._listener_roots
        }

        if self.stop_flag_path.exists():
            self.stop_flag_path.unlink()

        cmd = [str(binary), "-l", str(self.log_path), "-s", str(self.stop_flag_path)]
        if self.config_path:
            cmd.extend(["-c", str(self.config_path)])

        # Redirected to a file, never to a pipe.
        #
        # stderr was a PIPE that nothing read after the startup check. FakeNet
        # is verbose -- it echoes every intercepted request, headers included --
        # so the OS buffer filled within a few seconds and FakeNet blocked
        # forever on its next write. The symptom was a simulated internet that
        # answered for about four seconds and then went silent for the rest of
        # the run: DNS and TCP together, the log stopping mid-request, and a
        # sample's C2 lookup timing out against listeners that were up but
        # frozen. It worked when run by hand only because a console drains
        # stderr continuously.
        #
        # A file cannot fill, and it keeps the diagnostics that would have
        # identified this in one run rather than several.
        try:
            self._stderr_handle = open(self.stderr_path, "wb")
        except Exception as error:
            self.error = f"could not open FakeNet-NG stderr log: {error}"
            return {"started": False, "error": self.error}

        try:
            self.process = subprocess.Popen(
                cmd,
                cwd=str(self.output_dir),  # FakeNet drops its pcap in the cwd
                stdout=subprocess.DEVNULL,
                stderr=self._stderr_handle,
                stdin=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
            )
        except OSError as error:
            self.error = _describe_launch_error(error, binary)
            return {"started": False, "error": self.error}
        except Exception as error:
            self.error = f"failed to start FakeNet-NG: {error}"
            return {"started": False, "error": self.error}

        # Give the diverter time to install before the sample runs, otherwise
        # the sample's first connections escape interception.
        time.sleep(max(0, self.startup_grace_seconds))

        if self.process.poll() is not None:
            stderr = self._read_stderr()
            self.error = (
                f"FakeNet-NG exited immediately (rc={self.process.returncode}). "
                f"{stderr.strip()[:300]} It requires Administrator rights."
            )
            return {"started": False, "error": self.error}

        self.started = True
        return {"started": True, "error": "", "binary_path": str(binary)}

    # -- stop -------------------------------------------------------------

    def stop(self, timeout: int = 45) -> dict[str, Any]:
        if not self.started or self.process is None:
            return {"stopped": False, "error": "FakeNet-NG was not started"}

        error = ""
        try:
            # The stop-flag file is FakeNet's own graceful shutdown mechanism;
            # it lets the diverter unwind and the pcap be closed properly.
            self.stop_flag_path.touch()
            self.process.wait(timeout=timeout)
        except Exception:
            try:
                if hasattr(signal, "CTRL_BREAK_EVENT"):
                    os.kill(self.process.pid, signal.CTRL_BREAK_EVENT)
                self.process.wait(timeout=15)
            except Exception:
                try:
                    self.process.terminate()
                    self.process.wait(timeout=10)
                except Exception as inner:
                    error = f"failed to stop FakeNet-NG cleanly: {inner}"

        self._close_stderr()

        try:
            if self.stop_flag_path.exists():
                self.stop_flag_path.unlink()
        except Exception:
            pass

        # A non-zero exit is worth carrying: FakeNet dying mid-run leaves the
        # sample unserved, and the run would otherwise report a clean result.
        #
        # Except the one we cause ourselves. The stop path above sends
        # CTRL_BREAK_EVENT, and a process that honours it exits with
        # STATUS_CONTROL_C_EXIT -- so the first healthy run to reach this code
        # reported "FakeNet-NG exited with rc=3221225786" as an error while
        # having served the sample's exfil perfectly.
        returncode = self.process.poll()
        if not error and returncode not in EXPECTED_EXIT_CODES:
            detail = " ".join(self._read_stderr().split())[-300:]
            error = f"FakeNet-NG exited with rc={returncode}. {detail}".strip()

        # After the listeners are down, so a file still being written cannot be
        # copied half-finished. A failure here must not turn a served run into
        # a failed one.
        try:
            received = self._collect_received_files()
        except Exception as collect_error:
            received = {
                "collected": False,
                "note": f"could not collect received files: {collect_error}",
                "roots": [str(root) for root in self._listener_roots],
                "output_dir": str(self.received_dir),
                "files": [],
                "counts": {"files": 0, "new": 0, "overwritten": 0, "not_copied": 0},
            }

        return {
            "stopped": True,
            "error": error,
            "returncode": returncode,
            "log_path": str(self.log_path),
            "log_exists": self.log_path.exists(),
            "stderr_path": str(self.stderr_path),
            "pcap_path": str(self.find_pcap() or ""),
            "received_files": received,
        }

    # -- received files ---------------------------------------------------

    def _collect_received_files(self) -> dict[str, Any]:
        """Copy anything the sample uploaded into the case directory.

        FakeNet's listeners serve from directories inside the FakeNet
        installation, and an upload is written there. That is outside the case
        directory, so the next revert destroys it -- and it is the single most
        valuable artifact a run produces. AgentTesla's stolen-credential report
        was found by hand in ``tools/fakenet/defaultFiles/FakeNet.html``, having
        overwritten FakeNet's own default page, which is why a modified file
        counts here and not just a new one.

        Files are copied, never moved: the roots belong to FakeNet, and a run
        must not leave its installation missing the files it serves.
        """
        result: dict[str, Any] = {
            "collected": False,
            "note": "",
            "roots": [str(root) for root in self._listener_roots],
            "output_dir": str(self.received_dir),
            "files": [],
            "counts": {"files": 0, "new": 0, "overwritten": 0, "not_copied": 0},
        }

        if not self._listener_roots:
            result["note"] = (
                "No FakeNet listener root could be located, so an uploaded file "
                "would not have been collected. Check the Webroot/FTPRoot paths "
                "in the FakeNet config."
            )
            return result

        collected: list[dict[str, Any]] = []
        used_names: set[str] = set()

        for root in self._listener_roots:
            before = self._root_snapshots.get(str(root), {})
            after = _snapshot_root(root)

            for relative, (size, mtime_ns) in sorted(after.items()):
                previous = before.get(relative)
                if previous == (size, mtime_ns):
                    continue

                source = root / relative
                entry: dict[str, Any] = {
                    "name": Path(relative).name,
                    "relative_path": relative,
                    "root": str(root),
                    "source_path": str(source),
                    "size": size,
                    "state": "new" if previous is None else "overwritten",
                    "sha256": "",
                    "saved_as": "",
                    "copied": False,
                    "error": "",
                }

                if size > MAX_RECEIVED_FILE_BYTES:
                    entry["error"] = (
                        f"left in place: {size} bytes exceeds the "
                        f"{MAX_RECEIVED_FILE_BYTES} byte collection limit"
                    )
                    collected.append(entry)
                    continue

                # Roots can share a basename ("defaultFiles" under two
                # listeners), so a destination name that is already taken gets
                # a suffix rather than silently overwriting a sibling.
                destination_name = f"{root.name}__{relative}".replace("\\", "_").replace("/", "_")
                candidate = destination_name
                suffix = 2
                while candidate in used_names:
                    candidate = f"{destination_name}.{suffix}"
                    suffix += 1
                used_names.add(candidate)

                try:
                    self.received_dir.mkdir(parents=True, exist_ok=True)
                    destination = self.received_dir / candidate
                    shutil.copy2(source, destination)
                    entry["saved_as"] = str(destination)
                    entry["copied"] = True
                    entry["sha256"] = sha256_file(destination)
                except Exception as error:
                    entry["error"] = f"could not collect: {error}"

                collected.append(entry)

        result["collected"] = True
        result["files"] = collected
        result["counts"] = {
            "files": len(collected),
            "new": sum(1 for entry in collected if entry["state"] == "new"),
            "overwritten": sum(1 for entry in collected if entry["state"] == "overwritten"),
            "not_copied": sum(1 for entry in collected if not entry["copied"]),
        }
        if not collected:
            result["note"] = (
                f"{len(self._listener_roots)} listener root(s) watched; nothing "
                "was uploaded to them."
            )
        return result

    def find_pcap(self) -> Optional[Path]:
        """The pcap FakeNet created during this session, if any."""
        candidates = [
            p for p in self.output_dir.glob("*.pcap") if p.name not in self._existing_pcaps
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda p: p.stat().st_mtime)


# ---------------------------------------------------------------------------
# Log parsing
# ---------------------------------------------------------------------------

def _enabled_listeners(config_path: str) -> list[str]:
    """Listener sections FakeNet's config has switched on.

    The authority for "what will be served". A listener section carries a
    Listener key naming its handler, which is what separates it from the
    [FakeNet] and [Diverter] sections; Enabled decides whether it runs.

    Returns an empty list rather than raising for anything unreadable -- a
    parse failure here must cost the listener list and nothing else.
    """
    parser = _load_config(config_path)
    if parser is None:
        return []

    enabled: list[str] = []
    for section in parser.sections():
        if not parser.has_option(section, "listener"):
            continue
        try:
            if parser.getboolean(section, "enabled", fallback=False):
                enabled.append(section)
        except ValueError:
            continue

    return enabled


def parse_fakenet_log(log_path: str | Path) -> dict[str, Any]:
    """Recover requested domains, URLs and listener hits from a FakeNet log.

    This is the payoff: even with no real internet, the log records exactly
    what the sample tried to reach.
    """
    path = Path(log_path)
    summary: dict[str, Any] = {
        "parsed": False,
        "note": "",
        "dns_requests": [],
        "http_requests": [],
        "hosts": [],
        "listeners_configured": [],
        "listeners_source": "",
        "config_path": "",
        "process_requests": [],
        "diverted_connections": [],
        "dns_adapter": "",
        "dns_server": "",
        "counts": {},
    }

    if not path.exists():
        summary["note"] = "FakeNet log not found"
        return summary

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception as error:
        summary["note"] = f"could not read FakeNet log: {error}"
        return summary

    dns: list[str] = []
    for match in _DNS_RE.finditer(text):
        domain = match.group(1).strip().rstrip(".")
        if domain and domain not in dns:
            dns.append(domain)

    http: list[dict[str, str]] = []
    for match in _HTTP_REQUEST_RE.finditer(text):
        entry = {"method": match.group(1).upper(), "uri": match.group(2)}
        if entry not in http:
            http.append(entry)

    hosts: list[str] = []
    for match in _HOST_HEADER_RE.finditer(text):
        host = match.group(1).strip()
        if host and host not in hosts:
            hosts.append(host)

    modules: list[str] = []
    for match in _MODULE_TAG_RE.finditer(text):
        name = match.group(1).strip()
        if name and name.lower() not in _NON_LISTENER_TAGS and name not in modules:
            modules.append(name)

    config_path = ""
    config_match = _CONFIG_PATH_RE.search(text)
    if config_match:
        config_path = config_match.group(1).strip()

    listeners = _enabled_listeners(config_path)
    listeners_source = "config"
    if not listeners:
        # No config to read, or it parsed to nothing. The module tags are worse
        # evidence -- they miss any listener that started quietly -- but they
        # beat reporting nothing at all.
        listeners = modules
        listeners_source = "log"

    diverted: list[dict[str, str]] = []
    for match in _DIVERT_RE.finditer(text):
        entry = {
            "src": f"{match.group(1)}:{match.group(2)}",
            "dst": f"{match.group(3)}:{match.group(4)}",
        }
        if entry not in diverted:
            diverted.append(entry)

    # Which process asked for what. The pcap cannot attribute a packet to a
    # process; the diverter can, which makes this the more useful record.
    process_requests: list[dict[str, str]] = []
    for match in _PROCESS_REQUEST_RE.finditer(text):
        entry = {
            "process": match.group(1),
            "pid": match.group(2),
            "protocol": match.group(3).upper(),
            "destination": f"{match.group(4)}:{match.group(5)}",
        }
        if entry not in process_requests:
            process_requests.append(entry)

    adapter = ""
    dns_server = ""
    adapter_match = _DNS_ADAPTER_RE.search(text)
    if adapter_match:
        dns_server = adapter_match.group(1).strip()
        adapter = adapter_match.group(2).strip()

    summary.update(
        {
            "parsed": True,
            "dns_requests": dns[:300],
            "http_requests": http[:300],
            "hosts": hosts[:300],
            # Renamed from listeners_hit: these banners are printed at startup,
            # so their presence only proves a listener was configured.
            "listeners_configured": listeners[:50],
            "listeners_source": listeners_source,
            "config_path": config_path,
            "modules_logged": modules[:50],
            "process_requests": process_requests[:300],
            "diverted_connections": diverted[:300],
            "dns_adapter": adapter,
            "dns_server": dns_server,
            "counts": {
                "dns_requests": len(dns),
                "http_requests": len(http),
                "hosts": len(hosts),
                "process_requests": len(process_requests),
                "diverted_connections": len(diverted),
            },
        }
    )
    return summary
