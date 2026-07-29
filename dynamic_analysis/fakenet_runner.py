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

Requires Administrator rights (it installs a traffic diverter).
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Any, Optional

#: DNS request lines, e.g. "Received A request for domain 'evil.com'".
_DNS_RE = re.compile(
    r"request for domain\s+['\"]?([A-Za-z0-9_.\-]+)['\"]?", re.IGNORECASE
)
#: HTTP request lines, e.g. "GET /gate.php HTTP/1.1".
_HTTP_REQUEST_RE = re.compile(
    r"\b(GET|POST|HEAD|PUT|PATCH|DELETE|OPTIONS)\s+(\S+)\s+HTTP/\d", re.IGNORECASE
)
_HOST_HEADER_RE = re.compile(r"^\s*Host:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
#: Listener banners, e.g. "[HTTPListener80]" or "[DNS Server]".
_LISTENER_RE = re.compile(r"\[([A-Za-z0-9 _\-]*(?:Listener|Server)[A-Za-z0-9 _\-]*)\]")
#: Diverted connections, e.g. "tcp 10.0.0.5:1234 -> 93.184.216.34:443".
_DIVERT_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\s*(?:->|to)\s*(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})"
)


class FakeNetError(Exception):
    pass


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


def fakenet_status(configured: str | Path | None = None) -> dict[str, Any]:
    """Preflight summary describing whether simulated internet is available."""
    binary = find_fakenet(configured)
    available = binary is not None

    return {
        "available": available,
        "binary_path": str(binary) if binary else "",
        "note": (
            "FakeNet-NG found; the sample will be served a simulated internet."
            if available
            else "FakeNet-NG not found. Place fakenet.exe under tools/fakenet/ to "
            "let samples resolve and connect without reaching real infrastructure."
        ),
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
        self.stop_flag_path = self.output_dir / "fakenet.stop"
        self.process: Optional[subprocess.Popen] = None
        self.started = False
        self.error = ""
        self._existing_pcaps: set[str] = set()

    # -- start ------------------------------------------------------------

    def start(self) -> dict[str, Any]:
        binary = find_fakenet(self.fakenet_path)
        if binary is None:
            self.error = "FakeNet-NG not found"
            return {"started": False, "error": self.error}

        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Remember pre-existing pcaps so we only claim the one this run creates.
        self._existing_pcaps = {p.name for p in self.output_dir.glob("*.pcap")}

        if self.stop_flag_path.exists():
            self.stop_flag_path.unlink()

        cmd = [str(binary), "-l", str(self.log_path), "-s", str(self.stop_flag_path)]
        if self.config_path:
            cmd.extend(["-c", str(self.config_path)])

        try:
            self.process = subprocess.Popen(
                cmd,
                cwd=str(self.output_dir),  # FakeNet drops its pcap in the cwd
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
            )
        except Exception as error:
            self.error = f"failed to start FakeNet-NG: {error}"
            return {"started": False, "error": self.error}

        # Give the diverter time to install before the sample runs, otherwise
        # the sample's first connections escape interception.
        time.sleep(max(0, self.startup_grace_seconds))

        if self.process.poll() is not None:
            stderr = ""
            try:
                stderr = (self.process.stderr.read() or b"").decode("utf-8", "replace")
            except Exception:
                pass
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

        try:
            if self.stop_flag_path.exists():
                self.stop_flag_path.unlink()
        except Exception:
            pass

        return {
            "stopped": True,
            "error": error,
            "log_path": str(self.log_path),
            "log_exists": self.log_path.exists(),
            "pcap_path": str(self.find_pcap() or ""),
        }

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
        "listeners_hit": [],
        "diverted_connections": [],
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

    listeners: list[str] = []
    for match in _LISTENER_RE.finditer(text):
        name = match.group(1).strip()
        if name and name not in listeners:
            listeners.append(name)

    diverted: list[dict[str, str]] = []
    for match in _DIVERT_RE.finditer(text):
        entry = {
            "src": f"{match.group(1)}:{match.group(2)}",
            "dst": f"{match.group(3)}:{match.group(4)}",
        }
        if entry not in diverted:
            diverted.append(entry)

    summary.update(
        {
            "parsed": True,
            "dns_requests": dns[:300],
            "http_requests": http[:300],
            "hosts": hosts[:300],
            "listeners_hit": listeners[:50],
            "diverted_connections": diverted[:300],
            "counts": {
                "dns_requests": len(dns),
                "http_requests": len(http),
                "hosts": len(hosts),
                "diverted_connections": len(diverted),
            },
        }
    )
    return summary
