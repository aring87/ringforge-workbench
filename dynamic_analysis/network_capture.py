"""Full packet capture for dynamic analysis runs.

Procmon reports that a connection happened; it does not report what crossed the
wire. A pcap adds DNS answers, HTTP hosts and URIs, TLS SNI and JA3-able
handshakes, which is usually where C2 attribution actually comes from.

Two backends are supported:

``dumpcap``
    Ships with Wireshark and writes standard pcapng. Preferred.
``pktmon``
    Built into Windows 10 1809+, so it needs no install, but records to ETL and
    has to be converted afterwards. Used only as a fallback.

The pcap is the artifact that matters, so parsing is strictly best-effort: if
``tshark`` is missing the capture is still written and kept for manual review.
Both backends need Administrator rights.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
from pathlib import Path
from typing import Any, Optional

#: Ports that are ordinary for outbound traffic; anything else is worth a look.
COMMON_PORTS = {80, 443, 53, 123, 8080, 8443, 445, 139, 22, 21, 25, 587, 993, 995}

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class NetworkCaptureError(Exception):
    pass


# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------

def _tools_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "tools"


def _find_tool(name: str, configured: str | Path | None = None) -> Optional[Path]:
    """Find a Wireshark-family binary in tools/, the default install, or PATH."""
    if configured:
        candidate = Path(configured)
        if candidate.exists():
            return candidate

    local = _tools_dir() / name
    if local.exists():
        return local

    for base in (
        Path(r"C:\Program Files\Wireshark"),
        Path(r"C:\Program Files (x86)\Wireshark"),
    ):
        candidate = base / name
        if candidate.exists():
            return candidate

    found = shutil.which(name)
    return Path(found) if found else None


def find_dumpcap(configured: str | Path | None = None) -> Optional[Path]:
    return _find_tool("dumpcap.exe", configured)


def find_tshark(configured: str | Path | None = None) -> Optional[Path]:
    return _find_tool("tshark.exe", configured)


def pktmon_available() -> bool:
    return shutil.which("pktmon.exe") is not None or shutil.which("pktmon") is not None


def list_interfaces(dumpcap_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Enumerate capture interfaces.

    Prefers ``dumpcap -D -M``, whose JSON includes each interface's addresses --
    that is what makes it possible to pick the interface actually carrying
    traffic rather than whichever one happens to be listed first.
    """
    dumpcap = find_dumpcap(dumpcap_path)
    if dumpcap is None:
        return []

    interfaces = _list_interfaces_json(dumpcap)
    if interfaces:
        return interfaces
    return _list_interfaces_text(dumpcap)


def _list_interfaces_json(dumpcap: Path) -> list[dict[str, Any]]:
    try:
        result = subprocess.run(
            [str(dumpcap), "-D", "-M"],
            capture_output=True, text=True, timeout=30, errors="replace",
        )
    except Exception:
        return []

    if result.returncode != 0 or not (result.stdout or "").strip():
        return []

    try:
        raw = json.loads(result.stdout)
    except Exception:
        return []

    interfaces: list[dict[str, Any]] = []
    for position, entry in enumerate(raw, start=1):
        if not isinstance(entry, dict):
            continue
        for name, meta in entry.items():
            meta = meta if isinstance(meta, dict) else {}
            interfaces.append(
                {
                    "index": str(position),
                    "name": name,
                    "description": (
                        meta.get("friendly_name") or meta.get("vendor_description") or ""
                    ),
                    "vendor_description": meta.get("vendor_description") or "",
                    "addrs": [a for a in (meta.get("addrs") or []) if isinstance(a, str)],
                    "loopback": bool(meta.get("loopback")),
                }
            )
    return interfaces


def _list_interfaces_text(dumpcap: Path) -> list[dict[str, Any]]:
    """Fallback for Wireshark builds without ``-M``."""
    try:
        result = subprocess.run(
            [str(dumpcap), "-D"], capture_output=True, text=True, timeout=30, errors="replace"
        )
    except Exception:
        return []

    interfaces: list[dict[str, Any]] = []
    for line in (result.stdout or "").splitlines():
        # Format: "1. \Device\NPF_{GUID} (Ethernet)"
        match = re.match(r"\s*(\d+)\.\s+(\S+)(?:\s+\((.*)\))?", line.strip())
        if match:
            description = (match.group(3) or "").strip()
            interfaces.append(
                {
                    "index": match.group(1),
                    "name": match.group(2),
                    "description": description,
                    "vendor_description": description,
                    "addrs": [],
                    "loopback": "loopback" in f"{description} {match.group(2)}".lower(),
                }
            )
    return interfaces


def _local_route_ip() -> str:
    """IPv4 address the default route would use.

    ``connect`` on a UDP socket sends nothing; it only asks the OS to resolve
    the outbound route, so this works offline and generates no traffic.
    """
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except Exception:
        return ""
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _is_usable_ipv4(address: str) -> bool:
    if not _IPV4_RE.match(address):
        return False
    # Link-local means the adapter never got a real lease.
    return not address.startswith("169.254.") and not address.startswith("127.")


def pick_default_interface(dumpcap_path: str | Path | None = None) -> str:
    """Capture interface carrying the default route.

    Returns the device *name* rather than its index: indexes shift as adapters
    appear and disappear, and picking the wrong one yields a silently empty
    capture, which is the worst possible failure for an analyst.
    """
    interfaces = list_interfaces(dumpcap_path)
    if not interfaces:
        return "1"

    candidates = [i for i in interfaces if not i.get("loopback")]

    # Best signal: the interface holding the default-route source address.
    route_ip = _local_route_ip()
    if route_ip:
        for interface in candidates:
            if route_ip in (interface.get("addrs") or []):
                return interface["name"]

    # Next best: any adapter with a real (non link-local) IPv4 lease.
    for interface in candidates:
        if any(_is_usable_ipv4(a) for a in (interface.get("addrs") or [])):
            return interface["name"]

    # Then: anything with an address at all.
    for interface in candidates:
        if interface.get("addrs"):
            return interface["name"]

    if candidates:
        return candidates[0]["name"]
    return "1"


def capture_status(dumpcap_path: str | Path | None = None) -> dict[str, Any]:
    """Preflight summary describing whether packet capture can run."""
    dumpcap = find_dumpcap(dumpcap_path)
    tshark = find_tshark()
    pktmon = pktmon_available()

    if dumpcap is not None:
        backend, available = "dumpcap", True
        note = "dumpcap found; captures will be written as pcapng."
    elif pktmon:
        backend, available = "pktmon", True
        note = (
            "Wireshark/dumpcap not found. Falling back to the built-in pktmon, "
            "which needs an extra ETL to pcap conversion step."
        )
    else:
        backend, available = "", False
        note = (
            "No capture backend found. Install Wireshark (provides dumpcap and "
            "tshark) in the analysis VM to record network traffic."
        )

    return {
        "available": available,
        "backend": backend,
        "dumpcap_path": str(dumpcap) if dumpcap else "",
        "tshark_path": str(tshark) if tshark else "",
        "tshark_available": tshark is not None,
        "pktmon_available": pktmon,
        "note": note,
        "parse_note": (
            "" if tshark is not None
            else "tshark not found; the pcap is saved but will not be parsed automatically."
        ),
    }


# ---------------------------------------------------------------------------
# Capture lifecycle
# ---------------------------------------------------------------------------

class PacketCapture:
    """Starts a capture on construction-free ``start()`` and stops on ``stop()``.

    Kept as an object because the caller must hold the running process handle
    across the sample detonation.
    """

    def __init__(
        self,
        output_path: str | Path,
        interface: str | None = None,
        dumpcap_path: str | Path | None = None,
        capture_filter: str = "",
    ):
        self.output_path = Path(output_path)
        self.interface = interface or ""
        self.dumpcap_path = dumpcap_path
        self.capture_filter = capture_filter
        self.backend = ""
        self.process: Optional[subprocess.Popen] = None
        self._etl_path: Optional[Path] = None
        self.started = False
        self.error = ""

    # -- start ------------------------------------------------------------

    def start(self) -> dict[str, Any]:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

        dumpcap = find_dumpcap(self.dumpcap_path)
        if dumpcap is not None:
            return self._start_dumpcap(dumpcap)
        if pktmon_available():
            return self._start_pktmon()

        self.error = "no capture backend available"
        return {"started": False, "backend": "", "error": self.error}

    def _start_dumpcap(self, dumpcap: Path) -> dict[str, Any]:
        interface = self.interface or pick_default_interface(dumpcap)
        cmd = [str(dumpcap), "-i", str(interface), "-w", str(self.output_path), "-q"]
        if self.capture_filter:
            cmd.extend(["-f", self.capture_filter])

        try:
            # A new process group lets us send CTRL+BREAK, which makes dumpcap
            # finalise the capture file instead of being killed mid-write.
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
            )
        except Exception as error:
            self.error = f"failed to start dumpcap: {error}"
            return {"started": False, "backend": "dumpcap", "error": self.error}

        self.backend = "dumpcap"
        self.started = True
        return {
            "started": True,
            "backend": "dumpcap",
            "interface": str(interface),
            "error": "",
        }

    def _start_pktmon(self) -> dict[str, Any]:
        self._etl_path = self.output_path.with_suffix(".etl")
        if self._etl_path.exists():
            self._etl_path.unlink()

        try:
            result = subprocess.run(
                [
                    "pktmon", "start", "--capture",
                    "--pkt-size", "0",
                    "-f", str(self._etl_path),
                ],
                capture_output=True, text=True, timeout=60, errors="replace",
            )
        except Exception as error:
            self.error = f"failed to start pktmon: {error}"
            return {"started": False, "backend": "pktmon", "error": self.error}

        if result.returncode != 0:
            self.error = (result.stderr or result.stdout or "").strip()
            return {"started": False, "backend": "pktmon", "error": self.error}

        self.backend = "pktmon"
        self.started = True
        return {"started": True, "backend": "pktmon", "error": ""}

    # -- stop -------------------------------------------------------------

    def stop(self, timeout: int = 30) -> dict[str, Any]:
        if not self.started:
            return {"stopped": False, "backend": self.backend, "error": "capture was not started"}

        if self.backend == "dumpcap":
            return self._stop_dumpcap(timeout)
        return self._stop_pktmon(timeout)

    def _stop_dumpcap(self, timeout: int) -> dict[str, Any]:
        if self.process is None:
            return {"stopped": False, "backend": "dumpcap", "error": "no process handle"}

        error = ""
        try:
            # CTRL+BREAK first so the pcapng gets a clean trailer.
            if hasattr(signal, "CTRL_BREAK_EVENT"):
                os.kill(self.process.pid, signal.CTRL_BREAK_EVENT)
            else:
                self.process.terminate()
            self.process.wait(timeout=timeout)
        except Exception:
            try:
                self.process.terminate()
                self.process.wait(timeout=10)
            except Exception as inner:
                error = f"failed to stop dumpcap cleanly: {inner}"

        exists = self.output_path.exists()
        return {
            "stopped": True,
            "backend": "dumpcap",
            "error": error,
            "pcap_path": str(self.output_path),
            "pcap_exists": exists,
            "pcap_bytes": self.output_path.stat().st_size if exists else 0,
        }

    def _stop_pktmon(self, timeout: int) -> dict[str, Any]:
        error = ""
        try:
            subprocess.run(
                ["pktmon", "stop"], capture_output=True, text=True, timeout=timeout, errors="replace"
            )
        except Exception as inner:
            error = f"failed to stop pktmon: {inner}"

        # Convert ETL to pcapng so downstream parsing is backend-independent.
        if self._etl_path and self._etl_path.exists():
            try:
                subprocess.run(
                    [
                        "pktmon", "etl2pcap", str(self._etl_path),
                        "-o", str(self.output_path),
                    ],
                    capture_output=True, text=True, timeout=300, errors="replace",
                )
            except Exception as inner:
                error = error or f"failed to convert pktmon ETL: {inner}"

        exists = self.output_path.exists()
        return {
            "stopped": True,
            "backend": "pktmon",
            "error": error,
            "pcap_path": str(self.output_path),
            "etl_path": str(self._etl_path) if self._etl_path else "",
            "pcap_exists": exists,
            "pcap_bytes": self.output_path.stat().st_size if exists else 0,
        }


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _tshark_fields(
    tshark: Path,
    pcap: Path,
    display_filter: str,
    fields: list[str],
    timeout: int = 300,
) -> list[list[str]]:
    cmd = [str(tshark), "-r", str(pcap), "-T", "fields"]
    if display_filter:
        cmd.extend(["-Y", display_filter])
    for field in fields:
        cmd.extend(["-e", field])
    cmd.extend(["-E", "separator=\t", "-E", "occurrence=f"])

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, errors="replace"
        )
    except Exception:
        return []

    if result.returncode != 0:
        return []

    rows: list[list[str]] = []
    for line in (result.stdout or "").splitlines():
        if not line.strip():
            continue
        rows.append(line.split("\t"))
    return rows


def parse_pcap(pcap_path: str | Path, tshark_path: str | Path | None = None) -> dict[str, Any]:
    """Extract DNS, TLS SNI, HTTP and outbound connections from a capture."""
    pcap = Path(pcap_path)
    summary: dict[str, Any] = {
        "parsed": False,
        "note": "",
        "dns_queries": [],
        "tls_sni": [],
        "http_requests": [],
        "connections": [],
        "unique_destinations": [],
        "unusual_ports": [],
        "counts": {},
    }

    if not pcap.exists():
        summary["note"] = "capture file not found"
        return summary

    tshark = find_tshark(tshark_path)
    if tshark is None:
        summary["note"] = (
            "tshark not found; pcap saved for manual analysis but not parsed."
        )
        return summary

    # DNS questions.
    dns: list[str] = []
    for row in _tshark_fields(tshark, pcap, "dns.flags.response == 0", ["dns.qry.name"]):
        name = row[0].strip() if row else ""
        if name and name not in dns:
            dns.append(name)

    # TLS SNI from ClientHello.
    sni: list[str] = []
    for row in _tshark_fields(
        tshark, pcap, "tls.handshake.type == 1", ["tls.handshake.extensions_server_name"]
    ):
        name = row[0].strip() if row else ""
        if name and name not in sni:
            sni.append(name)

    # Plaintext HTTP requests.
    http: list[dict[str, str]] = []
    for row in _tshark_fields(
        tshark, pcap, "http.request",
        ["http.request.method", "http.host", "http.request.uri"],
    ):
        row += [""] * (3 - len(row))
        entry = {"method": row[0].strip(), "host": row[1].strip(), "uri": row[2].strip()}
        if entry["host"] and entry not in http:
            http.append(entry)

    # Outbound TCP connection attempts (SYN without ACK).
    connections: list[dict[str, str]] = []
    destinations: list[str] = []
    unusual: list[dict[str, str]] = []
    for row in _tshark_fields(
        tshark, pcap, "tcp.flags.syn == 1 && tcp.flags.ack == 0",
        ["ip.dst", "tcp.dstport"],
    ):
        row += [""] * (2 - len(row))
        dst, port = row[0].strip(), row[1].strip()
        if not dst:
            continue
        entry = {"dst": dst, "port": port}
        if entry not in connections:
            connections.append(entry)
        if dst not in destinations:
            destinations.append(dst)
        try:
            if int(port) not in COMMON_PORTS and entry not in unusual:
                unusual.append(entry)
        except ValueError:
            pass

    summary.update(
        {
            "parsed": True,
            "dns_queries": dns[:300],
            "tls_sni": sni[:300],
            "http_requests": http[:300],
            "connections": connections[:300],
            "unique_destinations": destinations[:300],
            "unusual_ports": unusual[:100],
            "counts": {
                "dns_queries": len(dns),
                "tls_sni": len(sni),
                "http_requests": len(http),
                "connections": len(connections),
                "unique_destinations": len(destinations),
                "unusual_ports": len(unusual),
            },
        }
    )
    return summary


def extract_network_iocs(summary: dict[str, Any]) -> dict[str, list[str]]:
    """Collapse a parsed capture into deduplicated domain and IP indicators."""
    domains: list[str] = []
    ips: list[str] = []
    urls: list[str] = []

    for name in list(summary.get("dns_queries", [])) + list(summary.get("tls_sni", [])):
        name = (name or "").strip().rstrip(".")
        if not name:
            continue
        if _IPV4_RE.match(name):
            if name not in ips:
                ips.append(name)
        elif name not in domains:
            domains.append(name)

    for entry in summary.get("http_requests", []):
        host = (entry.get("host") or "").strip()
        if host:
            bare = host.split(":")[0]
            if _IPV4_RE.match(bare):
                if bare not in ips:
                    ips.append(bare)
            elif bare not in domains:
                domains.append(bare)
        uri = (entry.get("uri") or "").strip()
        if host and uri:
            url = f"http://{host}{uri}"
            if url not in urls:
                urls.append(url)

    for entry in summary.get("connections", []):
        dst = (entry.get("dst") or "").strip()
        if dst and dst not in ips:
            ips.append(dst)

    return {"domains": domains[:300], "ips": ips[:300], "urls": urls[:300]}
